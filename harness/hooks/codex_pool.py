#!/usr/bin/env python3
"""codex-pool: budget-aware rotation of OpenAI API keys for Codex runs.

Order of preference for every run: the ChatGPT subscription login first, then API keys from
Secret Manager (least spent today first), each bounded by the caps in codex_pool_policy.json.
Keys are fetched inside this process, fed to `codex login --with-api-key` on stdin in a fresh
mode-0700 CODEX_HOME that is deleted after the run, and never appear in argv, the environment
of any other process, logs, the ledger or output (child output is scrubbed).

Commands: status | probe | run | enable | disable | subscription-block | install
"""
import argparse
import contextlib
import fcntl
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
SCHEMA = 1
ALIAS = re.compile(r'^[a-z0-9][a-z0-9-]{0,62}$')
KEY_SHAPE = re.compile(r'^sk-[A-Za-z0-9_\-]{20,400}$')
KEY_LIKE = re.compile(rb'sk-[A-Za-z0-9_\-]{16,}')
MODEL_SHAPE = re.compile(r'^[a-z0-9][a-z0-9._-]{0,63}$')
FAMILY = re.compile(r'^gpt-[0-9.]+-(terra|sol|astra)$')
MAX_CAPTURE = 32 << 20
MAX_STDIN = 8 << 20
EXIT_REFUSED, EXIT_POOL = 3, 4
# Config keys that could redirect an API key to another host or swap the model/account.
FORBIDDEN_CONFIG = re.compile(r'^(model\b|model_provider|openai|chatgpt|auth|cli_auth|forced_|env_key|base_url|'
                              r'experimental_bearer|preferred_auth|profile)', re.I)
FORBIDDEN_FLAGS = {'-m', '--model', '--oss', '--local-provider', '-p', '--profile'}


class PoolError(Exception):
    def __init__(self, message, code=EXIT_POOL):
        super().__init__(message)
        self.code = code


class Terminated(BaseException):
    pass


# ---------------------------------------------------------------- policy and store
def load_policy():
    path = Path(os.environ.get('CODEX_POOL_POLICY') or HERE / 'codex_pool_policy.json')
    try:
        policy = json.loads(path.read_text())  # input-ok: local policy file, small
    except (OSError, ValueError) as error:
        raise PoolError('policy unreadable: %s' % type(error).__name__) from None
    caps = policy.get('caps_usd', {})
    if policy.get('schema') != SCHEMA or not all(isinstance(caps.get(k), (int, float)) and caps[k] > 0
                                                 for k in ('per_run', 'per_key_day', 'total_day', 'total_month')):
        raise PoolError('policy invalid')
    for key in policy['keys']:
        if not ALIAS.match(key['alias']):
            raise PoolError('policy has an unsafe alias')
    return policy


def utcnow():
    return datetime.now(timezone.utc)


def iso(moment):
    return moment.astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


class Store:
    """State JSON plus an append-only JSONL ledger, both under one flock-protected directory."""

    def __init__(self, root=None):
        self.root = Path(root or os.environ.get('CODEX_POOL_STATE_DIR') or Path.home() / '.agent-harness' / 'codex-pool')
        if self.root.is_symlink():
            raise PoolError('state directory cannot be a symlink')
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.chmod(self.root, 0o700)
        self.state_path = self.root / 'state.json'
        self.ledger_path = self.root / 'ledger.jsonl'

    @contextlib.contextmanager
    def lock(self, timeout=60):
        fd = os.open(self.root / 'pool.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        deadline = time.monotonic() + timeout
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() > deadline:
                    os.close(fd)
                    raise PoolError('ledger lock busy')
                time.sleep(0.02)
        try:
            yield
        finally:
            os.close(fd)

    def state(self):
        try:
            data = json.loads(self.state_path.read_text())  # input-ok: private small file
        except FileNotFoundError:
            return {'schema': SCHEMA, 'keys': {}, 'subscription': {}}
        except (OSError, ValueError):
            raise PoolError('state file unreadable; inspect %s' % self.state_path)
        if not isinstance(data, dict):
            raise PoolError('state file invalid')
        data.setdefault('keys', {})
        data.setdefault('subscription', {})
        return data

    def save_state(self, data):
        tmp = self.state_path.with_suffix('.tmp')
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'w') as handle:
            handle.write(json.dumps(data, sort_keys=True, indent=1))
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, self.state_path)

    def rows(self):
        """Every ledger row; any unparsable line fails closed so spend can never be silently under-counted."""
        rows = []
        try:
            with open(self.ledger_path) as handle:
                for number, line in enumerate(handle, 1):
                    try:
                        row = json.loads(line)
                        assert isinstance(row, dict)
                        rows.append(row)
                    except (ValueError, AssertionError):
                        raise PoolError('ledger line %d is corrupt; refusing to run until it is repaired' % number)
        except FileNotFoundError:
            pass
        return rows

    def append(self, row):
        row = {'v': SCHEMA, 'at': iso(utcnow()), **row}
        line = (json.dumps(row, sort_keys=True) + '\n').encode()
        fd = os.open(self.ledger_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
        try:
            os.write(fd, line)
            os.fsync(fd)
        finally:
            os.close(fd)
        return row


def effective_spend(rows):
    """run id -> {alias, at, usd}: a settle row replaces its reserve row; an unsettled reserve counts in full."""
    runs = {}
    for row in rows:
        kind, run = row.get('type'), row.get('run')
        usd = row.get('usd')
        if not isinstance(usd, (int, float)) or usd < 0 or kind not in ('reserve', 'settle', 'probe') or not run:
            raise PoolError('ledger row malformed; refusing to run until it is repaired')
        if kind == 'reserve' and run not in runs:
            runs[run] = {'alias': row.get('alias'), 'at': row.get('at', ''), 'usd': usd}
        elif kind == 'settle':
            entry = runs.setdefault(run, {'alias': row.get('alias'), 'at': row.get('at', '')})
            entry['usd'] = usd
        elif kind == 'probe':
            runs[run] = {'alias': row.get('alias'), 'at': row.get('at', ''), 'usd': usd}
    return runs


def totals(rows, now=None):
    now = now or utcnow()
    day, month = iso(now)[:10], iso(now)[:7]
    out = {'day': 0.0, 'month': 0.0, 'key_day': {}, 'key_month': {}}
    for entry in effective_spend(rows).values():
        if not entry.get('alias') or entry['alias'] == 'subscription':
            continue
        at = entry['at']
        if at[:7] == month:
            out['month'] += entry['usd']
            out['key_month'][entry['alias']] = out['key_month'].get(entry['alias'], 0.0) + entry['usd']
            if at[:10] == day:
                out['day'] += entry['usd']
                out['key_day'][entry['alias']] = out['key_day'].get(entry['alias'], 0.0) + entry['usd']
    return out


# ---------------------------------------------------------------- prices, models
def price_for(policy, model):
    if not MODEL_SHAPE.match(model or ''):
        raise PoolError('model name is not acceptable', EXIT_REFUSED)
    explicit = policy['prices']['models'].get(model)
    if explicit:
        return explicit
    match = FAMILY.match(model)
    if match and match.group(1) in policy['prices']['families']:
        return policy['prices']['families'][match.group(1)]
    raise PoolError('model %s has no price entry; add one to the policy before using it' % model, EXIT_REFUSED)


def cost_of(price, usage):
    inp = int(usage.get('input_tokens', 0) or 0)
    cached = min(int(usage.get('cached_input_tokens', 0) or 0), inp)
    out = int(usage.get('output_tokens', 0) or 0)
    return ((inp - cached) * price['in'] + cached * price['cached'] + out * price['out']) / 1e6


def is_astra(model):
    match = FAMILY.match(model or '')
    return bool(match and match.group(1) == 'astra')


def astra_approved(task):
    """True only when escalation.py holds an approve-top permission record for the task (fail closed)."""
    if not task:
        return False
    try:
        sys.path.insert(0, str(HERE))
        import escalation
        return bool(escalation.Ledger().load(task).get('permission'))
    except Exception:  # any failure to prove approval means no approval
        return False


# ---------------------------------------------------------------- key material
def fetch_key(policy, alias):
    """Read the key from Secret Manager into memory only (never argv of another command, never a file)."""
    if not ALIAS.match(alias):
        raise PoolError('bad alias')
    secret = policy['secret_prefix'] + alias
    gcloud = os.environ.get('CODEX_POOL_GCLOUD_BIN') or shutil.which('gcloud')
    if gcloud:
        cmd = [gcloud, 'secrets', 'versions', 'access', 'latest', '--secret=' + secret, '--project=' + policy['project']]
    else:
        remote = 'gcloud secrets versions access latest --secret=%s --project=%s' % (secret, policy['project'])
        cmd = ['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10', policy['ssh_host'], remote]
    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL, timeout=90)
    except (OSError, subprocess.TimeoutExpired):
        raise PoolError('could not fetch the secret for %s' % alias)
    key = result.stdout.decode('utf-8', 'replace').strip()
    if result.returncode or not KEY_SHAPE.match(key):
        raise PoolError('secret fetch for %s failed or returned an unexpected shape' % alias)
    return key


def scrub(data, key=None):
    if key:
        data = data.replace(key.encode(), b'[REDACTED]')
    return KEY_LIKE.sub(b'[REDACTED]', data)


def sweep_stale_homes(base, max_age=3600):
    for path in base.glob('codex-pool-home-*'):
        try:
            if path.is_dir() and not path.is_symlink() and path.stat().st_uid == os.getuid() and time.time() - path.stat().st_mtime > max_age:
                shutil.rmtree(path, ignore_errors=True)
        except OSError:
            pass


# ---------------------------------------------------------------- failure classification
def parse_events(stdout):
    """(usage dict summed over turn.completed, completed bool, error text from error records)."""
    usage, completed, errors = {}, False, []
    for line in stdout.decode('utf-8', 'replace').splitlines():
        line = line.strip()
        if not line.startswith('{'):
            continue
        try:
            record = json.loads(line)
        except ValueError:
            continue
        if not isinstance(record, dict):
            continue
        kind = record.get('type')
        if kind == 'turn.completed' and isinstance(record.get('usage'), dict):
            completed = True
            for name, value in record['usage'].items():
                if isinstance(value, int) and value >= 0:
                    usage[name] = usage.get(name, 0) + value
        elif kind in ('error', 'turn.failed'):
            error = record.get('error')
            errors.append(str(record.get('message') or (error.get('message') if isinstance(error, dict) else error) or '')[:2000])
    return usage, completed, ' '.join(errors)


def classify_failure(text):
    text = text or ''
    if re.search(r'codex_byok_restricted|cannot be used for codex', text, re.I):
        return 'codex-restricted'  # the key works for the API but its org may not use it with Codex
    if re.search(r'invalid_api_key|incorrect api key|(?<![\w.])401(?!\w|\.\d)|unauthori[sz]ed', text, re.I):
        return '401'
    if re.search(r'insufficient_quota|exceeded your current quota|billing', text, re.I):
        return 'insufficient_quota'
    if re.search(r'usage[ _]limit|hit your .{0,30}limit|usage_limit_reached|try again at', text, re.I):
        return 'usage-limit'
    if re.search(r'rate[_ ]limit|(?<![\w.])429(?!\w|\.\d)|too many requests', text, re.I):
        return 'rate-limited'
    return None


# ---------------------------------------------------------------- child process
def run_child(cmd, env, stdin_bytes, max_seconds, key=None):
    """Run a child in its own process group; return (code, stdout, stderr, timed_out). Output is size-capped."""
    proc = subprocess.Popen(cmd, env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            start_new_session=True)
    buffers = {'out': bytearray(), 'err': bytearray()}

    def pump(stream, name):
        for chunk in iter(lambda: stream.read(65536), b''):
            if len(buffers[name]) < MAX_CAPTURE:
                buffers[name].extend(chunk[:MAX_CAPTURE - len(buffers[name])])

    def feed():
        try:
            proc.stdin.write(stdin_bytes)
        except OSError:
            pass
        finally:
            with contextlib.suppress(OSError):
                proc.stdin.close()

    threads = [threading.Thread(target=pump, args=(proc.stdout, 'out'), daemon=True),
               threading.Thread(target=pump, args=(proc.stderr, 'err'), daemon=True),
               threading.Thread(target=feed, daemon=True)]
    for thread in threads:
        thread.start()
    timed_out = False
    try:
        try:
            proc.wait(timeout=max_seconds)
        except subprocess.TimeoutExpired:
            timed_out = True
    finally:
        if proc.poll() is None:
            with contextlib.suppress(OSError):
                os.killpg(proc.pid, signal.SIGKILL)
            proc.wait()
    for thread in threads[:2]:
        thread.join(timeout=5)
    return proc.returncode, scrub(bytes(buffers['out']), key), scrub(bytes(buffers['err']), key), timed_out


def codex_binary(explicit=None):
    candidates = [explicit, os.environ.get('CODEX_POOL_CODEX_BIN'), shutil.which('codex'),
                  '/Applications/ChatGPT.app/Contents/Resources/codex-cli/bin/codex']
    for candidate in candidates:
        if candidate and os.access(candidate, os.X_OK):
            return candidate
    raise PoolError('no codex executable found on this host')


def validate_passthrough(args):
    """Only `codex exec ...` may be launched, and it may not redirect the key, swap the model or pick another profile."""
    if not args or args[0] != 'exec':
        raise PoolError('arguments after -- must start with `exec`', EXIT_REFUSED)
    i = 1
    while i < len(args):
        token = args[i]
        if token == '-':
            i += 1
            continue
        flag = token.split('=', 1)[0]
        if flag in FORBIDDEN_FLAGS or re.match(r'^-[mp]\S', token):
            raise PoolError('%s is set by codex-pool, not by the caller' % flag, EXIT_REFUSED)
        config = None
        if token in ('-c', '--config'):
            config = args[i + 1] if i + 1 < len(args) else ''
            i += 1
        elif token.startswith('--config='):
            config = token[len('--config='):]
        elif token.startswith('-c') and not token.startswith('--'):
            config = token[2:]
        if config is not None and FORBIDDEN_CONFIG.match(config.split('=', 1)[0].strip()):
            raise PoolError('config key %s is controlled by codex-pool' % config.split('=', 1)[0], EXIT_REFUSED)
        i += 1
    return args[1:]


def base_env():
    env = {k: v for k, v in os.environ.items()
           if k not in ('OPENAI_API_KEY', 'CODEX_API_KEY', 'OPENAI_BASE_URL', 'OPENAI_ORG_ID', 'OPENAI_PROJECT_ID', 'CODEX_HOME')
           and not k.startswith('CODEX_POOL_')}
    return env


# ---------------------------------------------------------------- run
def key_usable(policy, state, entry, now, daybreak_model=None):
    alias = entry['alias']
    saved = state['keys'].get(alias, {})
    enabled = saved.get('enabled', entry.get('enabled', True))
    if not enabled:
        return False
    health = saved.get('health') or {}
    result = health.get('result')
    if result in ('401', 'insufficient_quota', 'codex-restricted'):
        return False
    if result == 'rate-limited' and health.get('until', '') > iso(now):
        return False
    if daybreak_model and daybreak_model not in (saved.get('probe') or {}).get('daybreak', []):
        return False
    return True


def reserve_key(store, policy, purpose, model, effort, price, exclude, daybreak):
    """Choose the least-spent healthy key and write a reserve row, all under the ledger lock."""
    caps = policy['caps_usd']
    reserve = float(price['reserve_usd'])
    if reserve > caps['per_run']:
        raise PoolError('reserve $%.2f for %s exceeds the $%s per-run cap' % (reserve, model, caps['per_run']), EXIT_REFUSED)
    with store.lock():
        state, rows = store.state(), store.rows()
        spent, now = totals(rows), utcnow()
        if spent['day'] + reserve > caps['total_day']:
            raise PoolError('REFUSED: total daily cap $%s would be exceeded (spent $%.2f + reserve $%.2f)' % (caps['total_day'], spent['day'], reserve), EXIT_REFUSED)
        if spent['month'] + reserve > caps['total_month']:
            raise PoolError('REFUSED: monthly cap $%s would be exceeded (spent $%.2f + reserve $%.2f)' % (caps['total_month'], spent['month'], reserve), EXIT_REFUSED)
        usable = [k for k in policy['keys'] if k['alias'] not in exclude and key_usable(policy, state, k, now, model if daybreak else None)]
        if not usable:
            raise PoolError('no usable key (all disabled, failing, excluded%s)' % (' or lacking Daybreak access' if daybreak else ''))
        usable.sort(key=lambda k: (spent['key_day'].get(k['alias'], 0.0), k['alias']))
        for entry in usable:
            alias = entry['alias']
            if spent['key_day'].get(alias, 0.0) + reserve <= caps['per_key_day']:
                run_id = uuid.uuid4().hex
                store.append({'type': 'reserve', 'run': run_id, 'alias': alias, 'source': 'key', 'purpose': purpose,
                              'model': model, 'effort': effort, 'usd': reserve, 'status': 'reserved'})
                return run_id, alias, reserve
        raise PoolError('REFUSED: every usable key is at its $%s daily cap' % caps['per_key_day'], EXIT_REFUSED)


def settle(store, run_id, alias, usd, status, **extra):
    with store.lock():
        store.append({'type': 'settle', 'run': run_id, 'alias': alias, 'usd': round(float(usd), 6), 'status': status, **extra})


def mark_health(store, alias, result, minutes=0, detail=''):
    with store.lock():
        state = store.state()
        health = {'result': result, 'at': iso(utcnow())}
        if detail:
            health['detail'] = scrub(detail.encode()[:300]).decode('utf-8', 'replace')
        if minutes:
            health['until'] = iso(utcnow() + timedelta(minutes=minutes))
        state['keys'].setdefault(alias, {})['health'] = health
        store.save_state(state)


def subscription_blocked(store=None, now=None):
    store = store or Store()
    until = store.state()['subscription'].get('blocked_until')
    return bool(until and until > iso(now or utcnow()))


def mark_subscription_blocked(until=None, store=None, minutes=None):
    """Record that the subscription is quota-blocked; `until` is an ISO UTC string."""
    store = store or Store()
    policy = load_policy()
    if not until:
        until = iso(utcnow() + timedelta(minutes=minutes or policy['subscription']['default_block_minutes']))
    with store.lock():
        state = store.state()
        state['subscription'] = {'blocked_until': until, 'at': iso(utcnow())}
        store.save_state(state)
    return until


def emit(out, err):
    sys.stdout.buffer.write(out)
    sys.stdout.buffer.flush()
    sys.stderr.buffer.write(err)
    sys.stderr.buffer.flush()


def subscription_available():
    home = Path(os.environ.get('CODEX_HOME') or Path.home() / '.codex')
    return (home / 'auth.json').exists()


def run_command(args):
    policy, store = load_policy(), Store()
    purpose, model, effort = args.purpose, args.model, args.effort
    if purpose not in policy['purposes']:
        raise PoolError('unknown purpose', EXIT_REFUSED)
    passthrough = validate_passthrough(args.codex_args)
    price = price_for(policy, model)
    daybreak = model in policy['daybreak_models']
    if daybreak and purpose not in policy['daybreak_purposes']:
        raise PoolError('REFUSED: Daybreak models are only used for %s' % '/'.join(policy['daybreak_purposes']), EXIT_REFUSED)
    if is_astra(model) and not astra_approved(args.task):
        raise PoolError('REFUSED: %s needs an escalation.py approve-top record for --task' % model, EXIT_REFUSED)
    if not re.match(r'^(low|medium|high|xhigh|max)$', effort or ''):
        raise PoolError('unknown effort', EXIT_REFUSED)
    sweep_stale_homes(store.root / 'homes')
    stdin_bytes = b'' if sys.stdin is None or sys.stdin.isatty() else sys.stdin.buffer.read(MAX_STDIN + 1)
    if len(stdin_bytes) > MAX_STDIN:
        raise PoolError('prompt larger than 8 MiB', EXIT_REFUSED)
    codex = codex_binary(args.codex_bin)
    command = [codex, 'exec', '--model', model, '-c', 'model_reasoning_effort=' + effort, *passthrough]
    max_seconds = min(policy['max_run_seconds'], args.max_seconds or policy['max_run_seconds'])

    # 1. Subscription first, unless it is known to be blocked or this is a keys-only / Daybreak run.
    if policy['subscription']['first'] and not args.keys_only and not daybreak and subscription_available() \
            and not subscription_blocked(store):
        code, out, err, timed_out = run_child(command, base_env(), stdin_bytes, max_seconds)
        usage, completed, errors = parse_events(out)
        failure = None if completed or code == 0 else classify_failure(errors + ' ' + err.decode('utf-8', 'replace')[-2000:])
        with store.lock():
            store.append({'type': 'settle', 'run': uuid.uuid4().hex, 'alias': 'subscription', 'source': 'subscription',
                          'purpose': purpose, 'model': model, 'effort': effort, 'usd': 0, 'status': failure or ('ok' if code == 0 else 'failed'),
                          'tokens': usage})
        if failure != 'usage-limit':
            emit(out, err)
            return code
        mark_subscription_blocked(store=store)
        print('codex-pool: subscription is usage-limited; falling back to API keys', file=sys.stderr)

    # 2. API keys, bounded by the caps.
    tried = set()
    last = None
    for _ in range(policy['max_key_attempts']):
        run_id, alias, reserve = reserve_key(store, policy, purpose, model, effort, price, tried, daybreak)
        tried.add(alias)
        result = run_with_key(store, policy, run_id, alias, reserve, price, purpose, model, effort, command, stdin_bytes, max_seconds)
        if result['retry']:
            last = result
            continue
        emit(result['out'], result['err'])
        return result['code']
    if last:
        emit(last['out'], last['err'])
        return last['code']
    raise PoolError('no key attempt completed')


def run_with_key(store, policy, run_id, alias, reserve, price, purpose, model, effort, command, stdin_bytes, max_seconds):
    key, home, code, out, err, status, usd, usage = None, None, 1, b'', b'', 'crashed', reserve, {}
    handlers = {}

    def on_signal(signum, frame):
        raise Terminated()

    for sig in (signal.SIGTERM, signal.SIGHUP, signal.SIGINT):
        with contextlib.suppress(ValueError):
            handlers[sig] = signal.signal(sig, on_signal)
    retry = False
    try:
        key = fetch_key(policy, alias)
        old = os.umask(0o077)
        try:
            (store.root / 'homes').mkdir(mode=0o700, exist_ok=True)
            home = tempfile.mkdtemp(prefix='codex-pool-home-', dir=store.root / 'homes')  # private dir, not /tmp
        finally:
            os.umask(old)
        os.chmod(home, 0o700)
        env = {**base_env(), 'CODEX_HOME': home}
        login = [command[0], 'login', '--with-api-key']
        lcode, _, _, _ = run_child(login, env, (key + '\n').encode(), 60, key)
        if lcode != 0:
            status, usd, retry = 'login_failed', 0.0, True
            err = b'codex-pool: codex login with the pooled key failed\n'
        else:
            code, out, err, timed_out = run_child(command, env, stdin_bytes, max_seconds, key)
            usage, completed, errors = parse_events(out)
            failure = None if completed else classify_failure(errors + ' ' + err.decode('utf-8', 'replace')[-2000:])
            if completed:
                usd = cost_of(price, usage)
                status = 'ok' if code == 0 else 'failed_after_usage'
                if usd > reserve:
                    status += '_over_reserve'
            elif failure in ('401', 'insufficient_quota', 'rate-limited', 'codex-restricted'):
                usd, status, retry = 0.0, failure, True
                mark_health(store, alias, failure, policy['rate_limit_cooldown_minutes'] if failure == 'rate-limited' else 0,
                            detail=errors or err.decode('utf-8', 'replace')[-300:])
            else:
                # No usage report and no classified failure: keep the full reserve, never assume it was free.
                status = 'timeout_unknown_usage' if timed_out else ('ok_no_usage' if code == 0 else 'failed_unknown_usage')
    except PoolError as error:
        status, usd, retry = 'fetch_failed', 0.0, True
        err = ('codex-pool: %s\n' % error).encode()
    except Terminated:
        status = 'terminated_unknown_usage'
        err = b'codex-pool: terminated\n'
        code = 143
    finally:
        for sig, previous in handlers.items():
            with contextlib.suppress(ValueError):
                signal.signal(sig, previous)
        if home:
            shutil.rmtree(home, ignore_errors=True)
        settle(store, run_id, alias, usd, status, tokens=usage)
    if status == 'terminated_unknown_usage':
        raise SystemExit(143)
    return {'retry': retry, 'code': code if not retry else EXIT_POOL, 'out': out, 'err': scrub(err, key)}


# ---------------------------------------------------------------- probe
def http_json(method, url, key, body=None):
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(url, data=data, method=method)
    request.add_header('Authorization', 'Bearer ' + key)
    request.add_header('Content-Type', 'application/json')
    try:
        with urllib.request.urlopen(request, timeout=45) as response:
            return response.status, json.loads(response.read(2 << 20) or b'{}')
    except urllib.error.HTTPError as error:
        try:
            return error.code, json.loads(error.read(1 << 20) or b'{}')
        except ValueError:
            return error.code, {}
    except (urllib.error.URLError, OSError, ValueError):
        return 0, {}


def probe_alias(store, policy, alias):
    base = os.environ.get('CODEX_POOL_API_BASE') or policy['api_base']
    key = fetch_key(policy, alias)
    result, code_text = 'error', None
    try:
        status, listing = http_json('GET', base + '/v1/models', key)
        cost, relevant, daybreak = 0.0, [], []
        if status == 401:
            result = '401'
        elif status == 200:
            names = {m.get('id') for m in listing.get('data', []) if isinstance(m, dict)}
            relevant = sorted(n for n in names if isinstance(n, str) and FAMILY.match(n))
            for name in policy['daybreak_models']:
                if http_json('GET', base + '/v1/models/' + name, key)[0] == 200:
                    daybreak.append(name)
            call, body = http_json('POST', base + '/v1/responses', key,
                                   {'model': policy['probe_model'], 'input': 'ok', 'max_output_tokens': 16})
            error = body.get('error') if isinstance(body.get('error'), dict) else {}
            code_text = error.get('code') or error.get('type')
            if call == 200:
                result = 'ok'
                cost = cost_of(price_for(policy, policy['probe_model']), body.get('usage') or {})
            elif call == 429 and code_text == 'insufficient_quota':
                result = 'insufficient_quota'
            elif call == 429:
                result = 'rate-limited'
            elif call == 401:
                result = '401'
        else:
            result = 'error'
        with store.lock():
            state = store.state()
            record = state['keys'].setdefault(alias, {})
            record['probe'] = {'at': iso(utcnow()), 'result': result, 'http': status, 'daybreak': daybreak, 'relevant': relevant}
            if (record.get('health') or {}).get('result') != 'codex-restricted' or result != 'ok':
                record['health'] = {'result': result, 'at': iso(utcnow())}  # API-ok never clears a Codex restriction
            store.save_state(state)
            store.append({'type': 'probe', 'run': uuid.uuid4().hex, 'alias': alias, 'usd': round(cost, 6), 'status': result,
                          'model': policy['probe_model']})
        return result
    finally:
        del key


# ---------------------------------------------------------------- commands
def probe_command(args):
    policy, store = load_policy(), Store()
    aliases = [args.alias] if args.alias else [k['alias'] for k in policy['keys']]
    known = {k['alias'] for k in policy['keys']}
    for alias in aliases:
        if alias not in known:
            raise PoolError('unknown alias', EXIT_REFUSED)
        try:
            print('%-24s %s' % (alias, probe_alias(store, policy, alias)))
        except PoolError as error:
            print('%-24s error (%s)' % (alias, error))
    return 0


def status_rows(policy, store):
    state, rows, now = store.state(), store.rows(), utcnow()
    spent = totals(rows, now)
    out = []
    for entry in policy['keys']:
        alias = entry['alias']
        saved = state['keys'].get(alias, {})
        probe = saved.get('probe') or {}
        health = (saved.get('health') or {}).get('result') or 'unprobed'
        out.append({'alias': alias, 'enabled': bool(saved.get('enabled', entry.get('enabled', True))), 'health': health,
                    'last_probe': probe.get('result', '-'), 'probe_at': probe.get('at', '-'),
                    'daybreak': ','.join(probe.get('daybreak', [])) or ('none' if probe else '?'),
                    'today_usd': round(spent['key_day'].get(alias, 0.0), 4), 'month_usd': round(spent['key_month'].get(alias, 0.0), 4)})
    return out, spent, state


def status_command(args):
    policy, store = load_policy(), Store()
    rows, spent, state = status_rows(policy, store)
    caps = policy['caps_usd']
    until = state['subscription'].get('blocked_until')
    sub = 'BLOCKED until %s' % until if until and until > iso(utcnow()) else 'available (first choice)'
    if args.json:
        print(json.dumps({'subscription': sub, 'keys': rows, 'today_usd': spent['day'], 'month_usd': spent['month'], 'caps': caps}, indent=1))
        return 0
    print('subscription: %s' % sub)
    print('%-22s %-8s %-18s %-20s %-8s %9s %9s' % ('ALIAS', 'ENABLED', 'HEALTH', 'LAST PROBE', 'DAYBREAK', 'TODAY $', 'MONTH $'))
    for row in rows:
        print('%-22s %-8s %-18s %-20s %-8s %9.4f %9.4f' % (
            row['alias'], 'yes' if row['enabled'] else 'DISABLED', row['health'], row['probe_at'], row['daybreak'][:8],
            row['today_usd'], row['month_usd']))
    print('per-key day cap $%s | total today $%.4f / $%s | month $%.4f / $%s | per-run cap $%s'
          % (caps['per_key_day'], spent['day'], caps['total_day'], spent['month'], caps['total_month'], caps['per_run']))
    return 0


def toggle_command(args, enabled):
    policy, store = load_policy(), Store()
    if args.alias not in {k['alias'] for k in policy['keys']}:
        raise PoolError('unknown alias', EXIT_REFUSED)
    with store.lock():
        state = store.state()
        state['keys'].setdefault(args.alias, {})['enabled'] = enabled
        if enabled:
            state['keys'][args.alias].pop('health', None)  # an explicit enable is the way to clear a stuck failure mark
        store.save_state(state)
    print('%s %s' % (args.alias, 'enabled' if enabled else 'disabled'))
    return 0


def block_command(args):
    store = Store()
    if args.clear:
        with store.lock():
            state = store.state()
            state['subscription'] = {}
            store.save_state(state)
        print('subscription block cleared')
        return 0
    if not args.until:
        raise PoolError('give --until or --clear', EXIT_REFUSED)
    try:
        moment = datetime.fromisoformat(args.until.replace('Z', '+00:00'))
    except ValueError:
        raise PoolError('--until must be ISO 8601', EXIT_REFUSED)
    if moment.tzinfo is None:
        moment = moment.astimezone()  # naive input means this host's local time
    print('subscription blocked until %s' % mark_subscription_blocked(iso(moment), store=store))
    return 0


def install_command(args):
    target = Path(args.dir or Path.home() / '.agent-harness' / 'bin')
    target.mkdir(parents=True, exist_ok=True)
    script = Path(__file__).resolve()
    wrapper = target / 'codex-pool'
    wrapper.write_text('#!/bin/sh\nexec python3 -I %s "$@"\n' % shell_quote(str(script)))
    os.chmod(wrapper, 0o755)
    print('installed %s' % wrapper)
    return 0


def shell_quote(text):
    return "'" + text.replace("'", "'\\''") + "'"


def build_parser():
    parser = argparse.ArgumentParser(prog='codex-pool', description=__doc__.split('\n\n')[0])
    sub = parser.add_subparsers(dest='command', required=True)
    s = sub.add_parser('status', help='key table, probe results, ledger spend vs caps')
    s.add_argument('--json', action='store_true')
    p = sub.add_parser('probe', help='models list + 16-token call; records result and Daybreak access')
    p.add_argument('--alias')
    r = sub.add_parser('run', help='run `codex exec` through the pool: codex-pool run --purpose P --model M --effort E -- exec ...')
    r.add_argument('--purpose', required=True, choices=('build', 'review', 'redteam'))
    r.add_argument('--model', required=True)
    r.add_argument('--effort', default='medium')
    r.add_argument('--task', help='ladder task key (needed for Astra: escalation approve-top)')
    r.add_argument('--keys-only', action='store_true', help='skip the subscription attempt')
    r.add_argument('--codex-bin')
    r.add_argument('--max-seconds', type=int)
    r.add_argument('codex_args', nargs=argparse.REMAINDER)
    for name in ('enable', 'disable'):
        e = sub.add_parser(name)
        e.add_argument('--alias', required=True)
    b = sub.add_parser('subscription-block', help='mark the ChatGPT subscription quota-blocked until a time')
    b.add_argument('--until')
    b.add_argument('--clear', action='store_true')
    i = sub.add_parser('install', help='write the ~/.agent-harness/bin/codex-pool wrapper')
    i.add_argument('--dir')
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    if args.command == 'run':
        if args.codex_args and args.codex_args[0] == '--':
            args.codex_args = args.codex_args[1:]
    try:
        if args.command == 'status':
            return status_command(args)
        if args.command == 'probe':
            return probe_command(args)
        if args.command == 'run':
            return run_command(args)
        if args.command in ('enable', 'disable'):
            return toggle_command(args, args.command == 'enable')
        if args.command == 'subscription-block':
            return block_command(args)
        return install_command(args)
    except PoolError as error:
        print('codex-pool: %s' % error, file=sys.stderr)
        return error.code


if __name__ == '__main__':
    sys.exit(main())
