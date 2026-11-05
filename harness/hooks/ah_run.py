#!/usr/bin/env python3
"""ah-run: every agent command tracked, attributed and killable (GoodQA goodqa#14548, G10 item I5).

`ah-run --task K --agent A --ticket T --session S [--token X] [--readonly] -- CMD...` starts CMD in its own
process group (macOS) or a `systemd-run --user --scope` unit (Linux, when the user bus answers), with
stdin, stdout, stderr and cwd inherited, forwards SIGTERM/SIGINT/SIGHUP to the whole group (SIGKILL
after 2 s), kills the group when its parent dies, passes the exit status through (128+N on a signal),
and writes a ledger row at start and end under ~/.agent-harness/reserve/ledger/ holding digests, never
the command. `ah-run kill --task K|--agent A [--pause|--resume]` acts on the union of the ledger
groups, every same-uid process whose environment carries the task, and every process whose ancestry
reaches a ledger pid, each checked by its start token, excluding itself, Claude Code and the hooks.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import shutil
import signal
import subprocess
import sys
import threading
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import usage_guard  # noqa: E402  (SECRET detector; liveness helpers when the guard has them)


def host_identity():
    import socket
    return getattr(usage_guard, 'host_identity', lambda: socket.gethostname()[:255])()


def pid_exists(pid):
    if hasattr(usage_guard, 'pid_exists'):
        return usage_guard.pid_exists(pid)
    if type(pid) is not int or pid <= 0 or pid > 2 ** 31 - 1:
        return None
    try:
        os.kill(pid, 0); return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except (OSError, OverflowError, ValueError):
        return None


def process_start_token(pid):
    if hasattr(usage_guard, 'process_start_token'):
        return usage_guard.process_start_token(pid)
    try:
        after = Path('/proc/%d/stat' % pid).read_text().rsplit(')', 1)[1].split()  # input-ok: one-line kernel file
        return 'proc:' + after[19]
    except (OSError, IndexError, ValueError):
        pass
    try:
        probe = subprocess.run(['ps', '-p', str(pid), '-o', 'lstart='], capture_output=True, text=True, timeout=5,
                               env={**os.environ, 'TZ': 'UTC', 'LC_ALL': 'C', 'LANG': 'C'})
        if probe.returncode == 0 and probe.stdout.strip():
            return 'ps:' + ' '.join(probe.stdout.split())[:64]
    except (OSError, subprocess.SubprocessError, ValueError):
        pass
    return None

SCHEMA = 1
ENV_KEYS = ('AGENT_HARNESS_TASK', 'AGENT_ID', 'AGENT_HARNESS_TICKET', 'AGENT_HARNESS_SESSION', 'AGENT_HARNESS_RUN_ID')
KILL_GRACE = 2.0
PARENT_POLL = 1.0
MAX_ROW = 65536
MAX_LEDGER_ROWS_SCANNED = 20000
PROTECTED_COMMS = ('claude', 'codex', 'deadman.py', 'ah_run.py', 'ah-run')
HOOK_MARKERS = ('/.claude/hooks/', '/.codex/agent-harness/')
SAFE_KEY = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._:/#-]{0,127}$')
BEARER = re.compile(r'(?i)(bearer\s+)([A-Za-z0-9._~+/=-]{4,})')
FLAG_VALUE = re.compile(r'(?i)((?:^|\s)-{1,2}(?:token|password|passwd|secret|api[-_]?key|access[-_]?token)(?:[=\s]+))(\S+)')


def now():
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat()


def reserve_root():
    root = Path(os.environ.get('AGENT_HARNESS_RESERVE_DIR') or Path.home() / '.agent-harness' / 'reserve')
    if root.is_symlink():
        raise RuntimeError('reserve directory cannot be a symlink')
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    (root / 'ledger').mkdir(mode=0o700, exist_ok=True)
    (root / 'ledger' / 'pending').mkdir(mode=0o700, exist_ok=True)
    return root


def mask_argv(text, limit=512):
    """Mask credentials in a command line: Bearer tokens, credential flag values, then the SECRET detector."""
    if not isinstance(text, str):
        text = ' '.join(str(part) for part in (text or ()))
    masked = BEARER.sub(lambda m: m.group(1) + '****', text)
    masked = FLAG_VALUE.sub(lambda m: m.group(1) + '****', masked)
    masked = usage_guard.SECRET.sub('****', masked)
    masked = ''.join(ch if ch >= ' ' else ' ' for ch in masked)
    return masked[:limit]


def digest(value):
    return hashlib.sha256(value if isinstance(value, bytes) else str(value).encode('utf-8', 'replace')).hexdigest()


def safe_key(value, default):
    return value if isinstance(value, str) and SAFE_KEY.fullmatch(value) else default


def pid_tree(pgid):
    """Masked pid tree of a process group: pid, ppid, masked comm/args; never the full command."""
    try:
        out = subprocess.run(['ps', '-axo', 'pid=,ppid=,pgid=,args='], capture_output=True, text=True, timeout=5,
                             env={**os.environ, 'LC_ALL': 'C'})
    except (OSError, subprocess.SubprocessError):
        return []
    rows = []
    for line in out.stdout.splitlines()[:4096]:
        parts = line.split(None, 3)
        if len(parts) < 3:
            continue
        try:
            pid, ppid, group = int(parts[0]), int(parts[1]), int(parts[2])
        except ValueError:
            continue
        if group == pgid:
            rows.append({'pid': pid, 'ppid': ppid, 'args_masked': mask_argv(parts[3] if len(parts) > 3 else '', 120)})
    return rows[:256]


class Ledger:
    def __init__(self, root=None):
        self.root = Path(root) if root else reserve_root()
        self.dir = self.root / 'ledger'

    def path(self, run_id):
        return self.dir / (run_id + '.json')

    def write(self, run_id, row):
        body = json.dumps(row, sort_keys=True, separators=(',', ':')).encode('utf-8')
        if len(body) > MAX_ROW:
            row = {**row, 'pid_tree': row.get('pid_tree', [])[:16], 'truncated': True}
            body = json.dumps(row, sort_keys=True, separators=(',', ':')).encode('utf-8')[:MAX_ROW]
        tmp = self.path(run_id).with_suffix('.tmp')
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as handle:
            handle.write(body); handle.flush(); os.fsync(handle.fileno())
        os.replace(tmp, self.path(run_id))

    def read(self, run_id):
        path = self.path(run_id)
        info = os.stat(path, follow_symlinks=False)
        if not os.path.isfile(path) or os.path.islink(path) or info.st_size > MAX_ROW:
            raise ValueError('ledger row unsafe')
        return json.loads(path.read_bytes())  # input-ok: size checked above

    def rows(self):
        for number, path in enumerate(sorted(self.dir.glob('*.json'))):
            if number >= MAX_LEDGER_ROWS_SCANNED:
                break
            try:
                yield self.read(path.stem)
            except (OSError, ValueError):
                continue

    def live_rows(self, *, task=None, agent=None):
        for row in self.rows():
            if row.get('end') is not None:
                continue
            if task is not None and row.get('task') != task:
                continue
            if agent is not None and row.get('agent') != agent:
                continue
            yield row


def user_bus_answers():
    if sys.platform != 'linux' or shutil.which('systemd-run') is None:
        return False
    try:
        probe = subprocess.run(['systemctl', '--user', 'is-system-running'], capture_output=True, text=True, timeout=3)
        return probe.returncode == 0 or probe.stdout.strip() in ('running', 'degraded')
    except (OSError, subprocess.SubprocessError):
        return False


def shell_for_command():
    """The shell Claude Code uses, with its snapshot sourced when one is named."""
    shell = os.environ.get('CLAUDE_CODE_SHELL') or os.environ.get('SHELL') or '/bin/bash'
    if not os.path.isabs(shell) or not os.access(shell, os.X_OK):
        shell = '/bin/bash' if os.access('/bin/bash', os.X_OK) else '/bin/sh'
    snapshot = os.environ.get('CLAUDE_CODE_SHELL_SNAPSHOT')
    prelude = ''
    if snapshot and os.path.isfile(snapshot):
        prelude = 'source %s >/dev/null 2>&1 || true\n' % shell_quote(snapshot)
    return shell, prelude


def shell_quote(value):
    return "'" + str(value).replace("'", "'\\''") + "'"


def read_command(args):
    """The command text, from argv, a base64 argument or the pending payload file (unlinked after reading)."""
    if args.cmd_b64:
        return base64.b64decode(args.cmd_b64.encode('ascii')).decode('utf-8', 'replace')
    if args.cmd_file:
        path = Path(args.cmd_file)
        info = os.stat(path, follow_symlinks=False)
        if os.path.islink(path) or info.st_size > (1 << 20):
            raise RuntimeError('command payload unsafe or oversized')
        text = path.read_bytes().decode('utf-8', 'replace')  # input-ok: size checked above
        try:
            os.unlink(path)
        except OSError:
            pass
        return text
    return ' '.join(args.command)


PENDING_TTL = 600
TOKEN_RE = re.compile(r'^[A-Za-z0-9_-]{16,64}$')


def pending_dir(root):
    return Path(root) / 'ledger' / 'pending'


def mint_pending(root, command, task, agent, session='none'):
    """Write a single-use pending row for a hook-wrapped command; return the token."""
    token = secrets.token_urlsafe(18)
    row = {'schema': SCHEMA, 'command_sha256': digest(command), 'task': task, 'agent': agent, 'session': session,
           'created': time.time(), 'expires': time.time() + PENDING_TTL}
    directory = pending_dir(root)
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    tmp = directory / (token + '.tmp')
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as handle:
        handle.write(json.dumps(row, sort_keys=True).encode('utf-8')); handle.flush(); os.fsync(handle.fileno())
    os.replace(tmp, directory / (token + '.json'))
    return token


def consume_pending(root, token, command, task, agent):
    """(attribution, reason): `verified` only for a live, unreplayed token bound to this command, task and agent."""
    if not TOKEN_RE.fullmatch(token or ''):
        return 'unverified', 'token-malformed'
    path = pending_dir(root) / (token + '.json')
    claim = path.with_name('%s.claimed.%d' % (token, os.getpid()))
    try:
        os.rename(path, claim)  # atomic: of two racing consumers exactly one wins
    except OSError:
        return 'unverified', 'token-missing-or-replayed'
    try:
        row = json.loads(claim.read_bytes()[:MAX_ROW])
    except (OSError, ValueError):
        return 'unverified', 'token-row-unreadable'
    finally:
        try:
            os.unlink(claim)
        except OSError:
            pass
    if not isinstance(row, dict) or row.get('expires', 0) < time.time():
        return 'unverified', 'token-expired'
    if row.get('command_sha256') != digest(command):
        return 'unverified', 'token-command-mismatch'
    if row.get('task') != task or row.get('agent') != agent:
        return 'unverified', 'token-attribution-mismatch'
    return 'verified', None


def launch(args):
    ledger = Ledger()
    run_id = secrets.token_hex(16)
    command = read_command(args)
    task = safe_key(args.task, 'auto-' + digest(command)[:16])
    agent = safe_key(args.agent, 'main')
    ticket = safe_key(args.ticket, 'none')
    session = safe_key(args.session, 'none')
    shell, prelude = shell_for_command()
    env = {**os.environ, 'AGENT_HARNESS_TASK': task, 'AGENT_ID': agent, 'AGENT_HARNESS_TICKET': ticket,
           'AGENT_HARNESS_SESSION': session, 'AGENT_HARNESS_RUN_ID': run_id}
    if args.readonly:
        env['AGENT_HARNESS_READONLY'] = '1'
    env['AH_SUPERVISOR'] = str(os.getpid())
    # A watchdog inside the child's own group: when the supervisor (this process) disappears, even by
    # SIGKILL, the group terminates itself; it exits on its own once the group is gone.
    watchdog = ('( while kill -0 "$AH_SUPERVISOR" 2>/dev/null; do sleep 1; done; '
                'kill -TERM -- -$$ 2>/dev/null; sleep %d; kill -KILL -- -$$ 2>/dev/null ) &\n' % int(KILL_GRACE))
    script = prelude + watchdog + command
    use_unit = user_bus_answers() and not args.no_unit
    unit = 'ah-run-' + run_id if use_unit else None
    argv = [shell, '-c', script]
    if use_unit:
        argv = ['systemd-run', '--user', '--scope', '--quiet', '--collect', '--unit', unit, *argv]
    if args.token == 'via-hook-ssh':
        attribution, why = 'hook-ssh', None
    elif args.token:
        attribution, why = consume_pending(ledger.root, args.token, command, task, agent)
    else:
        attribution, why = 'unverified', 'no-token'
    if args.readonly and attribution == 'unverified':
        print('ah-run: a read-only agent run needs a hook token; refused', file=sys.stderr)
        return 126
    row = {'schema': SCHEMA, 'run_id': run_id, 'task': task, 'agent': agent, 'ticket': ticket, 'session': session,
           'attribution': attribution, 'attribution_reason': why, 'readonly': bool(args.readonly), 'host': host_identity(),
           'command_sha256': digest(command), 'command_class': args.command_class or 'unclassified',
           'cwd_sha256': digest(os.getcwd()), 'started_at': now(), 'supervisor_pid': os.getpid(),
           'supervisor_start': process_start_token(os.getpid()), 'unit': unit, 'end': None}
    try:
        child = subprocess.Popen(argv, env=env, start_new_session=True)
    except OSError as error:
        row.update(end=now(), exit_code=127, error=type(error).__name__)
        ledger.write(run_id, row)
        print('ah-run: cannot start the shell: %s' % type(error).__name__, file=sys.stderr)
        return 127
    pgid = child.pid  # a new session makes the child its own group leader
    row.update(pid=child.pid, pgid=pgid, start_token=process_start_token(child.pid))
    ledger.write(run_id, row)
    state = {'signal': None, 'parent_died': False}

    def forward(signum, frame):
        state['signal'] = signum
        kill_group(pgid, signum if signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP) else signal.SIGTERM)

    for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        signal.signal(signum, forward)
    parent = os.getppid()

    def watch_parent():
        while child.poll() is None:
            time.sleep(PARENT_POLL)
            if os.getppid() != parent:
                state['parent_died'] = True
                kill_group(pgid, signal.SIGTERM)
                time.sleep(KILL_GRACE)
                kill_group(pgid, signal.SIGKILL)
                return

    threading.Thread(target=watch_parent, daemon=True).start()
    try:
        code = child.wait()
    except KeyboardInterrupt:
        kill_group(pgid, signal.SIGTERM); code = child.wait()
    if state['signal'] is not None and child.poll() is None:
        time.sleep(KILL_GRACE); kill_group(pgid, signal.SIGKILL)
    tree = pid_tree(pgid)
    kill_group(pgid, signal.SIGTERM)  # leftovers of a finished leader are not part of the result
    usage = resource_usage()
    row.update(end=now(), exit_code=code, signal=state['signal'], parent_died=state['parent_died'],
               rusage=usage, pid_tree=tree)
    ledger.write(run_id, row)
    if code < 0:
        return 128 + (-code)
    return code


def resource_usage():
    try:
        import resource
        usage = resource.getrusage(resource.RUSAGE_CHILDREN)
        return {'utime': round(usage.ru_utime, 3), 'stime': round(usage.ru_stime, 3), 'maxrss': usage.ru_maxrss}
    except (ImportError, OSError):
        return {}


def kill_group(pgid, signum):
    try:
        os.killpg(pgid, signum)
    except (ProcessLookupError, PermissionError, OSError):
        pass


def process_table():
    """pid, ppid, pgid, uid, comm and masked args for every process the user can see."""
    try:
        out = subprocess.run(['ps', '-axo', 'pid=,ppid=,pgid=,uid=,comm=,args='], capture_output=True, text=True,
                             timeout=5, env={**os.environ, 'LC_ALL': 'C'})
    except (OSError, subprocess.SubprocessError):
        return {}
    table = {}
    for line in out.stdout.splitlines()[:8192]:
        parts = line.split(None, 5)
        if len(parts) < 5:
            continue
        try:
            pid, ppid, pgid, uid = int(parts[0]), int(parts[1]), int(parts[2]), int(parts[3])
        except ValueError:
            continue
        table[pid] = {'pid': pid, 'ppid': ppid, 'pgid': pgid, 'uid': uid, 'comm': parts[4],
                      'args': parts[5] if len(parts) > 5 else ''}
    return table


def process_env(pid):
    """Only the attribution keys from a process environment; nothing else is read into memory for long."""
    found = {}
    try:
        if sys.platform == 'linux':
            raw = Path('/proc/%d/environ' % pid).read_bytes()  # input-ok: kernel file bounded by the env size
            for item in raw.split(b'\0'):
                key, _, value = item.partition(b'=')
                if key.decode('ascii', 'replace') in ENV_KEYS:
                    found[key.decode('ascii')] = value.decode('utf-8', 'replace')[:128]
        else:
            out = subprocess.run(['ps', '-E', '-o', 'command=', '-p', str(pid)], capture_output=True, text=True, timeout=5,
                                 env={**os.environ, 'LC_ALL': 'C'})
            for token in out.stdout.split():
                key, _, value = token.partition('=')
                if key in ENV_KEYS and value:
                    found[key] = value[:128]
    except (OSError, subprocess.SubprocessError, UnicodeError):
        return {}
    return found


def protected(entry, own_pgid):
    if entry['pgid'] == own_pgid or entry['pid'] == os.getpid():
        return True
    comm = entry['comm'].rsplit('/', 1)[-1]
    if comm in PROTECTED_COMMS:
        return True
    return any(marker in entry['args'] for marker in HOOK_MARKERS)


def targets_for(ledger, table, *, task=None, agent=None):
    """Union of ledger groups, env-attributed processes and ledger ancestry, with start-token checks."""
    own_pgid = os.getpgid(0)
    selected, skipped, units = {}, [], []
    rows = list(ledger.live_rows(task=task, agent=agent))
    row_pids = {}
    for row in rows:
        pid, token = row.get('pid'), row.get('start_token')
        if row.get('unit'):
            units.append(row['unit'])
        if isinstance(pid, int) and pid_exists(pid) and (token is None or process_start_token(pid) == token):
            row_pids[pid] = row
        else:
            skipped.append({'pid': pid, 'why': 'ledger pid gone or reused'})
    tasks = {task} if task else {row.get('task') for row in rows if row.get('task')}
    for entry in table.values():
        if entry['uid'] != os.getuid():
            continue
        reason = None
        if entry['pgid'] in {row['pgid'] for row in row_pids.values() if isinstance(row.get('pgid'), int)}:
            reason = 'ledger group'
        else:
            env = process_env(entry['pid'])
            if env.get('AGENT_HARNESS_TASK') in tasks or (agent and env.get('AGENT_ID') == agent):
                reason = 'attribution env'
            else:
                cursor, hops = entry['ppid'], 0
                while cursor in table and hops < 32:
                    if cursor in row_pids:
                        reason = 'ledger ancestry'
                        break
                    cursor, hops = table[cursor]['ppid'], hops + 1
        if reason is None:
            continue
        if protected(entry, own_pgid):
            skipped.append({'pid': entry['pid'], 'why': 'protected: ' + entry['comm']})
            continue
        selected[entry['pid']] = {'pid': entry['pid'], 'pgid': entry['pgid'], 'comm': entry['comm'], 'why': reason}
    return selected, skipped, units


def kill(args):
    ledger = Ledger()
    table = process_table()
    selected, skipped, units = targets_for(ledger, table, task=args.task, agent=args.agent)
    signum = signal.SIGSTOP if args.pause else signal.SIGCONT if args.resume else signal.SIGTERM
    signalled = []
    for entry in selected.values():
        if args.pause and (entry['comm'].endswith('wal.py') or 'wal_note.py' in table[entry['pid']]['args'] or 'wal.py' in table[entry['pid']]['args']):
            skipped.append({'pid': entry['pid'], 'why': 'never paused: WAL writer'})
            continue
        try:
            os.kill(entry['pid'], signum)
            signalled.append({**entry, 'signal': int(signum)})
        except (ProcessLookupError, PermissionError):
            skipped.append({'pid': entry['pid'], 'why': 'gone or not ours'})
    if units and not args.pause and not args.resume and shutil.which('systemctl'):
        for unit in units:
            subprocess.run(['systemctl', '--user', 'kill', '--signal=TERM', unit], capture_output=True, timeout=5)
    if signalled and signum == signal.SIGTERM:
        time.sleep(KILL_GRACE)
        for entry in signalled:
            if pid_exists(entry['pid']):
                try: os.kill(entry['pid'], signal.SIGKILL)
                except (ProcessLookupError, PermissionError): pass
    report = {'task': args.task, 'agent': args.agent, 'action': 'pause' if args.pause else 'resume' if args.resume else 'kill',
              'signalled': signalled, 'skipped': skipped, 'units': units}
    print(json.dumps(report, sort_keys=True))
    return 0


def ledger_cmd(args):
    ledger = Ledger()
    rows = [row for row in ledger.rows() if (not args.task or row.get('task') == args.task)]
    if args.live:
        rows = [row for row in rows if row.get('end') is None]
    print(json.dumps(rows[-args.limit:], sort_keys=True, indent=1))
    return 0


# ---------------------------------------------------------------------------------------------------------
# PreToolUse Bash hook: evaluate permission rules against the ORIGINAL command, classify escapes, and wrap
# the command into `ah-run` (updatedInput). Claude Code evaluates its own rules against the REWRITTEN input
# (EXP2), so the hook must be the one that denies; it always exits 0 and degrades to `ask` on any error.
# ---------------------------------------------------------------------------------------------------------

INLINE_LIMIT = 64 * 1024
PAYLOAD_CAP = 1 << 20
AH_RUN_RULE = re.compile(r'(?:^|[\s/*])(?:ah-run|ah_run\.py)(?:$|[\s:*])')
ASSIGNMENT = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*=')
ENV_PREFIX = re.compile(r'''^(?:[A-Za-z_][A-Za-z0-9_]*=(?:'[^']*'|"[^"]*"|\S*)\s+)+''')
WRAPPER_PREFIX = re.compile(r'^(?:timeout\s+(?:-\S+\s+)*\d\S*|nice(?:\s+-n\s*\d+|\s+-\d+)?|nohup|time|command|builtin|env)\s+')
KEYWORD_PREFIX = re.compile(r'^(?:then|do|else|elif|if|while|until|!|\{)\s+')
ESCAPE_NAMES = frozenset(('nohup', 'setsid', 'disown', 'screen', 'tmux', 'at', 'batch', 'crontab', 'osascript', 'coproc'))
LAUNCHCTL_ESCAPES = frozenset(('submit', 'bootstrap', 'load', 'kickstart'))
TASK_TOKEN = re.compile(r'\[task:([A-Za-z0-9][A-Za-z0-9._:/#-]{0,127})\]')
AH_PREFIX = re.compile(r'^\s*(?:(?:\S*/)?python3?(?:\.\d+)?\s+)?\S*(?:ah_run\.py|ah-run)(?=\s)')
RECOVERY_SCRIPTS = frozenset(('reserve.py', 'reclaim.py'))
POLICY_SELFCHECK_FIX = 'python3 harness/install.py --apply --role ROLE'


def _skip_group(text, i):
    """Index just past the ')' that closes the '(' at text[i-1]... called with i at the opening paren."""
    depth, n = 0, len(text)
    while i < n:
        if text[i] == '(':
            depth += 1
        elif text[i] == ')':
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return n


def inner_commands(text):
    """Bodies of $(...), `...`, <(...) and >(...) outside single quotes (inside double quotes too)."""
    found, i, n, quote = [], 0, len(text), None
    while i < n:
        ch = text[i]
        if quote == "'":
            quote = None if ch == "'" else quote
            i += 1
        elif ch == '\\':
            i += 2
        elif ch == "'" and quote is None:
            quote = "'"; i += 1
        elif ch == '"':
            quote = None if quote == '"' else '"'; i += 1
        elif ch == '`':
            end = text.find('`', i + 1)
            end = n if end < 0 else end
            found.append(text[i + 1:end]); i = end + 1
        elif text.startswith('$(', i) or (quote is None and text[i:i + 2] in ('<(', '>(')):
            end = _skip_group(text, i + 1)
            found.append(text[i + 2:end - 1]); i = end
        else:
            i += 1
    return found


def _strip_heredocs(command):
    """Heredoc bodies removed (markers left behind), plus (body, quoted) pairs. Reuses commit_policy."""
    import commit_policy
    return commit_policy._heredocs(command)


def _tokens(text):
    import commit_policy
    return commit_policy.tokenize(text)


def _mask_redirect_amps(text):
    """Turn the '&' of >&, <&, &> and &>> into \\x01 outside quotes so it is not read as a background operator."""
    out, i, n, quote = [], 0, len(text), None
    while i < n:
        ch = text[i]
        if quote == "'":
            quote = None if ch == "'" else quote
        elif quote == '"':
            if ch == '\\' and i + 1 < n:
                out.append(ch); i += 1; ch = text[i]
            elif ch == '"':
                quote = None
        elif ch == '\\' and i + 1 < n:
            out.append(ch); i += 1; ch = text[i]
        elif ch in '\'"':
            quote = ch
        elif ch == '&' and ((i > 0 and text[i - 1] in '<>') or text[i + 1:i + 2] == '>'):
            ch = '\x01'
        out.append(ch); i += 1
    return ''.join(out)


class Parsed:
    def __init__(self):
        self.segments, self.inner, self.substitution, self.newline = [], [], False, False


def parse_command(command, depth=0):
    """Split into simple-command strings (quote, heredoc and comment aware) and flag substitutions and newlines."""
    parsed = Parsed()
    text, bodies = _strip_heredocs(command.strip())
    parsed.substitution = any(not quoted and re.search(r'\$\(|`', body) for body, quoted in bodies)
    cur, i, n, quote = [], 0, len(text), None

    def cut():
        segment = ''.join(cur).strip()
        del cur[:]
        if segment:
            parsed.segments.append(segment)

    while i < n:
        ch = text[i]
        if quote == "'":
            cur.append(ch); quote = None if ch == "'" else quote; i += 1
        elif quote == '"':
            if ch == '\\':
                cur.append(text[i:i + 2]); i += 2; continue
            if ch == '`' or text.startswith('$(', i):
                parsed.substitution = True
                if ch == '`':
                    end = text.find('`', i + 1); end = n - 1 if end < 0 else end
                    cur.append('X'); i = end + 1
                else:
                    cur.append('X'); i = _skip_group(text, i + 1)
                continue
            cur.append(ch); quote = None if ch == '"' else quote; i += 1
        elif ch == '\\':
            cur.append(text[i:i + 2]); i += 2
        elif ch in '\'"':
            quote = ch; cur.append(ch); i += 1
        elif ch == '#' and (not cur or cur[-1] in ' \t'):
            while i < n and text[i] != '\n':
                i += 1
        elif ch == '`' or text.startswith('$(', i) or text[i:i + 2] in ('<(', '>('):
            parsed.substitution = True
            if ch == '`':
                end = text.find('`', i + 1); end = n - 1 if end < 0 else end
                cur.append('X'); i = end + 1
            else:
                cur.append('X'); i = _skip_group(text, i + 1)
        elif ch == '\n':
            parsed.newline = True; cut(); i += 1
        elif ch in ';()':
            cut(); i += 1
        elif ch == '&' and ((i > 0 and text[i - 1] in '<>') or text[i + 1:i + 2] == '>'):
            cur.append(ch); i += 1
        elif ch in '&|':
            cut(); i += 2 if text[i + 1:i + 2] in ('&', '|') else 1
        else:
            cur.append(ch); i += 1
    cut()
    if depth < 4:
        for body in inner_commands(text):
            sub = parse_command(body, depth + 1)
            parsed.inner.extend(sub.segments + sub.inner)
    return parsed


def normalize_segment(segment):
    while True:
        stripped = KEYWORD_PREFIX.sub('', segment, count=1)
        if stripped == segment:
            return segment.strip()
        segment = stripped


def match_candidates(segment):
    """The segment as typed plus forms with leading env assignments and wrappers (timeout, nice...) removed."""
    forms, seen, current = [], set(), normalize_segment(segment)
    for _ in range(6):
        if current in seen:
            break
        seen.add(current); forms.append(current)
        nxt = ENV_PREFIX.sub('', current, count=1)
        if nxt == current:
            nxt = WRAPPER_PREFIX.sub('', current, count=1)
        current = normalize_segment(nxt)
    return forms


class Rule:
    def __init__(self, text, spec, source, path):
        self.text, self.spec, self.source, self.path = text, spec, source, path

    def matches(self, form):
        spec = self.spec
        if spec is None or spec == '*':
            return True
        if spec.endswith(':*'):
            prefix = spec[:-2]
            return form == prefix or form.startswith(prefix + ' ')
        if '*' in spec:
            pattern = '.*'.join(re.escape(part) for part in spec.split('*'))
            if re.fullmatch(pattern, form, re.S):
                return True
            return spec.endswith(' *') and form == spec[:-2]
        return form == spec

    def is_ah_run(self):
        return bool(self.spec and AH_RUN_RULE.search(self.spec))

    def label(self):
        return '%s (%s: %s)' % (self.text, self.source, self.path)


def _parse_rule(text, source, path):
    if not isinstance(text, str):
        return None
    match = re.fullmatch(r'Bash(?:\((.*)\))?', text.strip(), re.S)
    return Rule(text.strip(), match.group(1), source, path) if match else None


def _read_settings(source, path, rules):
    """Merge Bash permission rules from a settings file (or inline JSON given to --settings) into rules."""
    try:
        if isinstance(path, str) and path.lstrip().startswith('{'):
            data, label = json.loads(path), '<inline --settings>'
        else:
            info = os.stat(path)
            if info.st_size > (4 << 20):
                return
            data, label = json.loads(Path(path).read_bytes()), str(path)  # input-ok: size checked above
    except (OSError, ValueError):
        return
    permissions = data.get('permissions') if isinstance(data, dict) else None
    if not isinstance(permissions, dict):
        return
    for kind in ('deny', 'allow', 'ask'):
        for text in permissions.get(kind) or []:
            rule = _parse_rule(text, source, label)
            if rule:
                rules[kind].append(rule)


def project_root(cwd, home):
    """Nearest ancestor of cwd (never HOME itself) holding .claude/settings.json or settings.local.json."""
    try:
        current, home = Path(cwd).resolve(), Path(home).resolve()
    except (OSError, ValueError, RuntimeError):
        return None
    for directory in (current, *current.parents):
        if directory == home or directory == Path(directory.anchor):
            return None
        if any((directory / '.claude' / name).is_file() for name in ('settings.json', 'settings.local.json')):
            return directory
    return None


def ancestor_commands(limit=8):
    """argv text of the getppid chain (nearest first), bounded; the hook runs under a shell below Claude Code."""
    chain, pid = [], os.getppid()
    for _ in range(limit):
        if pid <= 1:
            break
        try:
            out = subprocess.run(['ps', '-o', 'ppid=,args=', '-p', str(pid)], capture_output=True, text=True, timeout=2,
                                 env={**os.environ, 'LC_ALL': 'C'}).stdout.strip()
        except (OSError, subprocess.SubprocessError):
            break
        parts = out.split(None, 1)
        if len(parts) < 2 or not parts[0].isdigit():
            break
        chain.append(parts[1]); pid = int(parts[0])
    return chain


def settings_from_ancestors(commands):
    for text in commands:
        try:
            words = shlex.split(text)
        except ValueError:
            words = text.split()
        for index, word in enumerate(words):
            if word == '--settings' and index + 1 < len(words):
                return words[index + 1]
            if word.startswith('--settings='):
                return word.split('=', 1)[1]
    return None


def load_rules(cwd, home, cli_settings=None):
    rules = {'deny': [], 'allow': [], 'ask': []}
    _read_settings('user', Path(home) / '.claude' / 'settings.json', rules)
    root = project_root(cwd, home)
    if root:
        _read_settings('project', root / '.claude' / 'settings.json', rules)
        _read_settings('local', root / '.claude' / 'settings.local.json', rules)
    if cli_settings:
        _read_settings('cli', cli_settings, rules)
    return rules


def rule_line(rule):
    try:
        for number, line in enumerate(Path(rule.path).read_text().splitlines(), 1):
            if rule.text in line.replace('\\"', '"'):
                return number
    except (OSError, ValueError):
        pass
    return None


# -- escape classification -------------------------------------------------------------------------------

def _classify_words(words, reasons, notes, depth):
    """Name the escape (if any) in one simple command; wrappers (env, timeout, sudo...) are looked through."""
    index = 0
    while index < len(words) and ASSIGNMENT.match(words[index]):
        index += 1
    for _ in range(8):
        if index >= len(words):
            return
        name = words[index].rsplit('/', 1)[-1]
        rest = words[index + 1:]
        if name in ('command', 'exec', 'builtin', 'time', 'sudo', 'then', 'do', 'else', 'if', 'while', '!', '{'):
            index += 1
            while index < len(words) and words[index].startswith('-') and name in ('command', 'exec', 'time', 'sudo'):
                index += 1
            continue
        if name == 'nice':
            index += 1
            if index < len(words) and words[index] == '-n':
                index += 2
            elif index < len(words) and re.fullmatch(r'-\d+', words[index]):
                index += 1
            continue
        if name == 'timeout':
            notes.append('pgid-split')
            index += 1
            while index < len(words) and words[index].startswith('-'):
                index += 2 if words[index] in ('-s', '-k', '--signal', '--kill-after') else 1
            index += 1  # the duration
            continue
        if name == 'env':
            index += 1
            while index < len(words):
                word = words[index]
                if ASSIGNMENT.match(word):
                    index += 1
                elif word in ('-i', '--ignore-environment') or (word.startswith('-') and not word.startswith('--') and 'i' in word[1:]
                                                               and 'u' not in word[1:]):
                    reasons.append('env -i clears the attribution environment'); index += 1
                elif word in ('-u', '--unset') or (word.startswith('-u') and len(word) > 2) or word.startswith('--unset='):
                    target = words[index + 1] if word in ('-u', '--unset') and index + 1 < len(words) else word.split('=', 1)[-1].lstrip('-u')
                    if target.startswith('AGENT_HARNESS_') or target == 'AGENT_ID':
                        reasons.append('env -u %s removes attribution' % target)
                    index += 2 if word in ('-u', '--unset') else 1
                elif word.startswith('-'):
                    index += 1
                else:
                    break
            continue
        break
    else:
        return
    if name in ESCAPE_NAMES:
        reasons.append('%s detaches a process from tracking' % name)
    elif name == 'launchctl':
        sub = next((word for word in rest if not word.startswith('-')), '')
        if sub in LAUNCHCTL_ESCAPES:
            reasons.append('launchctl %s starts an untracked job' % sub)
    elif name == 'systemd-run':
        reasons.append('systemd-run outside ah-run starts an untracked unit')
    elif name == 'open':
        if any(re.fullmatch(r'-[A-Za-z]*a[A-Za-z]*', word) for word in rest):
            reasons.append('open -a starts an untracked application')
    elif name == 'ssh':
        # TODO(AC-4 ssh rows, later slice): ssh -G host resolution, the host table and the --cmd-b64 remote
        # rewrite; this slice only classifies escapes inside the ssh options and the remote command string.
        _classify_ssh(rest, reasons, notes, depth)
    elif name in ('bash', 'sh', 'zsh', 'dash', 'ksh'):
        for position, word in enumerate(rest):
            if re.fullmatch(r'-[A-Za-z]*c[A-Za-z]*', word) and position + 1 < len(rest):
                _classify_text(rest[position + 1], reasons, notes, depth + 1, 'shell -c: ')
                break
    elif name == 'eval' and rest:
        _classify_text(' '.join(rest), reasons, notes, depth + 1, 'eval: ')


def _classify_ssh(args, reasons, notes, depth):
    with_arg = set('bcDEeFIiJLlmOopQRSWw')
    index, host = 0, None
    while index < len(args):
        word = args[index]
        if word == '--':
            index += 1
            break
        if word.startswith('-') and len(word) > 1:
            letters = word[1:]
            for position, letter in enumerate(letters):
                if letter == 'f':
                    reasons.append('ssh -f backgrounds the connection')
                if letter in with_arg:
                    if position == len(letters) - 1:
                        index += 1
                    break
            index += 1
            continue
        break
    if index < len(args):
        host, remote = args[index], args[index + 1:]
        if remote:
            _classify_text(' '.join(remote), reasons, notes, depth + 1, 'ssh remote: ')


def _classify_text(command, reasons, notes, depth, prefix=''):
    sub_reasons = []
    if depth > 4:
        sub_reasons.append('nested shells are too deep to analyze')
    else:
        _classify_command(command, sub_reasons, notes, depth)
    reasons.extend(prefix + reason for reason in sub_reasons)


def _classify_command(command, reasons, notes, depth):
    try:
        text, _bodies = _strip_heredocs(command.strip())
        entries = []
        for words, operator in _simple(_tokens(_mask_redirect_amps(text))):
            entries.append(([w[1].replace('\x01', '&') for w in words if w[0] == 'word'], operator))
        inner = inner_commands(text)
    except Exception as error:  # noqa: BLE001 - any parse failure is a verdict, never a crash
        reasons.append('parse failure: %s' % (str(error)[:60] or type(error).__name__))
        return
    for position, (words, operator) in enumerate(entries):
        _classify_words(words, reasons, notes, depth)
        if operator == '&' and words:
            later = any(_command_word(later_words) == 'wait' for later_words, _op in entries[position + 1:])
            if not later:
                reasons.append('background & without a later wait')
    for body in inner:
        _classify_text(body, reasons, notes, depth + 1, 'substitution: ')


def _simple(tokens):
    import commit_policy
    return commit_policy.simple_commands(tokens)


def _command_word(words):
    for word in words:
        if not ASSIGNMENT.match(word):
            return word.rsplit('/', 1)[-1]
    return ''


def analyze_escapes(command):
    """(reasons, notes): reasons name each tracking escape; notes record allowed oddities such as pgid-split."""
    reasons, notes = [], []
    _classify_command(command, reasons, notes, 0)
    return list(dict.fromkeys(reasons)), list(dict.fromkeys(notes))


def classify_escapes(command):
    return analyze_escapes(command)[0]


def escape_mode(home, env):
    """enforce|warn for the escape guard: warn when the policy file is missing, enforce when it is unreadable."""
    path = Path(env.get('AGENT_HARNESS_POLICY_FILE') or Path(home) / '.agent-harness' / 'resource_policy.json')
    try:
        data = json.loads(path.read_bytes()[:1 << 20])
    except FileNotFoundError:
        return 'warn'
    except (OSError, ValueError):
        return 'enforce'
    if not isinstance(data, dict):
        return 'enforce'
    modes = data.get('modes')
    mode = modes.get('escapes') if isinstance(modes, dict) else None
    if mode is None:
        return 'warn'
    return mode if mode in ('warn', 'enforce') else 'enforce'


# -- recovery commands and prefix stripping ----------------------------------------------------------------

def is_recovery(segment):
    """reserve.py, reclaim.py, `ah-run kill`, `harness doctor`, `install.py --apply`: never routed through the launcher."""
    try:
        words = shlex.split(segment)
    except ValueError:
        return False
    while words and (ASSIGNMENT.match(words[0]) or words[0] in ('sudo', 'command')):
        words = words[1:]
    if words and re.fullmatch(r'(?:\S*/)?python3?(?:\.\d+)?', words[0]):
        words = words[1:]
    if not words:
        return False
    name, rest = words[0].rsplit('/', 1)[-1], words[1:]
    if name in RECOVERY_SCRIPTS:
        return True
    if name in ('ah_run.py', 'ah-run'):
        return rest[:1] == ['kill']
    if name == 'harness':
        return rest[:1] == ['doctor']
    if name == 'install.py':
        return '--apply' in rest
    return False


def strip_ah_run_prefix(command):
    """A model-supplied `ah-run [run] flags -- CMD` prefix is removed so the hook's own attribution replaces it."""
    for _ in range(4):
        head = AH_PREFIX.match(command)
        if not head:
            return command
        i, n, first, found = head.end(), len(command), True, False
        while i < n:
            while i < n and command[i] in ' \t':
                i += 1
            start, quote = i, None
            while i < n and (quote or command[i] not in ' \t\n'):
                if command[i] == '\\' and quote != "'":
                    i += 2; continue
                if quote:
                    quote = None if command[i] == quote else quote
                elif command[i] in '\'"':
                    quote = command[i]
                i += 1
            word = command[start:i]
            if word == '--':
                command, found = command[i:].lstrip(' \t'), True
                break
            if (first and not word.startswith('-') and word != 'run') or re.search(r'[;&|<>`$()\n]', word) or not word:
                return command  # kill/ledger/mask or a compound form: leave it to the normal path
            first = False
        else:
            return command
    return command


# -- the hook -----------------------------------------------------------------------------------------------

def _out(decision=None, reason=None, updated=None, context=None):
    body = {'hookEventName': 'PreToolUse'}
    if decision:
        body['permissionDecision'] = decision
    if reason:
        body['permissionDecisionReason'] = reason
    if updated is not None:
        body['updatedInput'] = updated
    if context:
        body['additionalContext'] = context
    return {'hookSpecificOutput': body}


def _strings(value, skip_command=False, depth=0):
    if depth > 6:
        return
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, item in value.items():
            if skip_command and key == 'command':
                continue
            yield from _strings(item, skip_command, depth + 1)
    elif isinstance(value, list):
        for item in value[:64]:
            yield from _strings(item, skip_command, depth + 1)


def task_key(payload, env):
    """AGENT_HARNESS_TASK, else a [task:KEY] token outside the command text, else a stable generated key."""
    given = env.get('AGENT_HARNESS_TASK')
    if given and SAFE_KEY.fullmatch(given):
        return given
    for text in _strings({k: v for k, v in payload.items() if k != 'tool_input'}):
        found = TASK_TOKEN.search(text)
        if found:
            return found.group(1)
    for text in _strings(payload.get('tool_input'), skip_command=True):
        found = TASK_TOKEN.search(text)
        if found:
            return found.group(1)
    seed = '%s%s' % (payload.get('session_id') or '', payload.get('agent_id') or '')
    return 'auto-' + digest(seed)[:12]


def build_rewrite(command, payload, env, notes, context):
    """The wrapped command and, when the pending row could be written, its token. Raises ValueError to deny."""
    raw = command.encode('utf-8')
    if len(raw) > PAYLOAD_CAP:
        raise ValueError('command is %d bytes; the ah-run payload cap is %d bytes (1 MiB). Write it to a file and run the file.'
                         % (len(raw), PAYLOAD_CAP))
    task = task_key(payload, env)
    agent = safe_key(payload.get('agent_id'), 'main')
    session = safe_key(payload.get('session_id'), 'none')
    ticket = env.get('AGENT_HARNESS_TICKET')
    token, root = None, None
    try:
        root = reserve_root()
        token = mint_pending(root, command, task, agent, session)
    except (OSError, RuntimeError):
        context.append('ah-run: the pending token row could not be written; attribution will be unverified')
    parts = ['python3', str(Path(__file__).resolve()), 'run', '--task', task, '--agent', agent]
    if ticket and SAFE_KEY.fullmatch(ticket):
        parts += ['--ticket', ticket]
    parts += ['--session', session]
    if token:
        parts += ['--token', token]
    if 'pgid-split' in notes:
        parts += ['--command-class', 'pgid-split']
    if len(raw) > INLINE_LIMIT:
        if root is None or token is None:
            raise ValueError('command is %d bytes (over the %d byte inline limit) and the payload file could not be written'
                             % (len(raw), INLINE_LIMIT))
        payload_path = pending_dir(root) / (token + '.cmd')
        try:
            fd = os.open(payload_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, 'wb') as handle:
                handle.write(raw); handle.flush()
        except OSError as error:
            raise ValueError('command payload file could not be written (%s)' % type(error).__name__)
        parts += ['--cmd-file', str(payload_path)]
    else:
        parts += ['--', command]
    return ' '.join(shlex.quote(part) for part in parts)


def decide(payload, home=None, env=None, ancestors=None):
    """The hook decision for one PreToolUse payload (a dict); returns the JSON object to print."""
    home = home or str(Path.home())
    env = os.environ if env is None else env
    if payload.get('tool_name') != 'Bash':
        return {}
    original = (payload.get('tool_input') or {}).get('command')
    mode = payload.get('permission_mode') or 'default'
    if not isinstance(original, str) or not original.strip() or mode == 'plan':
        return {}
    command = strip_ah_run_prefix(original)
    cwd = payload.get('cwd') or os.getcwd()
    cli = settings_from_ancestors(ancestors() if ancestors else ancestor_commands())
    rules = load_rules(cwd, home, cli)
    parsed = parse_command(command)
    context = []

    for part in parsed.segments + parsed.inner:
        forms = match_candidates(part)
        for rule in rules['deny']:
            if any(rule.matches(form) for form in forms):
                return _out('deny', 'denied by permission rule %s' % rule.label())

    if parsed.segments and not parsed.substitution and not parsed.newline and all(is_recovery(s) for s in parsed.segments):
        return _out('allow', 'recovery command runs unwrapped')

    reasons, notes = analyze_escapes(command)
    if reasons:
        text = 'command escapes tracking: %s. Run it through `ah-run` or keep it in the foreground (use `wait`).' % '; '.join(reasons)
        if escape_mode(home, env) == 'enforce':
            return _out('deny', text)
        context.append('WARNING (escapes in warn mode, will be refused in enforce): ' + text)

    ignored = [rule for rule in rules['allow'] if rule.is_ah_run()]
    if ignored:
        where = ', '.join('%s line %s' % (rule.path, rule_line(rule) or '?') for rule in ignored[:3])
        context.append('ignored an ah-run allow rule (%s); repair: %s' % (where, POLICY_SELFCHECK_FIX))
    allows = [rule for rule in rules['allow'] if not rule.is_ah_run()]

    try:
        wrapped = build_rewrite(command, payload, env, notes, context)
    except ValueError as error:
        return _out('deny', 'ah-run: %s' % error)
    updated = {**(payload.get('tool_input') or {}), 'command': wrapped}

    if mode == 'bypassPermissions':
        return _out(None, None, updated, '\n'.join(context) or None)

    asked = any(rule.matches(form) for part in parsed.segments for rule in rules['ask'] for form in [normalize_segment(part)])
    committed = any(rule.source == 'project' for rule in ignored)  # F75: a committed ah-run rule degrades to ask
    eligible = (bool(parsed.segments) and not committed and not parsed.substitution and not parsed.newline and not asked
                and all(part.split(None, 1)[0] != 'eval' for part in parsed.segments)
                and all(any(rule.matches(normalize_segment(part)) for rule in allows) for part in parsed.segments))
    if eligible:
        return _out('allow', 'every command matches an allow rule; wrapped in ah-run', updated, '\n'.join(context) or None)
    if mode == 'dontAsk':
        return _out('deny', 'no allow rule matches and permission mode dontAsk refuses to ask')
    why = 'ask rule matched' if asked else ('contains substitution, eval or a newline' if (parsed.substitution or parsed.newline)
                                           else 'no allow rule matches every command')
    return _out('ask', why, updated, '\n'.join(context) or None)


def hook_main(stdin=None, stdout=None):
    """Entry point for `ah_run.py hook`: always exit 0; any internal error is an `ask` with the reason."""
    stdin, stdout = stdin or sys.stdin, stdout or sys.stdout
    try:
        raw = stdin.read((8 << 20) + 1)
        if len(raw) > (8 << 20):
            result = _out('ask', 'ah-run hook: input over 8 MiB')
        else:
            payload = json.loads(raw)
            if not isinstance(payload, dict):
                raise ValueError('hook input is not an object')
            result = decide(payload)
    except Exception as error:  # noqa: BLE001 - never a silent allow, never a crash
        result = _out('ask', 'ah-run hook internal error: %s: %s' % (type(error).__name__, str(error)[:120]))
    stdout.write(json.dumps(result)); stdout.write('\n'); stdout.flush()
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='action')
    run = sub.add_parser('run')
    for name in ('--task', '--agent', '--ticket', '--session', '--token', '--cmd-file', '--cmd-b64', '--command-class'):
        run.add_argument(name)
    run.add_argument('--readonly', action='store_true'); run.add_argument('--no-unit', action='store_true')
    run.add_argument('command', nargs=argparse.REMAINDER)
    kill_p = sub.add_parser('kill'); kill_p.add_argument('--task'); kill_p.add_argument('--agent')
    kill_p.add_argument('--pause', action='store_true'); kill_p.add_argument('--resume', action='store_true')
    led = sub.add_parser('ledger'); led.add_argument('--task'); led.add_argument('--live', action='store_true'); led.add_argument('--limit', type=int, default=50)
    mask = sub.add_parser('mask'); mask.add_argument('text', nargs=argparse.REMAINDER)
    sub.add_parser('hook')
    args = parser.parse_args(argv)
    if args.action == 'hook':
        return hook_main()
    if args.action == 'run':
        if args.command[:1] == ['--']: args.command = args.command[1:]
        if not args.command and not args.cmd_file and not args.cmd_b64:
            parser.error('a command is required')
        return launch(args)
    if args.action == 'kill':
        if not args.task and not args.agent: parser.error('--task or --agent is required')
        if args.pause and args.resume: parser.error('choose --pause or --resume')
        return kill(args)
    if args.action == 'ledger':
        return ledger_cmd(args)
    if args.action == 'mask':
        print(mask_argv(' '.join(args.text))); return 0
    parser.print_help(); return 2


if __name__ == '__main__':
    raise SystemExit(main())
