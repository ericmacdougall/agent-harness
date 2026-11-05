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
import stat
import subprocess
import sys
import threading
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import usage_guard  # noqa: E402  (SECRET detector; liveness helpers when the guard has them)
import host_table  # noqa: E402  (ssh target resolution and the host table, shared with the placement guard)


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


def safe_hex(value):
    return value if isinstance(value, str) and re.fullmatch(r'[0-9a-f]{64}', value) else None


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


WATCHDOG_CODE = (
    'import os, signal, sys, time\n'
    'sup, pgid, grace = int(sys.argv[1]), int(sys.argv[2]), float(sys.argv[3])\n'
    'while os.getppid() == sup:\n'
    '    time.sleep(0.5)\n'
    'signal.signal(signal.SIGTERM, signal.SIG_IGN)\n'
    'try:\n'
    '    os.killpg(pgid, signal.SIGTERM)\n'
    'except OSError:\n'
    '    pass\n'
    'time.sleep(grace)\n'
    'try:\n'
    '    os.killpg(pgid, signal.SIGKILL)\n'
    'except OSError:\n'
    '    pass\n')


def start_watchdog(pgid):
    """A sibling process in the child's group (not a job of the user's shell, so `wait`, `jobs` and `$!` are untouched):
    when the supervisor disappears, even by SIGKILL, it ends the group (SIGTERM, then SIGKILL after KILL_GRACE).
    The supervisor stops it on a normal end. Returns the Popen, or None when the group cannot be joined."""
    def join_group():
        os.setpgid(0, pgid)
    try:
        return subprocess.Popen([sys.executable, '-S', '-c', WATCHDOG_CODE, str(os.getpid()), str(pgid), str(KILL_GRACE)],
                                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                preexec_fn=join_group)
    except (OSError, subprocess.SubprocessError, ValueError):
        return None


def read_command(args, root=None):
    """(command text, payload path or None). A payload file is accepted only as <reserve>/ledger/pending/<token>.cmd,
    opened with O_NOFOLLOW and checked on the descriptor (regular file, our uid, one link); it is read once and the
    caller unlinks it only after the token's digest matches."""
    if args.cmd_b64:
        return base64.b64decode(args.cmd_b64.encode('ascii')).decode('utf-8', 'replace'), None
    if args.cmd_file:
        if not TOKEN_RE.fullmatch(args.token or '') or root is None:
            raise RuntimeError('a command payload needs a hook token')
        expected = os.path.abspath(pending_dir(root) / (args.token + '.cmd'))
        if os.path.abspath(args.cmd_file) != expected:
            raise RuntimeError('command payload is not a pending payload of this token')
        try:
            fd = os.open(expected, os.O_RDONLY | os.O_NOFOLLOW)
        except OSError:
            raise RuntimeError('command payload cannot be opened')
        with os.fdopen(fd, 'rb') as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1 or info.st_size > (1 << 20):
                raise RuntimeError('command payload unsafe or oversized')
            text = handle.read(info.st_size + 1).decode('utf-8', 'replace')  # input-ok: size checked above
        return text, expected
    return ' '.join(args.command), None


PENDING_TTL = 600
TOKEN_RE = re.compile(r'^[A-Za-z0-9_-]{16,64}$')


def pending_dir(root):
    return Path(root) / 'ledger' / 'pending'


def prune_pending(root, ttl=None):
    """Remove pending token rows, payloads and leftovers older than the TTL; returns the count removed."""
    ttl = PENDING_TTL if ttl is None else ttl
    removed, cutoff = 0, time.time() - ttl
    try:
        entries = list(os.scandir(pending_dir(root)))
    except OSError:
        return 0
    for entry in entries[:20000]:
        try:
            if entry.is_file(follow_symlinks=False) and entry.stat(follow_symlinks=False).st_mtime < cutoff:
                os.unlink(entry.path); removed += 1
        except OSError:
            continue
    return removed


def mint_pending(root, command, task, agent, session='none'):
    """Write a single-use pending row for a hook-wrapped command; return the token."""
    token = secrets.token_urlsafe(18).lstrip('-') or 'x'  # a leading '-' would be read as an option by `--token VALUE`
    token = token + 'x' * (16 - len(token)) if len(token) < 16 else token
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


def _ledger_write(ledger, run_id, row):
    """False when the row could not be written (full disk, read-only or symlinked reserve): the command still runs."""
    if ledger is None:
        return False
    try:
        ledger.write(run_id, row)
        return True
    except (OSError, ValueError):
        return False


def launch(args):
    try:
        ledger = Ledger()
    except (OSError, RuntimeError):
        ledger = None  # a symlinked or unwritable reserve must not stop the command (S5)
    if ledger is not None:
        prune_pending(ledger.root)
    run_id = secrets.token_hex(16)
    try:
        command, payload_path = read_command(args, ledger.root if ledger else None)
    except (RuntimeError, OSError, ValueError) as error:
        print('ah-run: refused: %s' % (error if isinstance(error, RuntimeError) else type(error).__name__), file=sys.stderr)
        return 126
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
    script = prelude + command
    use_unit = user_bus_answers() and not args.no_unit
    unit = 'ah-run-' + run_id if use_unit else None
    argv = [shell, '-c', script]
    if use_unit:
        argv = ['systemd-run', '--user', '--scope', '--quiet', '--collect', '--unit', unit, *argv]
    if args.token == 'via-hook-ssh':
        attribution, why = 'hook-ssh', None
    elif args.token and ledger is not None:
        attribution, why = consume_pending(ledger.root, args.token, command, task, agent)
    elif args.token:
        attribution, why = 'unverified', 'ledger-unavailable'
    else:
        attribution, why = 'unverified', 'no-token'
    if payload_path and attribution == 'verified':
        try:
            os.unlink(payload_path)  # only after the digest matched the pending row
        except OSError:
            pass
    if args.readonly and attribution == 'unverified':
        print('ah-run: a read-only agent run needs a hook token; refused', file=sys.stderr)
        return 126
    row = {'schema': SCHEMA, 'run_id': run_id, 'task': task, 'agent': agent, 'ticket': ticket, 'session': session,
           'task_source': args.task_source if args.task_source in ('input', 'record') else None,
           'attribution': attribution, 'attribution_reason': why, 'readonly': bool(args.readonly), 'host': host_identity(),
           'command_sha256': digest(command), 'command_class': args.command_class or 'unclassified',
           'remote_host_sha256': safe_hex(args.remote_host_sha256),
           'cwd_sha256': digest(os.getcwd()), 'started_at': now(), 'supervisor_pid': os.getpid(),
           'supervisor_start': process_start_token(os.getpid()), 'unit': unit, 'end': None}
    try:
        # own process group, same session, so the watchdog (a sibling) can join it with setpgid
        child = subprocess.Popen(argv, env=env, preexec_fn=os.setpgrp)
    except OSError as error:
        row.update(end=now(), exit_code=127, error=type(error).__name__)
        _ledger_write(ledger, run_id, row)
        print('ah-run: cannot start the shell: %s' % type(error).__name__, file=sys.stderr)
        return 127
    pgid = child.pid  # setpgrp made the child its own group leader
    watchdog = start_watchdog(pgid)
    row.update(pid=child.pid, pgid=pgid, start_token=process_start_token(child.pid),
               watchdog=watchdog.pid if watchdog else None)
    written = _ledger_write(ledger, run_id, row)
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
    if watchdog is not None:  # normal end: the watchdog's job is done
        try:
            watchdog.kill(); watchdog.wait(timeout=2)
        except (OSError, subprocess.SubprocessError):
            pass
    tree = [entry for entry in pid_tree(pgid) if not (watchdog and entry['pid'] == watchdog.pid)]
    kill_group(pgid, signal.SIGTERM)  # leftovers of a finished leader are not part of the result
    usage = resource_usage()
    row.update(end=now(), exit_code=code, signal=state['signal'], parent_died=state['parent_died'],
               rusage=usage, pid_tree=tree)
    if not _ledger_write(ledger, run_id, row):  # retry once; a row that never lands is noted, never fatal
        _warn_row('ledger-unwritable', run_id, guard='ledger')
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
    if args.prune:
        print(json.dumps({'pruned': prune_pending(ledger.root)}))
        return 0
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


ANSI_SIMPLE = {'a': '\a', 'b': '\b', 'e': '\x1b', 'E': '\x1b', 'f': '\f', 'n': '\n', 'r': '\r', 't': '\t', 'v': '\v',
               '\\': '\\', "'": "'", '"': '"', '?': '?'}


def _decode_ansi_c(text, i):
    """(value, index after the closing quote) for the $'...' string whose body starts at text[i]; ValueError when it is
    unterminated or its value cannot be modelled (NUL ends a shell string early)."""
    out, n = [], len(text)
    while i < n:
        ch = text[i]
        if ch == "'":
            return ''.join(out), i + 1
        if ch != '\\' or i + 1 >= n:
            out.append(ch); i += 1
            continue
        nxt = text[i + 1]
        if nxt in ANSI_SIMPLE:
            out.append(ANSI_SIMPLE[nxt]); i += 2
        elif nxt in '01234567':
            digits = re.match(r'[0-7]{1,3}', text[i + 1:]).group()
            value = int(digits, 8) & 0xFF
            if value == 0:
                raise ValueError('NUL in an ANSI-C string')
            out.append(chr(value)); i += 1 + len(digits)
        elif nxt in 'xuU':
            digits = re.match(r'[0-9a-fA-F]{1,%d}' % {'x': 2, 'u': 4, 'U': 8}[nxt], text[i + 2:])
            if not digits:
                out.append('\\' + nxt); i += 2
                continue
            value = int(digits.group(), 16)
            if value == 0:
                raise ValueError('NUL in an ANSI-C string')
            out.append(chr(value)); i += 2 + len(digits.group())
        elif nxt == 'c' and i + 2 < n:
            if ord(text[i + 2]) & 0x1f == 0:
                raise ValueError('NUL in an ANSI-C string')
            out.append(chr(ord(text[i + 2]) & 0x1f)); i += 3
        else:
            out.append('\\' + nxt); i += 2
    raise ValueError('unterminated $\'')


def _deansi_group(text, i, out):
    """Copy the substitution or process substitution at text[i] into out, normalizing its body; return the next index."""
    if text[i] == '`':
        end = text.find('`', i + 1)
        if end < 0:
            raise ValueError('unterminated backtick')
        body, ok = deansi(text[i + 1:end])
        if not ok:
            raise ValueError('inner quoting')
        out.append('`' + body + '`')
        return end + 1
    end = _skip_group(text, i + 1)
    if end > len(text) or text[end - 1] != ')':
        raise ValueError('unterminated substitution')
    body, ok = deansi(text[i + 2:end - 1])
    if not ok:
        raise ValueError('inner quoting')
    out.append(text[i:i + 2] + body + ')')
    return end


def deansi(text):
    """(text, ok): every $'...' word rewritten as an equivalent single-quoted word, so the splitter, the matcher and
    the classifier all read what the shell reads. ok is False for any quoting that cannot be tokenized with certainty
    (unterminated quotes, substitutions or ANSI-C strings, NUL escapes); callers then never answer allow."""
    out, i, n, quote = [], 0, len(text), None
    try:
        while i < n:
            ch = text[i]
            if quote == "'":
                out.append(ch); i += 1
                quote = None if ch == "'" else quote
            elif ch == '\\':
                out.append(text[i:i + 2]); i += 2
            elif quote == '"':
                if ch == '"':
                    quote = None; out.append(ch); i += 1
                elif ch == '`' or text.startswith('$(', i):
                    i = _deansi_group(text, i, out)
                else:
                    out.append(ch); i += 1
            elif ch in '\'"':
                quote = ch; out.append(ch); i += 1
            elif text.startswith("$'", i):
                value, i = _decode_ansi_c(text, i + 2)
                out.append(shell_quote(value))
            elif ch == '#' and (i == 0 or text[i - 1] in ' \t\n'):
                end = text.find('\n', i)
                end = n if end < 0 else end
                out.append(text[i:end]); i = end
            elif ch == '`' or text.startswith('$(', i) or text[i:i + 2] in ('<(', '>('):
                i = _deansi_group(text, i, out)
            else:
                out.append(ch); i += 1
    except ValueError:
        return text, False
    return ''.join(out), quote is None


class Parsed:
    def __init__(self):
        self.segments, self.inner, self.substitution, self.newline = [], [], False, False
        self.uncertain, self.pipeline = False, False  # quoting not modelled with certainty; a `|` or `&` joins commands


def parse_command(command, depth=0):
    """Split into simple-command strings (quote, heredoc and comment aware) and flag substitutions and newlines."""
    parsed = Parsed()
    text, bodies = _strip_heredocs(command.strip())
    text, parsed.uncertain = deansi(text)[0], not deansi(text)[1]
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
            if text[i:i + 2] not in ('&&', '||'):
                parsed.pipeline = True
            cut(); i += 2 if text[i + 1:i + 2] in ('&', '|') else 1
        else:
            cur.append(ch); i += 1
    cut()
    if quote:
        parsed.uncertain = True
    if depth < 4:
        for body in inner_commands(text):
            sub = parse_command(body, depth + 1)
            parsed.inner.extend(sub.segments + sub.inner)
            parsed.uncertain = parsed.uncertain or sub.uncertain
    return parsed


def normalize_segment(segment):
    while True:
        stripped = KEYWORD_PREFIX.sub('', segment, count=1)
        if stripped == segment:
            return segment.strip()
        segment = stripped


def _spans(text):
    """[(start, end)] of the words of text, quote aware; ValueError on an unbalanced quote."""
    spans, i, n = [], 0, len(text)
    while i < n:
        while i < n and text[i] in ' \t':
            i += 1
        if i >= n:
            break
        start, quote = i, None
        while i < n and (quote or text[i] not in ' \t'):
            ch = text[i]
            if quote:
                if ch == '\\' and quote == '"' and i + 1 < n:
                    i += 1
                elif ch == quote:
                    quote = None
            elif ch == '\\' and i + 1 < n:
                i += 1
            elif ch in '\'"':
                quote = ch
            i += 1
        if quote:
            raise ValueError('unbalanced quote')
        spans.append((start, i))
    return spans


SUDO_ARG_OPTS = frozenset(('-u', '-g', '-h', '-p', '-C', '-D', '-R', '-T', '-U', '-r', '-t'))


def _unquote_program(text):
    """text with its first word unquoted (`"rm" -rf` -> `rm -rf`, `\\rm` -> `rm`), or None when nothing changes."""
    try:
        spans = _spans(text)
        if not spans:
            return None
        raw = text[spans[0][0]:spans[0][1]]
        _raw, value, dynamic = raw_words(raw)[0]
    except (ValueError, IndexError):
        return None
    if dynamic or value == raw or not value or re.search(r'\s', value):
        return None
    return value + text[spans[0][1]:]


def peel_wrapper(text):
    """The command with its first wrapper removed (an env assignment, exec/command/builtin/time/nohup, nice, sudo with
    options, timeout with options and duration, env with options), or None when it starts with no wrapper."""
    try:
        spans = _spans(text)
        if not spans:
            return None

        def val(k):
            return raw_words(text[spans[k][0]:spans[k][1]])[0][1]
        first = text[spans[0][0]:spans[0][1]]
        base, k, count = val(0).rsplit('/', 1)[-1], 1, len(spans)
        if ASSIGNMENT.match(first):
            pass
        elif base in ('exec', 'command', 'builtin', 'time', 'nohup'):
            while k < count and val(k).startswith('-'):
                k += 2 if val(k) == '-a' else 1
        elif base == 'nice':
            if k < count and val(k) == '-n':
                k += 2
            elif k < count and (re.fullmatch(r'-\d+', val(k)) or val(k).startswith('--adjustment')):
                k += 1
        elif base == 'sudo':
            while k < count and val(k).startswith('-'):
                option = val(k)
                k += 2 if option in SUDO_ARG_OPTS else 1
                if option == '--':
                    break
        elif base == 'timeout':
            while k < count and val(k).startswith('-'):
                k += 2 if val(k) in ('-s', '-k') else 1
            k += 1
        elif base == 'env':
            while k < count:
                word = val(k)
                if word in ('-S', '--split-string') and k + 1 < count:
                    rest = text[spans[k + 2][0]:] if k + 2 < count else ''
                    return (val(k + 1) + ' ' + rest).strip()
                if ASSIGNMENT.match(text[spans[k][0]:spans[k][1]]):
                    k += 1
                elif word in ('-u', '-C', '--unset', '--chdir'):
                    k += 2
                elif word.startswith('-') and len(word) > 1:
                    k += 1
                else:
                    break
        else:
            return None
        return text[spans[k][0]:] if k < count else None
    except (ValueError, IndexError):
        return None


def match_candidates(segment):
    """The segment as typed plus every form with env assignments, wrappers (exec, command, time, nohup, nice, sudo,
    timeout, env) and the quoting of the program word removed. A deny or ask rule matching any form applies."""
    forms, seen, current = [], set(), normalize_segment(segment)
    for _ in range(12):
        if current in seen:
            break
        seen.add(current); forms.append(current)
        bare = _unquote_program(current)
        if bare and bare not in seen:
            seen.add(bare); forms.append(bare)
        base = bare or current
        nxt = peel_wrapper(base)
        if nxt is None:
            nxt = ENV_PREFIX.sub('', base, count=1)
            if nxt == base:
                nxt = WRAPPER_PREFIX.sub('', base, count=1)
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

def _is_attribution_key(key):
    return key.startswith('AGENT_HARNESS_') or key == 'AGENT_ID'


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
                index += 2 if name == 'sudo' and words[index] in SUDO_ARG_OPTS else 1
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
                elif word.startswith('--'):
                    option, _eq, inline = word.partition('=')
                    takes_next = option in ('--unset', '--split-string') and not _eq
                    arg = inline if _eq else (words[index + 1] if takes_next and index + 1 < len(words) else '')
                    if option == '--ignore-environment':
                        reasons.append('env -i clears the attribution environment')
                    elif option == '--unset' and _is_attribution_key(arg):
                        reasons.append('env -u %s removes attribution' % arg)
                    elif option == '--split-string':
                        _classify_text(arg, reasons, notes, depth + 1, 'env -S: ')
                    index += 2 if takes_next else 1
                elif word.startswith('-') and len(word) > 1:
                    letters, position, takes_next = word[1:], 0, False
                    while position < len(letters):
                        letter = letters[position]
                        if letter == 'i':
                            reasons.append('env -i clears the attribution environment')
                        elif letter in 'uSC':
                            takes_next = position + 1 == len(letters)
                            arg = letters[position + 1:] if not takes_next else (words[index + 1] if index + 1 < len(words) else '')
                            if letter == 'u' and _is_attribution_key(arg):
                                reasons.append('env -u %s removes attribution' % arg)
                            elif letter == 'S':
                                _classify_text(arg, reasons, notes, depth + 1, 'env -S: ')
                            break
                        position += 1
                    index += 2 if takes_next else 1
                else:
                    break
            continue
        break
    else:
        return
    if name in ESCAPE_NAMES:
        reasons.append('%s detaches a process from tracking' % name)
    elif name in ('unset', 'export', 'declare', 'typeset', 'readonly'):
        for word in rest:
            if _is_attribution_key(word.split('=', 1)[0]):
                reasons.append('%s %s changes the attribution environment' % (name, word.split('=', 1)[0]))
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
        # host resolution, the table and the remote rewrite live in rewrite_ssh (decide); this only finds escapes
        _classify_ssh(rest, reasons, notes, depth)
    elif name in ('bash', 'sh', 'zsh', 'dash', 'ksh'):
        for position, word in enumerate(rest):
            if re.fullmatch(r'-[A-Za-z]*c[A-Za-z]*', word) and position + 1 < len(rest):
                _classify_text(rest[position + 1], reasons, notes, depth + 1, 'shell -c: ')
                break
    elif name == 'eval' and rest:
        _classify_text(' '.join(rest), reasons, notes, depth + 1, 'eval: ')


def _classify_ssh(args, reasons, notes, depth):
    with_arg = set('bcDEeFIiJLlmOopQRSWwBP')
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
            # a model-supplied `ah-run ... --` prefix in the remote command is replaced by the hook, so look past it
            _classify_text(strip_ah_run_prefix(' '.join(remote)), reasons, notes, depth + 1, 'ssh remote: ')


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
        text = deansi(text)[0]
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
    path = host_table.policy_path(home, env)
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

ROLE_WORD = re.compile(r'^[A-Za-z0-9_-]+$')
INTERPRETER = re.compile(r'^(?:(?:/usr/bin/|/usr/local/bin/|/opt/homebrew/bin/)?python3?(?:\.\d+)?)$')


def _recovery_path_ok(path, home, repo_forms):
    """The installed hooks directory (this file's, ~/.claude/hooks, ~/.codex/agent-harness) or an in-repo relative path."""
    if path.startswith('~/'):
        path = os.path.join(home, path[2:])
    if '..' in path.split('/'):
        return False
    if os.path.isabs(path):
        directory = os.path.dirname(os.path.normpath(path))
        allowed = {str(Path(__file__).resolve().parent), os.path.join(home, '.claude', 'hooks'),
                   os.path.join(home, '.codex', 'agent-harness')}
        return directory in allowed
    return path in repo_forms or ('./' + path) in repo_forms or path.startswith('./') and path[2:] in repo_forms


def plain_recovery(segment, home):
    """True only for the plain form of a recovery command: reserve.py, reclaim.py, `ah-run kill`, `harness doctor`,
    `install.py --apply --role ROLE`, run as the user, at the installed or repo path, with no sudo, env assignment,
    redirection or expansion. Any other shape is an ordinary command."""
    if re.search(r'[<>$`*?\[\]{}|&;()!]', segment):
        return False
    try:
        words = shlex.split(segment)
    except ValueError:
        return False
    if words and INTERPRETER.fullmatch(words[0]):
        words = words[1:]
    if not words or ASSIGNMENT.match(words[0]):
        return False
    path, rest = words[0], words[1:]
    name = path.rsplit('/', 1)[-1]
    if name in RECOVERY_SCRIPTS:
        return _recovery_path_ok(path, home, ('harness/%s' % name, 'harness/hooks/%s' % name, 'hooks/%s' % name))
    if name == 'ah-run':
        return path == 'ah-run' and rest[:1] == ['kill']
    if name == 'ah_run.py':
        return rest[:1] == ['kill'] and _recovery_path_ok(path, home, ('harness/hooks/ah_run.py',))
    if name == 'harness':
        return path == 'harness' and rest[:1] == ['doctor']
    if name == 'install.py':
        if '--apply' not in rest or '--role' not in rest or rest.index('--role') + 1 >= len(rest):
            return False
        return bool(ROLE_WORD.match(rest[rest.index('--role') + 1])) and _recovery_path_ok(path, home, ('harness/install.py',))
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


# -- ssh: host table, remote rewrite (AC-4 ssh rows, AC-19 --readonly travel) ---------------------------------

REVIEW_TYPES = frozenset(('red-team', 'click-tester', 'reviewer', 'Explore', 'Plan'))
SSH_WORD = re.compile(r'^(?:\S*/)?ssh(?=\s)')
REDIRECT = re.compile(r'^(?:\d*|&)(?:<<<|<<-?|<>|>>|>&|<&|>\||>|<)(.*)$', re.S)
REMOTE_PATH = re.compile(r'^[A-Za-z0-9_./~-]+$')
REMOTE_ENV_KEY = re.compile(r'^AGENT_HARNESS_[A-Z_]{1,40}$')
REMOTE_ENV_VALUE = re.compile(r'^[A-Za-z0-9_./~:-]{1,200}$')


def agent_is_readonly(payload):
    """True for a review-set agent. TODO(slice 7, AC-19): fall back to the SubagentStart record for `agent_id`
    when the hook input carries no `agent_type`; until then only the hook input's own `agent_type` counts."""
    return payload.get('agent_type') in REVIEW_TYPES


def raw_words(text):
    """[(raw, value, dynamic)] for one simple command: quotes removed in `value`; `dynamic` when the local
    shell would expand it (`$`, backticks, globs, a leading `~`). Raises ValueError on an unbalanced quote."""
    words, i, n = [], 0, len(text)
    while i < n:
        while i < n and text[i] in ' \t':
            i += 1
        if i >= n:
            break
        start, quote, value, dynamic = i, None, [], False
        while i < n and (quote or text[i] not in ' \t'):
            ch = text[i]
            if quote == "'":
                if ch == "'":
                    quote = None
                else:
                    value.append(ch)
            elif quote == '"':
                if ch == '"':
                    quote = None
                elif ch == '\\' and i + 1 < n and text[i + 1] in '"\\$`':
                    i += 1; value.append(text[i])
                else:
                    dynamic = dynamic or ch in '$`'
                    value.append(ch)
            elif ch in '\'"':
                quote = ch
            elif ch == '\\' and i + 1 < n:
                i += 1; value.append(text[i])
            else:
                dynamic = dynamic or ch in '$`*?[{' or (ch == '~' and i == start)
                value.append(ch)
            i += 1
        if quote:
            raise ValueError('unbalanced quote')
        words.append((text[start:i], ''.join(value), dynamic))
    return words


def _warn_row(reason, target, guard='ssh-resolve'):
    """Append to <reserve>/warn.jsonl (AC-18 triage); a digest of the target, never the name."""
    try:
        root = reserve_root()
        row = json.dumps({'at': now(), 'guard': guard, 'reason': reason, 'target_sha256': digest(target)}, sort_keys=True)
        fd = os.open(root / 'warn.jsonl', os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'a') as handle:
            handle.write(row + '\n')
    except (OSError, RuntimeError):
        pass


def _ssh_form(segment):
    for form in match_candidates(segment):
        if SSH_WORD.match(form) and segment.endswith(form):
            return segment[:len(segment) - len(form)], form
    return None


def rewrite_ssh(command, parsed, payload, env, home, context):
    """(command, remote): each `ssh HOST CMD` simple command whose resolved host has `ah_run: "<path>"` in the
    table becomes `ssh HOST python3 <path> run ... --token via-hook-ssh [--readonly] --cmd-b64 B64` (stdin stays
    inherited). `remote` is (command_class, host_digest) for the local ledger row when the host is external
    (`remote-unattributed`) or has no remote ah-run (`remote-unwrapped`). Raises ValueError to deny."""
    segments = [s for s in dict.fromkeys(parsed.segments)]
    candidates = [(s, _ssh_form(s)) for s in segments]
    if not any(form for _s, form in candidates):
        return command, None
    policy = host_table.policy_path(home, env)
    table = host_table.load(policy)
    remote = None
    for segment, found in candidates:
        if not found:
            continue
        prefix, form = found
        try:
            words = raw_words(form)
        except ValueError:
            continue
        args, redirects, skip = [], [], False
        for position, word in enumerate(words):
            if skip:
                redirects.append(word[0]); skip = False
            elif position and REDIRECT.match(word[0]):
                redirects.append(word[0]); skip = not REDIRECT.match(word[0]).group(1)
            else:
                args.append(word)
        call = host_table.parse_ssh([w[1] for w in args[1:]])
        if call is None or not call.remote:
            continue  # `ssh HOST` with no command, `ssh -N`, `-W`: nothing to wrap
        raws = [w[0] for w in args[1:]]
        count = len(call.opts)
        target_dynamic = args[1 + count][2]
        if target_dynamic:
            cls = host_table.HostClass('external', None, None, None, reason='dynamic-target')
        else:
            cls = host_table.classify(call.target, call.resolve_args, table=table, policy=policy,
                                      warn=lambda text, t=call.target: _warn_row(text, t))
        if cls.kind == 'local':
            continue
        who = cls.name or cls.host or call.target
        if cls.kind == 'external':
            remote = remote or ('remote-unattributed', digest(who))
            continue
        path = cls.ah_run
        if not path or not REMOTE_PATH.fullmatch(path):
            remote = remote or ('remote-unwrapped', digest(who))
            if path:
                context.append('ah-run: host table ah_run path for %s is not a plain path; the ssh line was left unwrapped' % cls.name)
            continue
        task = task_key(payload, env)
        agent = safe_key(payload.get('agent_id'), 'main')
        session = safe_key(payload.get('session_id'), 'none')
        ticket = env.get('AGENT_HARNESS_TICKET')
        remote_raw = raws[count + 1:]
        remote_words = args[2 + count:]
        if any(w[2] for w in remote_words):
            # the local shell expands this text before ssh sees it: build the base64 from the same words at run time
            b64 = '"$(set -- %s; printf %%s "$*" | base64 | tr -d \'\\n\')"' % ' '.join(remote_raw)
        else:
            text = strip_ah_run_prefix(' '.join(w[1] for w in remote_words))
            if len(text.encode('utf-8')) > INLINE_LIMIT:
                raise ValueError('the remote command is %d bytes; the ssh limit is %d bytes (64 KiB). scp or rsync the payload '
                                 'to the host, then run a short remote command (for example `ssh HOST bash /path/script.sh`)'
                                 % (len(text.encode('utf-8')), INLINE_LIMIT))
            b64 = base64.b64encode(text.encode('utf-8')).decode('ascii')
        tail = ['python3', path] if path.endswith('.py') else [path]
        entry_env = cls.entry.get('remote_env')  # AGENT_HARNESS_* only: the rig points the remote reserve at a private dir
        pairs = []
        if isinstance(entry_env, dict):
            pairs = ['%s=%s' % (k, v) for k, v in sorted(entry_env.items())
                     if isinstance(k, str) and isinstance(v, str) and REMOTE_ENV_KEY.fullmatch(k) and REMOTE_ENV_VALUE.fullmatch(v)]
        tail = (['env'] + pairs if pairs else []) + tail
        tail += ['run', '--task', task, '--agent', agent]
        if ticket and SAFE_KEY.fullmatch(ticket):
            tail += ['--ticket', ticket]
        tail += ['--session', session, '--token', 'via-hook-ssh']
        if agent_is_readonly(payload):
            tail.append('--readonly')
        tail += ['--cmd-b64', b64]
        new_form = ' '.join([args[0][0], *raws[:count + 1], *tail, *redirects])
        if command.count(segment) != parsed.segments.count(segment):
            remote = remote or ('remote-unwrapped', digest(who))
            context.append('ah-run: an ssh line could not be rewritten safely (its text repeats inside another command); it runs unwrapped')
            continue
        command = command.replace(segment, prefix + new_form)
    return command, remote


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


def subagent_task(agent_id):
    """The task the spawn recorded for this agent (<reserve>/subagents/<agent_id>.json), or None. Written when a subagent
    starts (slice 7); a model cannot choose it per call."""
    key = safe_key(agent_id, None)
    if key is None or '/' in key:
        return None
    base = Path(os.environ.get('AGENT_HARNESS_RESERVE_DIR') or Path.home() / '.agent-harness' / 'reserve')
    try:
        fd = os.open(base / 'subagents' / (key + '.json'), os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd, 'rb') as handle:
            row = json.loads(handle.read(4097)[:4096])
    except (OSError, ValueError):
        return None
    task = row.get('task') if isinstance(row, dict) else None
    return task if isinstance(task, str) and SAFE_KEY.fullmatch(task) else None


def task_key_source(payload, env):
    """(key, source). AGENT_HARNESS_TASK in the hook environment wins, then the spawn record for this agent_id, then a
    [task:KEY] outside tool_input; a [task:KEY] in the tool input counts only for the main session (no agent_id) and is
    marked `input`; else a stable generated key."""
    given = env.get('AGENT_HARNESS_TASK')
    if given and SAFE_KEY.fullmatch(given):
        return given, 'env'
    agent_id = payload.get('agent_id')
    recorded = subagent_task(agent_id) if agent_id else None
    if recorded:
        return recorded, 'record'
    for text in _strings({k: v for k, v in payload.items() if k != 'tool_input'}):
        found = TASK_TOKEN.search(text)
        if found:
            return found.group(1), 'payload'
    if not agent_id:
        for text in _strings(payload.get('tool_input'), skip_command=True):
            found = TASK_TOKEN.search(text)
            if found:
                return found.group(1), 'input'
    seed = '%s%s' % (payload.get('session_id') or '', agent_id or '')
    return 'auto-' + digest(seed)[:12], 'generated'


def task_key(payload, env):
    return task_key_source(payload, env)[0]


def check_payload_cap(command):
    size = len(command.encode('utf-8'))
    if size > PAYLOAD_CAP:
        raise ValueError('command is %d bytes; the ah-run payload cap is %d bytes (1 MiB). Write it to a file and run the file.'
                         % (size, PAYLOAD_CAP))


def build_rewrite(command, payload, env, notes, context, remote=None):
    """The wrapped command and, when the pending row could be written, its token. Raises ValueError to deny."""
    raw = command.encode('utf-8')
    check_payload_cap(command)
    task, task_source = task_key_source(payload, env)
    agent = safe_key(payload.get('agent_id'), 'main')
    session = safe_key(payload.get('session_id'), 'none')
    ticket = env.get('AGENT_HARNESS_TICKET')
    token, root = None, None
    try:
        root = reserve_root()
        prune_pending(root)
        token = mint_pending(root, command, task, agent, session)
    except (OSError, RuntimeError):
        context.append('ah-run: the pending token row could not be written; attribution will be unverified')
    parts = ['python3', str(Path(__file__).resolve()), 'run', '--task', task, '--agent', agent]
    if ticket and SAFE_KEY.fullmatch(ticket):
        parts += ['--ticket', ticket]
    parts += ['--session', session]
    if token:
        parts += ['--token', token]
    if task_source in ('input', 'record'):
        parts += ['--task-source', task_source]
    if remote:
        parts += ['--command-class', remote[0], '--remote-host-sha256', remote[1]]
    elif 'pgid-split' in notes:
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

    asked = any(rule.matches(form) for part in parsed.segments + parsed.inner for rule in rules['ask'] for form in match_candidates(part))
    if (parsed.segments and not parsed.substitution and not parsed.newline and not parsed.uncertain and not parsed.pipeline
            and all(plain_recovery(segment, home) for segment in parsed.segments)):
        # exempt from the rewrite (and from the floor and heavy-command guards elsewhere), never from the allow rules
        recovery_allows = rules['allow']  # a rule naming ah-run is meaningful here: `ah-run kill` is recovery
        if not asked and all(any(rule.matches(normalize_segment(part)) for rule in recovery_allows) for part in parsed.segments):
            return _out('allow', 'recovery command with a matching allow rule runs unwrapped')
        if mode == 'bypassPermissions':
            return _out(None, 'recovery command runs unwrapped')
        if mode == 'dontAsk':
            return _out('deny', 'no allow rule matches this recovery command and permission mode dontAsk refuses to ask')
        return _out('ask', 'recovery command: no allow rule matches (run through its installed path or add a narrow rule)')

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
        command, remote = rewrite_ssh(command, parsed, payload, env, home, context)
        check_payload_cap(command)
    except ValueError as error:
        return _out('deny', 'ah-run: %s' % error)

    committed = any(rule.source == 'project' for rule in ignored)  # F75: a committed ah-run rule degrades to ask
    eligible = (bool(parsed.segments) and not committed and not parsed.substitution and not parsed.newline and not asked
                and not parsed.uncertain and all(part.split(None, 1)[0] != 'eval' for part in parsed.segments)
                and all(any(rule.matches(normalize_segment(part)) for rule in allows) for part in parsed.segments))
    if mode == 'bypassPermissions':
        decision = None
    elif eligible:
        decision = 'allow'
    elif mode == 'dontAsk':
        return _out('deny', 'no allow rule matches and permission mode dontAsk refuses to ask')  # nothing written for a refusal
    else:
        decision = 'ask'
    try:
        wrapped = build_rewrite(command, payload, env, notes, context, remote)  # the pending row and payload exist only now
    except ValueError as error:
        return _out('deny', 'ah-run: %s' % error)
    updated = {**(payload.get('tool_input') or {}), 'command': wrapped}
    extra = '\n'.join(context) or None
    if decision is None:
        return _out(None, None, updated, extra)
    if decision == 'allow':
        return _out('allow', 'every command matches an allow rule; wrapped in ah-run', updated, extra)
    if asked:
        why = 'ask rule matched'
    elif parsed.uncertain:
        why = 'quoting the hook cannot tokenize with certainty'
    elif parsed.substitution or parsed.newline:
        why = 'contains substitution, eval or a newline'
    else:
        why = 'no allow rule matches every command'
    return _out('ask', why, updated, extra)


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
    for name in ('--task', '--agent', '--ticket', '--session', '--token', '--cmd-file', '--cmd-b64', '--command-class', '--remote-host-sha256', '--task-source'):
        run.add_argument(name)
    run.add_argument('--readonly', action='store_true'); run.add_argument('--no-unit', action='store_true')
    run.add_argument('command', nargs=argparse.REMAINDER)
    kill_p = sub.add_parser('kill'); kill_p.add_argument('--task'); kill_p.add_argument('--agent')
    kill_p.add_argument('--pause', action='store_true'); kill_p.add_argument('--resume', action='store_true')
    led = sub.add_parser('ledger'); led.add_argument('--task'); led.add_argument('--live', action='store_true'); led.add_argument('--limit', type=int, default=50)
    led.add_argument('--prune', action='store_true')
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
