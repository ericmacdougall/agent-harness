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
import collections
import fnmatch
import functools
import fcntl
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


LAUNCH_SHELLS = frozenset(('bash', 'zsh'))
BASH_PATHS = ('/bin/bash', '/usr/bin/bash', '/opt/homebrew/bin/bash', '/usr/local/bin/bash')


def shell_for_command():
    """The shell Claude Code uses, with its snapshot sourced when one is named. Only bash or zsh, by basename: the hook's
    claim about a command is checked against what those two read, and an arbitrary $SHELL (fish, ksh, a wrapper script) would
    run text the claim never covered. Anything else falls back to the first bash found, then /bin/sh."""
    for shell in (os.environ.get('CLAUDE_CODE_SHELL'), os.environ.get('SHELL')):
        if shell and os.path.isabs(shell) and os.access(shell, os.X_OK) and shell.rsplit('/', 1)[-1] in LAUNCH_SHELLS:
            break
    else:
        shell = next((path for path in BASH_PATHS if os.access(path, os.X_OK)), '/bin/sh')
    snapshot = os.environ.get('CLAUDE_CODE_SHELL_SNAPSHOT')
    prelude = ''
    if snapshot and os.path.isfile(snapshot):
        prelude = 'source %s >/dev/null 2>&1 || true\n' % shell_quote(snapshot)
    return shell, prelude


def shell_quote(value):
    return "'" + str(value).replace("'", "'\\''") + "'"


TRAMPOLINE_CODE = (
    'import os, signal, sys, time\n'
    'rfd, grace, cmd = int(sys.argv[1]), float(sys.argv[2]), sys.argv[3:]\n'
    'forwarded = {signal.SIGTERM, signal.SIGINT, signal.SIGHUP}\n'
    # blocked across the forks: a signal arriving now waits for the watchdog's SIG_IGN and for the unblock before exec
    'signal.pthread_sigmask(signal.SIG_BLOCK, forwarded)\n'
    'try:\n'
    '    first = os.fork()\n'
    'except OSError:\n'
    '    first = -1\n'
    'if first == 0:\n'  # double fork: the watchdog is never a child of the shell
    '    try:\n'
    '        if os.fork() != 0:\n'
    '            os._exit(0)\n'
    '        for signum in forwarded:\n'
    '            signal.signal(signum, signal.SIG_IGN)\n'
    '        null = os.open(os.devnull, os.O_RDWR)\n'
    '        for fd in (0, 1, 2):\n'
    '            os.dup2(null, fd)\n'
    '        os.closerange(3, rfd); os.closerange(rfd + 1, 4096)\n'
    '        if os.read(rfd, 1) == b"":\n'  # EOF without the clean-end byte: the supervisor died
    '            group = os.getpgrp()\n'
    '            os.killpg(group, signal.SIGCONT); os.killpg(group, signal.SIGTERM)\n'
    '            time.sleep(grace); os.killpg(group, signal.SIGKILL)\n'
    '    except BaseException:\n'
    '        pass\n'
    '    os._exit(0)\n'
    'if first > 0:\n'
    '    os.waitpid(first, 0)\n'
    'os.close(rfd)\n'
    # Python ignores these at startup and an ignored signal stays ignored across exec
    'for name in ("SIGPIPE", "SIGXFSZ", "SIGXFZ"):\n'
    '    if hasattr(signal, name):\n'
    '        signal.signal(getattr(signal, name), signal.SIG_DFL)\n'
    'signal.pthread_sigmask(signal.SIG_UNBLOCK, forwarded)\n'
    'try:\n'
    '    os.execvp(cmd[0], cmd)\n'
    'except OSError:\n'
    '    os._exit(127)\n')


WATCHDOG_ARGV = '-I -S -c ' + TRAMPOLINE_CODE.split('\n', 1)[0]  # how the watchdog reads in `ps`; it keeps this argv


def trampoline_argv(read_fd, argv):
    """The child starts as a tiny Python process that is the session and group leader (start_new_session, so no job
    control stop on a controlling terminal). It double-forks a watchdog that stays in the group but is a child of
    neither the trampoline nor the shell, so the command sees no unexpected child, restores the signal dispositions
    Python changed, and execs the shell in its own pid. The watchdog ignores the forwarded signals and reads the pipe
    the supervisor holds: EOF without the clean-end byte means the supervisor died, and it ends the group (SIGCONT,
    SIGTERM, then SIGKILL after KILL_GRACE). -I keeps a signal.py or os.py in the cwd or on PYTHONPATH from running
    here; it reads no PYTHON* variable and changes no environment, so the command still sees the user's values."""
    return [sys.executable, '-I', '-S', '-c', TRAMPOLINE_CODE, str(read_fd), str(KILL_GRACE), *argv]


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


def pipe_above_stdio():
    """A pipe with both ends at 3 or above. With stdio closed, os.pipe() can return 0-2; the watchdog would overwrite that
    end with /dev/null, read EOF and end the group. Closed stdio itself is left closed, as it is without ah-run."""
    ends = []
    for fd in os.pipe():
        if fd < 3:
            moved = fcntl.fcntl(fd, fcntl.F_DUPFD_CLOEXEC, 3)
            ends.append((moved, fd))
        else:
            ends.append((fd, None))
    for _moved, old in ends:
        if old is not None:
            os.close(old)
    return ends[0][0], ends[1][0]


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
    try:
        read_fd, write_fd = pipe_above_stdio()
    except OSError:
        read_fd = write_fd = None  # no pipe: run without the in-group watchdog
    if read_fd is not None:
        argv = trampoline_argv(read_fd, argv)
    if use_unit:
        argv = ['systemd-run', '--user', '--scope', '--quiet', '--collect', '--unit', unit, *argv]
    if args.token == 'via-hook-ssh' and args.cmd_b64 and not args.cmd_file and not args.command:
        attribution, why = 'hook-ssh', None  # the hook-built remote form only
    elif args.token == 'via-hook-ssh':
        attribution, why = 'unverified', 'via-hook-ssh-needs-cmd-b64'
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
        for fd in (read_fd, write_fd):
            if fd is not None:
                os.close(fd)
        return 126
    row = {'schema': SCHEMA, 'run_id': run_id, 'task': task, 'agent': agent, 'ticket': ticket, 'session': session,
           'task_source': args.task_source if args.task_source in ('input', 'record') else None,
           'attribution': attribution, 'attribution_reason': why, 'readonly': bool(args.readonly), 'host': host_identity(),
           'command_sha256': digest(command), 'command_class': args.command_class or 'unclassified',
           'remote_host_sha256': safe_hex(args.remote_host_sha256),
           'cwd_sha256': digest(os.getcwd()), 'started_at': now(), 'supervisor_pid': os.getpid(),
           'supervisor_start': process_start_token(os.getpid()), 'unit': unit, 'end': None}
    try:
        child = subprocess.Popen(argv, env=env, start_new_session=True, pass_fds=(read_fd,) if read_fd is not None else ())
    except OSError as error:
        for fd in (read_fd, write_fd):
            if fd is not None:
                os.close(fd)
        row.update(end=now(), exit_code=127, error=type(error).__name__)
        _ledger_write(ledger, run_id, row)
        print('ah-run: cannot start the shell: %s' % type(error).__name__, file=sys.stderr)
        return 127
    pgid = child.pid  # a new session makes the child its own group leader
    if read_fd is not None:
        os.close(read_fd)
    row.update(pid=child.pid, pgid=pgid, start_token=process_start_token(child.pid),
               watchdog='in-group' if write_fd is not None else None)
    written = _ledger_write(ledger, run_id, row)
    state = {'signal': None, 'parent_died': False, 'escalation': None}

    def forward(signum, frame):
        state['signal'] = signum
        kill_group(pgid, signal.SIGCONT)  # a paused command must see the signal now, not when someone resumes it
        kill_group(pgid, signum if signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP) else signal.SIGTERM)
        if state['escalation'] is None:  # a command that ignores the signal still ends KILL_GRACE later
            state['escalation'] = threading.Timer(KILL_GRACE, kill_group, (pgid, signal.SIGKILL))
            state['escalation'].daemon = True
            state['escalation'].start()

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
    if write_fd is not None:  # normal end: tell the watchdog its job is done (its pipe would otherwise read as a death)
        try:
            os.write(write_fd, b'x')
        except OSError:
            pass
        os.close(write_fd)
    tree = pid_tree(pgid)
    end_group(pgid)  # leftovers of a finished leader are not part of the result
    if state['escalation'] is not None:
        state['escalation'].cancel()  # the group is gone; a late SIGKILL could only reach a reused pgid
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


def group_alive(pgid):
    try:
        os.killpg(pgid, 0)
        return True
    except OSError:  # gone, or (BSD) only zombies are left
        return False


def end_group(pgid):
    """SIGTERM what is left of a group; SIGKILL whatever still runs after KILL_GRACE. Returns at once when it empties."""
    kill_group(pgid, signal.SIGCONT)
    kill_group(pgid, signal.SIGTERM)
    deadline = time.monotonic() + KILL_GRACE
    while group_alive(pgid):
        if time.monotonic() >= deadline:
            kill_group(pgid, signal.SIGKILL)
            return
        time.sleep(0.02)


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
        if args.pause and WATCHDOG_ARGV in table[entry['pid']]['args']:
            skipped.append({'pid': entry['pid'], 'why': 'never paused: a stopped watchdog cannot end the group'})
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
ENV_PREFIX = re.compile(r'''^(?:[A-Za-z_][A-Za-z0-9_]*=(?:'[^']*'|"[^"]*"|[^ \t\n]*)[ \t\n]+)+''')
WRAPPER_PREFIX = re.compile(r'^(?:timeout[ \t\n]+(?:-[^ \t\n]+[ \t\n]+)*[0-9][^ \t\n]*|nice(?:[ \t\n]+-n[ \t\n]*[0-9]+|[ \t\n]+-[0-9]+)?|nohup|time|command|builtin|env)[ \t\n]+')
KEYWORD_PREFIX = re.compile(r'^(?:then|do|else|elif|if|while|until|!|\{)[ \t\n]+')
ESCAPE_NAMES = frozenset(('nohup', 'setsid', 'disown', 'screen', 'tmux', 'at', 'batch', 'crontab', 'osascript', 'coproc'))
LAUNCHCTL_ESCAPES = frozenset(('submit', 'bootstrap', 'load', 'kickstart'))
TASK_TOKEN = re.compile(r'\[task:([A-Za-z0-9][A-Za-z0-9._:/#-]{0,127})\]')
AH_PREFIX = re.compile(r'^[ \t\n]*(?:(?:[^ \t\n]*/)?python3?(?:\.[0-9]+)?(?:[ \t]+-[A-Za-z]+)*[ \t]+)?[^ \t\n]*(?:ah_run\.py|ah-run)(?=[ \t\n])')
RECOVERY_SCRIPTS = frozenset(('reserve.py', 'reclaim.py'))
POLICY_SELFCHECK_FIX = 'python3 harness/install.py --apply --role ROLE'
SCAN_CAP = 64 * 1024  # bytes of the whole command; above it nothing is scanned (docs/operations.md, ah-run hook)
HOOK_DEADLINE = 8.0  # seconds; the hook refuses rather than be killed by Claude Code's hook timeout


# -- the one lexer: "certain" is a closed claim ----------------------------------------------------------------
#
# A command is certain only when _Lexer finished without recording a reason. The grammar it accepts is the part of
# bash 3.2, bash 5.x, zsh, sh, dash and ksh that reads alike in all of them; every other character, token or construct
# records a named reason and the lexer carries on best effort, so an uncertain command still yields segments to check.
# Every other reader below (parse_command, heredoc_scan, join_continuations, inner_commands, script_bodies, physical_parts'
# ANSI decoding, the classifier and rewrite_ssh) consumes this output and decides nothing about quoting, blanks or comments
# itself. Python's str.strip, str.split and \s treat characters as blanks that no shell does, so they never decide here.
#
# Why named bad lists for the program word rather than a list of good programs: real commands run thousands of different
# programs and a positive list would make most of them uncertain. The lists below name only what changes how later text
# parses or runs quoted text as code. What they miss is stated in docs/operations.md under the limits of the claim.

HEREDOC_NONE, HEREDOC_CERTAIN, HEREDOC_UNCERTAIN = 'none', 'certain', 'uncertain'
HEREDOC_OPENER = re.compile(r"""<<(-?)[ \t]*(?:'([A-Za-z_][A-Za-z0-9_]*)'|"([A-Za-z_][A-Za-z0-9_]*)"|\\?([A-Za-z_][A-Za-z0-9_]*))(?=[ \t\n;&|)<>]|$)""")
HEREDOC_MARKER = re.compile(r'<<__HD(\d+)__')
SIMPLE_BRACE = re.compile(r'\$\{[A-Za-z_][A-Za-z0-9_]*\}')
MAX_GROUP_DEPTH = 16
WORD_END = ' \t\n;&|()<>'
WORD_RUN = re.compile(r"[A-Za-z0-9_./:,+=@%^~*?!\]-]+")
DQ_RUN = re.compile(r'[^"\\`$]+')
REDIRECT_OP = re.compile(r'&>>|&>|<<<|<<-?|<>|<&|>>|>&|>\||<|>')
SAFE_PARAM = re.compile(r'\$\{(?:#?[A-Za-z_][A-Za-z0-9_]*|[0-9]+|[@*#?]'
                        r'|(?:[A-Za-z_][A-Za-z0-9_]*|[0-9]+)(?::-|:=|:\+|:\?|-|=|\+|\?|##?|%%?|//?)'
                        r'(?:[A-Za-z0-9_./:,+=@%^~*?-]*|\$[A-Za-z_][A-Za-z0-9_]*))\}')
ANSI_ESCAPES = frozenset('abeEfnrtv\\"?01234567xuU')
ARITH_CHARS = frozenset('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_ \t+-*/%<>=!&|^~,?:$')
DOLLAR_SPECIALS = frozenset('#?!-_*@$0123456789')
ASSIGN_WORD = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*\+?=')
SUBSCRIPT_CODE = re.compile(r'(?<=[A-Za-z0-9_])\[[^\[\]]*(?:\$\(|`)')
SET_FLAGS = re.compile(r'[-+][eux]*o?')
SHELL_C = re.compile(r'-[A-Za-z]*c[A-Za-z]*')
KEYWORDS = frozenset(('if', 'then', 'elif', 'else', 'fi', 'for', 'while', 'until', 'do', 'done', '{', '}', '!'))
KEYWORD_AFTER = {'then': ('if',), 'elif': ('then',), 'else': ('then',), 'fi': ('then', 'else'), 'do': ('while', 'for'),
                 'done': ('do',), '}': ('{',)}
STATE_VARS = frozenset(('PS1 PS2 PS3 PS4 PROMPT PROMPT2 PROMPT3 PROMPT4 RPROMPT PROMPT_COMMAND histchars BASH_ENV ENV ZDOTDIR '
                        'SHELLOPTS BASHOPTS POSIXLY_CORRECT PATH path FPATH fpath').split(' '))
PARSE_CHANGING = frozenset(('function alias unalias shopt setopt unsetopt emulate enable disable hash bindkey bind zmodload '
                            'autoload repeat noglob nocorrect - foreach select coproc case esac declare typeset readonly '
                            'sched').split(' '))
QUOTED_CODE = frozenset('trap eval let mapfile readarray compgen complete compctl fc print'.split(' '))
UNPEELED_WRAPPERS = frozenset(('busybox stdbuf flock script arch caffeinate ionice chronic watch xargs parallel nsenter chroot '
                               'unshare setpriv taskset numactl unbuffer rlwrap su doas pkexec runuser fakeroot strace ltrace '
                               'dtruss').split(' '))
SHELL_NAMES = frozenset('bash sh zsh dash ksh ash mksh ksh93 rbash fish csh tcsh'.split(' '))
FIND_RUNNERS = frozenset(('-exec', '-execdir', '-ok', '-okdir'))
# ssh, scp and sftp run these option values as local shell code (r6 N22): a quoted-code host like find -exec. A config file
# named by -F that sets them is a limit (operations.md).
SSH_O_CLUSTER = re.compile(r'-[46AaCfGgKkMNnqsTtVvXxYy]*o')
SSH_OPTION_CODE = re.compile(r'(?i)(proxycommand|knownhostscommand|localcommand|match)([ \t=]|$)')

Word = collections.namedtuple('Word', 'raw value dynamic')  # raw: normalized text; value: quotes removed, a group is X
Command = collections.namedtuple('Command', 'text words operator closer')  # words exclude keywords, redirects and targets


class _WordBuf:
    __slots__ = ('raw', 'value', 'dynamic')

    def __init__(self):
        self.raw, self.value, self.dynamic = [], [], False

    def add(self, raw, value=None):
        self.raw.append(raw); self.value.append(raw if value is None else value)


class _ListState:
    """One command list: the top level, a subshell or a substitution body."""
    __slots__ = ('closer', 'depth', 'group', 'commands', 'cur', 'words', 'stack', 'after_close', 'need_command', 'prev_op',
                 'here_string', 'for_header', 'redirected', 'amp_redirect')

    def __init__(self, closer, depth, group, commands):
        self.closer, self.depth, self.group, self.commands = closer, depth, group, commands
        self.cur, self.words, self.stack = [], [], []
        self.after_close = self.need_command = self.here_string = self.for_header = False
        self.redirected = self.amp_redirect = False
        self.prev_op = None


class _Lexer:
    """One pass over one command. `reasons` names everything outside the grammar and is empty only for a certain command.
    `whole` reads `<<` as a plain redirect, so an uncertain command's body lines stay in the output as commands."""

    def __init__(self, text, whole=False):
        self.text, self.n, self.whole = text, len(text), whole
        self.reasons = {}
        self.commands, self.groups, self.group_texts = [], [], []
        self.bodies, self.openers, self.opener_spans, self.spans, self.pending = [], [], [], [], []
        self.continuations = []
        self.newline = self.pipeline = self.substitution = self.saw_nesting = self.stopped = False
        self.first = self.n - len(text.lstrip(' \t\n'))
        self.last = len(text.rstrip(' \t\n'))

    def reason(self, name):
        self.reasons.setdefault(name, None)

    def run(self):
        if '\0' in self.text:
            self.reason('nul')
        try:
            self._list(0, None, 0, False, self.commands)
        except RecursionError:
            self.reason('nesting')
        if self.pending:
            self.reason('heredoc-unterminated')
            self.pending = []
        if self.openers and self.saw_nesting:
            self.reason('heredoc-with-group')  # a body's start depends on where the nested text ends
        if _quoted_continuation(''.join(_cut_bodies(self.text, self.spans))):
            self.reason('quoted-continuation')
        return self

    # -- lists -------------------------------------------------------------------------------------------------

    def _list(self, i, closer, depth, group, commands):
        if depth > MAX_GROUP_DEPTH:
            self.reason('nesting')
            self.stopped = True
            return self.n
        st, text, n = _ListState(closer, depth, group, commands), self.text, self.n
        while i < n and not self.stopped:
            ch = text[i]
            if ch in ' \t':
                st.cur.append(ch); i += 1
            elif ch == '\n':
                i = self._newline(i, st)
            elif ch == '\\' and text[i + 1:i + 2] == '\n':
                self._continuation(i); i += 2
            elif ch == '#':
                i = self._comment(i, st)
            elif ch in '<>' or text.startswith('&>', i):
                i = self._redirect(i, st)
            elif ch in ';&|':
                i = self._operator(i, st)
            elif ch == '(':
                i = self._subshell(i, st)
            elif ch == ')':
                if closer == ')':
                    self._close_list(st)
                    return i + 1
                self.reason('stray-paren')
                self._cut(st, ')'); i += 1
            else:
                i = self._word_into(i, st)
        self._close_list(st)
        if closer and not self.stopped:
            self.reason('unterminated')
        return n

    def _close_list(self, st):
        self._cut(st, None)
        if st.stack:
            self.reason('unclosed-keyword')
        if st.need_command:
            self.reason('dangling-operator')

    def _cut(self, st, operator):
        text, words, closer = ''.join(st.cur).strip(' \t\n'), st.words, st.after_close
        st.cur, st.words = [], []
        if st.for_header:
            self._check_for_header(words)
            st.for_header, words = False, []
        elif words:
            self._check_command(words, st.prev_op, st.here_string)
        if text or words or closer:
            st.commands.append(Command(text, tuple(words), operator, closer))
        st.after_close = st.here_string = st.redirected = st.amp_redirect = False

    def _newline(self, i, st):
        self._cut(st, '\n')
        if not st.need_command:
            st.prev_op = '\n'
        j = self._read_bodies(i + 1) if self.pending else i + 1
        if not st.group and self.first < i and j < self.last:
            self.newline = True
        return j

    def _continuation(self, i):
        if self.pending:
            self.reason('continuation-after-opener')
        self.continuations.append(i)

    def _comment(self, i, st):
        text = self.text
        if text[max(i - 2, 0):i] == '\\\n':
            self.reason('hash-after-continuation')
        elif i and text[i - 1] in '()<>':
            self.reason('hash-glued')
        if st.group:
            self.reason('comment-in-group')
        end = text.find('\n', i)
        end = self.n if end < 0 else end
        if '<<' in text[i:end]:
            self.reason('heredoc-lookalike')
        return end

    def _operator(self, i, st):
        text = self.text
        two = text[i:i + 2]
        if two in (';;', ';&', ';|'):
            self.reason('case-operator')
        elif two == '|&':
            self.reason('pipe-amp')
        elif two in ('&|', '&!'):
            self.reason('zsh-disown')
        size = 2 if two in (';;', ';&', ';|', '|&', '&|', '&!', '&&', '||') else 1
        operator = {'|&': '|', '&|': '&', '&!': '&'}.get(two, text[i:i + size])
        if not (st.words or st.after_close or st.redirected or st.for_header):
            self.reason('empty-command')
        self._cut(st, operator)
        st.need_command, st.prev_op = operator in ('&&', '||', '|'), operator
        if not st.group and operator in ('|', '&'):
            self.pipeline = True
        self._split_operator(i + size)
        return i + size

    def _split_operator(self, j):
        if self.text.startswith('\\\n', j) and self.text[j + 2:j + 3] and self.text[j + 2] in ';&|<>':
            self.reason('split-operator')

    def _subshell(self, i, st):
        if self.text.startswith('((', i):
            self.reason('arith-command')
        if st.words or st.redirected or st.after_close or st.for_header or st.stack[-1:] == ['for']:
            self.reason('attached-paren')
        self._cut(st, '(')
        st.need_command = False
        end = self._list(i + 1, ')', st.depth + 1, st.group, st.commands)
        st.after_close = True
        return end

    # -- redirects and heredocs ----------------------------------------------------------------------------------

    def _redirect(self, i, st):
        text, n = self.text, self.n
        op = REDIRECT_OP.match(text, i).group()
        st.need_command = False
        if op in ('<', '>') and text[i + 1:i + 2] == '(':
            return self._process_substitution(i, st)
        if op in ('<<', '<<-') and not self.whole:
            return self._opener(i, op, st)
        j = i + len(op)
        if op == '<<<':
            st.here_string = True
            if text[j:j + 1] == '<':
                self.reason('heredoc-lookalike')
        elif op in ('&>', '&>>'):
            st.amp_redirect = True
        self._split_operator(j)
        st.cur.append(op)
        st.redirected = True
        while j < n and (text[j] in ' \t' or text.startswith('\\\n', j)):
            if text[j] == '\\':
                self._continuation(j); j += 2
            else:
                st.cur.append(text[j]); j += 1
        if j >= n or text[j] in WORD_END:
            self.reason('redirect-target')
            return j
        if text[j] == '#':
            self.reason('hash-glued')
            return self._comment(j, st)
        word, j = self._word(j, st)
        st.cur.append(word.raw)
        return j

    def _process_substitution(self, i, st):
        if i and self.text[i - 1] not in ' \t\n;&|(':
            self.reason('attached-procsub')
        end = self._group(i + 1, _WordBuf(), st)
        if end < self.n and self.text[end] not in WORD_END:
            self.reason('attached-procsub')
        st.cur.append('X')
        st.words.append(Word('X', 'X', True))
        return end

    def _opener(self, i, op, st):
        text = self.text
        found = HEREDOC_OPENER.match(text, i)
        if st.group:
            self.reason('heredoc-in-group')
        if not found:
            self.reason('heredoc-opener')
            st.cur.append(op)
            return i + len(op)
        delimiter = found.group(2) or found.group(3) or found.group(4)
        quoted = bool(found.group(2) or found.group(3)) or text[found.end() - len(delimiter) - 1] == '\\'
        self.pending.append((delimiter, quoted, bool(found.group(1))))
        self.openers.append(found.group())
        self.opener_spans.append((i, found.end()))
        st.cur.append('<<__HD%d__' % (len(self.openers) - 1))
        st.redirected = True
        return found.end()

    def _read_bodies(self, i):
        """The bodies of the pending openers from the line at i. A body ends only on a line holding exactly its delimiter
        (tabs stripped first for <<-). An unquoted body that a shell would read differently records a reason."""
        text, n, position = self.text, self.n, i
        for delimiter, quoted, strip_tabs in self.pending:
            body = []
            while True:
                if position > n:
                    self.reason('heredoc-unterminated')
                    self.pending = []
                    return i
                end = text.find('\n', position)
                end = n if end < 0 else end
                line = text[position:end]
                position = end + 1
                compared = line.lstrip('\t') if strip_tabs else line
                if compared == delimiter:
                    break
                if not quoted and _body_line_runs_code(line):
                    self.reason('heredoc-body')
                body.append(compared)
            self.bodies.append(('\n'.join(body) + '\n', quoted))
        self.pending = []
        self.spans.append((i, position))
        return min(position, n)

    # -- words ---------------------------------------------------------------------------------------------------

    def _word_into(self, i, st):
        text, n = self.text, self.n
        word, j = self._word(i, st)
        st.cur.append(word.raw)
        if j < n and text[j] in '<>' and word.raw.isdigit():
            return j  # a file descriptor, part of the redirect that follows
        st.need_command = False
        if st.after_close:
            self.reason('word-after-close')
        if st.amp_redirect:
            self.reason('amp-redirect-words')  # sh and dash read `a &>f b` as `a &` then `>f b`, which runs b
        if not st.words and not st.for_header and not st.redirected and not st.after_close and self._keyword(word, st):
            return j
        if word.raw in ('{', '}'):
            self.reason('lone-brace')  # zsh closes a group on a bare }; bash passes it as an argument
        st.words.append(word)
        return j

    def _keyword(self, word, st):
        name, stack = word.raw, st.stack
        top = stack[-1] if stack else None
        if top == 'for' and name != 'do':
            self.reason('keyword-order')
        if name not in KEYWORDS:
            return False
        if name == '!':
            return True
        if name in ('if', 'while', 'until', '{', 'for'):
            stack.append('while' if name == 'until' else name)
            st.for_header = name == 'for'
            return True
        closes = name in ('fi', 'done', '}')
        if top not in KEYWORD_AFTER[name]:
            self.reason('keyword-order')
            st.after_close = closes
            return True
        if closes:
            stack.pop()
            st.after_close = True
        else:
            stack[-1] = {'then': 'then', 'elif': 'if', 'else': 'else', 'do': 'do'}[name]
        return True

    def _check_for_header(self, words):
        ok = bool(words) and bool(re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', words[0].raw)) and (len(words) == 1 or words[1].raw == 'in')
        if not ok:
            self.reason('for-header')

    def _word(self, i, st):
        text, n, w = self.text, self.n, _WordBuf()
        while i < n and not self.stopped:
            run = WORD_RUN.match(text, i)
            if run:
                piece = run.group()
                w.add(piece)
                w.dynamic = w.dynamic or '*' in piece or '?' in piece
                i = run.end()
                continue
            ch = text[i]
            if ch in WORD_END:
                break
            if ch == "'":
                i = self._single(i, w, st)
            elif ch == '"':
                i = self._double(i, w, st)
            elif ch == '\\':
                i = self._escape(i, w, st)
            elif ch == '`':
                i = self._backtick(i, w, st)
            elif ch == '$':
                i = self._dollar(i, w, st)
            elif ch == '#':
                if text[max(i - 2, 0):i] in ('\\ ', '\\\t'):
                    self.reason('hash-after-escaped-blank')
                w.add(ch); i += 1
            elif ch in '{}':
                w.dynamic = w.dynamic or ch == '{'
                w.add(ch); i += 1
            elif ch == '[':
                i = self._bracket(i, w)
            else:
                self.reason('character')  # a control or non-ASCII character outside quotes, comments and bodies
                w.add(ch); i += 1
        return Word(''.join(w.raw), ''.join(w.value), w.dynamic), i

    def _bracket(self, i, w):
        text = self.text
        if not w.raw and text.startswith('[[', i):
            self.reason('dbracket')  # bash, zsh and ksh parse inside it; sh and dash run a program named [[
            w.add('[[')
            return i + 2
        following = text[i + 1:i + 2]
        if w.raw or (following and following not in WORD_END):
            self.reason('bracket-in-word')  # a glob in some shells, a subscript that holds blanks and code in others
            w.dynamic = True
        w.add('[')
        return i + 1

    def _escape(self, i, w, st):
        text, n = self.text, self.n
        following = text[i + 1:i + 2]
        if not following:
            self.reason('trailing-backslash')
            w.add('\\', '')
            return n
        if following == '\n':
            self._continuation(i)
            if i + 2 < n and text[i + 2] not in WORD_END:
                self.reason('split-word')  # best effort: the two pieces read as one word
            return i + 2
        if following in '<>':
            self.reason('escaped-redirect')
        elif st.group and following in '\'"`':
            self.reason('quote-in-group')
        elif following not in ' \t' and not ' ' <= following <= '~':
            self.reason('character')
        w.add(text[i:i + 2], following)
        return i + 2

    def _single(self, i, w, st):
        text = self.text
        if st.group:
            self.reason('quote-in-group')
        end = text.find("'", i + 1)
        if end < 0:
            self.reason('unterminated')
            w.add(text[i:], text[i + 1:])
            return self.n
        body = text[i + 1:end]
        self._check_quoted(body)
        w.add(text[i:end + 1], body)
        return end + 1

    def _check_quoted(self, body):
        if '<<' in body:
            self.reason('heredoc-lookalike')
        if self.pending and '\n' in body:
            self.reason('heredoc-quoted-newline')

    def _double(self, i, w, st):
        text, n, start = self.text, self.n, i
        if st.group:
            self.reason('quote-in-group')
        w.raw.append('"')
        i += 1
        while i < n and not self.stopped:
            run = DQ_RUN.match(text, i)
            if run:
                w.add(run.group())
                i = run.end()
                continue
            ch = text[i]
            if ch == '"':
                self._check_quoted(text[start:i])
                w.raw.append('"')
                return i + 1
            if ch == '\\':
                following = text[i + 1:i + 2]
                if following == '\n':
                    self._continuation(i)
                else:
                    w.add(text[i:i + 2], following if following in '"\\$`' else text[i:i + 2])
                i += 2
            elif ch == '`':
                i = self._backtick(i, w, st)
            else:
                i = self._dollar(i, w, st, quoted=True)
        self.reason('unterminated')
        return n

    def _dollar(self, i, w, st, quoted=False):
        text = self.text
        following = text[i + 1:i + 2]
        if not quoted and following == "'":
            return self._ansi(i, w, st)
        w.dynamic = True
        if following == '(':
            if text[i + 2:i + 3] == '(':
                end = self._arithmetic(i)
                if end is not None:
                    self.substitution = self.saw_nesting = True
                    w.add('X')
                    return end
                self.reason('arith')  # bash reads $(( that is not arithmetic as a command substitution
            return self._group(i + 1, w, st)
        if following == '{':
            return self._parameter(i, w)
        if following == '[':
            self.reason('old-arith')
            end = text.find(']', i)
            end = self.n if end < 0 else end + 1
            w.add(text[i:end])
            return end
        if not quoted and following == '"':
            w.add('$', '')
            return self._double(i + 1, w, st)
        if following and following in DOLLAR_SPECIALS:
            w.add(text[i:i + 2])
            after = text[i + 2:i + 3]
            if not quoted and after and after in '\'"(':
                self.reason('dollar-special-quote')
            return i + 2
        w.add('$')
        return i + 1

    def _ansi(self, i, w, st):
        text, n = self.text, self.n
        self.saw_nesting = True
        if st.group:
            self.reason('quote-in-group')
        j, clean = i + 2, True
        while j < n and text[j] != "'":
            if text[j] == '\\':
                clean = clean and text[j + 1:j + 2] in ANSI_ESCAPES
                j += 2
            else:
                j += 1
        if j >= n:
            self.reason('unterminated')
            w.add(text[i:])
            return n
        end = j + 1
        if not clean or "\\'" in text[i:end]:  # \c, or a shell without $'...' (dash) ends the string at that quote
            self.reason('ansi-c')
        try:
            value = _decode_ansi_c(text, i + 2)[0]
        except ValueError:
            self.reason('ansi-c')
            value = text[i + 2:j]
        self._check_quoted(text[i:end])
        w.add(shell_quote(value), value)
        return end

    def _arithmetic(self, i):
        """The index past the `))` of the plain arithmetic at text[i:], or None. A `)` that closes nothing opened inside and is
        not followed by another `)` makes bash read the whole thing as a command substitution."""
        text, n, j, depth = self.text, self.n, i + 3, 0
        while j < n:
            ch = text[j]
            if ch == '(':
                depth += 1
            elif ch == ')':
                if not depth:
                    return j + 2 if text[j + 1:j + 2] == ')' else None
                depth -= 1
            elif ch not in ARITH_CHARS or text.startswith('<<', j) or (ch == '$' and text[j + 1:j + 2] in ('(', '[', '{', "'", '"', '`')):
                return None
            j += 1
        return None

    def _parameter(self, i, w):
        safe = SAFE_PARAM.match(self.text, i)
        if safe:
            if not SIMPLE_BRACE.fullmatch(safe.group()):
                self.saw_nesting = True
            w.add(safe.group())
            return safe.end()
        self.reason('param-expansion')  # ${ cmd; }, a blank or # inside, a quote, a nested group: shells disagree on all of them
        self.saw_nesting = True
        end = self._parameter_end(i + 2)
        w.add(self.text[i:end])
        return end

    def _parameter_end(self, i):
        text, n, depth = self.text, self.n, 1
        while i < n:
            ch = text[i]
            if ch == '\\':
                i += 2
                continue
            depth += ch == '{'
            depth -= ch == '}'
            i += 1
            if not depth:
                return i
        self.reason('unterminated')
        return n

    def _group(self, i, w, st):
        """The substitution whose `(` is at text[i]. It appears as X in the word; its commands are kept in self.groups."""
        text = self.text
        self.substitution = self.saw_nesting = True
        commands, index = [], len(self.groups)
        self.groups.append(commands)
        self.group_texts.append('')
        end = self._list(i + 1, ')', st.depth + 1, True, commands)
        self.group_texts[index] = text[i + 1:end - 1] if text[end - 1:end] == ')' else text[i + 1:end]
        w.add('X')
        w.dynamic = True
        return end

    def _backtick(self, i, w, st):
        text, n, j = self.text, self.n, i + 1
        self.substitution = self.saw_nesting = True
        w.dynamic = True
        while j < n and text[j] != '`':
            if text[j] == '\\':
                self.reason('backslash-in-backtick')
                j += 2
            else:
                j += 1
        if j >= n:
            self.reason('unterminated')
            w.add('X')
            return n
        sub, commands = _Lexer(text[i + 1:j], self.whole), []
        sub.reasons, sub.groups, sub.group_texts = self.reasons, self.groups, self.group_texts
        self.groups.append(commands)
        self.group_texts.append(sub.text)
        sub._list(0, None, st.depth + 1, True, commands)
        self.stopped = self.stopped or sub.stopped
        if sub.pending:
            self.reason('heredoc-unterminated')
        w.add('X')
        return j + 1

    # -- the program word ------------------------------------------------------------------------------------------

    def _check_command(self, words, prev_op, here_string):
        """The closed checks on one simple command: anything that changes how later text parses, or runs quoted text as
        code, makes the command uncertain. Wrappers are looked through by the same step peel_wrapper uses."""
        values, raws, k, count = [w.value for w in words], [w.raw for w in words], 0, len(words)
        for value in values:
            if SUBSCRIPT_CODE.search(value):
                self.reason('subscript-code')
        for _ in range(12):
            while k < count and ASSIGN_WORD.match(raws[k]):
                if raws[k].split('=', 1)[0].rstrip('+') in STATE_VARS:
                    self.reason('state-variable')
                k += 1
            if k >= count:
                return
            word = words[k]
            if word.dynamic or word.value.startswith('='):
                self.reason('dynamic-program-word')  # the shell picks the program after expansion; zsh runs =cmd too
                return
            base = word.value.rsplit('/', 1)[-1]
            step = _wrapper_step(base, values, raws, k + 1)
            if step is None:
                self._check_program(base, words[k + 1:], prev_op, here_string)
                return
            if step < 0:
                self.reason('quoted-code:env-S')
                return
            if base == 'exec' and step >= count:
                self.reason('exec-redirect')  # later commands read and write through whatever it opened
            if base in ('env', 'sudo'):
                for j in range(k + 1, step):
                    if ASSIGN_WORD.match(raws[j]) and raws[j].split('=', 1)[0].rstrip('+') in STATE_VARS:
                        self.reason('state-variable')
            k = step
        self.reason('wrapper-depth')

    def _check_program(self, base, args, prev_op, here_string):
        values = [word.value for word in args]
        if base in PARSE_CHANGING:
            self.reason('parse-word:' + base)
        elif base in QUOTED_CODE:
            self.reason('quoted-code:' + base)
        elif base in UNPEELED_WRAPPERS:
            self.reason('wrapper:' + base)
        elif base in SHELL_NAMES:
            if any(SHELL_C.fullmatch(value) for value in values):
                self.reason('quoted-code:shell-c')
            elif here_string:
                self.reason('quoted-code:shell-here-string')
            elif any(word.dynamic for word in args):
                self.reason('shell-dynamic-arg')
            elif prev_op == '|':
                self.reason('pipe-into-shell')
        elif base == 'set':
            self._check_set(values)
        elif base == 'find':
            if any(value in FIND_RUNNERS for value in values):
                self.reason('find-exec')
        elif base == 'git':
            if any(value == '-c' and following.lower().startswith('alias.') for value, following in zip(values, values[1:])):
                self.reason('git-alias')
        elif base in ('ssh', 'scp', 'sftp'):
            for i, value in enumerate(values):
                cluster = SSH_O_CLUSTER.match(value)
                if cluster:
                    option = value[cluster.end():] or (values[i + 1] if i + 1 < len(values) else '')
                    if SSH_OPTION_CODE.match(option):
                        self.reason('quoted-code:ssh-option')
                        return
        elif base in ('source', '.'):
            if any(value.startswith('/dev/') for value in values):
                self.reason('source-dev')  # runs a body an earlier `exec 3<<E` saved
        elif base == 'export':
            if any(value.split('=', 1)[0] in STATE_VARS for value in values):
                self.reason('state-variable')

    def _check_set(self, values):
        """`set` is certain only for -e, -u, -x, -o pipefail, their + forms, -- and positional words."""
        i = 0
        while i < len(values):
            value = values[i]
            if value == '--' or value[:1] not in ('-', '+'):
                return
            if len(value) < 2 or not SET_FLAGS.fullmatch(value):
                self.reason('set-option')
                return
            if value.endswith('o'):
                if values[i + 1:i + 2] != ['pipefail']:
                    self.reason('set-option')
                    return
                i += 1
            i += 1


def _body_line_runs_code(line):
    """True when a shell reading an unquoted heredoc line can run or join something: a trailing backslash, $(...), a
    backtick, $[...], or ${...} other than ${NAME}."""
    if line.endswith('\\') or '$(' in line or '`' in line or '$[' in line:
        return True
    at = line.find('${')
    while at >= 0:
        found = SIMPLE_BRACE.match(line, at)
        if not found:
            return True
        at = line.find('${', found.end())
    return False


def lex(command):
    """The lexed command. When an uncertain command holds an opener, its text is read again with `<<` as a plain redirect:
    a body cannot be told from commands then, so its lines stay in the output as commands."""
    first = _Lexer(command).run()
    if not (first.reasons and first.openers):
        return first
    second = _Lexer(command, whole=True).run()
    second.reasons = first.reasons
    return second


CONTINUED_LINE = re.compile(r'(?<!\\)\n')


def _quoted_continuation(text):
    """True when a quote character sits in a fragment joined by backslash-newline: the shell's reading of that join depends
    on the quoting around it, and every model of it so far has been wrong somewhere. Any line ending in a backslash counts,
    an even run of them included; a false answer here costs a prompt."""
    if '\\\n' not in text:
        return False
    return any('\\\n' in fragment and ("'" in fragment or '"' in fragment) for fragment in CONTINUED_LINE.split(text))


def _cut_bodies(command, spans):
    """The typed text around the body spans, as a list: outside, outside, ..., one more item than spans."""
    pieces, at = [], 0
    for start, end in spans:
        pieces.append(command[at:start]); at = end
    pieces.append(command[at:])
    return pieces


def _replace_spans(command, cuts):
    out, at = [], 0
    for start, end, text in sorted(cuts):
        out.append(command[at:start]); out.append(text)
        at = end
    out.append(command[at:])
    return ''.join(out)


def _masked_text(command, lexed, join):
    """The typed text with each body swapped for a placeholder and, when `join`, the lexer's continuations removed."""
    cuts = [(start, end, '\0%d\0' % index) for index, (start, end) in enumerate(lexed.spans)]
    if join:
        cuts.extend((at, at + 2, '') for at in lexed.continuations)
    return _replace_spans(command, cuts)


def join_continuations(text):
    """Backslash-newline removed where the lexer found one (not in single quotes, $'...', a comment or a body)."""
    if '\\\n' not in text:
        return text
    return _replace_spans(text, [(at, at + 2, '') for at in lex(text).continuations])


def inner_commands(text):
    """The text of every $(...), `...`, <(...) and >(...), nested ones included, outer before inner."""
    return list(lex(text).group_texts)


def heredoc_scan(command, openers=None, spans=None):
    """(status, text, bodies): `certain` (markers replace the bodies; bodies are (text, quoted) pairs) when the lexer recorded
    no reason and read a body; `uncertain`, with the text left whole, when it recorded a reason and the text holds `<<`;
    `none` otherwise. `openers` receives each opener's text in marker order; `spans`, each (start, end) of the typed command
    that holds bodies, terminators included."""
    lexed = lex(command)
    if lexed.reasons:
        return (HEREDOC_UNCERTAIN if '<<' in command else HEREDOC_NONE), command, []
    if not lexed.bodies:
        return HEREDOC_NONE, command, []
    if openers is not None:
        openers.extend(lexed.openers)
    if spans is not None:
        spans.extend(lexed.spans)
    cuts = [(start, end, '<<__HD%d__' % index) for index, (start, end) in enumerate(lexed.opener_spans)]
    cuts.extend((start, end, '') for start, end in lexed.spans)
    return HEREDOC_CERTAIN, _replace_spans(command, cuts), lexed.bodies


HEREDOC_HINT = ("Text in a heredoc inside $(...) is checked line by line as commands. Use a top-level quoted heredoc: "
                "`git commit -F - <<'EOF'` for a commit message, `gh pr create --body-file - <<'EOF'` for a PR body.")
PHYSICAL_SPLIT = re.compile(r'[;&|()`\n\r<>]|\$\(')  # a redirect can touch the word before it (`touch<<E`)
BACKGROUND_AMP = re.compile(r'(?<![&<>])&(?=[ \t\n]|$)')
LATER_WAIT = re.compile(r'(?:^|[ \t\n;&|(])wait(?=[ \t\n;&|)]|$)')
SCRIPT_HOSTS = frozenset(('bash', 'sh', 'zsh', 'dash', 'ksh', 'source', '.'))
SHELL_LINE_BLANKS = re.compile(r'[ \t\n]+')
ANSI_IN_FRAGMENT = re.compile(r"\$'")


def _blank_split(text):
    """Words at the blanks a shell splits on."""
    return [word for word in SHELL_LINE_BLANKS.split(text) if word]


def _reads_script(fragment):
    """True when this simple command runs its stdin or a heredoc as shell text: a shell, source or `.` (through any wrapper),
    or ssh with no remote command or a shell in it."""
    for form in match_candidates(fragment):
        try:
            words = [word[1] for word in raw_words(HEREDOC_MARKER.sub('', form))]
        except ValueError:
            words = _blank_split(form)
        name = words[0].rsplit('/', 1)[-1] if words else ''
        if name in SCRIPT_HOSTS:
            return True
        if name == 'ssh':
            call = host_table.parse_ssh(words[1:])
            if call and (not call.remote or any(word.rsplit('/', 1)[-1] in SCRIPT_HOSTS for word in _blank_split(' '.join(call.remote)))):
                return True
    return False


def script_bodies(lexed):
    """The heredoc bodies of a certain command that a shell will run: read by a shell directly or on a compound command's
    close (`{ bash; } <<E`, `done <<E`, a subshell's `)`). Every shape that hides the reader further (a pipeline into a shell,
    a variable, a function, xargs, eval, `exec 3<<E`) is uncertain already. Any other reader (cat, python3 -) keeps its body
    as data."""
    found = []
    for command in lexed.commands:
        numbers = [int(number) for number in HEREDOC_MARKER.findall(command.text)]
        if numbers and (not command.words or command.closer or _reads_script(' '.join(word.raw for word in command.words))):
            found.extend(lexed.bodies[number][0] for number in numbers if number < len(lexed.bodies))
    return found


def _decoded_ansi(fragment):
    """The fragment with each $'...' it holds decoded, or None when none can be."""
    out, at, changed = [], 0, False
    for found in ANSI_IN_FRAGMENT.finditer(fragment):
        if found.start() < at:
            continue
        try:
            value, end = _decode_ansi_c(fragment, found.end())
        except ValueError:
            continue
        out.append(fragment[at:found.start()]); out.append(shell_quote(value))
        at, changed = end, True
    if not changed:
        return None
    out.append(fragment[at:])
    return ''.join(out)


def physical_parts(command):
    """Every fragment of every physical line of a command the hook could not parse with certainty, cut at each operator
    with quoting ignored, since the quoting is what is in doubt, and the same again with every backslash-newline removed, so
    a word split over a continuation is seen whole. Used only to widen a deny or an escape check; a fragment that is really
    string text can give a false deny, never a missed one."""
    parts = []
    text = command + '\n' + command.replace('\\\n', '') if '\\\n' in command else command
    for fragment in PHYSICAL_SPLIT.split(text):
        fragment = fragment.strip(' \t\n\r\f\v')
        bare = fragment.strip('\'"$ \t')
        for form in (fragment, bare):
            if form and form not in parts[-2:]:
                parts.append(form)
        if "$'" in fragment:
            decoded = _decoded_ansi(fragment)
            if decoded:
                parts.append(decoded)
    return parts


# The bypass rule for uncertain text. Bypass makes no decision of its own, so without this an uncertain command runs unless one
# of its guessed fragments matched a deny rule. It reads the text with quoting ignored: a rule's literal prefix (or an escape
# name) at a word start anywhere refuses the command. This is the only place that decides it. Python's wider \s is kept on
# purpose here: it only ever widens a refusal, and a Unicode blank before a denied word should count as a word start.
LITERAL_START = r'(?:^|(?<=[\s;&|()<>{}`/!=]))=*'  # after = too: option and variable values that programs run (r6 N22)
LITERAL_STOP = r'(?=$|[\s;&|()<>`}$])'
QUOTE_CHARACTERS = re.compile(r'''['"]''')
LITERAL_BLANKS = re.compile(r'[ \t]+')
# English words that appear in every prose heredoc; docs/operations.md gives the measured reason they are left out.
LITERAL_ESCAPE_NAMES = ESCAPE_NAMES - frozenset(('at', 'batch', 'screen'))


def literal_views(command):
    """The text as a shell might read it once its quoting is in doubt: continuations gone, then quotes removed, quotes as
    blanks (`alias e='cmd'`, `trap 'cmd'`), and quotes and backslashes removed (`to\\uch` reads as `touch`)."""
    text = command.replace('\\\n', '')
    plain = QUOTE_CHARACTERS.sub('', text)
    views = (plain, QUOTE_CHARACTERS.sub(' ', text), plain.replace('\\', ''))
    return tuple(dict.fromkeys(LITERAL_BLANKS.sub(' ', view) for view in views))


@functools.lru_cache(maxsize=256)
def _literal_pattern(head, stop):
    return re.compile(LITERAL_START + re.escape(head) + (LITERAL_STOP if stop else ''))


def literal_match(spec, views):
    """True when spec's literal text appears at a word start in any view. `prefix:*` and an exact spec need a word end after
    it; a glob needs its first literal at a word start and its later literals after it, in order."""
    spec = LITERAL_BLANKS.sub(' ', spec)
    if spec.endswith(':*'):
        parts, stop = [spec[:-2]], True
    elif '*' in spec:
        parts, stop = spec.split('*'), False
    else:
        parts, stop = [spec], True
    pattern = _literal_pattern(parts[0], stop)
    for view in views:
        found = pattern.search(view)
        if not found:
            continue
        at = found.end()
        for part in parts[1:]:
            at = view.find(part, at)
            if at < 0:
                break
            at += len(part)
        else:
            return True
    return False


GLOB_CHARS = re.compile(r'[*?\[]')


def _glob_matches(name, glob):
    """fnmatch, failing closed: a glob Python cannot compile (`[z-a]`) counts as a match, since the shell's reading is unknown."""
    try:
        return fnmatch.fnmatchcase(name, glob)
    except re.error:
        return True


def _glob_programs(lexed):
    """The program words that are globs (`/bin/tou?h`): the shell picks the program by matching file names."""
    found = []
    for commands in [lexed.commands] + list(lexed.groups):
        for item in commands:
            program = next((word for word in item.words if not ASSIGN_WORD.match(word.raw)), None)
            if program is not None and GLOB_CHARS.search(program.value):
                found.append(program.value.rsplit('/', 1)[-1])
    return found


def denied_as_literal(command, rules, lexed=None):
    """The first deny rule whose literal text appears at a word start in this uncertain command, or whose program a glob
    program word could name, or None."""
    views = literal_views(command)
    globs = _glob_programs(lexed) if lexed is not None else []
    for rule in rules:
        if rule.spec is None or rule.spec == '*' or literal_match(rule.spec, views):
            return rule
        program = LITERAL_BLANKS.split(rule.spec.strip(' \t'), 1)[0].split('*', 1)[0].rsplit(':', 1)[0]
        if program and any(_glob_matches(program, glob) for glob in globs):
            return rule
    return None


def literal_escape_names(command):
    views = literal_views(command)
    return [name for name in sorted(LITERAL_ESCAPE_NAMES) if literal_match(name, views)]


def _classify_physical_lines(command, reasons, depth):
    """The escape check for an uncertain command: the classifier over every fragment of every line, plus the literal names."""
    found = []
    for part in physical_parts(command):
        _classify_words([word.strip('\'"') for word in _blank_split(part)], found, [], depth)
    if BACKGROUND_AMP.search(command) and not LATER_WAIT.search(command):
        found.append('background & without a later wait')
    found.extend('%s detaches a process from tracking' % name for name in literal_escape_names(command))
    reasons.extend('a line of a command the hook cannot parse with certainty: ' + reason for reason in found)


ANSI_SIMPLE = {'a': '\a', 'b': '\b', 'e': '\x1b', 'E': '\x1b', 'f': '\f', 'n': '\n', 'r': '\r', 't': '\t', 'v': '\v',
               '\\': '\\', "'": "'", '"': '"', '?': '?'}


def _decode_ansi_c(text, i):
    """(value, index after the closing quote) for the $'...' string whose body starts at text[i]; ValueError when it is
    unterminated or its value cannot be modelled (NUL ends a shell string early). `\\c'` does not hide its closing quote:
    shells find the end of the string before they decode it."""
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
            digits = re.match(r'[0-7]{1,3}', text[i + 1:i + 4]).group()
            value = int(digits, 8) & 0xFF
            if value == 0:
                raise ValueError('NUL in an ANSI-C string')
            out.append(chr(value)); i += 1 + len(digits)
        elif nxt in 'xuU':
            digits = re.match(r'[0-9a-fA-F]{1,%d}' % {'x': 2, 'u': 4, 'U': 8}[nxt], text[i + 2:i + 10])
            if not digits:
                out.append('\\' + nxt); i += 2
                continue
            value = int(digits.group(), 16)
            if value == 0 or value > 0x10FFFF:
                raise ValueError('NUL in an ANSI-C string')
            out.append(chr(value)); i += 2 + len(digits.group())
        elif nxt == 'c' and i + 2 < n and text[i + 2] != "'":
            if ord(text[i + 2]) & 0x1f == 0:
                raise ValueError('NUL in an ANSI-C string')
            out.append(chr(ord(text[i + 2]) & 0x1f)); i += 3
        else:
            out.append('\\' + nxt); i += 2
    raise ValueError('unterminated $\'')


class Parsed:
    def __init__(self):
        self.segments, self.inner, self.substitution, self.newline = [], [], False, False
        self.uncertain, self.pipeline = False, False  # the lexer recorded a reason; a `|` or `&` joins commands
        self.heredoc, self.reasons, self.lexed = HEREDOC_NONE, [], None


def parse_command(command, depth=0):
    """The lexer's output as the decision reads it: simple-command strings, the ones inside substitutions and script bodies,
    and the flags that stop an allow."""
    parsed, lexed = Parsed(), lex(command)
    parsed.lexed, parsed.reasons, parsed.uncertain = lexed, list(lexed.reasons), bool(lexed.reasons)
    if lexed.reasons:
        parsed.heredoc = HEREDOC_UNCERTAIN if '<<' in command else HEREDOC_NONE
    else:
        parsed.heredoc = HEREDOC_CERTAIN if lexed.bodies else HEREDOC_NONE
    parsed.segments = [item.text for item in lexed.commands if item.text]
    parsed.inner = [item.text for group in lexed.groups for item in group if item.text]
    parsed.substitution, parsed.newline, parsed.pipeline = lexed.substitution, lexed.newline, lexed.pipeline
    if parsed.uncertain:
        return parsed
    for body in script_bodies(lexed):
        parsed.substitution = True  # never allow-eligible; its lines reach the deny check through inner
        if depth < 4:
            sub = parse_command(body, depth + 1)
            parsed.inner.extend(sub.segments + sub.inner)
            parsed.uncertain = parsed.uncertain or sub.uncertain
            parsed.reasons.extend(sub.reasons)
        else:
            parsed.uncertain = True
            parsed.reasons.append('nesting')
    return parsed


def normalize_segment(segment):
    while True:
        stripped = KEYWORD_PREFIX.sub('', segment, count=1)
        if stripped == segment:
            return segment.strip(' \t\n')
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
    if dynamic or value == raw or not value or re.search(r'[ \t\n]', value):
        return None
    return value + text[spans[0][1]:]


def _wrapper_step(base, values, raws, k):
    """The index of the word a wrapper named `base` would run, where k is the index just past the wrapper: None when `base`
    is no wrapper, and -(i + 1) when it is `env -S` at index i, whose next word is quoted code. Wrappers read: exec, command,
    builtin, time, nohup, nice, sudo with options, timeout with options and duration, env with options."""
    count = len(values)
    if base in ('exec', 'command', 'builtin', 'time', 'nohup'):
        while k < count and values[k].startswith('-'):
            k += 2 if values[k] == '-a' else 1
    elif base == 'nice':
        if k < count and values[k] == '-n':
            k += 2
        elif k < count and (re.fullmatch(r'-[0-9]+', values[k]) or values[k].startswith('--adjustment')):
            k += 1
    elif base == 'sudo':
        while k < count and values[k].startswith('-'):
            option = values[k]
            k += 2 if option in SUDO_ARG_OPTS else 1
            if option == '--':
                break
    elif base == 'timeout':
        while k < count and values[k].startswith('-'):
            k += 2 if values[k] in ('-s', '-k') else 1
        k += 1
    elif base == 'env':
        while k < count:
            word = values[k]
            if word.startswith(('-S', '--split-string')):
                return -(k + 1)
            if ASSIGNMENT.match(raws[k]):
                k += 1
            elif word in ('-u', '-C', '--unset', '--chdir'):
                k += 2
            elif word.startswith('-') and len(word) > 1:
                k += 1
            else:
                break
    else:
        return None
    return k


def peel_wrapper(text):
    """The command with its first wrapper removed (an env assignment or anything _wrapper_step reads), or None when it starts
    with no wrapper. `env -S` gives back its split string as the command."""
    try:
        spans = _spans(text)
        if not spans:
            return None
        raws = [text[start:end] for start, end in spans]
        values = [raw_words(raw)[0][1] for raw in raws]
        count = len(spans)
        if ASSIGNMENT.match(raws[0]):
            k = 1
        else:
            k = _wrapper_step(values[0].rsplit('/', 1)[-1], values, raws, 1)
            if k is None:
                return None
            if k < 0:
                at = -k - 1
                if values[at] not in ('-S', '--split-string') or at + 1 >= count:
                    return None
                rest = text[spans[at + 2][0]:] if at + 2 < count else ''
                return (values[at + 1] + ' ' + rest).strip(' \t\n')
        return text[spans[k][0]:] if k < count else None
    except (ValueError, IndexError):
        return None


BLANKS = re.compile(r'[ \t]+')
REDIRECT_ANYWHERE = re.compile(r'(?:(?<![^ \t\n])[0-9]+)?(?:&>>|&>|<<<|<<-?|<>|>>|>&|<&|>\||>|<)[ \t]*[^ \t\n<>&|;]*')
VARIABLE = re.compile(r'\$[A-Za-z_][A-Za-z0-9_]*|\$\{[A-Za-z_][A-Za-z0-9_]*\}')
EMPTY_HEAD = re.compile(r'^(?:\$""|=)+|^(?:"?(?:X|\$\([^()]*\)|`[^`]*`)"?[ \t]+)+')
BRACE_HEAD = re.compile(r'^\{[^{} \t\n]*,[^{} \t\n]*\}')
THROUGH_HINT = re.compile(r'[<>$=X{`]')


def _read_through(form):
    """The form the shell may really run when the words around the program are redirects, or a word holds an expansion that
    can be empty (`>f cmd`, `$x cmd`, `cmd$x`, `$(true) cmd`, which reads `X cmd` here, zsh's `=cmd`), a $"..." string, ${IFS}
    as a separator, or a brace list (`{cmd,arg}`). Only the deny and ask checks use it, so it can widen them and never an
    allow."""
    if not THROUGH_HINT.search(form):
        return form
    text = REDIRECT_ANYWHERE.sub(' ', form).replace('${IFS}', ' ').replace('$IFS', ' ')
    text = VARIABLE.sub('', text).strip(' \t\n')
    if BRACE_HEAD.match(text):
        return BRACE_HEAD.sub(lambda found: found.group()[1:-1].replace(',', ' '), text)
    return EMPTY_HEAD.sub('', text).replace('$"', '"', 1).strip(' \t\n') if text.startswith(('$', '=', 'X', '"', '`')) else text


def _peeled_forms(segment):
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


def _bare_forms(form):
    """The form with its quoting removed, and with the program's directory removed too."""
    try:
        words = raw_words(form)
    except ValueError:
        return []
    if not words:
        return []
    values = [word[1] for word in words]
    found = [' '.join(values)]
    if '/' in values[0] and not words[0][2]:
        found.append(' '.join([values[0].rsplit('/', 1)[-1]] + values[1:]))
    return found


@functools.lru_cache(maxsize=4096)
def match_candidates(segment):
    """The segment as typed plus every form with env assignments, wrappers (exec, command, time, nohup, nice, sudo,
    timeout, env) and the quoting of the program word removed, those with _read_through's words gone, and each with all
    its quoting or the program's directory removed, as a tuple. A deny or ask rule matching any form applies. Cached because
    one command asks for the same segment up to four times."""
    forms = _peeled_forms(segment)
    for form in list(forms):
        through = _read_through(form)
        if through != form and through:
            forms.extend(extra for extra in _peeled_forms(through) if extra not in forms)
    for form in list(forms):
        forms.extend(extra for extra in _bare_forms(form) if extra not in forms)
    # a run of blanks is one separator to the shell. Only these forms get it, not allow, so it can only widen a deny or ask.
    forms.extend(collapsed for collapsed in dict.fromkeys(BLANKS.sub(' ', form) for form in forms) if collapsed not in forms)
    return tuple(forms)


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
    call = host_table.parse_ssh(args)
    if call is None:
        return
    if 'f' in call.flags:
        reasons.append('ssh -f backgrounds the connection')
    for value in call.o_values:
        key, setting = (re.split(r'[ \t]*=[ \t]*|[ \t]+', value.strip(' \t'), maxsplit=1) + [''])[:2]  # ssh takes =, blanks or tabs
        key, setting = key.lower(), setting.strip(' \t')
        if key == 'forkafterauthentication' and setting.lower() != 'no':
            reasons.append('ssh -o ForkAfterAuthentication backgrounds the connection')
        elif key == 'controlpersist' and setting.lower() != 'no':
            reasons.append('ssh -o ControlPersist leaves a master connection running')
        elif key in ('remotecommand', 'localcommand') and setting:
            _classify_text(setting, reasons, notes, depth + 1, 'ssh -o %s: ' % key)
    if call.remote:
        # a model-supplied `ah-run ... --` prefix in the remote command is replaced by the hook, so look past it
        _classify_text(strip_ah_run_prefix(' '.join(call.remote)), reasons, notes, depth + 1, 'ssh remote: ')


def _classify_text(command, reasons, notes, depth, prefix=''):
    sub_reasons = []
    if depth > 4:
        sub_reasons.append('nested shells are too deep to analyze')
    else:
        _classify_command(command, sub_reasons, notes, depth)
    reasons.extend(prefix + reason for reason in sub_reasons)


def _classify_list(commands, reasons, notes, depth, uncertain):
    """The classifier over one command list. On uncertain text it also reads through what may be empty or a redirect."""
    entries = [[word.value for word in item.words] for item in commands]
    last_wait = max((position for position, words in enumerate(entries) if _command_word(words) == 'wait'), default=-1)
    for position, (item, words) in enumerate(zip(commands, entries)):
        _classify_words(words, reasons, notes, depth)
        if uncertain:
            through = _blank_split(_read_through(' '.join(words)))
            if through[:1] != words[:1]:  # only when another program runs: the words after it are quote-removed text
                _classify_words(through, reasons, notes, depth)
        if item.operator == '&' and (words or item.closer) and position >= last_wait:
            reasons.append('background & without a later wait')


def _classify_command(command, reasons, notes, depth):
    lexed = lex(command)
    uncertain = bool(lexed.reasons)
    if 'unterminated' in lexed.reasons and '<<' not in command:
        reasons.append('parse failure: an unterminated quote or group')
        return
    if uncertain:
        _classify_physical_lines(command, reasons, depth)
    _classify_list(lexed.commands, reasons, notes, depth, uncertain)
    for group in lexed.groups:
        found = []
        _classify_list(group, found, notes, depth + 1, uncertain)
        reasons.extend('substitution: ' + reason for reason in found)
    if not uncertain:
        for body in script_bodies(lexed):
            _classify_text(body, reasons, notes, depth + 1, 'heredoc script: ')


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
        if words[:1] == ['-I']:  # the isolated form every installed hook line uses
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
SSH_WORD = re.compile(r'^(?:[^ \t\n]*/)?ssh(?=[ \t\n])')
REDIRECT = re.compile(r'^(?:\d*|&)(?:<<<|<<-?|<>|>>|>&|<&|>\||>|<)(.*)$', re.S)
REMOTE_PATH = re.compile(r'^[A-Za-z0-9_./~-]+$')
QUOTED_TEXT = re.compile(r'\\.|\'[^\']*\'|"(?:\\.|[^"\\])*"', re.S)
ATTACHED_REDIRECT = re.compile(r'[<>]')
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


def _quoted_ssh_target(segment):
    """The target of an ssh whose program word is quoted or escaped (`"ssh" h ls`, `s\\sh h ls`). Such a line cannot be
    rewritten in place, so it runs unwrapped and is recorded."""
    for form in match_candidates(segment):
        if not SSH_WORD.match(form):
            continue
        try:
            call = host_table.parse_ssh([word[1] for word in raw_words(form)[1:]])
        except ValueError:
            continue
        if call is not None and (call.remote or HEREDOC_MARKER.search(form)):
            return call.target
    return None


def rewrite_ssh(command, parsed, payload, env, home, context):
    """(command, remote): each `ssh HOST CMD` simple command whose resolved host has `ah_run: "<path>"` in the
    table becomes `ssh HOST python3 <path> run ... --token via-hook-ssh [--readonly] --cmd-b64 B64` (stdin stays
    inherited). `remote` is (command_class, host_digest) for the local ledger row when the host is external
    (`remote-unattributed`) or has no remote ah-run (`remote-unwrapped`). Raises ValueError to deny.

    What runs must be what was checked. Heredoc bodies are never touched: the replacement works on the typed text with
    each body swapped for a placeholder (which also keeps a body line from matching) and put back byte for byte. Text
    outside bodies has its continuations joined only because the segments were cut from the joined text. A command with no
    wrapped line comes back exactly as typed. An uncertain command is wrapped only when the whole command is the one ssh
    line and every word is literal, since its text cannot be told apart from a body or a string; any other uncertain ssh
    line is left unwrapped and recorded. The result is re-parsed: a replacement that changed any other command is undone."""
    segments = [s for s in dict.fromkeys(parsed.segments)]
    candidates = [(s, _ssh_form(s)) for s in segments]
    hidden = next((target for s, form in candidates if not form for target in [_quoted_ssh_target(s)] if target), None)
    remote = ('remote-unattributed', digest(hidden)) if hidden else None
    if not any(form for _s, form in candidates):
        return command, remote
    typed_command, lexed = command, parsed.lexed
    openers, bodies = lexed.openers, [command[start:end] for start, end in lexed.spans]
    command = _masked_text(command, lexed, join=not parsed.uncertain)
    rewritten = []

    def with_openers(text):
        return HEREDOC_MARKER.sub(lambda m: openers[int(m.group(1))] if int(m.group(1)) < len(openers) else m.group(), text)
    policy = host_table.policy_path(home, env)
    table = host_table.load(policy)
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
        if call is not None and not call.remote and HEREDOC_MARKER.search(form):
            remote = remote or ('remote-unwrapped', digest(call.target))  # its login shell reads the body
        if call is None or not call.remote:
            continue  # `ssh HOST` with no command, `ssh -N`, `-W`: nothing to wrap
        raws = [w[0] for w in args[1:]]
        if '}' in raws or any(ATTACHED_REDIRECT.search(QUOTED_TEXT.sub('', raw)) for raw in raws):
            # `cat>f` read as a word would carry a local redirect to the remote shell, or make a syntax error run; a bare }
            # closes a zsh group or is a zsh parse error, and in the base64 it would be neither
            remote = remote or ('remote-unwrapped', digest(call.target))
            continue
        count = len(call.opts)
        before_remote = count + 1 + len(call.post_opts)  # ssh reads options after the host too, up to the first other word
        target_dynamic = args[1 + count][2]
        if call.unsafe:
            flags = ''.join(sorted(call.unsafe))
            cls = host_table.HostClass('external', None, None, None, reason='ssh-option-' + flags)
            _warn_row('ssh -%s not forwarded to ssh -G; host classed external, line left unwrapped' % '/-'.join(sorted(call.unsafe)), call.target)
        elif target_dynamic:
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
        remote_raw = raws[before_remote:]
        remote_words = args[1 + before_remote:]
        if any(w[2] for w in remote_words):
            # the local shell expands this text before ssh sees it: build the base64 from the same words at run time
            b64 = '"$(set -- %s; printf %%s "$*" | base64 | tr -d \'\\n\')"' % ' '.join(remote_raw)
        else:
            text = strip_ah_run_prefix(' '.join(w[1] for w in remote_words))  # within SCAN_CAP: decide refused anything longer
            b64 = base64.b64encode(text.encode('utf-8')).decode('ascii')
        tail = ['python3', '-I', path] if path.endswith('.py') else [path]
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
        new_form = with_openers(' '.join([args[0][0], *raws[:before_remote], *tail, *redirects]))
        typed = with_openers(segment)
        lone_line = len(parsed.segments) == 1 and typed == command.strip(' \t\n') and not any(w[2] for w in remote_words)
        if command.count(typed) != parsed.segments.count(segment) or (parsed.uncertain and not lone_line):
            remote = remote or ('remote-unwrapped', digest(who))
            context.append('ah-run: an ssh line could not be rewritten safely (its text repeats inside another command, or the quoting around it is uncertain); it runs unwrapped')
            continue
        command = command.replace(typed, prefix + new_form)
        rewritten.append((segment, who))
    if not rewritten:
        return typed_command, remote
    if bodies:  # a command holding a NUL never gets here with bodies: heredoc_scan calls it uncertain and returns no spans
        command = re.sub('\0(\\d+)\0', lambda found: bodies[int(found.group(1))], command)
    if not _only_these_changed(parsed.segments, parse_command(command).segments, {segment for segment, _who in rewritten}):
        context.append('ah-run: an ssh line could not be rewritten safely (the replacement changed another command); it runs unwrapped')
        return typed_command, remote or ('remote-unwrapped', digest(rewritten[0][1]))
    return command, remote


def _only_these_changed(before, after, replaced):
    """True when the re-parse holds the same commands in the same order, apart from the replaced ones."""
    return len(before) == len(after) and all(old in replaced or old == new for old, new in zip(before, after))


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
    for text in _strings(payload.get('prompt')):  # the spawn prompt only; never cwd, paths or other model-steerable fields
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
    parts = ['python3', '-I', str(Path(__file__).resolve()), 'run', '--task', task, '--agent', agent]
    if ticket and SAFE_KEY.fullmatch(ticket):
        parts += ['--ticket', ticket]
    parts += ['--session', session]
    if token:
        parts += ['--token', token]
    if task_source in ('input', 'record'):
        parts += ['--task-source', task_source]
    if remote:
        parts += ['--command-class', remote[0], '--remote-host-sha256', remote[1]]
        if agent_is_readonly(payload):  # no remote line carries it, so the local row records it
            parts.append('--readonly')
            context.append('ah-run: a read-only agent ran an ssh line that could not be wrapped; the local row records readonly')
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


def command_bytes(command):
    """The size the cap measures: bytes, not characters, so a multibyte command cannot slip under it."""
    return len(command.encode('utf-8', 'surrogatepass'))


def _over_scan_cap(command, size, mode, payload, env):
    """A command over SCAN_CAP is not scanned at all. A mode that cannot ask refuses it, since nothing else would stop it;
    any other mode asks, so a person sees it. The hook never allows it and never lets it pass silently."""
    text = ('ah-run: the command is %d bytes and the hook does not scan text over %d bytes (64 KiB). Write it to a script file '
            'and run the file, or scp or rsync the payload to the host and run a short command (for example '
            '`ssh HOST bash /path/script.sh`).' % (size, SCAN_CAP))
    try:
        check_payload_cap(command)  # over 1 MiB keeps its own refusal in every mode: ah-run cannot carry it
    except ValueError as error:
        return _out('deny', 'ah-run: %s' % error)
    if mode in ('bypassPermissions', 'dontAsk'):
        return _out('deny', text)
    context = ['ah-run: this command was not scanned: no deny rule, escape check or ssh rewrite was applied']
    try:
        wrapped = build_rewrite(strip_ah_run_prefix(command), payload, env, [], context)
    except ValueError as error:
        return _out('deny', 'ah-run: %s' % error)
    return _out('ask', text, {**(payload.get('tool_input') or {}), 'command': wrapped}, '\n'.join(context))


def decide(payload, home=None, env=None, ancestors=None):
    """The hook decision for one PreToolUse payload (a dict); returns the JSON object to print."""
    home = home or str(Path.home())
    env = os.environ if env is None else env
    if payload.get('tool_name') != 'Bash':
        return {}
    original = (payload.get('tool_input') or {}).get('command')
    mode = payload.get('permission_mode') or 'default'
    if not isinstance(original, str) or not original.strip(' \t\n') or mode == 'plan':
        return {}
    size = command_bytes(original)
    if size > SCAN_CAP:  # first: no parse, no rule, no analysis above the cap
        return _over_scan_cap(original, size, mode, payload, env)
    command = strip_ah_run_prefix(original)
    cwd = payload.get('cwd') or os.getcwd()
    cli = settings_from_ancestors(ancestors() if ancestors else ancestor_commands())
    rules = load_rules(cwd, home, cli)
    parsed = parse_command(command)
    context = []

    checked = parsed.segments + parsed.inner
    if parsed.uncertain and rules['deny']:
        checked = checked + physical_parts(command)  # what the parse may have swallowed as string or heredoc text
    for part in checked:
        forms = match_candidates(part)
        for rule in rules['deny']:
            if any(rule.matches(form) for form in forms):
                hint = ' %s' % HEREDOC_HINT if parsed.heredoc == HEREDOC_UNCERTAIN else ''
                return _out('deny', 'denied by permission rule %s%s' % (rule.label(), hint))
    if parsed.uncertain:
        rule = denied_as_literal(command, rules['deny'], parsed.lexed)
        if rule:
            hint = ' %s' % HEREDOC_HINT if parsed.heredoc == HEREDOC_UNCERTAIN else ''
            return _out('deny', 'denied by permission rule %s: the hook cannot parse this command with certainty (%s) and the '
                                "rule's text appears in it at a word start%s" % (rule.label(), ', '.join(parsed.reasons), hint))

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

    if parsed.uncertain:
        checked_text = ('(%s; the deny rules saw its guessed commands, every line, and their own text at any word start; a '
                        'command built at run time can still pass them; this command is never auto-allowed)' % ', '.join(parsed.reasons))
        context.append(('heredoc: uncertain ' if parsed.heredoc == HEREDOC_UNCERTAIN else 'quoting: uncertain ') + checked_text)
    reasons, notes = analyze_escapes(command)
    if reasons:
        text = 'command escapes tracking: %s. Run it through `ah-run` or keep it in the foreground (use `wait`).' % '; '.join(reasons)
        if parsed.heredoc == HEREDOC_UNCERTAIN:
            text += ' ' + HEREDOC_HINT
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
                and not parsed.uncertain
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
    elif parsed.heredoc == HEREDOC_UNCERTAIN:
        why = 'heredoc: uncertain (a `<<` the hook cannot read the way the shell does)'
    elif parsed.uncertain:
        why = 'quoting the hook cannot tokenize with certainty'
    elif parsed.substitution or parsed.newline:
        why = 'contains substitution, eval or a newline'
    else:
        why = 'no allow rule matches every command'
    return _out('ask', why, updated, extra)


class _HookDeadline(BaseException):
    """The hook's own time limit passed. BaseException, so no broad handler on the way out turns it into a result."""


def _deadline_verdict(payload):
    text = ('ah-run hook: the analysis passed its %d second limit, so nothing about this command was decided. Write it to a '
            'script file and run the file.' % HOOK_DEADLINE)
    mode = payload.get('permission_mode') if isinstance(payload, dict) else None
    return _out('deny' if mode in ('bypassPermissions', 'dontAsk') else 'ask', text)


class _Deadline:
    """The hook's own timer. The handler raises only while armed, so a signal that lands after disarm() does nothing."""

    def __init__(self):
        self.armed, self.previous = False, None

    def expire(self, _number, _frame):
        if self.armed:
            self.armed = False
            raise _HookDeadline()

    def arm(self, seconds):
        """True when the timer is armed. The signal exists only on the main thread; off it the hook has no limit of its own."""
        try:
            self.previous = signal.signal(signal.SIGALRM, self.expire)
            self.armed = True
            signal.setitimer(signal.ITIMER_REAL, seconds)
            return True
        except (ValueError, OSError):
            self.armed = False
            return False

    def disarm(self):
        if not self.armed and self.previous is None:
            return
        self.armed = False
        try:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, self.previous if self.previous is not None else signal.SIG_DFL)
        except (ValueError, OSError, TypeError):
            pass
        self.previous = None


def hook_main(stdin=None, stdout=None):
    """Entry point for `ah_run.py hook`: always exit 0; any internal error is an `ask` with the reason, and passing the time
    limit (HOOK_DEADLINE) refuses in a mode that cannot ask and asks in any other."""
    stdin, stdout = stdin or sys.stdin, stdout or sys.stdout
    payload, deadline = None, _Deadline()
    try:
        try:
            raw = stdin.read((8 << 20) + 1)
            if len(raw) > (8 << 20):
                result = _out('ask', 'ah-run hook: input over 8 MiB')
            else:
                payload = json.loads(raw)
                if not isinstance(payload, dict):
                    raise ValueError('hook input is not an object')
                deadline.arm(HOOK_DEADLINE)
                result = decide(payload)
                deadline.disarm()
        except Exception as error:  # noqa: BLE001 - never a silent allow, never a crash
            deadline.disarm()
            result = _out('ask', 'ah-run hook internal error: %s: %s' % (type(error).__name__, str(error)[:120]))
    except _HookDeadline:  # outside the handler above, so the timer cannot escape it either
        result = _deadline_verdict(payload)
    finally:
        deadline.disarm()
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
