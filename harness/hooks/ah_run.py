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
        return pid_exists(pid)
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
        return process_start_token(pid)
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
    attribution = 'verified' if args.token and args.token != 'via-hook-ssh' else ('hook-ssh' if args.token == 'via-hook-ssh' else 'unverified')
    if args.readonly and attribution == 'unverified':
        print('ah-run: a read-only agent run needs a hook token; refused', file=sys.stderr)
        return 126
    row = {'schema': SCHEMA, 'run_id': run_id, 'task': task, 'agent': agent, 'ticket': ticket, 'session': session,
           'attribution': attribution, 'readonly': bool(args.readonly), 'host': host_identity(),
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
    args = parser.parse_args(argv)
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
