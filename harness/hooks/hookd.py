#!/usr/bin/env python3
"""hookd: resident hook server (GoodQA goodqa#14859).

Every Claude hook used to start a cold Python process. A Bash call ran 7 PreToolUse hooks plus 2 analyser
children, at about 0.5-1.2 s of CPU per call. hookd imports the hook modules once. For each call it forks a
child of that warm parent, and the child runs the script's own `if __name__ == '__main__':` block unchanged,
with the caller's argv, environment, cwd, umask, stdin and pid identity. So the decisions are made by the
same code as before. The thin client (`hookc`, cmd/hookc) forwards the hook payload and prints the verdict.
If anything is off it runs the cold Python hook itself, so a missing, slow, stale or broken server can never
turn into an allow.

Design rules:
- **The parent only imports and forks.** It never runs hook code, so module state cannot leak between calls.
  It never starts a thread, so fork is safe. WAL appends go to a separate writer process (hookd_writer).
- **Staleness.** Every module file and every file opened during import is stat-checked before each fork.
  On a change the call is answered `fallback: stale` and the parent re-execs once its children are done.
  Environment keys read during import (HOME, for example) are compared with the caller's values; a
  difference sends that call to the cold path. Files read at run time are read by the child, fresh.
- **Analysers.** The launchers `command_guard_hook.py` and `kill_guard.py hook` run their analyser with
  `subprocess.run([sys.executable, '-I', <hooks>/<script>, <verb>], input=...)`. Exactly those pairs are
  served by a forked grandchild. The launcher's own timeout, garbage and crash checks run unchanged.
- **Peer check.** The socket lives in a 0700 directory with mode 0600, and the peer uid must equal ours.
- **Logs.** Only the event, the hook name, the duration and the outcome are logged. Never env, stdin or
  output.

Usage:
  hookd.py serve            run the server in the foreground (launchd/systemd run this)
  hookd.py status           JSON: socket, pid, uptime, served/fallback counts
  hookd.py install [--apply] [--uninstall]   service unit (launchd com.ericmacdougall.hookd / systemd hookd)
"""

import ast
import errno
import fcntl
import io
import json
import os
import select
import signal
import socket
import stat
import struct
import sys
import time

HOOKS_DIR = os.path.dirname(os.path.abspath(__file__))
PROTO = 1
MAX_STDIN = 8 * 1024 * 1024 + 1        # the guards read at most 8 MiB + 1 to detect oversize
MAX_HEADER = 1024 * 1024               # env + argv
MAX_REPLY = 4 * 1024 * 1024
DEFAULT_MAX_CHILDREN = 16
DEFAULT_BUDGET = 20.0                  # seconds a served call may run before the parent kills it
LOG_MAX = 4 * 1024 * 1024

# Scripts the server may run, with the verbs it serves. Anything else is a cold-path fallback.
SERVED = {
    'command_guard_hook.py': None,       # None: any argv (the launcher ignores its verb)
    'kill_guard.py': ('hook',),
    'wal.py': ('pretool', 'prompt', 'subagent', 'subagent_stop', 'session'),
    'tier_gate.py': ('hook', 'start', 'stop'),
    'commit_policy.py': ('hook',),
    'bg_lint.py': (),                    # (): only with no arguments
    'heavy_job_guard.py': (),
    'agent_gate.py': (),
    'spec_flow.py': ('hook',),
    'provenance_hooks.py': ('prompt', 'ask-gate', 'stop-lint'),
    'dropped_gate.py': ((), ('subagent-stop',)),
    'ledger_reminder.py': (),
}
# Analyser subprocesses a served launcher may start; run in a forked grandchild instead of a cold python.
ANALYSERS = {('command_guard.py', 'hook'), ('kill_guard.py', 'analyze')}


def home():
    return os.path.expanduser('~')


def run_dir():
    return os.environ.get('HOOKD_RUN_DIR') or os.path.join(home(), '.agent-harness', 'run', 'hookd')


def socket_path():
    return os.path.join(run_dir(), 'hookd.sock')


def log_path():
    return os.environ.get('HOOKD_LOG') or os.path.join(home(), '.agent-harness', 'logs', 'hookd.log')


# --------------------------------------------------------------------------- framing

def send_frame(sock, payload):
    sock.sendall(struct.pack('>I', len(payload)) + payload)


def recv_exact(sock, n):
    chunks, got = [], 0
    while got < n:
        chunk = sock.recv(min(n - got, 1 << 20))
        if not chunk:
            raise EOFError('peer closed')
        chunks.append(chunk)
        got += len(chunk)
    return b''.join(chunks)


def recv_frame(sock, limit):
    (size,) = struct.unpack('>I', recv_exact(sock, 4))
    if size > limit:
        raise ValueError('frame too large')
    return recv_exact(sock, size)


def served(script, args):
    """True when hookd may run `script args` (script is a basename inside HOOKS_DIR)."""
    if script not in SERVED:
        return False
    verbs = SERVED[script]
    if verbs is None:
        return True
    if script == 'dropped_gate.py':
        return tuple(args) in verbs
    if verbs == ():
        return not args
    return len(args) == 1 and args[0] in verbs


# --------------------------------------------------------------------------- peer credentials

def peer_cred(conn):
    """(pid, uid) of the connected peer, or (None, None) when the platform cannot say."""
    if hasattr(socket, 'SO_PEERCRED'):
        pid, uid, _gid = struct.unpack('3i', conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED,
                                                             struct.calcsize('3i')))
        return pid, uid
    if sys.platform == 'darwin':
        sol_local, local_peercred, local_peerpid = 0, 0x001, 0x002
        raw = conn.getsockopt(sol_local, local_peercred, 4 + 4 + 2 + 2 + 16 * 4)
        _version, uid = struct.unpack_from('Ii', raw, 0)
        pid = struct.unpack('i', conn.getsockopt(sol_local, local_peerpid, 4))[0]
        return pid, uid
    return None, None


# --------------------------------------------------------------------------- preload

class _RecordingEnviron(os._Environ):
    """os.environ that records every key read while the hook modules import."""

    def __init__(self, base, sink):
        super().__init__(base._data, base.encodekey, base.decodekey, base.encodevalue, base.decodevalue)
        self._sink = sink

    def __getitem__(self, key):
        try:
            value = super().__getitem__(key)
        except KeyError:
            self._sink.setdefault(key, None)
            raise
        self._sink.setdefault(key, value)
        return value

    def __iter__(self):
        self._sink.setdefault('*', '*')
        return super().__iter__()


class Preloaded:
    def __init__(self):
        self.modules = {}       # script basename -> module
        self.main_code = {}     # script basename -> code object of its __main__ block
        self.watch = {}         # path -> stat signature
        self.env_read = {}      # env key -> value seen at import (None = absent; '*' = whole env iterated)
        self.errors = {}


def _main_block(path):
    """Code for the trailing `if __name__ == '__main__':` statement of `path`, run in the module's globals."""
    with open(path, 'rb') as handle:
        source = handle.read()
    tree = ast.parse(source, filename=path)
    for node in reversed(tree.body):
        if (isinstance(node, ast.If) and isinstance(node.test, ast.Compare)
                and isinstance(node.test.left, ast.Name) and node.test.left.id == '__name__'
                and len(node.test.comparators) == 1
                and isinstance(node.test.comparators[0], ast.Constant)
                and node.test.comparators[0].value == '__main__'):
            module = ast.Module(body=node.body, type_ignores=[])
            return compile(module, path, 'exec')
    raise ValueError('%s has no __main__ block' % os.path.basename(path))


def _lazy_imports(paths):
    """Top-level module names imported anywhere in `paths`, followed through harness modules, limited to
    modules next to the hooks or in the standard library (never site-packages: the cold path may lack them)."""
    import importlib.util
    stdlib = os.path.dirname(os.__file__)
    seen, found, queue = set(), set(), list(paths)
    while queue:
        path = queue.pop()
        if path in seen:
            continue
        seen.add(path)
        try:
            with open(path, 'rb') as handle:
                tree = ast.parse(handle.read(), filename=path)
        except (OSError, SyntaxError, ValueError):
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [alias.name.split('.')[0] for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                names = [node.module.split('.')[0]]
            else:
                continue
            for name in names:
                local = os.path.join(HOOKS_DIR, name + '.py')
                if os.path.isfile(local):
                    found.add(name)
                    queue.append(local)
                    continue
                if name in sys.builtin_module_names:
                    continue
                try:
                    spec = importlib.util.find_spec(name)
                except (ImportError, ValueError):
                    continue
                origin = getattr(spec, 'origin', None) or ''
                if origin.startswith(stdlib) and 'site-packages' not in origin:
                    found.add(name)
    return found


def signature(path):
    try:
        st = os.stat(path)
    except OSError:
        return None
    return (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns)


def preload():
    """Import every served module and analyser once. Records watched files and import-time env reads."""
    import importlib.util
    pre = Preloaded()
    opened = set()

    def audit(event, args):
        if event == 'open' and args and isinstance(args[0], (str, bytes)):
            path = os.fsdecode(args[0])
            if not path.endswith(('.pyc',)) and os.path.isabs(path):
                opened.add(path)

    sys.addaudithook(audit)   # audit hooks cannot be removed; it only records while `collecting` is set
    if HOOKS_DIR not in sys.path:
        sys.path.insert(0, HOOKS_DIR)
    real_environ = os.environ
    os.environ = _RecordingEnviron(real_environ, pre.env_read)
    try:
        names = sorted(set(SERVED) | {s for s, _ in ANALYSERS})
        for script in names:
            path = os.path.join(HOOKS_DIR, script)
            name = script[:-3]
            try:
                module = sys.modules.get(name)
                if module is None or getattr(module, '__file__', None) != path:
                    spec = importlib.util.spec_from_file_location(name, path)
                    module = importlib.util.module_from_spec(spec)
                    sys.modules[name] = module
                    spec.loader.exec_module(module)
                pre.modules[script] = module
                pre.main_code[script] = _main_block(path)
            except BaseException as error:  # noqa: BLE001 - an unloadable hook is simply not served
                sys.modules.pop(name, None)
                pre.errors[script] = type(error).__name__
        # Modules the hooks import lazily (inside functions) would otherwise be imported again by every
        # child. Import them here too: harness modules next to the hooks and standard-library modules.
        for name in sorted(_lazy_imports([os.path.join(HOOKS_DIR, s) for s in pre.modules])):
            if name in sys.modules:
                continue
            try:
                importlib.import_module(name)
            except BaseException:  # noqa: BLE001 - the child imports it itself, as the cold path does
                sys.modules.pop(name, None)
    finally:
        os.environ = real_environ
    stdlib = os.path.dirname(os.__file__)
    for module in list(sys.modules.values()):
        path = getattr(module, '__file__', None)
        if path and not path.startswith(stdlib):
            opened.add(os.path.abspath(path))
    opened.add(os.path.abspath(__file__))
    for path in opened:
        if path.startswith(stdlib) or path.startswith(('/dev/', '/proc/', '/sys/')):
            continue
        pre.watch[path] = signature(path)
    return pre


def stale_paths(pre):
    return [p for p, sig in pre.watch.items() if signature(p) != sig]


def env_mismatch(pre, env):
    for key, value in pre.env_read.items():
        if key == '*':
            return '*'
        if env.get(key) != value:
            return key
    return None


# --------------------------------------------------------------------------- child execution

def _std_streams():
    """Recreate sys.stdin/stdout/stderr over fds 0/1/2 the way a fresh interpreter does (UTF-8, no tty)."""
    errors_in = 'surrogateescape'
    sys.stdin = io.TextIOWrapper(io.BufferedReader(io.FileIO(0, 'rb', closefd=False)), encoding='utf-8',
                                 errors=errors_in)
    sys.stdout = io.TextIOWrapper(io.BufferedWriter(io.FileIO(1, 'wb', closefd=False)), encoding='utf-8',
                                  errors='strict')
    sys.stderr = io.TextIOWrapper(io.BufferedWriter(io.FileIO(2, 'wb', closefd=False)), encoding='utf-8',
                                  errors='backslashreplace', line_buffering=True)
    sys.__stdin__, sys.__stdout__, sys.__stderr__ = sys.stdin, sys.stdout, sys.stderr


def _flush_std():
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.flush()
        except Exception:  # noqa: BLE001
            pass


def run_main(pre, script, argv):
    """Run `script`'s __main__ block in this (forked) process. Returns the exit status like the interpreter."""
    import atexit
    import traceback
    module = pre.modules[script]
    sys.argv = [os.path.join(HOOKS_DIR, script)] + list(argv)
    sys.modules['__main__'] = module
    status = 0
    try:
        exec(pre.main_code[script], module.__dict__)  # noqa: S102 - the script's own __main__ block
    except SystemExit as exc:
        code = exc.code
        if code is None:
            status = 0
        elif isinstance(code, int):
            status = code & 0xFF
        else:
            try:
                sys.stderr.write(str(code) + '\n')
            except Exception:  # noqa: BLE001
                pass
            status = 1
    except BaseException as exc:  # noqa: BLE001 - same as an uncaught exception in a fresh interpreter
        try:
            # Drop this frame so the traceback starts at `<module>`, as in a cold run.
            tb = exc.__traceback__.tb_next if exc.__traceback__ is not None else None
            traceback.print_exception(type(exc), exc, tb)
        except Exception:  # noqa: BLE001
            pass
        status = 1
    try:
        atexit._run_exitfuncs()
    except BaseException:  # noqa: BLE001
        pass
    _flush_std()
    return status


def _tmpfile(data=b''):
    """An anonymous file in the private run dir (unlinked at once), positioned at 0."""
    import tempfile
    handle = tempfile.TemporaryFile(dir=run_dir())
    if data:
        handle.write(data)
        handle.flush()
        handle.seek(0)
    return handle


# Regex warm-up. The guards compile many patterns at run time; a forked child starts from the parent's `re`
# cache, so each one would recompile them. A grandchild reports the patterns it compiled (one datagram each on
# an anonymous socketpair only our children inherit), and the parent compiles them with plain re.compile,
# which runs no hook code. Later forks then inherit a warm cache.
_RE_REPORT = None          # child side of the socketpair (set by serve before any fork)
RE_WARM_MAX = 2048         # distinct patterns the parent will compile
RE_PATTERN_MAX = 1500      # bytes; one datagram must hold a pattern (macOS unix dgram limit is 2048)


def _re_keys():
    import re
    return set(getattr(re, '_cache', {}))


def _report_patterns(before):
    import re
    if _RE_REPORT is None:
        return
    for key in set(getattr(re, '_cache', {})) - before:
        try:
            kind, pattern, flags = key
        except (TypeError, ValueError):
            continue
        if kind is str:
            doc = {'t': 's', 'p': pattern, 'f': int(flags)}
        elif kind is bytes:
            doc = {'t': 'b', 'p': pattern.decode('latin-1'), 'f': int(flags)}
        else:
            continue
        data = json.dumps(doc, separators=(',', ':')).encode()
        if len(data) > RE_PATTERN_MAX:
            continue
        try:
            _RE_REPORT.send(data)
        except OSError:
            return


def _warm_patterns(rx, warmed):
    """Parent: compile reported patterns (bounded). Pure stdlib work on strings; errors are ignored."""
    import re
    while True:
        try:
            data = rx.recv(4096)
        except (BlockingIOError, InterruptedError):
            return
        except OSError:
            return
        if len(warmed) >= RE_WARM_MAX:
            continue
        try:
            doc = json.loads(data)
            pattern = doc['p'] if doc['t'] == 's' else doc['p'].encode('latin-1')
            key = (doc['t'], doc['p'], int(doc['f']))
            if key not in warmed:
                re.compile(pattern, int(doc['f']))
                warmed.add(key)
        except Exception:  # noqa: BLE001 - a bad report only costs a warm cache entry
            continue


def _fork_run(pre, script, argv, stdin_bytes, timeout):
    """Fork, run script's main in the grandchild with captured stdio. Returns (status, out, err) or raises
    TimeoutError after killing the grandchild."""
    fin, fout, ferr = _tmpfile(stdin_bytes), _tmpfile(), _tmpfile()
    # Exit notification without polling: the grandchild holds the write end (non-inheritable, so programs it
    # execs do not), and the read end sees EOF when the grandchild is gone.
    done_r, done_w = os.pipe()
    pid = os.fork()
    if pid == 0:
        os.close(done_r)
        try:
            os.dup2(fin.fileno(), 0)
            os.dup2(fout.fileno(), 1)
            os.dup2(ferr.fileno(), 2)
            _std_streams()
            before = _re_keys()
            status = run_main(pre, script, argv)
            try:
                _report_patterns(before)
            except Exception:  # noqa: BLE001
                pass
        except BaseException:  # noqa: BLE001
            status = 1
        os._exit(status)
    os.close(done_w)
    deadline = None if timeout is None else time.monotonic() + timeout
    try:
        while True:
            left = None if deadline is None else deadline - time.monotonic()
            if left is not None and left <= 0:
                os.kill(pid, signal.SIGKILL)
                os.waitpid(pid, 0)
                raise TimeoutError
            try:
                ready, _, _ = select.select([done_r], [], [], left)
            except InterruptedError:
                continue
            if ready and not os.read(done_r, 1):
                break
    finally:
        os.close(done_r)
    _, raw = os.waitpid(pid, 0)
    status = os.waitstatus_to_exitcode(raw) if hasattr(os, 'waitstatus_to_exitcode') else (
        os.WEXITSTATUS(raw) if os.WIFEXITED(raw) else -os.WTERMSIG(raw))
    fout.seek(0)
    ferr.seek(0)
    return status, fout.read(), ferr.read()


def _patch_subprocess(pre):
    """Serve the launchers' analyser subprocess from a forked grandchild (exact call shape only)."""
    import subprocess
    real_run = subprocess.run

    def run(args, *a, **kw):
        if (not a and isinstance(args, (list, tuple)) and len(args) == 4 and args[0] == sys.executable
                and args[1] == '-I' and os.path.dirname(os.path.abspath(args[2])) == HOOKS_DIR
                and (os.path.basename(args[2]), args[3]) in ANALYSERS
                and os.path.basename(args[2]) in pre.modules
                and kw.get('stdout') == subprocess.PIPE and kw.get('stderr') == subprocess.PIPE
                and set(kw) <= {'input', 'stdout', 'stderr', 'timeout', 'check'}):
            timeout = kw.get('timeout')
            try:
                status, out, err = _fork_run(pre, os.path.basename(args[2]), [args[3]], kw.get('input') or b'',
                                             timeout)
            except TimeoutError:
                raise subprocess.TimeoutExpired(list(args), timeout)
            result = subprocess.CompletedProcess(list(args), status, out, err)
            if kw.get('check'):
                result.check_returncode()
            return result
        return real_run(args, *a, **kw)

    subprocess.run = run


def serve_one(pre, conn, counters_fd):
    """Runs in the forked request child. Never returns."""
    status_code = 0
    try:
        signal.signal(signal.SIGTERM, signal.SIG_DFL)
        signal.signal(signal.SIGCHLD, signal.SIG_DFL)
        conn.settimeout(5.0)
        pid, uid = peer_cred(conn)
        if uid is None or uid != os.getuid():
            send_frame(conn, json.dumps({'v': PROTO, 'status': 'refused', 'reason': 'peer'}).encode())
            os._exit(0)
        send_frame(conn, json.dumps({'v': PROTO, 'status': 'accepted'}).encode())
        header = json.loads(recv_frame(conn, MAX_HEADER))
        stdin_bytes = recv_frame(conn, MAX_STDIN)
        script, argv = header['script'], [str(a) for a in header.get('args', [])]
        env = {str(k): str(v) for k, v in header['env'].items()}
        reason = None
        if header.get('v') != PROTO:
            reason = 'protocol'
        elif os.path.dirname(script) != HOOKS_DIR or not served(os.path.basename(script), argv):
            reason = 'not-served'
        elif os.path.basename(script) not in pre.modules:
            reason = 'not-loaded'
        else:
            reason = env_mismatch(pre, env) and 'env'
        if reason is None:
            try:
                os.chdir(header['cwd'])
            except (OSError, KeyError, TypeError):
                reason = 'cwd'
        if reason:
            send_frame(conn, json.dumps({'v': PROTO, 'status': 'fallback', 'reason': reason}).encode())
            os._exit(0)
        os.environ.clear()
        os.environ.update(env)
        os.umask(int(header.get('umask', 0o022)) & 0o777)
        client_pid = pid if pid else int(header.get('pid') or os.getpid())
        client_ppid = int(header.get('ppid') or 1)
        os.getpid = lambda: client_pid
        os.getppid = lambda: client_ppid
        _patch_subprocess(pre)
        _patch_wal(pre)
        budget = float(header.get('budget') or DEFAULT_BUDGET)
        try:
            status, out, err = _fork_run(pre, os.path.basename(script), argv, stdin_bytes, budget)
        except TimeoutError:
            send_frame(conn, json.dumps({'v': PROTO, 'status': 'fallback', 'reason': 'timeout'}).encode())
            os._exit(0)
        if len(out) > MAX_REPLY or len(err) > MAX_REPLY:
            send_frame(conn, json.dumps({'v': PROTO, 'status': 'fallback', 'reason': 'reply-size'}).encode())
            os._exit(0)
        if status < 0:
            send_frame(conn, json.dumps({'v': PROTO, 'status': 'fallback', 'reason': 'signal'}).encode())
            os._exit(0)
        send_frame(conn, json.dumps({'v': PROTO, 'status': 'ok', 'exit': status}).encode())
        send_frame(conn, out)
        send_frame(conn, err)
    except BaseException:  # noqa: BLE001 - the client falls back on any broken reply
        status_code = 1
    os._exit(status_code)


# --------------------------------------------------------------------------- WAL write queue

def writer_path():
    return os.path.join(run_dir(), 'writer.sock')


def writer_main(wal_module):
    """Group-commit writer, a separate process forked from the parent (so the parent never has a thread).

    Each request is one WAL line for one path. Lines wait in FIFO order. A single flusher takes everything
    pending, writes each path's lines with one `wal.append_lines` (one lock, one write, one fsync) and only
    then acks each waiter. Batches form naturally: while one fsync runs, new lines queue behind it. A sync
    record is never acked before it is durable. If the writer dies, its waiters see EOF and append directly."""
    import threading
    from pathlib import Path
    signal.signal(signal.SIGTERM, signal.SIG_DFL)
    signal.signal(signal.SIGHUP, signal.SIG_IGN)
    signal.signal(signal.SIGINT, signal.SIG_IGN)
    path = writer_path()
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(path)
    os.chmod(path, 0o600)
    listener.listen(256)
    cond = threading.Condition()
    pending = []          # [path, line, result-holder]
    stats = {'lines': 0, 'batches': 0}
    busy = {'batch': 0, 'handlers': 0}   # guarded by cond: a batch being written, connections not yet acked

    def flusher():
        while True:
            with cond:
                while not pending:
                    cond.wait()
                batch = pending[:]
                del pending[:]
                busy['batch'] = 1
            by_path = {}
            for item in batch:
                by_path.setdefault(item[0], []).append(item)
            for wal_path, items in by_path.items():
                try:
                    wal_module.append_lines(Path(wal_path), [item[1] for item in items])
                    result = 'ok'
                except Exception as error:  # noqa: BLE001 - the waiter appends directly and gets the same error
                    result = type(error).__name__
                stats['batches'] += 1
                stats['lines'] += len(items)
                for item in items:
                    item[2].append(result)
            with cond:
                busy['batch'] = 0
                cond.notify_all()

    def handle(conn):
        with cond:
            busy['handlers'] += 1
        try:
            conn.settimeout(10.0)
            _pid, uid = peer_cred(conn)
            if uid != os.getuid():
                return
            wal_path = recv_frame(conn, 4096).decode()
            line = recv_frame(conn, 4 * 1024 * 1024)
            holder = []
            with cond:
                pending.append([wal_path, line, holder])
                cond.notify_all()
                while not holder:
                    cond.wait()
            send_frame(conn, holder[0].encode())
        except Exception:  # noqa: BLE001 - EOF tells the client to append directly
            pass
        finally:
            conn.close()
            with cond:
                busy['handlers'] -= 1
                cond.notify_all()

    threading.Thread(target=flusher, daemon=True).start()
    last = time.monotonic()
    parent = os.getppid()
    stopping = []
    signal.signal(signal.SIGTERM, lambda *_: stopping.append(1))
    listener.settimeout(0.2)
    while True:
        if stopping or os.getppid() != parent:
            # Shutdown, or hookd is gone: stop taking lines, flush what is queued, then exit.
            listener.close()
            give_up = time.monotonic() + 5.0
            with cond:
                # Every queued line is written and every accepted connection acked (bounded, a stuck peer
                # times out on its own 10 s socket limit and then appends directly).
                while (pending or busy['batch'] or busy['handlers']) and time.monotonic() < give_up:
                    cond.wait(0.05)
            log('writer-stop', lines=stats['lines'], batches=stats['batches'])
            os._exit(0)
        try:
            conn, _ = listener.accept()
        except (socket.timeout, InterruptedError):
            continue
        conn.settimeout(None)
        threading.Thread(target=handle, args=(conn,), daemon=True).start()
        if time.monotonic() - last > 60:
            log('writer', lines=stats['lines'], batches=stats['batches'])
            last = time.monotonic()


def _patch_wal(pre):
    """In a request child: route wal.append through the writer. The path check runs first, as before. Any
    writer failure appends directly, so the result, and any exception, are those of the cold path."""
    wal_module = pre.modules.get('wal.py')
    if wal_module is None or not hasattr(wal_module, 'append_lines'):
        return
    direct = wal_module.append_lines

    def append(path, record):
        wal_module.check_path(path)
        line = wal_module.encode(record)
        try:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                sock.settimeout(5.0)
                sock.connect(writer_path())
                send_frame(sock, os.fspath(path).encode())
                send_frame(sock, line)
                if recv_frame(sock, 256) == b'ok':
                    return
            finally:
                sock.close()
        except (OSError, EOFError, ValueError, struct.error):
            pass
        direct(path, [line])

    wal_module.append = append


# --------------------------------------------------------------------------- parent

def log(event, **fields):
    """One JSON line. Callers pass only names, counts and timings: never env, stdin or hook output."""
    path = log_path()
    try:
        os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
        if os.path.exists(path) and os.path.getsize(path) > LOG_MAX:
            os.replace(path, path + '.1')
        line = json.dumps(dict({'at': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()), 'event': event},
                               **fields), separators=(',', ':')) + '\n'
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        try:
            os.write(fd, line.encode())
        finally:
            os.close(fd)
    except OSError:
        pass


def secure_run_dir():
    path = run_dir()
    os.makedirs(path, mode=0o700, exist_ok=True)
    st = os.lstat(path)
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid():
        raise SystemExit('hookd: %s is not a directory owned by this user' % path)
    os.chmod(path, 0o700)
    return path


def serve(max_children=DEFAULT_MAX_CHILDREN):
    os.umask(0o077)
    rdir = secure_run_dir()
    lock_fd = os.open(os.path.join(rdir, 'hookd.lock'), os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        print('hookd: already running')
        return 0
    started = time.monotonic()
    pre = preload()
    # Move every preloaded object to the permanent generation: a child's GC pass then neither scans nor
    # writes to them, so they stay copy-on-write shared (measured: 4.6 -> 1.0 ms CPU per fork that collects).
    import gc
    gc.collect()
    gc.freeze()
    global _RE_REPORT
    re_rx, _RE_REPORT = socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
    re_rx.setblocking(False)
    _RE_REPORT.setblocking(False)
    warmed = set()
    path = socket_path()
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(path)
    os.chmod(path, 0o600)
    listener.listen(128)
    listener.setblocking(False)
    state = {'stop': False, 'reexec': False}
    signal.signal(signal.SIGTERM, lambda *_: state.update(stop=True))
    signal.signal(signal.SIGINT, lambda *_: state.update(stop=True))
    signal.signal(signal.SIGHUP, lambda *_: state.update(reexec=True))
    children = {}   # pid -> deadline (monotonic)
    counts = {'served': 0, 'stale': 0, 'writer_restarts': 0}

    def start_writer():
        wal_module = pre.modules.get('wal.py')
        if wal_module is None or not hasattr(wal_module, 'append_lines'):
            return None
        pid = os.fork()
        if pid == 0:
            listener.close()
            os.close(lock_fd)   # flock follows the open file: the writer must not keep the instance lock
            re_rx.close()
            _RE_REPORT.close()
            try:
                writer_main(wal_module)
            finally:
                os._exit(1)
        return pid

    writer = {'pid': start_writer()}

    def stop_writer():
        if writer['pid']:
            try:
                os.kill(writer['pid'], signal.SIGTERM)
                os.waitpid(writer['pid'], 0)
            except (OSError, ChildProcessError):
                pass
            writer['pid'] = None
    status_path = os.path.join(rdir, 'status.json')

    def write_status():
        doc = {'pid': os.getpid(), 'started_at': time.time() - (time.monotonic() - started),
               'socket': path, 'children': len(children), 'loaded': sorted(pre.modules),
               'load_errors': pre.errors, 'watch_files': len(pre.watch), 'warm_patterns': len(warmed),
               'env_keys_at_import': sorted(pre.env_read), **counts}
        import resource
        own, kids = resource.getrusage(resource.RUSAGE_SELF), resource.getrusage(resource.RUSAGE_CHILDREN)
        doc['cpu_s'] = round(own.ru_utime + own.ru_stime, 3)
        doc['children_cpu_s'] = round(kids.ru_utime + kids.ru_stime, 3)   # request children (+ their forks)
        doc['maxrss_kb'] = own.ru_maxrss // (1024 if sys.platform == 'darwin' else 1)
        tmp = status_path + '.tmp'
        with open(tmp, 'w') as handle:
            json.dump(doc, handle)
        os.replace(tmp, status_path)

    write_status()
    log('start', pid=os.getpid(), loaded=len(pre.modules), errors=sorted(pre.errors), ms=int(
        (time.monotonic() - started) * 1000))
    last_status = time.monotonic()
    while True:
        # reap request children and the writer; restart a writer that died
        while True:
            try:
                pid, _ = os.waitpid(-1, os.WNOHANG)
            except ChildProcessError:
                children.clear()
                break
            if not pid:
                break
            children.pop(pid, None)
            if pid == writer['pid']:
                writer['pid'] = None
                if not state['stop']:
                    counts['writer_restarts'] += 1
                    log('writer-died')
                    writer['pid'] = start_writer()
        now = time.monotonic()
        for pid, deadline in list(children.items()):
            if now > deadline:
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
        if state['stop'] and not children:
            break
        if state['reexec'] and not children:
            log('reexec', reason='stale', served=counts['served'])
            stop_writer()
            listener.close()
            os.close(lock_fd)
            os.execv(sys.executable, [sys.executable, os.path.abspath(__file__), 'serve'])
        if now - last_status > 5:
            write_status()
            last_status = now
        if state['stop'] or len(children) >= max_children:
            time.sleep(0.005)
            continue
        try:
            ready, _, _ = select.select([listener, re_rx], [], [], 0.25)
        except InterruptedError:
            continue
        if re_rx in ready:
            before = len(warmed)
            _warm_patterns(re_rx, warmed)
            if len(warmed) != before:
                gc.freeze()   # keep the new compiled patterns out of the children's GC scans
        if listener not in ready:
            continue
        try:
            conn, _ = listener.accept()
        except (BlockingIOError, InterruptedError):
            continue
        except OSError as error:
            if error.errno in (errno.EMFILE, errno.ENFILE):
                time.sleep(0.05)
            continue
        conn.setblocking(True)
        if state['reexec'] or stale_paths(pre):
            state['reexec'] = True
            counts['stale'] += 1
            try:
                conn.settimeout(1.0)
                # A fallback in place of the ack: the client never sends the request, so the parent reads nothing.
                send_frame(conn, json.dumps({'v': PROTO, 'status': 'fallback', 'reason': 'stale'}).encode())
            except OSError:
                pass
            conn.close()
            continue
        pid = os.fork()
        if pid == 0:
            listener.close()
            serve_one(pre, conn, None)
        conn.close()
        counts['served'] += 1
        children[pid] = time.monotonic() + 65.0   # hard cap above the longest hook timeout (60 s)
    stop_writer()
    try:
        os.unlink(path)
    except OSError:
        pass
    log('stop', served=counts['served'])
    return 0


def status_main():
    path = os.path.join(run_dir(), 'status.json')
    try:
        with open(path) as handle:
            doc = json.load(handle)
    except (OSError, ValueError):
        print(json.dumps({'running': False}))
        return 1
    alive = True
    try:
        os.kill(int(doc['pid']), 0)
    except (OSError, ValueError, KeyError):
        alive = False
    doc['running'] = alive and os.path.exists(socket_path())
    print(json.dumps(doc, indent=1))
    return 0 if doc['running'] else 1


# --------------------------------------------------------------------------- service install

LABEL = 'com.ericmacdougall.hookd'


def unit_files(script):
    """launchd agent (macOS) or systemd user unit (Linux). Default priority: hookd is on every tool call's path,
    so it is not niced like ahd. Memory is capped on Linux; on macOS the child cap bounds it."""
    h = home()
    logs = os.path.join(h, '.agent-harness', 'logs')
    if sys.platform == 'darwin':
        plist = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>%s</string>
<key>ProgramArguments</key><array><string>/usr/bin/python3</string><string>%s</string><string>serve</string></array>
<key>RunAtLoad</key><true/>
<key>KeepAlive</key><true/>
<key>ThrottleInterval</key><integer>5</integer>
<key>ProcessType</key><string>Interactive</string>
<key>StandardOutPath</key><string>/dev/null</string>
<key>StandardErrorPath</key><string>%s/hookd.err</string>
</dict></plist>
""" % (LABEL, script, logs)
        return {os.path.join(h, 'Library', 'LaunchAgents', LABEL + '.plist'): plist}
    unit = """[Unit]
Description=agent harness hook server (hookd, GoodQA goodqa#14859)

[Service]
ExecStart=/usr/bin/env python3 %s serve
Restart=always
RestartSec=2
MemoryMax=1G
TasksMax=256

[Install]
WantedBy=default.target
""" % script
    return {os.path.join(h, '.config', 'systemd', 'user', 'hookd.service'): unit}


def service_cmds(files, start):
    if sys.platform == 'darwin':
        cmds = [['launchctl', 'bootout', 'gui/%d/%s' % (os.getuid(), LABEL)]]
        if start:
            cmds.append(['launchctl', 'bootstrap', 'gui/%d' % os.getuid(), next(iter(files))])
        return cmds
    if start:
        return [['systemctl', '--user', 'daemon-reload'], ['systemctl', '--user', 'enable', 'hookd.service'],
                ['systemctl', '--user', 'restart', 'hookd.service']]
    return [['systemctl', '--user', 'disable', '--now', 'hookd.service'], ['systemctl', '--user', 'daemon-reload']]


def install_main(argv):
    import subprocess
    apply, remove = '--apply' in argv, '--uninstall' in argv
    files = unit_files(os.path.abspath(__file__))
    if not remove:
        for path, body in files.items():
            print('%s %s' % ('write' if apply else 'would write', path))
            if apply:
                os.makedirs(os.path.dirname(path), exist_ok=True)
                if os.path.exists(path):
                    import shutil
                    backup = path + '.bak-' + time.strftime('%Y%m%dT%H%M%SZ', time.gmtime())
                    shutil.copy2(path, backup)
                    print('backup %s' % backup)
                tmp = path + '.tmp'
                with open(tmp, 'w') as handle:
                    handle.write(body)
                os.replace(tmp, path)
    for cmd in service_cmds(files, start=not remove):
        print(('run ' if apply else 'would run ') + ' '.join(cmd))
        if apply:
            subprocess.run(cmd, stdin=subprocess.DEVNULL, check=False, capture_output=True)
    if remove:
        for path in files:
            print('%s %s' % ('remove' if apply else 'would remove', path))
            if apply:
                try:
                    os.unlink(path)
                except FileNotFoundError:
                    pass
    if apply and not remove:
        for _ in range(100):
            if os.path.exists(socket_path()):
                print('hookd is listening on %s' % socket_path())
                return 0
            time.sleep(0.1)
        print('hookd: the service did not open its socket within 10 s; hookc runs the cold hooks meanwhile',
              file=sys.stderr)
        return 1
    return 0


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ('-h', '--help'):
        print(__doc__)
        return 0
    if argv[0] == 'serve':
        return serve()
    if argv[0] == 'status':
        return status_main()
    if argv[0] == 'install':
        return install_main(argv[1:])
    print('hookd: unknown command %s' % argv[0], file=sys.stderr)
    return 2


if __name__ == '__main__':
    sys.exit(main())
