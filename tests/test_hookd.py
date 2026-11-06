"""hookd and hookc: same verdicts as the cold hooks, and never fail open (GoodQA goodqa#14859).

Payload commands are DATA handed to the hooks as JSON; nothing in them is executed.
"""

import json
import os
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HOOKS = ROOT / 'harness' / 'hooks'
SESSION = '0f0e0d0c-0b0a-4000-8000-0000000test1'
GO = shutil.which('go')
BLOCK_CMD = 'pkill -f node'   # kill_guard blocks a broad kill (exit 2)


def payload(cmd, tool='Bash', i=0):
    return json.dumps({'session_id': SESSION, 'cwd': '/', 'hook_event_name': 'PreToolUse', 'tool_name': tool,
                       'tool_input': {'command': cmd}, 'tool_use_id': 'toolu_t%d' % i}).encode()


def build_hookc(dest):
    env = dict(os.environ, GOTOOLCHAIN='local', CGO_ENABLED='0', GOFLAGS='')
    subprocess.run(['go', 'build', '-trimpath', '-o', str(dest), '.'], cwd=str(ROOT / 'tools' / 'hookc'),
                   env=env, check=True, capture_output=True)
    return dest


@unittest.skipIf(GO is None or os.name == 'nt', 'needs Go to build hookc and a POSIX host')
class HookdTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base = Path(tempfile.mkdtemp(prefix='hkt-', dir='/tmp'))
        os.chmod(cls.base, 0o700)
        cls.hookc = build_hookc(cls.base / 'hookc')

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.base, ignore_errors=True)

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix='c', dir=str(self.base)))
        self.home = self.dir / 'h'
        (self.home / '.claude').mkdir(parents=True)
        self.run_dir = self.dir / 'r'
        self.log = self.dir / 'hookd.log'
        self.hooks = HOOKS
        self.server = None

    def tearDown(self):
        self.stop()

    # ------------------------------------------------------------------ helpers
    def env(self, **extra):
        # Locale variables are set per case, never inherited (review round 1, F2): an ambient LC_CTYPE would
        # override the LANG a test names.
        env = {k: v for k, v in os.environ.items()
               if not k.startswith(('HOOKD_', 'HOOKC_', 'CLAUDE_', 'AH_', 'LC_')) and k != 'LANG'}
        env.update(HOME=str(self.home), HOOKD_RUN_DIR=str(self.run_dir), HOOKD_LOG=str(self.log),
                   HOOKC_DEBUG='1', PYTHONDONTWRITEBYTECODE='1', LANG='en_US.UTF-8')
        env.update(extra)
        return env

    # The interpreter the cold path runs (`python3` on PATH); the served one must be the same (review F3).
    python = os.path.realpath(shutil.which('python3') or sys.executable)

    def start(self, hooks=None, *extra):
        hooks = hooks or self.hooks
        self.server = subprocess.Popen([self.python, str(Path(hooks) / 'hookd.py'), 'serve', '--python', self.python,
                                        *extra], env=self.env(),
                                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                       stderr=subprocess.DEVNULL, start_new_session=True)
        sock = self.run_dir / 'hookd.sock'
        for _ in range(400):
            if sock.exists():
                return
            time.sleep(0.025)
        self.fail('hookd did not start')

    def stop(self):
        if self.server and self.server.poll() is None:
            os.killpg(self.server.pid, signal.SIGTERM)
            try:
                self.server.wait(timeout=15)
            except subprocess.TimeoutExpired:
                os.killpg(self.server.pid, signal.SIGKILL)
                self.server.wait()
        self.server = None

    def client(self, script, args, data, hooks=None, **extra):
        path = str(Path(hooks or self.hooks) / script)
        return subprocess.run([str(self.hookc), path] + args, input=data, capture_output=True,
                              env=self.env(**extra), cwd='/', timeout=60)

    def cold(self, script, args, data, hooks=None, **extra):
        path = str(Path(hooks or self.hooks) / script)
        env = self.env(**extra)
        return subprocess.run(['python3', path] + args, input=data, capture_output=True, env=env, cwd='/',
                              timeout=60)

    def assertSame(self, warm, cold):
        werr = b''.join(l + b'\n' for l in warm.stderr.split(b'\n') if l and not l.startswith(b'hookc: cold path'))
        self.assertEqual((warm.returncode, warm.stdout), (cold.returncode, cold.stdout))
        self.assertEqual(werr.strip(), cold.stderr.strip())

    def fake_server(self, behaviour, dir_mode=0o700, sock_mode=0o600):
        """A stand-in server at the hookd socket path. behaviour(conn) handles each connection."""
        self.run_dir.mkdir(mode=0o700, exist_ok=True)
        path = self.run_dir / 'hookd.sock'
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(path))
        os.chmod(path, sock_mode)
        os.chmod(self.run_dir, dir_mode)
        listener.listen(8)
        stop = threading.Event()

        def loop():
            listener.settimeout(0.1)
            while not stop.is_set():
                try:
                    conn, _ = listener.accept()
                except socket.timeout:
                    continue
                try:
                    behaviour(conn)
                except OSError:
                    pass
                finally:
                    conn.close()

        thread = threading.Thread(target=loop, daemon=True)
        thread.start()

        def cleanup():
            stop.set()
            thread.join(2)
            listener.close()
            os.chmod(self.run_dir, 0o700)
        self.addCleanup(cleanup)

    @staticmethod
    def frame(conn, obj):
        data = obj if isinstance(obj, bytes) else json.dumps(obj).encode()
        conn.sendall(struct.pack('>I', len(data)) + data)

    # ------------------------------------------------------------------ parity (served)
    def test_served_verdicts_match_cold(self):
        self.start()
        cases = [('kill_guard.py', ['hook'], payload(BLOCK_CMD)), ('kill_guard.py', ['hook'], payload('ls -la')),
                 ('command_guard_hook.py', ['hook'], payload('rm -rf ~/.claude/wals')),
                 ('command_guard_hook.py', ['hook'], payload('git status')),
                 ('bg_lint.py', [], payload('sleep 5 & echo started')),
                 ('wal.py', ['pretool'], b'{not json')]
        codes = set()
        for script, args, data in cases:
            with self.subTest(script=script, data=data[:60]):
                warm = self.client(script, args, data)
                self.assertNotIn(b'hookc: cold path', warm.stderr)   # really served
                cold = self.cold(script, args, data)
                self.assertSame(warm, cold)
                codes.add(cold.returncode)
        self.assertIn(2, codes)   # the set is not vacuous: it contains blocks
        self.assertIn(0, codes)

    # ------------------------------------------------------------------ fail closed
    def test_no_server_runs_cold_and_still_blocks(self):
        warm = self.client('kill_guard.py', ['hook'], payload(BLOCK_CMD))
        self.assertEqual(warm.returncode, 2)
        self.assertIn(b'hookc: cold path (no-private-socket)', warm.stderr)

    def test_garbage_reply_runs_cold(self):
        def garbage(conn):
            self.frame(conn, {'v': 1, 'status': 'accepted'})
            self.read_request(conn)
            conn.sendall(b'\x00\x00\x00\x05nope!')
        self.fake_server(garbage)
        warm = self.client('kill_guard.py', ['hook'], payload(BLOCK_CMD))
        self.assertEqual(warm.returncode, 2)
        self.assertIn(b'cold path (garbage)', warm.stderr)

    def test_truncated_reply_runs_cold(self):
        def truncated(conn):
            self.frame(conn, {'v': 1, 'status': 'accepted'})
            self.read_request(conn)
            self.frame(conn, {'v': 1, 'status': 'ok', 'exit': 0})
            conn.sendall(struct.pack('>I', 100) + b'short')
        self.fake_server(truncated)
        warm = self.client('kill_guard.py', ['hook'], payload(BLOCK_CMD))
        self.assertEqual(warm.returncode, 2)
        self.assertIn(b'cold path (truncated)', warm.stderr)

    def test_slow_server_runs_cold_within_budget(self):
        self.fake_server(lambda conn: time.sleep(4))
        t0 = time.monotonic()
        warm = self.client('kill_guard.py', ['hook'], payload(BLOCK_CMD))
        elapsed = time.monotonic() - t0
        self.assertEqual(warm.returncode, 2)
        self.assertIn(b'cold path (no-accept)', warm.stderr)
        self.assertGreaterEqual(elapsed, 1.9)

    # ------------------------------------------------------------------ one overall deadline (review F1)
    def hang_after_request(self, delay):
        def behaviour(conn):
            self.frame(conn, {'v': 1, 'status': 'accepted'})
            self.read_request(conn)
            time.sleep(delay)
        return behaviour

    def timed(self, argv, data, **extra):
        t0 = time.monotonic()
        result = subprocess.run([str(self.hookc)] + argv, input=data, capture_output=True,
                                env=self.env(**extra), cwd='/', timeout=60)
        return result, time.monotonic() - t0

    def test_served_hook_at_70pct_of_the_timeout_still_ends_inside_it(self):
        """A served call that runs 0.7T and never answers must not be followed by a cold rerun past T."""
        self.fake_server(self.hang_after_request(0.7 * 4 + 5))
        warm, elapsed = self.timed(['--deadline', '4', '--gate', str(HOOKS / 'kill_guard.py'), 'hook'],
                                   payload('ls -la'))   # an allow when run cold: a block here can only be fail-closed
        self.assertLess(elapsed, 4.0)
        self.assertEqual(warm.returncode, 2, warm.stderr)
        self.assertIn(b'fail-closed', warm.stderr)

    def test_served_answer_at_half_the_timeout_is_used(self):
        def slow_ok(conn):
            self.frame(conn, {'v': 1, 'status': 'accepted'})
            self.read_request(conn)
            time.sleep(0.5 * 4)
            self.frame(conn, {'v': 1, 'status': 'ok', 'exit': 0})
            self.frame(conn, b'served')
            self.frame(conn, b'')
        self.fake_server(slow_ok)
        warm, elapsed = self.timed(['--deadline', '4', '--gate', str(HOOKS / 'kill_guard.py'), 'hook'],
                                   payload('ls'))
        self.assertLess(elapsed, 4.0)
        self.assertEqual((warm.returncode, warm.stdout), (0, b'served'))

    def test_server_timeout_answer_is_not_rerun_cold(self):
        def timeout(conn):
            self.frame(conn, {'v': 1, 'status': 'accepted'})
            self.read_request(conn)
            self.frame(conn, {'v': 1, 'status': 'fallback', 'reason': 'timeout'})
        self.fake_server(timeout)
        warm, _ = self.timed(['--deadline', '4', '--gate', str(HOOKS / 'kill_guard.py'), 'hook'], payload('ls'))
        self.assertEqual(warm.returncode, 2)
        self.assertIn(b'fail-closed', warm.stderr)
        advisory, _ = self.timed(['--deadline', '4', str(HOOKS / 'bg_lint.py')], payload('ls'))
        self.assertEqual(advisory.returncode, 1)          # a fail-open hook reports a non-blocking error
        self.assertNotIn(b'fail-closed', advisory.stderr)

    def test_slow_cold_gate_with_hookd_down_blocks_inside_the_timeout(self):
        hooks = self.dir / 'slow'
        hooks.mkdir()
        (hooks / 'kill_guard.py').write_text('import time\ntime.sleep(30)\n')   # allows, but far too late
        warm, elapsed = self.timed(['--deadline', '2', '--gate', str(hooks / 'kill_guard.py'), 'hook'], b'{}')
        self.assertLess(elapsed, 2.0)
        self.assertEqual(warm.returncode, 2)
        self.assertIn(b'fail-closed', warm.stderr)

    def test_stalled_accept_leaves_the_cold_run_its_time(self):
        self.fake_server(lambda conn: time.sleep(6))
        warm, elapsed = self.timed(['--deadline', '4', '--gate', str(HOOKS / 'kill_guard.py'), 'hook'],
                                   payload(BLOCK_CMD))
        self.assertEqual(warm.returncode, 2)
        self.assertIn(b'cold path (no-accept)', warm.stderr)   # the real cold verdict, not a timeout block
        self.assertLess(elapsed, 4.0)

    def test_unknown_option_is_a_usage_error(self):
        warm, _ = self.timed(['--nope', str(HOOKS / 'bg_lint.py')], payload('ls'))
        self.assertEqual(warm.returncode, 2)
        self.assertIn(b'usage: hookc', warm.stderr)

    # ------------------------------------------------------------------ capacity (review F2)
    def test_calls_over_the_child_cap_go_cold_without_a_stall(self):
        hooks = self.dir / 'hooks'
        shutil.copytree(HOOKS, hooks, ignore=shutil.ignore_patterns('__pycache__'))
        target = hooks / 'bg_lint.py'
        marker = '    sys.exit(main())\n'
        text = target.read_text()
        self.assertIn(marker, text)
        target.write_text(text.replace(marker, "    import time as _t; _t.sleep(float(os.environ.get('HKT_HOLD', '0')))\n"
                                               + marker))
        self.assertIn('import os', text)
        self.start(hooks, '--max-children', '1')
        holder = threading.Thread(target=self.client, args=('bg_lint.py', [], payload('ls')),
                                  kwargs={'hooks': hooks, 'HKT_HOLD': '4'})
        holder.start()
        try:
            time.sleep(0.8)
            second, elapsed = self.timed([str(hooks / 'bg_lint.py')], payload('ls'))
            self.assertIn(b'server:busy', second.stderr)
            self.assertLess(elapsed, 1.5)
        finally:
            holder.join()

    # ------------------------------------------------------------------ interpreter and env (review F3)
    def test_other_python_on_path_goes_cold(self):
        self.start()
        shim = self.dir / 'bin'
        shim.mkdir()
        (shim / 'python3').write_text('#!/bin/sh\nexec %s "$@"\n' % self.python)
        (shim / 'python3').chmod(0o755)
        warm = self.client('kill_guard.py', ['hook'], payload(BLOCK_CMD),
                           PATH='%s:%s' % (shim, os.environ.get('PATH', '')))
        self.assertEqual(warm.returncode, 2)
        self.assertIn(b'server:interpreter', warm.stderr)

    def test_python_env_difference_goes_cold(self):
        self.start()
        warm = self.client('kill_guard.py', ['hook'], payload(BLOCK_CMD), PYTHONIOENCODING='latin-1')
        self.assertEqual(warm.returncode, 2)
        self.assertIn(b'server:env', warm.stderr)

    def test_non_utf8_locale_goes_cold(self):
        import locale
        try:
            locale.setlocale(locale.LC_CTYPE, 'en_US.ISO8859-1')
        except locale.Error:
            self.skipTest('no ISO8859-1 locale on this host')
        finally:
            locale.setlocale(locale.LC_CTYPE, '')
        self.start()
        warm = self.client('kill_guard.py', ['hook'], payload(BLOCK_CMD), LANG='en_US.ISO8859-1', LC_ALL='')
        self.assertEqual(warm.returncode, 2)
        self.assertIn(b'server:locale', warm.stderr)

    def test_invalid_utf8_stdin_matches_cold_in_both_locale_modes(self):
        self.start()
        data = b'{"session_id": "\xff\xfe", "tool_name": "Bash"}'
        cases = [{'LANG': 'en_US.UTF-8'}, {'LANG': 'C'}, {'LC_CTYPE': 'UTF-8'}, {'LC_CTYPE': 'C.UTF-8'},
                 {'LC_CTYPE': 'C.utf8'}, {'LC_ALL': 'C'}, {'LANG': 'no_SUCH.locale'}]
        modes = set()
        for extra in cases:
            with self.subTest(**extra):
                probe = subprocess.run([self.python, '-c', 'import sys; print(sys.stdin.errors)'],
                                       env=self.env(**extra), capture_output=True, text=True,
                                       stdin=subprocess.DEVNULL)
                modes.add(probe.stdout.strip())
                warm = self.client('wal.py', ['pretool'], data, **extra)
                self.assertNotIn(b'hookc: cold path', warm.stderr)
                cold = self.cold('wal.py', ['pretool'], data, **extra)
                self.assertSame(warm, cold)
        self.assertEqual(modes, {'strict', 'surrogateescape'})   # both handlers really exercised

    def test_served_hook_sees_the_coerced_locale_a_cold_one_sees(self):
        hooks = self.dir / 'probe'
        shutil.copytree(HOOKS, hooks, ignore=shutil.ignore_patterns('__pycache__'))
        target = hooks / 'bg_lint.py'
        marker = '    sys.exit(main())\n'
        probe = "    sys.stderr.write('LC=%s|%s\\n' % (os.environ.get('LC_CTYPE'), sys.stdout.errors))\n"
        target.write_text(target.read_text().replace(marker, probe + marker))
        self.start(hooks)
        seen = set()
        for extra in ({'LANG': 'C'}, {'LANG': 'en_US.UTF-8'}, {'LC_ALL': 'C'}, {'LC_CTYPE': 'UTF-8'}):
            with self.subTest(**extra):
                warm = self.client('bg_lint.py', [], payload('ls'), hooks=hooks, **extra)
                self.assertNotIn(b'hookc: cold path', warm.stderr)
                cold = self.cold('bg_lint.py', [], payload('ls'), hooks=hooks, **extra)
                self.assertIn(b'LC=', cold.stderr)
                seen.add(cold.stderr.split(b'LC=')[1].split(b'\n')[0])
                self.assertSame(warm, cold)
        self.assertGreaterEqual(len(seen), 3, seen)

    def test_a_pin_that_is_not_the_running_interpreter_serves_nothing(self):
        fake = self.dir / 'fakepy'
        fake.write_text('#!/bin/sh\necho /nonexistent/python3\n')
        fake.chmod(0o755)
        self.server = subprocess.Popen([self.python, str(HOOKS / 'hookd.py'), 'serve', '--python', str(fake)],
                                       env=self.env(), stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                       stderr=subprocess.DEVNULL, start_new_session=True)
        for _ in range(400):
            if (self.run_dir / 'hookd.sock').exists() and (self.run_dir / 'status.json').exists():
                break
            time.sleep(0.025)
        status = json.loads((self.run_dir / 'status.json').read_text())
        self.assertIs(status['python_ok'], False)
        warm = self.client('kill_guard.py', ['hook'], payload(BLOCK_CMD))
        self.assertEqual(warm.returncode, 2)
        self.assertIn(b'server:interpreter', warm.stderr)
        self.assertIn('interpreter-mismatch', self.log.read_text())

    def test_the_real_pin_is_recognised(self):
        self.start()
        for _ in range(400):
            if (self.run_dir / 'status.json').exists():
                break
            time.sleep(0.025)
        self.assertIs(json.loads((self.run_dir / 'status.json').read_text())['python_ok'], True)

    def test_unit_runs_the_pinned_interpreter(self):
        sys.path.insert(0, str(HOOKS))
        import hookd
        files = hookd.unit_files('/x/hookd.py', '/opt/py/bin/python3.12')
        (text,) = files.values()
        self.assertIn('/opt/py/bin/python3.12', text)
        self.assertIn('--python', text)
        self.assertNotIn('/usr/bin/env python3', text)

    def test_server_fallback_answer_runs_cold(self):
        def fallback(conn):
            self.frame(conn, {'v': 1, 'status': 'accepted'})
            self.read_request(conn)
            self.frame(conn, {'v': 1, 'status': 'fallback', 'reason': 'busy'})
        self.fake_server(fallback)
        warm = self.client('kill_guard.py', ['hook'], payload(BLOCK_CMD))
        self.assertEqual(warm.returncode, 2)

    @staticmethod
    def read_request(conn):
        for _ in range(2):   # header frame, then stdin frame
            size = struct.unpack('>I', conn.recv(4, socket.MSG_WAITALL))[0]
            got = 0
            while got < size:
                got += len(conn.recv(min(size - got, 1 << 20)))

    def _lying(self, conn):
        self.frame(conn, {'v': 1, 'status': 'accepted'})
        self.read_request(conn)
        self.frame(conn, {'v': 1, 'status': 'ok', 'exit': 0})
        self.frame(conn, b'')
        self.frame(conn, b'')

    def test_lying_server_is_believed_only_on_a_private_socket(self):
        # Control: a private socket is trusted (same uid); this proves the next tests exercise the permission check.
        self.fake_server(self._lying)
        self.assertEqual(self.client('kill_guard.py', ['hook'], payload(BLOCK_CMD)).returncode, 0)

    def test_open_directory_is_not_trusted(self):
        self.fake_server(self._lying, dir_mode=0o755)
        warm = self.client('kill_guard.py', ['hook'], payload(BLOCK_CMD))
        self.assertEqual(warm.returncode, 2)
        self.assertIn(b'no-private-socket', warm.stderr)

    def test_group_writable_socket_is_not_trusted(self):
        self.fake_server(self._lying, sock_mode=0o660)
        warm = self.client('kill_guard.py', ['hook'], payload(BLOCK_CMD))
        self.assertEqual(warm.returncode, 2)

    def test_symlinked_socket_is_not_trusted(self):
        other = self.dir / 'elsewhere'
        other.mkdir(mode=0o700)
        self.run_dir.mkdir(mode=0o700)
        real = other / 's.sock'
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(real))
        listener.listen(1)
        self.addCleanup(listener.close)
        (self.run_dir / 'hookd.sock').symlink_to(real)
        warm = self.client('kill_guard.py', ['hook'], payload(BLOCK_CMD))
        self.assertEqual(warm.returncode, 2)
        self.assertIn(b'no-private-socket', warm.stderr)

    def test_cold_path_that_cannot_start_blocks_a_gate(self):
        warm = subprocess.run([str(self.hookc), str(HOOKS / 'kill_guard.py'), 'hook'], input=payload('ls'),
                              capture_output=True, env=dict(self.env(), PATH='/nonexistent'), timeout=30)
        self.assertEqual(warm.returncode, 2)
        advisory = subprocess.run([str(self.hookc), str(HOOKS / 'bg_lint.py')], input=payload('ls'),
                                  capture_output=True, env=dict(self.env(), PATH='/nonexistent'), timeout=30)
        self.assertEqual(advisory.returncode, 1)

    def test_oversized_stdin_runs_cold(self):
        self.start()
        big = payload('echo ' + 'x' * (9 * 1024 * 1024))
        warm = self.client('kill_guard.py', ['hook'], big)
        cold = self.cold('kill_guard.py', ['hook'], big)
        self.assertSame(warm, cold)

    def test_unserved_script_runs_cold(self):
        self.start()
        warm = self.client('doctor.py', ['--help'], b'')
        self.assertIn(b'server:not-served', warm.stderr)

    def test_env_read_at_import_must_match(self):
        self.start()
        other_home = self.dir / 'other'
        (other_home / '.claude').mkdir(parents=True)
        warm = self.client('kill_guard.py', ['hook'], payload(BLOCK_CMD), HOME=str(other_home))
        self.assertEqual(warm.returncode, 2)
        self.assertIn(b'server:env', warm.stderr)

    # ------------------------------------------------------------------ staleness
    def test_code_edit_is_seen_by_the_next_call(self):
        hooks = self.dir / 'hooks'
        shutil.copytree(HOOKS, hooks, ignore=shutil.ignore_patterns('__pycache__'))
        self.start(hooks)
        first = self.client('bg_lint.py', [], payload('ls'), hooks=hooks)
        self.assertNotIn(b'cold path', first.stderr)
        self.assertNotIn(b'EDITED', first.stderr)
        target = hooks / 'bg_lint.py'
        text = target.read_text()
        marker = '    sys.exit(main())\n'
        self.assertIn(marker, text)
        target.write_text(text.replace(marker, "    sys.stderr.write('EDITED\\n')\n" + marker))
        second = self.client('bg_lint.py', [], payload('ls'), hooks=hooks)
        self.assertIn(b'EDITED', second.stderr)          # never the stale code
        self.assertIn(b'server:stale', second.stderr)
        for _ in range(100):                              # the server re-execs, then serves the new code warm
            third = self.client('bg_lint.py', [], payload('ls'), hooks=hooks)
            if b'cold path' not in third.stderr:
                break
            time.sleep(0.1)
        self.assertNotIn(b'cold path', third.stderr)
        self.assertIn(b'EDITED', third.stderr)

    def test_policy_edit_is_seen_by_the_next_call(self):
        hooks = self.dir / 'hooks'
        shutil.copytree(HOOKS, hooks, ignore=shutil.ignore_patterns('__pycache__'))
        self.start(hooks)
        self.assertEqual(self.client('kill_guard.py', ['hook'], payload(BLOCK_CMD), hooks=hooks).returncode, 2)
        policy_path = hooks / 'kill_guard_policy.json'
        policy = json.loads(policy_path.read_text())
        policy['mode'] = 'off'
        policy_path.write_text(json.dumps(policy))
        after = self.client('kill_guard.py', ['hook'], payload(BLOCK_CMD), hooks=hooks)
        cold = self.cold('kill_guard.py', ['hook'], payload(BLOCK_CMD), hooks=hooks)
        self.assertEqual(cold.returncode, 0)             # the edit really changes the cold verdict
        self.assertEqual(after.returncode, 0)

    # ------------------------------------------------------------------ WAL writer
    def wal_lines(self, name='main.jsonl'):
        path = self.home / '.claude' / 'wals' / SESSION / name
        raw = path.read_bytes() if path.exists() else b''
        self.assertTrue(raw == b'' or raw.endswith(b'\n'))
        return [json.loads(l) for l in raw.splitlines()]

    def test_concurrent_wal_records_are_complete_and_group_committed(self):
        self.start()
        n = 24
        results = [None] * n

        def call(i):
            results[i] = self.client('wal.py', ['pretool'], payload('ls', i=i))

        threads = [threading.Thread(target=call, args=(i,)) for i in range(n)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        for r in results:
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertNotIn(b'cold path', r.stderr)
        ids = sorted(rec['tool_use_id'] for rec in self.wal_lines())
        self.assertEqual(ids, sorted('toolu_t%d' % i for i in range(n)))
        self.stop()
        stops = [json.loads(l) for l in self.log.read_text().splitlines() if '"writer-stop"' in l]
        self.assertTrue(stops)
        self.assertEqual(stops[-1]['lines'], n)          # every record went through the queue
        self.assertLessEqual(stops[-1]['batches'], n)

    def test_sequential_records_keep_order(self):
        self.start()
        for i in range(12):
            self.assertEqual(self.client('wal.py', ['pretool'], payload('ls', i=i)).returncode, 0)
        self.assertEqual([r['tool_use_id'] for r in self.wal_lines()], ['toolu_t%d' % i for i in range(12)])

    def test_killed_writer_loses_nothing_and_restarts(self):
        self.start()
        self.assertEqual(self.client('wal.py', ['pretool'], payload('ls', i=0)).returncode, 0)
        out = subprocess.run(['pgrep', '-P', str(self.server.pid)], capture_output=True, text=True).stdout.split()
        self.assertTrue(out)
        for pid in out:
            os.kill(int(pid), signal.SIGKILL)   # the writer is the only long-lived child
        self.assertEqual(self.client('wal.py', ['pretool'], payload('ls', i=1)).returncode, 0)
        time.sleep(0.6)
        self.assertEqual(self.client('wal.py', ['pretool'], payload('ls', i=2)).returncode, 0)
        self.assertEqual([r['tool_use_id'] for r in self.wal_lines()], ['toolu_t0', 'toolu_t1', 'toolu_t2'])

    def test_stuck_writer_costs_at_most_one_short_timeout(self):
        """Red-team M2: a writer that is alive but stopped must not stall every WAL hook for seconds."""
        self.start()
        self.assertEqual(self.client('wal.py', ['pretool'], payload('ls', i=0)).returncode, 0)
        out = subprocess.run(['pgrep', '-P', str(self.server.pid)], capture_output=True, text=True).stdout.split()
        self.assertTrue(out)
        try:
            for pid in out:
                os.kill(int(pid), signal.SIGSTOP)
            started = time.monotonic()
            self.assertEqual(self.client('wal.py', ['pretool'], payload('ls', i=1)).returncode, 0)
            self.assertLess(time.monotonic() - started, 2.5)
            self.assertIn('toolu_t1', [r['tool_use_id'] for r in self.wal_lines()])  # appended directly, not lost
        finally:
            for pid in out:
                try:
                    os.kill(int(pid), signal.SIGCONT)
                except OSError:
                    pass

    def test_torn_tail_is_repaired(self):
        self.start()
        self.assertEqual(self.client('wal.py', ['pretool'], payload('ls', i=0)).returncode, 0)
        path = self.home / '.claude' / 'wals' / SESSION / 'main.jsonl'
        with open(path, 'ab') as handle:
            handle.write(b'{"at":"torn')                  # a writer killed mid-line
        self.assertEqual(self.client('wal.py', ['pretool'], payload('ls', i=1)).returncode, 0)
        self.assertEqual([r['tool_use_id'] for r in self.wal_lines()], ['toolu_t0', 'toolu_t1'])

    # ------------------------------------------------------------------ peer, threads, logs
    def test_other_uid_peer_is_refused(self):
        code = ('import sys, json, socket, struct, os\n'
                'sys.path.insert(0, %r)\n'
                'import hookd\n'
                'hookd.peer_cred = lambda conn: (1, os.getuid() + 1)\n'
                'a, b = socket.socketpair()\n'
                'pid = os.fork()\n'
                'if pid == 0:\n'
                '    hookd.serve_one(hookd.Preloaded(), a, None)\n'
                'n = struct.unpack(">I", b.recv(4))[0]\n'
                'print(b.recv(n).decode())\n'
                'os.waitpid(pid, 0)\n') % str(HOOKS)
        out = subprocess.run([sys.executable, '-c', code], capture_output=True, text=True, env=self.env(),
                             timeout=30)
        self.assertEqual(json.loads(out.stdout)['status'], 'refused', out.stderr)

    def test_parent_has_no_threads_after_preload(self):
        code = ('import sys, threading\nsys.path.insert(0, %r)\nimport hookd\npre = hookd.preload()\n'
                'print(threading.active_count(), len(pre.modules), sorted(pre.errors))\n') % str(HOOKS)
        out = subprocess.run([sys.executable, '-c', code], capture_output=True, text=True, env=self.env(),
                             timeout=60)
        count, loaded, errors = out.stdout.split(' ', 2)
        self.assertEqual(count, '1', out.stderr)
        self.assertGreaterEqual(int(loaded), 12)
        self.assertEqual(errors.strip(), '[]')

    def test_log_never_holds_payload_or_env(self):
        self.start()
        secret = 'hookd-canary-7f3a9c'
        self.client('command_guard_hook.py', ['hook'], payload('echo ' + secret), HOOKD_CANARY=secret)
        self.client('wal.py', ['pretool'], payload('echo ' + secret))
        self.stop()
        text = self.log.read_text()
        self.assertIn('"start"', text)
        self.assertNotIn(secret, text)
        status = (self.run_dir / 'status.json').read_text()
        self.assertNotIn(secret, status)


class WiringTest(unittest.TestCase):
    """install.py --hookd / --no-hookd and doctor's view of the client form (no Go needed)."""

    @classmethod
    def setUpClass(cls):
        sys.path.insert(0, str(ROOT))
        sys.path.insert(0, str(HOOKS))
        import install  # noqa: E402
        import doctor  # noqa: E402
        import hookd  # noqa: E402
        cls.install, cls.doctor, cls.hookd = install, doctor, hookd
        cls.claude = Path('/home/u/.claude')

    def handlers(self, settings):
        return [h for groups in settings['hooks'].values() for g in groups for h in g['hooks']]

    def test_client_form_wraps_exactly_the_served_handlers(self):
        plain = self.install.merged_settings({}, self.claude)
        wired = self.install.merged_settings({}, self.claude, hookd=True)
        before, after = self.handlers(plain), self.handlers(wired)
        self.assertEqual(len(before), len(after))
        switched = 0
        for old, new in zip(before, after):
            script = Path(old['args'][0]).name
            self.assertEqual(new.get('timeout'), old.get('timeout'))
            self.assertEqual(new.get('onFailure'), old.get('onFailure'))
            if script in self.hookd.SERVED:
                switched += 1
                self.assertEqual(new['command'], str(self.claude.parent / '.agent-harness' / 'bin' / 'hookc'))
                self.assertEqual(new['args'][:2], ['--deadline', '%g' % float(old.get('timeout', 10))])
                gate = old.get('onFailure') == 'block' or old['args'][1:2] == ['ask-gate']
                self.assertEqual(new['args'][2] == '--gate', gate, old['args'])
                self.assertEqual(new['args'][3 if gate else 2:], old['args'])
            else:
                self.assertEqual(new, old)
        self.assertGreaterEqual(switched, 15)

    def test_rewire_is_idempotent_and_reversible(self):
        plain = self.install.merged_settings({}, self.claude)
        wired = self.install.merged_settings({}, self.claude, hookd=True)
        self.assertEqual(self.install.merged_settings(wired, self.claude, hookd=True), wired)
        self.assertEqual(self.install.merged_settings(wired, self.claude, hookd=False), plain)
        self.assertTrue(self.install.uses_hookc(wired))
        self.assertFalse(self.install.uses_hookc(plain))

    def test_every_installed_hook_is_served_or_known_cold(self):
        cold_by_design = {'merge_gate.py', 'log_backup.py'}
        scripts = {Path(h['args'][0]).name for h in self.handlers(self.install.merged_settings({}, self.claude))}
        self.assertEqual(scripts - set(self.hookd.SERVED), cold_by_design)

    def real_hookc(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.claude = Path(tmp.name) / '.claude'
        client = self.install.hookc_path(self.claude)
        client.parent.mkdir(parents=True, exist_ok=True)
        client.write_text('#!/bin/sh\nexit 2\n')
        client.chmod(0o700)
        return str(client)

    def test_doctor_accepts_the_client_only_for_the_same_script(self):
        client = self.real_hookc()
        hooks_dir = self.claude / 'hooks'
        ok = self.doctor.wired_path_ok([client, '--budget', '4', str(hooks_dir / 'wal.py'), 'pretool'],
                                       'wal.py', 'pretool', hooks_dir)
        wrong = self.doctor.wired_path_ok([client, str(hooks_dir / 'bg_lint.py')], 'wal.py', 'pretool',
                                          hooks_dir)
        other = self.doctor.wired_path_ok(['/x/notc', str(hooks_dir / 'wal.py'), 'pretool'], 'wal.py', 'pretool',
                                          hooks_dir)
        self.assertEqual((ok, wrong, other), (True, False, False))

    def test_doctor_accepts_the_deadline_and_gate_options(self):
        client = self.real_hookc()
        hooks_dir = self.claude / 'hooks'
        wal = str(hooks_dir / 'wal.py')
        self.assertTrue(self.doctor.wired_path_ok([client, '--deadline', '10', '--gate', wal, 'pretool'],
                                                  'wal.py', 'pretool', hooks_dir))
        self.assertTrue(self.doctor.wired_path_ok([client, '--deadline', '10', wal, 'pretool'],
                                                  'wal.py', 'pretool', hooks_dir))
        self.assertFalse(self.doctor.wired_path_ok([client, '--deadline', '10', '--gate', '/x/wal.py', 'pretool'],
                                                   'wal.py', 'pretool', hooks_dir))

    def test_doctor_checks_the_deadline_and_gate_against_the_entry(self):
        ok = self.doctor.hookc_options_ok

        def h(*args, **kw):
            return dict({'type': 'command', 'command': '/h/.agent-harness/bin/hookc', 'args': list(args)}, **kw)
        self.assertTrue(ok(h('--deadline', '10', '--gate', '/x/wal.py', 'pretool', timeout=10, onFailure='block'),
                           'wal.py', 'pretool'))
        self.assertFalse(ok(h('--deadline', '10', '/x/wal.py', 'pretool', timeout=10, onFailure='block'),
                            'wal.py', 'pretool'))                       # a blocking hook without --gate
        self.assertFalse(ok(h('--deadline', '30', '--gate', '/x/wal.py', 'pretool', timeout=10, onFailure='block'),
                            'wal.py', 'pretool'))                       # a deadline past the host timeout
        self.assertFalse(ok(h('--deadline', '10', '/x/p.py', 'ask-gate', timeout=10), 'provenance_hooks.py',
                            'ask-gate'))                                # ask-gate enforces without onFailure
        self.assertTrue(ok(h('--deadline', '5', '/x/bg_lint.py', timeout=5), 'bg_lint.py', None))
        self.assertFalse(ok(h('--budget', '4', '/x/bg_lint.py', timeout=10), 'bg_lint.py', None))   # old form
        self.assertFalse(ok(h('/x/bg_lint.py', timeout=10), 'bg_lint.py', None))   # no deadline at all
        self.assertTrue(ok({'type': 'command', 'command': 'python3', 'args': ['/x/bg_lint.py']}, 'bg_lint.py', None))
        wired = self.install.merged_settings({}, self.claude, hookd=True)
        checked = 0
        for handler in self.handlers(wired):
            if Path(handler['command']).name == 'hookc':
                args = handler['args'][2:]
                args = args[1:] if args[0] == '--gate' else args
                self.assertTrue(ok(handler, Path(args[0]).name, (args[1:2] or [None])[0]), handler)
                checked += 1
        self.assertGreaterEqual(checked, 15)

    def test_doctor_rejects_a_hookc_that_is_not_the_installed_executable(self):
        """Red-team M1: a missing, relocated or non-executable hookc must not pass doctor (fail-open guards and
        blocking hooks would both misbehave while doctor reports green)."""
        client = self.real_hookc()
        hooks_dir = self.claude / 'hooks'
        tail = ['--budget', '4', str(hooks_dir / 'wal.py'), 'pretool']
        self.assertFalse(self.doctor.wired_path_ok(['/nonexistent/dir/hookc'] + tail, 'wal.py', 'pretool', hooks_dir))
        Path(client).chmod(0o600)
        self.assertFalse(self.doctor.wired_path_ok([client] + tail, 'wal.py', 'pretool', hooks_dir))
        Path(client).chmod(0o700)
        stray = self.claude.parent / 'elsewhere' / 'hookc'
        stray.parent.mkdir(parents=True, exist_ok=True)
        stray.write_text('#!/bin/sh\nexit 2\n')
        stray.chmod(0o700)
        self.assertFalse(self.doctor.wired_path_ok([str(stray)] + tail, 'wal.py', 'pretool', hooks_dir))

    def test_client_gate_list_matches_onfailure_block(self):
        source = (ROOT / 'tools' / 'hookc' / 'main.go').read_text()
        blocking = {Path(h['args'][0]).name for h in self.handlers(self.install.merged_settings({}, self.claude))
                    if h.get('onFailure') == 'block'}
        self.assertGreaterEqual(len(blocking), 6)
        missing = sorted(s for s in blocking if '"%s": true' % s not in source)
        self.assertEqual(missing, [], 'hookc gates must list every onFailure: block hook')


if __name__ == '__main__':
    unittest.main()
