"""ah-run launcher core (goodqa#14548): exit pass-through, ledger digests, signals, parent death, kill, mask."""

import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest

HOOKS = Path(__file__).resolve().parents[1] / 'harness/hooks'
sys.path.insert(0, str(HOOKS))
import ah_run

AH = str(HOOKS / 'ah_run.py')


class Fixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='ahrun-'); self.addCleanup(self.temp.cleanup)
        self.reserve = Path(self.temp.name) / 'reserve'; self.reserve.mkdir(mode=0o700)
        self.env = {**os.environ, 'AGENT_HARNESS_RESERVE_DIR': str(self.reserve), 'LC_ALL': 'C'}
        self.env.pop('CLAUDE_CODE_SHELL_SNAPSHOT', None)

    def run_cmd(self, command, *flags, **kw):
        return subprocess.run([sys.executable, AH, 'run', '--task', 't1', '--agent', 'a1', '--token', 'tok', '--no-unit', *flags, '--', command],
                              env=self.env, capture_output=True, text=True, timeout=30, **kw)

    def rows(self):
        return list(ah_run.Ledger(self.reserve).rows())

    def wait_gone(self, pid, seconds=5):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if ah_run.pid_exists(pid) is False:
                return True
            time.sleep(0.05)
        return False


class Launcher(Fixture):
    def test_exit_status_stdout_cwd_and_env_pass_through(self):
        result = self.run_cmd('echo "$AGENT_HARNESS_TASK:$AGENT_ID:$AGENT_HARNESS_RUN_ID"; pwd; exit 3', cwd=self.temp.name)
        self.assertEqual(result.returncode, 3)
        head, cwd = result.stdout.splitlines()[:2]
        self.assertTrue(head.startswith('t1:a1:')); self.assertEqual(len(head.split(':')[2]), 32)
        self.assertEqual(Path(cwd).resolve(), Path(self.temp.name).resolve())

    def test_stdin_is_inherited(self):
        result = self.run_cmd('cat', input='piped in\n')
        self.assertEqual(result.stdout, 'piped in\n')

    def test_ledger_row_holds_digests_never_the_command(self):
        secret = 'ghp_' + 'x' * 30
        self.run_cmd('echo %s >/dev/null' % secret)
        rows = self.rows()
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual((row['task'], row['agent'], row['attribution'], row['exit_code']), ('t1', 'a1', 'verified', 0))
        serialized = json.dumps(row)
        self.assertNotIn(secret, serialized); self.assertNotIn('echo', serialized)
        self.assertEqual(len(row['command_sha256']), 64); self.assertIsNotNone(row['end'])
        self.assertIn('rusage', row)

    def test_missing_task_gets_a_generated_key_and_no_token_is_unverified(self):
        result = subprocess.run([sys.executable, AH, 'run', '--no-unit', '--', 'true'], env=self.env, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0)
        row = self.rows()[0]
        self.assertTrue(row['task'].startswith('auto-')); self.assertEqual(row['attribution'], 'unverified')
        refused = subprocess.run([sys.executable, AH, 'run', '--readonly', '--no-unit', '--', 'true'], env=self.env, capture_output=True, text=True, timeout=30)
        self.assertEqual(refused.returncode, 126)

    def test_payload_file_is_read_once_and_unlinked(self):
        payload = self.reserve / 'ledger' / 'pending' / 'tok.cmd'
        payload.parent.mkdir(parents=True, exist_ok=True)
        payload.write_text('echo from-file'); payload.chmod(0o600)
        result = subprocess.run([sys.executable, AH, 'run', '--task', 't1', '--token', 'tok', '--no-unit', '--cmd-file', str(payload)],
                                env=self.env, capture_output=True, text=True, timeout=30)
        self.assertEqual((result.returncode, result.stdout.strip()), (0, 'from-file'))
        self.assertFalse(payload.exists())

    def test_base64_transport(self):
        import base64
        encoded = base64.b64encode(b"printf '%s\\n' \"it's $HOME-free\"").decode()
        result = subprocess.run([sys.executable, AH, 'run', '--task', 't1', '--token', 'via-hook-ssh', '--no-unit', '--cmd-b64', encoded],
                                env=self.env, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0); self.assertIn("it's", result.stdout)
        self.assertEqual(self.rows()[0]['attribution'], 'hook-ssh')


class Signals(Fixture):
    def start_sleeper(self):
        marker = Path(self.temp.name) / 'pids.txt'
        script = ('sh -c \'echo $$ > %s; sleep 60\' & child=$!; echo $child >> %s; wait' % (marker, marker))
        proc = subprocess.Popen([sys.executable, AH, 'run', '--task', 't1', '--token', 'tok', '--no-unit', '--', script],
                                env=self.env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and (not marker.exists() or len(marker.read_text().split()) < 2):
            time.sleep(0.05)
        pids = [int(p) for p in marker.read_text().split()]
        return proc, pids

    def test_sigterm_to_the_launcher_kills_the_whole_group(self):
        proc, pids = self.start_sleeper()
        proc.send_signal(signal.SIGTERM)
        proc.wait(timeout=10)
        for pid in pids:
            self.assertTrue(self.wait_gone(pid), 'pid %d survived' % pid)
        self.assertEqual(proc.returncode, 128 + signal.SIGTERM)
        self.assertEqual(self.rows()[0]['signal'], int(signal.SIGTERM))

    def test_parent_death_kills_the_group(self):
        marker = Path(self.temp.name) / 'pids2.txt'
        wrapper = ('%s %s run --task t1 --token tok --no-unit -- "sh -c \'echo \\$\\$ > %s; sleep 60\' & echo \\$! >> %s; wait"'
                   % (sys.executable, AH, marker, marker))
        # "; :" keeps sh from exec-ing straight into ah-run, so killing sh is a true parent death.
        parent = subprocess.Popen(['/bin/sh', '-c', wrapper + '; :'], env=self.env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and (not marker.exists() or len(marker.read_text().split()) < 2):
            time.sleep(0.05)
        pids = [int(p) for p in marker.read_text().split()]
        os.kill(parent.pid, signal.SIGKILL); parent.wait(timeout=5)
        for pid in pids:
            self.assertTrue(self.wait_gone(pid, 6), 'pid %d survived the parent death' % pid)

    def test_sigkill_on_the_launcher_itself_still_ends_the_group(self):
        proc, pids = self.start_sleeper()
        os.kill(proc.pid, signal.SIGKILL); proc.wait(timeout=5)
        for pid in pids:
            self.assertTrue(self.wait_gone(pid, 8), 'pid %d survived the launcher SIGKILL' % pid)


class Kill(Fixture):
    def test_kill_by_task_reaches_env_attributed_orphans_and_spares_the_rest(self):
        marker = Path(self.temp.name) / 'orphan.txt'
        # A grandchild that leaves the group with its own session but keeps the attribution env.
        script = ('%s -c "import os,subprocess,sys,time; p=subprocess.Popen([\'sleep\',\'60\'], start_new_session=True); '
                  'open(%r,\'w\').write(str(p.pid)); time.sleep(60)"' % (sys.executable, str(marker)))
        proc = subprocess.Popen([sys.executable, AH, 'run', '--task', 'kt', '--token', 'tok', '--no-unit', '--', script], env=self.env,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline and not marker.exists(): time.sleep(0.05)
        orphan = int(marker.read_text())
        bystander = subprocess.Popen(['sleep', '60'])
        self.addCleanup(lambda: bystander.poll() is None and bystander.kill())
        result = subprocess.run([sys.executable, AH, 'kill', '--task', 'kt'], env=self.env, capture_output=True, text=True, timeout=30)
        report = json.loads(result.stdout)
        self.assertTrue(any(e['pid'] == orphan for e in report['signalled']), report)
        self.assertTrue(self.wait_gone(orphan)); proc.wait(timeout=10)
        self.assertIsNone(bystander.poll())
        self.assertFalse(any(e['pid'] == os.getpid() for e in report['signalled']))
        none = json.loads(subprocess.run([sys.executable, AH, 'kill', '--task', 'nothing'], env=self.env, capture_output=True, text=True, timeout=30).stdout)
        self.assertEqual(none['signalled'], [])

    def test_pause_and_resume(self):
        proc = subprocess.Popen([sys.executable, AH, 'run', '--task', 'pt', '--token', 'tok', '--no-unit', '--', 'sleep 60'], env=self.env,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.addCleanup(lambda: subprocess.run([sys.executable, AH, 'kill', '--task', 'pt'], env=self.env, capture_output=True, timeout=30))
        self.addCleanup(lambda: proc.poll() is None and proc.kill())
        time.sleep(1)
        paused = json.loads(subprocess.run([sys.executable, AH, 'kill', '--task', 'pt', '--pause'], env=self.env, capture_output=True, text=True, timeout=30).stdout)
        self.assertTrue(paused['signalled'])
        pid = paused['signalled'][0]['pid']
        state = subprocess.run(['ps', '-o', 'stat=', '-p', str(pid)], capture_output=True, text=True).stdout.strip()
        self.assertTrue(state.startswith('T'), state)
        resumed = json.loads(subprocess.run([sys.executable, AH, 'kill', '--task', 'pt', '--resume'], env=self.env, capture_output=True, text=True, timeout=30).stdout)
        self.assertTrue(resumed['signalled'])
        state = subprocess.run(['ps', '-o', 'stat=', '-p', str(pid)], capture_output=True, text=True).stdout.strip()
        self.assertFalse(state.startswith('T'), state)


class Mask(unittest.TestCase):
    def test_masks_bearer_flag_values_and_detector_patterns(self):
        text = 'curl -H "Authorization: Bearer abc123DEF" --token s3cr3t --api-key=K9K9 -token t2 --passwd pw ghp_' + 'q' * 20 + ' plain'
        masked = ah_run.mask_argv(text)
        for secret in ('abc123DEF', 's3cr3t', 'K9K9', 't2', 'pw', 'ghp_' + 'q' * 20):
            self.assertNotIn(secret, masked)
        self.assertIn('plain', masked)
        self.assertLessEqual(len(ah_run.mask_argv('x' * 2000)), 512)
        self.assertNotIn('\n', ah_run.mask_argv('a\nb'))


if __name__ == '__main__':
    unittest.main()
