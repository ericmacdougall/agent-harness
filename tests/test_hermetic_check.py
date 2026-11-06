"""Behavior of the gate runner tests/hermetic_check.sh against small fixture trees (GoodQA #14560).

Each case builds a throwaway tree with one test module, runs the real script with the suite's own interpreter and checks the
exit code and verdict line. The protected-write case only tries to open a file inside a nonexistent directory below a real
state dir, so the audit hook sees the attempt but nothing is written.
"""
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import hermetic  # noqa: E402

SCRIPT = Path(__file__).resolve().parent / 'hermetic_check.sh'

PASSING = "import unittest\nclass T(unittest.TestCase):\n    def test_ok(self):\n        self.assertTrue(True)\n"
FAILING = "import unittest\nclass T(unittest.TestCase):\n    def test_bad(self):\n        self.fail('boom')\n"
SSH_OUTSIDE = ("import subprocess, unittest\nclass T(unittest.TestCase):\n    def test_ssh(self):\n"
               "        subprocess.run(['ssh', '-o', 'BatchMode=yes', 'dev2', 'uptime'])\n")
SSH_GIT_LOOPBACK = ("import subprocess, unittest\nclass T(unittest.TestCase):\n    def test_ssh(self):\n"
                    "        subprocess.run(['ssh', '-o', 'SendEnv=GIT_PROTOCOL', '127.0.0.1', 'git-upload-pack', '/x'])\n")
SSH_LOOPBACK_OTHER = ("import subprocess, unittest\nclass T(unittest.TestCase):\n    def test_ssh(self):\n"
                      "        subprocess.run(['ssh', '-J', 'bastion', '127.0.0.1', 'curl', 'localhost'])\n")
PROTECTED_WRITE = ("import os, unittest\nclass T(unittest.TestCase):\n    def test_write(self):\n"
                   "        path = os.path.join(%r, '.claude', '.hc-fixture-missing-dir', 'x')\n"
                   "        try:\n            open(path, 'w')\n        except OSError:\n            pass\n")


class GateRunner(unittest.TestCase):
    def setUp(self):
        self.temp = Path(os.path.realpath(tempfile.mkdtemp(prefix='gate-fixture-')))
        self.addCleanup(shutil.rmtree, self.temp, True)
        self.reports = []

    def tree(self, source):
        tree = self.temp / 'tree'
        (tree / 'tests').mkdir(parents=True, exist_ok=True)
        (tree / 'tests' / 'test_fixture.py').write_text(source)
        return tree

    def run_gate(self, source, *, pattern=None, env=None, script=SCRIPT):
        tree = self.tree(source) if source is not None else self.temp
        command = ['bash', str(script), sys.executable, str(tree)] + ([pattern] if pattern else [])
        environment = {key: value for key, value in os.environ.items() if not key.startswith('HC_')}
        environment.update(env or {})
        done = subprocess.run(command, capture_output=True, text=True, env=environment, timeout=240)
        match = re.search(r'REPORT_DIR=(\S+)', done.stdout)
        if match:
            self.addCleanup(shutil.rmtree, match.group(1), True)
        return done

    def result_line(self, done):
        return next((line for line in done.stdout.splitlines() if line.startswith('suite_rc=')), '')

    def test_a_clean_tree_passes_with_exit_zero(self):
        done = self.run_gate(PASSING)
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertIn('HERMETIC_PASS', done.stdout)
        self.assertRegex(self.result_line(done), r'tests_ran=1 final_ok=1 audit_writes=0 .*ssh_calls=0 ')

    def test_zero_tests_cannot_pass(self):
        # python 3.9-3.11 exit 0 on zero tests, so only there does the 'Ran N, N>0' clause decide the verdict; on 3.12+
        # unittest's own exit code 5 already fails the run. The test holds on every version either way.
        done = self.run_gate(PASSING, pattern='nomatch_*.py')
        self.assertEqual(done.returncode, 1, done.stdout + done.stderr)
        self.assertIn('HERMETIC_FAIL', done.stdout)

    def test_a_failing_suite_fails_the_gate(self):
        done = self.run_gate(FAILING)
        self.assertEqual(done.returncode, 1, done.stdout + done.stderr)
        self.assertIn('HERMETIC_FAIL', done.stdout)
        self.assertIn('final_ok=0', done.stdout)

    def test_ssh_to_an_outside_host_fails_the_gate(self):
        done = self.run_gate(SSH_OUTSIDE)
        self.assertEqual(done.returncode, 1, done.stdout + done.stderr)
        self.assertRegex(self.result_line(done), r'ssh_calls=1 ')

    def test_only_the_exact_git_loopback_form_is_exempt(self):
        done = self.run_gate(SSH_GIT_LOOPBACK)
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertRegex(self.result_line(done), r'ssh_calls=0 ssh_loopback_calls=1 ')
        other = self.run_gate(SSH_LOOPBACK_OTHER)
        self.assertEqual(other.returncode, 1, other.stdout + other.stderr)
        self.assertRegex(self.result_line(other), r'ssh_calls=1 ')

    def test_an_attempted_write_into_a_protected_dir_fails_the_gate(self):
        done = self.run_gate(PROTECTED_WRITE % str(hermetic.real_home()))
        self.assertEqual(done.returncode, 1, done.stdout + done.stderr)
        self.assertNotRegex(self.result_line(done), r'audit_writes=0 ')

    def test_a_missing_hook_stops_the_gate_before_any_suite_runs(self):
        lonely = self.temp / 'lonely'
        lonely.mkdir()
        shutil.copy(SCRIPT, lonely / 'hermetic_check.sh')
        done = self.run_gate(PASSING, script=lonely / 'hermetic_check.sh')
        self.assertEqual(done.returncode, 4, done.stdout + done.stderr)
        self.assertNotIn('HERMETIC_PASS', done.stdout)

    def test_unpinned_mode_without_a_sandbox_is_refused(self):
        done = self.run_gate(PASSING, env={'HC_UNPINNED': '1'})
        self.assertEqual(done.returncode, 5, done.stdout + done.stderr)
        self.assertNotIn('HERMETIC_PASS', done.stdout)


if __name__ == '__main__':
    unittest.main()
