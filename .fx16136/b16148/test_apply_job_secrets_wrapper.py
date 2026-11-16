"""goodqa#16148 spec v4 AC-11 with R3 and R4: apply-job-secrets.sh (runner side). A stub ssh records each call (its
command and a sha256 of what was streamed on stdin) and answers from a script. No VM, no secrets.
Run: python3 -m unittest -v test_apply_job_secrets_wrapper
"""
import fcntl
import hashlib
import os
import shutil
import subprocess
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
WRAPPER = os.path.join(HERE, 'apply-job-secrets.sh')


def sha(path):
    with open(path, 'rb') as f:
        return hashlib.sha256(f.read()).hexdigest()


STUB_SSH = r'''#!/usr/bin/env python3
import hashlib, json, os, sys
root = os.environ['STUB_ROOT']
data = sys.stdin.buffer.read()
cmd = sys.argv[-1]
with open(os.path.join(root, 'calls.jsonl'), 'a') as f:
    f.write(json.dumps({'argv': sys.argv[1:], 'cmd': cmd, 'stdin': hashlib.sha256(data).hexdigest()}) + '\n')
derive = 'derive' if data.split(b'\n')[1].startswith(b'"""derive-job-secrets.py') else 'host'
answer = open(os.path.join(root, 'answer-' + derive)).read() if os.path.exists(os.path.join(root, 'answer-' + derive)) else '0|ok'
rc, out = answer.split('|', 1)
sys.stdout.write(out + '\n')
sys.exit(int(rc))
'''


class WrapperTests(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp(prefix='apply-wrap-', dir=os.environ.get('DERIVE_TEST_TMP'))
        self.lane = os.path.join(self.root, 'lane')
        os.makedirs(os.path.join(self.lane, 'biz/release-waves'))
        with open(os.path.join(self.lane, 'biz/release-waves/ship.conf'), 'w') as f:
            f.write('SELFHOST_APP=ubuntu@app.invalid\nSELFHOST_DIR=/opt/goodqa/infra/selfhost/app\nSELFHOST_ENV_DIR=/etc/goodqa\n')
        self.ssh = os.path.join(self.root, 'ssh')
        with open(self.ssh, 'w') as f:
            f.write(STUB_SSH)
        os.chmod(self.ssh, 0o755)
        self.answer('derive', '0|job secret github-app-private-key: written')
        self.answer('host', '0|job secrets host apply: applied')

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def answer(self, which, text):
        with open(os.path.join(self.root, 'answer-' + which), 'w') as f:
            f.write(text)

    def run_wrapper(self, *args, env_extra=None):
        env = dict(os.environ, RW_LANE_ROOT=self.lane, APPLY_SSH=self.ssh, STUB_ROOT=self.root, APPLY_TEST_MODE='1')
        env.update(env_extra or {})
        return subprocess.run(['bash', WRAPPER, *args], env=env, capture_output=True, text=True, timeout=60)

    def calls(self):
        p = os.path.join(self.root, 'calls.jsonl')
        if not os.path.exists(p):
            return []
        import json
        return [json.loads(l) for l in open(p)]

    def lockf(self, suffix='.lock'):
        return os.path.join(self.lane, 'locks', 'gq-promote' + suffix)

    def test_apply_streams_derive_then_host_apply_under_the_lock(self):
        r = self.run_wrapper('apply')
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        c = self.calls()
        self.assertEqual(len(c), 2)
        self.assertEqual(c[0]['stdin'], sha(os.path.join(HERE, 'derive-job-secrets.py')))
        self.assertEqual(c[0]['cmd'], 'sudo python3 -I -')
        self.assertEqual(c[1]['stdin'], sha(os.path.join(HERE, 'apply-job-secrets-host.py')))
        self.assertRegex(c[1]['cmd'], r'^sudo python3 -I - --dir /opt/goodqa/infra/selfhost/app --env-dir /etc/goodqa apply --stamp \d{8}T\d{6}Z$')
        self.assertIn('ubuntu@app.invalid', c[0]['argv'])
        self.assertEqual(open(self.lockf('.epoch')).read().strip(), '1')
        self.assertFalse(os.path.exists(self.lockf('.holder')), 'holder removed after the run')

    def test_lock_held_refuses_with_75_and_calls_nothing(self):
        os.makedirs(os.path.dirname(self.lockf()), exist_ok=True)
        with open(self.lockf(), 'a') as f:
            fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
            r = self.run_wrapper('apply')
        self.assertEqual(r.returncode, 75, r.stdout)
        self.assertIn('deploy lock is held', r.stdout)
        self.assertEqual(self.calls(), [])

    def test_release_in_flight_refuses_with_75(self):
        os.makedirs(os.path.dirname(self.lockf()), exist_ok=True)
        with open(self.lockf('.inflight.json'), 'w') as f:
            f.write('{}')
        for mode in ('apply', 'restore', '--check'):
            r = self.run_wrapper(mode)
            self.assertEqual(r.returncode, 75, mode + r.stdout)
        self.assertEqual(self.calls(), [])

    def test_derive_refused_stops_before_the_host_apply(self):
        for answer in ('2|job secret github-app-private-key: REFUSED no GITHUB_APP_PRIVATE_KEY line',
                       '0|job secret github-app-private-key: written\nextra line',
                       '0|',
                       '255|ssh: connect to host app.invalid: Connection refused'):
            open(os.path.join(self.root, 'calls.jsonl'), 'w').close()
            self.answer('derive', answer)
            r = self.run_wrapper('apply')
            self.assertEqual(r.returncode, 2, answer + r.stdout)
            self.assertIn('nothing else applied', r.stdout)
            self.assertEqual(len(self.calls()), 1, answer)

    def test_check_is_read_only_and_does_not_bump_the_epoch(self):
        r = self.run_wrapper('--check')
        self.assertEqual(r.returncode, 0, r.stdout)
        c = self.calls()
        self.assertEqual(c[0]['cmd'], 'sudo python3 -I - --check')
        self.assertTrue(c[1]['cmd'].endswith(' --check'))
        self.assertFalse(os.path.exists(self.lockf('.epoch')))

    def test_restore_streams_only_the_host_apply(self):
        r = self.run_wrapper('restore')
        self.assertEqual(r.returncode, 0, r.stdout)
        c = self.calls()
        self.assertEqual(len(c), 1)
        self.assertTrue(c[0]['cmd'].endswith(' restore'))

    def test_host_apply_failure_is_the_exit_code(self):
        self.answer('host', '2|job secrets host apply: REFUSED conflict: dispatcher.env X')
        r = self.run_wrapper('apply')
        self.assertEqual(r.returncode, 2)

    def test_refusals_without_config(self):
        self.assertEqual(self.run_wrapper('bogus').returncode, 2)
        self.assertEqual(self.run_wrapper('apply', env_extra={'RW_LANE_ROOT': ''}).returncode, 2)
        os.unlink(os.path.join(self.lane, 'biz/release-waves/ship.conf'))
        r = self.run_wrapper('apply')
        self.assertEqual(r.returncode, 2)
        self.assertIn('SELFHOST_APP is not set', r.stdout)
        self.assertEqual(self.calls(), [])


if __name__ == '__main__':
    unittest.main()
