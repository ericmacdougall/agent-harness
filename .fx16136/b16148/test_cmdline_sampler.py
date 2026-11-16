"""goodqa#16148 spec v4 AC-6 (3), NEG-18 (P2, R6): cmdline-sampler.py against a fake /proc tree. Unprivileged.
Run: python3 -m unittest -v test_cmdline_sampler
"""
import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, 'cmdline-sampler.py')
spec = importlib.util.spec_from_file_location('sampler', SCRIPT)
sampler = importlib.util.module_from_spec(spec)
spec.loader.exec_module(sampler)

CID = 'ab' * 32
OTHER = 'cd' * 32
MARKER = 'FAKEsamplerMARKER0123456789abcdefXYZ'


class SamplerTests(unittest.TestCase):
    def setUp(self):
        self.proc = tempfile.mkdtemp(prefix='fakeproc-', dir=os.environ.get('DERIVE_TEST_TMP'))
        self.next_pid = 100

    def tearDown(self):
        shutil.rmtree(self.proc, ignore_errors=True)

    def add(self, argv, container=CID, style='systemd'):
        pid = str(self.next_pid)
        self.next_pid += 1
        d = os.path.join(self.proc, pid)
        os.makedirs(d)
        cg = '0::/system.slice/docker-%s.scope\n' % container if style == 'systemd' else '12:pids:/docker/%s\n' % container
        with open(os.path.join(d, 'cgroup'), 'w') as f:
            f.write(cg)
        with open(os.path.join(d, 'cmdline'), 'wb') as f:
            f.write(b'\0'.join(a.encode() for a in argv) + b'\0')
        with open(os.path.join(d, 'stat'), 'w') as f:
            f.write('%s (docker) S ' % pid + ' '.join(['1'] * 18) + ' %s 0 0\n' % (1000 + int(pid)))
        return pid

    def sample(self, *extra, seconds='0.3'):
        return sampler.run(['--container', CID, '--proc', self.proc, '--seconds', seconds, '--interval', '0.01', *extra])

    def test_env_file_launch_passes_and_records_names_only(self):
        self.add(['/usr/bin/docker', 'run', '--rm', '-d', '--cap-drop=ALL', '--env-file', '/tmp/goodqa-envfile-x/env', 'img@sha256:' + 'a' * 64, 'arg'])
        out, code = self.sample('--expect-runs', '1')
        self.assertEqual((out['verdict'], code), ('PASS', 0))
        self.assertEqual(out['label'], 'sampled')
        self.assertEqual(out['runs'][0]['flags'], ['--rm', '-d', '--cap-drop', '--env-file'])
        self.assertNotIn('goodqa-envfile', json.dumps(out))

    def test_neg18_planted_marker_in_every_form_never_reaches_output(self):
        for argv in (['docker', 'run', '-e', 'K=' + MARKER, 'img'],
                     ['docker', 'run', '-eK=' + MARKER, 'img'],
                     ['docker', 'run', '--env=K=' + MARKER, 'img'],
                     ['docker', 'run', '--env-file=' + MARKER, 'img'],
                     ['docker', 'run', '--' + MARKER + '=x', 'img'],
                     ['docker', 'run', '-' + MARKER, 'img']):
            self.add(argv)
        buf = io.StringIO()
        saved = sys.stdout
        sys.stdout = buf
        try:
            argv0 = sys.argv
            sys.argv = ['cmdline-sampler.py', '--container', CID, '--proc', self.proc, '--seconds', '0.2', '--interval', '0.01', '--expect-runs', '6']
            code = sampler.main()
        finally:
            sys.stdout = saved
            sys.argv = argv0
        text = buf.getvalue()
        self.assertEqual(code, 1)
        out = json.loads(text)
        self.assertEqual(out['verdict'], 'FAIL')
        for i in range(0, len(MARKER) - 7):
            self.assertNotIn(MARKER[i:i + 8], text)
        flags = [r['flags'] for r in out['runs']]
        self.assertIn(['-e'], flags)
        self.assertIn(['-e(attached)'], flags)
        self.assertIn(['--env(attached)'], flags)
        self.assertIn(['--env-file'], flags)
        self.assertIn(['--(other)'], flags)
        self.assertIn(['-(other)(attached)'], flags)
        self.assertEqual(os.listdir(os.path.dirname(self.proc)).count(os.path.basename(self.proc)), 1)

    def test_neg18_other_cgroup_is_not_sampled(self):
        self.add(['docker', 'run', '-e', 'K=' + MARKER, 'img'], container=OTHER)
        self.add(['docker', 'run', '--env-file', '/x', 'img'])
        out, code = self.sample('--expect-runs', '1')
        self.assertEqual((out['verdict'], out['runs_seen']), ('PASS', 1))

    def test_cgroup_v1_docker_path_is_matched(self):
        self.add(['docker', 'run', '-e', 'K=v', 'img'], style='v1')
        out, _ = self.sample('--expect-runs', '1')
        self.assertEqual(out['verdict'], 'FAIL')

    def test_positive_control_no_sample_fails(self):
        out, code = self.sample('--expect-runs', '2')
        self.assertEqual((out['verdict'], code), ('NO_SAMPLE', 1))
        self.add(['docker', 'run', '--env-file', '/x', 'img'])
        out, code = self.sample('--expect-runs', '2')
        self.assertEqual((out['verdict'], code), ('NO_SAMPLE', 1))

    def test_non_run_docker_commands_and_other_binaries_are_ignored(self):
        self.add(['docker', 'inspect', 'abc'])
        self.add(['node', 'run', '-e', 'K=v'])
        out, _ = self.sample('--expect-runs', '1')
        self.assertEqual(out['verdict'], 'NO_SAMPLE')

    def test_a_short_lived_process_is_seen_by_polling(self):
        def later():
            time.sleep(0.1)
            pid = self.add(['docker', 'run', '--env-file', '/x', 'img'])
            time.sleep(0.15)
            shutil.rmtree(os.path.join(self.proc, pid))
        t = threading.Thread(target=later)
        t.start()
        out, code = self.sample('--expect-runs', '1', seconds='0.5')
        t.join()
        self.assertEqual((out['verdict'], code), ('PASS', 0))

    def test_same_process_counted_once(self):
        self.add(['docker', 'run', '--env-file', '/x', 'img'])
        out, _ = self.sample('--expect-runs', '1')
        self.assertEqual(out['runs_seen'], 1)

    def test_bad_container_id_refused(self):
        out, code = sampler.run(['--container', 'not-hex', '--proc', self.proc, '--seconds', '0'])
        self.assertEqual((out['verdict'], code), ('FAIL', 1))

    def test_runs_unprivileged_on_the_real_proc(self):
        r = subprocess.run([sys.executable, '-I', SCRIPT, '--container', CID, '--seconds', '0.2', '--expect-runs', '0'],
                           capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(json.loads(r.stdout)['verdict'], 'PASS')


if __name__ == '__main__':
    unittest.main()
