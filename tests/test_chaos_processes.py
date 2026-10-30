"""Small real-process races at shared output boundaries."""

import os
import json
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


HOOKS = Path(__file__).resolve().parents[1] / 'harness/hooks'
ROOT = HOOKS.parents[1]


class ChaosProcesses(unittest.TestCase):
    def test_eight_simultaneous_installs_keep_one_policy_block_and_valid_settings(self):
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary).resolve()
            claude = home / '.claude'
            claude.mkdir()
            (claude / 'CLAUDE.md').write_text('Existing user guidance.\n')
            (claude / 'settings.json').write_text(json.dumps({'model': 'sonnet', 'env': {'FIXTURE': 'keep'}}))
            gate = home / 'go'
            code = ('import subprocess,sys,time\nfrom pathlib import Path\n'
                    'gate=Path(sys.argv[1]); deadline=time.monotonic()+10\n'
                    'while not gate.exists() and time.monotonic()<deadline: time.sleep(.005)\n'
                    'if not gate.exists(): raise SystemExit(9)\n'
                    'result=subprocess.run([sys.executable,sys.argv[2],"--apply","--home",sys.argv[3]],'
                    'capture_output=True,text=True)\n'
                    'if result.returncode: sys.stderr.write(result.stderr)\n'
                    'raise SystemExit(result.returncode)\n')
            workers = []
            try:
                for _ in range(8):
                    workers.append(subprocess.Popen(
                        [sys.executable, '-c', code, str(gate), str(ROOT / 'install.py'), str(home)],
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True))
                gate.touch()
                results = [(worker.communicate(timeout=20), worker.returncode) for worker in workers]
            finally:
                for worker in workers:
                    if worker.poll() is None:
                        worker.kill()
                        worker.communicate(timeout=5)
            self.assertEqual(len(results), 8)
            for streams, code in results:
                if code:
                    self.assertEqual(code, 1, streams)
                    self.assertTrue(any(reason in streams[1] for reason in
                                        ('Directory appeared during installation', 'Directory replaced during installation',
                                         'Parent directory replaced', 'Unexpected parent directory',
                                         'User settings or instructions changed',
                                         'Managed file changed since snapshot',
                                         'Managed file changed after replacement', 'FileExistsError')), streams)
            retry = subprocess.run([sys.executable, str(ROOT / 'install.py'), '--apply', '--home', str(home)],
                                   capture_output=True, text=True, timeout=20)
            self.assertEqual(retry.returncode, 0, retry.stderr)
            text = (claude / 'CLAUDE.md').read_text()
            self.assertIn('Existing user guidance.', text)
            self.assertEqual(text.count('<!-- agent-harness:start -->'), 1)
            self.assertEqual(text.count('<!-- agent-harness:end -->'), 1)
            settings = json.loads((claude / 'settings.json').read_text())
            self.assertEqual(settings['model'], 'sonnet')
            self.assertEqual(settings['env'], {'FIXTURE': 'keep'})
            self.assertEqual(sum('wal.py' in json.dumps(item) for item in settings['hooks']['PreToolUse']), 1)
            for source in (ROOT / 'harness/agents').iterdir():
                self.assertEqual((claude / 'agents' / source.name).read_bytes(), source.read_bytes())
            self.assertFalse(list(claude.rglob('.agent-harness-*')))

    def test_twelve_reviewers_racing_for_one_report_publish_exactly_once(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            repo = root / 'repo'
            repo.mkdir()
            packet = root / 'packet.md'
            packet.write_text('fixture')
            reports = root / 'reports'
            reports.mkdir()
            output = reports / 'report.txt'
            gate = root / 'go'
            code = (
                'import sys,time\nfrom pathlib import Path\n'
                'from report_file import ReportTarget\n'
                'output,repo,packet,gate,token=map(Path,sys.argv[1:])\n'
                'deadline=time.monotonic()+10\n'
                'while not gate.exists() and time.monotonic()<deadline: time.sleep(.005)\n'
                'if not gate.exists(): raise SystemExit(9)\n'
                'target=ReportTarget(output,repo,packet)\n'
                'try:\n'
                '    target.require_fresh()\n'
                '    target.write_text(token.name)\n'
                '    target.verify_current()\n'
                '    print(token.name)\n'
                'except (FileExistsError,ValueError,OSError):\n'
                '    raise SystemExit(3)\n'
                'finally:\n'
                '    target.close()\n'
            )
            workers = []
            env = {**os.environ, 'PYTHONPATH': str(HOOKS)}
            try:
                for index in range(12):
                    workers.append(subprocess.Popen(
                        [sys.executable, '-c', code, str(output), str(repo), str(packet),
                         str(gate), str(root / f'writer-{index}')],
                        env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE))
                gate.touch()
                results = [(worker.communicate(timeout=15), worker.returncode) for worker in workers]
            finally:
                for worker in workers:
                    if worker.poll() is None:
                        worker.kill()
                        worker.communicate(timeout=5)
            winners = [(streams[0].strip(), code) for streams, code in results if code == 0]
            self.assertEqual(len(winners), 1, results)
            self.assertEqual(sorted(code for _, code in results), [0] + [3] * 11, results)
            self.assertEqual(output.read_text(), winners[0][0])
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
            self.assertEqual(list(reports.iterdir()), [output], 'no orphaned temporary reports')


if __name__ == '__main__':
    unittest.main()
