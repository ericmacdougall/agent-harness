"""End-to-end delivery phase controls in disposable repositories."""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


DELIVER = Path(__file__).resolve().parents[1] / 'harness/hooks/deliver.py'
CHECK = 'python3 -m unittest discover -s tests'


def command(*argv, cwd=None, env=None, check=True):
    result = subprocess.run(argv, cwd=cwd, env=env, text=True, capture_output=True, timeout=90)
    if check and result.returncode:
        raise AssertionError((argv, result.stdout, result.stderr))
    return result


class DeliveryWorkflow(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='harness-delivery-')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.home = self.root / 'home'
        self.home.mkdir()
        self.env = {**os.environ, 'HOME': str(self.home), 'GIT_CONFIG_GLOBAL': os.devnull,
                    'GIT_CONFIG_NOSYSTEM': '1'}
        for name in tuple(self.env):
            if name.startswith('GIT_') and name not in {'GIT_CONFIG_GLOBAL', 'GIT_CONFIG_NOSYSTEM'}:
                self.env.pop(name)
        self.env['PYTHONDONTWRITEBYTECODE'] = '1'
        self.original = self.root / 'original'
        command('git', 'init', '-q', '-b', 'main', str(self.original), env=self.env)
        command('git', 'config', 'user.name', 'Harness Test', cwd=self.original, env=self.env)
        command('git', 'config', 'user.email', 'test@example.invalid', cwd=self.original, env=self.env)
        (self.original / 'app.txt').write_text('base\n')
        command('git', 'add', 'app.txt', cwd=self.original, env=self.env)
        command('git', 'commit', '-qm', 'base', cwd=self.original, env=self.env)
        self.base = command('git', 'rev-parse', 'HEAD', cwd=self.original, env=self.env).stdout.strip()
        self.source = self.root / 'source'
        command('git', 'worktree', 'add', '-qb', 'codex/feature', str(self.source), cwd=self.original, env=self.env)
        tests = self.source / 'tests'
        tests.mkdir()
        (tests / 'test_change.py').write_text('import unittest\n'
                                               'class Change(unittest.TestCase):\n'
                                               '    def test_value(self):\n'
                                               '        self.assertEqual(2 + 2, 4)\n')
        (self.source / 'app.txt').write_text('feature\n')
        command('git', 'add', 'app.txt', 'tests', cwd=self.source, env=self.env)
        command('git', 'commit', '-qm', 'feature', cwd=self.source, env=self.env)
        self.head = command('git', 'rev-parse', 'HEAD', cwd=self.source, env=self.env).stdout.strip()
        self.remote = self.root / 'remote.git'
        command('git', 'init', '-q', '--bare', str(self.remote), env=self.env)
        command('git', 'remote', 'add', 'origin', str(self.remote), cwd=self.original, env=self.env)
        command('git', 'push', '-q', 'origin', 'main:main', cwd=self.original, env=self.env)
        command('git', 'symbolic-ref', 'HEAD', 'refs/heads/main', cwd=self.remote, env=self.env)
        wal_dir = self.home / '.claude' / 'wals' / 'fixture-session'
        wal_dir.mkdir(parents=True, mode=0o700)
        self.wal = wal_dir / 'main.jsonl'
        self.wal.write_text('{}\n')
        self.wal.chmod(0o600)
        self.kit = self.root / 'kit.json'
        self.kit.write_text(json.dumps({'run': 'python3 app.py', 'test': CHECK,
                                        'watch': 'watch-tests -- python3 -m unittest discover -s tests'}))
        self.kit.chmod(0o600)
        self.body = self.root / 'pr-body.md'
        self.body.write_text('Reviewed feature scope and test result.\n')
        self.body.chmod(0o600)

    def invoke(self, *args):
        result = command(sys.executable, str(DELIVER), *args, env=self.env, check=False)
        self.assertTrue(result.stdout, result.stderr)
        return result, json.loads(result.stdout)

    def prepare_args(self):
        return ('prepare', '--wal', str(self.wal), '--task', 'fixture',
                '--source', str(self.source), '--original', str(self.original),
                '--original-branch', 'main', '--expected-source-head', self.head,
                '--expected-original-head', self.base, '--pr-title', 'Feature fixture',
                '--pr-body-file', str(self.body), '--kit-file', str(self.kit))

    def test_unsupported_origin_is_rejected_before_any_publication(self):
        prepared, prep = self.invoke(*self.prepare_args())
        pushed = command('git', 'show-ref', '--verify', 'refs/heads/codex/feature',
                         cwd=self.remote, env=self.env, check=False).returncode == 0
        self.assertEqual((prepared.returncode, prep['status'], pushed),
                         (2, 'BLOCKED_POLICY', False), prepared.stdout + prepared.stderr)
        self.assertEqual(command('git', 'rev-parse', 'HEAD', cwd=self.original,
                                 env=self.env).stdout.strip(), self.base)


if __name__ == '__main__':
    unittest.main()
