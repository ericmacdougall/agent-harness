import json
import subprocess
import tempfile
import unittest
from pathlib import Path


PUBLISH = Path(__file__).resolve().parents[1] / 'harness/hooks/publish_feature.py'
INTEGRATE = Path(__file__).resolve().parents[1] / 'harness/hooks/integrate_local.py'


def cmd(*args, cwd=None, check=True):
    p = subprocess.run(args, cwd=cwd, text=True, capture_output=True)
    if check and p.returncode:
        raise AssertionError(f'{args}: {p.stdout}\n{p.stderr}')
    return p


class DeliveryHelpers(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / 'repo'
        self.repo.mkdir()
        cmd('git', 'init', '-q', '-b', 'main', str(self.repo))
        cmd('git', 'config', 'user.email', 'test@example.invalid', cwd=self.repo)
        cmd('git', 'config', 'user.name', 'Harness test', cwd=self.repo)
        (self.repo / 'app.txt').write_text('base\n')
        cmd('git', 'add', 'app.txt', cwd=self.repo)
        cmd('git', 'commit', '-qm', 'base', cwd=self.repo)
        self.base = cmd('git', 'rev-parse', 'HEAD', cwd=self.repo).stdout.strip()
        self.feature = self.root / 'feature'
        cmd('git', 'worktree', 'add', '-qb', 'feat/app', str(self.feature), cwd=self.repo)
        (self.feature / 'app.txt').write_text('feature\n')
        cmd('git', 'commit', '-qam', 'feature', cwd=self.feature)
        self.feature_head = cmd('git', 'rev-parse', 'HEAD', cwd=self.feature).stdout.strip()

    def invoke(self, helper, *args):
        p = cmd('python3', str(helper), *args, check=False)
        return p, json.loads(p.stdout)

    def test_publish_success_and_protected_branch(self):
        remote = self.root / 'origin.git'
        cmd('git', 'init', '-q', '--bare', str(remote))
        cmd('git', 'remote', 'add', 'origin', str(remote), cwd=self.repo)
        p, data = self.invoke(PUBLISH, '--repo', str(self.feature), '--branch', 'feat/app', '--original-branch', 'main', '--expected-head', self.feature_head)
        self.assertEqual((p.returncode, data['status']), (0, 'PUSHED'))
        self.assertEqual(cmd('git', 'show-ref', '--verify', 'refs/heads/feat/app', cwd=remote).returncode, 0)
        self.assertNotEqual(cmd('git', 'show-ref', '--verify', 'refs/heads/main', cwd=remote, check=False).returncode, 0)
        p, data = self.invoke(PUBLISH, '--repo', str(self.repo), '--branch', 'main', '--original-branch', 'main', '--expected-head', self.base)
        self.assertEqual((p.returncode, data['status']), (2, 'BLOCKED_POLICY'))

    def test_failed_check_restores_original(self):
        tests = self.feature / 'tests'
        tests.mkdir()
        (tests / 'test_failure.py').write_text('import unittest\nclass Failure(unittest.TestCase):\n    def test_fails(self):\n        self.fail("intentional")\n')
        cmd('git', 'add', 'tests/test_failure.py', cwd=self.feature)
        cmd('git', 'commit', '-qm', 'add failing control', cwd=self.feature)
        self.feature_head = cmd('git', 'rev-parse', 'HEAD', cwd=self.feature).stdout.strip()
        p, data = self.invoke(INTEGRATE, '--repo', str(self.repo), '--original-branch', 'main', '--expected-head', self.base,
                              '--source', 'feat/app', '--expected-source-head', self.feature_head, '--check', 'python3 -m unittest discover -s tests -v')
        self.assertEqual((p.returncode, data['status']), (3, 'BLOCKED_LOCAL'))
        self.assertEqual(cmd('git', 'rev-parse', 'HEAD', cwd=self.repo).stdout.strip(), self.base)
        self.assertFalse(cmd('git', 'status', '--porcelain', cwd=self.repo).stdout.strip())

    def test_conflict_restores_original(self):
        (self.repo / 'app.txt').write_text('main divergent\n')
        cmd('git', 'commit', '-qam', 'diverge', cwd=self.repo)
        head = cmd('git', 'rev-parse', 'HEAD', cwd=self.repo).stdout.strip()
        p, data = self.invoke(INTEGRATE, '--repo', str(self.repo), '--original-branch', 'main', '--expected-head', head,
                              '--source', 'feat/app', '--expected-source-head', self.feature_head, '--check', 'python3 -m unittest discover -s tests -v')
        self.assertEqual((p.returncode, data['status']), (3, 'BLOCKED_LOCAL'))
        self.assertEqual(cmd('git', 'rev-parse', 'HEAD', cwd=self.repo).stdout.strip(), head)
        self.assertFalse(cmd('git', 'status', '--porcelain', cwd=self.repo).stdout.strip())

    def test_stale_feature_and_unapproved_check_are_rejected(self):
        p, data = self.invoke(PUBLISH, '--repo', str(self.feature), '--branch', 'feat/app', '--original-branch', 'main', '--expected-head', self.base)
        self.assertEqual((p.returncode, data['status']), (2, 'BLOCKED_POLICY'))
        p, data = self.invoke(INTEGRATE, '--repo', str(self.repo), '--original-branch', 'main', '--expected-head', self.base,
                              '--source', 'feat/app', '--expected-source-head', self.base, '--check', 'python3 -m unittest discover -s tests -v')
        self.assertEqual((p.returncode, data['status']), (2, 'BLOCKED_POLICY'))
        p, data = self.invoke(INTEGRATE, '--repo', str(self.repo), '--original-branch', 'main', '--expected-head', self.base,
                              '--source', 'feat/app', '--expected-source-head', self.feature_head, '--check', 'python3 -c "print(1)"')
        self.assertEqual((p.returncode, data['status']), (2, 'BLOCKED_POLICY'))
        self.assertEqual(cmd('git', 'rev-parse', 'HEAD', cwd=self.repo).stdout.strip(), self.base)

    def test_dirty_original_is_preserved(self):
        local = self.repo / 'user-notes.txt'
        local.write_text('do not replace\n')
        p, data = self.invoke(INTEGRATE, '--repo', str(self.repo), '--original-branch', 'main', '--expected-head', self.base,
                              '--source', 'feat/app', '--expected-source-head', self.feature_head, '--check', 'python3 -m unittest discover -s tests -v')
        self.assertEqual((p.returncode, data['status']), (3, 'BLOCKED_LOCAL'))
        self.assertEqual(local.read_text(), 'do not replace\n')
        self.assertEqual(cmd('git', 'rev-parse', 'HEAD', cwd=self.repo).stdout.strip(), self.base)


if __name__ == '__main__':
    unittest.main()
