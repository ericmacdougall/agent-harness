"""Real small Git controls for sparse admission, never a user checkout."""
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'harness/hooks'))
import git_safety
from git_safety import git_environment, require_safe_source


class SparseSafety(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name).resolve()
        self.env = git_environment(isolated=True)
        self.git('init', '-q')
        self.git('config', 'user.name', 'Fixture')
        self.git('config', 'user.email', 'fixture@example.invalid')
        for name in ('keep/app.txt', 'omit/data.txt', 'root.txt'):
            path = self.repo / name
            path.parent.mkdir(exist_ok=True)
            path.write_text('fixture\n')
        self.git('add', '.')
        self.git('commit', '-qm', 'fixture')

    def git(self, *args):
        return subprocess.run(['git', '-C', str(self.repo), *args], env=self.env,
                              check=True, capture_output=True).stdout

    def sparse(self, cone=False):
        self.git('sparse-checkout', 'set', '--cone' if cone else '--no-cone',
                 'keep' if cone else '/keep/')

    def guard(self):
        return require_safe_source(self.repo, self.env, timeout=5)

    def test_noncone_real_partition_admitted(self):
        self.sparse()
        self.assertIn(b'S omit/data.txt\0', self.git('ls-files', '-v', '-z'))
        self.assertFalse((self.repo / 'omit').exists())
        self.guard()

    def test_cone_real_partition_admitted(self):
        self.sparse(True)
        self.guard()

    def test_manual_hidden_included_refused(self):
        self.sparse()
        self.git('update-index', '--skip-worktree', 'keep/app.txt')
        (self.repo / 'keep/app.txt').unlink()
        with self.assertRaises(OSError): self.guard()

    def test_assume_unchanged_refused(self):
        self.sparse()
        self.git('update-index', '--assume-unchanged', 'keep/app.txt')
        with self.assertRaises(OSError): self.guard()

    def test_present_omission_refused(self):
        self.sparse()
        path = self.repo / 'omit/data.txt'
        path.parent.mkdir()
        path.write_text('private sentinel')
        with self.assertRaises(OSError): self.guard()
        self.assertEqual(path.read_text(), 'private sentinel')

    def test_symlink_ancestor_refused(self):
        self.sparse()
        (self.repo / 'omit').symlink_to(self.repo / 'keep', target_is_directory=True)
        with self.assertRaises(OSError): self.guard()

    def test_unsupported_pattern_refused(self):
        self.sparse()
        rules = Path(self.git('rev-parse', '--git-path', 'info/sparse-checkout').decode().strip())
        if not rules.is_absolute(): rules = self.repo / rules
        rules.write_text('/keep/\n!/keep/private\n')
        with self.assertRaises(OSError): self.guard()

    def test_ordinary_fingerprint_distinguishes_sparse(self):
        ordinary = self.guard()
        self.sparse()
        sparse = self.guard()
        self.assertNotEqual(ordinary, sparse)

    def test_nested_cone_canonical(self):
        self.git('sparse-checkout', 'set', '--cone', 'keep/nested', 'other/deep')
        self.guard()

    def test_actual_positive_wildcard_subset(self):
        self.git('sparse-checkout', 'set', '--no-cone', '/keep/*.txt', '/root.txt', '/keep/*.txt')
        self.guard()

    def test_invalid_boolean_refused(self):
        self.sparse()
        self.git('config', 'core.sparseCheckoutCone', 'maybe')
        with self.assertRaises(OSError): self.guard()

    def test_sparse_directory_index_refused(self):
        self.git('sparse-checkout', 'set', '--cone', '--sparse-index', 'keep')
        with self.assertRaises(OSError): self.guard()

    def test_local_filter_refused(self):
        self.sparse()
        self.git('config', 'filter.fixture.clean', 'false')
        with self.assertRaises(OSError): self.guard()

    def test_rules_change_during_matching_refused(self):
        self.sparse()
        real = git_safety._bounded_git
        def changed(repo, args, env, **kwargs):
            result = real(repo, args, env, **kwargs)
            if args[:2] == ['sparse-checkout', 'check-rules']:
                rules = self.repo / '.git/info/sparse-checkout'
                rules.write_bytes(rules.read_bytes() + b'/new-file\n')
            return result
        with mock.patch.object(git_safety, '_bounded_git', changed), self.assertRaises(OSError):
            self.guard()

    def test_index_change_during_matching_refused(self):
        self.sparse()
        real = git_safety._bounded_git
        def changed(repo, args, env, **kwargs):
            result = real(repo, args, env, **kwargs)
            if args[:2] == ['sparse-checkout', 'check-rules']:
                self.git('update-index', '--assume-unchanged', 'keep/app.txt')
            return result
        with mock.patch.object(git_safety, '_bounded_git', changed), self.assertRaises(OSError):
            self.guard()

    def test_sparse_settings_drift_refused(self):
        self.git('config', 'core.ignoreCase', 'false')
        self.sparse()
        real = git_safety._bounded_git
        def changed(repo, args, env, **kwargs):
            result = real(repo, args, env, **kwargs)
            if args[:2] == ['sparse-checkout', 'check-rules']:
                self.git('config', 'core.ignoreCase', 'true')
            return result
        with mock.patch.object(git_safety, '_bounded_git', changed), self.assertRaises(OSError):
            self.guard()

    def test_matcher_duplicate_or_truncated_output_refused(self):
        self.sparse()
        real = git_safety._bounded_git
        for output in (b'keep/app.txt\0keep/app.txt\0', b'keep/app.txt', b'foreign\0'):
            def changed(repo, args, env, **kwargs):
                if args[:2] == ['sparse-checkout', 'check-rules']: return 0, output
                return real(repo, args, env, **kwargs)
            with self.subTest(output=output), mock.patch.object(git_safety, '_bounded_git', changed), self.assertRaises(OSError):
                self.guard()

    def test_case_matching_agrees_with_git(self):
        self.git('config', 'core.ignoreCase', 'true')
        self.git('sparse-checkout', 'set', '--no-cone', '/KEEP/')
        self.guard()

    def test_skipped_lowercase_assume_unchanged_refused(self):
        self.sparse()
        self.git('update-index', '--assume-unchanged', 'omit/data.txt')
        with self.assertRaises(OSError): self.guard()

    def test_rules_symlink_refused(self):
        self.sparse()
        path = self.repo / '.git/info/sparse-checkout'
        content = path.read_bytes()
        path.unlink()
        target = self.repo / 'private-rules'
        target.write_bytes(content)
        path.symlink_to(target)
        with self.assertRaises(OSError): self.guard()

    def test_metadata_stderr_warning_refused(self):
        with self.assertRaises(OSError):
            git_safety._bounded_git(self.repo, ['not-a-real-command'], self.env,
                                   timeout=2, limit=1024, reject_stderr=True)

    def test_sparse_inspection_shared_deadline_refused(self):
        self.sparse()
        with self.assertRaises(OSError):
            require_safe_source(self.repo, self.env, timeout=0)

    def test_unreadable_ancestor_refused(self):
        if os.geteuid() == 0: self.skipTest('permission denial requires non-root fixture')
        self.sparse()
        path = self.repo / 'omit'
        path.mkdir(mode=0o700)
        self.addCleanup(path.chmod, 0o700)
        path.chmod(0)
        with self.assertRaises(OSError): self.guard()

    def test_gitlink_still_refused(self):
        self.sparse()
        head = self.git('rev-parse', 'HEAD').strip().decode()
        self.git('update-index', '--add', '--cacheinfo', '160000,' + head + ',nested')
        with self.assertRaises(OSError): self.guard()

    def test_present_skipped_directory_refused(self):
        self.sparse()
        path = self.repo / 'omit/data.txt'
        path.mkdir(parents=True)
        with self.assertRaises(OSError): self.guard()


if __name__ == '__main__': unittest.main()
