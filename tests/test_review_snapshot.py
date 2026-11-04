"""Review snapshots copy only the reviewed commit and keep their isolation checks."""

import importlib.util
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


REVIEW = Path(__file__).resolve().parents[1] / 'harness/hooks/peer_review.py'


def load_review():
    sys.path.insert(0, str(REVIEW.parent))
    try:
        spec = importlib.util.spec_from_file_location('peer_review_snapshot_test', REVIEW)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module
    finally:
        sys.path.remove(str(REVIEW.parent))


def git(repo, *args):
    return subprocess.run(['git', '-C', str(repo), *args], check=True, capture_output=True,
                          text=True).stdout.strip()


class ReviewSnapshotTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.review = load_review()

    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.repo = self.root / 'repo'
        subprocess.run(['git', 'init', '-q', '-b', 'main', str(self.repo)], check=True)
        git(self.repo, 'config', 'user.name', 'Fixture')
        git(self.repo, 'config', 'user.email', 'fixture@example.invalid')
        (self.repo / 'app.txt').write_text('first\n')
        # Old history carries a blob that the reviewed tree no longer contains.
        (self.repo / 'history.bin').write_bytes(os.urandom(64 * 1024))
        git(self.repo, 'add', '.')
        git(self.repo, 'commit', '-qm', 'first')
        self.first = git(self.repo, 'rev-parse', 'HEAD')
        self.history_blob = git(self.repo, 'rev-parse', 'HEAD:history.bin')
        git(self.repo, 'rm', '-q', 'history.bin')
        git(self.repo, 'commit', '-qm', 'drop history blob')
        self.middle = git(self.repo, 'rev-parse', 'HEAD')
        (self.repo / 'app.txt').write_text('reviewed\n')
        git(self.repo, 'commit', '-qam', 'reviewed change')
        self.head = git(self.repo, 'rev-parse', 'HEAD')
        self.snapshot = self.root / 'snapshot'

    def has_object(self, object_id):
        return subprocess.run(['git', '-C', str(self.snapshot), 'cat-file', '-e', object_id],
                              capture_output=True).returncode == 0

    def test_snapshot_copies_only_the_reviewed_commit(self):
        self.review.make_snapshot(self.repo, self.snapshot, self.head)
        self.assertEqual(git(self.snapshot, 'rev-parse', 'HEAD'), self.head)
        self.assertEqual(git(self.snapshot, 'rev-parse', 'HEAD^{tree}'),
                         git(self.repo, 'rev-parse', 'HEAD^{tree}'))
        self.assertEqual((self.snapshot / 'app.txt').read_text(), 'reviewed\n')
        self.assertTrue(self.has_object(self.head))
        self.assertFalse(self.has_object(self.history_blob), 'old history was copied')
        self.assertFalse(self.has_object(self.middle), 'parent commit was copied')
        self.assertEqual((self.snapshot / '.git/shallow').read_text().split(), [self.head])

    def test_base_is_copied_for_diffs_without_intermediate_history(self):
        self.review.make_snapshot(self.repo, self.snapshot, self.head, base=self.first)
        self.assertTrue(self.has_object(self.first))
        self.assertFalse(self.has_object(self.middle))
        self.assertEqual(git(self.snapshot, 'diff', '--name-only', self.first, 'HEAD').split(),
                         ['app.txt', 'history.bin'])

    def test_base_must_be_a_full_present_ancestor(self):
        git(self.repo, 'checkout', '-q', '-b', 'side', self.first)
        (self.repo / 'side.txt').write_text('side\n')
        git(self.repo, 'add', 'side.txt')
        git(self.repo, 'commit', '-qm', 'side')
        side = git(self.repo, 'rev-parse', 'HEAD')
        git(self.repo, 'checkout', '-q', 'main')
        cases = {'unrelated': (side, 'ancestor'), 'short': (self.first[:12], 'full'),
                 'missing': ('0' * 40, 'not present'), 'uppercase': (self.first.upper(), 'full')}
        for name, (base, message) in cases.items():
            with self.subTest(name):
                with self.assertRaisesRegex(OSError, message):
                    self.review.make_snapshot(self.repo, self.snapshot, self.head, base=base)
                self.assertFalse(self.snapshot.exists())

    def test_unsafe_sources_are_refused_before_any_snapshot(self):
        git_dir = self.repo / '.git'
        cases = {
            'grafts': (lambda: (git_dir / 'info').mkdir(exist_ok=True)
                       or (git_dir / 'info/grafts').write_text(self.head + '\n'),
                       lambda: (git_dir / 'info/grafts').unlink()),
            'alternates': (lambda: (git_dir / 'objects/info/alternates').write_text(str(self.root) + '\n'),
                           lambda: (git_dir / 'objects/info/alternates').unlink()),
            'shallow': (lambda: (git_dir / 'shallow').write_text(self.first + '\n'),
                        lambda: (git_dir / 'shallow').unlink()),
            'partial': (lambda: git(self.repo, 'config', 'remote.origin.promisor', 'true'),
                        lambda: git(self.repo, 'config', '--unset', 'remote.origin.promisor')),
        }
        for name, (apply, undo) in cases.items():
            with self.subTest(name):
                apply()
                try:
                    with self.assertRaisesRegex(OSError, 'unsupported for review'):
                        self.review.make_snapshot(self.repo, self.snapshot, self.head)
                finally:
                    undo()
                self.assertFalse(self.snapshot.exists())
        self.review.make_snapshot(self.repo, self.snapshot, self.head)

    def test_replace_objects_cannot_substitute_reviewed_content(self):
        (self.repo / 'app.txt').write_text('substitute\n')
        substitute = git(self.repo, 'hash-object', '-w', 'app.txt')
        git(self.repo, 'checkout', '-q', '--', 'app.txt')
        git(self.repo, 'replace', git(self.repo, 'rev-parse', 'HEAD:app.txt'), substitute)
        self.review.make_snapshot(self.repo, self.snapshot, self.head)
        self.assertEqual((self.snapshot / 'app.txt').read_text(), 'reviewed\n')

    def test_snapshot_timeout_bounds_slow_operations_and_reports_option(self):
        seen = []
        real = self.review.run_process

        def record(command, **kwargs):
            if 'fetch' in command or 'checkout' in command:
                seen.append(kwargs['timeout'])
            return real(command, **kwargs)
        with patch.object(self.review, 'run_process', side_effect=record):
            self.review.make_snapshot(self.repo, self.snapshot, self.head, timeout=4000)
        self.assertTrue(seen)
        for timeout in seen:
            self.assertGreater(timeout, 3000)
            self.assertLessEqual(timeout, 4000)

        def slow_fetch(command, **kwargs):
            if 'fetch' in command:
                raise subprocess.TimeoutExpired(command, kwargs['timeout'])
            return real(command, **kwargs)
        with patch.object(self.review, 'run_process', side_effect=slow_fetch):
            with self.assertRaisesRegex(OSError, r'--snapshot-timeout of 5 seconds'):
                self.review.make_snapshot(self.repo, self.root / 'slow', self.head, timeout=5)

    def test_snapshot_rejects_tree_or_boundary_mismatch(self):
        real = self.review.run_process

        def wrong_tree(command, **kwargs):
            result = real(command, **kwargs)
            if command[2] == str(self.repo) and command[-1] == self.head + '^{tree}':
                result = subprocess.CompletedProcess(command, 0, '0' * 40 + '\n', '')
            return result
        with patch.object(self.review, 'run_process', side_effect=wrong_tree):
            with self.assertRaisesRegex(OSError, 'does not match reviewed commit'):
                self.review.make_snapshot(self.repo, self.snapshot, self.head)

        def extra_boundary(command, **kwargs):
            result = real(command, **kwargs)
            if 'fetch' in command:
                with open(Path(command[2]) / '.git/shallow', 'a') as stream:
                    stream.write(self.middle + '\n')
            return result
        with patch.object(self.review, 'run_process', side_effect=extra_boundary):
            with self.assertRaisesRegex(OSError, 'history boundary'):
                self.review.make_snapshot(self.repo, self.root / 'boundary', self.head)

    def test_reviewer_prompt_describes_snapshot_history(self):
        prompts = []

        def provider(cmd, prompt, cwd, timeout):
            prompts.append(prompt)
            Path(cmd[cmd.index('--output-last-message') + 1]).write_text('PLAN_RESULT: ACCEPT\nok')
            return 0, '', ''
        with patch.object(self.review.shutil, 'which', return_value='/bin/true'), \
                patch.object(self.review, 'run', side_effect=provider):
            self.review.review_snapshot(self.root, self.head, 'plan', 'rules', 'packet', {})
            self.review.review_snapshot(self.root, self.head, 'plan', 'rules', 'packet', {'base': self.first})
        self.assertIn('only the reviewed commit (depth 1)', prompts[0])
        self.assertIn(f'git diff {self.first} HEAD', prompts[1])

    def test_cli_validates_snapshot_options(self):
        for args, message in ((['--snapshot-timeout', '7201'], 'snapshot-timeout must be between'),
                              (['--snapshot-timeout', '0'], 'snapshot-timeout must be between'),
                              (['--base', 'HEAD~1'], 'base must be a full commit SHA')):
            with self.subTest(args):
                result = subprocess.run([sys.executable, str(REVIEW), 'plan', '--repo', str(self.repo),
                                         '--packet', str(self.root / 'packet.md'),
                                         '--output', str(self.root / 'out.md'), *args],
                                        capture_output=True, text=True, timeout=60)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn(message, result.stderr)


if __name__ == '__main__':
    unittest.main()
