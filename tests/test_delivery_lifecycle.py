"""Real disposable delivery and explicit recovery lifecycle controls."""

import importlib.util
import json
import os
import sys
import unittest
from pathlib import Path
from unittest import mock

import test_scratch_recovery as fixtures


class DeliveryLifecycle(unittest.TestCase):
    setUp = fixtures.ScratchRecovery.setUp
    head = fixtures.ScratchRecovery.head
    invoke = fixtures.ScratchRecovery.invoke

    def commit_feature(self, text, *, test=None):
        (self.feature / 'app.txt').write_text(text)
        if test is not None:
            (self.feature / 'tests/test_ok.py').write_text(test)
        fixtures.command('git', 'add', 'app.txt', 'tests/test_ok.py', cwd=self.feature, env=self.env)
        fixtures.command('git', 'commit', '-qm', 'next feature', cwd=self.feature, env=self.env)
        self.feature_head = self.head(self.feature)

    def resolve(self, key, *, expected=None, env=None):
        result = fixtures.command(sys.executable, str(fixtures.INTEGRATE),
                                  '--repo', str(self.original), '--original-branch', 'main',
                                  '--expected-head', expected or self.head(self.original),
                                  '--resolve-journal', key, '--check', fixtures.CHECK,
                                  env=self.env if env is None else env, check=False)
        return result, json.loads(result.stdout) if result.stdout else {}

    def test_scratch_check_runs_outside_vcs_path_components(self):
        self.commit_feature('feature\n', test=
            'import unittest\nfrom pathlib import Path\nclass Check(unittest.TestCase):\n'
            ' def test_visible_worktree(self):\n'
            '  self.assertFalse(set(Path.cwd().parts) & {".git", ".hg", ".sl"})\n')
        result, data = self.invoke()
        self.assertEqual((result.returncode, data['status']), (0, 'INTEGRATED'), result.stdout)

    def test_natural_cleanup_does_not_block_next_feature(self):
        fixtures.command('git', 'config', 'core.hooksPath', '/dev/null', cwd=self.original, env=self.env)
        (self.feature / '.gitignore').write_text('scratch-result.tmp\n')
        self.commit_feature('feature\n', test=
            'import unittest\nfrom pathlib import Path\nclass Check(unittest.TestCase):\n'
            ' def test_artifact(self):\n'
            '  self.assertTrue(Path("app.txt").exists())\n'
            f'  if Path.cwd().resolve()!=Path({str(self.original)!r}).resolve():\n'
            '   Path("scratch-result.tmp").write_text("retain")\n')
        fixtures.command('git', 'add', '.gitignore', cwd=self.feature, env=self.env)
        fixtures.command('git', 'commit', '-qm', 'ignore artifact', cwd=self.feature, env=self.env)
        self.feature_head = self.head(self.feature)
        result, data = self.invoke()
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertTrue(data['cleanup_pending'])
        record = json.loads(Path(data['journal']).read_text())
        scratch = Path(record['scratch'])
        (scratch / 'scratch-result.tmp').unlink()
        fixtures.command('git', 'worktree', 'remove', str(scratch), cwd=self.original, env=self.env)
        fixtures.command('git', 'update-ref', '-d', record['ref'], data['head'], cwd=self.original, env=self.env)
        repeat, repeated = self.invoke()
        self.assertEqual((repeat.returncode, repeated['status']), (0, 'ALREADY_INTEGRATED'), repeat.stdout)
        self.assertFalse(repeated['cleanup_pending'])
        self.base = self.head(self.original)
        self.commit_feature('next feature\n')
        next_result, next_data = self.invoke()
        self.assertEqual((next_result.returncode, next_data['status']), (0, 'INTEGRATED'), next_result.stdout)

    def test_resolve_preapply_failure_preserves_artifacts_and_allows_corrected_feature(self):
        self.commit_feature('feature\n', test='import unittest\nclass Check(unittest.TestCase):\n def test_fail(self): self.fail("control")\n')
        failed, data = self.invoke()
        self.assertEqual(failed.returncode, 3, failed.stdout)
        self.assertEqual(self.head(self.original), self.base)
        journal = Path(data['journal'])
        before = json.loads(journal.read_text())
        resolved, resolution = self.resolve(before['key'])
        self.assertEqual((resolved.returncode, resolution.get('status')), (0, 'RESOLVED'), resolved.stdout + resolved.stderr)
        self.assertTrue(Path(before['scratch']).exists(), 'resolver deleted retained scratch')
        self.assertEqual(self.head(self.original), self.base)
        self.commit_feature('corrected\n', test='import unittest\nclass Check(unittest.TestCase):\n def test_ok(self): self.assertEqual(2+2,4)\n')
        fixed, fixed_data = self.invoke()
        self.assertEqual((fixed.returncode, fixed_data['status']), (0, 'INTEGRATED'), fixed.stdout)

    def test_resolver_rejects_wrong_head_and_wrong_scope_without_retiring(self):
        self.commit_feature('feature\n', test='import unittest\nclass Check(unittest.TestCase):\n def test_fail(self): self.fail("control")\n')
        _, data = self.invoke()
        journal = Path(data['journal'])
        record = json.loads(journal.read_text())
        result, _ = self.resolve(record['key'], expected=self.feature_head)
        self.assertNotEqual(result.returncode, 0)
        self.assertNotEqual(json.loads(journal.read_text())['phase'], 'resolved')


if __name__ == '__main__':
    unittest.main()
