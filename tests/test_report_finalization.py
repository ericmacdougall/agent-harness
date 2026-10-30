"""Deterministic filesystem races after publication, without model/network calls."""
import contextlib
import importlib.util
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

HOOKS = Path(__file__).resolve().parents[1] / 'harness/hooks'
sys.path.insert(0, str(HOOKS))


def load(name):
    spec = importlib.util.spec_from_file_location(name + '_finalization', HOOKS / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ReportFinalizationTests(unittest.TestCase):
    def exercise(self, helper, phase, mutation):
        module = load(helper)
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            repo = root / 'repo'
            repo.mkdir()

            def git(*args):
                return subprocess.run(['git', '-C', str(repo), *args], check=True,
                                      capture_output=True, text=True).stdout.strip()

            git('init', '-q', '-b', 'feat/fixture')
            git('config', 'user.name', 'Fixture')
            git('config', 'user.email', 'fixture@example.invalid')
            (repo / 'app.txt').write_text('before')
            git('add', 'app.txt')
            git('commit', '-qm', 'baseline')
            base = git('rev-parse', 'HEAD')
            packet = root / 'packet.md'
            packet.write_text('Fixture scope')
            reports = root / 'reports'
            reports.mkdir(mode=0o700)
            output = reports / 'report.txt'
            replacement = root / 'replacement.txt'
            replacement.write_text('unrelated replacement')
            fired = []
            events = []
            original_unlink = os.unlink

            def mutate():
                self.assertTrue(output.is_file(), 'race must occur after publication')
                fired.append(True)
                if mutation == 'directory':
                    reports.rename(root / 'moved')
                    reports.mkdir(mode=0o700)
                    output.write_text('unrelated replacement')
                else:
                    output.rename(root / 'original-report')
                    if mutation == 'file':
                        output.write_text('unrelated replacement')
                    elif mutation == 'symlink':
                        output.symlink_to(replacement)

            def unlink(path, *args, **kwargs):
                self.assertNotEqual(path, output.name, 'never unlink public destination')
                result = original_unlink(path, *args, **kwargs)
                if str(path).startswith('.report-') and not fired:
                    mutate()
                return result

            def append(wal, record):
                events.append(record['event'])
                if record['event'] == 'rescue_result':
                    if mutation == 'error':
                        raise OSError('fixture WAL failure')
                    mutate()

            def model(*args):
                if helper == 'rescue':
                    (repo / 'app.txt').write_text('after')
                return 0, 'VERDICT: PASS\nFixture handoff', ''

            argv = [helper, *(['pr'] if helper == 'peer_review' else []),
                    '--repo', str(repo), '--packet', str(packet), '--output', str(output)]
            if phase == 'wal':
                argv += ['--wal', str(root / 'fixture-wal')]
            stdout, stderr = io.StringIO(), io.StringIO()
            with contextlib.ExitStack() as stack:
                stack.enter_context(patch.object(sys, 'argv', argv))
                stack.enter_context(patch.object(module.shutil, 'which', return_value='fixture-model'))
                stack.enter_context(patch.object(module, 'run', side_effect=model))
                stack.enter_context(contextlib.redirect_stdout(stdout))
                stack.enter_context(contextlib.redirect_stderr(stderr))
                if phase == 'cleanup':
                    stack.enter_context(patch.object(os, 'unlink', side_effect=unlink))
                else:
                    stack.enter_context(patch.object(module, 'append_wal', side_effect=append))
                code = module.main()
            if mutation != 'error':
                self.assertEqual(fired, [True])
                if mutation == 'missing':
                    self.assertFalse(output.exists())
                else:
                    self.assertEqual(output.read_text(), 'unrelated replacement')
                self.assertEqual(replacement.read_text(), 'unrelated replacement')
            if phase == 'wal':
                self.assertEqual(events, ['rescue_start', 'rescue_result'])
            if helper == 'rescue':
                self.assertNotEqual(git('rev-parse', 'HEAD'), base)
                self.assertEqual(git('status', '--porcelain'), '')
                self.assertEqual((repo / 'app.txt').read_text(), 'after')
            self.assertEqual(code, 2 if helper == 'peer_review' else 3, stdout.getvalue())
            self.assertEqual(stdout.getvalue(), '', 'must not announce PASS or report success')
            self.assertNotIn('Traceback', stderr.getvalue())
            if helper == 'rescue':
                self.assertIn('inspect the worktree', stderr.getvalue())

    def test_writer_checks_after_cleanup(self):
        module = load('report_file')
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            reports = root / 'reports'
            reports.mkdir()
            output = reports / 'report.txt'
            target = module.ReportTarget(output, root / 'repo', root / 'packet')
            original_unlink = os.unlink

            def unlink(path, *args, **kwargs):
                self.assertTrue(str(path).startswith('.report-'))
                original_unlink(path, *args, **kwargs)
                reports.rename(root / 'moved')
                reports.mkdir()
                output.write_text('replacement')

            try:
                with patch.object(os, 'unlink', side_effect=unlink):
                    with self.assertRaises(OSError):
                        target.write_text('report')
                self.assertEqual(output.read_text(), 'replacement')
                self.assertEqual((root / 'moved/report.txt').read_text(), 'report')
            finally:
                target.close()

    def test_review_cleanup_races(self):
        for mutation in ('directory', 'file', 'symlink', 'missing'):
            with self.subTest(mutation=mutation):
                self.exercise('peer_review', 'cleanup', mutation)

    def test_rescue_cleanup_races(self):
        for mutation in ('directory', 'file', 'symlink', 'missing'):
            with self.subTest(mutation=mutation):
                self.exercise('rescue', 'cleanup', mutation)

    def test_rescue_wal_races(self):
        for mutation in ('directory', 'file', 'symlink', 'missing', 'error'):
            with self.subTest(mutation=mutation):
                self.exercise('rescue', 'wal', mutation)
