import importlib.util
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


REVIEW = Path(__file__).resolve().parents[1] / 'harness/hooks/peer_review.py'


class PeerReviewTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / 'repo'
        self.repo.mkdir()
        subprocess.run(['git', 'init', '-q', '-b', 'main', str(self.repo)], check=True)
        self.packet = self.root / 'packet.md'
        self.packet.write_text('Scope and evidence for a disposable review.')
        self.output = self.root / 'review.md'
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        self.fake('codex', '''import os, sys
from pathlib import Path
prompt = sys.stdin.read()
capture = os.environ.get('CAPTURE_CODEX_PROMPT')
if capture: Path(capture).write_text(prompt)
last = Path(sys.argv[sys.argv.index('--output-last-message') + 1])
last.write_text(os.environ.get('CODEX_VERDICT', 'VERDICT: PASS\\nReviewed.'))
race = os.environ.get('RACE_OUTPUT')
if race: Path(race).write_text('independent file created during review')
relocated = os.environ.get('RACE_DIRECTORY_OUTPUT')
if relocated:
    parent = Path(relocated).parent
    parent.rename(parent.with_name(parent.name + '-moved'))
    parent.mkdir()
    Path(relocated).write_text('VERDICT: PASS\\nstale path')
sys.exit(int(os.environ.get('CODEX_EXIT', '0')))
''')
        self.fake('claude', '''import os, sys
from pathlib import Path
prompt = sys.stdin.read()
capture = os.environ.get('CAPTURE_CLAUDE_PROMPT')
if capture: Path(capture).write_text(prompt)
print(os.environ.get('CLAUDE_VERDICT', 'VERDICT: PASS\\nFallback reviewed.'))
sys.exit(int(os.environ.get('CLAUDE_EXIT', '0')))
''')

    def fake(self, name, body):
        path = self.bin / name
        path.write_text(f'#!{sys.executable}\n{body}')
        path.chmod(0o700)

    def invoke(self, *, packet=None, output=None, env=None):
        environment = {**os.environ, 'PATH': str(self.bin) + os.pathsep + '/usr/bin:/bin', **(env or {})}
        return subprocess.run([sys.executable, str(REVIEW), 'pr', '--repo', str(self.repo),
                               '--packet', str(packet or self.packet), '--output', str(output or self.output)],
                              text=True, capture_output=True, env=environment, timeout=15)

    def test_valid_sol_pass_is_private_and_identified(self):
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('Reviewer: Codex gpt-6.1-sol', self.output.read_text())
        self.assertIn('VERDICT: PASS', self.output.read_text())
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o600)

    def test_block_verdict_is_not_signoff(self):
        result = self.invoke(env={'CODEX_VERDICT': 'VERDICT: BLOCK\nMissing proof.'})
        self.assertEqual(result.returncode, 3, result.stdout)
        self.assertIn('VERDICT: BLOCK', self.output.read_text())

    def test_invalid_sol_result_uses_blind_opus_fallback(self):
        captured = self.root / 'fallback-prompt.txt'
        result = self.invoke(env={'CODEX_VERDICT': 'VERDICT: MAYBE\nUntrusted prior opinion.',
                                  'CAPTURE_CLAUDE_PROMPT': str(captured)})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('Reviewer: Blind Claude Opus fallback', self.output.read_text())
        self.assertNotIn('Untrusted prior opinion', captured.read_text())

    def test_existing_report_is_preserved_and_review_does_not_run(self):
        self.output.write_text('VERDICT: PASS\nstale')
        capture = self.root / 'model.capture'
        result = self.invoke(env={'CAPTURE_CODEX_PROMPT': str(capture)})
        self.assertEqual(result.returncode, 2)
        self.assertEqual(self.output.read_text(), 'VERDICT: PASS\nstale')
        self.assertFalse(capture.exists())

    def test_both_reviewers_failing_leave_fresh_path_absent(self):
        result = self.invoke(env={'CODEX_EXIT': '7', 'CLAUDE_EXIT': '8'})
        self.assertEqual(result.returncode, 2)
        self.assertFalse(self.output.exists())

    def test_invalid_packet_never_creates_a_report(self):
        result = self.invoke(packet=self.root / 'missing.md')
        self.assertEqual(result.returncode, 2)
        self.assertFalse(self.output.exists())

    def test_existing_unrelated_file_outside_repo_is_not_deleted(self):
        important = self.root / 'ssh-config'
        important.write_text('important configuration\n')
        result = self.invoke(output=important)
        self.assertEqual(result.returncode, 2, result.stdout)
        self.assertEqual(important.read_text(), 'important configuration\n')

    def test_file_created_during_review_is_not_overwritten(self):
        result = self.invoke(env={'RACE_OUTPUT': str(self.output)})
        self.assertEqual(result.returncode, 2, result.stdout)
        self.assertEqual(self.output.read_text(), 'independent file created during review')

    def test_relocated_report_directory_cannot_yield_false_signoff(self):
        reports = self.root / 'reports'
        reports.mkdir()
        output = reports / 'review.md'
        result = self.invoke(output=output, env={'RACE_DIRECTORY_OUTPUT': str(output)})
        self.assertEqual(result.returncode, 2, result.stdout)
        self.assertEqual(output.read_text(), 'VERDICT: PASS\nstale path')
        self.assertFalse((self.root / 'reports-moved/review.md').exists())

    def test_directory_relocated_just_after_link_removes_unadvertised_report(self):
        spec = importlib.util.spec_from_file_location('report_file_under_test', REVIEW.parent / 'report_file.py')
        report_file = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(report_file)
        reports = self.root / 'reports'
        reports.mkdir()
        output = reports / 'review.md'
        target = report_file.ReportTarget(output, self.repo, self.packet)
        target.require_fresh()
        original_link = os.link

        def link_then_move(*args, **kwargs):
            original_link(*args, **kwargs)
            reports.rename(self.root / 'reports-moved')
            reports.mkdir()
            output.write_text('VERDICT: PASS\nstale path')

        try:
            with patch.object(report_file.os, 'link', side_effect=link_then_move):
                with self.assertRaises(OSError):
                    target.write_text('Reviewer: Sol\nVERDICT: BLOCK\n')
        finally:
            target.close()
        self.assertEqual(output.read_text(), 'VERDICT: PASS\nstale path')
        self.assertFalse((self.root / 'reports-moved/review.md').exists())

    def test_output_symlink_never_changes_target(self):
        target = self.root / 'important.txt'
        target.write_text('preserve')
        self.output.symlink_to(target)
        result = self.invoke()
        self.assertEqual(result.returncode, 2, result.stdout)
        self.assertEqual(target.read_text(), 'preserve')

    def test_output_inside_checkout_is_refused(self):
        result = self.invoke(output=self.repo / 'review.md')
        self.assertEqual(result.returncode, 2, result.stdout)
        self.assertFalse((self.repo / 'review.md').exists())

    def test_repo_subdirectory_is_refused_before_model_call(self):
        subdir = self.repo / 'subdir'
        subdir.mkdir()
        capture = self.root / 'model.capture'
        environment = {**os.environ, 'PATH': str(self.bin) + os.pathsep + '/usr/bin:/bin',
                       'CAPTURE_CODEX_PROMPT': str(capture)}
        result = subprocess.run([sys.executable, str(REVIEW), 'pr', '--repo', str(subdir),
                                 '--packet', str(self.packet), '--output', str(self.output)],
                                text=True, capture_output=True, env=environment, timeout=15)
        self.assertEqual(result.returncode, 2, result.stdout)
        self.assertFalse(capture.exists())

    def test_invalid_subdirectory_repo_cannot_delete_tracked_output(self):
        subdir = self.repo / 'subdir'
        subdir.mkdir()
        tracked = self.repo / 'tracked.txt'
        tracked.write_text('preserve\n')
        result = subprocess.run([sys.executable, str(REVIEW), 'pr', '--repo', str(subdir),
                                 '--packet', str(self.packet), '--output', str(tracked)],
                                text=True, capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 2, result.stdout)
        self.assertEqual(tracked.read_text(), 'preserve\n')

    def test_packet_parent_alias_cannot_be_deleted_as_output(self):
        alias = self.root / 'alias'
        alias.symlink_to(self.root, target_is_directory=True)
        result = self.invoke(packet=alias / 'packet.md', output=self.packet)
        self.assertEqual(result.returncode, 2, result.stdout)
        self.assertEqual(self.packet.read_text(), 'Scope and evidence for a disposable review.')

    def test_case_aliases_cannot_delete_repo_file_or_packet(self):
        alias_repo = self.repo.parent / self.repo.name.upper()
        alias_packet = self.packet.with_name(self.packet.name.upper())
        if not alias_repo.exists() or not alias_repo.samefile(self.repo) or not alias_packet.exists():
            self.skipTest('filesystem is case-sensitive')
        tracked = self.repo / 'tracked.txt'
        tracked.write_text('preserve\n')
        first = self.invoke(output=alias_repo / 'tracked.txt')
        self.assertEqual(first.returncode, 2, first.stdout)
        self.assertEqual(tracked.read_text(), 'preserve\n')
        second = self.invoke(output=alias_packet)
        self.assertEqual(second.returncode, 2, second.stdout)
        self.assertEqual(self.packet.read_text(), 'Scope and evidence for a disposable review.')

    def test_hardlinked_packet_cannot_be_unlinked_as_output(self):
        alias = self.root / 'packet-hardlink.md'
        os.link(self.packet, alias)
        result = self.invoke(output=alias)
        self.assertEqual(result.returncode, 2, result.stdout)
        self.assertTrue(alias.exists())
        self.assertTrue(self.packet.exists())

    def test_packet_symlink_is_refused_before_model_call(self):
        private = self.root / 'private.txt'
        private.write_text('fixture private text')
        link = self.root / 'packet-link.md'
        link.symlink_to(private)
        capture = self.root / 'model-prompt.txt'
        result = self.invoke(packet=link, env={'CAPTURE_CODEX_PROMPT': str(capture)})
        self.assertEqual(result.returncode, 2, result.stdout)
        self.assertFalse(capture.exists())

    def test_packet_hardlink_fifo_and_oversize_are_refused_without_model_call(self):
        private = self.root / 'private.txt'
        private.write_text('fixture private text')
        hardlink = self.root / 'linked.md'
        os.link(private, hardlink)
        fifo = self.root / 'pipe.md'
        os.mkfifo(fifo)
        large = self.root / 'large.md'
        large.write_bytes(b'x' * 150001)
        for packet in (hardlink, fifo, large):
            with self.subTest(packet=packet.name):
                capture = self.root / f'{packet.name}.capture'
                result = self.invoke(packet=packet, env={'CAPTURE_CODEX_PROMPT': str(capture)})
                self.assertEqual(result.returncode, 2, result.stdout)
                self.assertFalse(capture.exists())

    def test_existing_output_directory_is_reported_without_model_call(self):
        self.output.mkdir()
        capture = self.root / 'model.capture'
        result = self.invoke(env={'CAPTURE_CODEX_PROMPT': str(capture)})
        self.assertEqual(result.returncode, 2, result.stdout)
        self.assertFalse(capture.exists())
        self.assertTrue(self.output.is_dir())


if __name__ == '__main__':
    unittest.main()
