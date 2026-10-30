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
        subprocess.run(['git', '-C', str(self.repo), 'config', 'user.name', 'Fixture'], check=True)
        subprocess.run(['git', '-C', str(self.repo), 'config', 'user.email', 'fixture@example.invalid'], check=True)
        (self.repo / 'app.txt').write_text('baseline\n')
        subprocess.run(['git', '-C', str(self.repo), 'add', 'app.txt'], check=True)
        subprocess.run(['git', '-C', str(self.repo), 'commit', '-qm', 'baseline'], check=True)
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
if os.environ.get('RACE_HEAD'):
    import subprocess
    repo = sys.argv[sys.argv.index('--cd') + 1]
    subprocess.run(['git', '-C', os.environ.get('RACE_SOURCE_HEAD', repo), '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '--allow-empty', '-qm', 'concurrent commit'], check=True)
if os.environ.get('RACE_WORKTREE'):
    repo = sys.argv[sys.argv.index('--cd') + 1]
    (Path(repo) / 'app.txt').write_text('concurrent worktree edit\\n')
if os.environ.get('RACE_UNTRACKED'):
    Path(os.environ['RACE_UNTRACKED']).write_text('changed during review\\n')
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

    def invoke(self, *, packet=None, output=None, env=None, expected_head=None, stage='pr'):
        environment = {**os.environ, 'PATH': str(self.bin) + os.pathsep + '/usr/bin:/bin', **(env or {})}
        if expected_head is None:
            expected_head = subprocess.run(['git', '-C', str(self.repo), 'rev-parse', 'HEAD'],
                                           check=True, capture_output=True, text=True).stdout.strip()
        command = [sys.executable, str(REVIEW), stage, '--repo', str(self.repo),
                               '--packet', str(packet or self.packet), '--output', str(output or self.output),
                               *(['--expected-head', expected_head] if stage == 'pr' else [])]
        return subprocess.run(command,
                              text=True, capture_output=True, env=environment, timeout=15)

    def test_both_reviewers_use_committed_snapshot_without_ignored_content(self):
        (self.repo / '.gitignore').write_text('private.txt\nnode_modules/\n')
        subprocess.run(['git', '-C', str(self.repo), 'add', '.gitignore'], check=True)
        subprocess.run(['git', '-C', str(self.repo), 'commit', '-qm', 'ignore fixtures'], check=True)
        secret = self.repo / 'private.txt'
        secret.write_text('synthetic ignored fixture')
        vendor = self.repo / 'node_modules'
        vendor.mkdir()
        os.mkfifo(vendor / 'pipe')
        head = subprocess.check_output(['git', '-C', str(self.repo), 'rev-parse', 'HEAD'], text=True).strip()
        body = """import json, os, subprocess, sys
from pathlib import Path
prompt = sys.stdin.read()
cwd = Path.cwd()
seen = cwd / 'private.txt'
exposed = seen.exists()
ignored_read = seen.read_text() if exposed else None
if exposed: seen.write_text('synthetic mutation')
record = {'ignored_read': ignored_read, 'diff': subprocess.check_output(['git', 'diff', 'HEAD^', 'HEAD', '--'], text=True), 'config': (cwd / '.git/config').read_text(), 'cwd': str(cwd), 'exposed': exposed, 'vendor': (cwd / 'node_modules').exists(),
          'head': subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip(),
          'history': subprocess.check_output(['git', 'log', '--format=%s'], text=True), 'prompt': prompt}
Path(os.environ['ISOLATION_CAPTURE']).write_text(json.dumps(record))
if '--cd' in sys.argv:
    assert Path(sys.argv[sys.argv.index('--cd') + 1]) == cwd
    Path(sys.argv[sys.argv.index('--output-last-message') + 1]).write_text('VERDICT: PASS')
else: print('VERDICT: PASS')
"""
        import json
        for fallback in (False, True):
            with self.subTest(fallback=fallback):
                secret.write_text('synthetic ignored fixture')
                self.fake('codex', 'import sys; sys.exit(7)' if fallback else body)
                self.fake('claude', body)
                capture = self.root / 'isolation.json'
                result = self.invoke(stage='plan', output=self.root / f'review-{fallback}.md',
                                     env={'ISOLATION_CAPTURE': str(capture)})
                self.assertEqual(result.returncode, 0, result.stderr)
                record = json.loads(capture.read_text())
                self.assertFalse(record['exposed'])
                self.assertIsNone(record['ignored_read'])
                self.assertNotEqual(Path(record['cwd']).resolve(), self.repo.resolve())
                self.assertFalse(record['vendor'])
                self.assertEqual(record['head'], head)
                self.assertIn('baseline', record['history'])
                self.assertIn('private.txt', record['diff'])
                self.assertNotIn(str(self.repo), record['config'])
                self.assertIn(head, record['prompt'])
                self.assertFalse(Path(record['cwd']).exists(), 'snapshot cleanup before return')
                self.assertEqual(secret.read_text(), 'synthetic ignored fixture')

    def test_snapshot_rejects_committed_symlink_before_model(self):
        (self.repo / 'entry').symlink_to(self.packet)
        subprocess.run(['git', '-C', str(self.repo), 'add', 'entry'], check=True)
        subprocess.run(['git', '-C', str(self.repo), 'commit', '-qm', 'link'], check=True)
        capture = self.root / 'model.capture'
        result = self.invoke(env={'CAPTURE_CODEX_PROMPT': str(capture)})
        self.assertEqual(result.returncode, 2, result.stdout)
        self.assertFalse(capture.exists())
        self.assertFalse(self.output.exists())

    def test_source_config_and_inherited_git_routing_are_not_review_context(self):
        marker = self.root / 'hook-fired'
        hook = self.root / 'hook'
        hook.write_text('#!/bin/sh\ntouch "' + str(marker) + '"\nexit 1\n')
        hook.chmod(0o700)
        for key, value in (('core.hooksPath', str(self.root)),
                           ('uploadpack.packObjectsHook', str(hook)),
                           ('remote.private.url', 'synthetic-private-config')):
            subprocess.run(['git', '-C', str(self.repo), 'config', key, value], check=True)
        capture = self.root / 'config-capture'
        self.fake('codex', """import os, subprocess, sys
from pathlib import Path
sys.stdin.read()
assert 'synthetic-private-config' not in Path('.git/config').read_text()
assert 'GIT_DIR' not in os.environ and 'GIT_WORK_TREE' not in os.environ
assert subprocess.check_output(['git', 'status', '--porcelain'], text=True) == ''
Path(os.environ['CONFIG_CAPTURE']).write_text(str(Path.cwd()))
Path(sys.argv[sys.argv.index('--output-last-message') + 1]).write_text('VERDICT: PASS')
""")
        result = self.invoke(env={'GIT_DIR': '/nonexistent-fixture', 'GIT_WORK_TREE': str(self.root),
                                  'GIT_CONFIG_COUNT': '1', 'GIT_CONFIG_KEY_0': 'uploadpack.packObjectsHook',
                                  'GIT_CONFIG_VALUE_0': str(hook), 'CONFIG_CAPTURE': str(capture)})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(marker.exists())
        self.assertFalse(Path(capture.read_text()).exists())

    def test_isolation_failures_cleanup_without_publishing(self):
        import contextlib
        import io
        sys.path.insert(0, str(REVIEW.parent))
        self.addCleanup(sys.path.remove, str(REVIEW.parent))
        spec = importlib.util.spec_from_file_location('peer_isolation_test', REVIEW)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        real_snapshot = module.make_snapshot
        for failure in ('review', 'timeout', 'validation', 'source-race', 'cleanup'):
            with self.subTest(failure=failure):
                seen = []
                output = self.root / f'{failure}.report'
                def snapshot(repo, destination, head):
                    seen.append(destination)
                    real_snapshot(repo, destination, head)
                    if failure == 'validation':
                        raise OSError('synthetic validation failure')
                    if failure == 'source-race':
                        (repo / 'app.txt').write_text('changed source')
                def review(*args):
                    if failure == 'timeout':
                        raise subprocess.TimeoutExpired('fixture', 1)
                    if failure == 'review':
                        raise OSError('synthetic reviewer failure')
                    return 'fixture', 'VERDICT: PASS', ''
                real_cleanup = module.tempfile.TemporaryDirectory.cleanup
                def cleanup(directory):
                    real_cleanup(directory)
                    if failure == 'cleanup':
                        raise OSError('synthetic cleanup failure')
                with contextlib.ExitStack() as stack:
                    stack.enter_context(patch.object(sys, 'argv', ['review', 'plan', '--repo', str(self.repo),
                                       '--packet', str(self.packet), '--output', str(output)]))
                    stack.enter_context(patch.object(module, 'make_snapshot', side_effect=snapshot))
                    model = stack.enter_context(patch.object(module, 'review_snapshot', side_effect=review))
                    stack.enter_context(patch.object(module.tempfile.TemporaryDirectory, 'cleanup', cleanup))
                    stack.enter_context(contextlib.redirect_stderr(io.StringIO()))
                    self.assertEqual(module.main(), 2)
                self.assertTrue(seen)
                self.assertFalse(seen[0].exists())
                self.assertFalse(output.exists())
                if failure in ('validation', 'source-race'):
                    model.assert_not_called()
                (self.repo / 'app.txt').write_text('baseline\n')

    def test_valid_sol_pass_is_private_and_identified(self):
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('Reviewer: Codex gpt-6.1-sol', self.output.read_text())
        self.assertIn('VERDICT: PASS', self.output.read_text())
        self.assertIn('Reviewed HEAD: ', self.output.read_text())
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o600)

    def test_plan_review_pins_observed_commit_without_explicit_head(self):
        result = self.invoke(stage='plan')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('Reviewed HEAD: ', self.output.read_text())

    def test_plan_refuses_dirty_untracked_file_before_model(self):
        untracked = self.repo / 'untracked.txt'
        untracked.write_text('sparse private note\n')
        capture = self.root / 'model.capture'
        result = self.invoke(stage='plan', env={'CAPTURE_CODEX_PROMPT': str(capture),
                                                'RACE_UNTRACKED': str(untracked)})
        self.assertEqual(result.returncode, 2, result.stdout)
        self.assertEqual(untracked.read_text(), 'sparse private note\n')
        self.assertFalse(capture.exists())
        self.assertFalse(self.output.exists())
        self.assertNotIn('sparse private note', result.stderr + result.stdout)

    def test_plan_refuses_dirty_tracked_file_before_model(self):
        (self.repo / 'app.txt').write_text('dirty tracked content\n')
        capture = self.root / 'model.capture'
        result = self.invoke(stage='plan', env={'CAPTURE_CODEX_PROMPT': str(capture)})
        self.assertEqual(result.returncode, 2, result.stdout)
        self.assertFalse(capture.exists())
        self.assertFalse(self.output.exists())

    def test_plan_refuses_untracked_symlink_fifo_and_large_file_without_reading(self):
        outside = self.root / 'outside-private.txt'
        outside.write_text('never disclose this fixture value\n')
        for kind in ('symlink', 'fifo', 'large'):
            with self.subTest(kind=kind):
                path = self.repo / f'{kind}.dat'
                if kind == 'symlink':
                    path.symlink_to(outside)
                elif kind == 'fifo':
                    os.mkfifo(path)
                else:
                    path.write_bytes(b'x' * 4_000_000)
                capture = self.root / f'{kind}.capture'
                output = self.root / f'{kind}.review.md'
                result = self.invoke(stage='plan', output=output,
                                     env={'CAPTURE_CODEX_PROMPT': str(capture)})
                self.assertEqual(result.returncode, 2, result.stdout)
                self.assertFalse(capture.exists())
                self.assertFalse(output.exists())
                self.assertNotIn('never disclose this fixture value', result.stderr + result.stdout)
                path.unlink()
        self.assertEqual(outside.read_text(), 'never disclose this fixture value\n')

    def test_plan_skips_large_ignored_vendor_tree_but_rejects_visible_fifo(self):
        ignore = self.repo / '.gitignore'
        ignore.write_text('node_modules/\n')
        subprocess.run(['git', '-C', str(self.repo), 'add', '.gitignore'], check=True)
        subprocess.run(['git', '-C', str(self.repo), 'commit', '-qm', 'ignore vendor'], check=True)
        vendor = self.repo / 'node_modules'
        vendor.mkdir()
        for index in range(2000):
            (vendor / f'fixture-{index}.js').write_text('ignored\n')
        os.mkfifo(vendor / 'ignored-pipe')
        accepted = self.invoke(stage='plan', output=self.root / 'ignored-review.md')
        self.assertEqual(accepted.returncode, 0, accepted.stderr)
        visible = self.repo / 'visible-pipe'
        os.mkfifo(visible)
        capture = self.root / 'model.capture'
        refused = self.invoke(stage='plan', output=self.root / 'visible-review.md',
                              env={'CAPTURE_CODEX_PROMPT': str(capture)})
        self.assertEqual(refused.returncode, 2, refused.stdout)
        self.assertFalse(capture.exists())
        self.assertFalse((self.root / 'visible-review.md').exists())

    def test_plan_accepts_substantial_clean_tracked_tree(self):
        source = self.repo / 'src'
        source.mkdir()
        for index in range(1000):
            (source / f'fixture-{index}.txt').write_text('tracked\n')
        subprocess.run(['git', '-C', str(self.repo), 'add', 'src'], check=True)
        subprocess.run(['git', '-C', str(self.repo), 'commit', '-qm', 'tracked fixtures'], check=True)
        result = self.invoke(stage='plan')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('VERDICT: PASS', self.output.read_text())

    def test_snapshot_commit_blocks_pass_and_report(self):
        result = self.invoke(env={'RACE_HEAD': '1'})
        self.assertEqual(result.returncode, 2, result.stdout)
        self.assertFalse(self.output.exists())

    def test_concurrent_source_commit_blocks_pass_and_report(self):
        result = self.invoke(env={'RACE_HEAD': '1', 'RACE_SOURCE_HEAD': str(self.repo)})
        self.assertEqual(result.returncode, 2, result.stdout)
        self.assertFalse(self.output.exists())

    def test_concurrent_source_edit_blocks_pass_and_preserves_edit(self):
        result = self.invoke(env={'RACE_UNTRACKED': str(self.repo / 'app.txt')})
        self.assertEqual(result.returncode, 2, result.stdout)
        self.assertFalse(self.output.exists())
        self.assertEqual((self.repo / 'app.txt').read_text(), 'changed during review\n')

    def test_snapshot_worktree_edit_blocks_pass_and_report(self):
        result = self.invoke(env={'RACE_WORKTREE': '1'})
        self.assertEqual(result.returncode, 2, result.stdout)
        self.assertFalse(self.output.exists())

    def test_stale_expected_commit_blocks_before_reviewer(self):
        capture = self.root / 'model.capture'
        result = self.invoke(env={'CAPTURE_CODEX_PROMPT': str(capture)}, expected_head='0' * 40)
        self.assertEqual(result.returncode, 2, result.stdout)
        self.assertFalse(capture.exists())

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

    def test_directory_relocated_just_after_link_never_unlinks_destination(self):
        spec = importlib.util.spec_from_file_location('report_file_under_test', REVIEW.parent / 'report_file.py')
        report_file = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(report_file)
        reports = self.root / 'reports'
        reports.mkdir()
        output = reports / 'review.md'
        target = report_file.ReportTarget(output, self.repo, self.packet)
        target.require_fresh()
        original_link = os.link
        original_unlink = os.unlink

        def link_then_move(*args, **kwargs):
            original_link(*args, **kwargs)
            reports.rename(self.root / 'reports-moved')
            reports.mkdir()
            output.write_text('VERDICT: PASS\nstale path')

        def unlink_only_temporary(path, *args, **kwargs):
            if path == output.name:
                raise AssertionError('public report destination must never be unlinked')
            return original_unlink(path, *args, **kwargs)

        try:
            with patch.object(report_file.os, 'link', side_effect=link_then_move), \
                 patch.object(report_file.os, 'unlink', side_effect=unlink_only_temporary):
                with self.assertRaises(OSError):
                    target.write_text('Reviewer: Sol\nVERDICT: BLOCK\n')
        finally:
            target.close()
        self.assertEqual(output.read_text(), 'VERDICT: PASS\nstale path')
        self.assertEqual((self.root / 'reports-moved/review.md').read_text(),
                         'Reviewer: Sol\nVERDICT: BLOCK\n')

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
