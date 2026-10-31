import importlib.util
import json
import os
import shlex
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


RESCUE = Path(__file__).resolve().parents[1] / 'harness/hooks/rescue.py'
sys.path.insert(0, str(RESCUE.parent))
SPEC = importlib.util.spec_from_file_location('rescue_under_test', RESCUE)
rescue = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(rescue)


def git(repo, *args):
    result = subprocess.run(['git', '-C', str(repo), *args], capture_output=True, text=True, check=True)
    return result.stdout.strip()


class RescueTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / 'repo'
        self.repo.mkdir()
        git(self.repo, 'init', '-q', '-b', 'feat/rescue')
        git(self.repo, 'config', 'user.email', 'fixture@example.invalid')
        git(self.repo, 'config', 'user.name', 'Fixture')
        (self.repo / 'app.txt').write_text('baseline\n')
        git(self.repo, 'add', 'app.txt')
        git(self.repo, 'commit', '-qm', 'baseline')
        self.base = git(self.repo, 'rev-parse', 'HEAD')
        self.packet = self.root / 'packet.md'
        self.packet.write_text('A disposable rescue packet.')
        self.output = self.root / 'report.json'
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        self.fake('codex', '''import os, sys
from pathlib import Path
prompt = sys.stdin.read()
capture = os.environ.get('CAPTURE_CODEX_PROMPT')
if capture: Path(capture).write_text(prompt)
action = os.environ.get('CODEX_ACTION', '')
if action: Path('app.txt').write_text(action + '\\n')
if os.environ.get('CODEX_SWITCH_BRANCH'):
    import subprocess
    subprocess.run(['git', 'switch', '-q', '-c', 'feat/wrong'], check=True)
    subprocess.run(['git', 'commit', '--allow-empty', '-qm', 'wrong branch'], check=True)
if os.environ.get('CODEX_LOCAL_FILTER'):
    import shlex, subprocess
    marker = os.environ['CODEX_LOCAL_FILTER']
    subprocess.run(['git', 'config', 'filter.fixture.clean',
                    "sh -c 'touch " + shlex.quote(marker) + "; cat'"], check=True)
    Path('app.txt').write_text('updated\\n')
last = Path(sys.argv[sys.argv.index('--output-last-message') + 1])
last.write_text('Fixture handoff')
race = os.environ.get('RACE_OUTPUT')
if race: Path(race).write_text('independent file created during rescue')
relocated = os.environ.get('RACE_DIRECTORY_OUTPUT')
if relocated:
    parent = Path(relocated).parent
    parent.rename(parent.with_name(parent.name + '-moved'))
    parent.mkdir()
    Path(relocated).write_text('stale rescue report')
sys.exit(int(os.environ.get('CODEX_EXIT', '0')))
''')
        self.fake('claude', '''import os, sys
from pathlib import Path
prompt = sys.stdin.read()
capture = os.environ.get('CAPTURE_CLAUDE_PROMPT')
if capture: Path(capture).write_text(prompt)
action = os.environ.get('CLAUDE_ACTION', '')
if action: Path('app.txt').write_text(action + '\\n')
print('Fixture fallback handoff')
sys.exit(int(os.environ.get('CLAUDE_EXIT', '0')))
''')

    def fake(self, name, body):
        path = self.bin / name
        path.write_text(f'#!{sys.executable}\n{body}')
        path.chmod(0o700)

    def invoke(self, *, output=None, packet=None, wal=None, env=None):
        command = [sys.executable, str(RESCUE), '--repo', str(self.repo), '--packet', str(packet or self.packet),
                   '--output', str(output or self.output)]
        if wal is not None:
            command += ['--wal', str(wal)]
        environment = {**os.environ, 'PATH': str(self.bin) + os.pathsep + '/usr/bin:/bin', **(env or {})}
        return subprocess.run(command, text=True, capture_output=True, env=environment, timeout=15)

    def test_private_report_and_snapshot_on_successful_model_edit(self):
        result = self.invoke(env={'CODEX_ACTION': 'updated'})
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(self.output.read_text())
        self.assertEqual(report['status'], 'needs-main-verification')
        self.assertTrue(report['snapshot_commit_by_wrapper'])
        self.assertEqual(report['commits'], 1)
        self.assertFalse(report['dirty'])
        self.assertEqual((self.repo / 'app.txt').read_text(), 'updated\n')
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o600)

    def test_rescue_refuses_clean_commit_on_a_different_branch(self):
        result = self.invoke(env={'CODEX_SWITCH_BRANCH': '1', 'CAPTURE_CLAUDE_PROMPT': str(self.root / 'fallback')})
        self.assertEqual(result.returncode, 3, result.stderr)
        report = json.loads(self.output.read_text())
        self.assertEqual(report['status'], 'blocked')
        self.assertEqual(report['branch'], 'feat/rescue')
        self.assertEqual(report['actual_branch'], 'feat/wrong')
        self.assertFalse((self.root / 'fallback').exists())

    def test_rescue_refuses_local_filter_before_status_executes_it(self):
        (self.repo / '.gitattributes').write_text('app.txt filter=fixture\n')
        git(self.repo, 'add', '.gitattributes')
        git(self.repo, 'commit', '-qm', 'mark filter')
        marker = self.root / 'filter-ran'
        git(self.repo, 'config', 'filter.fixture.clean',
            f"sh -c 'touch {shlex.quote(str(marker))}; cat'")
        tracked = self.repo / 'app.txt'
        info = tracked.stat()
        os.utime(tracked, ns=(info.st_atime_ns, info.st_mtime_ns + 2_000_000_000))
        result = self.invoke()
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertFalse(marker.exists())
        self.assertFalse(self.output.exists())

    def test_rescue_refuses_untracked_file_hidden_by_status_config(self):
        git(self.repo, 'config', 'status.showUntrackedFiles', 'no')
        (self.repo / 'unreviewed.txt').write_text('unreviewed\n')
        self.assertEqual(git(self.repo, 'status', '--porcelain'), '')
        capture = self.root / 'model-prompt'
        result = self.invoke(env={'CAPTURE_CODEX_PROMPT': str(capture)})
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertFalse(capture.exists())
        self.assertFalse(self.output.exists())

    def test_rescue_blocks_if_model_adds_local_filter_before_postcheck(self):
        (self.repo / '.gitattributes').write_text('app.txt filter=fixture\n')
        git(self.repo, 'add', '.gitattributes')
        git(self.repo, 'commit', '-qm', 'mark filter')
        marker = self.root / 'post-model-filter-ran'
        fallback = self.root / 'fallback'
        result = self.invoke(env={'CODEX_LOCAL_FILTER': str(marker),
                                  'CAPTURE_CLAUDE_PROMPT': str(fallback)})
        self.assertEqual(result.returncode, 3, result.stderr)
        self.assertIn('inspect it before retrying', result.stderr)
        self.assertFalse(marker.exists())
        self.assertFalse(self.output.exists())
        self.assertFalse(fallback.exists())

    def test_failed_model_after_edits_does_not_fallback_or_commit(self):
        capture = self.root / 'fallback-prompt.txt'
        result = self.invoke(env={'CODEX_ACTION': 'unfinished', 'CODEX_EXIT': '7',
                                  'CAPTURE_CLAUDE_PROMPT': str(capture)})
        self.assertEqual(result.returncode, 3, result.stdout)
        report = json.loads(self.output.read_text())
        self.assertEqual(report['status'], 'blocked')
        self.assertEqual(report['head'], self.base)
        self.assertTrue(report['dirty'])
        self.assertFalse(capture.exists())

    def test_fallback_before_edits_is_blind_and_snapshotted(self):
        capture = self.root / 'fallback-prompt.txt'
        result = self.invoke(env={'CODEX_EXIT': '7', 'CLAUDE_ACTION': 'fallback',
                                  'CAPTURE_CLAUDE_PROMPT': str(capture)})
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(self.output.read_text())
        self.assertEqual(report['source'], 'Claude Fable fallback')
        self.assertEqual(report['status'], 'needs-main-verification')
        self.assertIn('A disposable rescue packet', capture.read_text())
        self.assertNotIn('Fixture handoff', capture.read_text())

    def test_output_symlink_does_not_delete_target(self):
        target = self.root / 'important.txt'
        target.write_text('preserve')
        self.output.symlink_to(target)
        result = self.invoke(env={'CODEX_ACTION': 'updated'})
        self.assertEqual(result.returncode, 2, result.stdout)
        self.assertEqual(target.read_text(), 'preserve')
        self.assertEqual(git(self.repo, 'rev-parse', 'HEAD'), self.base)

    def test_existing_unrelated_file_outside_repo_is_not_deleted(self):
        important = self.root / 'ssh-config'
        important.write_text('important configuration\n')
        capture = self.root / 'model.capture'
        result = self.invoke(output=important, env={'CAPTURE_CODEX_PROMPT': str(capture)})
        self.assertEqual(result.returncode, 2, result.stdout)
        self.assertEqual(important.read_text(), 'important configuration\n')
        self.assertFalse(capture.exists())

    def test_file_created_during_rescue_is_not_overwritten(self):
        result = self.invoke(env={'RACE_OUTPUT': str(self.output), 'CODEX_ACTION': 'updated'})
        self.assertEqual(result.returncode, 3, result.stdout)
        self.assertEqual(self.output.read_text(), 'independent file created during rescue')
        self.assertIn('inspect the worktree', result.stderr)
        self.assertEqual((self.repo / 'app.txt').read_text(), 'updated\n')

    def test_relocated_report_directory_preserves_replacement_after_rescue_edits(self):
        reports = self.root / 'reports'
        reports.mkdir()
        output = reports / 'report.json'
        result = self.invoke(output=output, env={'RACE_DIRECTORY_OUTPUT': str(output),
                                                 'CODEX_ACTION': 'updated'})
        self.assertEqual(result.returncode, 3, result.stdout)
        self.assertEqual(output.read_text(), 'stale rescue report')
        self.assertFalse((self.root / 'reports-moved/report.json').exists())
        self.assertIn('inspect the worktree', result.stderr)
        self.assertEqual((self.repo / 'app.txt').read_text(), 'updated\n')

    def test_packet_symlink_is_not_sent_to_model(self):
        private = self.root / 'private.txt'
        private.write_text('private fixture')
        link = self.root / 'packet-link.md'
        link.symlink_to(private)
        capture = self.root / 'codex-prompt.txt'
        result = self.invoke(packet=link, env={'CAPTURE_CODEX_PROMPT': str(capture)})
        self.assertEqual(result.returncode, 2, result.stdout)
        self.assertFalse(capture.exists())

    def test_packet_hardlink_fifo_and_oversize_are_refused_before_model_call(self):
        private = self.root / 'private.txt'
        private.write_text('private fixture')
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

    def test_invalid_subdirectory_repo_cannot_delete_tracked_output(self):
        subdir = self.repo / 'subdir'
        subdir.mkdir()
        tracked = self.repo / 'app.txt'
        result = subprocess.run([sys.executable, str(RESCUE), '--repo', str(subdir),
                                 '--packet', str(self.packet), '--output', str(tracked)],
                                text=True, capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 2, result.stdout)
        self.assertEqual(tracked.read_text(), 'baseline\n')

    def test_packet_parent_alias_cannot_be_deleted_as_output(self):
        alias = self.root / 'alias'
        alias.symlink_to(self.root, target_is_directory=True)
        result = self.invoke(packet=alias / 'packet.md', output=self.packet)
        self.assertEqual(result.returncode, 2, result.stdout)
        self.assertEqual(self.packet.read_text(), 'A disposable rescue packet.')

    def test_case_aliases_cannot_delete_repo_file_or_packet(self):
        alias_repo = self.repo.parent / self.repo.name.upper()
        alias_packet = self.packet.with_name(self.packet.name.upper())
        if not alias_repo.exists() or not alias_repo.samefile(self.repo) or not alias_packet.exists():
            self.skipTest('filesystem is case-sensitive')
        first = self.invoke(output=alias_repo / 'app.txt')
        self.assertEqual(first.returncode, 2, first.stdout)
        self.assertEqual((self.repo / 'app.txt').read_text(), 'baseline\n')
        second = self.invoke(output=alias_packet)
        self.assertEqual(second.returncode, 2, second.stdout)
        self.assertEqual(self.packet.read_text(), 'A disposable rescue packet.')

    def test_hardlinked_packet_cannot_be_unlinked_as_output(self):
        alias = self.root / 'packet-hardlink.md'
        os.link(self.packet, alias)
        result = self.invoke(output=alias)
        self.assertEqual(result.returncode, 2, result.stdout)
        self.assertTrue(alias.exists())
        self.assertTrue(self.packet.exists())

    def test_wal_symlink_and_hardlink_do_not_modify_outside_file(self):
        with patch.dict(os.environ, {'HOME': str(self.root)}):
            directory = self.root / '.claude/wals/session-1'
            directory.mkdir(parents=True)
            for kind in ('symlink', 'hardlink'):
                with self.subTest(kind=kind):
                    target = self.root / f'outside-{kind}.txt'
                    target.write_text('preserve\n')
                    wal = directory / 'main.jsonl'
                    wal.unlink(missing_ok=True)
                    if kind == 'symlink':
                        wal.symlink_to(target)
                    else:
                        os.link(target, wal)
                    with self.assertRaises((ValueError, OSError)):
                        rescue.log(wal, {'event': 'probe'})
                    self.assertEqual(target.read_text(), 'preserve\n')

    def test_wal_outside_private_root_is_rejected(self):
        outside = self.root / 'arbitrary.txt'
        with patch.dict(os.environ, {'HOME': str(self.root)}):
            with self.assertRaises((ValueError, OSError)):
                rescue.log(outside, {'event': 'probe'})
        self.assertFalse(outside.exists())

    def test_snapshot_refuses_hardlinked_external_content(self):
        outside = self.root / 'outside-secret.txt'
        outside.write_text('private fixture\n')
        link = self.repo / 'config.py'
        os.link(outside, link)
        success, detail = rescue.snapshot_commit(self.repo, 'fixture')
        self.assertFalse(success, detail)
        self.assertEqual(git(self.repo, 'rev-parse', 'HEAD'), self.base)
        self.assertEqual(outside.read_text(), 'private fixture\n')

    def test_snapshot_refuses_sensitive_paths(self):
        for name in ('.env', 'src/credentials.txt', 'node_modules/pkg/index.js', 'keys/private.pem'):
            with self.subTest(name=name):
                git(self.repo, 'reset', '--hard', self.base)
                git(self.repo, 'clean', '-fdq')
                path = self.repo / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('fixture')
                success, _ = rescue.snapshot_commit(self.repo, 'fixture')
                self.assertFalse(success)
                self.assertEqual(git(self.repo, 'rev-parse', 'HEAD'), self.base)
                path.unlink()

    def test_wrapper_snapshot_commit_does_not_run_source_hook(self):
        (self.repo / 'app.txt').write_text('updated\n')
        marker = self.root / 'hook-ran'
        hook = self.repo / '.git/hooks/pre-commit'
        hook.write_text(f'#!/bin/sh\ntouch {shlex.quote(str(marker))}\nexit 1\n')
        hook.chmod(0o700)
        committed, detail = rescue.snapshot_commit(self.repo, 'fixture')
        self.assertTrue(committed, detail)
        self.assertFalse(marker.exists())
        self.assertNotEqual(git(self.repo, 'rev-parse', 'HEAD'), self.base)

    def test_wrapper_snapshot_commit_does_not_run_signing_program(self):
        (self.repo / 'app.txt').write_text('updated\n')
        marker = self.root / 'signing-ran'
        signer = self.root / 'signer'
        signer.write_text(f'#!/bin/sh\ntouch {shlex.quote(str(marker))}\nexit 1\n')
        signer.chmod(0o700)
        git(self.repo, 'config', 'commit.gpgsign', 'true')
        git(self.repo, 'config', 'gpg.program', str(signer))
        committed, detail = rescue.snapshot_commit(self.repo, 'fixture')
        self.assertTrue(committed, detail)
        self.assertFalse(marker.exists())


if __name__ == '__main__':
    unittest.main()
