import importlib.util
import hashlib
import json
import os
import resource
import shlex
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch


REVIEW = Path(__file__).resolve().parents[1] / 'harness/hooks/peer_review.py'


class PeerReviewTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.guard_environment = patch.dict(os.environ, {
            'AGENT_HARNESS_USAGE_DIR': str(self.root / 'usage-state')})
        self.guard_environment.start()
        self.addCleanup(self.guard_environment.stop)
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
launches = os.environ.get('PROVIDER_LAUNCH_LOG')
if launches:
    with open(launches,'a') as stream: stream.write('codex\\n')
capture = os.environ.get('CAPTURE_CODEX_PROMPT')
if capture: Path(capture).write_text(prompt)
last = Path(sys.argv[sys.argv.index('--output-last-message') + 1])
default = ('PLAN_RESULT: ACCEPT' if 'Stage: plan.' in prompt else
           'CODE_INSPECTION_RESULT: ACCEPT' if 'Stage: code-inspection.' in prompt else 'VERDICT: PASS')
last.write_text(os.environ.get('CODEX_VERDICT', default + '\\nReviewed.'))
if os.environ.get('CODEX_EVENTS'): print(os.environ['CODEX_EVENTS'])
packet_action = os.environ.get('RACE_PACKET_ACTION')
if packet_action:
    packet = Path(os.environ['RACE_PACKET_PATH'])
    if packet_action == 'rewrite':
        packet.write_text('Tests: pass. Rewritten after reviewer read the old packet.')
    elif packet_action == 'replace':
        replacement = packet.with_name('replacement.md')
        replacement.write_text('Tests: pass. Replaced after reviewer read the old packet.')
        replacement.replace(packet)
    elif packet_action == 'symlink':
        replacement = packet.with_name('replacement.md')
        replacement.write_text('Tests: pass. Symlinked after reviewer read the old packet.')
        packet.unlink()
        packet.symlink_to(replacement)
    elif packet_action == 'hardlink':
        os.link(packet, packet.with_name('packet-hardlink.md'))
    elif packet_action == 'delete':
        packet.unlink()
    elif packet_action == 'oversize':
        packet.write_bytes(b'x' * 150001)
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
if os.environ.get('RACE_HIDDEN_INDEX'):
    import subprocess
    repo = os.environ['RACE_HIDDEN_INDEX']
    subprocess.run(['git', '-C', repo, 'update-index', '--assume-unchanged', 'app.txt'], check=True)
    (Path(repo) / 'app.txt').write_text('hidden edit during review\\n')
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
launches = os.environ.get('PROVIDER_LAUNCH_LOG')
if launches:
    with open(launches,'a') as stream: stream.write('claude\\n')
capture = os.environ.get('CAPTURE_CLAUDE_PROMPT')
if capture: Path(capture).write_text(prompt)
default = ('PLAN_RESULT: ACCEPT' if 'Stage: plan.' in prompt else
           'CODE_INSPECTION_RESULT: ACCEPT' if 'Stage: code-inspection.' in prompt else 'VERDICT: PASS')
print(os.environ.get('CLAUDE_VERDICT', default + '\\nFallback reviewed.'))
sys.exit(int(os.environ.get('CLAUDE_EXIT', '0')))
''')

    def fake(self, name, body):
        path = self.bin / name
        path.write_text(f'#!{sys.executable}\n{body}')
        path.chmod(0o700)

    def invoke(self, *, packet=None, output=None, env=None, expected_head=None, stage='pr', extra=()):
        environment = {**os.environ, 'PATH': str(self.bin) + os.pathsep + '/usr/bin:/bin', **(env or {})}
        if expected_head is None:
            expected_head = subprocess.run(['git', '-C', str(self.repo), 'rev-parse', 'HEAD'],
                                           check=True, capture_output=True, text=True).stdout.strip()
        command = [sys.executable, str(REVIEW), stage, '--repo', str(self.repo),
                               '--packet', str(packet or self.packet), '--output', str(output or self.output),
                               *(['--expected-head', expected_head] if stage in {'pr', 'code-inspection'} else []), *extra]
        return subprocess.run(command,
                              text=True, capture_output=True, env=environment, timeout=45)

    def test_source_local_clean_filter_is_refused_before_execution(self):
        (self.repo / '.gitattributes').write_text('app.txt filter=fixture\n')
        subprocess.run(['git', '-C', str(self.repo), 'add', '.gitattributes'], check=True)
        subprocess.run(['git', '-C', str(self.repo), 'commit', '-qm', 'mark fixture filter'], check=True)
        marker = self.root / 'filter-ran'
        command = f"sh -c 'touch {shlex.quote(str(marker))}; cat'"
        subprocess.run(['git', '-C', str(self.repo), 'config', 'filter.fixture.clean', command], check=True)
        tracked = self.repo / 'app.txt'
        stat_info = tracked.stat()
        os.utime(tracked, ns=(stat_info.st_atime_ns, stat_info.st_mtime_ns + 2_000_000_000))

        result = self.invoke(stage='plan')
        self.assertFalse(marker.exists(), 'source status executed a repository-local clean filter')
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertFalse(self.output.exists())

    def test_conditional_local_include_filter_is_refused(self):
        (self.repo / '.gitattributes').write_text('app.txt filter=fixture\n')
        subprocess.run(['git', '-C', str(self.repo), 'add', '.gitattributes'], check=True)
        subprocess.run(['git', '-C', str(self.repo), 'commit', '-qm', 'mark fixture filter'], check=True)
        marker = self.root / 'included-filter-ran'
        included = self.root / 'local-filter-config'
        included.write_text('[filter "fixture"]\n'
                            f' clean = sh -c "touch {marker}; cat"\n')
        gitdir = subprocess.check_output(['git', '-C', str(self.repo), 'rev-parse',
                                          '--absolute-git-dir'], text=True).strip()
        with (Path(gitdir) / 'config').open('a') as config:
            config.write(f'\n[includeIf "gitdir:{gitdir}"]\n path = {included}\n')
        tracked = self.repo / 'app.txt'
        info = tracked.stat()
        os.utime(tracked, ns=(info.st_atime_ns, info.st_mtime_ns + 2_000_000_000))
        result = self.invoke(stage='plan')
        self.assertFalse(marker.exists())
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)

    def test_worktree_scoped_filter_is_refused(self):
        (self.repo / '.gitattributes').write_text('app.txt filter=fixture\n')
        subprocess.run(['git', '-C', str(self.repo), 'add', '.gitattributes'], check=True)
        subprocess.run(['git', '-C', str(self.repo), 'commit', '-qm', 'mark fixture filter'], check=True)
        subprocess.run(['git', '-C', str(self.repo), 'config', 'extensions.worktreeConfig', 'true'], check=True)
        marker = self.root / 'worktree-filter-ran'
        subprocess.run(['git', '-C', str(self.repo), 'config', '--worktree',
                        'filter.fixture.clean', f"sh -c 'touch {shlex.quote(str(marker))}; cat'"], check=True)
        tracked = self.repo / 'app.txt'
        info = tracked.stat()
        os.utime(tracked, ns=(info.st_atime_ns, info.st_mtime_ns + 2_000_000_000))
        result = self.invoke(stage='plan')
        self.assertFalse(marker.exists())
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)

    def test_populated_submodule_filter_is_not_executed(self):
        child = self.root / 'child'
        subprocess.run(['git', 'init', '-q', '-b', 'main', str(child)], check=True)
        subprocess.run(['git', '-C', str(child), 'config', 'user.name', 'Fixture'], check=True)
        subprocess.run(['git', '-C', str(child), 'config', 'user.email', 'fixture@example.invalid'], check=True)
        (child / '.gitattributes').write_text('child.txt filter=fixture\n')
        (child / 'child.txt').write_text('child\n')
        subprocess.run(['git', '-C', str(child), 'add', '.'], check=True)
        subprocess.run(['git', '-C', str(child), 'commit', '-qm', 'child'], check=True)
        subprocess.run(['git', '-C', str(self.repo), '-c', 'protocol.file.allow=always',
                        'submodule', 'add', '-q', str(child.resolve()), 'module'], check=True)
        subprocess.run(['git', '-C', str(self.repo), 'commit', '-qam', 'add submodule'], check=True)
        module = self.repo / 'module'
        marker = self.root / 'submodule-filter-ran'
        subprocess.run(['git', '-C', str(module), 'config', 'filter.fixture.clean',
                        f"sh -c 'touch {shlex.quote(str(marker))}; cat'"], check=True)
        tracked = module / 'child.txt'
        info = tracked.stat()
        os.utime(tracked, ns=(info.st_atime_ns, info.st_mtime_ns + 2_000_000_000))
        subprocess.run(['git', '-C', str(self.repo), 'status', '--porcelain'],
                       check=True, capture_output=True)
        self.assertTrue(marker.exists(), 'control must exercise Git submodule filter')
        marker.unlink()
        result = self.invoke(stage='plan')
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertFalse(marker.exists())

    def test_index_listing_works_with_pipe_descriptor_above_1023(self):
        soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
        if hard != resource.RLIM_INFINITY and hard < 1100:
            self.skipTest('host descriptor limit below high-FD fixture')
        raised = soft < 1100
        if raised:
            try:
                resource.setrlimit(resource.RLIMIT_NOFILE, (1100, hard))
            except OSError as error:
                self.skipTest(f'cannot raise descriptor limit: {error}')
        opened = []
        try:
            while not opened or opened[-1] < 1050:
                opened.append(os.open(os.devnull, os.O_RDONLY))
            sys.path.insert(0, str(REVIEW.parent))
            try:
                spec = importlib.util.spec_from_file_location('peer_review_high_fd', REVIEW)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                module.require_unflagged_index(self.repo)
            finally:
                sys.path.pop(0)
        finally:
            for descriptor in reversed(opened):
                os.close(descriptor)
            if raised:
                resource.setrlimit(resource.RLIMIT_NOFILE, (soft, hard))

    def test_blocked_config_include_fails_within_metadata_deadline(self):
        include = self.root / 'stalled-config'
        os.mkfifo(include)
        subprocess.run(['git', '-C', str(self.repo), 'config', 'include.path', str(include)], check=True)
        sys.path.insert(0, str(REVIEW.parent))
        try:
            from git_safety import git_environment, require_safe_source
            started = time.monotonic()
            with self.assertRaises(OSError):
                require_safe_source(self.repo, git_environment(isolated=True), timeout=1)
            self.assertLess(time.monotonic() - started, 4)
        finally:
            sys.path.pop(0)

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
    assert Path(sys.argv[sys.argv.index('--cd') + 1]).resolve() == cwd.resolve()
    Path(sys.argv[sys.argv.index('--output-last-message') + 1]).write_text('PLAN_RESULT: ACCEPT')
else: print('PLAN_RESULT: ACCEPT')
"""
        import json
        for fallback in (False, True):
            with self.subTest(fallback=fallback):
                secret.write_text('synthetic ignored fixture')
                self.fake('codex', 'import json,sys; print(json.dumps({"type":"turn.failed","error":{"code":"model_not_found"}}));sys.exit(7)' if fallback else body)
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
                    return 'fixture', 'PLAN_RESULT: ACCEPT', ''
                real_cleanup = module.tempfile.TemporaryDirectory.cleanup
                def cleanup(directory):
                    real_cleanup(directory)
                    if failure == 'cleanup':
                        raise OSError('synthetic cleanup failure')
                with contextlib.ExitStack() as stack:
                    stack.enter_context(patch.dict(os.environ, {'AGENT_HARNESS_USAGE_DIR': str(self.root / ('usage-' + failure))}))
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

    def test_plan_refuses_hidden_index_flags_before_model(self):
        for flag in ('--assume-unchanged', '--skip-worktree'):
            with self.subTest(flag=flag):
                subprocess.run(['git', '-C', str(self.repo), 'update-index', flag, 'app.txt'], check=True)
                (self.repo / 'app.txt').write_text('hidden private edit\n')
                capture = self.root / f'{flag}.capture'
                output = self.root / f'{flag}.review.md'
                result = self.invoke(stage='plan', output=output,
                                     env={'CAPTURE_CODEX_PROMPT': str(capture)})
                self.assertEqual(result.returncode, 2, result.stdout)
                self.assertFalse(capture.exists())
                self.assertFalse(output.exists())
                self.assertNotIn('hidden private edit', result.stderr + result.stdout)
                (self.repo / 'app.txt').write_text('baseline\n')
                subprocess.run(['git', '-C', str(self.repo), 'update-index', '--no-assume-unchanged',
                                '--no-skip-worktree', 'app.txt'], check=True)

    def test_plan_refuses_index_flag_set_during_review(self):
        result = self.invoke(stage='plan', env={'RACE_HIDDEN_INDEX': str(self.repo)})
        self.assertEqual(result.returncode, 2, result.stdout)
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
        self.assertIn('PLAN_RESULT: ACCEPT', self.output.read_text())

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

    def test_block_receipt_preserves_named_finding_ids_without_fallback(self):
        launches = self.root / 'launches'
        result = self.invoke(env={'CODEX_VERDICT': 'VERDICT: BLOCK\nF1: missing negative case\n## F2 security issue',
                                  'PROVIDER_LAUNCH_LOG': str(launches)})
        self.assertEqual(result.returncode, 3, result.stderr)
        self.assertEqual(launches.read_text().splitlines(), ['codex'])
        finals = list((self.root / 'usage-state' / 'runs').glob('*/final.json'))
        self.assertEqual(len(finals), 1)
        value = json.loads(finals[0].read_text())
        self.assertEqual((value['reason'], value['review']['findings']), ('CODE_FINDINGS', ['F1', 'F2']))

    def test_invalid_sol_result_does_not_spend_a_fallback_call(self):
        captured = self.root / 'fallback-prompt.txt'
        result = self.invoke(env={'CODEX_VERDICT': 'VERDICT: MAYBE\nUntrusted prior opinion.',
                                  'CAPTURE_CLAUDE_PROMPT': str(captured)})
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertFalse(self.output.exists())
        self.assertFalse(captured.exists())

    def test_structured_failure_overrides_exit_zero_and_last_message_pass(self):
        capture = self.root / 'fallback.capture'
        events = json.dumps({'type': 'turn.failed', 'error': {
            'code': 'invalid_request', 'message': 'VERDICT: PASS'}})
        result = self.invoke(env={'CODEX_EVENTS': events, 'CAPTURE_CLAUDE_PROMPT': str(capture)})
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertFalse(self.output.exists())
        self.assertFalse(capture.exists())

    def test_plan_result_cannot_be_mistaken_for_pr_pass(self):
        result = self.invoke(stage='plan')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn('VERDICT: PASS', self.output.read_text())
        self.assertIn('PLAN_RESULT: ACCEPT', self.output.read_text())

    def test_soft_packet_warning_does_not_reject_valid_content(self):
        self.packet.write_text('Scope and evidence.\n' + 'x' * 33000)
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('32 KiB', result.stderr)

    def test_code_inspection_has_no_pr_marker_and_persists_its_stage(self):
        result = self.invoke(stage='code-inspection')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('CODE_INSPECTION_RESULT: ACCEPT', self.output.read_text())
        self.assertNotIn('VERDICT: PASS', self.output.read_text())
        finals = list((self.root / 'usage-state' / 'runs').glob('*/final.json'))
        self.assertEqual(len(finals), 1)
        self.assertEqual(json.loads(finals[0].read_text())['review'],
                         {'stage': 'CODE_INSPECTION', 'verdict': 'ACCEPT', 'findings': []})

    def finalization_fixture(self, after_finish=None, *, fail_announcement=False):
        import contextlib
        import io
        sys.path.insert(0, str(REVIEW.parent))
        self.addCleanup(sys.path.remove, str(REVIEW.parent))
        spec = importlib.util.spec_from_file_location('peer_finalization_fixture', REVIEW)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        import usage_guard
        manifest = self.root / 'inputs.json'
        manifest.write_text(json.dumps({'schema': 1, 'files': [], 'revisions': {},
            'complete': True, 'deterministic': True, 'target': 'fixture',
            'toolchain': {'fixture': {'path': str(self.bin / 'codex'), 'public': True,
                'sha256': hashlib.sha256((self.bin / 'codex').read_bytes()).hexdigest()}}}))
        manifest.chmod(0o600)
        head = subprocess.check_output(['git', '-C', str(self.repo), 'rev-parse', 'HEAD'], text=True).strip()
        observed = {}
        real_finish = usage_guard.Run.finish

        def finish_with_hook(run, **arguments):
            reference = real_finish(run, **arguments)
            observed.update(reference=reference, subject=run.subject,
                            invocation=run.start['invocation'], store=run.store,
                            guard_error=usage_guard.GuardError)
            if after_finish is not None:
                after_finish(observed)
            return reference

        def announce(*arguments, **keywords):
            if fail_announcement and arguments and str(arguments[0]).startswith('fixture:'):
                raise OSError('synthetic stdout failure')
            print(*arguments, **keywords)

        output, errors = io.StringIO(), io.StringIO()
        with patch.object(sys, 'argv', ['review', 'code-inspection', '--repo', str(self.repo),
                '--packet', str(self.packet), '--output', str(self.output),
                '--expected-head', head, '--input-manifest', str(manifest)]), \
             patch.dict(os.environ, {'PATH': str(self.bin) + os.pathsep + '/usr/bin:/bin'}), \
             patch.object(module, 'review_snapshot', return_value=('fixture', 'CODE_INSPECTION_RESULT: ACCEPT', '')), \
             patch.object(usage_guard.Run, 'finish', finish_with_hook), \
             patch.object(module, 'print', side_effect=announce, create=True), \
             contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            result = module.main()
        observed.update(result=result, stdout=output.getvalue(), stderr=errors.getvalue())
        self.assertTrue(observed['subject']['reusable'])
        return observed

    def assert_review_cannot_authorize(self, observed):
        historical = observed['store'].load_ref(observed['reference'])
        self.assertEqual((historical['result'], historical['reason']), ('CHECK_OK', 'NONE'))
        with self.assertRaises(observed['guard_error']):
            observed['store'].check_gate(observed['subject'], observed['reference'])
        self.assertFalse(observed['store'].reuse(observed['subject'], observed['invocation'],
                                               observed['reference'])['eligible'])

    def test_post_final_packet_mutation_cannot_authorize_full_validation(self):
        def mutate(_):
            self.packet.write_text('Changed after the successful FINAL was persisted.')

        observed = self.finalization_fixture(mutate)
        self.assertEqual(observed['result'], 2, observed['stderr'])
        self.assertEqual(observed['stdout'], '')
        self.assert_review_cannot_authorize(observed)

    def test_provisional_review_is_ineligible_until_final_publication_settles(self):
        provisional = []

        def inspect(observed):
            self.assert_review_cannot_authorize(observed)
            provisional.append(True)

        observed = self.finalization_fixture(inspect)
        self.assertEqual(provisional, [True])
        self.assertEqual(observed['result'], 0, observed['stderr'])
        self.assertIn('CODE_INSPECTION_RESULT: ACCEPT', observed['stdout'])
        self.assertEqual(observed['store'].check_gate(observed['subject'], observed['reference'])['result'],
                         'CHECK_OK')
        self.assertTrue(observed['store'].reuse(observed['subject'], observed['invocation'],
                                              observed['reference'])['eligible'])

    def test_announcement_error_invalidates_settled_review_without_rewriting_final(self):
        observed = self.finalization_fixture(fail_announcement=True)
        self.assertEqual(observed['result'], 2, observed['stderr'])
        self.assertEqual(observed['stdout'], '')
        self.assertIn('synthetic stdout failure', observed['stderr'])
        self.assert_review_cannot_authorize(observed)

    def test_wrong_stage_provider_result_refuses_without_fallback(self):
        capture = self.root / 'fallback.capture'
        result = self.invoke(env={'CODEX_VERDICT': 'PLAN_RESULT: ACCEPT',
                                  'CAPTURE_CLAUDE_PROMPT': str(capture)})
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertFalse(self.output.exists())
        self.assertFalse(capture.exists())

    def test_identical_completed_invocation_is_not_launched_again(self):
        launches = self.root / 'launches'
        first = self.invoke(env={'PROVIDER_LAUNCH_LOG': str(launches)})
        self.assertEqual(first.returncode, 0, first.stderr)
        second = self.invoke(output=self.root / 'second.report', env={'PROVIDER_LAUNCH_LOG': str(launches)})
        self.assertEqual(second.returncode, 2, second.stderr)
        self.assertEqual(launches.read_text().splitlines(), ['codex'])
        self.assertFalse((self.root / 'second.report').exists())

    def test_quota_pools_remain_shared_across_new_run_and_model(self):
        launches = self.root / 'launches'
        environment = {'PROVIDER_LAUNCH_LOG': str(launches),
            'CODEX_EVENTS': json.dumps({'type': 'turn.failed', 'error': {'code': 'insufficient_quota'}}),
            'CLAUDE_VERDICT': json.dumps({'type': 'result', 'subtype': 'error_during_execution',
                'is_error': True, 'error': {'code': 'insufficient_quota'}, 'result': 'VERDICT: PASS'})}
        first = self.invoke(env=environment)
        self.assertEqual(first.returncode, 2, first.stderr)
        self.assertEqual(launches.read_text().splitlines(), ['codex', 'claude'])
        self.packet.write_text('Changed evidence remains subject to the same provider pools.')
        environment['CODEX_REVIEW_MODEL'] = 'alternate-fixture-model'
        second = self.invoke(output=self.root / 'second.report', env=environment)
        self.assertEqual(second.returncode, 2, second.stderr)
        self.assertEqual(launches.read_text().splitlines(), ['codex', 'claude'])

    def test_packet_budget_refuses_before_model_and_duplication_is_advisory(self):
        launches = self.root / 'launches'
        refused = self.invoke(env={'PROVIDER_LAUNCH_LOG': str(launches)}, extra=['--packet-budget-bytes', '10'])
        self.assertEqual(refused.returncode, 2, refused.stderr)
        self.assertFalse(launches.exists())
        block = '```text\nRepeated relevant fixture\n```\n'
        self.packet.write_text(block * 2)
        accepted = self.invoke(env={'PROVIDER_LAUNCH_LOG': str(launches)})
        self.assertEqual(accepted.returncode, 0, accepted.stderr)
        self.assertIn('warning only', accepted.stderr)
        self.assertEqual(launches.read_text().splitlines(), ['codex'])

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

    def test_packet_read_error_paths_close_open_descriptor(self):
        sys.path.insert(0, str(REVIEW.parent))
        self.addCleanup(sys.path.remove, str(REVIEW.parent))
        spec = importlib.util.spec_from_file_location('peer_packet_descriptor_test', REVIEW)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        oversized = self.root / 'oversized.md'
        oversized.write_bytes(b'x' * 150001)
        fifo = self.root / 'packet-fifo'
        os.mkfifo(fifo)
        linked = self.root / 'packet-linked.md'
        os.link(self.packet, linked)
        for packet in (oversized, fifo, linked):
            with self.subTest(packet=packet.name):
                before = set(os.listdir('/dev/fd'))
                with self.assertRaises(ValueError):
                    module.read_packet(packet)
                self.assertEqual(set(os.listdir('/dev/fd')), before)
        linked.unlink()
        before = set(os.listdir('/dev/fd'))
        with patch.object(module, 'packet_bytes', side_effect=ValueError('changed')) as read:
            with self.assertRaises(ValueError):
                module.read_packet(self.packet)
        read.assert_called_once()
        self.assertEqual(set(os.listdir('/dev/fd')), before)

    def test_main_early_exit_closes_packet_descriptor(self):
        import contextlib
        import io
        sys.path.insert(0, str(REVIEW.parent))
        self.addCleanup(sys.path.remove, str(REVIEW.parent))
        spec = importlib.util.spec_from_file_location('peer_main_descriptor_test', REVIEW)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        for failure in ('stale-head', 'repo-inspection'):
            with self.subTest(failure=failure):
                args = ['review', 'pr', '--repo', str(self.repo), '--packet', str(self.packet),
                        '--output', str(self.root / f'{failure}.md'), '--expected-head', '0' * 40]
                before = set(os.listdir('/dev/fd'))
                with patch.object(sys, 'argv', args), contextlib.redirect_stderr(io.StringIO()):
                    if failure == 'repo-inspection':
                        with patch.object(module, 'repo_state', side_effect=OSError('fixture')):
                            with self.assertRaises(SystemExit) as raised:
                                module.main()
                    else:
                        with self.assertRaises(SystemExit) as raised:
                            module.main()
                self.assertEqual(raised.exception.code, 2)
                self.assertEqual(set(os.listdir('/dev/fd')), before)

    def test_packet_changed_by_reviewer_cannot_publish_pass(self):
        for action in ('rewrite', 'replace', 'symlink', 'hardlink', 'delete', 'oversize'):
            with self.subTest(action=action):
                if self.packet.is_symlink() or self.packet.exists():
                    self.packet.unlink()
                hardlink = self.root / 'packet-hardlink.md'
                if hardlink.exists():
                    hardlink.unlink()
                self.packet.write_text('Tests: pending. Reviewer saw this evidence.')
                output = self.root / f'{action}.review.md'
                capture = self.root / f'{action}.prompt'
                result = self.invoke(output=output, env={
                    'RACE_PACKET_ACTION': action, 'RACE_PACKET_PATH': str(self.packet),
                    'CAPTURE_CODEX_PROMPT': str(capture),
                    'AGENT_HARNESS_USAGE_DIR': str(self.root / ('usage-packet-' + action)),
                })
                self.assertIn('Tests: pending.', capture.read_text())
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertFalse(output.exists())

    def test_report_names_raw_packet_bytes_digest(self):
        raw = b'Scope with non-UTF8 byte: \xff'
        self.packet.write_bytes(raw)
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('Reviewed packet SHA-256: ' + hashlib.sha256(raw).hexdigest(),
                      self.output.read_text())
        self.packet.write_bytes(b'changed after successful review')
        self.assertNotIn('Reviewed packet SHA-256: ' + hashlib.sha256(self.packet.read_bytes()).hexdigest(),
                         self.output.read_text())

    def test_packet_changed_during_report_staging_blocks_publication(self):
        import contextlib
        import io
        sys.path.insert(0, str(REVIEW.parent))
        self.addCleanup(sys.path.remove, str(REVIEW.parent))
        spec = importlib.util.spec_from_file_location('peer_staging_packet_race', REVIEW)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        real_fsync = os.fsync
        changed = []

        def fsync_then_mutate(fd):
            real_fsync(fd)
            if not changed and list(self.root.glob('.report-*')):
                self.packet.write_text('Tests: pass. Mutated during report staging.')
                changed.append(True)

        errors = io.StringIO()
        with patch.object(sys, 'argv', ['review', 'plan', '--repo', str(self.repo),
                                       '--packet', str(self.packet), '--output', str(self.output)]), \
             patch.object(module, 'review_snapshot', return_value=('fixture', 'PLAN_RESULT: ACCEPT', '')), \
             patch.object(os, 'fsync', side_effect=fsync_then_mutate), \
             contextlib.redirect_stderr(errors):
            result = module.main()
        self.assertEqual(result, 2, errors.getvalue())
        self.assertEqual(changed, [True])
        self.assertFalse(self.output.exists())
        self.assertEqual(list(self.root.glob('.report-*')), [])

    def test_packet_changed_just_after_link_cannot_announce_current_signoff(self):
        import contextlib
        import io
        sys.path.insert(0, str(REVIEW.parent))
        self.addCleanup(sys.path.remove, str(REVIEW.parent))
        spec = importlib.util.spec_from_file_location('peer_late_packet_race', REVIEW)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        original = self.packet.read_bytes()
        real_link = os.link
        linked = []

        def link_then_mutate(*args, **kwargs):
            real_link(*args, **kwargs)
            if args[1] == self.output.name:
                self.packet.write_text('Tests: pass. Mutated just after report publication.')
                linked.append(True)

        output = io.StringIO()
        errors = io.StringIO()
        with patch.object(sys, 'argv', ['review', 'plan', '--repo', str(self.repo),
                                       '--packet', str(self.packet), '--output', str(self.output)]), \
             patch.object(module, 'review_snapshot', return_value=('fixture', 'PLAN_RESULT: ACCEPT', '')), \
             patch.object(os, 'link', side_effect=link_then_mutate), \
             contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            result = module.main()
        self.assertEqual(result, 2, errors.getvalue())
        self.assertEqual(linked, [True])
        self.assertEqual(output.getvalue(), '')
        self.assertIn('A digest-bound historical report may remain', errors.getvalue())
        self.assertIn('Reviewed packet SHA-256: ' + hashlib.sha256(original).hexdigest(),
                      self.output.read_text())
        self.assertNotIn('Tests: pass.', self.output.read_text())

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


class ProviderEnvelopeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location('peer_envelope_unit', REVIEW)
        cls.module = importlib.util.module_from_spec(spec)
        with patch.object(sys, 'path', [str(REVIEW.parent), *sys.path]):
            spec.loader.exec_module(cls.module)

    def codex(self, message='VERDICT: PASS\nReviewed.', extra=()):
        return '\n'.join(json.dumps(value) for value in [
            {'type': 'thread.started', 'thread_id': 'fixture'}, {'type': 'turn.started'},
            *extra, {'type': 'item.completed', 'item': {'id': '1', 'type': 'agent_message', 'text': message}},
            {'type': 'turn.completed', 'usage': {'input_tokens': 10, 'output_tokens': 4}}])

    def test_supported_codex_and_claude_envelopes_require_terminal_success(self):
        codex = self.module.normalize_provider('codex', 0, self.codex(), last_message='VERDICT: PASS\nReviewed.')
        self.assertEqual((codex['result'], codex['reason'], codex['usage']),
                         ('CHECK_OK', 'NONE', {'input_tokens': 10, 'output_tokens': 4}))
        record = {'type': 'result', 'subtype': 'success', 'is_error': False,
                  'result': 'VERDICT: PASS\nReviewed.', 'usage': {'input_tokens': 3}, 'total_cost_usd': .01}
        for data in (json.dumps(record, indent=2), json.dumps({'type': 'system'}) + '\n' + json.dumps(record)):
            result = self.module.normalize_provider('claude', 0, data)
            self.assertEqual(result['result'], 'CHECK_OK')
            self.assertEqual(result['usage'], {'input_tokens': 3, 'cost_usd': .01})

    def test_errors_truncation_and_nonzero_exit_cannot_be_pass(self):
        cases = [('claude', 0, json.dumps({'type': 'result', 'subtype': 'error_during_execution',
                                          'is_error': True, 'result': 'VERDICT: PASS'})),
                 ('claude', 0, json.dumps({'type': 'result', 'subtype': 'success', 'is_error': False,
                                          'result': {}, 'usage': {}})),
                 ('codex', 0, '{"type":"turn.completed"'),
                 ('codex', 0, json.dumps({'type': 'item.completed', 'item': {
                     'type': 'agent_message', 'text': 'VERDICT: PASS'}})),
                 ('codex', 0, self.codex().replace('"type": "turn.completed"',
                                                 '"type": "turn.completed", "is_error": true')),
                 ('codex', 1, self.codex()),
                 ('codex', 0, json.dumps({'unexpected': 'VERDICT: PASS'}))]
        for provider, code, data in cases:
            with self.subTest(provider=provider, data=data):
                result = self.module.normalize_provider(provider, code, data, last_message='VERDICT: PASS')
                self.assertEqual(result['result'], 'NO_RESULT')
                self.assertFalse(result['fallback_allowed'])

    def test_account_errors_are_distinct_from_model_credit_and_tool_content(self):
        quota = self.module.normalize_provider('codex', 0, json.dumps({
            'type': 'turn.failed', 'error': {'code': 'insufficient_quota', 'reset_at': 2000000000}}))
        self.assertEqual((quota['reason'], quota['account_cooldown'], quota['fallback_allowed']),
                         ('QUOTA', True, True))
        for error in ({'code': 'insufficient_credits', 'scope': 'model'},
                      {'code': 'quota_exceeded', 'scope': 'model'},
                      {'code': 'model_not_found'}, {'message': 'credit limit reached'}):
            with self.subTest(error=error):
                result = self.module.normalize_provider('codex', 1, json.dumps({'type': 'turn.failed', 'error': error}))
                self.assertFalse(result['account_cooldown'])
        tool = {'type': 'item.completed', 'item': {'type': 'command_execution',
                'aggregated_output': 'ERROR: ACCOUNT_QUOTA_EXCEEDED', 'exit_code': 1}}
        result = self.module.normalize_provider('codex', 0, self.codex(extra=[tool]))
        self.assertEqual(result['result'], 'CHECK_OK')
        self.assertFalse(result['account_cooldown'])
        vague = self.module.normalize_provider('codex', 1, 'Credit balance too low')
        self.assertFalse(vague['account_cooldown'])

    def test_block_is_code_findings_without_fallback(self):
        result = self.module.normalize_provider('codex', 0, self.codex('VERDICT: BLOCK\nF1 material defect'))
        self.assertEqual((result['result'], result['reason'], result['fallback_allowed']),
                         ('CHECK_FAILED', 'CODE_FINDINGS', False))

    def test_malformed_terminal_field_types_are_invalid_not_tracebacks(self):
        cases = [('codex', {'type': []}),
                 ('codex', {'type': 'turn.failed', 'error': {'code': 'quota_exceeded', 'scope': []}}),
                 ('codex', {'type': 'turn.completed', 'status': []}),
                 ('codex', {'type': 'turn.completed', 'is_error': []}),
                 ('claude', {'type': 'result', 'subtype': 'success', 'is_error': False,
                             'stop_reason': [], 'result': 'VERDICT: PASS'}),
                 ('claude', {'type': 'result', 'subtype': 'success', 'is_error': False,
                             'result': 'VERDICT: PASS\ud800'}),
                 ('claude', {'type': 'result', 'subtype': 'success', 'is_error': False,
                             'error': {'code': 'invalid_request'}, 'result': 'VERDICT: PASS'})]
        for provider, record in cases:
            with self.subTest(provider=provider, record=record):
                result = self.module.normalize_provider(provider, 0, json.dumps(record))
                self.assertEqual(result['result'], 'NO_RESULT')
                self.assertFalse(result['account_cooldown'])
        nested = '[' * 2000 + '0' + ']' * 2000
        self.assertEqual(self.module.normalize_provider('codex', 0, nested)['result'], 'NO_RESULT')

    def test_non_pr_stage_removes_all_generic_pass_markers(self):
        for stage in ('plan', 'code-inspection'):
            with self.subTest(stage=stage):
                report = ('PLAN' if stage == 'plan' else 'CODE_INSPECTION') + '_RESULT: ACCEPT\nEvidence quoted VERDICT: PASS.'
                rendered = self.module.stage_report(stage, report)
                self.assertNotIn('VERDICT: PASS', rendered)
                self.assertIn('_RESULT: ACCEPT', rendered)
        self.assertEqual(self.module.stage_report('pr', 'VERDICT: PASS'), 'VERDICT: PASS')

    def test_inspection_and_plan_acceptance_cannot_become_pr_pass(self):
        for marker in ('PLAN_RESULT: ACCEPT', 'CODE_INSPECTION_RESULT: ACCEPT'):
            with self.subTest(marker=marker), self.assertRaises(OSError):
                self.module.stage_report('pr', marker)

    def test_pr_pass_cannot_become_plan_or_inspection_acceptance(self):
        for stage in ('plan', 'code-inspection'):
            with self.subTest(stage=stage), self.assertRaises(OSError):
                self.module.stage_report(stage, 'VERDICT: PASS')

    def test_claude_provider_error_before_success_still_wins(self):
        records = [{'type': 'error', 'error': {'code': 'quota_exceeded'}},
                   {'type': 'result', 'subtype': 'success', 'is_error': False, 'result': 'VERDICT: PASS'}]
        result = self.module.normalize_provider('claude', 0, '\n'.join(map(json.dumps, records)))
        self.assertEqual((result['result'], result['reason'], result['account_cooldown']),
                         ('NO_RESULT', 'QUOTA', True))

    def test_duplicate_packet_blocks_are_warning_only(self):
        block = '```python\nprint("fixture")\n```\n'
        warnings = self.module.packet_warnings(block * 2)
        self.assertEqual(len(warnings), 1)
        self.assertIn('warning only', warnings[0])

    def test_fallback_has_remaining_budget_and_never_a_third_call(self):
        quota = json.dumps({'type': 'turn.failed', 'error': {'code': 'insufficient_quota'}})
        valid = json.dumps({'type': 'result', 'subtype': 'success', 'is_error': False,
                            'result': 'VERDICT: PASS'})
        calls = []
        def run(command, prompt, cwd, timeout):
            calls.append((command[0], timeout))
            return (1, quota, '') if len(calls) == 1 else (0, valid, '')
        with tempfile.TemporaryDirectory() as temporary, \
             patch.object(self.module.shutil, 'which', return_value='fixture'), \
             patch.object(self.module, 'run', side_effect=run), \
             patch.object(self.module.time, 'monotonic', side_effect=[0, 0, 0, 721, 721]):
            source, report, reason = self.module.review_snapshot(Path(temporary), 'a' * 40, 'pr', 'Review', 'Evidence')
        self.assertEqual(calls, [('codex', 720), ('claude', 719)])
        self.assertEqual(report, 'VERDICT: PASS')
        self.assertIn('fallback', reason)


if __name__ == '__main__':
    unittest.main()
