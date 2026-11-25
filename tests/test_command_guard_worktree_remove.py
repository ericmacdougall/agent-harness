"""Narrow git worktree remove exemption: real temporary repositories, fake network only.

Raw commands are data passed to decide(). The delegated tests remove only disposable fixtures.
"""

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
HOOKS = Path(os.environ.get('CG_HOOKS_DIR') or ROOT / 'harness/hooks')
sys.path.insert(0, str(HOOKS))
import command_guard as cg  # noqa: E402

URL = 'https://github.com/acme/widgets.git'
GIT_ENV = {key: value for key, value in os.environ.items() if not key.startswith('GIT_')}
GIT_ENV.update(GIT_CONFIG_GLOBAL='/dev/null', GIT_CONFIG_NOSYSTEM='1', GIT_AUTHOR_NAME='t',
               GIT_AUTHOR_EMAIL='t@example.invalid', GIT_COMMITTER_NAME='t', GIT_COMMITTER_EMAIL='t@example.invalid')


def git(cwd, *args, check=True):
    done = subprocess.run(['git', *args], cwd=str(cwd), env=GIT_ENV, capture_output=True, text=True, check=False)
    if check and done.returncode:
        raise AssertionError('git %s: %s' % (' '.join(args), done.stderr))
    return done.stdout.strip()


class WorktreeRemoveCase(unittest.TestCase):
    """The strict verifier (linked_worktree_remove_refusal), which lifecycle_cleanup's managed copies still use. Since
    2026-11-24 the hook form `git worktree remove` follows the role rules instead (tests/test_guard_delete_redesign.py),
    so the hook-form assertions that were here are gone."""
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='cg-worktree-remove-')
        self.addCleanup(self.temp.cleanup)
        self.home = Path(os.path.realpath(self.temp.name))
        self.old_home = os.environ.get('HOME')
        os.environ['HOME'] = str(self.home)
        self.addCleanup(self._restore_home)
        self.base = self.home / '.agent-harness/work/S/T'
        self.primary = self.base / 'primary'
        self.linked = self.base / 'linked'
        self.primary.mkdir(parents=True)
        git(self.primary, 'init', '-q', '-b', 'main')
        (self.primary / 'a.txt').write_text('one\n')
        git(self.primary, 'add', 'a.txt')
        git(self.primary, 'commit', '-q', '-m', 'one')
        git(self.primary, 'remote', 'add', 'origin', URL)
        git(self.primary, 'worktree', 'add', '-q', '-b', 'linked', str(self.linked))
        self.head = git(self.linked, 'rev-parse', 'HEAD')
        git(self.primary, 'update-ref', 'refs/remotes/origin/main', self.head)
        git(self.primary, 'update-ref', 'refs/remotes/origin/linked', self.head)
        self.live = {'refs/heads/main': self.head, 'refs/heads/linked': self.head}
        patch = mock.patch.object(cg, 'REMOTE_LS', lambda url, repo, timeout: dict(self.live))
        patch.start()
        self.addCleanup(patch.stop)
        self.policy = cg.load_policy(path=str(self.home / 'missing-policy.json'))

    def _restore_home(self):
        if self.old_home is None:
            os.environ.pop('HOME', None)
        else:
            os.environ['HOME'] = self.old_home

    def decide(self, command, cwd=None):
        cwd = str(cwd or self.primary)
        compiled = cg.Compiled(self.policy, home=str(self.home), cwd=cwd)
        return cg.decide(command, compiled, cwd=cwd)

    def refusal(self, path=None, cwd=None):
        return cg.linked_worktree_remove_refusal(str(path or self.linked), str(cwd or self.primary), self.policy)

    def publish_linked_head(self):
        self.head = git(self.linked, 'rev-parse', 'HEAD')
        self.live['refs/heads/linked'] = self.head
        git(self.primary, 'update-ref', 'refs/remotes/origin/linked', self.head)

    def test_exact_clean_registered_published_linked_top_is_allowed(self):
        self.assertIsNone(self.refusal())
        # The full-clone verifier intentionally cannot judge this shape: .git is a file.
        self.assertIn('.git is not a real directory', cg.reproducible_clone_refusal(str(self.linked), self.policy))

    def test_published_detached_head_is_allowed_but_unpublished_detached_head_is_not(self):
        git(self.linked, 'checkout', '-q', '--detach')
        (self.linked / 'local.txt').write_text('local\n')
        git(self.linked, 'add', 'local.txt')
        git(self.linked, 'commit', '-q', '-m', 'local only')
        self.assertIn('detached-unpublished', self.refusal())

    def test_modified_staged_untracked_and_unique_ignored_content_block(self):
        (self.linked / 'a.txt').write_text('changed\n')
        self.assertIn('not clean', self.refusal())
        git(self.linked, 'add', 'a.txt')
        git(self.linked, 'reset', '-q', '--hard', 'HEAD')
        (self.linked / 'notes.txt').write_text('unique\n')
        (self.linked / 'notes.txt').unlink()
        (self.primary / '.git/info/exclude').write_text('secret.txt\n')
        (self.linked / 'secret.txt').write_text('unique ignored\n')
        self.assertIn('ignored', self.refusal())

    def backed_ignored_fixture(self):
        (self.primary / '.git/info/exclude').write_text('.cache/\n')
        folder = self.linked / '.cache'
        folder.mkdir()
        paths = [folder / name for name in ('first.tsbuildinfo', 'second.tsbuildinfo')]
        policy = dict(self.policy, marker=dict(self.policy['marker'], recent_change_seconds=0))

        class SyntheticMirror:
            def remote_types(self):
                return {'dropbox': 'dropbox'}

            def verify(self, local_root, manifest, remote):
                return cg.VerifyResult(True, checked=len(manifest))

        for path in paths:
            path.write_text('synthetic cache bytes\n')
            cg.approve_delete(str(path), 'dropbox:fixture/cache', verifier=SyntheticMirror(),
                              home=str(self.home), policy=policy)
        return folder, paths, policy

    def test_backed_ignored_leaves_preview_then_consume_in_delegated_remove_only(self):
        folder, paths, policy = self.backed_ignored_fixture()
        self.assertIn('ignored', self.refusal(), 'raw git must not acquire backup authorization')
        idle = {'busy': [], 'unreadable': [], 'skipped': [], 'failed': False}
        with mock.patch.object(cg, '_pinned_home', return_value=str(self.home)), \
                mock.patch.object(cg, 'busy_scan', return_value=idle):
            preview = cg.verify_worktree(str(self.linked), policy=policy)
            self.assertTrue(preview.get('removable'), preview)
            self.assertEqual(len(cg.load_marker(self.home)[0]), len(paths))
            result = cg.remove_worktree(str(self.linked), expect_head=self.head, policy=policy)
        self.assertTrue(result.get('removed'), result)
        self.assertFalse(self.linked.exists())
        self.assertEqual(cg.load_marker(self.home)[0], [])

    def test_backed_ignored_late_unapproved_sibling_preserves_all_markers(self):
        folder, paths, policy = self.backed_ignored_fixture()
        idle = {'busy': [], 'unreadable': [], 'skipped': [], 'failed': False}

        def late_change(*args):
            (folder / 'new.tsbuildinfo').write_text('unarchived content\n')
            return idle

        with mock.patch.object(cg, '_pinned_home', return_value=str(self.home)), \
                mock.patch.object(cg, 'busy_scan', side_effect=late_change):
            result = cg.remove_worktree(str(self.linked), expect_head=self.head, policy=policy)
        self.assertFalse(result['removed'])
        self.assertFalse(result['removable'])
        self.assertTrue(self.linked.exists())
        self.assertEqual(len(cg.load_marker(self.home)[0]), len(paths))

    def test_backed_ignored_preserves_bytes_with_same_size_and_restored_mtime(self):
        folder, paths, policy = self.backed_ignored_fixture()
        first = paths[0]
        info = first.stat()
        first.write_bytes(b'x' * info.st_size)
        os.utime(first, ns=(info.st_atime_ns, info.st_mtime_ns))
        idle = {'busy': [], 'unreadable': [], 'skipped': [], 'failed': False}
        with mock.patch.object(cg, '_pinned_home', return_value=str(self.home)), \
                mock.patch.object(cg, 'busy_scan', return_value=idle):
            self.assertTrue(cg.verify_worktree(str(self.linked), policy=policy)['removable'])
            result = cg.remove_worktree(str(self.linked), expect_head=self.head, policy=policy)
        self.assertFalse(result['removed'])
        self.assertEqual(first.read_bytes(), b'x' * info.st_size)
        self.assertEqual(len(cg.load_marker(self.home)[0]), len(paths))

    def test_backed_ignored_refuses_a_replaced_inode_or_links_and_mounts(self):
        folder, paths, policy = self.backed_ignored_fixture()
        with mock.patch.object(cg, '_pinned_home', return_value=str(self.home)):
            with mock.patch.object(cg, '_worktree_mount_clear', return_value=False):
                self.assertFalse(cg.verify_worktree(str(self.linked), policy=policy)['removable'])
            replaced = paths[0].with_name('replacement')
            replaced.write_bytes(paths[0].read_bytes())
            os.replace(replaced, paths[0])
            self.assertFalse(cg.verify_worktree(str(self.linked), policy=policy)['removable'])
            paths[0].unlink()
            paths[0].symlink_to(paths[1])
            self.assertFalse(cg.verify_worktree(str(self.linked), policy=policy)['removable'])
        self.assertEqual(len(cg.load_marker(self.home)[0]), len(paths))

    def test_backed_ignored_revoke_or_different_marker_set_refuses_removal(self):
        folder, paths, policy = self.backed_ignored_fixture()
        idle = {'busy': [], 'unreadable': [], 'skipped': [], 'failed': False}

        def revoke_during_final_check(*args):
            cg.revoke_delete(home=self.home)
            return idle

        with mock.patch.object(cg, '_pinned_home', return_value=str(self.home)), \
                mock.patch.object(cg, 'busy_scan', side_effect=revoke_during_final_check):
            result = cg.remove_worktree(str(self.linked), expect_head=self.head, policy=policy)
        self.assertFalse(result['removed'])
        self.assertTrue(all(path.exists() for path in paths))
        self.assertEqual(cg.load_marker(self.home)[0], [])

    def test_backed_ignored_rejects_no_backup_and_expired_marker_without_partial_spend(self):
        folder, paths, policy = self.backed_ignored_fixture()
        entries, _ = cg.load_marker(self.home)
        actual = next(entry for entry in entries if entry['path'] == str(paths[1]))
        for changes in ({'kind': cg.NO_BACKUP_KIND}, {'expires_at': time.time() - 1}):
            with self.subTest(changes=changes):
                replaced = dict(actual, **changes)
                cg._store_entry(replaced, str(paths[1]), time.time(), str(self.home))
                with mock.patch.object(cg, '_pinned_home', return_value=str(self.home)):
                    result = cg.remove_worktree(str(self.linked), expect_head=self.head, policy=policy)
                self.assertFalse(result['removed'])
                self.assertTrue(all(path.exists() for path in paths))
                self.assertEqual(len(cg.load_marker(self.home)[0]), len(paths))

    def test_late_consumed_leaf_preserves_other_grant_under_backed_lock(self):
        self.late_backed_invalidation('consume')

    def test_late_replaced_leaf_preserves_both_grants_under_backed_lock(self):
        self.late_backed_invalidation('replace')

    def test_late_revocation_refuses_backed_consumption_and_git_removal(self):
        self.late_backed_invalidation('revoke')

    def late_backed_invalidation(self, mutation):
        folder, paths, policy = self.backed_ignored_fixture()
        idle = {'busy': [], 'unreadable': [], 'skipped': [], 'failed': False}
        real_consume = cg._IgnoredBackups.consume
        real_recheck = cg.Approvals._recheck_backups
        rechecks, calls = [], []
        original, _ = cg.load_marker(self.home)

        def late(backups):
            self.assertEqual(set(backups.approvals.backup_records), set(map(str, paths)))
            calls.append(mutation)
            if mutation == 'consume':
                other = cg.Approvals(home=str(self.home), compiled=cg.Compiled(policy, home=str(self.home)))
                self.assertTrue(other.covers(str(paths[1]), backup_only=True))
                self.assertTrue(other.consume())
            elif mutation == 'replace':
                entry = next(row for row in original if row['path'] == str(paths[1]))
                # Same nonce: a generic nonce-count check cannot detect this changed signed grant.
                replacement = dict(entry, remote='dropbox:fixture/replaced-grant')
                cg._store_entry(replacement, str(paths[1]), time.time(), str(self.home))
            else:
                cg.revoke_delete(home=self.home)
            return real_consume(backups)

        def checked(approvals, *args):
            rechecks.append(True)
            return real_recheck(approvals, *args)

        with mock.patch.object(cg, '_pinned_home', return_value=str(self.home)), \
                mock.patch.object(cg, 'busy_scan', return_value=idle), \
                mock.patch.object(cg._IgnoredBackups, 'consume', late), \
                mock.patch.object(cg.Approvals, '_recheck_backups', checked), \
                mock.patch.object(cg, '_worktree_audit') as audit:
            result = cg.remove_worktree(str(self.linked), expect_head=self.head, policy=policy)
        self.assertEqual(calls, [mutation])
        self.assertFalse(result['removed'], result)
        self.assertTrue(all(path.exists() for path in paths))
        self.assertFalse(audit.called, 'refusal must precede the Git removal intent')
        remaining, _ = cg.load_marker(self.home)
        if mutation == 'revoke':
            self.assertEqual(remaining, [])
        else:
            self.assertEqual(rechecks, [True], 'must reach the actual locked backed recheck')
            first = next(row for row in original if row['path'] == str(paths[0]))
            self.assertIn(first, remaining, 'unaffected grant must remain intact')
            self.assertEqual(len(remaining), 1 if mutation == 'consume' else 2)

    def test_two_backed_removers_race_and_only_one_consumes_or_removes(self):
        folder, paths, policy = self.backed_ignored_fixture()
        idle = {'busy': [], 'unreadable': [], 'skipped': [], 'failed': False}
        rendezvous = threading.Barrier(2, timeout=15)
        real_consume, real_run = cg._IgnoredBackups.consume, subprocess.run
        results, errors, git_removals = [], [], []

        def synchronized(backups):
            self.assertEqual(len(backups.approvals.backup_records), 2)
            rendezvous.wait()
            return real_consume(backups)

        def spy(argv, *args, **kwargs):
            if 'worktree' in argv and 'remove' in argv:
                git_removals.append(list(argv))
            return real_run(argv, *args, **kwargs)

        def remove():
            try:
                results.append(cg.remove_worktree(str(self.linked), expect_head=self.head, policy=policy))
            except BaseException as error:
                errors.append(error)

        with mock.patch.object(cg, '_pinned_home', return_value=str(self.home)), \
                mock.patch.object(cg, 'busy_scan', return_value=idle), \
                mock.patch.object(cg._IgnoredBackups, 'consume', synchronized), \
                mock.patch.object(cg.subprocess, 'run', spy):
            workers = [threading.Thread(target=remove, daemon=True) for _ in range(2)]
            for worker in workers:
                worker.start()
            for worker in workers:
                worker.join(timeout=25)
            self.assertTrue(all(not worker.is_alive() for worker in workers))
        self.assertEqual(errors, [])
        self.assertEqual(sorted(row['removed'] for row in results), [False, True], results)
        self.assertEqual(len(git_removals), 1)
        self.assertNotIn('--force', git_removals[0])
        self.assertEqual(cg.load_marker(self.home)[0], [])
        self.assertFalse(self.linked.exists())

    def test_failed_git_removal_spends_backed_grants_and_retry_cannot_reuse_them(self):
        folder, paths, policy = self.backed_ignored_fixture()
        idle = {'busy': [], 'unreadable': [], 'skipped': [], 'failed': False}
        real_run, git_removals = subprocess.run, []

        def fail_remove(argv, *args, **kwargs):
            if 'worktree' in argv and 'remove' in argv:
                git_removals.append(list(argv))
                return subprocess.CompletedProcess(argv, 1, '', 'injected Git removal failure')
            return real_run(argv, *args, **kwargs)

        with mock.patch.object(cg, '_pinned_home', return_value=str(self.home)), \
                mock.patch.object(cg, 'busy_scan', return_value=idle), \
                mock.patch.object(cg.subprocess, 'run', fail_remove):
            result = cg.remove_worktree(str(self.linked), expect_head=self.head, policy=policy)
            self.assertFalse(result['removed'], result)
            self.assertIn('injected Git removal failure', result['reason'])
            self.assertEqual(cg.load_marker(self.home)[0], [])
            retry = cg.remove_worktree(str(self.linked), expect_head=self.head, policy=policy)
        self.assertFalse(retry['removed'], retry)
        self.assertEqual(len(git_removals), 1, 'retry must not reach Git with spent approvals')
        self.assertTrue(all(path.exists() for path in paths))

    def test_late_membership_sibling_during_final_idle_preserves_files_and_grants(self):
        self.late_membership('idle', 'sibling')

    def test_late_membership_root_during_final_idle_preserves_files_and_grants(self):
        self.late_membership('idle', 'root')

    def test_late_membership_sibling_during_lock_wait_preserves_files_and_grants(self):
        self.late_membership('lock', 'sibling')

    def test_late_membership_root_during_lock_wait_preserves_files_and_grants(self):
        self.late_membership('lock', 'root')

    def test_grants_expiring_during_locked_scope_check_spend_nothing(self):
        folder, paths, policy = self.backed_ignored_fixture()
        original, _ = cg.load_marker(self.home)
        idle = {'busy': [], 'unreadable': [], 'skipped': [], 'failed': False}
        real_scope = cg._IgnoredBackups.locked_scope_matches
        clock = mock.patch.object(cg.time, 'time', return_value=max(row['expires_at'] for row in original) + 1)
        advanced = []

        def slow_scope(backups):
            self.assertTrue(real_scope(backups), 'valid unchanged scope must reach the final expiry boundary')
            advanced.append(True)
            clock.start()
            return True

        try:
            with mock.patch.object(cg, '_pinned_home', return_value=str(self.home)), \
                    mock.patch.object(cg, 'busy_scan', return_value=idle), \
                    mock.patch.object(cg._IgnoredBackups, 'locked_scope_matches', slow_scope), \
                    mock.patch.object(cg, '_worktree_audit') as audit:
                result = cg.remove_worktree(str(self.linked), expect_head=self.head, policy=policy)
                self.assertFalse(audit.called, 'expired authority must not reach Git intent')
        finally:
            if advanced:
                clock.stop()
        self.assertEqual(advanced, [True])
        self.assertFalse(result['removed'], result)
        self.assertTrue(all(path.exists() for path in paths))
        self.assertEqual(cg.load_marker(self.home)[0], original)

    def late_membership(self, boundary, location):
        import fcntl
        folder, paths, policy = self.backed_ignored_fixture()
        addition = (folder if location == 'sibling' else self.linked) / 'unapproved.tsbuildinfo'
        original, _ = cg.load_marker(self.home)
        idle = {'busy': [], 'unreadable': [], 'skipped': [], 'failed': False}
        results, errors, idle_calls = [], [], []
        waiting = threading.Event()
        real_flock = fcntl.flock
        held = os.open(cg.state_dir(self.home) / cg.LOCK_NAME, os.O_WRONLY | os.O_CREAT, 0o600)
        if boundary == 'lock':
            real_flock(held, fcntl.LOCK_EX)

        def observed_idle(backups):
            idle_calls.append(True)
            if boundary == 'idle' and len(idle_calls) == 2:
                addition.write_text('new content with no recovery grant\n')
            return True

        def observed_flock(fd, operation):
            if boundary == 'lock' and operation == fcntl.LOCK_EX and fd != held:
                waiting.set()
            return real_flock(fd, operation)

        def remove():
            try:
                results.append(cg.remove_worktree(str(self.linked), expect_head=self.head, policy=policy))
            except BaseException as error:
                errors.append(error)

        try:
            with mock.patch.object(cg, '_pinned_home', return_value=str(self.home)), \
                    mock.patch.object(cg, 'busy_scan', return_value=idle), \
                    mock.patch.object(cg._IgnoredBackups, 'idle', observed_idle), \
                    mock.patch.object(fcntl, 'flock', observed_flock), \
                    mock.patch.object(cg, '_worktree_audit') as audit:
                if boundary == 'lock':
                    worker = threading.Thread(target=remove, daemon=True)
                    worker.start()
                    try:
                        self.assertTrue(waiting.wait(timeout=15), 'consumer never reached real approval lock')
                        addition.write_text('new content created while approval lock is held\n')
                    finally:
                        real_flock(held, fcntl.LOCK_UN)
                    worker.join(timeout=25)
                    self.assertFalse(worker.is_alive())
                else:
                    remove()
                self.assertFalse(audit.called, 'unapproved membership must refuse before Git removal intent')
        finally:
            real_flock(held, fcntl.LOCK_UN)
            os.close(held)
        self.assertEqual(errors, [])
        self.assertEqual(len(results), 1)
        self.assertFalse(results[0]['removed'], results)
        self.assertTrue(addition.exists(), 'new unapproved content must be retained')
        self.assertTrue(all(path.exists() for path in paths))
        self.assertEqual(cg.load_marker(self.home)[0], original, 'failure must spend no leaf grant')

    def test_unpushed_commit_and_remote_without_exact_head_block(self):
        (self.linked / 'local.txt').write_text('local\n')
        git(self.linked, 'add', 'local.txt')
        git(self.linked, 'commit', '-q', '-m', 'local only')
        self.assertIn('exact HEAD', self.refusal())
        self.publish_linked_head()
        self.live['refs/heads/linked'] = '0' * 40

    def test_stale_moved_deleted_offline_and_nonallowlisted_remotes_block(self):
        self.live['refs/heads/main'] = '0' * 40
        self.assertIn('stale', self.refusal())
        del self.live['refs/heads/main']
        self.assertIn('stale', self.refusal())
        self.live['refs/heads/main'] = self.head
        with mock.patch.object(cg, 'REMOTE_LS', lambda url, repo, timeout: None):
            self.assertIn('did not answer', self.refusal())
        git(self.primary, 'remote', 'set-url', 'origin', 'https://evil.example/acme/widgets.git')
        called = []
        with mock.patch.object(cg, 'REMOTE_LS', lambda *args: called.append(args) or dict(self.live)):
            self.assertIn('known hosting', self.refusal())
        self.assertEqual(called, [])

    def test_primary_current_unregistered_sibling_and_nested_worktrees_block(self):
        sibling = self.base / 'sibling'
        sibling.mkdir()
        (sibling / '.git').write_text('gitdir: /nowhere\n')
        nested = self.primary / 'nested'
        git(self.primary, 'worktree', 'add', '-q', '-b', 'nested', str(nested))
        self.assertIn('nested', self.refusal(nested))

    def test_gitlink_and_hidden_index_flags_block(self):
        (self.linked / 'a.txt').write_text('hidden edit\n')
        git(self.linked, 'update-index', '--assume-unchanged', 'a.txt')
        self.assertIn('hidden', self.refusal())
        git(self.linked, 'update-index', '--no-assume-unchanged', 'a.txt')
        git(self.linked, 'reset', '-q', '--hard', 'HEAD')
        git(self.linked, 'update-index', '--skip-worktree', 'a.txt')
        self.assertIn('hidden', self.refusal())
        git(self.linked, 'update-index', '--no-skip-worktree', 'a.txt')
        sub = self.linked / 'sub'
        sub.mkdir()
        git(sub, 'init', '-q', '-b', 'main')
        (sub / 'inner.txt').write_text('inner\n')
        git(sub, 'add', 'inner.txt')
        git(sub, 'commit', '-q', '-m', 'inner')
        git(self.linked, 'add', 'sub')
        git(self.linked, 'commit', '-q', '-m', 'embedded')
        self.publish_linked_head()
        self.assertIn('embedded repository', self.refusal())

    def test_verification_errors_fail_closed(self):
        with mock.patch.object(cg, '_git_out', side_effect=OSError('broken git')):
            self.assertIn('could not verify', self.refusal())


if __name__ == '__main__':
    unittest.main()


class WorktreeRemoveMerged(WorktreeRemoveCase):
    """goodqa#15334: the normal state after a merge and branch cleanup is a clean worktree whose HEAD is an ancestor of the
    remote default branch while its own remote branch is gone. That is published. Dirty, unmerged or unverifiable
    worktrees keep their refusals."""

    def advance_main(self):
        """origin/main moves on by one commit (objects present locally), and the worktree's own remote branch is deleted."""
        (self.primary / 'b.txt').write_text('two\n')
        git(self.primary, 'add', 'b.txt')
        git(self.primary, 'commit', '-q', '-m', 'two')
        new = git(self.primary, 'rev-parse', 'HEAD')
        git(self.primary, 'update-ref', 'refs/remotes/origin/main', new)
        self.live['refs/heads/main'] = new
        self.live.pop('refs/heads/linked', None)
        return new

    def test_head_merged_into_live_default_with_remote_branch_deleted_is_allowed(self):
        self.advance_main()
        self.assertIsNone(self.refusal())

    def test_control_unmerged_dirty_and_unverifiable_stay_refused(self):
        self.advance_main()
        # an unpublished commit in the worktree: not an ancestor of live main
        (self.linked / 'local.txt').write_text('local\n')
        git(self.linked, 'add', 'local.txt'); git(self.linked, 'commit', '-q', '-m', 'local only')
        self.assertIsNotNone(self.refusal())
        git(self.linked, 'reset', '-q', '--hard', 'HEAD~1')
        self.assertIn('reflog', self.refusal())  # the abandoned commit now lives only in this worktree's reflog
        # dirty
        (self.linked / 'a.txt').write_text('changed\n')
        self.assertIn('not clean', self.refusal())
        git(self.linked, 'checkout', '-q', 'a.txt')
        # live default sha unknown locally (cannot prove ancestry)
        self.live['refs/heads/main'] = 'f' * 40
        self.assertIsNotNone(self.refusal())
        # remote did not answer
        self.live['refs/heads/main'] = git(self.primary, 'rev-parse', 'HEAD')
        with mock.patch.object(cg, 'REMOTE_LS', lambda url, repo, timeout: None):
            self.assertIn('did not answer', self.refusal())

    def test_ancestry_of_a_stale_remote_tracking_ref_only_passes_when_merged(self):
        new = self.advance_main()
        # a tracking ref for a deleted remote branch that holds an UNMERGED commit stays refused
        git(self.primary, 'checkout', '-q', '-b', 'side', 'main~1')
        (self.primary / 'c.txt').write_text('side\n')
        git(self.primary, 'add', 'c.txt'); git(self.primary, 'commit', '-q', '-m', 'side')
        git(self.primary, 'update-ref', 'refs/remotes/origin/side', git(self.primary, 'rev-parse', 'HEAD'))
        git(self.primary, 'checkout', '-q', 'main')
        self.assertIn('stale', self.refusal())

    def test_calling_directory_outside_any_repository_is_not_an_error(self):
        # the read-only check returned "could not verify (ValueError)" when cwd was a plain directory such as $HOME
        plain = self.home / 'plain'; plain.mkdir()
        self.assertIsNone(self.refusal(cwd=plain))

    def test_commit_reachable_only_from_the_worktree_reflog_or_private_refs_blocks(self):
        # red-team F1: a detached commit made and then abandoned lives only in this worktree's admin directory
        self.advance_main()
        git(self.linked, 'checkout', '-q', '--detach')
        (self.linked / 'wip.txt').write_text('wip\n')
        git(self.linked, 'add', 'wip.txt'); git(self.linked, 'commit', '-q', '-m', 'WIP detached')
        git(self.linked, 'checkout', '-q', '--detach', 'main')
        self.assertIn('reflog', self.refusal())

    def test_private_worktree_ref_blocks_and_branch_kept_commits_do_not(self):
        self.advance_main()
        git(self.linked, 'update-ref', 'refs/worktree/keep', git(self.linked, 'rev-parse', 'HEAD'))
        self.assertIn('private refs', self.refusal())
        git(self.linked, 'update-ref', '-d', 'refs/worktree/keep')
        self.assertIsNone(self.refusal())
        # a commit that only a shared branch keeps survives the removal, so it does not block
        (self.linked / 'kept.txt').write_text('kept\n')
        git(self.linked, 'add', 'kept.txt'); git(self.linked, 'commit', '-q', '-m', 'on branch')
        git(self.linked, 'checkout', '-q', '--detach', 'main')
        self.assertIsNone(self.refusal())
