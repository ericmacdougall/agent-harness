"""Narrow git worktree remove exemption: real temporary repositories, fake network only.

Commands are data passed to decide(); this suite never executes the removal being judged.
"""

import os
from pathlib import Path
import subprocess
import sys
import tempfile
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
        self.assertEqual(self.decide('git worktree remove %s' % self.linked)[0], 'allow')
        self.assertEqual(self.decide('git worktree remove -- %s' % self.linked)[0], 'allow')
        # The full-clone verifier intentionally cannot judge this shape: .git is a file.
        self.assertIn('.git is not a real directory', cg.reproducible_clone_refusal(str(self.linked), self.policy))

    def test_published_detached_head_is_allowed_but_unpublished_detached_head_is_not(self):
        git(self.linked, 'checkout', '-q', '--detach')
        self.assertEqual(self.decide('git worktree remove %s' % self.linked)[0], 'allow')
        (self.linked / 'local.txt').write_text('local\n')
        git(self.linked, 'add', 'local.txt')
        git(self.linked, 'commit', '-q', '-m', 'local only')
        self.assertIn('detached-unpublished', self.refusal())
        self.assertEqual(self.decide('git worktree remove %s' % self.linked)[0], 'block')

    def test_modified_staged_untracked_and_unique_ignored_content_block(self):
        (self.linked / 'a.txt').write_text('changed\n')
        self.assertIn('not clean', self.refusal())
        self.assertEqual(self.decide('git worktree remove %s' % self.linked)[0], 'block')
        git(self.linked, 'add', 'a.txt')
        self.assertEqual(self.decide('git worktree remove %s' % self.linked)[0], 'block')
        git(self.linked, 'reset', '-q', '--hard', 'HEAD')
        (self.linked / 'notes.txt').write_text('unique\n')
        self.assertEqual(self.decide('git worktree remove %s' % self.linked)[0], 'block')
        (self.linked / 'notes.txt').unlink()
        (self.primary / '.git/info/exclude').write_text('secret.txt\n')
        (self.linked / 'secret.txt').write_text('unique ignored\n')
        self.assertIn('ignored', self.refusal())
        self.assertEqual(self.decide('git worktree remove %s' % self.linked)[0], 'block')

    def test_unpushed_commit_and_remote_without_exact_head_block(self):
        (self.linked / 'local.txt').write_text('local\n')
        git(self.linked, 'add', 'local.txt')
        git(self.linked, 'commit', '-q', '-m', 'local only')
        self.assertIn('exact HEAD', self.refusal())
        self.assertEqual(self.decide('git worktree remove %s' % self.linked)[0], 'block')
        self.publish_linked_head()
        self.assertEqual(self.decide('git worktree remove %s' % self.linked)[0], 'allow')
        self.live['refs/heads/linked'] = '0' * 40
        self.assertEqual(self.decide('git worktree remove %s' % self.linked)[0], 'block')

    def test_stale_moved_deleted_offline_and_nonallowlisted_remotes_block(self):
        self.live['refs/heads/main'] = '0' * 40
        self.assertIn('stale', self.refusal())
        self.assertEqual(self.decide('git worktree remove %s' % self.linked)[0], 'block')
        del self.live['refs/heads/main']
        self.assertIn('stale', self.refusal())
        self.live['refs/heads/main'] = self.head
        with mock.patch.object(cg, 'REMOTE_LS', lambda url, repo, timeout: None):
            self.assertIn('did not answer', self.refusal())
            self.assertEqual(self.decide('git worktree remove %s' % self.linked)[0], 'block')
        git(self.primary, 'remote', 'set-url', 'origin', 'https://evil.example/acme/widgets.git')
        called = []
        with mock.patch.object(cg, 'REMOTE_LS', lambda *args: called.append(args) or dict(self.live)):
            self.assertIn('known hosting', self.refusal())
        self.assertEqual(called, [])

    def test_symlink_alias_dotdot_glob_variable_force_compound_and_substitution_block(self):
        alias = self.base / 'alias'
        alias.symlink_to(self.linked, target_is_directory=True)
        commands = [
            'git worktree remove %s' % alias,
            'git worktree remove %s/T/../linked' % self.base,
            'git worktree remove %s/lin*' % self.base,
            'git worktree remove $LINKED',
            'git worktree remove --force %s' % self.linked,
            'git worktree remove %s --force' % self.linked,
            'git worktree remove %s && true' % self.linked,
            'true && git worktree remove %s' % self.linked,
            'git worktree remove $(printf %s) ' % self.linked,
            'git worktree remove %s %s' % (self.linked, self.linked),
            'git worktree prune %s' % self.linked,
        ]
        for command in commands:
            with self.subTest(command=command):
                self.assertEqual(self.decide(command)[0], 'block')

    def test_primary_current_unregistered_sibling_and_nested_worktrees_block(self):
        self.assertEqual(self.decide('git worktree remove %s' % self.primary)[0], 'block')
        self.assertEqual(self.decide('git worktree remove %s' % self.linked, cwd=self.linked)[0], 'block')
        sibling = self.base / 'sibling'
        sibling.mkdir()
        (sibling / '.git').write_text('gitdir: /nowhere\n')
        self.assertEqual(self.decide('git worktree remove %s' % sibling)[0], 'block')
        nested = self.primary / 'nested'
        git(self.primary, 'worktree', 'add', '-q', '-b', 'nested', str(nested))
        self.assertIn('nested', self.refusal(nested))
        self.assertEqual(self.decide('git worktree remove %s' % nested)[0], 'block')

    def test_gitlink_and_hidden_index_flags_block(self):
        (self.linked / 'a.txt').write_text('hidden edit\n')
        git(self.linked, 'update-index', '--assume-unchanged', 'a.txt')
        self.assertIn('hidden', self.refusal())
        self.assertEqual(self.decide('git worktree remove %s' % self.linked)[0], 'block')
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
        self.assertEqual(self.decide('git worktree remove %s' % self.linked)[0], 'block')

    def test_verification_errors_fail_closed(self):
        with mock.patch.object(cg, '_git_out', side_effect=OSError('broken git')):
            self.assertIn('could not verify', self.refusal())
            self.assertEqual(self.decide('git worktree remove %s' % self.linked)[0], 'block')


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
        self.assertEqual(self.decide('git worktree remove %s' % self.linked)[0], 'allow')

    def test_control_unmerged_dirty_and_unverifiable_stay_refused(self):
        self.advance_main()
        # an unpublished commit in the worktree: not an ancestor of live main
        (self.linked / 'local.txt').write_text('local\n')
        git(self.linked, 'add', 'local.txt'); git(self.linked, 'commit', '-q', '-m', 'local only')
        self.assertIsNotNone(self.refusal())
        self.assertEqual(self.decide('git worktree remove %s' % self.linked)[0], 'block')
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
        self.assertEqual(self.decide('git worktree remove %s' % self.linked, cwd=plain)[0], 'allow')

    def test_commit_reachable_only_from_the_worktree_reflog_or_private_refs_blocks(self):
        # red-team F1: a detached commit made and then abandoned lives only in this worktree's admin directory
        self.advance_main()
        git(self.linked, 'checkout', '-q', '--detach')
        (self.linked / 'wip.txt').write_text('wip\n')
        git(self.linked, 'add', 'wip.txt'); git(self.linked, 'commit', '-q', '-m', 'WIP detached')
        git(self.linked, 'checkout', '-q', '--detach', 'main')
        self.assertIn('reflog', self.refusal())
        self.assertEqual(self.decide('git worktree remove %s' % self.linked)[0], 'block')

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


class WorktreeRemoveDashC(WorktreeRemoveCase):
    """A subagent's shell resets to $HOME on every call, so the only way to name the registry repository is one literal
    -C. Every other -C shape, and every refusal the plain form has, must still block."""

    def test_literal_dash_c_repo_is_allowed_and_keeps_every_refusal(self):
        plain = self.home / 'plain'; plain.mkdir()
        ok = 'git -C %s worktree remove %s' % (self.primary, self.linked)
        self.assertEqual(self.decide(ok, cwd=plain)[0], 'allow')
        self.assertEqual(self.decide('git -C %s worktree remove -- %s' % (self.primary, self.linked), cwd=plain)[0], 'allow')
        blocked = (
            'git -C %s worktree remove %s' % (self.primary, self.linked) + ' --force',
            'git -C ../primary worktree remove %s' % self.linked,
            'git -C %s -C %s worktree remove %s' % (self.primary, self.primary, self.linked),
            'git -C $HOME worktree remove %s' % self.linked,
            'git -C "%s" worktree remove %s' % (self.primary, self.linked),
            'git -C %s worktree remove %s; true' % (self.primary, self.linked),
            'git -C %s worktree remove %s %s' % (self.primary, self.linked, self.primary),
            'git -C %s worktree remove %s' % (self.linked, self.linked),          # cannot remove the current worktree
            'git -C %s/nonexistent worktree remove %s' % (self.primary, self.linked),
            'git -C %s worktree remove %s' % (self.primary, self.primary),        # the primary is not removable
        )
        passed = [c for c in blocked if self.decide(c, cwd=plain)[0] != 'block']
        self.assertEqual(passed, [], 'a -C shape slipped through')
        (self.linked / 'a.txt').write_text('changed\n')
        self.assertEqual(self.decide(ok, cwd=plain)[0], 'block')

    def test_red_team_shell_inside_the_target_and_unrelated_repo_block(self):
        ok = 'git -C %s worktree remove %s' % (self.primary, self.linked)
        sub = self.linked / 'sub'; sub.mkdir()
        for cwd in (self.linked, sub):  # F1: the plain form refuses a shell inside the target; so must -C
            self.assertEqual(self.decide(ok, cwd=cwd)[0], 'block', cwd)
        other = self.home / 'other'; other.mkdir()
        git(other, 'init', '-q', '-b', 'main')
        git(other, 'remote', 'add', 'origin', URL)
        self.assertEqual(self.decide('git -C %s worktree remove %s' % (other, self.linked), cwd=self.home)[0], 'block')  # F2
        self.assertEqual(self.decide(ok, cwd=self.home)[0], 'allow')
