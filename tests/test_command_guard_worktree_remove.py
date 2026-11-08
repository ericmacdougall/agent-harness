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


class WorktreeRemoveIndirect(WorktreeRemoveCase):
    """goodqa#15346: `git worktree remove` reached through xargs, find -exec, parallel or a wrapper has no literal target on
    the command line, and used to skip every refusal (--force included). Only the single verified literal form passes."""

    def forms(self):
        path = str(self.linked)
        lst = self.home / 'list.txt'
        lst.write_text(path + '\n')
        return (
            'echo %s | xargs git worktree remove --force' % path,
            'echo %s | xargs git worktree remove' % path,
            'xargs git worktree remove --force < %s' % lst,
            'xargs git worktree remove < %s' % lst,
            'cat %s | xargs -I{} git worktree remove --force {}' % lst,
            'find %s -maxdepth 0 -exec git worktree remove --force {} +' % path,
            'find %s -maxdepth 0 -exec git worktree remove {} \;' % path,
            'find %s -maxdepth 0 -exec git worktree remove --force {} \;' % self.base,
            'echo %s | parallel git worktree remove --force' % path,
            'parallel git worktree remove --force ::: %s' % path,
            'echo %s | env xargs git worktree remove --force' % path,
            "sh -c 'echo %s | xargs git worktree remove --force'" % path,
            "bash -c 'xargs git worktree remove --force < %s'" % lst,
            'env git worktree remove --force %s' % path,
            "sh -c 'git worktree remove --force %s'" % path,
            'git worktree remove --force %s' % path,
            'echo %s | xargs git -C %s worktree remove --force' % (path, self.primary),
            # red-team H1/H2: options with a separate value hide the command from a table-driven parser
            'xargs -J %% git worktree remove --force %% < %s' % lst,
            'xargs -R 1 -I {} git worktree remove --force {} < %s' % lst,
            'xargs -S 255 -I {} git worktree remove --force {} < %s' % lst,
            'xargs --max-args 1 git worktree remove --force < %s' % lst,
            'xargs --arg-file %s git worktree remove --force' % lst,
            'xargs --delimiter X git worktree remove --force < %s' % lst,
            'xargs --max-procs 4 git worktree remove --force < %s' % lst,
            'echo %s | parallel -j 4 git worktree remove --force' % path,
            'parallel -j 4 git worktree remove --force ::: %s' % path,
            'parallel -a %s git worktree remove --force' % lst,
            'parallel --arg-file %s git worktree remove --force' % lst,
            'parallel --jobs 4 rm -rf %s' % path,
            # red-team M1-M5
            'git --attr-source HEAD worktree remove --force %s' % path,
            "git -c alias.wr='worktree remove' wr --force %s" % path,
            "git -c 'alias.wr=!git worktree remove --force' wr %s" % path,
            '/usr/libexec/git-core/git-worktree remove --force %s' % path,
            'git-worktree remove --force %s' % path,
            'git $(echo worktree) remove --force %s' % path,
            'git worktree $(echo remove) --force %s' % path,
            'git "$W" remove --force %s' % path,
            'git worktree move %s %s/moved' % (path, self.home),
        )

    def test_indirect_forms_block_and_the_lone_literal_form_still_passes(self):
        passed = [c for c in self.forms() if self.decide(c)[0] != 'block']
        self.assertEqual(passed, [], 'an indirect worktree remove slipped through')
        self.assertEqual(self.decide('git worktree remove %s' % self.linked)[0], 'allow')

    def test_harmless_indirect_git_stays_allowed(self):
        lst = self.home / 'list.txt'
        lst.write_text(str(self.linked) + '\n')
        for c in ('xargs git worktree list < %s' % lst, 'find %s -maxdepth 0 -exec git status {} +' % self.linked,
                  'xargs -J %% git -C %% status < %s' % lst, 'git worktree add %s/new' % self.home,
                  'parallel -j 4 git status ::: %s' % self.linked):
            self.assertEqual(self.decide(c)[0], 'allow', c)

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

    def test_delta_n1_n3_shell_in_a_scan_blind_subdir_alias_or_the_git_dir_blocks(self):
        # an upper-cased spelling of the target is another path string but the same directory on a case-folding volume
        ok = 'git -C %s worktree remove %s' % (self.primary, self.linked)
        gitdir = Path(git(self.linked, 'rev-parse', '--absolute-git-dir'))
        self.assertEqual(self.decide(ok, cwd=gitdir)[0], 'block')                 # N3: the admin folder is deleted too
        self.assertEqual(self.decide('git -C %s worktree remove %s' % (gitdir, self.linked), cwd=self.home)[0], 'block')
        deep = self.linked / 'node_modules' / 'a' / 'b'
        deep.mkdir(parents=True)
        (self.primary / '.git/info/exclude').write_text('node_modules/\n')
        upper = Path(str(self.linked).replace('/linked', '/LINKED'))
        if upper.exists():  # case-insensitive volume (macOS default): the spelling differs, the directory is the same
            self.assertEqual(self.decide(ok, cwd=upper / 'node_modules' / 'a' / 'b')[0], 'block')
        self.assertEqual(self.decide(ok, cwd=deep)[0], 'block')


class WorktreeRemoveIndirectRound2(WorktreeRemoveCase):
    """goodqa#15346 delta review M1-M4 (BLOCK on 546a1d1): an option flood, a quoted parallel command, a built or hidden
    alias, and aliases defined outside -c must not turn a protected worktree remove into an allow."""

    def forms(self):
        path = str(self.linked)
        rep = ' '.join(['-R 1'] * 12)
        return (
            # M1: the command sits past any fixed word bound
            'xargs %s git worktree remove --force < /dev/null' % rep,
            'parallel %s git worktree remove --force ::: %s' % (' '.join(['-j 4'] * 13), path),
            'ls -d %s | xargs -o -t -p -r -x -0 -E X -L 1 %s git worktree remove --force' % (path, ' '.join(['-R 1'] * 9)),
            # M2: parallel with the command as one quoted word, or as the data when no command is given
            "parallel -j 4 'git worktree remove --force {}' ::: %s" % path,
            "parallel --jobs 4 'rm -rf {}' ::: %s" % path,
            'parallel -j 4 "git worktree remove --force %s" ::: x' % path,
            "parallel ::: 'git worktree remove --force %s'" % path,
            # M3: built subcommand or non-literal alias, target on stdin or in a placeholder
            'echo %s | xargs git $(echo worktree) remove --force' % path,
            'echo %s | xargs git "$W" remove --force' % path,
            'find %s -maxdepth 0 -exec git $(echo worktree) remove --force {} +' % path,
            'echo %s | xargs git -c alias.wt=worktree wt remove --force' % path,
            'echo %s | xargs git -c alias.wr="$A" wr' % path,
            "echo %s | xargs git -c 'alias.wr=!f(){ git \"worktree\" \"re\"\"move\" --force \"$@\"; }; f' wr" % path,
            # M4: aliases defined without -c
            "W='worktree remove --force' git --config-env=alias.wr=W wr %s" % path,
            "W='worktree remove --force' git --config-env alias.wr=W wr %s" % path,
            "GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=alias.wr GIT_CONFIG_VALUE_0='worktree remove --force' git wr %s" % path,
            "export GIT_CONFIG_KEY_0=alias.wr; git wr %s" % path,
            "git config alias.wr 'worktree remove --force'",
            "git config --global alias.wr 'worktree remove --force'",
            'git -c include.path=/tmp/x wr %s' % path,
        )

    def test_round2_forms_block(self):
        passed = [c for c in self.forms() if self.decide(c)[0] != 'block']
        self.assertEqual(passed, [], 'a round-2 bypass slipped through')

    def test_round2_harmless_forms_stay_allowed(self):
        lst = self.home / 'list.txt'
        lst.write_text(str(self.linked) + '\n')
        for c in ("git -c alias.st=status st", "git -c alias.lg='log --oneline' lg", 'git worktree list',
                  'xargs git worktree list < %s' % lst, "parallel -j 4 'git -C {} status' ::: %s" % self.primary,
                  'parallel -j 4 git status ::: %s' % self.linked, "parallel ::: 'echo hello'",
                  'xargs ls < %s' % lst, 'find %s -maxdepth 0 -exec echo {} +' % self.linked,
                  'git config user.name x', 'git "$cmd" status'):
            self.assertEqual(self.decide(c)[0], 'allow', c)

    def test_lone_literal_form_still_passes(self):
        self.assertEqual(self.decide('git worktree remove %s' % self.linked)[0], 'allow')


class WorktreeRemoveParallelRebuildEdges(WorktreeRemoveCase):
    """goodqa#15346 round 3 self-probes: forms past the fixed list, found while building the rebuild."""

    def test_edges_block(self):
        p, h = str(self.linked), str(self.home)
        for c in ("git -c alias.wr='worktree remove' wr %s" % p,   # an expansion never earns the lone-literal exemption
                  "git -c alias.st=status -c alias.st='worktree remove --force' st %s" % p,  # the last -c wins
                  'git -c alias.a=b -c alias.b="worktree remove --force" a %s' % p,  # a chain
                  'git -C %s wr linked' % self.base,                 # relative to -C
                  'git wr --path=%s' % p,
                  "git config --global alias.wr '--git-dir=x worktree remove --force'",
                  'parallel ::: "$UNKNOWN"',                         # parallel re-parses: the value may be a command line
                  'parallel "$UNKNOWN" ::: %s' % p,
                  "parallel 'rm -rf {= s/x// =}' ::: %sx" % h,
                  'parallel --arg-sep @@ git worktree remove --force @@ %s' % p,
                  'parallel --bogus-opt git status ::: a',           # an unknown option: the template start is unknown
                  'parallel --jo 4 git status ::: a',                # ambiguous abbreviation (--jobs, --joblog)
                  'parallel -kj4 git worktree remove --force ::: %s' % p,
                  'parallel rm -rf {2} ::: a ::: %s' % h,
                  'parallel --dnr @@ "rm -rf @@" ::: %s/x' % h,
                  "parallel --colsep , 'rm -rf {1}' ::: %s,x" % h,
                  "parallel -N2 'rm -rf {2}' ::: a %s" % h,
                  "echo %s | parallel 'git wr {}'" % p,
                  'echo %s | parallel' % p,
                  'parallel --semaphore git worktree remove --force %s' % p,
                  'sem --id x git wr %s' % p,
                  "parallel -j 4 sh -c 'git worktree remove --force {}' ::: %s" % p,  # the reading that keeps the quotes
                  'git config rename-section foo alias',
                  'parallel echo ::: %s' % ' '.join('x%d' % n for n in range(cg.PAR_LINE_LIMIT + 1))):
            self.assertEqual(self.decide(c)[0], 'block', c[:120])

    def test_every_line_is_rebuilt_past_the_old_caps(self):
        # the protected path sits past the old 32 and 50 item caps; the same list without it stays allowed
        many = ' '.join('x%d' % n for n in range(200))
        self.assertEqual(self.decide("parallel 'rm -rf {}' ::: %s %s" % (many, self.home))[0], 'block')
        self.assertEqual(self.decide("parallel 'rm -rf {}' ::: %s" % many)[0], 'allow')

    def test_plan_builds_the_cartesian_product_and_placeholders(self):
        words = lambda *t: [cg._literal_word(x) for x in t]
        lines, mode, error = cg.parallel_plan(words('echo', '{2}', '{1}', ':::', 'a', 'b', ':::', 'c', 'd'))
        self.assertIsNone(error)
        self.assertEqual(mode, 'args')
        self.assertEqual(lines, ["echo 'c' 'a'", "echo 'd' 'a'", "echo 'c' 'b'", "echo 'd' 'b'"])
        self.assertEqual(cg.parallel_plan(words('e', '{.}', '{/}', '{//}', '{/.}', ':::', '/d/f.x'))[0],
                         ["e '/d/f' 'f.x' '/d' 'f'"])
        self.assertEqual(cg.parallel_plan(words(':::', 'make a', 'make b'))[0], ['make a', 'make b'])
        self.assertEqual(cg.parallel_plan(words('echo', ':::', 'a b'))[0], ["echo 'a b'"])

    def test_edges_stay_allowed(self):
        for c in ('parallel -j 4 echo ::: a b c', 'parallel --bar -k echo ::: a', 'parallel -I @@ echo @@ ::: ok',
                  'git co main', 'git -C %s st' % self.linked, 'git lg src/*.py', "git config alias.wl 'worktree list'"):
            self.assertEqual(self.decide(c)[0], 'allow', c)


class WorktreeRemoveRound3RedTeam(WorktreeRemoveCase):
    """goodqa#15346 red-team BLOCK on 28c9a0f. OUT is a linked worktree outside every protected root: raw_sensitive cannot
    rescue a fail-open there, so a budget stop must still end in a block."""

    def setUp(self):
        super().setUp()
        self.out = self.home / 'wt' / 'x'
        git(self.primary, 'worktree', 'add', '-q', '-b', 'x', str(self.out))

    def env(self):
        return dict(P=str(self.linked), OUT=str(self.out), H=str(self.home), B=str(self.base), PR=str(self.primary))

    BLOCK = (
        # M1 M2 option table and empty sources
        'parallel --trim lr git worktree remove --force ::: {P}',
        'parallel git worktree remove --force ::: ::: {P}',
        'parallel rm -rf ::: {H} :::',
        'parallel --arg-sep @@ rm -rf @@ @@ {H}',
        # M3 names that are not built-ins on every supported git
        "git -c alias.bisect--helper='worktree remove --force' bisect--helper {P}",
        "git -c alias.rebase--interactive='worktree remove --force' rebase--interactive {P}",
        "git -c alias.history='worktree remove --force' history {P}",
        # M4 M5 a later key the scan cannot read, or the alias.NAME.command spelling
        "git -c alias.wr=status -c alias.wr.command='worktree remove --force' wr {P}",
        "git -c alias.wr=status --config-env=alias.wr.command=V wr {P}",
        'git -c alias.wr=status -c "$(echo alias.wr)=worktree remove --force" wr {P}',
        'K=$(echo alias.wr); git -c alias.wr=status -c "$K=worktree remove --force" wr {P}',
        # M6 the line defines the alias but hides what it does
        'git -c "alias.wr=$(cat f)" wr',
        "V='worktree remove --force {P}' git --config-env=alias.wr=V wr",
        "GIT_CONFIG_PARAMETERS=\"'alias.wr=worktree remove --force {P}'\" git wr",
        'git -c include.path={H}/evil wr',
        'git ' + ' '.join('-c alias.a%d=a%d' % (n, n + 1) for n in range(1, 10))
        + " -c 'alias.a10=worktree remove --force {P}' a1",
        # M7 only leading assignments reach git
        'git wr {P} GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=alias.wr GIT_CONFIG_VALUE_0=status',
        'echo {P} | xargs git wr GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=alias.wr GIT_CONFIG_VALUE_0=status',
        'GIT_CONFIG_COUNT=1; GIT_CONFIG_KEY_0=alias.wr; GIT_CONFIG_VALUE_0=status; git wr {P}',
        # M8 -q with the placeholder as a whole word
        "parallel -q sh -c {{}} ::: 'git worktree remove --force {P}'",
        # M9 negative positions, trailing slash, other parens
        "parallel 'echo {{1}}; rm -rf {{-1}}' ::: x ::: {H}",
        "parallel 'rm -rf {{//}}' ::: {H}/x/",
        "parallel --parens ,,,, 'rm -rf ,,s:^:{B}/:,,' ::: linked",
        # M10 arguments that parallel splits
        "parallel rm -rf ::: $'a\\n'{H}",
        'parallel -d , rm -rf ::: a,{H}',
        'parallel --colsep , rm -rf ::: a,{H}',
        "parallel -C ' ' rm -rf ::: 'a {H}'",
        # M11 options that run code or move the job
        "parallel --limit 'rm -rf {H}' echo ::: a",
        "parallel --filter 'system(q(rm -rf {H}))' echo ::: a",
        "parallel --tagstring '{{= system(q(rm -rf {H})) =}}' echo ::: a",
        "parallel --results '{{= system(q(rm -rf {H})) =}}' echo ::: a",
        "parallel --compress --compress-program 'rm -rf {H}' echo ::: a",
        "parallel --ssh 'rm -rf {H};:' -S x echo ::: a",
        "parallel -S 'rm -rf {H};: x' echo ::: a",
        'parallel --wd {B} rm -rf linked ::: x',
        # M12 configuration from the environment, and option values built at run time
        "PARALLEL='git worktree remove --force' parallel ::: {P}",
        "PARALLEL='-I XX' parallel 'echo {{1}}; rm -rf XX' ::: {H}",
        "export PARALLEL='-I XX'; parallel 'echo {{1}}; rm -rf XX' ::: {H}",
        'R=$(echo XX); parallel -I "$R" \'echo {{1}}; rm -rf XX\' ::: {H}',
        # M13 a budget stop inside the rebuild is a refusal, outside every protected path too
        "parallel 'rm -f {{1}} {{2}} {{3}} {{4}} {{5}} {{6}}' ::: a b c d ::: a b c d ::: a b c d ::: a b c d ::: a b c d "
        "::: a b c d ; git worktree remove --force {OUT}",
        # M14 xargs or a placeholder supplies the subcommand or the verb
        'echo "worktree remove --force {P}" | xargs git',
        'echo "remove --force {P}" | xargs git worktree',
        'echo remove | xargs -I{{}} git worktree {{}} --force {P}',
        'find {P} -name remove -exec git worktree {{}} --force {P} \\;',
        'echo {P} | xargs git "$S"',
        # M15 parallel and sem under find -exec
        'find {P} -maxdepth 0 -exec parallel git worktree remove --force ::: {{}} +',
        'find {P} -exec sem rm -rf {{}} +',
        'find {P} -execdir sem rm -rf {{}} +',
        'find {P} -exec nice parallel rm -rf ::: {{}} +',
        # M16 M17
        'git config --rename-section --global foo alias',
        'git --shallow-file status worktree remove --force {P}',
        # M19 a cd inside an alias or a parallel job stays there
        "git -c 'alias.x=!cd /tmp' x ; rm -rf linked",
        "parallel 'cd /tmp' ::: x ; rm -rf linked",
        # minor, cheap: a config location or PATH set next to an unknown subcommand, a glued short option
        'GIT_CONFIG_GLOBAL={H}/evil git wr',
        'HOME={H}/fake git wr',
        'PATH={H}/bin:$PATH git -c alias.wr=status wr {P}',
        'GIT_EXEC_PATH={H}/bin git -c alias.wr=status wr {P}',
        'git wr -f{P}',
    )

    ALLOW = (
        # F1 the textbook use of parallel: a transform of a glob or an unknown value
        'parallel convert {{}} {{.}}.png ::: *.jpg',
        "parallel 'mv {{}} {{.}}.bak' ::: *.txt",
        "parallel 'cp {{}} out/{{/}}' ::: src/*",
        "parallel 'echo {{/}}' ::: \"$F\"",
        # F2 information options run nothing
        'sem --wait',
        'parallel --version',
        'parallel --number-of-cores',
        'parallel --number-of-threads',
        'parallel --help',
        # still rebuilt
        'parallel -j4 -k echo ::: a b',
        "parallel -q echo 'a b' ::: c",
        'parallel rm -rf ::: :::',
    )

    def test_red_team_forms_block(self):
        env = self.env()
        passed = [c for c in self.BLOCK if self.decide(c.format(**env), cwd=self.base if 'rm -rf linked' in c else None)[0]
                  != 'block']
        self.assertEqual(passed, [], 'a red-team form slipped through')

    def test_red_team_false_refusals_are_cleared(self):
        env = self.env()
        blocked = [c for c in self.ALLOW if self.decide(c.format(**env))[0] != 'allow']
        self.assertEqual(blocked, [], 'a harmless form is blocked')

    def test_cwd_is_kept_for_a_later_command_that_is_harmless(self):
        self.assertEqual(self.decide("parallel 'cd /tmp' ::: x ; ls")[0], 'allow')

    def test_plan_semantics(self):
        words = lambda *t: [cg._literal_word(x) for x in t]
        self.assertEqual(cg.parallel_plan(words('rm', ':::', ':::', 'b'))[0], ["rm '' 'b'"])
        self.assertEqual(cg.parallel_plan(words('rm', ':::', ':::'))[0], [])
        self.assertEqual(cg.parallel_plan(words('e', '{-1}', ':::', 'a', ':::', 'b'))[0], ["e 'b'"])
        self.assertEqual(cg.parallel_plan(words('e', '{//}', ':::', '/h/x/'))[0], ["e '/h'"])
        self.assertEqual(cg.parallel_plan(words('rm', ':::', 'a\nb'))[0], ["rm 'a'", "rm 'b'"])
        self.assertEqual(cg.parallel_plan(words('-q', 'sh', '-c', '{}', ':::', 'a b'))[0], ["'sh' '-c' 'a b'"])
        self.assertEqual(cg.parallel_plan(words('--version'))[0], [])
        self.assertIsNotNone(cg.parallel_plan(words('--trim', 'lr', 'rm', ':::', 'a'))[2])

    def test_a_budget_stop_inside_the_rebuild_is_a_refusal(self):
        # below the line limit, so only the budget stops it; nothing here names a protected path, so raw text cannot help.
        # The limit is past what lexing the command costs, so the stop lands inside the launcher.
        plain = self.home / 'plain'
        plain.mkdir()
        items = ' '.join('x%d' % n for n in range(900))
        command = "parallel 'rm -f {}' ::: %s" % items
        self.assertEqual(self.decide(command, cwd=plain)[0], 'allow')  # fine with the normal budget
        self.policy = dict(self.policy, limits=dict(self.policy['limits'], max_nodes=16000))
        verdict = self.decide(command, cwd=plain)
        self.assertEqual(verdict[0], 'block')
        self.assertIn('parallel-unverifiable', str(verdict))

    def test_a_word_after_the_command_is_data_not_the_fed_command(self):
        for c in ("find . -name '*.py' | xargs grep -n git", "echo x | xargs printf '%s\\n' git", 'xargs -n 1 grep git < f'):
            self.assertEqual(self.decide(c, cwd=self.home)[0], 'allow', c)
        for c in ('echo "worktree remove --force x" | xargs -R 1 git', 'echo x | xargs -n 1 git'):
            self.assertEqual(self.decide(c, cwd=self.home)[0], 'block', c)

    def test_a_named_external_on_path_is_not_an_alias(self):
        with mock.patch.object(cg.shutil, 'which', lambda name: '/x/git-lfs' if name == 'git-lfs' else None):
            self.assertEqual(self.decide('git ls-files | xargs git lfs track')[0], 'allow')
            self.assertEqual(self.decide('git wr %s' % self.linked)[0], 'block')
            self.assertEqual(self.decide('PATH=/x git lfs track %s' % self.linked)[0], 'block')
        with mock.patch.object(cg.shutil, 'which', lambda name: None):
            self.assertEqual(self.decide('git ls-files | xargs git lfs track')[0], 'block')


class WorktreeRemoveIndirectRound3(WorktreeRemoveCase):
    """goodqa#15346 round-2 delta review (BLOCK on c70e378). Git ignores an alias that shadows a built-in, so any
    subcommand outside a static built-in list is treated as a possible alias: it may not act on a protected path or on
    input from stdin, xargs or a placeholder. parallel and sem lines are rebuilt the way GNU parallel builds them
    (word join, cartesian product of the ::: sources, placeholder substitution) and each line is judged as a script."""

    def env(self):
        lst = self.home / 'list.txt'
        lst.write_text(str(self.linked) + '\n')
        return dict(P=str(self.linked), L=str(lst), PR=str(self.primary), H=str(self.home), B=str(self.base),
                    MANY=' '.join('x%d' % n for n in range(60)))

    BLOCK = (
        # parallel: several ::: sources, numbered placeholders, no command given, quoted sh -c, data lines
        'parallel ::: git ::: worktree ::: remove ::: --force ::: {P}',
        'parallel git ::: worktree ::: remove ::: {P}',
        'parallel git worktree {{1}} --force {{2}} ::: remove ::: {P}',
        "parallel 'git worktree {{1}} --force {{2}}' ::: remove ::: {P}",
        'parallel sh -c "\'git worktree remove --force {{}}\'" ::: {P}',
        "parallel ::: 'cd {B}; git worktree remove --force linked'",
        "parallel ::: 'X=1 git worktree remove --force {P}'",
        "parallel 'rm -rf {{}}' ::: {MANY} {H}",
        "parallel -j 4 'rm -rf {{}}' ::: {MANY} {P}",
        "parallel 'rm -rf {{.}}' ::: {H}.x",
        "parallel -I @@ 'rm -rf @@' ::: {H}",
        "parallel 'rm -rf {{//}}' ::: {H}/x",
        "parallel -a {L} 'rm -rf {{}}'",
        "parallel 'rm -rf {{}}' :::: {L}",
        "parallel 'git wr --force {{}}' ::: {P}",
        # sem is GNU parallel --semaphore
        'sem git worktree remove --force {P}',
        # a subcommand that is not a built-in may be an alias defined anywhere
        'git wr {P}',
        'echo {P} | xargs git wr',
        'echo {P} | xargs git wr --force',
        'echo {P} | xargs -n 1 git wr',
        'find {P} -maxdepth 0 -exec git wr --force {{}} +',
        'git --exec-path worktree remove --force {P}',
        'git -c core.alias=x wr {P}',
        'GIT_CONFIG_GLOBAL={H}/evil git wr {P}',
        'echo {P} | GIT_CONFIG_GLOBAL={H}/evil xargs git wr',
        'export GIT_CONFIG_GLOBAL={H}/evil ; echo {P} | xargs git wr',
        'GIT_CONFIG_SYSTEM={H}/evil git wr {P}',
        'HOME={H}/fake git wr {P}',
        'XDG_CONFIG_HOME={H}/x git wr {P}',
        "env GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=alias.wr GIT_CONFIG_VALUE_0='worktree remove --force' git wr {P}",
        "echo {P} | env GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=alias.wr GIT_CONFIG_VALUE_0='worktree remove --force' "
        "xargs git wr",
        "printf -v GIT_CONFIG_KEY_0 alias.wr ; export GIT_CONFIG_KEY_0 GIT_CONFIG_COUNT=1 "
        "GIT_CONFIG_VALUE_0='worktree remove --force' ; echo {P} | xargs git wr",
        "git config --global foo.wr 'worktree remove --force' ; git config --global --rename-section foo alias ; "
        "git wr {P}",
        "printf '[alias]\\n\\twr = worktree remove --force\\n' > {H}/evil ; GIT_CONFIG_GLOBAL={H}/evil git wr {P}",
        # alias values whose quotes git strips (split_cmdline)
        "echo {P} | xargs git -c 'alias.wr=\"work\"\"tree\" remove --force' wr",
        "echo {P} | xargs git -c 'alias.wr=\"work\"\"tree\" \"re\"\"move\"' wr --force",
        "git config --global alias.wr '\"work\"\"tree\" remove --force'",
        "git config --global alias.wr 'work\\tree remove --force'",
        "git config --global alias.wr \"'work'tree remove --force\"",
        "git config --global alias.wr '\"work\"\"tree\" remove --force' ; git wr {P}",
    )

    ALLOW = (
        # an alias provably defined on this command line to a harmless built-in
        "git -c alias.wl='worktree list' wl",
        "git -c alias.lg='log --oneline' lg {P}",
        'git -c alias.st=status st',
        'GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=alias.st GIT_CONFIG_VALUE_0=status git st',
        'export GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=alias.st GIT_CONFIG_VALUE_0=status; git log -1',
        'export GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=alias.st GIT_CONFIG_VALUE_0=status; git -C {P} status',
        # a built-in is never an alias, whatever config says
        'git -c alias.status=x status',
        'git st',
        'echo a | xargs git log -1 --',
        'git config --global include.path ~/.gitconfig.local',
        "git config --global alias.lg 'log --oneline --graph'",
        # parallel lines that rebuild to harmless commands
        "parallel 'rm -rf {{}}' ::: {MANY}",
        "parallel -j 4 'git -C {{}} status' ::: {PR} {P}",
        'parallel -j 4 git -C {{}} log -1 ::: {PR} {P}',
        "parallel echo ::: 'rm -rf x'",
        "parallel 'echo {{}}' ::: 'rm -rf x'",
        "parallel ::: 'make test' 'make lint'",
        "parallel 'cd {{}} && git status' ::: {PR} {P}",
        'parallel -j 4 git status ::: {P}',
        'sem echo done',
    )

    def test_round3_reproducers_block(self):
        env = self.env()
        passed = [c for c in self.BLOCK if self.decide(c.format(**env))[0] != 'block']
        self.assertEqual(passed, [], 'a round-3 reproducer slipped through')

    def test_round3_harmless_forms_stay_allowed(self):
        env = self.env()
        blocked = [c for c in self.ALLOW if self.decide(c.format(**env))[0] != 'allow']
        self.assertEqual(blocked, [], 'a harmless form is blocked')

    def test_lone_literal_form_still_passes(self):
        self.assertEqual(self.decide('git worktree remove %s' % self.linked)[0], 'allow')
