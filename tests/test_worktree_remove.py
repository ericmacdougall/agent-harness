"""goodqa#15253 item 3: `git worktree remove` of a clean linked worktree whose HEAD is on a live origin branch needs no
Dropbox backup. Removing a worktree never deletes a commit or a branch; what it can lose is uncommitted work, an
unpushed detached HEAD, and ignored files. The first two still block; ignored files are the safety given up.

Real git repositories in a temporary HOME; the only fake is the network (cg.REMOTE_LS), as in test_reproducible_clone.
"""
import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_reproducible_clone import CloneCase, git  # noqa: E402


class WorktreeCase(CloneCase):
    def setUp(self):
        super().setUp()
        self.wt = self.base / 'wt'
        git(self.clone, 'worktree', 'add', '-q', '-b', 'feat', str(self.wt))

    def remove(self, *flags, path=None):
        return self.verdict('git -C %s worktree remove %s %s' % (self.clone, ' '.join(flags), path or self.wt))


class Allowed(WorktreeCase):
    def test_clean_worktree_on_a_pushed_commit(self):
        self.assertAllowed(self.remove())

    def test_ignored_files_do_not_block(self):
        # the safety this item gives up: ignored files in the worktree are lost with it
        (self.wt / '.git-info-exclude-probe').write_text('x')
        exclude = Path(git(self.clone, 'rev-parse', '--git-common-dir'))
        if not exclude.is_absolute():
            exclude = self.clone / exclude
        (exclude / 'info').mkdir(exist_ok=True)
        (exclude / 'info' / 'exclude').write_text('.git-info-exclude-probe\n')
        self.assertAllowed(self.remove())


class MustRefuse(WorktreeCase):
    def test_force_flag(self):
        self.assertRefused(self.remove('--force'))
        self.assertRefused(self.remove('-f'))

    def test_modified_file(self):
        (self.wt / 'a.txt').write_text('changed\n')
        self.assertRefused(self.remove())

    def test_untracked_file(self):
        (self.wt / 'new.txt').write_text('new\n')
        self.assertRefused(self.remove())

    def test_unpushed_commit_on_detached_head(self):
        (self.wt / 'b.txt').write_text('two\n')
        git(self.wt, 'add', '.')
        git(self.wt, 'commit', '-q', '-m', 'local only')
        git(self.wt, 'checkout', '-q', '--detach')
        self.assertRefused(self.remove())

    def test_unpushed_commit_on_branch(self):
        (self.wt / 'b.txt').write_text('two\n')
        git(self.wt, 'add', '.')
        git(self.wt, 'commit', '-q', '-m', 'local only')
        self.assertRefused(self.remove())

    def test_remote_moved_since_fetch(self):
        self.live['refs/heads/main'] = 'f' * 40  # a force-push or a new commit the clone has not fetched
        self.assertRefused(self.remove())

    def test_remote_silent(self):
        self.live.clear()
        self.assertRefused(self.remove())

    def test_not_a_linked_worktree(self):
        self.assertRefused(self.remove(path=self.clone))

    def test_symlinked_path(self):
        link = self.base / 'wt-link'
        os.symlink(self.wt, link)
        self.assertRefused(self.remove(path=link))

    def test_prune_is_unchanged(self):
        self.assertRefused(self.verdict('git -C %s worktree prune %s' % (self.clone, self.wt)))


if __name__ == '__main__':
    unittest.main()
