"""goodqa#16943 (H16): the delegated worktree removal admits an agent worktree nested in its own primary checkout.

Admitted shape, exactly: <primary worktree top>/.claude/worktrees/agent-<letters and digits>, the layout agent worktrees
are created in. Everything else the verifier checks stays as it was. Refused (must-fail):
- a target that contains another worktree (removing it would delete that worktree);
- any other nested shape (<repo>/src/wt, .claude/worktrees/<not agent-*>, a deeper path, inside a linked worktree);
- a target whose containing checkout tracks a path under it;
- a locked worktree (refused up front, nested or not);
- a symlinked folder that would lend the admitted spelling to another nested place, a dirty or unpublished agent worktree, and a caller standing inside the target.
Real temporary repositories under a temporary HOME; the network is faked."""

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


def git(cwd, *args):
    done = subprocess.run(['git', *args], cwd=str(cwd), env=GIT_ENV, capture_output=True, text=True, check=False)
    if done.returncode:
        raise AssertionError('git %s: %s' % (' '.join(args), done.stderr))
    return done.stdout.strip()


class NestedAgentWorktree(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='cg-nested-')
        self.addCleanup(self.temp.cleanup)
        self.home = Path(os.path.realpath(self.temp.name))
        patch = mock.patch.dict(os.environ, {'HOME': str(self.home)})
        patch.start()
        self.addCleanup(patch.stop)
        self.primary = self.home / '.agent-harness' / 'work' / 'S' / 'T' / 'proj'  # a harness work root: the hook form applies
        self.primary.mkdir(parents=True)
        git(self.primary, 'init', '-q', '-b', 'main')
        (self.primary / '.gitignore').write_text('.claude/worktrees/\n')
        (self.primary / 'a.txt').write_text('one\n')
        git(self.primary, 'add', '.gitignore', 'a.txt')
        git(self.primary, 'commit', '-q', '-m', 'one')
        git(self.primary, 'remote', 'add', 'origin', URL)
        self.head = git(self.primary, 'rev-parse', 'HEAD')
        git(self.primary, 'update-ref', 'refs/remotes/origin/main', self.head)
        self.live = {'refs/heads/main': self.head}
        patch = mock.patch.object(cg, 'REMOTE_LS', lambda url, repo, timeout: dict(self.live))
        patch.start()
        self.addCleanup(patch.stop)
        self.policy = cg.load_policy(path=str(self.home / 'missing-policy.json'))
        self.agent = self.add('.claude/worktrees/agent-a1b2c3')

    def add(self, rel, base=None, branch=None):
        """A linked worktree at <base or primary>/<rel>, on its own branch, published at the primary's HEAD."""
        path = (base or self.primary) / rel
        name = branch or 'b-' + rel.replace('/', '-').replace('.', '')
        git(self.primary, 'worktree', 'add', '-q', '-b', name, str(path), 'main')
        git(self.primary, 'update-ref', 'refs/remotes/origin/' + name, self.head)
        self.live['refs/heads/' + name] = self.head
        return path

    def refusal(self, path, cwd=None):
        return cg.linked_worktree_remove_refusal(str(path), str(cwd or self.primary), self.policy)

    # ---- admitted

    def test_a_clean_published_agent_worktree_in_its_primary_is_removed_by_the_delegated_route(self):
        self.assertIsNone(self.refusal(self.agent))
        self.assertTrue(cg.verify_worktree(str(self.agent))['removable'])
        result = cg.remove_worktree(str(self.agent), expect_head=self.head)
        self.assertTrue(result['removed'], result.get('reason'))
        self.assertFalse(self.agent.exists())
        self.assertTrue((self.primary / 'a.txt').exists())  # the containing checkout is untouched

    def test_the_hook_form_is_unchanged_and_still_refuses_it(self):
        # the PreToolUse exemption judges only literal tops its path classes call harness work state; a .claude path is
        # not one, so the raw command keeps its refusal and the audited `ah worktree-remove` route is the only way in
        compiled = cg.Compiled(self.policy, home=str(self.home), cwd=str(self.primary))
        verdict = cg.decide('git worktree remove %s' % self.agent, compiled, cwd=str(self.primary))
        self.assertEqual(verdict[0], 'block', verdict)
        self.assertTrue(self.agent.exists())

    # ---- refused

    def test_a_target_that_contains_another_worktree_stays_refused(self):
        outer = self.add('outer-wt', base=self.home)
        inner = self.add('.claude/worktrees/agent-d4e5', base=outer)
        self.assertIn('nested', self.refusal(outer))
        self.assertIsNotNone(self.refusal(inner))  # inside a LINKED worktree: not the admitted shape
        self.assertTrue(outer.exists() and inner.exists())

    def test_other_nested_shapes_stay_refused(self):
        for rel in ('src/wt', '.claude/worktrees/x123', '.claude/worktrees/agent-a_b', '.claude/worktrees/agent-',
                    '.claude/worktrees/agent-f00/deeper', '.claude/wt/agent-f01', 'claude/worktrees/agent-f02'):
            path = self.add(rel)
            self.assertIn('nested', self.refusal(path) or '', rel)

    def test_a_target_the_containing_checkout_tracks_a_path_under_is_refused(self):
        blob = subprocess.run(['git', 'hash-object', '-w', '--stdin'], cwd=str(self.primary), env=GIT_ENV, input='x\n',
                              capture_output=True, text=True, check=True).stdout.strip()
        git(self.primary, 'update-index', '--add', '--cacheinfo', '100644,%s,.claude/worktrees/agent-a1b2c3/x' % blob)
        self.assertIn('tracks', self.refusal(self.agent) or '')

    def test_a_locked_worktree_is_refused_up_front(self):
        git(self.primary, 'worktree', 'lock', '--reason', 'claude agent agent-a1b2c3 (pid 1 start x)', str(self.agent))
        self.assertIn('locked', self.refusal(self.agent) or '')
        plain = self.add('plain-wt', base=self.home)
        git(self.primary, 'worktree', 'lock', str(plain))
        self.assertIn('locked', self.refusal(plain) or '')
        self.assertFalse(cg.remove_worktree(str(self.agent), expect_head=self.head)['removed'])
        self.assertTrue(self.agent.exists())

    def test_a_symlinked_worktrees_folder_does_not_borrow_the_admitted_shape(self):
        # <primary>/.claude/worktrees is a symlink to another folder of the primary: the worktree really lives at
        # <primary>/scratch/agent-c0ffee, which is not the admitted shape, so it stays refused under either spelling
        real = self.primary / 'scratch'
        real.mkdir()
        (self.primary / '.git' / 'info' / 'exclude').write_text('scratch/\n')
        (self.primary / '.claude').mkdir(exist_ok=True)
        os.symlink(str(real), str(self.primary / '.claude' / 'linked'))
        path = self.primary / '.claude' / 'linked' / 'agent-c0ffee'
        git(self.primary, 'worktree', 'add', '-q', '-b', 'linkwt', str(path), 'main')
        git(self.primary, 'update-ref', 'refs/remotes/origin/linkwt', self.head)
        self.live['refs/heads/linkwt'] = self.head
        self.assertIsNotNone(self.refusal(path))
        self.assertIn('nested', self.refusal(real / 'agent-c0ffee') or '')
        self.assertTrue((real / 'agent-c0ffee').exists())

    def test_a_dirty_or_unpublished_agent_worktree_is_still_refused(self):
        (self.agent / 'a.txt').write_text('edited\n')
        self.assertIn('not clean', self.refusal(self.agent) or '')
        git(self.agent, 'checkout', '-q', '--', 'a.txt')
        (self.agent / 'b.txt').write_text('two\n')
        git(self.agent, 'add', 'b.txt')
        git(self.agent, 'commit', '-q', '-m', 'local only')
        self.assertIsNotNone(self.refusal(self.agent))

    def test_a_caller_inside_the_target_is_refused(self):
        self.assertIn('itself', self.refusal(self.agent, cwd=self.agent) or '')


if __name__ == '__main__':
    unittest.main()
