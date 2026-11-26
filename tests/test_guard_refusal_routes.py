"""goodqa#16943: guard refusals name the sanctioned route instead of the log-backup procedure.

H7: every refused `git worktree remove` (a compound line, --force, an ssh payload, a container) names the
`ah worktree-remove` route as CONSTANT text with placeholders, and a stale-tracking-ref refusal names a constant
`git fetch --prune <the remote that holds the deleted branch>` step that states when pruning is safe. The route advice
fills in no path, host or remote of its own: review rounds of PR 333 showed that any value the guard resolves can differ
from what the kernel or git resolves. The verifier reason printed before the advice is the verifier's own text, unchanged
by this ticket, and may name a remote or ignored files of the worktree (asserted below). Every refusal stays a refusal.
Real temporary repositories under a temporary HOME, fake network and ssh only; commands are data passed to decide()."""

import json
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
import ah_worktree  # noqa: E402
import command_guard as cg  # noqa: E402

URL = 'https://github.com/acme/widgets.git'
REMOTE = ah_worktree.REMOTE_HOSTS[0]  # the one remote host the route serves; never spelled out here
GIT_ENV = {key: value for key, value in os.environ.items() if not key.startswith('GIT_')}
GIT_ENV.update(GIT_CONFIG_GLOBAL='/dev/null', GIT_CONFIG_NOSYSTEM='1', GIT_AUTHOR_NAME='t',
               GIT_AUTHOR_EMAIL='t@example.invalid', GIT_COMMITTER_NAME='t', GIT_COMMITTER_EMAIL='t@example.invalid')
# the fixed advice, spelled out here so a change to it is a visible test change (byte-stable)
ROUTE = ('python3 -I ~/.claude/hooks/ah.py worktree-remove --host <local|%s> --path <absolute path of the worktree> '
         '--reason "<why>" [--remote-auth] (one worktree per call, no --force, audited; add --remote-auth when the '
         'repository is private, so the host reads its remote with its own credentials)' % REMOTE)
SAFE_PRUNE = ('but only when every fetch refspec of that remote writes under refs/remotes/<that remote>/ and pruneTags is '
              'not set; prune deletes local branches or tags through any other destination (for example +refs/*:refs/* '
              'or +refs/heads/*:refs/heads/up/*)')
PRUNE = ('run `git fetch --prune <the remote that holds the deleted branch>` in the registry repository (the checkout '
         'the worktree was added from) first, ' + SAFE_PRUNE)
NEXT_STALE = ('run `git fetch --prune <the remote that holds the deleted branch>` in the registry repository (the '
              'checkout the worktree was added from) on the same host first, ' + SAFE_PRUNE +
              '. Then repeat the same ah worktree-remove call')


def git(cwd, *args):
    done = subprocess.run(['git', *args], cwd=str(cwd), env=GIT_ENV, capture_output=True, text=True, check=False)
    if done.returncode:
        raise AssertionError('git %s: %s' % (' '.join(args), done.stderr))
    return done.stdout.strip()


class Home(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='cg-routes-')
        self.addCleanup(self.temp.cleanup)
        self.home = Path(os.path.realpath(self.temp.name))
        patch = mock.patch.dict(os.environ, {'HOME': str(self.home)})
        patch.start()
        self.addCleanup(patch.stop)
        self.work = self.home / '.agent-harness/work/S'
        self.work.mkdir(parents=True)
        self.policy = cg.load_policy(path=str(self.home / 'missing-policy.json'))

    def decide(self, command, cwd=None):
        cwd = str(cwd or self.work)
        compiled = cg.Compiled(self.policy, home=str(self.home), cwd=cwd)
        return cg.decide(command, compiled, cwd=cwd)

    def blocked(self, command, cwd=None):
        verdict, message = self.decide(command, cwd)
        self.assertEqual(verdict, 'block', command)
        return message


class FixedText(unittest.TestCase):
    """The advice is byte-stable: fixed text, placeholders only."""

    def test_the_route_and_prune_texts_are_fixed(self):
        self.assertEqual(getattr(cg, 'WORKTREE_ROUTE', None), ROUTE)
        self.assertEqual(getattr(cg, 'WORKTREE_PRUNE_STEP', None), PRUNE)
        self.assertEqual(getattr(ah_worktree, 'NEXT_STALE', None), NEXT_STALE)
        self.assertNotIn('--all', PRUNE + NEXT_STALE)

    def test_the_route_hosts_agree_with_ah_worktree(self):
        self.assertEqual(tuple(cg.WORKTREE_ROUTE_HOSTS), tuple(ah_worktree.REMOTE_HOSTS))


# class WorktreeRoutes was removed on 2026-11-24: the hook form of `git worktree remove` no longer runs the strict
# verifier or prints its reason; it follows the role rules (tests/test_guard_delete_redesign.py).


class StaleRefNextStep(unittest.TestCase):
    """The delegated route keeps its stale-ref rule; its answer names the fixed next step."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)

    def run_remove(self, answer, host=REMOTE, authenticated=False):
        def runner(argv, **kwargs):
            return subprocess.CompletedProcess(argv, 1, json.dumps(answer), '')
        return ah_worktree.remove(host, '/home/u/scratch/wt', 'merged and published', authenticated, 's1', 'a1',
                                  self.home, runner)

    @staticmethod
    def stale(**kw):
        base = {'removable': False, 'removed': False, 'verifier': ah_worktree.VERIFIER_VERSION, 'head': 'a' * 40,
                'reason': 'a remote-tracking ref is stale or names a moved/deleted remote branch; fetch --prune first',
                'repo': '/home/u/repos/base', 'urls': {'origin': [URL], 'upstream': [URL]}}
        base.update(kw)
        return base

    def test_a_stale_ref_refusal_gives_the_fixed_next_step_on_both_hosts(self):
        for host in (REMOTE, 'local'):
            result = self.run_remove(self.stale(), host=host, authenticated=True)
            self.assertFalse(result['removed'])
            self.assertEqual(result['next'], NEXT_STALE)
            for value in ('/home/u', 'origin', 'upstream', '--all', 'ssh '):
                self.assertNotIn(value, result['next'], (host, value))

    def test_no_next_step_for_other_refusals(self):
        self.assertNotIn('next', self.run_remove(self.stale(reason='the working tree is not clean')))


if __name__ == '__main__':
    unittest.main()
