"""goodqa#15307 (defect 9): a lessons owner ran `git checkout --detach origin/main` in the blog drip's dedicated source
checkout (~/sites-seo/t2-drip-src on t2-dev); the 13:00Z drip run then refused and paused. A directory marked with a
`.harness-owned` file (or listed in the policy's owned_checkouts) must not be changed by an agent's git command. Reads,
fetch, linked worktrees and restoring the declared branch stay allowed. Corpus rows are data and never run."""

import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'harness/hooks'))
import command_guard as cg  # noqa: E402

REFUSED = (
    'cd {d} && git checkout --detach origin/main',
    'cd {d} && git checkout -q --detach origin/main',
    'git -C {d} checkout origin/main',
    'git -C {d} switch --detach origin/main',
    'git -C {d} reset --hard origin/main',
    'cd {d} && git pull',
    'cd {d} && git clean -fd',
    'cd {d} && git stash',
    'cd {d} && git checkout -f main',
    'cd {d} && git checkout -B main origin/main',
    'cd {d} && git rebase origin/main',
    'cd {d}/sub && git checkout other-branch',
    "ssh t2-dev 'cd {d} && git fetch origin && git checkout -q --detach origin/main'",
)
ALLOWED = (
    'cd {d} && git status',
    'cd {d} && git fetch origin',
    'git -C {d} log --oneline -3',
    'git -C {d} diff origin/main',
    'cd {d} && git checkout main',
    'git -C {d} switch main',
    'git -C {d} worktree add {w} origin/main',
    'cd {w} && git checkout --detach origin/main',
    'cd {u} && git checkout --detach origin/main',
)


class OwnedCheckout(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(); self.addCleanup(tmp.cleanup)
        self.home = Path(os.path.realpath(tmp.name))
        p = mock.patch.dict(os.environ, {'HOME': str(self.home)}); p.start(); self.addCleanup(p.stop)
        self.d = self.home / 'drip-src'
        (self.d / 'sub').mkdir(parents=True)
        (self.d / '.harness-owned').write_text('owner: blog drip timer\nbranch: main\n')
        self.u = self.home / 'unmarked'; self.u.mkdir()
        self.w = self.home / 'wt-other'; self.w.mkdir()
        self.policy = cg.load_policy(path=str(self.home / 'none.json'))
        self.c = cg.Compiled(self.policy, cwd=str(self.home))

    def decide(self, row):
        return cg.decide(row.format(d=self.d, w=self.w, u=self.u), self.c, cwd=str(self.home))[0]

    def test_changes_to_a_marked_checkout_are_refused(self):
        passed = [r for r in REFUSED if self.decide(r) != 'block']
        self.assertEqual(passed, [], 'not refused: %r' % passed)

    def test_control_reads_restores_and_other_checkouts_stay_allowed(self):
        blocked = [r for r in ALLOWED if self.decide(r) == 'block']
        self.assertEqual(blocked, [], 'wrongly refused: %r' % blocked)

    def test_policy_listed_checkout_is_refused_without_a_local_marker(self):
        # the checkout lives on another host (ssh): no local marker, so the policy names it
        pol = cg.load_policy(path=str(self.home / 'none.json'))
        pol['owned_checkouts'] = ['sites-seo/t2-drip-src']
        c = cg.Compiled(pol, cwd=str(self.home))
        cmd = "ssh t2-dev 'cd ~/sites-seo/t2-drip-src && git checkout -q --detach origin/main'"
        self.assertEqual(cg.decide(cmd, c, cwd=str(self.home))[0], 'block')
        ok = "ssh t2-dev 'cd ~/sites-seo/t2-drip-src && git status && git fetch origin'"
        self.assertNotEqual(cg.decide(ok, c, cwd=str(self.home))[0], 'block')


if __name__ == '__main__':
    unittest.main()
