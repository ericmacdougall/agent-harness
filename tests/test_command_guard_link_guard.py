"""goodqa#17145: a command that hard-links or renames a path under the live log trees is refused by the command guard,
from one helper (Analyzer.makes_hard_link and link_operands); ordinary copies and reads stay allowed. Backups copy and
never link. Rows are data only; every path lives under a temporary HOME."""

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'harness/hooks'))
import command_guard as cg  # noqa: E402

W = '~/.claude/wals/s/main.jsonl'
P = '~/.claude/projects/p/a.jsonl'
X = '~/.codex/sessions/2026/a.jsonl'

REFUSED = (
    # hard links
    'ln %s ~/stash/a' % W, 'ln -f %s ~/stash/a' % P, 'ln -- %s ~/stash/a' % W, 'ln %s ~/stash/' % X,
    'ln -t ~/stash %s' % W, 'ln --force --target-directory=~/stash %s' % W, 'ln -L %s ~/stash/a' % W,
    'link %s ~/stash/a' % W,
    'cp -l %s ~/stash/a' % W, 'cp --link %s ~/stash/a' % W, 'cp -al ~/.claude/wals ~/stash', 'cp -rl %s ~/stash' % P,
    'cp -al ~/.claude ~/stash', 'cp -al ~/.codex/sessions ~/stash',
    'rsync -a --link-dest=~/.claude/wals ~/stash/ ~/out/', 'rsync -a --link-dest ~/.claude/projects ~/stash/ ~/out/',
    'rsync -a --link-dest=~/stash ~/.claude/wals/ ~/out/',
    # wrappers
    'env ln %s ~/stash/a' % W, 'command ln %s ~/stash/a' % W, '/bin/ln %s ~/stash/a' % W,
    'sudo ln %s ~/stash/a' % W, 'nice ln %s ~/stash/a' % W,
    'find ~/.claude/wals -name "*.jsonl" -exec ln {} ~/stash/ \\;',
    'echo %s | xargs ln -t ~/stash' % W,
    'sh -c "ln %s ~/stash/a"' % W, 'bash -c \'cp -l %s ~/stash/a\'' % P,
    # spellings of the path
    'ln "%s" ~/stash/a' % W, "ln '%s' ~/stash/a" % P, 'ln $HOME/.claude/wals/s/main.jsonl ~/stash/a',
    'ln ~/.claude/wals/s/*.jsonl ~/stash/', 'ln ~/.claude/wals/../wals/s/main.jsonl ~/stash/a',
    'cd ~/.claude/wals && ln s/main.jsonl ~/stash/a',
    # moves and renames
    'mv %s ~/stash/a' % W, 'mv ~/stash/a %s' % W, 'mv ~/.claude/wals ~/stash', 'mv ~/.claude ~/claude.bak',
    'mv %s ~/stash/a' % X, 'mv -t ~/stash %s' % P, 'rename s/a/b/ ~/.claude/wals/s/main.jsonl',
    'perl -e \'rename "%s", "/x"\'' % W,
    # interpreters
    'python3 -c "import os; os.link(\'%s\', \'/x\')"' % W,
    'python3 -c "import os; os.rename(\'%s\', \'/x\')"' % W,
    'python3 -c "import pathlib; pathlib.Path(\'/x\').hardlink_to(\'%s\')"' % W,
    'python3 -c "import os; os.link(os.path.expanduser(\'~/.claude/projects/p/a.jsonl\'), \'/x\')"',
    'node -e "require(\'fs\').linkSync(\'%s\', \'/x\')"' % W,
    'ruby -e \'File.link("%s", "/x")\'' % W,
    "python3 - <<'PY'\nimport os\nos.link('%s', '/x')\nPY" % W,
)

ALLOWED = (
    'cp %s ~/backup/a' % W, 'cp -a %s ~/backup/' % P, 'cp -a ~/.claude/wals ~/backup', 'cp -r ~/.claude/projects ~/backup',
    'cp --reflink=auto %s ~/backup/a' % W, 'rsync -a ~/.claude/wals/ ~/backup/',
    'rsync -a --link-dest=~/backups/prev ~/work/src/ ~/backups/new/', 'rclone copy ~/.claude/wals remote:wals',
    'cat %s' % W, 'ls -l %s' % P, 'tail -n 3 %s' % X, 'wc -l %s' % W, 'stat %s' % W,
    'ln ~/a ~/b', 'ln -s ~/target ~/alias', 'ln -sf ~/work/a ~/work/b', 'cp -l ~/work/a ~/work/b',
    'cp -al ~/repo ~/repo-copy', 'cp -al ~/repo-with-wals-folder/wals ~/elsewhere', 'mv ~/work/a ~/work/b',
    'find ~/work -name "*.log" -exec ln {} ~/work/links/ \\;', 'rename s/a/b/ ~/work/a.txt',
    'python3 -c "import os; os.link(\'/tmp/a\', \'/tmp/b\')"', 'python3 -c "import shutil; shutil.copy2(\'%s\', \'/tmp/b\')"' % W,
    'git mv docs/a.md docs/b.md', 'echo link wals', 'grep -c link %s' % W,
    'python3 ~/.claude/hooks/wal.py recover %s' % W,
)


class GuardBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name)
        for rel in ('.claude/wals/s', '.claude/projects/p', '.codex/sessions/2026', 'work', 'stash', 'backup', 'out',
                    'repo', 'repo-with-wals-folder/wals', 'backups/prev'):
            (self.home / rel).mkdir(parents=True, exist_ok=True)
        for rel in ('.claude/wals/s/main.jsonl', '.claude/projects/p/a.jsonl', '.codex/sessions/2026/a.jsonl'):
            (self.home / rel).write_text('{}\n')
        patcher = mock.patch.dict(os.environ, {'HOME': str(self.home)})
        patcher.start()
        self.addCleanup(patcher.stop)
        self.compiled = cg.Compiled(cg.load_policy(), cwd=str(self.home))

    def decide(self, command):
        return cg.decide(command.replace('~', str(self.home)).replace('$HOME', str(self.home)), self.compiled,
                         cwd=str(self.home))


class LinkGuard(GuardBase):
    def test_every_link_and_move_form_over_a_live_log_tree_is_refused(self):
        missed = [row for row in REFUSED if self.decide(row)[0] != 'block']
        self.assertEqual(missed, [], '%d of %d rows were not refused' % (len(missed), len(REFUSED)))

    def test_link_refusals_tell_the_agent_that_backups_copy(self):
        for row in ('ln %s ~/stash/a' % W, 'cp -al ~/.claude/wals ~/stash', 'rsync -a --link-dest=~/.claude/wals ~/s/ ~/o/',
                    'find ~/.claude/wals -exec ln {} ~/stash/ \\;', 'link %s ~/stash/a' % W):
            with self.subTest(row=row):
                verdict, message = self.decide(row)
                self.assertEqual(verdict, 'block')
                self.assertIn('Backups copy', message)
                self.assertIn('cp -a', message)


class Allowed(GuardBase):
    def test_ordinary_copies_reads_and_unrelated_links_stay_allowed(self):
        wrongly = [(row, self.decide(row)[1][:120]) for row in ALLOWED if self.decide(row)[0] == 'block']
        self.assertEqual(wrongly, [], '%d of %d rows were refused' % (len(wrongly), len(ALLOWED)))


if __name__ == '__main__':
    unittest.main()
