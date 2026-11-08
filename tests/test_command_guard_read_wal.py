"""goodqa harness-fixes defect 2 (queue 2026-11-08T16:30Z "fix all the weird harness issues"): a read-only Python script
that opens a WAL for reading, with a destroyer word inside a regex pattern, was blocked as [log_delete/log-delete-text].
Reading a WAL must not block; every real destruction of a log must still block. Corpus rows are data only."""

import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'harness/hooks'))
import command_guard as cg  # noqa: E402

WAL = '~/.claude/wals/s/main.jsonl'


def heredoc(body):
    return "python3 - <<'PY'\n%s\nPY" % body


class ReadWal(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name)
        (self.home / '.claude/wals/s').mkdir(parents=True)
        (self.home / '.claude/wals/s/main.jsonl').write_text('{}\n')
        p = mock.patch.dict(os.environ, {'HOME': str(self.home)}); p.start(); self.addCleanup(p.stop)
        self.compiled = cg.Compiled(cg.load_policy(), cwd=str(self.home))

    def decide(self, command):
        return cg.decide(command.replace('~', str(self.home)), self.compiled, cwd=str(self.home))[0]

    def test_reading_a_wal_with_destroyer_words_in_a_regex_is_allowed(self):
        rows = (
            "import re\nfor l in open('%s'):\n    m = re.search(r'rewrite|delete|remove|truncate', l)" % WAL,
            "import re\np = re.compile(r'(delete|rewrite|unlink)\\b')\nfor l in open('%s'):\n    p.search(l)" % WAL,
            "import re\nprint(re.findall(r'rm -rf|rmtree', open('%s').read()))" % WAL,
        )
        blocked = [(r, self.decide(heredoc(r)), self.decide('python3 -c %s' % cg.shlex.quote(r))) for r in rows
                   if 'block' in (self.decide(heredoc(r)), self.decide('python3 -c %s' % cg.shlex.quote(r)))]
        self.assertEqual(blocked, [], 'a read of a WAL blocked: %d of %d rows' % (len(blocked), len(rows)))

    def test_control_real_destruction_still_blocks(self):
        rows = (
            "import os\nos.remove('%s')" % WAL,
            "import shutil\nshutil.rmtree('~/.claude/wals/s')",
            "import re,os\nre.search(r'delete', 'x')\nos.unlink('%s')" % WAL,
            "import re\nre.sub(r'a', 'b', 'c'); open('%s', 'w').write('')" % WAL,
            "import pathlib\npathlib.Path('%s').write_text('')" % WAL,
            "import os\ngetattr(os, 'remove')('%s')" % WAL,
            "import os\nos.system('rm %s')" % WAL,
            "import re,os\nre.search(os.remove('%s'), 'x')" % WAL,
            # red-team C1: a pattern literal that flows back out as a string, or a local `re`
            "import re,os\ngetattr(os, re.compile('remove').pattern)('%s')" % WAL,
            "import re,subprocess\nsubprocess.run([re.compile('rm').pattern, '%s'])" % WAL,
            "import re,os\nos.remove(re.compile('%s').pattern)" % WAL,
            "import re,shutil\nshutil.rmtree(re.compile('~/.claude/wals/s').pattern)",
            "import re\nopen(re.compile('%s').pattern, 'w')" % WAL,
            "import os\nclass re:\n    sub = staticmethod(lambda p, *a: os.remove(p))\nre.sub('%s', '')" % WAL,
            "import re\nexec(re.compile('import os; os.remove(\"%s\")').pattern)" % WAL,
        )
        passed = [r for r in rows if 'block' not in (self.decide(heredoc(r)), self.decide('python3 -c %s' % cg.shlex.quote(r)))]
        self.assertEqual(passed, [], 'real log destruction no longer blocks')


if __name__ == '__main__':
    unittest.main()
