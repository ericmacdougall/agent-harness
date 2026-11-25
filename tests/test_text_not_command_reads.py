"""Programs that only read, and a tee into the session's own work dir, are not deletions (goodqa#17084, goodqa#17104).

Every command string here is data for a guard. None of them is ever run. TNC_HOOKS_DIR points the suite at another hooks
directory (the base commit's) to show the allow rows failing first.
"""
import json
import os
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_text_not_command as tnc  # noqa: E402
import command_guard as cg  # noqa: E402

WAL = "~/.claude/wals/s1/main.jsonl"
LOG = "~/.claude/projects/-p/5.jsonl"
MINE = "1a1b1c1d-2222-4333-8444-5555555555ef"
OTHER = "99999999-2222-4333-8444-555555555555"


def heredoc(body, head="python3 -", delim="'E'"):
    return "%s <<%s\n%s\nE" % (head, delim, body)


# Read-only programs that name a protected file and, as text or as a method name, a destroyer word.
READS = [
    "import json\nfor l in open('%s'):\n    t = json.dumps(json.loads(l))\n    if t.find('PR 19') > 0:\n"
    "        print(t[:200].replace(chr_nl, ' '))".replace("chr_nl", "'\\n'") % LOG,
    "import json, re\nfor l in open('%s', errors='ignore'):\n    o = json.loads(l)\n    s = json.dumps(o)\n"
    "    if len(s) >= 5 and re.search('delete|unlink', s):\n        print(s[:5000])" % LOG,
    "n = 0\nwith open('%s', encoding='utf-8') as f:\n    for l in f:\n        n += 'remove' in l\nprint(n)" % WAL,
    "import glob, os\nfor p in sorted(glob.glob('%s')):\n    print('rename me not', os.path.getsize(p))" % LOG,
    "from collections import Counter, defaultdict\nc, d = Counter(), defaultdict(int)\nfor l in open('%s', 'r'):\n"
    "    c.update(l.split())\n    d['truncate'] += 1\nprint(c.most_common(3), {k: v for k, v in d.items()})" % WAL,
    "import json\nrows = []\nfor l in open('%s'):\n    try:\n        rows.append(json.loads(l))\n    except ValueError:\n"
    "        continue\nprint([r.get('note') for r in rows if 'unlink' in r.get('note', '')])" % WAL,
    "import datetime\nprint(f'{datetime.datetime.now():%H} the mv row', open('" + WAL + "').read().count('shred'))",
    "# delete nothing: only count\nprint(len(open('%s').readlines()))" % WAL,
]

# Programs that name a protected file and can do more than read: each stays refused, as a here-document and with -c.
WRITES = [
    "open('%s', 'w').write('')" % WAL, "open('%s', mode='w')" % WAL, "open('%s', 'r+').truncate(0)" % WAL,
    "m = 'w'\nopen('%s', m)  # delete" % WAL, "open('%s', *['w'])  # delete" % WAL, "open('%s', **{'mode': 'w'})  # delete" % WAL,
    "open('%s', 'r', -1, None, None, None, True, None)  # remove" % WAL, "open('%s', opener=print)  # remove" % WAL,
    "import pathlib\npathlib.Path('%s').write_text('')" % WAL, "from pathlib import Path\nPath('%s').unlink()" % WAL,
    "from pathlib import Path\nPath('%s').replace('x')  # rename" % WAL,
    "import os\nos.replace('x', '%s')  # rename" % WAL, "import os\nos.remove('%s')" % WAL, "import os\nos.truncate('%s', 0)" % WAL,
    "import shutil\nshutil.rmtree('%s')" % WAL, "import subprocess\nsubprocess.run(['rm', '%s'])" % WAL,
    "import os\nos.system('rm %s')" % WAL, "from os import remove as print\nprint('%s')" % WAL,
    "import shutil as json\njson.rmtree('%s')" % WAL, "from os import unlink\nunlink('%s')" % WAL,
    "import os\nprint = os.remove\nprint('%s')" % WAL, "import os\nlist(map(os.remove, ['%s']))" % WAL,
    "import os\nsorted(['%s'], key=os.remove)" % WAL, "import re, os\nre.sub('.*', os.remove, '%s')" % WAL,
    "import os\ngetattr(os, 'remove')('%s')" % WAL, "exec(\"import os; os.remove('%s')\")" % WAL,
    "__import__('os').remove('%s')" % WAL, "import os.path\nos.remove('%s')" % WAL, "import glob\nglob.os.remove('%s')" % WAL,
    "import json\njson.decoder.scanner.re.sys.modules['os'].remove('%s')" % WAL,
    "import re\nre.enum.sys.modules['os'].remove('%s')" % WAL, "import os\np = os.path\np.os.remove('%s')" % WAL,
    "import os\nos.path.os.remove('%s')" % WAL, "import collections\ncollections.abc.sys.modules['os'].remove('%s')" % WAL,
    "print.__self__.exec(\"import os; os.remove('%s')\")" % WAL, "import os\n(lambda p: os.remove(p))('%s')" % WAL,
    "import os\n[os.remove][0]('%s')" % WAL, "import os\n{'a': os.remove}['a']('%s')" % WAL,
    "class json:\n    loads = open\njson.loads('%s', 'w')" % WAL, "def f(p):\n    return open(p, 'w')\nf('%s')" % WAL,
    "import os\njson = os\njson.remove('%s')" % WAL, "import os\nfor print in [os.remove]:\n    print('%s')" % WAL,
    "import os\nwith os as json:\n    json.remove('%s')" % WAL, "import json, os\njson.dumps = os.remove\njson.dumps('%s')" % WAL,
    "try:\n    open('%s', 'w')\nexcept Exception as print:\n    pass" % WAL, "import os\n[print for print in [os.remove]][0]('%s')" % WAL,
    "'{0.__class__}'.format('%s')  # delete" % WAL, "from json import *\nopen('%s')  # delete" % WAL,
    "from .json import loads\nopen('%s')  # delete" % WAL, "import json as a\nimport os as a\na.remove('%s')" % WAL,
    "# -*- coding: utf-7 -*-\nprint('delete %s')" % WAL, "\n# vim: set fileencoding=utf-7 :\nprint('delete %s')" % WAL,
    "print('delete %s'" % WAL, "while 1:\n    open('%s')  # delete" % WAL, "(x := open)('%s', 'w')" % WAL,
    "f = open\nf('%s', 'w')" % WAL, "global print\nimport os\nos.remove('%s')" % WAL, "del open  # %s remove" % WAL,
    "breakpoint()  # remove %s" % WAL, "input('%s remove')" % WAL, "import ctypes  # remove %s" % WAL,
    # R2: an edit of other files whose new text names a protected place. Its written text is not followed, so it stays
    "from pathlib import Path\np = Path('harness/hooks/x.py')\np.write_text(p.read_text().replace('a', '%s'))" % WAL,
    "open('notes.txt', 'w').write('remove %s')" % WAL,
]

READ = READS[2]

# The program text is a reader, but it is not certain that Python reads exactly that text.
OTHER_SHAPES = [
    heredoc(READ, "perl -"), heredoc(READ, "ruby -"), heredoc(READ, "node -"), heredoc(READ, "python3 x.py"),
    heredoc(READ, "python3 -i -"), heredoc(READ, "python3 -c 'x' -"), heredoc(READ, "python3 -m code"), heredoc(READ, "python3 -X a -"),
    heredoc(READ, "sudo python3 -"), heredoc(READ, "env X=1 python3 -"), heredoc(READ, "X=1 python3 -"), heredoc(READ, "/tmp/python3 -"),
    heredoc(READ, "./python3 -"), heredoc(READ, "'python3' -"), heredoc(READ, "python3 -- -"),
    heredoc(READ + "\n# $(rm -rf ~/.claude/wals)", delim="E"), heredoc(READ + "\n# `rm -rf ~/.claude/wals`", delim="E"),
    heredoc(READ + "\n# $X", delim="E"), heredoc(READ + "\n# a\\", delim="E"),
    "python3 - <<'E' <<'F'\n" + READ + "\nE\nimport os; os.remove('" + WAL + "')\nF",
    "python3 - <<'E' < /tmp/x\n" + READ + "\nE", "python3 - < /tmp/x <<'E'\n" + READ + "\nE",
    "python3() { bash; }; " + heredoc(READ), "function python3 { bash; }\n" + heredoc(READ), "alias python3=bash; " + heredoc(READ),
    "hash -p /bin/bash python3; " + heredoc(READ), "source /tmp/x; " + heredoc(READ), ". /tmp/x; " + heredoc(READ),
    "PATH=/tmp/x; " + heredoc(READ), "export PATH=/tmp/x; " + heredoc(READ), "eval x; " + heredoc(READ),
    "PYTHONPATH=/tmp/x; " + heredoc(READ),
    "PATH='%s rm'\n" % WAL + heredoc("PATH='%s rm'" % WAL), "alias python3=bash\n" + heredoc(READ + "\nalias = 1"),
]

# Real destruction next to a proven reader.
BESIDE = [
    heredoc(READ) + "\nrm -rf ~/.claude/wals/s1", "rm " + WAL + "; " + heredoc(READ), heredoc(READ, "python3 - > " + WAL),
    "sed -i '' s/a/b/ " + WAL,
] + [
    # the reader only prints, but something else runs or keeps what it prints
    shape % "print('rm -rf ~/.claude/wals')\nE" for shape in (
        "python3 - <<'E' | sh\n%s", "python3 - <<'E' | head | bash\n%s", "python3 - <<'E' |& sh\n%s", "python3 - <<'E' | tee x.sh\n%s\nsh x.sh",
        "python3 - <<'E' > x.sh\n%s\nsh x.sh", "python3 - > x.sh <<'E'\n%s\n. ./x.sh", "python3 - <<'E' >> x.sh\n%s\nbash x.sh",
        "python3 - <<'E' | cat > x.sh\n%s\nsh x.sh", "eval \"$(python3 - <<'E'\n%s\n)\"", "sh <(python3 - <<'E'\n%s\n)",
        "x=$(python3 - <<'E'\n%s\n); $x", "{ python3 - <<'E'\n%s\n} > x.sh; sh x.sh", "( python3 - <<'E'\n%s\n) | sh",
        "exec > x.sh; python3 - <<'E'\n%s\nsh x.sh", "if true; then python3 - <<'E'\n%s\nfi | sh",
        "while true; do python3 - <<'E'\n%s\ndone | sh", "python3 - <<'E' | while read l; do $l; done\n%s",
        "python3 - <<'E' | xargs -0 sh -c\n%s", "python3 - <<'E' | ssh h sh\n%s", "coproc python3 - <<'E'\n%s", "python3 - 2> x.sh <<'E'\n%s")
]


class ProvenReads(tnc.Home):
    def setUp(self):
        super().setUp()
        for name in (WAL, LOG):
            path = self.home / name[2:]
            path.parent.mkdir(parents=True)
            path.write_text("{}\n")

    def decide(self, command):
        compiled = cg.Compiled(cg.load_policy(), cwd=str(self.home))
        return cg.decide(command.replace("~", str(self.home)), compiled, cwd=str(self.home))[0]

    def test_reading_a_protected_file_is_not_a_deletion(self):
        for body in READS:
            for command in (heredoc(body), heredoc(body, "python3 -I -B"), heredoc(body, "/usr/bin/python3 - a b"),
                            "cd /tmp && " + heredoc(body) + "\necho done", heredoc(body, "python3 - 2>&1", "'E' | grep -c x | head -5")):
                with self.subTest(command=command):
                    self.assertNotEqual(self.decide(command), "block")

    def test_a_program_that_can_do_more_stays_refused(self):
        self.assertGreater(len(WRITES), 60)
        self.assertEqual([b for b in WRITES if self.decide(heredoc(b)) != "block"], [])
        self.assertEqual([b for b in WRITES if cg.python_only_reads(b)], [])

    def test_text_python_may_not_read_stays_refused(self):
        for command in OTHER_SHAPES:
            with self.subTest(command=command[:60] + " ... " + command[-60:]):
                self.assertEqual(self.decide(command), "block")
        self.assertTrue(cg.python_only_reads(READ))  # the program alone is proven, so each row tests its shape
        self.assertNotEqual(self.decide(heredoc(READ)), "block")

    def test_destruction_beside_a_reader_stays_refused(self):
        for command in BESIDE:
            with self.subTest(command=command):
                self.assertEqual(self.decide(command), "block")


class OwnWorkDir(tnc.Launcher):
    """`tee` over the calling session's own evidence file. The session id is the payload's, never the command's."""

    # the launcher tests of the base class run once, in their own module
    test_recording_calls_never_wait_for_the_analyser = test_a_timed_out_analyser_still_refuses_what_names_a_protected_place = None
    test_a_note_that_names_a_guarded_subcommand_is_recorded = test_the_child_has_five_seconds_less_than_the_hook_entry = None

    def setUp(self):
        super().setUp()
        self.work = self.home / ".agent-harness" / "work"
        for session in (MINE, OTHER):
            (self.work / session / "run" / "state").mkdir(parents=True)
            (self.work / session / "kept").mkdir()
            (self.work / session / "kept" / ".keep").write_text("")
            for name in ("walk.txt", "walk.log", "run/a.md", "run/state/x.txt", "kept/a.txt", "r.json", "n.jsonl", "my-wal.md"):
                (self.work / session / name).write_text("x\n")
        (self.work / "top.txt").write_text("x\n")
        for name in (WAL, LOG, "~/.agent-harness/state/a.txt", "~/.claude/hooks/hook.py"):
            path = self.home / name[2:]
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("{}\n")
        mine = self.work / MINE
        (mine / "to-wal.txt").symlink_to(self.home / WAL[2:])
        (mine / "to-other.txt").symlink_to(self.work / OTHER / "walk.txt")
        (mine / "dir").symlink_to(self.work / OTHER)
        (mine / "here").symlink_to(mine / "run")
        os.link(self.work / OTHER / "walk.log", mine / "linked.txt")

    def verdict(self, command, session=MINE, cwd=None):
        payload = self.bash(command, agent_id="a1", cwd=str(cwd or self.work / MINE))
        if session is not None:
            payload["session_id"] = session
        return self.run_launcher(payload)

    def test_tee_over_the_sessions_own_evidence_file(self):
        own = "~/.agent-harness/work/%s/" % MINE
        for command in ("python3 walk.py | tee walk.txt", "node walk.mjs 2>&1 | tee walk.log", "ls | tee " + own + "run/a.md",
                        "ls | tee %s/%s/walk.txt walk.log" % (self.work, MINE), "cd run && ls | tee a.md"):
            with self.subTest(command=command):
                code, err = self.verdict(command)
                self.assertEqual(code, 0, err)

    def test_every_other_tee_target_stays_refused(self):
        own, other = ("~/.agent-harness/work/%s/" % s for s in (MINE, OTHER))
        for target in (WAL, LOG, "~/.agent-harness/state/a.txt", "~/.claude/hooks/hook.py", other + "walk.txt", "../%s/walk.txt" % OTHER,
                       "r.json", "n.jsonl", "my-wal.md", "run/state/x.txt", "kept/a.txt", "to-wal.txt", "to-other.txt",
                       "dir/walk.txt", "linked.txt", "../%s/walk.txt" % MINE, "$X/walk.txt", "walk.*", "{walk.txt,r.json}",
                       own + "walk.txt " + other + "walk.txt", "~/.agent-harness/work/top.txt", own + "../top.txt",
                       "here/a.md", own + "here/a.md", "~/.agent-harness/work/../work/%s/walk.txt" % MINE, "run/../walk.txt"):
            with self.subTest(target=target):
                code, err = self.verdict("ls | tee " + target)
                self.assertEqual(code, 2, target)
                self.assertIn("log_delete", err)

    def test_the_session_is_the_payloads_and_must_be_known(self):
        for session in (None, "", OTHER, MINE.upper(), MINE + "/..", "..", ["x"], 5):
            with self.subTest(session=session):
                self.assertEqual(self.verdict("ls | tee walk.txt", session=session)[0], 2)
        self.assertEqual(self.verdict("CLAUDE_SESSION_ID=%s; ls | tee walk.txt" % MINE, session=OTHER)[0], 2)

    def test_a_case_variant_is_another_path(self):
        upper = self.work / MINE.upper()  # on Linux another directory, on a Mac the same one: refused on both
        (upper / "run").mkdir(parents=True, exist_ok=True)
        (upper / "walk.txt").write_text("x\n")
        (self.home / ".agent-harness" / "WORK" / MINE).mkdir(parents=True, exist_ok=True)
        (self.home / ".agent-harness" / "WORK" / MINE / "walk.txt").write_text("x\n")
        for target in ("~/.agent-harness/work/%s/walk.txt" % MINE.upper(), "~/.agent-harness/WORK/%s/walk.txt" % MINE):
            self.assertEqual(self.verdict("ls | tee " + target)[0], 2, target)

    def test_other_ways_to_empty_or_move_an_own_file_are_unchanged(self):
        for command in ("truncate -s 0 walk.txt", ": > walk.txt", "mv walk.txt /tmp/x", "rm walk.txt", "dd if=/dev/null of=walk.txt",
                        "cp /dev/null " + WAL, "tee -a %s < /dev/null; rm %s" % (WAL, WAL)):
            with self.subTest(command=command):
                self.assertEqual(self.verdict(command)[0], 2)


class KillGuardReads(tnc.Home):
    """Items 1 and 2: a here-document program is judged by what it can do, and `bash -n` runs nothing."""

    kill = tnc.OtherGuards.kill

    def test_a_reading_here_document_may_talk_about_signals(self):
        for body in ("import json\nn = 0\nfor l in open('audit.jsonl'):\n    n += 'os.kill' in json.loads(l).get('why', '')\nprint(n)",
                     "import glob\n# count the kill mutants\nprint(len([p for p in glob.glob('m/*') if 'pkill' in p]))",
                     "killed = 0\nfor l in open('a.txt'):\n    killed += l.count('SIGKILL')\nprint('os.kill rows', killed)"):
            for command in (heredoc(body), heredoc(body, "python3 -I"), "cd /tmp && " + heredoc(body) + "\necho done"):
                with self.subTest(command=command):
                    self.assertEqual(self.kill(command), (0, ""))

    def test_a_program_that_can_signal_stays_refused(self):
        say = "print(open('a').read().count('os.kill'))"
        for command in [heredoc(b) for b in (
                "import os\nos.kill(4242, 9)", "import os, signal\nos.killpg(4242, signal.SIGKILL)", "import os\nos.system('pkill -f x')",
                "import subprocess\nsubprocess.run(['kill', '4242'])", "from os import kill as print\nprint(4242, 9)",
                "import os\nprint = os.kill\nprint(4242, 9)", "import glob\nglob.os.kill(4242, 9)", "import os\nos.path.os.kill(4242, 9)",
                "import os\nlist(map(os.kill, [4242], [9]))", "exec('import os; os.kill(4242, 9)')", "import os\ngetattr(os, 'kill')(4242, 9)",
                "import re, os\nre.sub('x', lambda m: os.kill(4242, 9), 'x')", "open('/tmp/x', 'w').write('pkill -f x')",
                "# coding: utf-7\nprint('os.kill')")] + [
                heredoc(say, "perl -"), heredoc(say, "python3 x.py"), heredoc(say, "python3 -i -"),
                heredoc(say + "\n# $(pkill -f x)", delim="E"), heredoc(say) + "\npkill -f x", "alias python3=bash; " + heredoc(say),
                "python3() { bash; }; " + heredoc(say), "python3 - <<'E' <<'F'\n" + say + "\nE\nimport os; os.kill(4242, 9)\nF"]:
            with self.subTest(command=command):
                code, err = self.kill(command)
                self.assertEqual(code, 2)
                self.assertIn("kill_guard BLOCKED", err)

    def test_a_syntax_check_runs_nothing(self):
        (self.home / "stop.sh").write_text("#!/bin/bash\npkill -f server\n")
        path = str(self.home / "stop.sh")
        for command in ("bash -n " + path, "/bin/bash -n stop.sh", "bash -n ./stop.sh && echo ok"):
            with self.subTest(command=command):
                self.assertEqual(self.kill(command), (0, ""))
        for command in ("bash " + path, "bash -n %s; bash %s" % (path, path), "bash -nc 'pkill -f x'", "bash -n -c 'pkill -f x'",
                        "bash -c 'pkill -f x' -n", "bash -n -s < " + path, "bash -x " + path,
                        "bash -o noexec " + path, "bash -n " + path + " | bash " + path, "sh -n x; sh " + path,
                        "bash() { command bash \"$2\"; }; bash -n " + path,
                        "PATH=/tmp/x; bash -n " + path, "N=-n; bash $N " + path, "bash \"-n\" " + path, "./bash -n " + path,
                        "env bash -n " + path, "bash -n $(echo " + path + ")"):
            with self.subTest(command=command):
                self.assertEqual(self.kill(command)[0], 2)


# R1, verbatim as it was refused on 2026-11-25 (goodqa#17149). It only prints.
R1 = ("cd /Users/eric/fable-review-wj284/.claude/worktrees/agent-afcb760e4462a3ceb && sed -n 1940,2110p harness/hooks/merge_gate.py "
      "| cut -c1-190; grep -n \"STATE_GLOB\\|WAIVER\\|_waiver_text\\|FREE_TEXT_COMMANDS\\|DATA_COMMANDS\\|HOOK_SCRIPT\" "
      "harness/hooks/merge_gate.py | head -60")


# R4, verbatim as it was refused on 2026-11-25. It only reads.
R4 = ("cd /Users/eric/fable-review-wj284/.claude/worktrees/agent-afcb760e4462a3ceb; sed -n 260,330p harness/hooks/merge_gate.py; "
      "grep -n \"_strip_heredocs\" harness/hooks/merge_gate.py; grep -n \"^def find_merges\" -A45 harness/hooks/merge_gate.py; "
      "grep -n \"^DATA_COMMANDS\\|^FREE_TEXT_COMMANDS\\|^STATE_GLOB\\|^WAIVE_ANY\\|^HOOK_SCRIPT\\|^def _waiver_text\" -A7 "
      "harness/hooks/merge_gate.py; sed -n 500,546p harness/hooks/merge_gate.py; python3 ~/.claude/hooks/ah.py ticket comments "
      "goodqa#17149 | grep -o '\"body\": \".*' | grep -i \"run time\" | cut -c1-1800")


class WaiverReads(tnc.Home):
    """Item 4: a subagent's search of the gate's own source is not an attempt to record an exception."""

    merge = tnc.OtherGuards.merge

    def test_plain_reads_of_the_gate_source(self):
        for command in (R1, R4, "sed -n '10,20p' harness/hooks/merge_gate.py; grep -n waive harness/hooks/merge_gate.py",
                        "grep -n waive harness/hooks/merge_gate.py | cut -d: -f1 | head", "sed -n '5p;9,12p' merge_gate.py | grep waive"):
            with self.subTest(command=command):
                self.assertEqual(self.merge(command), (0, ""))

    def test_every_way_to_record_one_stays_refused(self):
        waive = "python3 ~/.claude/hooks/merge_gate.py waive --pr 5"
        for command in (waive, R1 + "; " + waive, R1 + " && " + waive, R1 + " | sh", R1 + " | xargs python3", R1 + " $(" + waive + ")",
                        R1 + " `" + waive + "`", R1 + " <(" + waive + ")", R1 + " & " + waive, "( " + waive + " ); " + R1,
                        "sed -n '1e " + waive + "' f", "sed -n 's/x/" + "y/e; # merge_gate waive' f", "sed -n 1p -e '1e " + waive + "' f",
                        "sed -n 1p f --expression='1e " + waive + "'", "sed -n -f merge_gate_waive.sed f", "sed -i s/a/b/ merge_gate.py # waive",
                        "sed -n '1w merge_gate_waive.py' f", "sed 1e merge_gate_waive f", "sed -n '1,2p' f > x.py; python3 x.py merge_gate waive",
                        "sed -n '1,2p' merge_gate.py > ~/.bashrc; grep waive f", "sed -n 1,2p $X merge_gate.py waive",
                        "cut -c1-9 f | " + waive, "cut -c1-9 f > merge_gate_waive.sh", "cut $X merge_gate waive | sh",
                        "cut() { " + waive + "; }; cut -c1-9 f", "alias cut='" + waive + "'; cut -c1-9 f", "PATH=/tmp/x cut -c1-9 merge_gate.waive",
                        "HOME=/tmp/x; cut -c1-9 merge_gate.waive", "./cut -c1-9 merge_gate.waive", "/tmp/sed -n 1p merge_gate.waive",
                        "find . -name merge_gate.py -exec python3 {} waive \\;", "awk 'BEGIN{system(\"" + waive + "\")}'",
                        "git -C /r log --grep 'merge_gate waive'", "git grep --open-files-in-pager='" + waive + "' x",
                        "env sed -n 1p f; " + waive, "eval \"sed -n 1p merge_gate.py waive\"", "echo merge_gate waive > x.sh; sed -n 1p x.sh | bash",
                        "sed -n 1p f >> ~/.claude/merge-gate-waivers.jsonl", "ssh host 'sed -n 1p merge_gate.py; " + waive + "'"):
            with self.subTest(command=command):
                self.assertEqual(self.merge(command)[0], 2)


def written(body, target=".agent-harness/work/%s/notes.md" % MINE, op=">", head="cat", end="E"):
    return "%s %s ~/%s <<'%s'\n%s\n%s" % (head, op, target, end, body, end)


class WorkFiles(tnc.Home):
    """Items 3, 5 and 8: text written to a file of the session's own work dir is data."""

    BODY = "The gate doesn't merge it.\n$word says gh pr merge 5 is main's\nos.kill, pkill -f x, dispose: closed\ncp -a /srv/big /srv/b2\n"

    def payload(self, command, session=MINE):
        return self.bash(command, agent_id="a1", session_id=session)

    def ok(self, command, session=MINE):
        return tnc.launcher.payload_records_only(self.payload(command, session), assignments=True)

    def test_one_or_more_plain_files(self):
        two = written(self.BODY) + "\n" + written("a", op=">>", end="EOF") + "\n"
        for command in (written(self.BODY), two, written(""), written("E2\n E\nE ")):
            self.assertTrue(self.ok(command), command)
            self.assertFalse(tnc.launcher.payload_records_only(self.payload(command)), "never the launcher's fast path")

    def test_anything_else_does_not_qualify(self):
        work = ".agent-harness/work/"
        outside = self.home / work / MINE
        outside.mkdir(parents=True)
        (outside / "out").symlink_to(self.home / ".claude" / "hooks")
        (outside / "run").mkdir()
        (outside / "here").symlink_to(outside / "run")
        note = written(self.BODY)
        for command in (note + "\nkill 4242", "cd /tmp && " + note, note + "\nbash ~/" + work + MINE + "/notes.md", note + "; x",
                        note + "\n\nls", note[:-2], note.replace("<<'E'", "<<E"), note.replace("<<'E'", '<<"E"'), note.replace("<<", "<<-"),
                        note.replace("<<'E'", "<<'E' | sh"), note.replace("<<'E'", "<<'E' && sh"), note.replace("<<'E'", "<<'E' <<'F'"),
                        note.replace("<<'E'", "<<'E' # x"), written("x", head="tee"), written("x", head="bash"), written("x", head="cat -n"),
                        written("x", head="cat x"), written("x", op="2>"), written("x", op=">&"), written("x", op=">|"), written("x", op="<>"),
                        written("x", target=work + OTHER + "/a"), written("x", target=work + "a"), written("x", target=work + MINE),
                        written("x", target=work + MINE + "/../" + OTHER + "/a"), written("x", target=work + MINE + "/out/kill_guard.py"),
                        written("x", target=work + MINE + "/here/a"), written("x", target=work + MINE.upper() + "/a"),
                        written("x", target=".agent-harness/Work/" + MINE + "/a"), written("x", target=work + MINE + "/run/../a"),
                        written("x", target=work + MINE + "/OWNER-DECISION-1.md"), written("x", target=work + MINE + "/inbox/a.md"),
                        written("x", target=".claude/hooks/a.py"), written("x", target=".claude/wals/s1/main.jsonl"),
                        written("x", target=work + MINE + "/$X"), written("x", target=work + MINE + "/*"), written("x", target=work + MINE + "/a b"),
                        written("x\r"), written("x\x00"), written("x\nE\nkill 1"), "HOME=/tmp/x " + note, "X=1\n" + note, "", "\n"):
            self.assertFalse(self.ok(command), command)
        for session in (None, "", OTHER, "..", MINE + "/..", 5, ["x"]):
            self.assertFalse(self.ok(note, session), session)

    def test_the_guards_read_it_as_data(self):
        import copy_hygiene
        import dropped_gate
        import merge_gate

        def no_gh(*_args, **_kwargs):
            raise merge_gate.GateError("no gh in this test")
        low = mock.patch.object(copy_hygiene, "disk_low", lambda *a, **k: (True, 1.0, 50.0))
        for body, guard, want in (
                ("It doesn't matter.\n$word then gh pr merge 5 by main", lambda p: merge_gate.decide(p, no_gh, str(self.home)), (0, "")),
                # allowed before and still: the dispose gate already skips this here-document
                ("python3 ~/.claude/hooks/ah.py task dispose --agent a --kind closed", dropped_gate.cmd_pretool, {}),
                ("git clone /srv/a /srv/b\ncp -a /srv/big /srv/b2", copy_hygiene.pretool, (0, ""))):
            with self.subTest(body=body), low, mock.patch.object(copy_hygiene, "alert", lambda *a, **k: None):
                self.assertEqual(guard(self.payload(written(body))), want)
                self.assertNotEqual(guard(self.payload(written(body) + "\n" + body.split("\n")[-1].replace("$word then ", ""))), want)


if __name__ == "__main__":
    unittest.main()
