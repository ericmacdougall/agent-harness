"""#170 round 2 F3 (class 5): every close that ask_sweep prints must be one that the real wal_note.py and provenance accept.

A fixed corpus of answers (straight and curly quotes, `...` and `…`, backslashes, a newline, unicode in NFC and NFD, an
over-long answer, too many ellipsis pieces) is answered on AskUserQuestion cards in a synthetic transcript under a
temporary HOME. The real ask_sweep.py lists them, and then:

- in one copy of the HOME, each printed `close` command runs through /bin/sh as printed;
- in another copy, one `--apply --only <every pin>` run closes them.

Every printed close must be accepted (rc 0), must write exactly one ask_resolved row with that source and no decision,
and the row's source must resolve in provenance as the user's words. An answer that provenance would accept in no form
must be listed under `short` with no printed close. Nothing is stubbed.

Run: python3 -m unittest tests.test_ask_sweep_quoting
"""
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HOOKS = Path(__file__).resolve().parents[1] / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
import provenance  # noqa: E402

S1 = "aaaaaaaa-3333-4333-8333-000000000001"
BACKSLASH = "\\"

# (answer, citable, elided)
CORPUS = [
    ('Use the "fast" path for this', True, False),
    ("Use the “fast” path for this one", True, False),
    ("It’s fine, go ahead with it", True, False),
    ("Yes... but only on staging today", True, True),
    ("Wait… then release it to staging", True, True),
    ("Keep C:" + BACKSLASH + "temp" + BACKSLASH + "build as the folder", True, False),
    ("A backslash then a quote " + BACKSLASH + '" stays as typed', True, False),
    ("Line one of it\nLine two of the answer", True, False),
    ("Déployer en production, s’il vous plaît ✓", True, False),
    ("Café is open for the whole team now", True, False),
    (" ".join(["word%d" % n for n in range(80)]), True, True),
    ("first piece is long... second piece is long... third piece is long... fourth piece is long", True, True),
    ("Ends with a backslash " + BACKSLASH, True, False),
    ('Quote at the very end "done"', True, False),
    ("...leading ellipsis then the words", True, False),
    ("Say “yes”... and \"no\" when asked twice", True, True),
    ("Okay... sure... fine by me", False, None),
    ("Run <bash-input>rm x</bash-input> for me", False, None),
]


def uid(n, kind=0):
    return "%08d-0000-4000-8000-%012d" % (kind, n)


def at(minute):
    return "2026-11-23T11:%02d:00Z" % minute


class QuotingContract(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name) / "a"
        proj = self.home / ".claude" / "projects" / "-q"
        proj.mkdir(parents=True)
        wal = self.home / ".claude" / "wals" / S1 / "main.jsonl"
        wal.parent.mkdir(parents=True)
        self.asks = ["w%011x" % (0xc00 + n) for n in range(len(CORPUS))]
        transcript, rows = [], []
        for n, (answer, _citable, _elided) in enumerate(CORPUS):
            use = "toolu_Q%05d" % n
            rows.append({"at": at(1).replace("Z", "+00:00"), "event": "ask", "id": self.asks[n], "note": "question %d" % n})
            transcript.append({"type": "assistant", "uuid": uid(n, 1), "timestamp": at(2), "sessionId": S1,
                               "message": {"content": [{"type": "tool_use", "id": use, "name": "AskUserQuestion", "input": {}}]}})
            transcript.append({"type": "user", "uuid": uid(n, 2), "timestamp": at(3), "sessionId": S1,
                               "toolUseResult": {"answers": {"[ask:%s] Question %d?" % (self.asks[n], n): answer}},
                               "message": {"role": "user", "content": [{"type": "tool_result", "tool_use_id": use,
                                                                        "content": "rendered"}]}})
        (proj / (S1 + ".jsonl")).write_text("".join(json.dumps(r) + "\n" for r in transcript))
        wal.write_text("".join(json.dumps(r, separators=(",", ":")) + "\n" for r in rows))
        self.copy = Path(self.tmp.name) / "b"
        shutil.copytree(self.home, self.copy, symlinks=True)

    def env(self, home):
        return {"PATH": os.environ.get("PATH", ""), "HOME": str(home)}

    def sweep(self, home, *args):
        p = subprocess.run([sys.executable, "-I", str(HOOKS / "ask_sweep.py"), "--session", S1, *args],
                           env=self.env(home), capture_output=True, text=True, timeout=300)
        try:
            return p.returncode, json.loads(p.stdout)
        except ValueError:
            self.fail("not JSON: %r %r" % (p.stdout[-400:], p.stderr[-400:]))

    def closes(self, home):
        rows = [json.loads(x) for x in (home / ".claude" / "wals" / S1 / "main.jsonl").read_text().splitlines()]
        return {r["ref"]: r for r in rows if r.get("event") == "ask_resolved"}

    def check_written(self, home, listed):
        written = self.closes(home)
        self.assertEqual(sorted(written), sorted(listed))
        for ask, item in listed.items():
            row = written[ask]
            self.assertEqual((row["source"], row.get("by"), row.get("closed_by")), (item["source"], "ask-sweep", "ask-sweep"))
            self.assertNotIn("decision", row)
            result = provenance.resolve(row["source"], {"home": home / ".claude"})
            self.assertEqual((result.get("ok"), result.get("origin")), (True, "user"), (ask, result.get("problem")))

    def test_every_printed_close_is_accepted_by_the_real_wal_note_and_provenance(self):
        code, doc = self.sweep(self.home)
        self.assertEqual(code, 0, doc.get("unread"))
        listed = {a["ask"]: a for a in doc["answered"]}
        short = {s["ask"]: s for s in doc["short"]}
        for n, (answer, citable, elided) in enumerate(CORPUS):
            with self.subTest(answer=answer):
                ask = self.asks[n]
                if citable:
                    self.assertIn(ask, listed)
                    self.assertEqual(listed[ask]["elided"], elided)
                    self.assertIn("'", listed[ask]["close"])  # printed for a shell, quoted
                else:
                    self.assertNotIn(ask, listed)
                    self.assertIn("by hand", short[ask]["reason"])
        # the printed close commands, run as printed through a shell
        for ask, item in listed.items():
            p = subprocess.run(["/bin/sh", "-c", item["close"]], env=self.env(self.home), capture_output=True,
                               text=True, timeout=120)
            self.assertEqual(p.returncode, 0, (ask, item["source"], p.stderr[-400:]))
        self.check_written(self.home, listed)
        # the same listing in a fresh copy, closed by one --apply with every pin
        code, doc = self.sweep(self.copy)
        pins = [a["pin"] for a in doc["answered"]]
        code, doc = self.sweep(self.copy, "--apply", "--only", *pins)
        self.assertEqual((code, sorted({c["rc"] for c in doc["closed"]})), (0, [0]), json.dumps(doc["closed"])[:600])
        self.check_written(self.copy, {a["ask"]: a for a in doc["answered"]})


if __name__ == "__main__":
    unittest.main()
