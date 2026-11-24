"""#170 round 2 F3 (class 5): every close that ask_sweep prints must be one that the real wal_note.py and provenance accept.

A fixed corpus of answers (straight and curly quotes, `...` and `…`, backslashes, a newline, unicode in NFC and NFD, an
over-long answer, too many ellipsis pieces) is answered on AskUserQuestion cards in a synthetic transcript under a
temporary HOME. The real ask_sweep.py lists them, and then:

- in one copy of the HOME, each printed `close` command runs through /bin/sh as printed;
- in another copy, one `--apply --only <every pin>` run closes them.

Every printed close must be accepted (rc 0), must write exactly one ask_resolved row with that source and no decision,
and the row's source must resolve in provenance as the user's words. An answer that can be cited only with words left
out (#170 triage, CRITICAL) or that provenance would accept in no form must be listed under `short` with no printed
close, and --apply must refuse it and write nothing. Nothing is stubbed.

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

# (answer, expected): "close" = cited whole and closed; "elided" = only citable with words left out, so short and never
# closed (#170 triage); "uncitable" = provenance would accept no excerpt, so short
CORPUS = [
    ('Use the "fast" path for this', "close"),
    ("Use the “fast” path for this one", "close"),
    ("It’s fine, go ahead with it", "close"),
    ("Yes... but only on staging today", "elided"),
    ("Wait… then release it to staging", "elided"),
    ("Keep C:" + BACKSLASH + "temp" + BACKSLASH + "build as the folder", "close"),
    ("A backslash then a quote " + BACKSLASH + '" stays as typed', "close"),
    ("Line one of it\nLine two of the answer", "close"),
    ("Déployer en production, s’il vous plaît ✓", "close"),
    ("Café is open for the whole team now", "close"),
    (" ".join(["word%d" % n for n in range(80)]), "elided"),
    ("first piece is long... second piece is long... third piece is long... fourth piece is long", "elided"),
    ("Ends with a backslash " + BACKSLASH, "close"),
    ('Quote at the very end "done"', "close"),
    ("...leading ellipsis then the words", "close"),
    ("Release the build now…then tell the team", "close"),
    ("Say “yes”... and \"no\" when asked twice", "elided"),
    ("Don't... stop the worker", "elided"),
    ("Please stop the worker now", "close"),  # the positive control for the line above
    ("Okay... sure... fine by me", "uncitable"),
    ("Run <bash-input>rm x</bash-input> for me", "uncitable"),
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
        for n, (answer, _expected) in enumerate(CORPUS):
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
        for n, (answer, expected) in enumerate(CORPUS):
            with self.subTest(answer=answer):
                ask = self.asks[n]
                if expected == "close":
                    self.assertIn(ask, listed)
                    # the whole answer, nothing left out (#170 triage)
                    self.assertEqual(provenance.parse_excerpt(listed[ask]["source"].split(" ", 1)[1]),
                                     provenance.norm(" ".join(answer.split())))
                    self.assertIn("'", listed[ask]["close"])  # printed for a shell, quoted
                else:
                    self.assertNotIn(ask, listed)
                    self.assertFalse({"source", "close", "apply", "pin"} & set(short[ask]), short[ask])
                    self.assertEqual(short[ask].get("elided", False), expected == "elided")
                    self.assertIn("by hand", short[ask]["reason"])
                    if expected == "uncitable":
                        # the citation's own reason, found before any close is built: since round 6 the writer's
                        # precheck would also refuse it, but with a reason about a source the user never saw
                        self.assertTrue(short[ask]["reason"].startswith(("provenance would accept no excerpt",
                                                                         "too short to cite")), short[ask]["reason"])
        self.assertEqual(len(listed), sum(e == "close" for _, e in CORPUS))
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

    def test_an_elided_answer_is_never_closed_or_written_even_when_named_and_the_whole_one_is(self):
        # #170 triage (CRITICAL): "Don't... stop the worker" must never be recorded as "...stop the worker"
        answers = [answer for answer, _ in CORPUS]
        elided = self.asks[answers.index("Don't... stop the worker")]
        control = self.asks[answers.index("Please stop the worker now")]
        code, doc = self.sweep(self.home)
        self.assertEqual(code, 0, doc.get("unread"))
        self.assertNotIn(elided, {a["ask"] for a in doc["answered"] + doc.get("evidence", [])})
        self.assertNotIn("...stop the worker", json.dumps(doc))
        pin = {a["ask"]: a["pin"] for a in doc["answered"]}[control]
        turn = uid(answers.index("Don't... stop the worker"), 2)
        code, doc = self.sweep(self.home, "--apply", "--only", "%s=%s" % (elided, turn), pin)
        self.assertEqual(code, 1)  # the elided ask is refused, and that is reported
        self.assertEqual(sorted((c["ask"], c["rc"]) for c in doc["closed"]), sorted([(elided, 3), (control, 0)]))
        written = self.closes(self.home)
        self.assertNotIn(elided, written)
        self.assertEqual(sorted(written), [control])
        wal_text = (self.home / ".claude" / "wals" / S1 / "main.jsonl").read_text()
        self.assertNotIn("...stop the worker", wal_text)
        self.assertEqual(written[control]["source"], 'answer:%s/%s "Please stop the worker now"'
                         % (S1, uid(answers.index("Please stop the worker now"), 2)))
        result = provenance.resolve(written[control]["source"], {"home": self.home / ".claude"})
        self.assertEqual((result.get("ok"), result.get("origin")), (True, "user"), result.get("problem"))


if __name__ == "__main__":
    unittest.main()
