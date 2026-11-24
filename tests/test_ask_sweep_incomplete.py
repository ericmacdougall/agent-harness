"""#170 round 6, end to end with nothing stubbed: "could not tell" is never "no", and the listing prints no close the
writer refuses (real ask_sweep.py, wal_note.py and provenance as subprocesses under a temporary HOME).

- A dangling wal: pointer under an answer row makes that ask manual and the listing exit 2 with the walk under
  `incomplete`; the same fixture with the pointer intact exits 0. Another ask's close still applies.
- An ask that wal_note's bounded tail read no longer sees (more than 4 MiB of later rows) is listed manual with
  wal_note's own "no open ask" reason, and wal_note refuses that close too; with the rows trimmed it is offered.

Run: python3 -I -m unittest tests.test_ask_sweep_incomplete
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HOOKS = Path(__file__).resolve().parents[1] / "harness" / "hooks"
S1 = "aaaaaaaa-1111-4111-8111-0000000c0de1"
U1 = "%08d-0000-4000-8000-%012d" % (1, 1)
ASK, OTHER, SUPER, SUPER2, ANSWER_ROW, TARGET = ("w%011x" % n for n in (0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6))


def at(minute):
    return "2026-11-23T10:%02d:00+00:00" % minute


def row(event, ident, minute, note, source=None, **extra):
    out = {"at": at(minute), "event": event, "id": ident, "note": note, **extra}
    if source is not None:
        out["source"] = source
    return out


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name)
        proj = self.home / ".claude" / "projects" / "-p"
        proj.mkdir(parents=True)
        (proj / (S1 + ".jsonl")).write_text(json.dumps(
            {"type": "user", "uuid": U1, "timestamp": "2026-11-23T10:05:00Z", "sessionId": S1, "origin": {"kind": "human"},
             "message": {"role": "user", "content": "Yes, restart the worker now"}}) + "\n")
        cache = self.home / ".agent-harness" / "provenance" / "tickets.json"
        cache.parent.mkdir(parents=True)
        cache.write_text(json.dumps({"goodqa#777": {"title": "the ask is replaced"}}))
        self.main = self.home / ".claude" / "wals" / S1 / "main.jsonl"
        self.main.parent.mkdir(parents=True)
        self.env = {"PATH": os.environ.get("PATH", ""), "HOME": str(self.home), "AH_HOME": str(self.home),
                    "HARNESS_PROVENANCE_OFFLINE": "1"}

    def write_rows(self, rows, filler=0):
        with open(self.main, "w") as handle:
            for r in rows[:-1]:
                handle.write(json.dumps(r, separators=(",", ":")) + "\n")
            pad = "x" * 900
            for n in range(filler):  # later rows that name no ask
                handle.write(json.dumps(row("status", "w%011x" % (0x100000 + n), 30, "filler " + pad)) + "\n")
            handle.write(json.dumps(rows[-1], separators=(",", ":")) + "\n")
        return self.main.read_bytes()

    def sweep(self, *args):
        p = subprocess.run([sys.executable, "-I", str(HOOKS / "ask_sweep.py"), "--session", S1, *args], env=self.env,
                           capture_output=True, text=True, timeout=300)
        return p.returncode, json.loads(p.stdout)

    def note(self, ask, source, outcome=None):
        argv = [sys.executable, str(HOOKS / "wal_note.py"), "--wal", str(self.main), "--event", "ask_resolved", "--ref", ask,
                "--note", "by hand", "--source", source] + (["--outcome", outcome] if outcome else [])
        p = subprocess.run(argv, env=self.env, capture_output=True, text=True, timeout=120)
        return p.returncode, json.loads(p.stderr.strip().splitlines()[-1]) if p.returncode else None


class IncompleteWalk(Base):
    def rows(self, pointer_entry):
        return [row("ask", ASK, 1, "May main restart the worker?"),
                row("ask", OTHER, 1, "the other question"),
                row("decision", ANSWER_ROW, 6, "the user's answer, recorded", f'user:{S1}/{U1} "Yes, restart the worker now"'),
                row("decision", "w%011x" % 0xd1, 7, f"Answer to ask {ASK}: the user said yes",
                    f"wal:{self.main}#{pointer_entry}"),
                row("ask", SUPER, 8, f"SUPERSEDES {ASK}: replaced", "ticket:GoodQA goodqa#777"),
                row("ask", SUPER2, 8, f"SUPERSEDES {OTHER}: replaced", "ticket:GoodQA goodqa#777")]

    def test_a_dangling_pointer_makes_its_ask_manual_and_the_listing_exit_2(self):
        before = self.write_rows(self.rows("w0000000dead"))
        code, doc = self.sweep()
        self.assertEqual(code, 2)
        self.assertEqual(doc["unread"], [])
        self.assertEqual([(e["ask"], e["stops"]) for e in doc["incomplete"]], [(ASK, ["wal-entry-not-found"])])
        items = {i["ask"]: i for i in doc["evidence"]}
        self.assertEqual((items[ASK]["kind"], items[ASK]["manual"], items[ASK]["close"]), ("answer", True, None))
        self.assertIn("could not be traced to its end (wal-entry-not-found)", items[ASK]["action"])
        self.assertEqual((items[OTHER]["kind"], items[OTHER]["manual"]), ("superseded", False))
        # the incomplete walk does not stop --apply for the other ask, and refuses its own
        code, doc = self.sweep("--apply", "--only", items[OTHER]["pin"], items[ASK]["pin"])
        self.assertEqual(code, 1)
        self.assertEqual({c["ask"]: c["rc"] for c in doc["closed"]}, {OTHER: 0, ASK: 3})
        new = [json.loads(x) for x in self.main.read_bytes()[len(before):].decode().splitlines()]
        self.assertEqual([(r["ref"], r.get("outcome")) for r in new], [(OTHER, "obsolete")])

    def test_the_same_answer_traced_to_its_end_exits_0(self):
        self.write_rows(self.rows(ANSWER_ROW))
        code, doc = self.sweep()
        self.assertEqual((code, doc["incomplete"]), (0, []))
        items = {i["ask"]: i for i in doc["evidence"]}
        self.assertEqual((items[ASK]["kind"], items[ASK]["manual"]), ("answer", True))  # a wal: source closes no answer
        self.assertNotIn("could not be traced", items[ASK]["action"])


class BeyondTheWritersTail(Base):
    def rows(self):
        return [row("ask", TARGET, 1, "the old question"),
                row("ask", SUPER, 40, f"SUPERSEDES {TARGET}: replaced", "ticket:GoodQA goodqa#777")]

    def test_an_ask_the_writer_cannot_see_is_never_offered(self):
        # more than wal_note's 4 MiB tail of rows after the ask: the listing (whole file) sees it open, the writer not
        self.write_rows(self.rows(), filler=5000)
        self.assertGreater(self.main.stat().st_size, 4 << 20)
        code, doc = self.sweep()
        item = {i["ask"]: i for i in doc["evidence"]}[TARGET]
        self.assertEqual((item["kind"], item["manual"], item["close"]), ("superseded", True, None))
        self.assertIn(f"no open ask {TARGET} in this WAL", item["action"])
        rc, refusal = self.note(TARGET, item["evidence"][0]["source"], "obsolete")
        self.assertEqual((rc, refusal["status"]), (2, "REFUSED"))
        self.assertIn(refusal["problem"], item["action"])

    def test_the_same_ask_inside_the_tail_is_offered(self):
        self.write_rows(self.rows(), filler=10)
        code, doc = self.sweep()
        item = {i["ask"]: i for i in doc["evidence"]}[TARGET]
        self.assertEqual((code, item["manual"], bool(item["close"])), (0, False, True))


if __name__ == "__main__":
    unittest.main()
