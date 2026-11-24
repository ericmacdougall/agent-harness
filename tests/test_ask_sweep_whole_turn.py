"""#170 round 4 (main's ruling, CRITICAL class): ask_sweep offers a close only for a citation of the user's WHOLE turn.

An excerpt that leaves any words out, with an ellipsis or without, can invert what the user said: "Don't... stop the
worker" cited as "...stop the worker", "Do not stop the worker now" cited as "stop the worker now". Round 3 closed this for
answer cards (plan). These tests close it for WAL evidence too, the `answer` and `resolved-elsewhere` kinds, which copy the
source another row already wrote. One shared function, ask_evidence.cites_whole, decides "is this excerpt the whole
turn" for both paths.

- TABLE runs through cites_whole directly, and end to end with NOTHING stubbed: the real ask_sweep.py, the real wal_note.py
  and the real provenance, under a temporary HOME. Every row is cited twice, by a decision row in the asking session and
  by an ask_resolved row in a related session.
- A partial excerpt must be listed for manual close only (no close, no apply). --apply must refuse it (rc 3) and write
  nothing.
- A whole-turn excerpt (the positive controls) must be closed with exactly that source and no decision.

Run: python3 -I -m unittest tests.test_ask_sweep_whole_turn
"""
import ast
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HOOKS = Path(__file__).resolve().parents[1] / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
import provenance  # noqa: E402

S1 = "aaaaaaaa-4444-4444-8444-000000000001"   # the session that asked
S2 = "bbbbbbbb-4444-4444-8444-000000000002"   # a related session (a successor or the coordinator)

# (name, the user's whole turn, the excerpt another row cites, whether a close may be offered)
TABLE = [
    ("elided repro: negation dropped by a leading ellipsis", "Don't... stop the worker", "...stop the worker", False),
    ("plain partial repro: negation dropped, no ellipsis", "Do not stop the worker now", "stop the worker now", False),
    ("prefix, no ellipsis: the condition dropped", "Ship it to staging, but not to production", "Ship it to staging", False),
    ("prefix with a closing ellipsis", "Ship it to staging, but never to production", "Ship it to staging...", False),
    ("suffix with a leading ellipsis: negation dropped", "Never under any circumstances restart the worker",
     "...restart the worker", False),
    ("middle, no ellipsis", "Please do not delete the backups yet", "do not delete the backups", False),
    ("middle elided: negation dropped between two pieces", "Restart the worker, then do not touch the database at all",
     "Restart the worker...touch the database", False),
    ("suffix, no ellipsis: negation dropped", "I do not want you to release the build today", "release the build today",
     False),
    ("words the user never typed (provenance refuses it)", "Yes, restart the worker now",
     "words the user never typed here", False),
    ("positive control: the whole turn", "Please stop the worker now", "Please stop the worker now", True),
    ("positive control: whole turn, spaces, a newline and a curly apostrophe folded",
     "Don’t  stop the worker,\nplease", "Don't stop the worker, please", True),
    ("positive control: a literal ellipsis the user typed, quoted whole", "Release it now... then tell the whole team",
     "Release it now... then tell the whole team", True),
    ("positive control: a short whole turn", "yes", "yes", True),
]


def uid(n, kind):
    return "%08d-0000-4000-8000-%012d" % (kind, n)


def at(minute, z=False):
    stamp = "2026-11-24T09:%02d:00+00:00" % minute
    return stamp.replace("+00:00", "Z") if z else stamp


def human(session, ident, minute, text):
    return {"type": "user", "uuid": ident, "timestamp": at(minute, z=True), "sessionId": session,
            "origin": {"kind": "human"}, "message": {"role": "user", "content": text}}


def row(event, ident, minute, note, source=None, **extra):
    out = {"at": at(minute), "event": event, "id": ident, "note": note, **extra}
    if source is not None:
        out["source"] = source
    return out


def quoted(excerpt):
    return '"' + excerpt.replace('"', '\\"') + '"'


class SharedRule(unittest.TestCase):
    def test_cites_whole_over_the_table(self):
        import ask_evidence
        for name, turn, excerpt, whole in TABLE:
            with self.subTest(name):
                self.assertIs(ask_evidence.cites_whole(excerpt, turn), whole)
        for excerpt, text in ((None, "x y"), ("x y", None), ("", ""), ("   ", " \n ")):
            self.assertIs(ask_evidence.cites_whole(excerpt, text), False)  # nothing is never a whole turn

    def test_plan_and_wal_evidence_decide_through_the_one_shared_function(self):
        def calls(path, function):
            tree = ast.parse((HOOKS / path).read_text(), path)
            node = next(n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef) and n.name == function)
            return {(c.func.attr if isinstance(c.func, ast.Attribute) else getattr(c.func, "id", None))
                    for c in ast.walk(node) if isinstance(c, ast.Call)}
        self.assertIn("cites_whole", calls("ask_evidence.py", "cite"))          # the card path: plan() reads cite's flag
        self.assertIn("cite", calls("ask_sweep.py", "plan"))
        self.assertIn("cites_whole", calls("ask_sweep.py", "whole_citation"))   # the WAL-evidence path
        self.assertIn("whole_citation", calls("ask_sweep.py", "held_back"))      # round 5: before the writer's rule
        self.assertIn("precheck", calls("ask_sweep.py", "held_back"))  # round 6: the writer's checks, all of them
        self.assertIn("held_back", calls("ask_sweep.py", "wal_evidence"))


class WalEvidenceWholeTurn(unittest.TestCase):
    """End to end over TABLE, nothing stubbed."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name)
        proj = self.home / ".claude" / "projects" / "-w"
        proj.mkdir(parents=True)
        self.main = self.home / ".claude" / "wals" / S1 / "main.jsonl"
        self.other = self.home / ".claude" / "wals" / S2 / "main.jsonl"
        self.main.parent.mkdir(parents=True)
        self.other.parent.mkdir(parents=True)
        transcript, mine, theirs = [], [], []
        self.cases = {}   # ask id -> (name, kind, source, whole)
        for n, (name, turn, excerpt, whole) in enumerate(TABLE):
            turn_id = uid(n, 1)
            transcript.append(human(S1, turn_id, 5, turn))
            source = "user:%s/%s %s" % (S1, turn_id, quoted(excerpt))
            by_row, elsewhere = "w%011x" % (0xa00 + n), "w%011x" % (0xb00 + n)
            mine.append(row("ask", by_row, 1, "question %d, answered in a decision row" % n))
            mine.append(row("ask", elsewhere, 1, "question %d, closed in a related session" % n))
            mine.append(row("decision", "w%011x" % (0xd00 + n), 20, "Answer to ask %s: the user answered" % by_row,
                            source=source))
            theirs.append(row("ask_resolved", "w%011x" % (0xe00 + n), 30, "closed in the successor", ref=elsewhere,
                              source=source))
            self.cases[by_row] = (name, "answer", source, whole)
            self.cases[elsewhere] = (name, "resolved-elsewhere", source, whole)
        # an inferred: chain that quotes the user cannot be checked against a whole turn: manual
        chained = "w%011x" % 0xc01
        mine.append(row("ask", chained, 1, "question chained"))
        chain = 'inferred: from user:%s/%s %s -- the user agreed to it' % (S1, uid(1, 1), quoted("stop the worker now"))
        theirs.append(row("ask_resolved", "w%011x" % 0xe99, 31, "closed in the successor", ref=chained, source=chain))
        self.cases[chained] = ("an inferred: chain that quotes the user", "resolved-elsewhere", chain, False)
        (proj / (S1 + ".jsonl")).write_text("".join(json.dumps(r) + "\n" for r in transcript))
        (proj / (S2 + ".jsonl")).write_text("")
        self.main.write_text("".join(json.dumps(r, separators=(",", ":")) + "\n" for r in mine))
        self.other.write_text("".join(json.dumps(r, separators=(",", ":")) + "\n" for r in theirs))

    def sweep(self, *args):
        env = {"PATH": os.environ.get("PATH", ""), "HOME": str(self.home)}
        p = subprocess.run([sys.executable, "-I", str(HOOKS / "ask_sweep.py"), "--session", S1, "--related", S2, *args],
                           env=env, capture_output=True, text=True, timeout=300)
        try:
            return p.returncode, json.loads(p.stdout)
        except ValueError:
            self.fail("not JSON: %r %r" % (p.stdout[-400:], p.stderr[-400:]))

    def closes(self):
        rows = [json.loads(x) for x in self.main.read_text().splitlines()]
        return {r["ref"]: r for r in rows if r.get("event") == "ask_resolved"}

    def test_only_a_whole_turn_is_ever_closed_from_wal_evidence(self):
        code, doc = self.sweep()
        self.assertEqual(code, 0, doc.get("unread"))
        listed = {i["ask"]: i for i in doc["evidence"]}
        self.assertEqual(sorted(listed), sorted(self.cases))
        for ask, (name, kind, source, whole) in self.cases.items():
            item = listed[ask]
            with self.subTest(name, kind=kind):
                self.assertEqual((item["kind"], item["evidence"][0]["source"]), (kind, source))
                if whole:
                    self.assertFalse(item["manual"])
                    self.assertIn("--source", item["close"])
                    self.assertTrue(item["apply"])
                else:
                    # listed so main reads it, but never offered as a close
                    self.assertTrue(item["manual"])
                    self.assertEqual((item["close"], item["apply"]), (None, None))
                    self.assertIn("by hand", item["action"])
                    if source.startswith("user:"):
                        # the whole-turn gate itself holds a direct cite back, not only the writer's rule after it
                        # (round 5: close_verdict also refuses a cite provenance rejects, so the reason is what differs)
                        self.assertEqual((item.get("partial"), item["action"]), (True, "manual: this evidence quotes only "
                                         "part of the user's turn, or cannot be checked against the whole turn, and "
                                         "leaving words out can change its meaning: read the whole turn and close the "
                                         "ask by hand"))
                    else:
                        # an inferred: chain backs no answer close: the writer's own reason
                        self.assertNotIn("partial", item)
                        self.assertIn("wal_note would refuse this close", item["action"])
        # every pin at once: each partial excerpt is refused, each whole turn is closed, in one run
        code, doc = self.sweep("--apply", "--only", *[listed[a]["pin"] for a in self.cases])
        self.assertEqual(code, 1)   # refusals are reported
        rcs = {c["ask"]: c["rc"] for c in doc["closed"]}
        self.assertEqual(rcs, {a: 0 if case[3] else 3 for a, case in self.cases.items()}, json.dumps(doc["closed"])[:900])
        written = self.closes()
        self.assertEqual(sorted(written), sorted(a for a, case in self.cases.items() if case[3]))
        for ask, close in written.items():
            with self.subTest(self.cases[ask][0], kind=self.cases[ask][1]):
                self.assertEqual((close["source"], close.get("by")), (self.cases[ask][2], "ask-sweep"))
                self.assertNotIn("decision", close)
                result = provenance.resolve(close["source"], {"home": self.home / ".claude", "want_text": True})
                self.assertEqual((result.get("ok"), result.get("origin")), (True, "user"), result.get("problems"))
                node = result["chain"][0]
                self.assertEqual(provenance.norm(node["excerpt"]), provenance.norm(node["text"]))  # the whole turn
        # no close anywhere carries an excerpt that leaves words out
        for close in written.values():
            self.assertNotIn('"...stop the worker"', close["source"])
            self.assertNotIn('"stop the worker now"', close["source"])

    def test_an_answer_card_cited_in_part_by_another_row_is_manual_and_cited_whole_is_closed(self):
        # the `answer:` variant: the whole turn is every answer on the card, joined
        use, use2, card, single = "toolu_W00001", "toolu_W00002", uid(1, 7), uid(2, 7)
        records = [
            {"type": "assistant", "uuid": uid(1, 6), "timestamp": at(40, z=True), "sessionId": S1,
             "message": {"content": [{"type": "tool_use", "id": use, "name": "AskUserQuestion", "input": {}}]}},
            {"type": "user", "uuid": card, "timestamp": at(41, z=True), "sessionId": S1,
             "toolUseResult": {"answers": {"Restart the worker?": "Do not restart the worker",
                                           "Keep the cache?": "Keep the cache warm please"}},
             "message": {"role": "user", "content": [{"type": "tool_result", "tool_use_id": use, "content": "rendered"}]}},
            {"type": "assistant", "uuid": uid(2, 6), "timestamp": at(42, z=True), "sessionId": S1,
             "message": {"content": [{"type": "tool_use", "id": use2, "name": "AskUserQuestion", "input": {}}]}},
            {"type": "user", "uuid": single, "timestamp": at(43, z=True), "sessionId": S1,
             "toolUseResult": {"answers": {"Release it?": "Yes, release it to staging today"}},
             "message": {"role": "user", "content": [{"type": "tool_result", "tool_use_id": use2,
                                                      "content": "rendered"}]}},
        ]
        with open(self.home / ".claude" / "projects" / "-w" / (S1 + ".jsonl"), "a") as fh:
            fh.write("".join(json.dumps(r) + "\n" for r in records))
        part, whole = "w%011x" % 0xf01, "w%011x" % 0xf02
        part_src = "answer:%s/%s %s" % (S1, card, quoted("Do not restart the worker"))
        whole_src = "answer:%s/%s %s" % (S1, single, quoted("Yes, release it to staging today"))
        with open(self.main, "a") as fh:
            for r in (row("ask", part, 2, "card part"), row("ask", whole, 2, "card whole"),
                      row("decision", "w%011x" % 0xf11, 45, "Answer to ask %s: the user answered" % part, source=part_src),
                      row("decision", "w%011x" % 0xf12, 45, "Answer to ask %s: the user answered" % whole, source=whole_src)):
                fh.write(json.dumps(r, separators=(",", ":")) + "\n")
        code, doc = self.sweep()
        self.assertEqual(code, 0, doc.get("unread"))
        listed = {i["ask"]: i for i in doc["evidence"]}
        self.assertEqual((listed[part]["manual"], listed[part]["close"]), (True, None))
        self.assertFalse(listed[whole]["manual"])
        code, doc = self.sweep("--apply", "--only", listed[part]["pin"], listed[whole]["pin"])
        self.assertEqual({c["ask"]: c["rc"] for c in doc["closed"]}, {part: 3, whole: 0})
        written = self.closes()
        self.assertNotIn(part, written)
        self.assertEqual(written[whole]["source"], whole_src)


if __name__ == "__main__":
    unittest.main()
