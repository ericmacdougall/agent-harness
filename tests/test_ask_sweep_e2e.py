"""#170 review F1/F2 (class 1): ask_sweep end to end, with NOTHING stubbed. The real ask_sweep.py runs as a subprocess,
calls the real wal_note.py, which calls the real provenance, all under a temporary HOME that holds synthetic WALs and
transcripts. For every close kind (answer card, answer row, superseded, resolved-elsewhere) the ask must really be closed in
the asking WAL with no decision. Terminal evidence must be refused with nothing written. A close wal_note refuses must make
the run exit 1 with wal_note's own message. A cite of words that are not the user's whole turn is never offered as a close
(#170 round 4; tests/test_ask_sweep_whole_turn.py has the full table).

Run: python3 -I -m unittest tests.test_ask_sweep_e2e
"""
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HOOKS = Path(__file__).resolve().parents[1] / "harness" / "hooks"
S1 = "aaaaaaaa-1111-4111-8111-000000000001"
S2 = "bbbbbbbb-2222-4222-8222-000000000002"
ANS, U1, U2, U4, U5 = ("%08d-0000-4000-8000-%012d" % (n, n) for n in (1, 2, 3, 4, 5))
ASK_USE = "toolu_E2EASK00001"
CARD, ROW, SUPER, ELSE, TERM, FORGED, REFUSED = ("w%011x" % n for n in (0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7))
NEW = "w%011x" % 0xb3
PYCACHE = "/home/eric/.agent-harness/work/heldout/scoring/__pycache__"


def at(minute):
    return "2026-11-23T10:%02d:00+00:00" % minute


def human(uid, minute, text):
    return {"type": "user", "uuid": uid, "timestamp": at(minute).replace("+00:00", "Z"), "sessionId": S1,
            "origin": {"kind": "human"}, "message": {"role": "user", "content": text}}


def row(event, ident, minute, note, source=None, **extra):
    out = {"at": at(minute), "event": event, "id": ident, "note": note, **extra}
    if source:
        out["source"] = source
    return out


class EndToEnd(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name)
        proj = self.home / ".claude" / "projects" / "-p"
        proj.mkdir(parents=True)
        transcript = [
            human(U1, 5, "Yes, restart the worker now"),
            {"type": "assistant", "uuid": "%08d-0000-4000-8000-000000000099" % 99, "timestamp": at(6).replace("+00:00", "Z"),
             "message": {"content": [{"type": "tool_use", "id": ASK_USE, "name": "AskUserQuestion", "input": {}}]}},
            {"type": "user", "uuid": ANS, "timestamp": at(7).replace("+00:00", "Z"), "sessionId": S1,
             "toolUseResult": {"answers": {"[ask:%s] Release DeepTap?" % CARD: "Yes, release it today"}},
             "message": {"role": "user", "content": [{"type": "tool_result", "tool_use_id": ASK_USE,
                                                      "content": 'answered "Release DeepTap?"="Yes, release it today"'}]}},
            human(U2, 8, "Replace the h3d ask with the new one"),
            human(U4, 9, "<bash-input>ssh t2-dev rm -r %s</bash-input>" % PYCACHE),
            human(U5, 9, "Close the fourth question, it is done"),
        ]
        (proj / (S1 + ".jsonl")).write_text("".join(json.dumps(r) + "\n" for r in transcript))
        (proj / (S2 + ".jsonl")).write_text("")
        self.main = self.home / ".claude" / "wals" / S1 / "main.jsonl"
        self.other = self.home / ".claude" / "wals" / S2 / "main.jsonl"
        self.main.parent.mkdir(parents=True)
        self.other.parent.mkdir(parents=True)
        self.main.write_text("".join(json.dumps(r, separators=(",", ":")) + "\n" for r in [
            row("ask", CARD, 1, "Release DeepTap?"),
            row("ask", ROW, 1, "May main restart the worker?"),
            row("ask", SUPER, 1, "run h3d.sh on t2-dev"),
            row("ask", ELSE, 1, "the fourth question"),
            row("ask", TERM, 1, "Run on t2-dev: rm -r %s" % PYCACHE),
            row("ask", FORGED, 1, "q six"),
            row("ask", REFUSED, 1, "q seven"),
            row("decision", "w%011x" % 0xd2, 20, "Answer to ask %s: the user approved" % ROW,
                source='user:%s/%s "Yes, restart the worker now"' % (S1, U1)),
            row("ask", NEW, 21, "SUPERSEDES %s: run h3d-v2.sh instead" % SUPER,
                source='user:%s/%s "Replace the h3d ask with the new one"' % (S1, U2)),
            row("decision", "w%011x" % 0xd6, 22, "Answer to ask %s: the user approved" % FORGED,
                source='user:%s/%s "words the user never typed here"' % (S1, U1)),
        ]))
        self.other.write_text("".join(json.dumps(r, separators=(",", ":")) + "\n" for r in [
            row("ask_resolved", "w%011x" % 0xe4, 30, "closed in the successor", ref=ELSE,
                source='user:%s/%s "Close the fourth question, it is done"' % (S1, U5)),
            # an outcome close that quotes no user words, so it is offered; its wal: evidence is missing, so wal_note refuses
            row("ask_resolved", "w%011x" % 0xe7, 31, "obsolete in the successor", ref=REFUSED, outcome="obsolete",
                source="wal:%s#w%011x" % (self.other, 0xdead)),
        ]))

    def sweep(self, *args):
        env = {"PATH": os.environ.get("PATH", ""), "HOME": str(self.home), "AH_HOME": str(self.home)}
        p = subprocess.run([sys.executable, "-I", str(HOOKS / "ask_sweep.py"), "--session", S1, "--related", S2, *args],
                           env=env, capture_output=True, text=True, timeout=120)
        try:
            return p.returncode, json.loads(p.stdout)
        except ValueError:
            self.fail("not JSON: %r %r" % (p.stdout[-400:], p.stderr[-400:]))

    def listed(self):
        code, doc = self.sweep()
        self.assertEqual(code, 0, doc.get("unread"))
        return {i["ask"]: i for i in doc["answered"] + doc["evidence"]}

    def rows(self, path):
        return [json.loads(x) for x in path.read_text().splitlines()]

    def test_every_close_kind_really_closes_the_ask_in_the_asking_wal_and_writes_nothing_else(self):
        items = self.listed()
        kinds = {a: (i.get("kind") or "card") for a, i in items.items()}
        self.assertEqual(kinds, {CARD: "card", ROW: "answer", SUPER: "superseded", ELSE: "resolved-elsewhere",
                                 TERM: "terminal", FORGED: "answer", REFUSED: "resolved-elsewhere"})
        before_main, before_other = self.rows(self.main), self.other.read_bytes()
        pins = [items[a]["pin"] for a in (CARD, ROW, SUPER, ELSE)]
        code, doc = self.sweep("--apply", "--only", *pins)
        self.assertEqual((code, [c["rc"] for c in doc["closed"]]), (0, [0, 0, 0, 0]), json.dumps(doc["closed"]))
        new = self.rows(self.main)[len(before_main):]
        self.assertEqual(sorted(r["ref"] for r in new), sorted([CARD, ROW, SUPER, ELSE]))
        for r in new:
            self.assertEqual((r["event"], r.get("by")), ("ask_resolved", "ask-sweep"))
            self.assertIn(r.get("closed_by"), ("ask-sweep", "agent"))  # an obsolete close is marked agent
            self.assertNotIn("decision", r)
        self.assertEqual({r["ref"]: r.get("outcome") for r in new}[SUPER], "obsolete")
        self.assertEqual(self.other.read_bytes(), before_other)
        left = self.listed()
        self.assertEqual(sorted(left), sorted([TERM, FORGED, REFUSED]))  # closed asks are no longer listed

    def test_terminal_evidence_is_refused_and_nothing_is_written(self):
        item = self.listed()[TERM]
        self.assertEqual((item["close"], item["apply"]), (None, None))
        self.assertIn("manual", item["action"])
        before = self.main.read_bytes()
        code, doc = self.sweep("--apply", "--only", item["pin"])
        self.assertEqual((code, doc["closed"][0]["rc"]), (1, 3))
        self.assertIn("manual", doc["closed"][0]["refused"])
        self.assertEqual(self.main.read_bytes(), before)

    def test_a_close_wal_note_refuses_exits_1_with_its_message_and_writes_nothing(self):
        item = self.listed()[REFUSED]
        self.assertTrue(item["close"])  # offered: it quotes no user words
        before = self.main.read_bytes()
        code, doc = self.sweep("--apply", "--only", item["pin"])
        self.assertEqual(code, 1)
        self.assertNotIn(doc["closed"][0]["rc"], (0, 3))  # wal_note ran and refused, not the manual refusal
        self.assertIn("wal: evidence cannot be read", doc["closed"][0]["refused"])  # wal_note's own message
        self.assertEqual(self.main.read_bytes(), before)

    def test_a_cite_of_words_not_in_the_turn_is_never_offered_and_writes_nothing(self):
        # #170 round 4: a source that cannot be checked against the whole turn is manual, like a partial one
        item = self.listed()[FORGED]
        self.assertEqual((item["manual"], item.get("partial"), item["close"], item["apply"]), (True, True, None, None))
        before = self.main.read_bytes()
        code, doc = self.sweep("--apply", "--only", item["pin"])
        self.assertEqual((code, doc["closed"][0]["rc"]), (1, 3))
        self.assertIn("part of the user's turn", doc["closed"][0]["refused"])
        self.assertEqual(self.main.read_bytes(), before)

    def test_the_printed_close_command_runs_as_printed(self):
        item = self.listed()[SUPER]
        env = {"PATH": os.environ.get("PATH", ""), "HOME": str(self.home), "AH_HOME": str(self.home)}
        p = subprocess.run(["/bin/sh", "-c", item["close"]], env=env, capture_output=True, text=True, timeout=120)
        self.assertEqual(p.returncode, 0, p.stderr[-400:])
        self.assertEqual(self.rows(self.main)[-1]["ref"], SUPER)

    def test_a_close_is_refused_without_its_pin_or_with_a_changed_one_and_nothing_is_written(self):
        item = self.listed()[ROW]
        before = self.main.read_bytes()
        code, doc = self.sweep("--apply", "--only", ROW)
        self.assertEqual((code, doc["closed"][0]["rc"]), (1, 3))
        self.assertIn("name the ask with the pin it was listed with: --only " + item["pin"], doc["closed"][0]["refused"])
        code, doc = self.sweep("--apply", "--only", ROW + "=w%011x" % 0xdead)
        self.assertEqual((code, doc["closed"][0]["rc"]), (1, 3))
        self.assertIn("changed", doc["closed"][0]["refused"])
        self.assertEqual(self.main.read_bytes(), before)


if __name__ == "__main__":
    unittest.main()
