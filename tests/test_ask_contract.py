"""goodqa#16599: every reader of "is this ask open" returns the same answer over the same WAL fixtures.

Seven readers carried their own copy of the rule and had drifted (id format, a rejected record, a re-asked id). The
rule is now ask_state.fold; this contract runs each reader over each fixture so they cannot drift again. Fixtures are
synthetic (no real WAL text)."""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

HOOKS = Path(__file__).resolve().parents[1] / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
SESSION = "11111111-2222-3333-4444-555555555555"
OTHER = "66666666-7777-8888-9999-000000000000"
A, B, C = "w00000000001", "w00000000002", "w00000000003"
AT = "2026-11-21T10:00:00+00:00"


def ask(ident, **extra):
    return dict({"at": AT, "event": "ask", "id": ident, "note": "synthetic question", "reason": "synthetic reason"}, **extra)


def resolved(ref, **extra):
    return dict({"at": AT, "event": "ask_resolved", "ref": ref, "note": "answered", "source": "answer:x/y"}, **extra)


FIXTURES = {
    "open": ([ask(A)], {A}),
    "closed": ([ask(A), resolved(A)], set()),
    "two asks one closed": ([ask(A), ask(B), resolved(B)], {A}),
    "resolution names an unknown ask": ([ask(A), resolved(C)], {A}),
    "re-asked id stays closed": ([ask(A), resolved(A), ask(A)], set()),
    "short hand-written id": ([ask("w1")], {"w1"}),
    "rejected resolution opens nothing and closes nothing": ([ask(A), resolved(A, at="not-a-time")], {A}),
    "rejected ask is not an ask": ([ask(A, at="not-a-time")], set()),
    "undated ask is an ask": ([ask(A, at=None)], {A}),
}


class Readers(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.home = Path(tmp.name)
        self.old_home = os.environ.get("HOME")
        os.environ["HOME"] = str(self.home)
        self.addCleanup(lambda: os.environ.__setitem__("HOME", self.old_home) if self.old_home else os.environ.pop("HOME", None))
        self.wals = self.home / ".claude" / "wals"
        (self.wals / SESSION).mkdir(parents=True)
        self.main = self.wals / SESSION / "main.jsonl"

    def write(self, rows):
        self.main.write_text("".join(json.dumps(r) + "\n" for r in rows))

    # each reader: WAL rows on disk -> the set of ask ids it reports as open
    def r_ask_state(self):
        import ask_state
        return set(ask_state.open_asks(ask_state.read_records(self.main)))

    def r_ask_reminders(self):
        import ask_reminders
        return {a["id"] for a in ask_reminders.open_asks(self.main, lambda v: 1.0)}

    def r_ahd(self):
        import ahd
        return {a["id"] for a in ahd.wal_asks({}, [SESSION])}

    def r_ah(self):
        import ah
        return {k for k, v in ah.ask_states(self.main).items() if v == "open"}

    def r_wal_note(self):
        import wal_note
        ids = {"w1", A, B, C}
        return {i for i in ids if wal_note.open_ask_exists(self.main, i)}

    def r_mission_coverage(self):
        import mission_coverage
        return {k for k, v in mission_coverage.ask_states(self.home, SESSION).items() if v.get("state") == "open"}

    def r_provenance_ledger(self):
        import provenance
        records, _ = provenance.ledger_read(SESSION, self.home / ".claude")
        return {r["id"] for r in records if r.get("_closed") is None}

    READERS = ("r_ask_state", "r_ask_reminders", "r_ahd", "r_ah", "r_wal_note", "r_mission_coverage", "r_provenance_ledger")

    def test_every_reader_agrees_on_every_fixture(self):
        for name, (rows, expected) in FIXTURES.items():
            self.write(rows)
            for reader in self.READERS:
                with self.subTest(fixture=name, reader=reader):
                    self.assertEqual(getattr(self, reader)(), expected)

    def test_an_ask_id_never_closes_an_ask_of_another_session(self):
        other = self.wals / OTHER
        other.mkdir()
        (other / "main.jsonl").write_text(json.dumps(resolved(A)) + "\n")  # same id, other session: closes nothing here
        self.write([ask(A)])
        for reader in self.READERS:
            with self.subTest(reader=reader):
                self.assertEqual(getattr(self, reader)(), {A})


if __name__ == "__main__":
    unittest.main()
