"""ah asks / requirements / sessions: read-only JSON views for the console (GoodQA asks-view)."""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

HOOKS = Path(__file__).resolve().parents[1] / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
os.environ["AGENT_HARNESS_POLICY_LOCAL"] = str(Path(__file__).resolve().parent / "data" / "policy_profile_fixture.json")
import ah  # noqa: E402

S1 = "11111111-2222-3333-4444-555555555555"
S2 = "66666666-2222-3333-4444-555555555555"
NOW = 1_800_000_000.0
USER_SRC = 'wal:main.jsonl#w1'


def iso(ts):
    return ah.iso(ts).replace("Z", "+00:00")


class ViewTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name)

    def wal(self, session, rows, name="main.jsonl", raw=None):
        p = self.home / ".claude" / "wals" / session / name
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "w") as f:
            for r in rows:
                f.write(json.dumps(r, separators=(",", ":")) + "\n")  # WALs are compact JSON; readers grep for it
            for r in raw or []:
                f.write(r + "\n")

    def test_empty_home_has_no_sessions_and_no_rows(self):
        self.assertEqual(ah.sessions_view(self.home)["sessions"], [])
        self.assertEqual(ah.asks_view(self.home, every=True, now=NOW)["asks"], [])
        self.assertEqual(ah.requirements_view(self.home, every=True, now=NOW)["requirements"], [])

    def test_ask_states_open_resolved_blocked(self):
        old = iso(NOW - 10)
        self.wal(S1, [
            {"at": old, "event": "ask", "id": "wA", "note": "n1", "reason": "r", "source": ""},
            {"at": old, "event": "ask", "id": "wB", "note": "n2", "reason": "r", "source": ""},
            {"at": iso(NOW - 5), "event": "ask_resolved", "ref": "wB"},
        ])
        rows = {r["id"]: r for r in ah.asks_view(self.home, S1, now=NOW)["asks"]}
        self.assertEqual(rows["wB"]["state"], "resolved")
        self.assertEqual(rows["wB"]["resolved_at"], iso(NOW - 5))
        self.assertEqual(rows["wA"]["state"], "blocked")  # no source: untraceable, never shown as a plain open ask
        self.assertEqual(rows["wA"]["age_s"], 10)
        self.assertIsNone(rows["wA"]["surfaced_count"])

    def test_malformed_lines_are_skipped_not_fatal(self):
        self.wal(S1, [{"at": iso(NOW), "event": "requirement", "id": "wR", "note": "x", "source": "q"}],
                 raw=['{"event":"requirement" truncated', "not json", '["event","requirement"]', '{"event":"requirement","id":7}'])
        reqs = ah.requirements_view(self.home, S1, now=NOW)["requirements"]
        self.assertEqual([r["id"] for r in reqs if r["id"] == "wR"], ["wR"])

    def test_large_ledger_is_capped_and_flagged(self):
        rows = [{"at": iso(NOW), "event": "requirement", "id": f"w{i}", "note": "x" * 5000, "source": "q"}
                for i in range(ah._prov().MAX_HITS + 25)]
        self.wal(S1, rows)
        out = ah.requirements_view(self.home, S1, now=NOW)
        # the shared WAL reader returns at most MAX_HITS lines; the view must say it is partial
        self.assertEqual(len(out["requirements"]), ah._prov().MAX_HITS)
        self.assertTrue(out["truncated"])
        self.assertLessEqual(len(out["requirements"][0]["text"]), 600)

    def test_all_sessions_and_secret_redaction(self):
        secret = "sk-ant-api03-" + "A" * 40
        self.wal(S1, [{"at": iso(NOW), "event": "requirement", "id": "w1", "note": "k " + secret, "source": "q"}])
        self.wal(S2, [{"at": iso(NOW), "event": "requirement", "id": "w2", "note": "ok", "source": "q"}])
        out = ah.requirements_view(self.home, every=True, now=NOW)
        self.assertEqual({r["session"] for r in out["requirements"]}, {S1, S2})
        self.assertNotIn("AAAAAAAAAAAAAAAA", json.dumps(out))

    def test_bad_session_is_rejected(self):
        with self.assertRaises(ah.AhError):
            ah.asks_view(self.home, "../x", now=NOW)


if __name__ == "__main__":
    unittest.main()
