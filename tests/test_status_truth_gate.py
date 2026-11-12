"""Expired-wait gate and distinct-owner digest (GoodQA goodqa#15754, P1-4).

Evidence: on 2026-11-12 four SILENT-HIGH owners (idle ~49 h) had waits that expired ~9 h earlier, yet `ah owners`
returned `undisposed: []` because decision_required needed state DROPPED; and the ops-watch line said "12 owner(s)
silent or dropped" for 6 owners because each held a critical and a high alert row under one key. On main 4f9f4a39 the
expired-wait and 7 h cases return no undisposed owner and the digest counts 3 rows, so those tests fail there.
"""
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

HOOKS = Path(__file__).resolve().parents[1] / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
import ah  # noqa: E402
import ops_watch  # noqa: E402

NOW = 1_800_000_000.0
SESSION = "sess-gate-0001"
AGENT = "a49ace148946abcae"


def iso(ts):
    return time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime(ts))


class ExpiredWait(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name)
        env = mock.patch.dict(os.environ, {"AH_HOME": str(self.home), "HOME": str(self.home)})
        env.start()
        self.addCleanup(env.stop)
        self.wal = self.home / ".claude" / "wals" / SESSION
        self.wal.mkdir(parents=True)

    def owner(self, idle_s, disposition):
        (self.wal / "main.jsonl").write_text(json.dumps({"at": iso(NOW - idle_s - 60), "event": "subagent",
                                                          "agent_id": AGENT, "agent_type": "task-owner"}) + "\n")
        (self.wal / f"agent-{AGENT}.jsonl").write_text(json.dumps(
            {"at": iso(NOW - idle_s), "event": "intent", "note": "lab G gateway, goodqa#15643"}) + "\n")
        disp = {} if disposition is None else {AGENT: disposition}
        with mock.patch.object(ah, "dispositions", return_value=disp):
            return ah.owners(self.home, SESSION, now=NOW)

    def row(self, data):
        return next(r for r in data["owners"] if r["agent_id"] == AGENT)

    def test_silent_high_with_expired_wait_needs_a_decision(self):
        data = self.owner(49 * 3600, {"kind": "waiting", "at": NOW - 40 * 3600, "until": NOW - 9 * 3600,
                                      "ref": "goodqa#15643", "seq": 1})
        self.assertTrue(self.row(data)["state"].startswith("SILENT"))
        self.assertIn(AGENT, data["undisposed"])
        self.assertIn("wait-expired", self.row(data)["flags"])

    def test_live_wait_stays_quiet(self):
        data = self.owner(49 * 3600, {"kind": "waiting", "at": NOW - 3600, "until": NOW + 4 * 86400,
                                      "ref": "goodqa#15643", "seq": 1})
        self.assertNotIn(AGENT, data["undisposed"])

    def test_owner_quiet_31_minutes_is_not_undisposed(self):
        data = self.owner(31 * 60, None)
        self.assertEqual(self.row(data)["state"], "SILENT")
        self.assertNotIn(AGENT, data["undisposed"])

    def test_silent_7h_without_any_disposition_needs_a_decision(self):
        data = self.owner(7 * 3600, None)
        self.assertIn(AGENT, data["undisposed"])
        self.assertIn("silent-undisposed", self.row(data)["flags"])


class Digest(unittest.TestCase):
    def test_counts_distinct_owners_and_the_session_share(self):
        alerts = [{"severity": "critical", "host": "mac", "key": "liveness:baab765b/agent-a1", "message": "x"},
                  {"severity": "high", "host": "mac", "key": "liveness:baab765b/agent-a1", "message": "x"},
                  {"severity": "high", "host": "mac", "key": "liveness:ed7b14c4/agent-a2", "message": "x"}]
        with mock.patch.object(ops_watch, "active_alerts", return_value=alerts), \
                mock.patch.object(ops_watch, "load_state", return_value={"last_run": time.time()}):
            text = ops_watch.injection_text(Path("/nonexistent"), session="baab765b-d85c-46b4-b7b9-588eb912c770")
        self.assertIn("2 owner(s) silent or dropped (1 in this session)", text)


if __name__ == "__main__":
    unittest.main()
