"""ah task dispose --kind finished (2026-11-24): a task whose process ended or which reported finished (the reported
case: a reviewer that returned its result) is disposed of by the session that registered it, a supervisor or a
top-rung caller, with no deploy evidence and no ticket. Fails on the previous ah.py: `finished` was not a kind and
`closed` demanded --deployed and --live-test, which a reviewer never has."""
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

NOW = 1_800_000_000.0
SESSION = "sess-finished-01"
OTHER = "sess-other-0002"
REVIEWER, RUNNING = "a00000000000000r1", "a00000000000000w1"


def iso(ts):
    return time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime(ts))


def jl(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a") as fh:
        for r in rows:
            fh.write(json.dumps(r) + "\n")


class Finished(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name)
        env = mock.patch.dict(os.environ, {"AH_HOME": str(self.home), "HOME": str(self.home),
                                           "CLAUDE_CODE_SESSION_ID": SESSION})
        env.start()
        self.addCleanup(env.stop)
        for k in ("AH_AGENT_ID", "AGENT_ID"):
            os.environ.pop(k, None)
        for patch in (mock.patch.object(ah, "server_now", side_effect=lambda: iso(NOW)),
                      mock.patch.object(ah.time, "time", side_effect=lambda: NOW)):
            patch.start()
            self.addCleanup(patch.stop)
        w = self.home / ".claude" / "wals" / SESSION
        # a reviewer registered as an owner, stopped with its result returned; and an owner still running
        jl(w / "main.jsonl", [
            {"at": iso(NOW - 3000), "event": "subagent", "agent_id": REVIEWER, "agent_type": "task-owner"},
            {"at": iso(NOW - 2000), "event": "subagent_stop", "agent_id": REVIEWER, "agent_type": "task-owner"},
            {"at": iso(NOW - 3000), "event": "subagent", "agent_id": RUNNING, "agent_type": "task-owner"}])
        jl(w / f"agent-{REVIEWER}.jsonl", [{"at": iso(NOW - 2500), "event": "intent", "note": "review PR 12"}])
        jl(w / f"agent-{RUNNING}.jsonl", [{"at": iso(NOW - 10), "event": "intent", "note": "build the thing"}])

    def dispose(self, who, kind="finished"):
        return ah.write(self.home, "task.dispose", {"agent": who, "session": SESSION, "kind": kind, "at": iso(NOW)},
                        SESSION)

    def row(self, who):
        return next(r for r in ah.owners(self.home, SESSION, now=NOW)["owners"] if r["agent_id"] == who)

    def test_a_finished_reviewer_is_disposed_and_stops_needing_a_decision(self):
        self.assertTrue(self.row(REVIEWER)["decision_required"])
        with self.assertRaises(ah.AhError):  # the control: closed needs deploy evidence a reviewer never has
            self.dispose(REVIEWER, kind="closed")
        self.dispose(REVIEWER)
        row = self.row(REVIEWER)
        self.assertFalse(row["decision_required"])
        self.assertEqual(row["disposition"]["kind"], "finished")
        self.assertTrue(row["disposition"]["live"])
        self.assertNotIn(REVIEWER, ah.owners(self.home, SESSION, now=NOW)["undisposed"])

    def test_a_running_task_is_not_finished(self):
        with self.assertRaises(ah.AhError) as caught:
            self.dispose(RUNNING)
        self.assertEqual(caught.exception.code, "not_finished")

    def test_another_session_needs_a_role(self):
        with mock.patch.dict(os.environ, {"CLAUDE_CODE_SESSION_ID": OTHER}):
            with self.assertRaises(ah.AhError) as caught:
                self.dispose(REVIEWER)
            self.assertEqual(caught.exception.code, "forbidden")
            import ah_roles
            for role in ("is_top_rung", "is_supervisor"):
                with self.subTest(role=role), mock.patch.object(ah_roles, role, return_value=True):
                    self.dispose(REVIEWER)

    def test_cli_offers_the_kind(self):
        args = ah.build_parser().parse_args(["task", "dispose", "--agent", REVIEWER, "--kind", "finished"])
        self.assertEqual(args.kind, "finished")


if __name__ == "__main__":
    unittest.main()
