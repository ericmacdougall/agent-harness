"""S1 (GoodQA goodqa#15946): ops-watch lane alerts and the spawn-hook advisory.

Covers AC-51, NEG-91 of software-factory/s1/spec.md. Bounded: one temp directory, no network, no subprocess
except the tier_gate hook run in-process.
"""
import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

HOOKS = Path(__file__).resolve().parents[1] / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
import model_tiers  # noqa: E402
import ops_watch  # noqa: E402
import tier_gate  # noqa: E402
from lane import ops  # noqa: E402

POLICY = model_tiers.load_policy()


class AdvisoryTests(unittest.TestCase):
    def test_owner_spawn_without_a_lane_key_gets_the_text(self):
        for task in (None, "auto-123", "my-own-key"):
            with self.subTest(task=task):
                self.assertIn("no lane: run `ah lane new`", ops.advisory_text(task, "task-owner", POLICY))

    def test_lane_keyed_spawn_gets_no_text(self):  # positive control
        self.assertIsNone(ops.advisory_text("stream-0123456789ab", "task-owner", POLICY))

    def test_helpers_get_no_text(self):
        for helper in ("red-team", "click-tester", "fixer", "Explore"):
            self.assertIsNone(ops.advisory_text(None, helper, POLICY))

    def test_it_reads_nothing_even_if_the_store_is_hostile(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            (home / ".agent-harness" / "state").mkdir(parents=True)
            os.mkfifo(home / ".agent-harness" / "state" / "lanes")
            old = os.environ.get("AH_HOME")
            os.environ["AH_HOME"] = str(home)
            try:
                self.assertIsNotNone(ops.advisory_text(None, "task-owner", POLICY))  # returns at once, no read
            finally:
                if old is None:
                    os.environ.pop("AH_HOME", None)
                else:
                    os.environ["AH_HOME"] = old

    def test_spawn_decision_is_identical_with_and_without_the_advisory(self):
        data = {"tool_name": "Agent", "tool_input": {"subagent_type": "task-owner", "prompt": "do it",
                                                      "description": "x [task:stream-0123456789ab]"}}
        plain = {"tool_name": "Agent", "tool_input": {"subagent_type": "task-owner", "prompt": "do it",
                                                       "description": "x [task:other-key]"}}

        class L:
            def path(self, t):
                return Path("/nonexistent/" + t)

            def status(self, t):
                return {"rung": "R0", "blocked_by": [], "permission": None}
        a = tier_gate.decide_spawn(data, POLICY, L(), session_id="s")
        b = tier_gate.decide_spawn(plain, POLICY, L(), session_id="s")
        self.assertEqual(a[0], b[0])
        self.assertEqual((a[2]['model'], a[2]['effort']), (b[2]['model'], b[2]['effort']))  # same applied rung


class OpsAlertTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / "lanes"
        self.root.mkdir()

    def tearDown(self):
        self.tmp.cleanup()

    def snap(self, name, flags):
        d = self.root / name
        d.mkdir()
        (d / "snapshot.json").write_text(json.dumps({"v": 1, "lane": name, "flags": flags}))

    def test_each_flag_raises_its_alert_and_a_clean_snapshot_none(self):
        self.snap("lane_A", ["reservation-stale", "push-late", "record-lagging", "source-unknown", "drift"])
        self.snap("lane_B", [])
        alerts = ops.lane_alerts(self.root)
        self.assertEqual(sorted(k.split(":")[2] for k, _, _ in alerts),
                         ["drift", "push-late", "record-lagging", "reservation-stale", "source-unknown"])
        self.assertTrue(all(k.startswith("lane:lane_A:") for k, _, _ in alerts))

    def test_broken_store_gives_no_alerts_and_no_exception(self):  # NEG-91
        os.mkfifo(self.root / "lane_fifo_dir_not")
        (self.root / "lane_C").mkdir()
        (self.root / "lane_C" / "snapshot.json").write_text("{not json")
        (self.root / "lane_D").mkdir()
        os.mkfifo(self.root / "lane_D" / "snapshot.json")
        (self.root / "lane_E").symlink_to(self.root.parent)
        self.assertEqual(ops.lane_alerts(self.root), [])
        self.assertEqual(ops.lane_alerts(self.root.parent / "missing"), [])
        link = self.root.parent / "link"
        link.symlink_to(self.root)
        self.assertEqual(ops.lane_alerts(link), [])

    def test_check_writes_nothing_and_ops_watch_wiring_uses_it(self):
        self.snap("lane_A", ["push-late"])
        before = sorted(str(p) for p in self.root.rglob("*"))
        cfg = {"home": self.tmp.name}
        old = ops_watch.home_of
        ops_watch.home_of = lambda c: Path(self.tmp.name)
        try:
            (Path(self.tmp.name) / ".agent-harness" / "state").mkdir(parents=True)
            os.symlink(self.root, Path(self.tmp.name) / ".agent-harness" / "state" / "lanes")
            found = ops_watch.check_lanes(cfg)  # a symlinked store is refused: nothing
            self.assertEqual(found, [])
        finally:
            ops_watch.home_of = old
        self.assertEqual(sorted(str(p) for p in self.root.rglob("*")), before)
        self.assertIn("lanes", ops_watch.DEFAULT_CHECKS)


if __name__ == "__main__":
    unittest.main()
