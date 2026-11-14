"""Lifecycle display (GoodQA goodqa#15952 AC-6, NEG-12): `ah goals`, `ah status` and Mission Control each show every
goal's lifecycle state; an unreadable ledger reads INITIATIVES UNAVAILABLE in `ah status`, never an empty list.

The user (queue 2026-11-14T04:40:36Z #f500ab254868): "the harness/fabric/sytems need to operate like that".
Failing first: against main 98e33c5d `ah status` has no initiatives section, goals_view has no lifecycle block and the
Mission Control collector has no lifecycle field.
"""
import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
sys.path.insert(0, str(ROOT / "harness" / "hooks"))
sys.path.insert(0, str(ROOT / "harness" / "mission_control"))
import test_lifecycle as tl  # noqa: E402
import ah  # noqa: E402
import goals_view  # noqa: E402
import mission_coverage as mc  # noqa: E402
import collectors as col  # noqa: E402
import events as ev  # noqa: E402
import safeio  # noqa: E402

GID = tl.GID


class StatusSection(tl.LBase):
    def test_every_goal_shows_its_lifecycle_state(self):
        self.seed_old_goals(ids=("old-a",))
        self.ok(["migrate-lifecycle"])
        self.to_active()
        self.ok(["add", "--goal", "p1", "--title", "P"])
        view = ah.initiatives_view(self.home)
        states = {r["id"]: r["state"] for r in view["goals"]}
        self.assertEqual(states, {"old-a": "LEGACY", GID: "ACTIVE", "p1": "PENDING"})
        row = next(r for r in view["goals"] if r["id"] == GID)
        self.assertEqual((row["gates_met"], row["gates"], row["unmet"]), (0, 3, ["G1", "G2", "G3"]))
        text = ah.status_text(dict(self.empty_report(), initiatives=view))
        self.assertIn("## INITIATIVES (3)", text)
        self.assertIn(f"ACTIVE     {GID} (goodqa#900) gates 0/3 unmet G1,G2,G3", text)
        self.assertIn("DONE (the user's own words only)", text)

    def test_unreadable_ledger_reads_unavailable_never_empty(self):
        self.seed_old_goals(ids=("old-a",))
        mc.goals_path(self.home).write_text("{not json")
        view = ah.initiatives_view(self.home)
        self.assertIn("error", view)
        text = ah.status_text(dict(self.empty_report(), initiatives=view))
        self.assertIn("## INITIATIVES UNAVAILABLE", text)
        self.assertNotIn("## INITIATIVES (", text)

    def test_tampered_ledger_reads_unavailable(self):
        self.to_active()
        path = mc.goals_path(self.home)
        doc = json.loads(path.read_text())
        doc["goals"][-1]["lifecycle"]["state"] = "done"
        path.write_text(json.dumps(doc))
        self.assertIn("audit chain", ah.initiatives_view(self.home)["error"])

    def test_status_report_carries_the_section(self):
        self.to_active()
        report = ah.status_report(self.home, tl.SESSION, 3600)
        self.assertEqual([r["state"] for r in report["initiatives"]["goals"]], ["ACTIVE"])

    def empty_report(self):
        return {"session": tl.SESSION, "since_s": 3600, "entries": 0, "verified": [], "failed": [], "live": [],
                "live_legacy": [], "pending": [], "claimed": [], "blockers": [], "asks_open": [], "assumptions": [],
                "commits": [], "unread": [], "owners": {"error": "x"}, "rule": "r"}


class GoalsText(tl.LBase):
    def test_goals_text_has_a_lifecycle_line_per_goal(self):
        self.seed_old_goals(ids=("old-a",))
        self.ok(["migrate-lifecycle"])
        self.to_active()
        text = goals_view.goals_text(goals_view.goals_report(self.home, scan_budget_s=0))
        self.assertIn("lifecycle: LEGACY", text)
        self.assertIn("lifecycle: ACTIVE gates 0/3 met; unmet G1,G2,G3", text)


class MissionControl(tl.LBase):
    def collector(self, rows):
        path = self.home / "dash" / "initiatives.json"
        path.parent.mkdir(exist_ok=True)
        path.write_text(json.dumps(rows))
        hub = ev.Hub(max_rate=10_000)
        c = col.Initiatives(hub, col.Health(hub), safeio.Reader([path.parent]), path)
        return c, path

    def test_badge_comes_from_the_ledger(self):
        self.to_active()
        self.ok(["add", "--goal", "p1", "--title", "P"])
        c, _path = self.collector([{"id": GID, "initiative": "L"}, {"id": "p1", "initiative": "P"},
                                   {"id": "dash-only", "initiative": "D"}])
        c.run(time.time())
        self.assertEqual([i["lifecycle"] for i in c.items], ["ACTIVE", "PENDING", "NOT IN LEDGER"])
        # a ledger change alone (the dashboard file untouched) updates the badge
        self.evidence_all()
        self.ok(["ready", "--goal", GID, "--ask", tl.DONE_ASK])
        c.run(time.time())
        self.assertEqual(c.items[0]["lifecycle"], "READY")
        self.assertEqual(c.snapshot()["items"][0]["lifecycle"], "READY")

    def test_no_ledger_and_tampered_ledger(self):
        c, _path = self.collector([{"id": GID, "initiative": "L"}])
        c.run(time.time())
        self.assertEqual(c.items[0]["lifecycle"], "NO LEDGER")
        self.to_active()
        path = mc.goals_path(self.home)
        doc = json.loads(path.read_text())
        doc["goals"][-1]["lifecycle"]["state"] = "done"
        path.write_text(json.dumps(doc))
        c.run(time.time())
        self.assertEqual(c.items[0]["lifecycle"], "UNKNOWN")
        self.assertIn("audit", c.items[0]["lifecycle_error"])

    def test_a_hand_set_state_in_the_file_is_not_shown(self):
        c, _path = self.collector([{"id": GID, "initiative": "L", "lifecycle": "DONE"}])
        self.to_active()
        c.run(time.time())
        self.assertEqual(c.items[0]["lifecycle"], "ACTIVE")


if __name__ == "__main__":
    import unittest
    unittest.main()
