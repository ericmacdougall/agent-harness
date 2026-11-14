"""Drive loop (owner-runtime-drive, goodqa#15968). These fail against origin/main 98e33c5d: there is no drive module,
no per-initiative conditions, no response ledger and no drive Stop gate."""
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

HOOKS = Path(__file__).resolve().parents[1] / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
import drive  # noqa: E402
import owner_rt as ort  # noqa: E402

NOW = 1_800_000_000.0
MISSION = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name)
        p = mock.patch.dict(os.environ, {"AH_HOME": str(self.home)})
        p.start()
        self.addCleanup(p.stop)
        (self.home / ".agent-harness" / "mission").mkdir(parents=True)
        self.goals = [
            {"id": "solve", "title": "Solve", "status": "active", "ticket": "goodqa#11", "priority": 1},
            {"id": "leads", "title": "Leads", "status": "imported", "ticket": "goodqa#12"},
            {"id": "old", "title": "Old", "status": "done"},
            {"id": "pp", "title": "ParentProof", "status": "deferred", "deferral": {"by": "user", "ref": "x"}},
        ]
        self.write_goals()
        self.repo = self.home / "repo"
        self.repo.mkdir()
        subprocess.run(["git", "init", "-q", str(self.repo)], check=True)
        self.commit("init")
        for g in self.goals:
            g.setdefault("repos", [str(self.repo)])
        self.write_goals()
        p2 = mock.patch.object(drive, "mission_session", return_value=MISSION)
        p2.start()
        self.addCleanup(p2.stop)
        p3 = mock.patch.object(drive, "owner_rows_of", return_value=[])  # a fresh, empty signed owner list
        p3.start()
        self.addCleanup(p3.stop)

    def commit(self, msg):
        subprocess.run(["git", "-C", str(self.repo), "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-q",
                        "--allow-empty", "-m", msg], check=True)
        return subprocess.run(["git", "-C", str(self.repo), "rev-parse", "HEAD"], capture_output=True,
                              text=True).stdout.strip()

    def write_goals(self):
        (self.home / ".agent-harness" / "mission" / "goals.json").write_text(
            json.dumps({"mission_session": MISSION, "goals": self.goals}))

    def row(self, a, goal):
        return next(r for r in a["rows"] if r["goal"] == goal)

    def conds(self, a, goal):
        return [x["cond"] for x in self.row(a, goal)["actions"]]

    def owner(self, goal="solve"):
        st = ort.init_owner(self.home, goal, str(self.repo), "ticket:goodqa#11")
        return st


class TableTests(Base):
    def test_table_lists_every_goal_whatever_status(self):
        a = drive.assess(self.home, MISSION, NOW, owner_rows=[], with_git=False)
        self.assertEqual(sorted(r["goal"] for r in a["rows"]), ["leads", "old", "pp", "solve"])
        self.assertEqual(self.conds(a, "old"), [])
        self.assertEqual(self.row(a, "old")["distance"], "done")

    def test_table_render_and_cli_json(self):
        with mock.patch("sys.stdout") as out:
            self.assertEqual(drive.main(["table", "--json"]), 0)
        snap = drive.load_snapshot(self.home)
        self.assertEqual(len(snap["rows"]), 4)
        text = drive.render(snap, [], NOW)
        self.assertIn("REQUIRED UNOWNED", text)


class ConditionTests(Base):
    def test_condition_imported_and_unowned(self):
        a = drive.assess(self.home, MISSION, NOW, owner_rows=[], with_git=False)
        self.assertEqual(self.conds(a, "leads"), ["IMPORTED", "UNOWNED"])
        self.assertEqual(self.conds(a, "solve"), ["UNOWNED"])

    def test_condition_user_deferral_suppresses(self):
        a = drive.assess(self.home, MISSION, NOW, owner_rows=[], with_git=False)
        self.assertEqual(self.conds(a, "pp"), [])

    def test_condition_legacy_owner_counts(self):
        rows = [{"agent_id": "a1234567890abcdef0", "ticket": "goodqa#11", "state": "live", "owner": True,
                 "agent_type": "task-owner"}]
        with mock.patch.object(drive, "legacy_owners", side_effect=lambda h, s, g, r: ["a1234567890abcdef0"]
                               if g["id"] == "solve" else []):
            a = drive.assess(self.home, MISSION, NOW, owner_rows=rows, with_git=False)
        self.assertNotIn("UNOWNED", self.conds(a, "solve"))

    def test_condition_stalled_proof_29_vs_31(self):
        self.owner()
        st = ort.load_state(self.home, "solve")
        st["last_beat"] = {"ts": NOW - 29 * 60}
        ort.save_state(self.home, "solve", st)
        self.assertEqual(self.conds(drive.assess(self.home, MISSION, NOW, owner_rows=[], with_git=False), "solve"), [])
        st["last_beat"] = {"ts": NOW - 31 * 60}
        ort.save_state(self.home, "solve", st)
        self.assertEqual(self.conds(drive.assess(self.home, MISSION, NOW, owner_rows=[], with_git=False), "solve"), ["STALLED"])

    def test_condition_stuck_help_and_loop(self):
        self.owner()
        st = ort.load_state(self.home, "solve")
        st["last_beat"], st["stuck"] = {"ts": NOW}, True
        ort.save_state(self.home, "solve", st)
        ort.add_task(self.home, "solve", "a", "ticket:goodqa#11")
        ort.add_task(self.home, "solve", "b", "ticket:goodqa#11")
        ort.move_task(self.home, "solve", "t1", "blocked", help_text="need grant")
        ac = self.home / "ac.md"
        ac.write_text("AC-1 x\nVerify by: pytest x\nNEG-1 y\n")
        ort.move_task(self.home, "solve", "t2", "planned", ac_file=str(ac))
        ort.review_round(self.home, "solve", "t2", "a1234567890abcdef", "REJECT")
        ort.review_round(self.home, "solve", "t2", "a1234567890abcdef", "REJECT")
        a = drive.assess(self.home, MISSION, NOW, owner_rows=[], with_git=False)
        self.assertEqual(self.conds(a, "solve"), ["STUCK", "HELP_OPEN", "REVIEW_LOOP"])
        keys = [x["key"] for x in self.row(a, "solve")["actions"]]
        self.assertIn("solve:HELP_OPEN:t1", keys)
        self.assertIn("solve:REVIEW_LOOP:t2", keys)

    def test_condition_merged_not_released(self):
        self.goals[0]["repos"] = [str(self.repo)]
        self.write_goals()
        self.commit("fix(x): thing\n\nRefs: GoodQA goodqa#11")
        subprocess.run(["git", "-C", str(self.repo), "update-ref", "refs/remotes/origin/main", "HEAD"], check=True)
        a = drive.assess(self.home, MISSION, time.time(), owner_rows=[])
        self.assertIn("MERGED_NOT_RELEASED", self.conds(a, "solve"))
        self.goals[0]["evidence"] = [{"kind": "deploy", "at": time.time() + 60}]
        self.write_goals()
        self.assertNotIn("MERGED_NOT_RELEASED", self.conds(drive.assess(self.home, MISSION, time.time(), owner_rows=[]), "solve"))

    def test_condition_pending_gates_never_replaces_owner(self):
        with mock.patch.object(drive, "lifecycle_state", return_value="pending"):
            a = drive.assess(self.home, MISSION, NOW, owner_rows=[], with_git=False)
        self.assertEqual(self.conds(a, "solve"), ["UNOWNED", "PENDING_GATES"])

    def test_condition_no_capacity_action_exists(self):
        for text in drive.ACTIONS.values():
            self.assertNotRegex(text.lower(), r"\bqueue\b|\bcapacity\b|\bwait for a slot\b")


class ResponseTests(Base):
    def setUp(self):
        super().setUp()
        self.wal = self.home / ".claude" / "wals" / MISSION / "main.jsonl"
        self.wal.parent.mkdir(parents=True)
        self.asks = []

    def ask(self, wid, note, resolved=False):
        rows = [{"event": "ask", "id": wid, "note": note}]
        if resolved:
            rows.append({"event": "ask_resolved", "ref": wid})
        with open(self.wal, "a") as fh:
            for r in rows:
                fh.write(json.dumps(r) + "\n")

    def patch_asks(self):
        import mission_coverage as mc
        return mock.patch.object(mc, "ask_states", lambda h, s: {
            json.loads(l)["id"]: {"state": "open", "note": json.loads(l)["note"]}
            for l in self.wal.read_text().splitlines() if json.loads(l)["event"] == "ask"} | {
            json.loads(l)["ref"]: {"state": "resolved", "note": ""}
            for l in self.wal.read_text().splitlines() if json.loads(l)["event"] == "ask_resolved"})

    def test_response_ask_must_be_open_and_name_goal(self):
        self.ask("w00000000001", "Agree gates for goal solve")
        self.ask("w00000000002", "Agree gates for goal leads")
        self.ask("w00000000003", "goal solve old question", resolved=True)
        with self.patch_asks():
            drive.respond(self.home, "solve", "PENDING_GATES", "ask", "w00000000001", now=NOW)
            for ref in ("w00000000002", "w00000000003", "w0000000000f"):
                with self.assertRaises(drive.DriveError, msg=ref):
                    drive.respond(self.home, "solve", "PENDING_GATES", "ask", ref, now=NOW)

    def test_response_kind_must_fit_condition(self):
        with self.assertRaises(drive.DriveError):
            drive.respond(self.home, "solve", "UNOWNED", "ticket", "goodqa#5", now=NOW)

    def test_response_ticket_must_be_open(self):
        self.owner()
        ac = self.home / "ac.md"
        ac.write_text("AC-1 x\nVerify by: pytest x\nNEG-1 y\n")
        ort.add_task(self.home, "solve", "a", "ticket:goodqa#11")
        ort.move_task(self.home, "solve", "t1", "planned", ac_file=str(ac))
        for state in ("closed", "missing", None):
            with self.assertRaises(drive.DriveError, msg=state):
                drive.respond(self.home, "solve", "REVIEW_LOOP", "ticket", "goodqa#1", detail="t1", now=NOW,
                              ticket_check=lambda ref, s=state: s)
        drive.respond(self.home, "solve", "REVIEW_LOOP", "ticket", "goodqa#1", detail="t1", now=NOW,
                      ticket_check=lambda ref: "open")

    def test_response_raw_append_and_forged_snapshot_ignored(self):
        drive.tick(self.home, MISSION, now=NOW, owner_rows=[])
        for key in [a["key"] for r in drive.load_snapshot(self.home)["rows"] for a in r["actions"]]:
            ort._append(drive._safe_dir(self.home) / "responses.jsonl", {"key": key, "ts": NOW + 2})  # unsigned
        self.assertEqual(drive.read_responses(self.home), [])
        (drive._safe_dir(self.home) / "snapshot.json").write_text(json.dumps({"at": NOW, "rows": []}))
        self.assertIsNone(drive.load_snapshot(self.home))
        out = drive.stop_decision(self.home, {"session_id": MISSION}, now=NOW + 3, is_main=True)
        self.assertEqual(out.get("decision"), "block")

    def test_response_owner_needs_successful_launch(self):
        with self.assertRaises(drive.DriveError):
            drive.respond(self.home, "solve", "STALLED", "owner", now=NOW)  # no owner
        self.owner()
        with self.assertRaises(drive.DriveError):
            drive.respond(self.home, "solve", "STALLED", "owner", now=NOW)  # no launch
        st = ort.load_state(self.home, "solve")
        st["launches"] = [{"ts": NOW - 3 * 86400, "code": 0}]  # an old launch (r1 M5)
        ort.save_state(self.home, "solve", st)
        with self.assertRaises(drive.DriveError):
            drive.respond(self.home, "solve", "STALLED", "owner", now=NOW)
        st["launches"].append({"ts": NOW, "code": 0})
        ort.save_state(self.home, "solve", st)
        drive.respond(self.home, "solve", "STALLED", "owner", now=NOW)

    def test_response_inferred_or_agent_park_refused(self):
        for src in ("inferred:from x -- y", "wal:w123", "queue:s/2026#abc \"park solve\"", ""):
            with self.assertRaises(drive.DriveError, msg=src):
                drive.respond(self.home, "solve", "UNOWNED", "park", source=src, now=NOW)

    def test_response_stale_episode_not_counted(self):
        snap = drive.with_episodes(self.home, drive.assess(self.home, MISSION, NOW, owner_rows=[], with_git=False), prev={})
        ort._append(drive._safe_dir(self.home) / "responses.jsonl",
                    drive._sign(self.home, {"key": "solve:UNOWNED", "ts": NOW - 10}))  # recorded before the episode began
        todo = [t["key"] for t in drive.unanswered(snap, drive.read_responses(self.home), NOW + 5)]
        self.assertIn("solve:UNOWNED", todo)
        ort._append(drive._safe_dir(self.home) / "responses.jsonl",
                    drive._sign(self.home, {"key": "solve:UNOWNED", "ts": NOW + 1}))
        todo = [t["key"] for t in drive.unanswered(snap, drive.read_responses(self.home), NOW + 5)]
        self.assertNotIn("solve:UNOWNED", todo)
        todo = [t["key"] for t in drive.unanswered(snap, drive.read_responses(self.home),
                                                   NOW + drive.RESPONSE_TTL_S + 10)]
        self.assertIn("solve:UNOWNED", todo)  # expired


class NewConditionTests(Base):
    def test_condition_owners_unknown_never_claims_unowned(self):
        a = drive.assess(self.home, MISSION, NOW, owner_rows=None, with_git=False)
        self.assertNotIn("UNOWNED", self.conds(a, "solve"))
        self.assertIn("unknown", self.row(a, "solve")["owner"])

    def test_condition_blocked_user_and_release_check_off(self):
        self.goals[0]["deferral"] = {"by": "ask", "ref": "w00000000001"}
        self.goals[0]["repos"] = []
        self.write_goals()
        conds = self.conds(drive.assess(self.home, MISSION, NOW, owner_rows=[], with_git=False), "solve")
        self.assertIn("BLOCKED_USER", conds)
        self.assertIn("RELEASE_CHECK_OFF", conds)
        self.assertIn("UNOWNED", conds)  # blocked on the user never excuses an ownerless goal

    def test_condition_legacy_owner_stalled(self):
        with mock.patch.object(drive, "legacy_owners", side_effect=lambda h, s, g, r: ["a1234567890abcdef0"]
                               if g["id"] == "solve" else []), \
                mock.patch.object(drive, "legacy_progress", return_value=NOW - 31 * 60):
            self.assertEqual(self.conds(drive.assess(self.home, MISSION, NOW, owner_rows=[], with_git=False),
                                        "solve"), ["STALLED"])

    def test_condition_full_cap_names_a_lane_owner(self):
        import mission_coverage as mc
        rows = [{"agent_id": "a1234567890abcdef0"}]
        with mock.patch.object(mc, "owner_cap", return_value=1), mock.patch.object(mc, "live_owner",
                                                                                   return_value=True):
            text = drive.unowned_action("solve", rows)
        self.assertIn("add a lane to live owner a1234567890abcdef", text)


class LegacyOwnerTests(Base):
    """The real matcher (mission_coverage.live_owner + _matches), not a mock (red-team r1 m7)."""

    def rows(self, **over):
        row = {"agent_id": "a1234567890abcdef0", "type": "task-owner", "state": "live", "ticket": "GoodQA goodqa#11"}
        row.update(over)
        return [row]

    def test_legacy_live_owner_by_ticket_counts(self):
        self.assertNotIn("UNOWNED", self.conds(drive.assess(self.home, MISSION, NOW, owner_rows=self.rows(),
                                                            with_git=False), "solve"))

    def test_legacy_dead_helper_or_other_ticket_does_not_count(self):
        for over in ({"state": "DROPPED"}, {"type": "red-team"}, {"ticket": "GoodQA goodqa#999"}):
            conds = self.conds(drive.assess(self.home, MISSION, NOW, owner_rows=self.rows(**over), with_git=False),
                               "solve")
            self.assertIn("UNOWNED", conds, over)

    def test_legacy_bound_agent_counts(self):
        self.goals[0]["bound"] = ["a1234567890abcdef0"]
        self.write_goals()
        rows = self.rows(ticket="")
        self.assertNotIn("UNOWNED", self.conds(drive.assess(self.home, MISSION, NOW, owner_rows=rows,
                                                            with_git=False), "solve"))


class StopTests(Base):
    def payload(self, sid=MISSION):
        return {"session_id": sid, "hook_event_name": "Stop"}

    def test_stop_blocks_main_then_allows_after_response(self):
        drive.tick(self.home, MISSION, now=NOW, owner_rows=[])
        out = drive.stop_decision(self.home, self.payload(), now=NOW + 1, is_main=True)
        self.assertEqual(out.get("decision"), "block")
        self.assertIn("solve UNOWNED", out["reason"])
        for key in [a["key"] for r in drive.load_snapshot(self.home)["rows"] for a in r["actions"]]:
            ort._append(drive._safe_dir(self.home) / "responses.jsonl", drive._sign(self.home, {"key": key, "ts": NOW + 2}))
        self.assertEqual(drive.stop_decision(self.home, self.payload(), now=NOW + 3, is_main=True), {})

    def test_stop_non_main_or_other_session_never_blocked(self):
        drive.tick(self.home, MISSION, now=NOW, owner_rows=[])
        self.assertEqual(drive.stop_decision(self.home, self.payload(), now=NOW, is_main=False), {})
        self.assertEqual(drive.stop_decision(self.home, self.payload("ffffffff-bbbb-cccc-dddd-eeeeeeeeeeee"),
                                             now=NOW, is_main=True), {})

    def test_stop_bounded_valve_keeps_action_open(self):
        drive.tick(self.home, MISSION, now=NOW, owner_rows=[])
        with mock.patch.object(drive, "_ring") as ring:
            outs = [drive.stop_decision(self.home, self.payload(), now=NOW + i, is_main=True) for i in range(5)]
        self.assertEqual([o.get("decision") for o in outs].count("block"), drive.MAX_STOP_BLOCKS)
        self.assertIn("block budget spent", outs[-1]["systemMessage"])
        self.assertTrue(any(c.args[1] == "raise" for c in ring.call_args_list))

    def test_stop_stale_path_keeps_episode_so_responses_count(self):
        out = drive.stop_decision(self.home, {"session_id": MISSION}, now=NOW, is_main=True)  # no tick snapshot
        self.assertEqual(out.get("decision"), "block")
        for key in [a["key"] for r in drive.load_snapshot(self.home)["rows"] for a in r["actions"]]:
            ort._append(drive._safe_dir(self.home) / "responses.jsonl", drive._sign(self.home, {"key": key, "ts": NOW + 1}))
        for t in (2, 60, 600):  # r1 M6: before the fix the episode restarted on every Stop
            self.assertEqual(drive.stop_decision(self.home, {"session_id": MISSION}, now=NOW + t, is_main=True), {},
                             t)

    def test_stop_stale_snapshot_still_checks(self):
        out = drive.stop_decision(self.home, self.payload(), now=NOW, is_main=True)  # no snapshot at all
        self.assertEqual(out.get("decision"), "block")
        self.assertIn("stale", out["reason"])

    def test_stop_internal_error_fails_open(self):
        import io
        with mock.patch.object(drive, "stop_decision", side_effect=RuntimeError("x")), \
                mock.patch("sys.stdout", new_callable=io.StringIO) as out:
            self.assertEqual(drive.cmd_stop(io.StringIO(json.dumps(self.payload()))), 0)
        self.assertNotIn('"block"', out.getvalue())


class OpsWatchTests(Base):
    def test_ops_watch_alerts_one_per_unanswered_action(self):
        with mock.patch.object(ort, "tick", return_value=[{"goal": "solve", "action": "stuck", "reason": "x"}]):
            alerts = drive.ops_alerts(self.home, now=NOW)
        keys = [a["key"] for a in alerts]
        self.assertIn("owner:solve:stuck", keys)
        self.assertIn("drive:solve:UNOWNED", keys)
        self.assertIn("drive:leads:IMPORTED", keys)
        self.assertTrue(all(a["severity"] == "high" for a in alerts))


class McTests(Base):
    def test_mc_api_state_carries_drive_rows(self):
        sys.path.insert(0, str(HOOKS.parent / "mission_control"))
        with mock.patch.dict(os.environ, {"MC_HOOKS": str(HOOKS)}):
            import server  # noqa: PLC0415
        drive.tick(self.home, MISSION, now=time.time(), owner_rows=[])
        fake = type("S", (), {"demo": False})()
        cls = next(v for v in vars(server).values() if isinstance(v, type) and "drive_snapshot" in vars(v))
        out = cls.drive_snapshot(fake)
        self.assertEqual(out["state"], "ok")
        self.assertEqual(sorted(r["goal"] for r in out["rows"]), ["leads", "old", "pp", "solve"])
        solve = next(r for r in out["rows"] if r["goal"] == "solve")
        self.assertTrue(solve["actions"][0]["required"])


if __name__ == "__main__":
    unittest.main()
