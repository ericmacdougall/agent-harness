"""Owner runtime (owner-runtime-drive). These fail against origin/main 98e33c5d: there is no owner_rt module, no task
inbox, no owner Stop gate and no resume tick."""
import io
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
import owner_rt as ort  # noqa: E402

NOW = 1_800_000_000.0
SID = "11111111-2222-3333-4444-555555555555"
GOAL_AC = """# t1
AC-1 the page loads
Verify by: pytest tests/test_page.py -k load
AC-2 the page saves
Verify by: curl -sf localhost/save
NEG-1 (AC-2) a double click saves once
"""


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name)
        p = mock.patch.dict(os.environ, {"AH_HOME": str(self.home)})
        p.start()
        self.addCleanup(p.stop)
        mission = self.home / ".agent-harness" / "mission"
        mission.mkdir(parents=True)
        self.goals = [{"id": "solve", "title": "Solve working live", "status": "active", "ticket": "goodqa#1"},
                      {"id": "shipped", "title": "Done thing", "status": "done"}]
        self.write_goals()
        self.repo = self.home / "repo"
        self.repo.mkdir()
        subprocess.run(["git", "init", "-q", str(self.repo)], check=True)
        subprocess.run(["git", "-C", str(self.repo), "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-q",
                        "--allow-empty", "-m", "init"], check=True)
        self.sha = subprocess.run(["git", "-C", str(self.repo), "rev-parse", "HEAD"], capture_output=True,
                                  text=True).stdout.strip()
        self.ac = self.home / "ac.md"
        self.ac.write_text(GOAL_AC)

    def write_goals(self):
        (self.home / ".agent-harness" / "mission" / "goals.json").write_text(json.dumps({"goals": self.goals}))

    def init(self, goal="solve"):
        return ort.init_owner(self.home, goal, str(self.repo), "ticket:goodqa#1")

    def set_session(self, sid=SID):
        st = ort.load_state(self.home, "solve")
        st["session_id"] = sid
        ort.save_state(self.home, "solve", st)


class StateInboxTests(Base):
    def test_state_init_requires_ledger_goal_and_source(self):
        with self.assertRaises(ort.OwnerError):
            ort.init_owner(self.home, "nope", str(self.repo), "ticket:goodqa#1")
        with self.assertRaises(ort.OwnerError):
            ort.init_owner(self.home, "solve", str(self.repo), "")
        st = self.init()
        self.assertEqual(st["goal"], "solve")
        self.assertEqual(oct((self.home / ".agent-harness/owners/solve").stat().st_mode & 0o777), "0o700")
        with self.assertRaises(ort.OwnerError):
            self.init()  # one owner per goal

    def test_inbox_tasks_queue_and_fold(self):
        self.init()
        ort.add_task(self.home, "solve", "fix login", "ticket:goodqa#2")
        ort.add_task(self.home, "solve", "ship release", "ticket:goodqa#3")
        tmap = ort.tasks(ort.inbox_rows(self.home, "solve"))
        self.assertEqual(sorted(tmap), ["t1", "t2"])
        self.assertEqual([t["id"] for t in ort.actionable(tmap)], ["t1", "t2"])
        with self.assertRaises(ort.OwnerError):
            ort.add_task(self.home, "solve", "x", "")  # no source

    def test_inbox_out_of_order_moves_refused(self):
        self.init()
        ort.add_task(self.home, "solve", "fix login", "ticket:goodqa#2")
        for bad in ("building", "converged", "verifying", "done"):
            with self.assertRaises(ort.OwnerError, msg=bad):
                ort.move_task(self.home, "solve", "t1", bad)

    def test_state_symlinked_owner_dir_refused(self):
        root = self.home / ".agent-harness" / "owners"
        root.mkdir(parents=True)
        (self.home / "elsewhere").mkdir()
        os.symlink(self.home / "elsewhere", root / "solve")
        with self.assertRaises(ort.OwnerError):
            self.init()


class ConvergeLoopTests(Base):
    def setUp(self):
        super().setUp()
        self.init()
        ort.add_task(self.home, "solve", "fix login", "ticket:goodqa#2")

    def test_converge_planned_needs_ac_with_verify_and_neg(self):
        bad = self.home / "bad.md"
        bad.write_text("AC-1 loads\nAC-2 saves\nVerify by: x y\nNEG-1 no\n")  # AC-1 lacks Verify by
        with self.assertRaises(ort.OwnerError):
            ort.move_task(self.home, "solve", "t1", "planned", ac_file=str(bad))
        bad.write_text("AC-1 loads\nVerify by: pytest x\n")  # no NEG
        with self.assertRaises(ort.OwnerError):
            ort.move_task(self.home, "solve", "t1", "planned", ac_file=str(bad))
        ort.move_task(self.home, "solve", "t1", "planned", ac_file=str(self.ac))

    def test_converge_needs_reviewer_accept_before_building(self):
        ort.move_task(self.home, "solve", "t1", "planned", ac_file=str(self.ac))
        with self.assertRaises(ort.OwnerError):
            ort.move_task(self.home, "solve", "t1", "building")
        with self.assertRaises(ort.OwnerError):
            ort.move_task(self.home, "solve", "t1", "converged", reviewer="a1234567890abcdef", verdict="REJECT")
        with self.assertRaises(ort.OwnerError):  # no recorded review round yet (r1 m2)
            ort.move_task(self.home, "solve", "t1", "converged", reviewer="a1234567890abcdef", verdict="ACCEPT")
        ort.review_round(self.home, "solve", "t1", "a1234567890abcdef", "REJECT")
        with self.assertRaises(ort.OwnerError):  # latest round is a REJECT
            ort.move_task(self.home, "solve", "t1", "converged", reviewer="a1234567890abcdef", verdict="ACCEPT")
        ort.review_round(self.home, "solve", "t1", "a1234567890abcdef", "ACCEPT")
        with self.assertRaises(ort.OwnerError):  # a different reviewer than the one who accepted
            ort.move_task(self.home, "solve", "t1", "converged", reviewer="b1234567890abcdef", verdict="ACCEPT")
        ort.move_task(self.home, "solve", "t1", "converged", reviewer="a1234567890abcdef", verdict="ACCEPT")
        ort.move_task(self.home, "solve", "t1", "building")

    def test_loop_two_rejects_force_break(self):
        ort.move_task(self.home, "solve", "t1", "planned", ac_file=str(self.ac))
        ort.review_round(self.home, "solve", "t1", "a1234567890abcdef", "REJECT")
        ort.review_round(self.home, "solve", "t1", "a1234567890abcdef", "REVISE")
        t = ort.tasks(ort.inbox_rows(self.home, "solve"))["t1"]
        self.assertTrue(t["loop"])
        with self.assertRaises(ort.OwnerError):
            ort.review_round(self.home, "solve", "t1", "a1234567890abcdef", "ACCEPT")
        with self.assertRaises(ort.OwnerError):
            ort.move_task(self.home, "solve", "t1", "converged", reviewer="a1234567890abcdef", verdict="ACCEPT")
        with self.assertRaises(ort.OwnerError):
            ort.break_loop(self.home, "solve", "t1", "park", "no-ticket")
        ort.break_loop(self.home, "solve", "t1", "redesign", "split the flow", ac_file=str(self.ac))
        self.assertFalse(ort.tasks(ort.inbox_rows(self.home, "solve"))["t1"]["loop"])
        ort.review_round(self.home, "solve", "t1", "a1234567890abcdef", "ACCEPT")

    def test_loop_park_blocks_task_with_ticket(self):
        ort.move_task(self.home, "solve", "t1", "planned", ac_file=str(self.ac))
        ort.break_loop(self.home, "solve", "t1", "park", "goodqa#99")
        t = ort.tasks(ort.inbox_rows(self.home, "solve"))["t1"]
        self.assertEqual(t["state"], "blocked")
        self.assertIn("goodqa#99", t["help"])

    def test_blocked_needs_help_and_returns_to_prior_state(self):
        ort.move_task(self.home, "solve", "t1", "planned", ac_file=str(self.ac))
        with self.assertRaises(ort.OwnerError):
            ort.move_task(self.home, "solve", "t1", "blocked")
        ort.move_task(self.home, "solve", "t1", "blocked", help_text="need prod DB read grant")
        with self.assertRaises(ort.OwnerError):
            ort.move_task(self.home, "solve", "t1", "building")
        ort.move_task(self.home, "solve", "t1", "planned")

    def test_done_needs_resolving_evidence(self):
        ort.move_task(self.home, "solve", "t1", "planned", ac_file=str(self.ac))
        ort.review_round(self.home, "solve", "t1", "a1234567890abcdef", "ACCEPT")
        ort.move_task(self.home, "solve", "t1", "converged", reviewer="a1234567890abcdef", verdict="ACCEPT")
        ort.move_task(self.home, "solve", "t1", "building")
        ort.move_task(self.home, "solve", "t1", "verifying")
        with self.assertRaises(ort.OwnerError):
            ort.move_task(self.home, "solve", "t1", "done", evidence=["commit:deadbeefdeadbeef"])
        with self.assertRaises(ort.OwnerError):  # the repo's first commit predates the task (r1 M8)
            ort.move_task(self.home, "solve", "t1", "done", evidence=[f"commit:{self.sha}"])
        time.sleep(1.1)
        subprocess.run(["git", "-C", str(self.repo), "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-q",
                        "--allow-empty", "-m", "work"], check=True)
        new = subprocess.run(["git", "-C", str(self.repo), "rev-parse", "HEAD"], capture_output=True,
                             text=True).stdout.strip()
        ort.move_task(self.home, "solve", "t1", "done", evidence=[f"commit:{new}"])


class ProofTests(Base):
    def test_proof_beat_refuses_unresolved_evidence(self):
        self.init()
        with self.assertRaises(ort.OwnerError):
            ort.beat(self.home, "solve", ["commit:deadbeefdeadbeef", "wal:w000000000000"], "next")
        b = ort.beat(self.home, "solve", [f"commit:{self.sha}"], "wire the API")
        self.assertEqual(b["evidence"], [f"commit:{self.sha}"])

    def test_proof_wal_evidence_in_owner_session(self):
        self.init()
        self.set_session()
        wal = self.home / ".claude" / "wals" / SID
        wal.mkdir(parents=True)
        (wal / "main.jsonl").write_text(json.dumps({"event": "check", "id": "w0123456789a",
                                                     "at": ort.now_iso()}) + "\n")
        ort.beat(self.home, "solve", ["wal:w0123456789a"], "")

    def test_proof_old_evidence_cannot_reset_clock_or_clear_stuck(self):
        self.init()
        ort.beat(self.home, "solve", [f"commit:{self.sha}"], "first")
        st = ort.load_state(self.home, "solve")
        st["stuck"], st["no_progress_launches"] = True, 3
        ort.save_state(self.home, "solve", st)
        with self.assertRaises(ort.OwnerError):  # same commit again, made before the last proof
            ort.beat(self.home, "solve", [f"commit:{self.sha}"], "again", now=time.time() + 5)
        self.assertTrue(ort.load_state(self.home, "solve")["stuck"])

    def test_proof_first_beat_rejects_stale_commit(self):
        self.init()
        with self.assertRaises(ort.OwnerError):
            ort.beat(self.home, "solve", [f"commit:{self.sha}"], "", now=time.time() + 3 * 3600)

    def test_proof_age_29_and_31_minutes(self):
        self.init()
        st = ort.load_state(self.home, "solve")
        st["last_beat"] = {"ts": NOW - 29 * 60}
        ort.save_state(self.home, "solve", st)
        self.assertEqual(ort.due_reason(self.home, "solve", ort.load_state(self.home, "solve"), NOW), "")
        st["last_beat"] = {"ts": NOW - 31 * 60}
        ort.save_state(self.home, "solve", st)
        self.assertIn("proof", ort.due_reason(self.home, "solve", ort.load_state(self.home, "solve"), NOW))


class SubagentStopTests(Base):
    """The owner session's Stop hook (`owner_rt.py stop`); named for the gate id own-stop-gate."""

    def setUp(self):
        super().setUp()
        self.init()
        self.set_session()

    def decide(self, sid=SID, now=None):
        return ort.stop_decision(self.home, {"session_id": sid, "hook_event_name": "Stop"}, now=now)

    def test_subagent_stop_unrecorded_session_in_owner_workspace_is_gated_and_adopted(self):
        other = "99999999-2222-3333-4444-555555555555"
        ort.add_task(self.home, "solve", "x", "ticket:goodqa#2")
        out = ort.stop_decision(self.home, {"session_id": other, "cwd": str(self.repo)})
        self.assertEqual(out.get("decision"), "block")
        self.assertEqual(ort.load_state(self.home, "solve")["session_id"], other)
        self.assertEqual(ort.stop_decision(self.home, {"session_id": "88888888-2222-3333-4444-555555555555",
                                                       "cwd": str(self.home)}), {})  # another directory

    def test_subagent_stop_non_owner_session_never_blocked(self):
        ort.add_task(self.home, "solve", "x", "ticket:goodqa#2")
        self.assertEqual(self.decide(sid="99999999-2222-3333-4444-555555555555"), {})

    def test_subagent_stop_blocks_while_task_actionable(self):
        ort.add_task(self.home, "solve", "fix login", "ticket:goodqa#2")
        ort.checkpoint(self.home, "solve", "working t1")
        out = self.decide()
        self.assertEqual(out.get("decision"), "block")
        self.assertIn("t1", out["reason"])

    def test_subagent_stop_wait_with_other_open_task_blocked(self):
        ort.add_task(self.home, "solve", "needs review", "ticket:goodqa#2")
        ort.add_task(self.home, "solve", "other facet", "ticket:goodqa#3")
        ort.move_task(self.home, "solve", "t1", "blocked", help_text="waiting on review")
        ort.checkpoint(self.home, "solve", "t1 waits")
        out = self.decide()
        self.assertEqual(out.get("decision"), "block")
        self.assertIn("t2", out["reason"])

    def test_subagent_stop_all_blocked_with_checkpoint_allowed_and_resume_scheduled(self):
        ort.add_task(self.home, "solve", "needs grant", "ticket:goodqa#2")
        ort.move_task(self.home, "solve", "t1", "blocked", help_text="need grant")
        ort.checkpoint(self.home, "solve", "all blocked on grant")
        self.assertEqual(self.decide(), {})
        self.assertTrue(ort.load_state(self.home, "solve")["resume"].get("due_ts"))

    def test_subagent_stop_no_checkpoint_blocks(self):
        out = self.decide()
        self.assertEqual(out.get("decision"), "block")
        self.assertIn("checkpoint", out["reason"])

    def test_subagent_stop_done_goal_allowed(self):
        self.goals[0]["status"] = "done"
        self.write_goals()
        ort.add_task(self.home, "solve", "x", "ticket:goodqa#2")
        self.assertEqual(self.decide(), {})

    def test_subagent_stop_bounded_per_signature(self):
        ort.add_task(self.home, "solve", "x", "ticket:goodqa#2")
        blocks = [self.decide().get("decision") for _ in range(ort.MAX_STOP_BLOCKS_PER_SIG + 2)]
        self.assertEqual(blocks.count("block"), ort.MAX_STOP_BLOCKS_PER_SIG)

    def test_subagent_stop_internal_error_allows(self):
        with mock.patch.object(ort, "stop_decision", side_effect=RuntimeError("boom")), \
                mock.patch("sys.stdout", new_callable=io.StringIO) as out:
            self.assertEqual(ort.cmd_stop(io.StringIO(json.dumps({"session_id": SID}))), 0)
        self.assertNotIn('"block"', out.getvalue())


class TickTests(Base):
    def setUp(self):
        super().setUp()
        self.init()
        self.set_session()
        (self.home / ".agent-harness" / "owners" / "runtime.json").write_text(json.dumps({"enabled": True}))
        self.calls, self.cwds = [], []
        p = mock.patch.object(ort, "claude_bin", return_value="claude")
        p.start()
        self.addCleanup(p.stop)
        self.sessions = [{"id": "8d84dcef", "sessionId": SID, "pid": 1, "status": "idle", "state": "done"}]

    def runner(self, argv, timeout=60, cwd=None):
        self.calls.append(argv)
        if "--bg" in argv:
            self.cwds.append(cwd)
        if argv[1:2] == ["agents"]:
            return 0, json.dumps(self.sessions + [{"id": "c9f43044", "sessionId": "new-session-id-0001"}])
        if "--bg" in argv:
            return 0, "backgrounded · c9f43044 · owner-solve"
        return 0, ""

    def test_tick_resumes_idle_owner_with_actionable_task(self):
        proj = self.home / ".claude" / "projects" / "-x"
        proj.mkdir(parents=True)
        (proj / f"{SID}.jsonl").write_text("{}\n")
        ort.add_task(self.home, "solve", "fix login", "ticket:goodqa#2")
        out = ort.tick(self.home, now=NOW, runner=self.runner)
        self.assertEqual(out[0]["action"], "launch")
        launch = [c for c in self.calls if "--bg" in c][0]
        self.assertEqual(launch[launch.index("--resume") + 1], SID)
        self.assertIn("OWNER RESUME", launch[-1])
        self.assertIn("t1", launch[-1])
        st = ort.load_state(self.home, "solve")
        self.assertEqual(st["bg_id"], "c9f43044")
        self.assertEqual(st["session_id"], "new-session-id-0001")
        self.assertIn(["claude", "stop", "8d84dcef"], self.calls)
        self.assertEqual(self.cwds, [str(self.repo.resolve())])  # launched in the owner's workspace (live G2 bug)

    def test_tick_fresh_generation_when_transcript_missing(self):
        ort.add_task(self.home, "solve", "fix login", "ticket:goodqa#2")
        ort.tick(self.home, now=NOW, runner=self.runner)
        launch = [c for c in self.calls if "--bg" in c][0]
        self.assertNotIn("--resume", launch)
        self.assertIn("OWNER CHARTER", launch[-1])
        self.assertEqual(ort.load_state(self.home, "solve")["generation"], 1)

    def test_tick_observed_busy_states_never_stopped(self):
        # observed live: mid-turn, and turn ended while a background sub-agent runs, both read busy/working
        self.sessions[0].update(status="busy", state="working")
        ort.add_task(self.home, "solve", "fix login", "ticket:goodqa#2")
        self.assertEqual(ort.tick(self.home, now=NOW, runner=self.runner)[0]["reason"], "running")
        self.assertFalse([c for c in self.calls if c[1:2] == ["stop"] or "--bg" in c])

    def test_tick_finds_owner_by_name_and_stops_every_idle_duplicate(self):
        self.sessions.append({"id": "aa11bb22", "sessionId": "other-0001", "pid": 2, "status": "idle", "state": "done",
                              "name": "owner-solve"})
        ort.add_task(self.home, "solve", "fix login", "ticket:goodqa#2")
        ort.tick(self.home, now=NOW, runner=self.runner)
        stops = [c[2] for c in self.calls if c[1:2] == ["stop"]]
        self.assertEqual(sorted(stops), ["8d84dcef", "aa11bb22"])

    def test_tick_unknown_name_session_busy_blocks_second_launch(self):
        st = ort.load_state(self.home, "solve")
        st["session_id"] = ""  # id lookup failed after the last launch
        ort.save_state(self.home, "solve", st)
        self.sessions[:] = [{"id": "aa11bb22", "sessionId": "x", "pid": 2, "status": "busy", "state": "working",
                             "name": "owner-solve"}]
        ort.add_task(self.home, "solve", "fix login", "ticket:goodqa#2")
        self.assertEqual(ort.tick(self.home, now=NOW, runner=self.runner)[0]["reason"], "running")

    def test_tick_every_launch_is_a_generation_and_lost_id_cleared(self):
        def runner(argv, timeout=60, cwd=None):
            if argv[1:2] == ["agents"]:
                return 0, json.dumps(self.sessions)  # the new session is not listed: lookup fails
            return (0, "backgrounded · c9f43044 · owner-solve") if "--bg" in argv else (0, "")
        ort.add_task(self.home, "solve", "fix login", "ticket:goodqa#2")
        ort.tick(self.home, now=NOW, runner=runner)
        st = ort.load_state(self.home, "solve")
        self.assertEqual((st["generation"], st["session_id"]), (1, ""))

    def test_tick_prompt_cites_inbox_head(self):
        ort.add_task(self.home, "solve", "fix login", "ticket:goodqa#2")
        ort.tick(self.home, now=NOW, runner=self.runner)
        prompt = [c for c in self.calls if "--bg" in c][0][-1]
        self.assertIn("Inbox head: " + ort.inbox_head(self.home, "solve"), prompt)

    def test_flags_unstick_pause(self):
        st = ort.load_state(self.home, "solve")
        st["stuck"], st["no_progress_launches"] = True, 3
        ort.save_state(self.home, "solve", st)
        with self.assertRaises(ort.OwnerError):
            ort.set_flag(self.home, "solve", "pause", "inferred:from x -- y")
        ort.set_flag(self.home, "solve", "unstick", "ticket:goodqa#2")
        self.assertFalse(ort.load_state(self.home, "solve")["stuck"])
        ort.set_flag(self.home, "solve", "pause", "ticket:goodqa#2")
        ort.add_task(self.home, "solve", "fix login", "ticket:goodqa#2")
        self.assertIn("paused", ort.tick(self.home, now=NOW, runner=self.runner)[0]["reason"])

    def test_tick_busy_owner_left_alone(self):
        self.sessions[0].update(status="busy", state="running")
        ort.add_task(self.home, "solve", "fix login", "ticket:goodqa#2")
        self.assertEqual(ort.tick(self.home, now=NOW, runner=self.runner)[0]["action"], "none")

    def test_tick_nothing_due_no_launch(self):
        st = ort.load_state(self.home, "solve")
        st["last_beat"] = {"ts": NOW - 60}
        ort.save_state(self.home, "solve", st)
        self.assertEqual(ort.tick(self.home, now=NOW, runner=self.runner)[0]["reason"], "nothing due")

    def test_tick_disabled_runtime_never_launches(self):
        (self.home / ".agent-harness" / "owners" / "runtime.json").write_text(json.dumps({"enabled": False}))
        ort.add_task(self.home, "solve", "fix login", "ticket:goodqa#2")
        self.assertEqual(ort.tick(self.home, now=NOW, runner=self.runner)[0]["action"], "would-launch")
        self.assertFalse([c for c in self.calls if "--bg" in c])

    def test_tick_rate_limits_and_stuck(self):
        ort.add_task(self.home, "solve", "fix login", "ticket:goodqa#2")
        actions = []
        for i in range(6):
            actions.append(ort.tick(self.home, now=NOW + i * 400, runner=self.runner)[0]["action"])
        self.assertEqual(actions[:3], ["launch", "launch", "launch"])
        self.assertEqual(actions[3], "stuck")
        self.assertEqual(len([c for c in self.calls if "--bg" in c]), 3)

    def test_tick_min_gap(self):
        ort.add_task(self.home, "solve", "fix login", "ticket:goodqa#2")
        ort.tick(self.home, now=NOW, runner=self.runner)
        self.assertEqual(ort.tick(self.home, now=NOW + 60, runner=self.runner)[0]["reason"], "min gap")

    def test_tick_done_goal_never_launches(self):
        self.goals[0]["status"] = "done"
        self.write_goals()
        ort.add_task(self.home, "solve", "fix login", "ticket:goodqa#2")
        self.assertEqual(ort.tick(self.home, now=NOW, runner=self.runner)[0]["reason"], "goal done")

    def test_tick_untrusted_workspace_failure_logged(self):
        def runner(argv, timeout=60, cwd=None):
            if argv[1:2] == ["agents"]:
                return 0, json.dumps(self.sessions)
            if "--bg" in argv:
                return 1, "Workspace not trusted."
            return 0, ""
        ort.add_task(self.home, "solve", "fix login", "ticket:goodqa#2")
        out = ort.tick(self.home, now=NOW, runner=runner)
        self.assertEqual(out[0]["action"], "launch-failed")
        self.assertIn("trusted", (self.home / ".agent-harness/owners/solve/launch.log").read_text())


class HardeningTests(Base):
    """Red-team r1 fixes: M1 M2 M3 M7 M8 m4."""

    def write_runtime(self, data):
        root = self.home / ".agent-harness" / "owners"
        root.mkdir(parents=True, exist_ok=True)
        (root / "runtime.json").write_text(json.dumps(data))

    def test_runtime_claude_field_ignored_and_brakes_clamped(self):
        self.write_runtime({"enabled": True, "claude": "/tmp/evil.sh", "min_gap_s": 0, "max_launches_per_hour": 999,
                            "fresh_bytes": 1})
        with mock.patch.object(ort, "claude_bin", return_value="/x/claude"):
            cfg = ort.runtime(self.home)
        self.assertEqual(cfg["claude"], "/x/claude")
        self.assertEqual((cfg["min_gap_s"], cfg["max_launches_per_hour"], cfg["fresh_bytes"]), (120, 6, 200_000))

    def test_runtime_disabled_runs_no_program(self):
        self.write_runtime({"enabled": False})
        self.init()
        ort.add_task(self.home, "solve", "x", "ticket:goodqa#2")
        calls = []
        out = ort.tick(self.home, now=NOW, runner=lambda *a, **k: calls.append(a) or (0, "[]"))
        self.assertEqual(calls, [])
        self.assertEqual(out[0]["action"], "would-launch")

    def test_runtime_bypass_needs_user_words(self):
        self.write_runtime({"enabled": True, "permission_mode": "bypassPermissions"})
        self.assertEqual(ort.runtime(self.home)["permission_mode"], "auto")
        self.write_runtime({"enabled": True, "permission_mode": "bypassPermissions",
                            "permission_source": "answer:s/u \"Bypass, like main\""})
        with mock.patch.object(ort, "user_decided", return_value=True):
            self.assertEqual(ort.runtime(self.home)["permission_mode"], "bypassPermissions")

    def test_model_top_rungs_refused(self):
        for bad in ("fable", "astra", "claude-fable-5", "x; rm"):
            with self.assertRaises(ort.OwnerError, msg=bad):
                ort.init_owner(self.home, "solve", str(self.repo), "ticket:goodqa#1", model=bad)
        ort.init_owner(self.home, "solve", str(self.repo), "ticket:goodqa#1", model="opus")

    def test_ac_file_fifo_and_huge_refused(self):
        fifo = self.home / "fifo"
        os.mkfifo(fifo)
        self.assertIn("regular", ort.ac_file_problem(str(fifo)))
        big = self.home / "big.md"
        big.write_text("AC-1 x\nVerify by: y z\nNEG-1 q\n" + "x" * 300_000)
        self.assertIn("larger", ort.ac_file_problem(str(big)))

    def test_proof_wal_row_must_be_a_proof_event(self):
        self.init()
        self.set_session()
        wal = self.home / ".claude" / "wals" / SID
        wal.mkdir(parents=True)
        (wal / "main.jsonl").write_text(json.dumps({"event": "intent", "id": "w0123456789b", "at": ort.now_iso()})
                                        + "\n")
        with self.assertRaises(ort.OwnerError):
            ort.beat(self.home, "solve", ["wal:w0123456789b"], "")

    def test_cli_main_only_commands_need_main_stamp(self):
        self.init()
        import caller_identity
        with mock.patch.object(caller_identity, "take_stamp", return_value=None):
            for argv in (["init", "--goal", "x", "--cwd", ".", "--source", "ticket:goodqa#1"],
                         ["task", "add", "--goal", "solve", "--text", "t", "--source", "ticket:goodqa#1"],
                         ["pause", "--goal", "solve", "--source", "ticket:goodqa#1"],
                         ["task", "move", "--goal", "solve", "--task", "t1", "--to", "dropped"]):
                with mock.patch("sys.stderr"):
                    self.assertEqual(ort.main(argv), 2, argv)
        self.assertEqual(ort.inbox_rows(self.home, "solve"), [])

    def test_cli_task_add_by_owner_session_or_main(self):
        self.init()
        self.set_session()
        import caller_identity
        import mission_coverage
        argv = ["task", "add", "--goal", "solve", "--text", "t", "--source", "ticket:goodqa#1"]
        with mock.patch.object(mission_coverage, "mission_session_of", return_value="main-session-0000"), \
                mock.patch("sys.stdout"), mock.patch("sys.stderr"):
            with mock.patch.object(caller_identity, "take_stamp", return_value={"session": SID}):
                self.assertEqual(ort.main(argv), 0)  # the goal's own owner session
            with mock.patch.object(caller_identity, "take_stamp", return_value={"session": "main-session-0000"}):
                self.assertEqual(ort.main(argv), 0)  # main
            with mock.patch.object(caller_identity, "take_stamp", return_value={"session": "other-owner-0000"}):
                self.assertEqual(ort.main(argv), 2)  # another owner's session
            with mock.patch.object(caller_identity, "take_stamp", return_value={"session": SID}):
                self.assertEqual(ort.main(["pause", "--goal", "solve", "--source", "ticket:goodqa#1"]), 2)


class MissionGateStampTests(unittest.TestCase):
    def test_gate_stamps_only_guarded_owner_commands_with_matching_key(self):
        import mission_gate
        line = "python3 ~/.claude/hooks/owner_rt.py task add --goal solve --text 'fix it' --source ticket:goodqa#1"
        got = mission_gate.owner_stamps_for(line)
        argv = ["task", "add", "--goal", "solve", "--text", "fix it", "--source", "ticket:goodqa#1"]
        self.assertEqual(got, [("task add", ort.argv_key(argv))])
        for line in ("echo python3 owner_rt.py init --goal x", "python3 owner_rt.py beat --goal x --evidence a:b",
                     "cat owner_rt.py | grep init", "python3 owner_rt.py show --goal x"):
            self.assertEqual(mission_gate.owner_stamps_for(line), [], line)

    def test_gate_pretool_writes_owner_stamp_for_main_only(self):
        import caller_identity
        import mission_gate
        payload = {"tool_name": "Bash", "session_id": "s1", "tool_use_id": "toolu_0123456789abcdefABCDEF",
                   "tool_input": {"command": "python3 owner_rt.py pause --goal solve --source ticket:goodqa#1"}}
        with mock.patch.object(caller_identity, "put_stamp") as put:
            with mock.patch.object(caller_identity, "is_main", return_value=False):
                mission_gate.cmd_pretool(payload)
            self.assertFalse(put.called)
            with mock.patch.object(caller_identity, "is_main", return_value=True):
                mission_gate.cmd_pretool(payload)
        self.assertEqual(put.call_args.args[0], "owner-main")
        self.assertEqual(put.call_args.args[1][0], "pause")


if __name__ == "__main__":
    unittest.main()
