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
sys.path.insert(0, str(Path(__file__).resolve().parent))
import owner_rt as ort  # noqa: E402
import authority_fixture as fx  # noqa: E402

NOW = 1_800_000_000.0
SID = "11111111-2222-3333-4444-555555555555"
NEW_SID = "99999999-8888-7777-6666-555555555555"
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

    def transcript(self, sid, name="owner-solve", first="OWNER CHARTER (owner_rt, written by the harness)"):
        d = self.home / ".claude" / "projects" / "-ws"
        d.mkdir(parents=True, exist_ok=True)
        rows = [{"type": "agent-name", "agentName": name, "sessionId": sid},
                {"type": "user", "message": {"role": "user", "content": first}, "sessionId": sid}]
        (d / f"{sid}.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows))

    def test_subagent_stop_unrecorded_session_in_owner_workspace_is_gated_and_adopted(self):
        other = "99999999-2222-3333-4444-555555555555"
        ort.add_task(self.home, "solve", "x", "ticket:goodqa#2")
        self.set_session("")
        st = ort.load_state(self.home, "solve")
        st["launches"] = [{"ts": NOW - 60, "code": 0}]
        ort.save_state(self.home, "solve", st)
        self.transcript(other)
        out = ort.stop_decision(self.home, {"session_id": other, "cwd": str(self.repo)}, now=NOW)
        self.assertEqual(out.get("decision"), "block")
        self.assertEqual(ort.load_state(self.home, "solve")["session_id"], other)
        self.assertEqual(ort.stop_decision(self.home, {"session_id": "88888888-2222-3333-4444-555555555555",
                                                       "cwd": str(self.home)}, now=NOW), {})  # another directory

    def test_subagent_stop_foreign_session_in_workspace_never_adopted(self):
        """Delta D1: main, a reviewer or a `claude -p` run stopping in the owner workspace is not the owner."""
        foreign = "77777777-2222-3333-4444-555555555555"
        ort.add_task(self.home, "solve", "x", "ticket:goodqa#2")
        payload = {"session_id": foreign, "cwd": str(self.repo)}
        self.transcript(foreign)
        self.assertEqual(ort.stop_decision(self.home, payload, now=NOW), {})  # an id is already recorded
        self.assertEqual(ort.load_state(self.home, "solve")["session_id"], SID)
        self.set_session("")
        self.assertEqual(ort.stop_decision(self.home, payload, now=NOW), {})  # no recent successful launch
        st = ort.load_state(self.home, "solve")
        st["launches"] = [{"ts": NOW - 3 * 3600, "code": 0}, {"ts": NOW - 60, "code": 1}]
        ort.save_state(self.home, "solve", st)
        self.assertEqual(ort.stop_decision(self.home, payload, now=NOW), {})  # old or failed launches only
        st["launches"].append({"ts": NOW - 60, "code": 0})
        ort.save_state(self.home, "solve", st)
        for name, first in (("main", "OWNER CHARTER (owner_rt"), ("owner-solve", "please review this diff"),
                            ("owner-other", "OWNER RESUME (owner_rt")):
            self.transcript(foreign, name=name, first=first)
            self.assertEqual(ort.stop_decision(self.home, payload, now=NOW), {}, name)
        self.assertEqual(ort.load_state(self.home, "solve")["session_id"], "")
        st = ort.load_state(self.home, "solve")
        out = ort.tick(self.home, now=NOW + 600, dry_run=True, runner=lambda *a, **k: (0, "[]"))
        self.assertNotIn(foreign, json.dumps(out))

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
            return 0, json.dumps(self.sessions + [{"id": "c9f43044", "sessionId": NEW_SID}])
        if "--bg" in argv:
            return 0, "backgrounded · c9f43044 · owner-solve"
        if argv[1:2] == ["stop"]:
            if getattr(self, "stop_code", 0):
                return self.stop_code, "stop failed"
            if not getattr(self, "stop_ignored", False):
                for a in self.sessions:
                    if a.get("id") == argv[2]:
                        a.pop("pid", None)  # the real listing drops pid for a stopped session
        return 0, ""

    def test_tick_replace_refused_unless_old_session_proven_stopped(self):
        """Receipt v3 F3: a failed or ineffective stop, an id-less session, or one working again: no new launch."""
        ort.add_task(self.home, "solve", "fix login", "ticket:goodqa#2")
        cases = [("stop_code", 1, "failed"), ("stop_ignored", True, "still live")]
        for i, (attr, value, why) in enumerate(cases):
            self.calls = []
            self.sessions = [{"id": "8d84dcef", "sessionId": SID, "pid": 1, "status": "idle", "state": "done"}]
            setattr(self, attr, value)
            out = ort.tick(self.home, now=NOW + i * 4000, runner=self.runner)
            setattr(self, attr, 0 if attr == "stop_code" else False)
            self.assertEqual(out[0]["action"], "launch-failed", why)
            self.assertIn(why, out[0]["reason"])
            self.assertEqual([c for c in self.calls if "--bg" in c], [], why)
        st = ort.load_state(self.home, "solve")
        self.assertEqual([x["code"] for x in st["launches"]], [-1, -1])  # refusals count toward the hourly brake
        self.assertEqual(st["generation"], 0)
        self.calls = []
        self.sessions = [{"id": "", "sessionId": SID, "pid": 1, "status": "idle", "state": "done"}]
        out = ort.tick(self.home, now=NOW + 9000, runner=self.runner)
        self.assertIn("no id", out[0]["reason"])
        self.assertEqual([c for c in self.calls if "--bg" in c], [])

    def test_tick_replace_never_stops_a_session_working_again(self):
        ort.add_task(self.home, "solve", "fix login", "ticket:goodqa#2")
        listings = iter([[{"id": "8d84dcef", "sessionId": SID, "pid": 1, "status": "idle", "state": "done"}],
                         [{"id": "8d84dcef", "sessionId": SID, "pid": 1, "status": "busy", "state": "working"}]])

        def runner(argv, timeout=60, cwd=None):
            self.calls.append(argv)
            if argv[1:2] == ["agents"]:
                return 0, json.dumps(next(listings))
            return 0, "backgrounded · c9f43044 · owner-solve" if "--bg" in argv else ""
        out = ort.tick(self.home, now=NOW, runner=runner)
        self.assertEqual(out[0]["action"], "launch-failed")
        self.assertNotIn(["claude", "stop", "8d84dcef"], self.calls)
        self.assertEqual([c for c in self.calls if "--bg" in c], [])

    def test_tick_attempt_recorded_before_launch_and_on_exception(self):
        """Receipt v4 F3: the attempt is on disk before the launch runs; an exception still counts for the brakes."""
        ort.add_task(self.home, "solve", "fix login", "ticket:goodqa#2")
        seen = []

        def runner(argv, timeout=60, cwd=None):
            if argv[1:2] == ["agents"]:
                return 0, json.dumps([a for a in self.sessions if a.get("pid")])
            if argv[1:2] == ["stop"]:
                for a in self.sessions:
                    if a.get("id") == argv[2]:
                        a.pop("pid", None)
                return 0, ""
            if "--bg" in argv:
                seen.append(ort.load_state(self.home, "solve")["launches"][-1]["code"])
                raise subprocess.TimeoutExpired(argv[:2], 90)
            return 0, ""
        out = ort.tick(self.home, now=NOW, runner=runner)
        self.assertEqual(seen, [None])  # pending attempt already saved when the launch ran
        self.assertEqual(out[0]["action"], "launch-failed")
        st = ort.load_state(self.home, "solve")
        self.assertEqual([x["code"] for x in st["launches"]], [-2])
        self.assertIn("TimeoutExpired", (self.home / ".agent-harness/owners/solve/launch.log").read_text())
        self.assertEqual(ort.tick(self.home, now=NOW + 30, runner=runner)[0]["reason"], "min gap")

    def test_tick_stop_exception_recorded_and_braked(self):
        ort.add_task(self.home, "solve", "fix login", "ticket:goodqa#2")

        def runner(argv, timeout=60, cwd=None):
            if argv[1:2] == ["agents"]:
                return 0, json.dumps(self.sessions)
            if argv[1:2] == ["stop"]:
                raise subprocess.TimeoutExpired(argv[:2], 30)
            if "--bg" in argv:
                self.fail("must not launch after a stop raised")
            return 0, ""
        out = ort.tick(self.home, now=NOW, runner=runner)
        self.assertEqual(out[0]["action"], "launch-failed")
        self.assertEqual([x["code"] for x in ort.load_state(self.home, "solve")["launches"]], [-1])
        self.assertEqual(ort.tick(self.home, now=NOW + 30, runner=runner)[0]["reason"], "min gap")

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
        self.assertEqual(st["session_id"], NEW_SID)
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
        self.sessions.append({"id": "aa11bb22", "sessionId": "22222222-0000-0000-0000-000000000001", "pid": 2, "status": "idle", "state": "done",
                              "name": "owner-solve"})
        ort.add_task(self.home, "solve", "fix login", "ticket:goodqa#2")
        ort.tick(self.home, now=NOW, runner=self.runner)
        stops = [c[2] for c in self.calls if c[1:2] == ["stop"]]
        self.assertEqual(sorted(stops), ["8d84dcef", "aa11bb22"])

    def test_tick_unknown_name_session_busy_blocks_second_launch(self):
        st = ort.load_state(self.home, "solve")
        st["session_id"] = ""  # id lookup failed after the last launch
        ort.save_state(self.home, "solve", st)
        self.sessions[:] = [{"id": "aa11bb22", "sessionId": "22222222-0000-0000-0000-000000000002", "pid": 2, "status": "busy", "state": "working",
                             "name": "owner-solve"}]
        ort.add_task(self.home, "solve", "fix login", "ticket:goodqa#2")
        self.assertEqual(ort.tick(self.home, now=NOW, runner=self.runner)[0]["reason"], "running")

    def test_tick_every_launch_is_a_generation_and_lost_id_cleared(self):
        def runner(argv, timeout=60, cwd=None):
            if argv[1:2] == ["stop"]:
                for a in self.sessions:
                    if a.get("id") == argv[2]:
                        a.pop("pid", None)
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
            if argv[1:2] == ["stop"]:
                for a in self.sessions:
                    if a.get("id") == argv[2]:
                        a.pop("pid", None)
            if argv[1:2] == ["agents"]:
                return 0, json.dumps(self.sessions)
            if "--bg" in argv:
                return 1, "Workspace not trusted."
            return 0, ""
        ort.add_task(self.home, "solve", "fix login", "ticket:goodqa#2")
        out = ort.tick(self.home, now=NOW, runner=runner)
        self.assertEqual(out[0]["action"], "launch-failed")
        self.assertIn("trusted", (self.home / ".agent-harness/owners/solve/launch.log").read_text())


class CharterTests(Base):
    def test_charter_commands_parse(self):
        """Receipt F2: every command the charter tells the owner to run parses with the real CLI parser."""
        import re as _re
        import shlex
        self.init()
        text = ort.owner_prompt(self.home, "solve", resume=False)
        cmds = [c for c in _re.findall(r"`([^`]+)`", text) if "owner_rt" in c]
        self.assertGreaterEqual(len(cmds), 6, cmds)
        subs = ("task", "beat", "checkpoint", "show", "init", "prompt", "tick")
        bare = [c for c in _re.findall(r"`([^`]+)`", text) if c.split() and c.split()[0] in subs]
        self.assertEqual(bare, [], "charter commands must name the script so they run as written")
        parser = ort.build_parser()
        for c in cmds:
            words = shlex.split(_re.sub(r"(\w+)(?:\|\w+)+", r"\1", _re.sub(r"<[^>]*>", "x", c)))
            i = next(n for n, w in enumerate(words) if w.endswith("owner_rt.py"))
            argv = [w for w in words[i + 1:]]
            with mock.patch("sys.stderr"):
                try:
                    parser.parse_args(argv)
                except SystemExit as exc:
                    self.fail(f"charter command does not parse: {c} ({exc})")
        self.assertIn("--need", text)
        self.assertNotIn("--help \"", text)


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

    def test_init_workspace_must_be_dedicated(self):
        """Delta D1: the workspace identifies the owner session, so it is never a home dir or shared."""
        for bad in (str(self.home), str(Path.home()), "/"):
            with self.assertRaises(ort.OwnerError, msg=bad):
                ort.init_owner(self.home, "solve", bad, "ticket:goodqa#1")
        self.init()
        with self.assertRaises(ort.OwnerError):
            ort.init_owner(self.home, "shipped", str(self.repo), "ticket:goodqa#1")

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

    def test_cli_duplicate_or_abbreviated_goal_refused(self):
        """Receipt v4 F1: authorization and execution must read the same goal: a repeated --goal (argparse keeps the
        last) or an abbreviated spelling never lets one owner act on another goal."""
        self.init()
        self.set_session()
        (self.home / "repo2").mkdir()
        ort.init_owner(self.home, "shipped", str(self.home / "repo2"), "ticket:goodqa#1")
        import caller_identity
        import mission_coverage
        add = ["task", "add", "--goal", "solve", "--text", "t", "--source", "ticket:goodqa#1"]
        ort.add_task(self.home, "shipped", "victim", "ticket:goodqa#1")
        bad = [add + ["--goal", "shipped"], add + ["--goal=shipped"], add[:4] + ["--goa", "shipped"] + add[4:],
               ["task", "move", "--goal", "solve", "--task", "t1", "--to", "dropped", "--goal", "shipped"],
               ["task", "move", "--goal=solve", "--task", "t1", "--to=dropped", "--goal=shipped"]]
        with mock.patch.object(mission_coverage, "mission_session_of", return_value="main-session-0000"), \
                mock.patch.object(caller_identity, "take_stamp", return_value={"session": SID}), \
                mock.patch("sys.stdout"), mock.patch("sys.stderr"):
            for argv in bad:
                try:
                    code = ort.main(argv)
                except SystemExit as exc:
                    code = exc.code
                self.assertEqual(code, 2, argv)
        rows = ort.inbox_rows(self.home, "shipped")
        self.assertEqual([r.get("text") for r in rows if r.get("text")], ["victim"])
        self.assertEqual(ort.tasks(rows)["t1"]["state"], "queued")

    def test_cli_goal_layers_each_hold(self):
        """Receipt v4 F1, each layer alone: the repeat check, the parser without abbreviations, and the post-parse
        cross-check of command and goal."""
        add = ["task", "add", "--goal", "solve", "--text", "t", "--source", "ticket:goodqa#1"]
        self.assertIn("--goal", ort.argv_problem(add + ["--goal", "shipped"]))
        self.assertIn("--goal", ort.argv_problem(add + ["--goal=shipped"]))
        self.assertEqual(ort.argv_problem(["beat", "--goal", "solve", "--evidence", "a", "--evidence", "b"]), "")
        with mock.patch("sys.stderr"), self.assertRaises(SystemExit):
            ort.build_parser().parse_args(add[:4] + ["--goa", "shipped"] + add[4:])
        self.init()
        self.set_session()
        (self.home / "repo2").mkdir()
        ort.init_owner(self.home, "shipped", str(self.home / "repo2"), "ticket:goodqa#1")
        import caller_identity
        import mission_coverage
        with mock.patch.object(ort, "argv_problem", return_value=""), \
                mock.patch.object(mission_coverage, "mission_session_of", return_value="main-session-0000"), \
                mock.patch.object(caller_identity, "take_stamp", return_value={"session": SID}), \
                mock.patch("sys.stdout"), mock.patch("sys.stderr"):
            self.assertEqual(ort.main(add + ["--goal", "shipped"]), 2)  # the cross-check alone refuses it
        self.assertEqual(ort.inbox_rows(self.home, "shipped"), [])

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


# Every bypass phrase the earlier review rounds used (receipts v2-v6, delta D3): none may grant, whatever form it
# arrives in. The last group were positives under the text parser; they are refusals now.
BYPASS_PHRASES = (
    "Use bypass cache for this request.",                                   # v6 F1
    "Use bypassPermissions for the disposable test session.",               # v6 F1
    "What does bypassPermissions do?", "Should we use bypass", "If tests pass, use bypass",  # v4 F2
    "bypass would be nice", "maybe bypass", "use bypass when ready", "Can owners bypass",
    "What does bypassPermissions do", "is bypass on", "I wonder about bypass", "owners in bypass mode",
    "Do not use bypassPermissions for owners.",                             # v5 F1 (quoted in part below)
    "Thanks. If it is safe, use bypassPermissions for owners.", "No. use bypassPermissions for owners!",
    "Would you use bypassPermissions for owners?", "Ok use bypassPermissions for owners. Actually no, keep auto.",
    "do not bypass permissions", "never use bypass", "don't bypass", "ok go ahead", "yes",  # delta D3
    "Bypass, like main", "yes, use bypassPermissions for owners", "ok bypass",
    "Good work today. Yes, use bypassPermissions for owners.",
)


class AuthorityBase(Base):
    def setUp(self):
        super().setUp()
        self.init()
        self.set_session()
        ort.add_task(self.home, "solve", "fix login", "ticket:goodqa#2")
        p = mock.patch.dict(os.environ, {"CLAUDE_CONFIG_DIR": str(self.home / ".claude")})
        p.start()
        self.addCleanup(p.stop)
        p = mock.patch.object(ort, "claude_bin", return_value="claude")
        p.start()
        self.addCleanup(p.stop)
        import mission_coverage
        p = mock.patch.object(mission_coverage, "mission_session_of", return_value=fx.MISSION)
        p.start()
        self.addCleanup(p.stop)
        import command_guard
        p = mock.patch.object(command_guard, "_pinned_home", return_value=str(self.home))  # v7 F4: answers home
        p.start()
        self.addCleanup(p.stop)
        self.write_runtime({"enabled": True})

    def write_runtime(self, data):
        root = self.home / ".agent-harness" / "owners"
        root.mkdir(parents=True, exist_ok=True)
        (root / "runtime.json").write_text(json.dumps(data))

    def launch_mode(self, now=None):
        """The --permission-mode the tick would launch this owner with (dry run, no program runs)."""
        out = ort.tick(self.home, now=time.time() if now is None else now, dry_run=True,
                       runner=lambda *a, **k: (0, "[]"))
        argv = out[0].get("argv")
        self.assertTrue(argv, out)  # the tick did reach the launch: never vacuous
        return argv[argv.index("--permission-mode") + 1]

    def grant_answer(self, scope="*", hours=24, chosen=None, **kw):
        q = ort.bypass_question(scope, hours) if "question" not in kw else kw.pop("question")
        chosen = ort.BYPASS_LABEL if chosen is None else chosen
        options = kw.pop("options", ort.bypass_options(scope, hours))
        session = kw.pop("session", fx.MISSION)
        uid = fx.answer(self.home, session, q, chosen, options=options, **kw)
        return f"answer:{session}/{uid}"


class BypassAuthorityTests(AuthorityBase):
    """Receipt v6 F1: bypassPermissions only from the user's structured answer to the exact grant question."""

    def test_bypass_no_text_ever_grants_bypass(self):
        for words in BYPASS_PHRASES:
            uid = fx.human_turn(self.home, fx.MISSION, words)
            for quote in (words, "use bypassPermissions for owners"):
                if quote not in words:
                    continue
                src = f'user:{fx.MISSION}/{uid} "{quote}"'
                # 1. runtime.json naming bypass with the user's words as permission_source (the old path)
                self.write_runtime({"enabled": True, "permission_mode": "bypassPermissions",
                                    "permission_source": src})
                self.assertEqual(self.launch_mode(), "auto", words)
                self.assertIn("never comes from runtime.json", ort.runtime(self.home).get("note", ""))
                # 2. the words cited to the grant command
                with self.assertRaisesRegex(ort.OwnerError, "must be exactly answer:", msg=words):
                    ort.grant_bypass(self.home, "*", 24, src)
            for src in ("inferred:from x -- the user surely wants bypass", "wal:w0123456789a",
                        f'queue:{fx.MISSION}/2026-11-14T10:00:00Z#0123456789ab "{words}"', "", words):
                with self.assertRaisesRegex(ort.OwnerError, "must be exactly answer:", msg=src):
                    ort.grant_bypass(self.home, "*", 24, src)
            # 3. the words typed as the free-text "Other" reply to the exact grant question
            src = self.grant_answer(chosen=words)
            with self.assertRaisesRegex(ort.OwnerError, "did not choose", msg=words):
                ort.grant_bypass(self.home, "*", 24, src)
            # 4. the words as the question itself, with the user choosing the grant label
            src = self.grant_answer(question=words)
            with self.assertRaisesRegex(ort.OwnerError, "different question", msg=words):
                ort.grant_bypass(self.home, "*", 24, src)
        self.write_runtime({"enabled": True})
        self.assertEqual(self.launch_mode(), "auto")
        self.assertEqual(ort.load_authority(self.home)["bypass"], [])
        # positive control on the same fixture home: the exact structured answer does grant, and revoking ends it
        ort.grant_bypass(self.home, "*", 24, self.grant_answer())
        self.assertEqual(self.launch_mode(), "bypassPermissions")
        ort.revoke_bypass(self.home, "*")
        self.assertEqual(self.launch_mode(), "auto")

    def test_bypass_answer_must_fit_scope_hours_and_shape(self):
        cases = [
            ("declined", dict(chosen="No bypass: keep the configured mode"), "did not choose"),
            ("other hours", dict(question=ort.bypass_question("*", 48)), "different question"),
            ("other scope", dict(question=ort.bypass_question("solve", 24)), "different question"),
            ("multi-select", dict(multi=True), "single question"),
            ("two questions", dict(questions=[
                {"question": ort.bypass_question("*", 24), "multiSelect": False,
                 "options": [{"label": ort.BYPASS_LABEL}, {"label": "No"}]},
                {"question": "Anything else?", "multiSelect": False, "options": [{"label": "No"}]}],
                answers={ort.bypass_question("*", 24): ort.BYPASS_LABEL, "Anything else?": "No"}), "single question"),
            ("sub-agent", dict(sidechain=True), "resolve"),
            ("stale", dict(ts=time.time() - 25 * 3600), "older than"),
            ("not main's session", dict(session="bbbbbbbb-bbbb-cccc-dddd-eeeeeeeeeeee"), "mission session"),
        ]
        for name, kw, why in cases:
            with self.assertRaisesRegex(ort.OwnerError, why, msg=name):
                ort.grant_bypass(self.home, "*", 24, self.grant_answer(**kw))
        self.assertEqual(ort.load_authority(self.home)["bypass"], [])
        for bad in (0, 169, "24", True):
            with self.assertRaises(ort.OwnerError, msg=bad):
                ort.grant_bypass(self.home, "*", bad, self.grant_answer())
        with self.assertRaisesRegex(ort.OwnerError, "--scope"):
            ort.grant_bypass(self.home, "nope", 24, self.grant_answer(scope="nope"))
        ort.grant_bypass(self.home, "*", 24, self.grant_answer())  # control: the exact answer is accepted
        self.assertEqual(self.launch_mode(), "bypassPermissions")

    def test_bypass_scope_is_per_goal(self):
        (self.home / "repo2").mkdir()
        ort.init_owner(self.home, "shipped", str(self.home / "repo2"), "ticket:goodqa#1")
        self.goals[1]["status"] = "active"
        self.write_goals()
        ort.add_task(self.home, "shipped", "x", "ticket:goodqa#1")
        ort.grant_bypass(self.home, "shipped", 24, self.grant_answer(scope="shipped"))
        out = {r["goal"]: r for r in ort.tick(self.home, now=time.time(), dry_run=True,
                                              runner=lambda *a, **k: (0, "[]"))}
        self.assertEqual(out["shipped"]["permission_mode"], "bypassPermissions")
        self.assertEqual(out["solve"]["permission_mode"], "auto")

    def test_bypass_window_ends_from_the_answer_time(self):
        ort.grant_bypass(self.home, "*", 2, self.grant_answer(hours=2, ts=time.time() - 3600))
        self.assertEqual(self.launch_mode(), "bypassPermissions")
        self.assertEqual(self.launch_mode(now=time.time() + 3700), "auto")  # 2 h after the answer
        with self.assertRaisesRegex(ort.OwnerError, "already ended"):
            ort.grant_bypass(self.home, "*", 1, self.grant_answer(hours=1, ts=time.time() - 2 * 3600))

    def test_bypass_record_file_alone_grants_nothing(self):
        """A hand-written grant is re-resolved at every launch: without the user's real answer it is ignored."""
        human = fx.human_turn(self.home, fx.MISSION, "Use bypassPermissions for owners.")
        declined = self.grant_answer(chosen="No bypass: keep the configured mode")
        wrong_hours = self.grant_answer(hours=48)
        root = self.home / ".agent-harness" / "owners"
        for answer, hours in ((f"answer:{fx.MISSION}/{human}", 24), (declined, 24), (wrong_hours, 24),
                              (f"answer:{fx.MISSION}/00000000-0000-4000-8000-000000000000", 24), ("", 24)):
            (root / "authority.json").write_text(json.dumps({"bypass": [{"scope": "*", "hours": hours,
                                                                          "answer": answer}]}))
            self.assertEqual(self.launch_mode(), "auto", answer)
        other = self.grant_answer(session="bbbbbbbb-bbbb-cccc-dddd-eeeeeeeeeeee")  # exact answer, other session
        (root / "authority.json").write_text(json.dumps({"bypass": [{"scope": "*", "hours": 24, "answer": other}]}))
        self.assertEqual(self.launch_mode(), "auto")  # the session binds at use, not only when recorded
        (root / "authority.json").write_text("{not json")
        self.assertEqual(self.launch_mode(), "auto")
        (root / "authority.json").write_text(json.dumps({"bypass": [{"scope": "*", "hours": 48,
                                                                      "answer": wrong_hours}]}))
        self.assertEqual(self.launch_mode(), "bypassPermissions")  # control: a real, matching answer

    def test_bypass_grant_and_park_are_main_only(self):
        import caller_identity
        src = self.grant_answer()
        with mock.patch.object(caller_identity, "take_stamp", return_value=None), mock.patch("sys.stderr"), \
                mock.patch("sys.stdout"):
            self.assertEqual(ort.main(["grant-bypass", "--scope", "*", "--hours", "24", "--answer", src]), 2)
            self.assertEqual(ort.main(["park", "--goal", "solve", "--until", "2099-01-01", "--answer", src]), 2)
        self.assertEqual(ort.load_authority(self.home), {"bypass": [], "parks": []})
        self.assertEqual(ort.guarded_name(["grant-bypass"]), "grant-bypass")
        import mission_gate
        line = f"python3 ~/.claude/hooks/owner_rt.py grant-bypass --scope '*' --hours 24 --answer {src}"
        self.assertEqual(mission_gate.owner_stamps_for(line),
                         [("grant-bypass", ort.argv_key(["grant-bypass", "--scope", "*", "--hours", "24",
                                                         "--answer", src]))])

    def test_bypass_ask_text_is_the_question_the_grant_checks(self):
        text = ort.ask_text("bypass", "*", 24)
        self.assertEqual(text["question"], ort.bypass_question("*", 24))
        self.assertEqual(text["options"][0]["label"], ort.BYPASS_LABEL)
        ort.grant_bypass(self.home, "*", 24, self.grant_answer(options=text["options"]))
        self.assertEqual(self.launch_mode(), "bypassPermissions")

    def test_bypass_text_heuristics_are_gone(self):
        for name in ("chooses_bypass", "decision_context", "decision_clauses", "affirms", "user_decided",
                     "BYPASS_WORD", "NEGATION", "UNDECIDED"):
            self.assertFalse(hasattr(ort, name), name)
        self.assertNotIn("permission_source", ort.DEFAULT_RUNTIME)
        self.assertNotIn("bypassPermissions", ort.PERMISSION_MODES)


class BypassLapseTests(AuthorityBase):
    """Receipt v7 F1/F2: a bypass session lives only while a grant covers it, and every launch records its mode."""
    BUSY = {"id": "c9f43044", "sessionId": NEW_SID, "pid": 5, "status": "busy", "state": "working",
            "name": "owner-solve"}

    def setUp(self):
        super().setUp()
        self.calls, self.live, self.stop_code, self.stop_ignored, self.listing_ok = [], [], 0, False, True

    def runner(self, argv, timeout=60, cwd=None):
        self.calls.append(argv)
        if argv[1:2] == ["agents"]:
            if not self.listing_ok:
                return 1, "Error: listing refused"
            return 0, json.dumps(self.live)
        if "--bg" in argv:
            self.live = [dict(self.BUSY)]
            return 0, "backgrounded · c9f43044 · owner-solve"
        if argv[1:2] == ["stop"]:
            if self.stop_code:
                return self.stop_code, "stop failed"
            if not self.stop_ignored:
                for a in self.live:
                    if a.get("id") == argv[2]:
                        a.pop("pid", None)
        return 0, ""

    def stops(self):
        return [c for c in self.calls if c[1:2] == ["stop"]]

    def launches(self):
        return [c for c in self.calls if "--bg" in c]

    def launch_with_bypass(self, hours=2):
        self.t0 = time.time()
        self.answer = self.grant_answer(hours=hours)
        ort.grant_bypass(self.home, "*", hours, self.answer, now=self.t0)
        out = ort.tick(self.home, now=self.t0, runner=self.runner)
        self.assertEqual(out[0]["action"], "launch", out)
        argv = self.launches()[-1]
        self.assertEqual(argv[argv.index("--permission-mode") + 1], "bypassPermissions")
        st = ort.load_state(self.home, "solve")
        self.assertEqual(st["bypass"]["answer"], self.answer)
        entry = st["launches"][-1]  # receipt v7 F2: the launch says its mode and the answer that granted it
        self.assertEqual((entry["permission_mode"], entry["grant_answer"]), ("bypassPermissions", self.answer))
        self.assertTrue(entry["grant_expires_at"])
        self.calls = []

    def test_lapse_expiry_mid_run_stops_busy_session_and_confirms(self):
        self.launch_with_bypass(hours=2)
        out = ort.tick(self.home, now=self.t0 + 600, runner=self.runner)  # inside the window: nothing stopped
        self.assertEqual(self.stops(), [], out)
        out = ort.tick(self.home, now=self.t0 + 2 * 3600 + 60, runner=self.runner)
        self.assertEqual(out[0]["action"], "bypass-ended", out)
        self.assertIn("stopped and confirmed", out[0]["reason"])
        self.assertEqual(self.stops(), [["claude", "stop", "c9f43044"]])
        self.assertEqual(self.launches(), [])  # nothing relaunches in the same tick
        st = ort.load_state(self.home, "solve")
        self.assertEqual(st["bypass"], {})
        self.assertEqual(st["bypass_history"][-1]["answer"], self.answer)
        log = [json.loads(x) for x in (self.home / ".agent-harness/owners/solve/launch.log").read_text().splitlines()]
        self.assertEqual(log[-1]["event"], "bypass-ended")
        self.assertEqual(log[-1]["grant_answer"], self.answer)

    def test_lapse_revoke_mid_run_stops_busy_session(self):
        self.launch_with_bypass(hours=24)
        ort.revoke_bypass(self.home, "*")
        out = ort.tick(self.home, now=self.t0 + 120, runner=self.runner)
        self.assertEqual(out[0]["action"], "bypass-ended", out)
        self.assertEqual(self.stops(), [["claude", "stop", "c9f43044"]])

    def test_lapse_answer_unresolvable_fails_closed(self):
        self.launch_with_bypass(hours=24)
        empty = Path(tempfile.mkdtemp(dir=self.home))
        with mock.patch("command_guard._pinned_home", return_value=str(empty)):
            ort._ANSWER_CACHE.clear()
            out = ort.tick(self.home, now=self.t0 + 120, runner=self.runner)
        self.assertEqual(out[0]["action"], "bypass-ended", out)
        self.assertEqual(len(self.stops()), 1)

    def test_lapse_stop_failure_reported_never_assumed(self):
        self.launch_with_bypass(hours=2)
        for attr, value in (("stop_code", 1), ("stop_ignored", True)):
            setattr(self, attr, value)
            self.calls = []
            out = ort.tick(self.home, now=self.t0 + 3 * 3600, runner=self.runner)
            self.assertEqual(out[0]["action"], "bypass-stop-failed", (attr, out))
            self.assertEqual(self.launches(), [])
            st = ort.load_state(self.home, "solve")
            self.assertEqual(st["bypass"]["answer"], self.answer)  # still held: retried next tick
            self.assertIn("stop_failed_at", st["bypass"])
            setattr(self, attr, 0 if attr == "stop_code" else False)
        self.calls = []
        out = ort.tick(self.home, now=self.t0 + 4 * 3600, runner=self.runner)  # the retry succeeds
        self.assertEqual(out[0]["action"], "bypass-ended", out)

    def test_lapse_listing_refused_reports_unconfirmed(self):
        self.launch_with_bypass(hours=2)
        self.listing_ok = False
        out = ort.tick(self.home, now=self.t0 + 3 * 3600, runner=self.runner)
        actions = {r["action"] for r in out}
        self.assertEqual(actions, {"bypass-stop-unconfirmed"}, out)
        self.assertEqual(self.launches(), [])
        self.assertTrue(ort.load_state(self.home, "solve")["bypass"])

    def test_lapse_enforced_while_runtime_disabled(self):
        self.launch_with_bypass(hours=2)
        self.write_runtime({"enabled": False})
        out = ort.tick(self.home, now=self.t0 + 3 * 3600, runner=self.runner)
        self.assertEqual(out[0]["action"], "bypass-ended", out)
        self.assertEqual(len(self.stops()), 1)
        self.assertEqual(self.launches(), [])
        self.calls = []
        out = ort.tick(self.home, now=self.t0 + 4 * 3600, runner=self.runner)  # disabled: nothing else runs
        self.assertEqual(self.calls, [], out)

    def test_lapse_session_already_gone_clears_without_stop(self):
        self.launch_with_bypass(hours=2)
        self.live = []
        out = ort.tick(self.home, now=self.t0 + 3 * 3600, runner=self.runner)
        self.assertEqual(out[0]["action"], "bypass-ended", out)
        self.assertEqual(self.stops(), [])

    def test_launch_audit_records_mode_and_grant(self):
        out = ort.tick(self.home, now=time.time(), runner=self.runner)  # no grant: configured mode
        self.assertEqual(out[0]["action"], "launch", out)
        entry = ort.load_state(self.home, "solve")["launches"][-1]
        self.assertEqual(entry["permission_mode"], "auto")
        self.assertIsNone(entry["grant_answer"])


class AnswerBindingTests(AuthorityBase):
    """Receipt v7 F3-F5: options bound exactly, answers read only from the pinned home, resolves cached."""

    def test_options_must_equal_generated_labels_and_descriptions(self):
        good = ort.bypass_options("*", 24)
        bad = [[good[0]], [dict(good[0], description="no prompts, forever"), good[1]],
               [good[0], dict(good[1], label="Maybe")], [good[0], good[1], {"label": "Other", "description": ""}],
               [good[1], good[0]], [ort.BYPASS_LABEL, "No bypass: keep the configured mode"]]
        for options in bad:
            with self.assertRaises(ort.OwnerError, msg=options):
                ort.grant_bypass(self.home, "*", 24, self.grant_answer(options=options))
        ort.grant_bypass(self.home, "*", 24, self.grant_answer(options=good))  # control
        self.assertEqual(self.launch_mode(), "bypassPermissions")

    def test_park_options_bound(self):
        until = time.strftime("%Y-%m-%d", time.gmtime(time.time() + 3 * 86400))
        q = ort.park_question("solve", until)
        good = ort.park_options("solve", until)
        uid = fx.answer(self.home, fx.MISSION, q, good[0]["label"],
                        options=[dict(good[0], description="park it, and also bypass"), good[1]])
        with self.assertRaises(ort.OwnerError):
            ort.park_goal(self.home, "solve", until, f"answer:{fx.MISSION}/{uid}")

    def test_ah_home_never_relocates_where_answers_are_read(self):
        forged = Path(tempfile.mkdtemp(dir=self.home))
        uid = fx.answer(forged, fx.MISSION, ort.bypass_question("*", 24), ort.BYPASS_LABEL,
                        options=ort.bypass_options("*", 24))
        with mock.patch.dict(os.environ, {"AH_HOME": str(forged)}):
            # the harness home moved to `forged`, and the answer exists only in its transcripts: refused, because
            # answers are read from the pinned account home whatever AH_HOME says
            with self.assertRaises(ort.OwnerError):
                ort.grant_bypass(forged, "*", 24, f"answer:{fx.MISSION}/{uid}")
            ort.grant_bypass(forged, "*", 24, self.grant_answer())  # control: the pinned home's answer grants

    def test_resolve_cached_until_transcript_changes(self):
        import command_guard
        src = self.grant_answer()
        real = command_guard.resolve_user_source
        with mock.patch.object(command_guard, "resolve_user_source", side_effect=real) as spy:
            ort._ANSWER_CACHE.clear()
            for _ in range(3):
                ort.answer_at(self.home, src, ort.bypass_question("*", 24), ort.bypass_options("*", 24), time.time())
            self.assertEqual(spy.call_count, 1)
            fx.human_turn(self.home, fx.MISSION, "unrelated")  # transcript grows: read again
            ort.answer_at(self.home, src, ort.bypass_question("*", 24), ort.bypass_options("*", 24), time.time())
            self.assertEqual(spy.call_count, 2)

    def test_cached_answer_still_ages_out(self):
        src = self.grant_answer()
        q, opts = ort.bypass_question("*", 24), ort.bypass_options("*", 24)
        ort.answer_at(self.home, src, q, opts, time.time(), ort.ANSWER_MAX_AGE_S)
        with self.assertRaises(ort.OwnerError):
            ort.answer_at(self.home, src, q, opts, time.time() + 2 * 86400, ort.ANSWER_MAX_AGE_S)
        with self.assertRaises(ort.OwnerError):  # future-dated against the caller's clock
            ort.answer_at(self.home, src, q, opts, time.time() - 3600)


class ListingTests(Base):
    """Receipt v6 F2: an unreadable session listing is never proof that no owner session runs."""
    BAD = ("", "   \n", "not json", "Update available!\n[]", "{}", '{"sessions": []}', "[1]", '[{"id": "x"}]',
           '[{"sessionId": 5}]', '[{"sessionId": "not a session id!"}]',
           json.dumps([{"sessionId": SID, "pid": "1", "status": "idle"}]),
           json.dumps([{"sessionId": SID, "pid": 0, "status": "idle"}]),
           json.dumps([{"sessionId": SID, "pid": True, "status": "idle"}]),
           json.dumps([{"sessionId": SID, "pid": None, "status": "idle"}]),
           json.dumps([{"sessionId": SID, "pid": 7}]),
           json.dumps([{"sessionId": SID, "name": 3}]), "[{]")

    def setUp(self):
        super().setUp()
        self.init()
        self.set_session()
        ort.add_task(self.home, "solve", "fix login", "ticket:goodqa#2")
        (self.home / ".agent-harness" / "owners" / "runtime.json").write_text(json.dumps({"enabled": True}))
        p = mock.patch.object(ort, "claude_bin", return_value="claude")
        p.start()
        self.addCleanup(p.stop)

    def test_listing_parse_rejects_every_malformed_shape(self):
        for out in self.BAD:
            with self.assertRaises(ort.OwnerError, msg=out):
                ort.parse_sessions(out)
        real = [{"id": "8d84dcef", "cwd": "/x", "kind": "background", "startedAt": 1, "sessionId": SID,
                 "name": "owner-solve", "state": "done"},
                {"pid": 42, "cwd": "/x", "kind": "interactive", "startedAt": 1, "sessionId": NEW_SID, "name": "m",
                 "status": "waiting", "waitingFor": "input"}]
        self.assertEqual(ort.parse_sessions(json.dumps(real) + "\nsome stderr line"), real)  # stderr follows stdout
        self.assertEqual(ort.parse_sessions("[]"), [])

    def test_listing_unreadable_launches_nothing_and_is_logged(self):
        for i, listing in enumerate(self.BAD):
            calls = []

            def runner(argv, timeout=60, cwd=None, listing=listing):
                calls.append(argv)
                return (0, listing) if argv[1:2] == ["agents"] else (0, "backgrounded · c9f43044 · owner-solve")
            out = ort.tick(self.home, now=NOW + i * 4000, runner=runner)
            self.assertEqual(out[0]["action"], "error", listing)
            self.assertIn("nothing launched", out[0]["reason"])
            self.assertEqual([c for c in calls if "--bg" in c or c[1:2] == ["stop"]], [], listing)
        log = (self.home / ".agent-harness/owners/solve/launch.log").read_text().splitlines()
        self.assertEqual(len(log), len(self.BAD))
        self.assertEqual(ort.load_state(self.home, "solve")["generation"], 0)
        calls = []
        out = ort.tick(self.home, now=NOW + 99 * 4000,
                       runner=lambda argv, timeout=60, cwd=None: calls.append(argv) or
                       ((0, "[]") if argv[1:2] == ["agents"] else (0, "backgrounded · c9f43044 · owner-solve")))
        self.assertEqual(out[0]["action"], "launch")  # control: a valid empty listing does launch

    def test_listing_unreadable_after_stop_never_confirms_the_stop(self):
        idle = [{"id": "8d84dcef", "sessionId": SID, "pid": 1, "status": "idle", "state": "done"}]
        for i, after in enumerate(("", "not json", '[{"id": "8d84dcef"}]', "Error: x")):
            calls, listings = [], iter([json.dumps(idle), json.dumps(idle), after])

            def runner(argv, timeout=60, cwd=None, listings=listings):
                calls.append(argv)
                if argv[1:2] == ["agents"]:
                    return 0, next(listings)
                return (0, "backgrounded · c9f43044 · owner-solve") if "--bg" in argv else (0, "")
            out = ort.tick(self.home, now=NOW + i * 4000, runner=runner)
            self.assertEqual(out[0]["action"], "launch-failed", after)
            self.assertIn("could not confirm the stop", out[0]["reason"])
            self.assertIn(["claude", "stop", "8d84dcef"], calls)  # the stop ran; its effect was not proven
            self.assertEqual([c for c in calls if "--bg" in c], [], after)
        st = ort.load_state(self.home, "solve")
        self.assertEqual([x["code"] for x in st["launches"]], [-1, -1, -1, -1])


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
