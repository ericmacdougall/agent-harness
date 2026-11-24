"""Status-truth hardening (GoodQA goodqa#15754, red-team review of db41da6f: F1, F2, F5).

Evidence: the red-team probes in hardening-rt/probes/ (probe_a_stamp_replay.py, probe_b_row_rewrite.py,
probe_f_bigwal.py / probe_f2_bigwal_primed.py) showed, on origin/main ee9fc12d:
  F1  a stamp main's PreToolUse hook wrote for a command that never ran (`cd /nonexistent && ...`, a command another
      hook denied, a rejected prompt) let a later non-main process attach as `by main`: goal LIVE_UNTESTED -> DONE_LIVE;
  F2  an attached WAL row was re-read at report time, so an owner rewriting its FAIL row to PASS turned FAILING into
      DONE_LIVE with both rows still `by main`;
  F5  attached rows were resolved by one whole-file rescan each, with no shared budget; on a fresh install (no
      remembered mission pointer) a slow read timed out with NO output at all instead of GOALS UNAVAILABLE.
Every test class below fails on ee9fc12d.
"""
import contextlib
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

ROOT = Path(__file__).resolve().parents[1]
HOOKS = ROOT / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
import caller_identity  # noqa: E402
import goals_view as gv  # noqa: E402
import mission_coverage as mc  # noqa: E402
import mission_gate  # noqa: E402
import safe_input  # noqa: E402

SESSION = "11111111-2222-4333-8444-555555555555"
OTHER = "99999999-2222-4333-8444-555555555555"
OWNER_WAL = "agent-aowner1234567890ab.jsonl"


def iso(ts):
    return time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime(ts))


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name)
        env = mock.patch.dict(os.environ, {"AH_HOME": str(self.home), "HOME": str(self.home),
                                           "CLAUDE_CONFIG_DIR": str(self.home / ".claude")})
        env.start()
        self.addCleanup(env.stop)
        for k in ("CLAUDE_CODE_SESSION_ID", "CLAUDE_SESSION_ID", "AH_AGENT_ID"):
            os.environ.pop(k, None)
        self.addCleanup(mc._PROOF.clear)
        self.wal = self.home / ".claude" / "wals" / SESSION
        self.wal.mkdir(parents=True)
        (self.wal / "main.jsonl").write_text("")
        self.transcript = self.home / ".claude" / "projects" / "p" / f"{SESSION}.jsonl"
        self.transcript.parent.mkdir(parents=True)
        self.transcript.write_text(json.dumps({"type": "user", "message": {"role": "user", "content": "go"}}) + "\n")
        self.tool_n = 0

    # -- what Claude Code does around main's Bash call
    def tool_id(self):
        self.tool_n += 1
        return "toolu_01TEST%018d" % self.tool_n

    def pretool(self, command, tool_use_id):
        return mission_gate.cmd_pretool({"session_id": SESSION, "transcript_path": str(self.transcript),
                                         "hook_event_name": "PreToolUse", "tool_name": "Bash",
                                         "tool_input": {"command": command}, "tool_use_id": tool_use_id})

    def tool_result(self, tool_use_id, text="Exit code 1", is_error=True):
        """Claude Code appends the call's tool_result to main's transcript when the call ends or is refused."""
        with open(self.transcript, "a") as fh:
            fh.write(json.dumps({"type": "user", "message": {"role": "user", "content": [
                {"tool_use_id": tool_use_id, "type": "tool_result", "content": text, "is_error": is_error}]}},
                separators=(",", ":")) + "\n")

    def run_mc(self, argv):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            try:
                rc = mc.main(list(argv))
            except SystemExit as stop:
                rc = stop.code if isinstance(stop.code, int) else 2
        return rc, out.getvalue()

    def main_run(self, argv):
        """main's Bash call running `mission_coverage.py ARGV`: PreToolUse stamps it, the process runs, the call ends."""
        tid = self.tool_id()
        self.pretool("python3 ~/.claude/hooks/mission_coverage.py " + " ".join(argv), tid)
        rc, out = self.run_mc(argv)
        self.tool_result(tid, "ok", is_error=False)
        post = getattr(mission_gate, "cmd_posttool", None)  # absent before the fix: the probe still runs there
        post and post({"session_id": SESSION, "transcript_path": str(self.transcript),
                                   "hook_event_name": "PostToolUse", "tool_name": "Bash", "tool_use_id": tid,
                                   "tool_input": {"command": "x mission_coverage.py"}})
        return rc, out

    def row(self, wal, rec):
        rec = dict(rec)
        rec.setdefault("at", iso(time.time()))
        with open(self.wal / wal, "a") as fh:
            fh.write(json.dumps(rec) + "\n")
        return rec["id"]

    def seed(self, goal="prod-move", ticket="goodqa#100"):
        self.assertEqual(self.main_run(["set-session", "--session", SESSION])[0], 0)
        mc.add_goal(self.home, goal, "Prod move", ticket)

    def goal(self, gid="prod-move"):
        doc = gv.goals_report(self.home, session=SESSION)
        self.assertEqual(doc["state"], "ok", doc)
        return next(g for g in doc["goals"] if g["id"] == gid)

    def stamps(self):
        d = caller_identity.stamp_dir(self.home)
        return sorted(p.name for p in d.glob("*.json")) if d.is_dir() else []


# ---------------------------------------------------------------------------------------------------- F1
class F1StampBoundToExecutedCall(Base):
    def setUp(self):
        super().setUp()
        self.seed()
        self.dep = self.row("main.jsonl", {"event": "deploy", "id": "wd0000000001",
                                           "note": "DEPLOYED abc1234def to prod goodqa#100"})
        self.lt = self.row(OWNER_WAL, {"event": "result", "id": "wa0000000001", "result": "PASS", "live": True,
                                       "note": "REALLY_TESTED prod-smoke PASS: smoke goodqa#100"})
        self.assertEqual(self.main_run(["attach", "--goal", "prod-move", "--evidence", self.dep, "--kind", "deploy"])[0], 0)
        self.args = ["attach", "--goal", "prod-move", "--evidence", self.lt, "--kind", "live_test"]
        self.line = "cd /nonexistent && python3 ~/.claude/hooks/mission_coverage.py " + " ".join(self.args)

    def by_of_live_test(self):
        g = self.goal()
        return g["state"], [e["by"] for e in g["evidence"] if e["id"] == self.lt]

    def test_probe_a_stamp_of_a_refused_call_is_not_honoured_by_a_later_process(self):
        """Another PreToolUse hook denies the line (or the user rejects it): no Post hook fires, but Claude Code writes
        the refusal as the call's tool_result. The owner then runs the exact line `ah goals --candidates` printed."""
        tid = self.tool_id()
        self.pretool(self.line, tid)
        self.tool_result(tid, "PreToolUse:Bash hook error: command_guard BLOCKED")
        rc, _ = self.run_mc(self.args)  # a plain process, no main hook: an owner
        state, by = self.by_of_live_test()
        self.assertNotEqual(state, "DONE_LIVE")
        self.assertEqual(by, ["owner"] if rc == 0 else [])

    def test_post_tool_failure_deletes_the_unconsumed_stamp(self):
        """`cd /nonexistent && ...` runs and fails before python starts: PostToolUseFailure removes the stamp even
        before the transcript holds the result."""
        tid = self.tool_id()
        self.pretool(self.line, tid)
        self.assertEqual(len(self.stamps()), 1)
        mission_gate.cmd_posttool({"session_id": SESSION, "transcript_path": str(self.transcript),
                                   "hook_event_name": "PostToolUseFailure", "tool_name": "Bash", "tool_use_id": tid,
                                   "tool_input": {"command": self.line}, "error": "Exit code 1"})
        self.assertEqual(self.stamps(), [])
        self.run_mc(self.args)
        self.assertNotEqual(self.by_of_live_test()[0], "DONE_LIVE")

    def test_permission_denied_deletes_the_stamp_and_other_calls_keep_theirs(self):
        tid, other = self.tool_id(), self.tool_id()
        self.pretool(self.line, tid)
        self.pretool("python3 ~/.claude/hooks/mission_coverage.py attach --goal prod-move --evidence wd0000000001 "
                     "--kind deploy", other)
        self.assertEqual(len(self.stamps()), 2)
        mission_gate.cmd_posttool({"session_id": SESSION, "transcript_path": str(self.transcript),
                                   "hook_event_name": "PermissionDenied", "tool_name": "Bash", "tool_use_id": tid,
                                   "tool_input": {"command": self.line}, "reason": "auto mode classifier"})
        self.assertEqual(len(self.stamps()), 1)  # the parallel call's stamp stays

    def test_stamp_older_than_sixty_seconds_is_refused(self):
        self.assertLessEqual(mc.MAIN_STAMP_TTL_SECONDS, 60)
        tid = self.tool_id()
        self.pretool(self.line.replace("cd /nonexistent && ", ""), tid)
        with mock.patch.object(time, "time", return_value=time.time() + mc.MAIN_STAMP_TTL_SECONDS + 5):
            mc.claim_main(self.args, self.home)
        self.assertIsNone(mc._PROOF.get("stamp"))

    def test_stamp_without_a_tool_use_id_is_refused(self):
        """An unbound stamp (older runtime, hand-written file) never proves main."""
        caller_identity.put_stamp("mission-main", [self.args[0], mc.argv_key(self.args)], session=SESSION,
                                  home=self.home)
        mc.claim_main(self.args, self.home)
        self.assertIsNone(mc._PROOF.get("stamp"))

    def test_main_call_still_attaches_as_main_while_it_runs(self):  # positive control
        rc, out = self.main_run(self.args)
        self.assertEqual(rc, 0, out)
        self.assertEqual(self.by_of_live_test(), ("DONE_LIVE", ["main"]))
        self.assertEqual(self.stamps(), [])

    def test_unverifiable_transcript_fails_closed(self):
        """A missing or shrunken transcript, or a payload without a tool_use_id, never yields a usable stamp."""
        plain = self.line.replace("cd /nonexistent && ", "")
        self.pretool(plain, "")  # no tool_use_id: no stamp at all
        self.assertEqual(self.stamps(), [])
        self.pretool(plain, self.tool_id())
        self.transcript.write_text("")  # shrunk below the recorded offset
        mc.claim_main(self.args, self.home)
        self.assertIsNone(mc._PROOF.get("stamp"))
        self.pretool(plain, self.tool_id())
        self.transcript.unlink()
        mc.claim_main(self.args, self.home)
        self.assertIsNone(mc._PROOF.get("stamp"))


# ---------------------------------------------------------------------------------------------------- F2
class F2PinnedEvidence(Base):
    def setUp(self):
        super().setUp()
        self.seed()
        self.dep = self.row("main.jsonl", {"event": "deploy", "id": "wd0000000002",
                                           "note": "DEPLOYED abc1234def to prod goodqa#100"})
        self.lt = self.row(OWNER_WAL, {"event": "result", "id": "wa0000000002", "result": "FAIL", "live": True,
                                       "note": "REALLY_TESTED prod-smoke FAIL: login 500 goodqa#100"})
        for wid, kind in ((self.dep, "deploy"), (self.lt, "live_test")):
            self.assertEqual(self.main_run(["attach", "--goal", "prod-move", "--evidence", wid, "--kind", kind])[0], 0)

    def rewrite(self, wid, **fields):
        p = self.wal / OWNER_WAL
        rows = [json.loads(x) for x in p.read_text().splitlines()]
        for r in rows:
            if r["id"] == wid:
                r.update(fields)
        p.write_text("".join(json.dumps(r) + "\n" for r in rows))

    def test_attach_pins_row_hash_verdict_and_at(self):
        ev = next(e for e in mc.load_goals(self.home)["goals"][0]["evidence"] if e["id"] == self.lt)
        rec = json.loads((self.wal / OWNER_WAL).read_text().splitlines()[0])
        self.assertEqual(ev["row_sha"], mc.row_digest(rec))
        self.assertEqual(ev["row_verdict"], "FAIL")
        self.assertEqual(ev["row_at"], rec["at"])

    def test_probe_b_rewritten_row_is_tampered_and_never_counts(self):
        self.assertEqual(self.goal()["state"], "FAILING")
        self.rewrite(self.lt, result="PASS", note="REALLY_TESTED prod-smoke PASS: ok goodqa#100")
        g = self.goal()
        self.assertNotEqual(g["state"], "DONE_LIVE")
        item = next(e for e in g["evidence"] if e["id"] == self.lt)
        self.assertEqual(item["verdict"], "TAMPERED")
        self.assertEqual(g["tampered"], [self.lt])
        text = gv.goals_text(gv.goals_report(self.home, session=SESSION), notes=False)
        self.assertIn("TAMPERED", text)
        self.assertIn(self.lt, text)

    def test_moved_timestamp_is_tampered(self):
        self.rewrite(self.lt, at=iso(time.time() + 3600))
        self.assertEqual(self.goal()["tampered"], [self.lt])

    def test_legacy_unpinned_entry_counts_but_is_flagged_and_main_reattach_pins_it(self):
        self.rewrite(self.lt, result="PASS", note="REALLY_TESTED prod-smoke PASS: ok goodqa#100")

        def strip(doc):  # a ledger written before pinning: no row_sha / row_verdict / row_at
            for e in doc["goals"][0]["evidence"]:
                for k in ("row_sha", "row_verdict", "row_at"):
                    e.pop(k, None)
            return doc
        mc._mutate(self.home, "fixture", "*", strip, {})
        g = self.goal()
        # review L3: legacy rows still count, but an unpinned row cannot carry a goal to DONE_LIVE until main re-pins it
        self.assertEqual(g["state"], "UNCONFIRMED")
        self.assertEqual(g["cap"]["would_be"], "DONE_LIVE")
        self.assertEqual(sorted(g["cap"]["unpinned"]), sorted([self.dep, self.lt]))
        self.assertEqual(sorted(g["unpinned"]), sorted([self.dep, self.lt]))
        self.assertTrue(all(e.get("unpinned") for e in g["evidence"]))
        self.assertIn("unpinned", gv.goals_text(gv.goals_report(self.home, session=SESSION), notes=False))
        for wid, kind in ((self.dep, "deploy"), (self.lt, "live_test")):
            self.assertEqual(self.main_run(["attach", "--goal", "prod-move", "--evidence", wid, "--kind", kind])[0], 0)
        g = self.goal()
        self.assertEqual(g["unpinned"], [])
        self.assertEqual(g["state"], "DONE_LIVE")

    def test_malformed_pin_fails_ledger_validation(self):
        def bad(doc):
            doc["goals"][0]["evidence"][0]["row_sha"] = "not-a-hash"
            return doc
        with self.assertRaises(Exception):
            mc._mutate(self.home, "fixture", "*", bad, {})
        self.assertEqual(mc.load_goals(self.home)["state"], "ok")


# ---------------------------------------------------------------------------------------------------- F5
class F5OnePassAndVisibleBudget(Base):
    GOALS, PER = 4, 3

    def build(self, filler_mb=0):
        self.seed("goal-0", "goodqa#200")
        for gi in range(1, self.GOALS):
            mc.add_goal(self.home, f"goal-{gi}", f"goal {gi}", f"goodqa#{200 + gi}")
        if filler_mb:
            line = json.dumps({"at": "2026-11-01T00:00:00+00:00", "event": "pretool", "tool": "Bash",
                               "target_chars": 100, "pad": "x" * 200}) + "\n"
            with open(self.wal / "main.jsonl", "a") as fh:
                fh.write(line * (filler_mb * 1024 * 1024 // len(line)))
        n = 0
        for gi in range(self.GOALS):
            for k in range(self.PER):
                n += 1
                wid = "w%011x" % (0xabc00000 + n)
                self.row("main.jsonl", {"event": "result", "id": wid, "result": "PASS",
                                        "note": f"REALLY_TESTED chk{gi}-{k} PASS: x goodqa#{200 + gi}"})
                self.assertEqual(self.main_run(["attach", "--goal", f"goal-{gi}", "--evidence", wid,
                                                "--kind", "test"])[0], 0)

    def test_each_wal_file_is_read_once_per_report(self):
        self.build()
        opened = []
        real = safe_input.open_regular_file

        def counting(path, *a, **kw):
            opened.append(Path(str(path)).name)
            return real(path, *a, **kw)
        with mock.patch.object(safe_input, "open_regular_file", side_effect=counting):
            doc = gv.goals_report(self.home, session=SESSION)
        self.assertEqual(doc["state"], "ok")
        self.assertTrue(all(g["state"] == "VERIFIED" for g in doc["goals"]), [g["state"] for g in doc["goals"]])
        self.assertEqual(opened.count("main.jsonl"), 1, opened)

    def test_exhausted_budget_is_an_unavailable_report_not_a_partial_one(self):
        self.build()
        with mock.patch.object(gv, "EVIDENCE_BUDGET_S", 0.0, create=True):
            doc = gv.goals_report(self.home, session=SESSION)
        self.assertEqual(doc["state"], "timeout")
        self.assertIn("GOALS UNAVAILABLE (timeout)", gv.goals_text(doc))

    def hook(self, session, script):
        """status_truth.py prompt in a child process (its watchdog calls os._exit), with `script` run first."""
        code = ("import sys; sys.path.insert(0, %r)\nimport status_truth as st, goals_view as gv\n%s\n"
                "sys.exit(st.main(['prompt']))" % (str(HOOKS), script))
        env = dict(os.environ)
        started = time.monotonic()
        r = subprocess.run([sys.executable, "-c", code], input=json.dumps({"session_id": session, "prompt": "whats left?",
                                                                           "transcript_path": ""}),
                           env=env, capture_output=True, text=True, timeout=60)
        return r, time.monotonic() - started

    def test_fresh_install_timeout_still_says_unavailable_in_the_mission_session_only(self):
        """No mission pointer remembered yet (fresh install), and the ledger read overruns the hook's wall clock: the
        mission session still gets GOALS UNAVAILABLE (from the ledger header, read before the WAL scan); another
        session gets nothing (NEG-8)."""
        self.build()
        pointer = self.home / ".agent-harness" / "state" / "status-truth" / "mission-session"
        self.assertFalse(pointer.exists())
        slow = ("import time\nst.WALL_LIMIT_S = 1.0\n_real = gv.goals_report\n"
                "def _slow(*a, **k):\n    time.sleep(5)\n    return _real(*a, **k)\ngv.goals_report = _slow")
        r, _ = self.hook(SESSION, slow)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(r.stdout.count('{"hookSpecificOutput"'), 1, r.stdout)
        self.assertIn("GOALS UNAVAILABLE (timeout)", json.loads(r.stdout)["hookSpecificOutput"]["additionalContext"])
        r, _ = self.hook(OTHER, slow)
        self.assertEqual(r.stdout.strip(), "")

    def test_in_budget_overrun_reports_unavailable_without_the_watchdog(self):
        self.build()
        r, _ = self.hook(SESSION, "gv.EVIDENCE_BUDGET_S = 0.0")
        self.assertIn("GOALS UNAVAILABLE (timeout)", r.stdout)
        r, _ = self.hook(OTHER, "gv.EVIDENCE_BUDGET_S = 0.0")
        self.assertEqual(r.stdout.strip(), "")

    def test_large_wal_resolves_inside_the_hook_budget(self):
        """Timing (bounded: one ~90 MB WAL in a temp dir, well under 60 s). The red-team saw 8.1 s and no output for
        100 MB x 30 attached rows on the old per-row rescan; one pass must finish inside the hook's wall clock."""
        self.GOALS, self.PER = 10, 3
        self.build(filler_mb=90)
        self.assertLess((self.wal / "main.jsonl").stat().st_size, 200 << 20)
        r, took = self.hook(SESSION, "")
        self.assertEqual(r.returncode, 0, r.stderr)
        ctx = json.loads(r.stdout)["hookSpecificOutput"]["additionalContext"]
        self.assertNotIn("GOALS UNAVAILABLE", ctx)
        self.assertIn("goal-9", ctx)
        self.assertLess(took, 8.0)


# ---------------------------------------------------------------------------------------------------- round 3
# PR 226 review (pr226-review/review.md): H1, H2, M1 side effect, L1 mutants M5/M10/M14, L2, L3.
class H1PinnedVerdictStillScores(Base):
    """review H1 (probe_b2_pins.py, probe_b3_owner_repin.py): a TAMPERED or MISSING pinned row is scored by its pinned
    verdict at its pinned `at`, and any goal with one is capped below DONE_LIVE until main re-attaches or removes it."""
    T0 = time.time() - 7200

    def setUp(self):
        super().setUp()
        self.seed()
        self.dep = self.row("main.jsonl", {"event": "deploy", "id": "wd0000000003", "at": iso(self.T0),
                                           "note": "DEPLOYED abc1234def to prod goodqa#100"})
        self.p1 = self.row(OWNER_WAL, {"event": "result", "id": "wa0000000031", "result": "PASS", "live": True,
                                       "goal": "prod-move", "at": iso(self.T0 + 300),
                                       "note": "REALLY_TESTED prod-smoke PASS: ok goodqa#100"})
        self.f1 = self.row(OWNER_WAL, {"event": "result", "id": "wa0000000032", "result": "FAIL", "live": True,
                                       "goal": "prod-move", "at": iso(self.T0 + 600),
                                       "note": "REALLY_TESTED prod-smoke FAIL: login 500 goodqa#100"})

    def attach(self, wid, kind, main=True):
        argv = ["attach", "--goal", "prod-move", "--evidence", wid, "--kind", kind]
        return self.main_run(argv) if main else self.run_mc(argv)

    def rows(self):
        return [json.loads(x) for x in (self.wal / OWNER_WAL).read_text().splitlines()]

    def write(self, rows):
        (self.wal / OWNER_WAL).write_text("".join(json.dumps(r) + "\n" for r in rows))

    def to_pass(self, wid):
        rows = self.rows()
        for r in rows:
            if r["id"] == wid:
                r.update(result="PASS", note="REALLY_TESTED prod-smoke PASS: ok goodqa#100")
        self.write(rows)

    def main_attached_regression(self):
        for wid, kind in ((self.dep, "deploy"), (self.p1, "live_test"), (self.f1, "live_test")):
            self.assertEqual(self.attach(wid, kind)[0], 0)
        self.assertEqual(self.goal()["state"], "FAILING")

    def test_probe_b2_main_attached_newer_fail_rewritten_stays_failing(self):
        self.main_attached_regression()
        self.to_pass(self.f1)
        g = self.goal()
        self.assertEqual(g["state"], "FAILING")  # f4cbf628: DONE_LIVE
        self.assertEqual(g["tampered"], [self.f1])
        item = next(e for e in g["evidence"] if e["id"] == self.f1)
        self.assertEqual((item["verdict"], item["pinned_verdict"]), ("TAMPERED", "FAIL"))

    def test_probe_b2_deleted_fail_row_stays_failing(self):
        self.main_attached_regression()
        self.write([r for r in self.rows() if r["id"] != self.f1])
        g = self.goal()
        self.assertEqual(g["state"], "FAILING")  # f4cbf628 and origin/main: DONE_LIVE
        self.assertEqual(g["missing"], [self.f1])

    def test_probe_b2_duplicate_id_pass_prepended_stays_failing(self):
        self.main_attached_regression()
        rows = self.rows()
        dup = dict(next(r for r in rows if r["id"] == self.f1), result="PASS", at=iso(self.T0 + 1200),
                   note="REALLY_TESTED prod-smoke PASS: ok")
        self.write([dup] + rows)
        g = self.goal()
        self.assertEqual(g["state"], "FAILING")  # f4cbf628: DONE_LIVE
        self.assertEqual(g["tampered"], [self.f1])

    def test_deleted_unpinned_legacy_fail_row_cannot_leave_done_live(self):
        """L3: a legacy (unpinned) FAIL row deleted from its WAL has no pin to score from; the goal still cannot read
        DONE_LIVE while that unpinned row is unresolved."""
        self.main_attached_regression()

        def strip(doc):
            for e in doc["goals"][0]["evidence"]:
                if e["id"] == self.f1:
                    for k in ("row_sha", "row_verdict", "row_at"):
                        e.pop(k, None)
            return doc
        mc._mutate(self.home, "fixture", "*", strip, {})
        self.write([r for r in self.rows() if r["id"] != self.f1])
        g = self.goal()
        self.assertEqual(g["state"], "UNCONFIRMED")
        self.assertEqual((g["cap"]["would_be"], g["cap"]["unpinned"]), ("DONE_LIVE", [self.f1]))

    def test_duplicate_id_appended_changes_nothing(self):  # control: the first row with the id is the evidence
        self.main_attached_regression()
        with open(self.wal / OWNER_WAL, "a") as fh:
            fh.write(json.dumps({"event": "result", "id": self.f1, "result": "PASS", "live": True,
                                 "note": "REALLY_TESTED prod-smoke PASS: ok", "at": iso(self.T0 + 1200)}) + "\n")
        g = self.goal()
        self.assertEqual((g["state"], g["tampered"]), ("FAILING", []))

    def test_probe_b3_owner_attached_fail_rewritten_stays_failing_and_owner_cannot_repin(self):
        for wid, kind in ((self.dep, "deploy"), (self.p1, "live_test")):
            self.assertEqual(self.attach(wid, kind)[0], 0)
        self.assertEqual(self.attach(self.f1, "live_test", main=False)[0], 0)  # the owner attaches its own FAIL
        self.assertEqual(self.goal()["state"], "FAILING")
        self.to_pass(self.f1)
        self.assertEqual(self.goal()["state"], "FAILING")  # origin/main: LIVE_UNTESTED; f4cbf628: DONE_LIVE
        rc, out = self.attach(self.f1, "live_test", main=False)  # the owner re-pins its rewritten row
        self.assertNotEqual(rc, 0, out)
        self.assertIn("changed since it was attached", out)
        g = self.goal()
        self.assertEqual((g["state"], g["tampered"]), ("FAILING", [self.f1]))

    def test_tampered_pass_caps_the_goal_below_done_live_until_main_reattaches(self):
        for wid, kind in ((self.dep, "deploy"), (self.p1, "live_test")):
            self.assertEqual(self.attach(wid, kind)[0], 0)
        self.assertEqual(self.goal()["state"], "DONE_LIVE")
        rows = self.rows()
        rows[0]["note"] = "REALLY_TESTED prod-smoke PASS: ok (edited) goodqa#100"
        self.write(rows)
        g = self.goal()
        self.assertEqual(g["state"], "UNCONFIRMED")
        self.assertEqual(g["cap"], {"would_be": "DONE_LIVE", "tampered": [self.p1], "missing": [], "unpinned": []})
        doc = gv.goals_report(self.home, session=SESSION)
        self.assertIn("UNCONFIRMED", gv.goals_text(doc, notes=False))
        import status_truth as st
        hits = st.classify("Prod move is done and tested.", doc)["contradictions"]
        self.assertEqual([(c["goal"], c["state"]) for c in hits], [("prod-move", "UNCONFIRMED")])
        hits = st.classify("Prod move has not been started.", doc)["contradictions"]  # it has attached evidence
        self.assertEqual([(c["goal"], c["rule"]) for c in hits], [("prod-move", "no-work")])
        self.assertEqual(self.attach(self.p1, "live_test")[0], 0)  # main read it and re-attaches: re-pinned
        g = self.goal()
        self.assertEqual((g["state"], g["cap"]), ("DONE_LIVE", None))

    def test_missing_pinned_pass_caps_the_goal_until_main_removes_it(self):
        for wid, kind in ((self.dep, "deploy"), (self.p1, "live_test")):
            self.assertEqual(self.attach(wid, kind)[0], 0)
        self.write([r for r in self.rows() if r["id"] != self.p1])
        g = self.goal()
        self.assertEqual(g["state"], "UNCONFIRMED")
        self.assertEqual(g["cap"]["missing"], [self.p1])
        self.assertEqual(self.main_run(["attach", "--goal", "prod-move", "--evidence", self.p1, "--remove"])[0], 0)
        self.assertEqual(self.goal()["state"], "LIVE_UNTESTED")

    def test_deferred_goal_still_shows_the_cap(self):
        for wid, kind in ((self.dep, "deploy"), (self.p1, "live_test")):
            self.assertEqual(self.attach(wid, kind)[0], 0)
        self.write([r for r in self.rows() if r["id"] != self.p1])

        def defer(doc):
            doc["goals"][0]["status"] = "deferred"
            return doc
        mc._mutate(self.home, "fixture", "*", defer, {})
        self.assertEqual(self.goal()["state"], "UNCONFIRMED")


class H2CapIsUnavailable(Base):
    """review H2 / mutant M14: a WAL cut at its scan cap while attached ids are unresolved is GOALS UNAVAILABLE."""

    def build(self):
        self.seed()
        pad = json.dumps({"at": iso(time.time()), "event": "pretool", "pad": "x" * 300}) + "\n"
        self.early = self.row("main.jsonl", {"event": "result", "id": "wc0000000001", "result": "PASS",
                                             "note": "REALLY_TESTED early PASS: ok goodqa#100"})
        with open(self.wal / "main.jsonl", "a") as fh:
            fh.write(pad * 40)
        self.late = self.row("main.jsonl", {"event": "result", "id": "wc0000000002", "result": "PASS",
                                            "note": "REALLY_TESTED late PASS: ok goodqa#100"})

    def test_unresolved_attached_row_past_the_cap_is_unavailable(self):
        self.build()
        for wid in (self.early, self.late):
            self.assertEqual(self.main_run(["attach", "--goal", "prod-move", "--evidence", wid, "--kind", "test"])[0], 0)
        with mock.patch.object(gv, "WAL_SCAN_BYTES", 8192):
            doc = gv.goals_report(self.home, session=SESSION)
        self.assertEqual(doc["state"], "timeout")  # f4cbf628: "ok" with the late row MISSING
        self.assertIn("size cap", doc["error"])
        self.assertIn("GOALS UNAVAILABLE (timeout)", gv.goals_text(doc))

    def test_capped_file_with_every_attached_row_resolved_stays_ok(self):  # control
        self.build()
        self.assertEqual(self.main_run(["attach", "--goal", "prod-move", "--evidence", self.early, "--kind",
                                        "test"])[0], 0)
        with mock.patch.object(gv, "WAL_SCAN_BYTES", 8192):
            doc = gv.goals_report(self.home, session=SESSION)
        self.assertEqual(doc["state"], "ok")
        self.assertEqual(doc["goals"][0]["state"], "VERIFIED")


class L1MutantGaps(Base):
    """review L1: mutants M5 (header fallback without the audit check) and M10 (spacing in the tool_use_id scan)."""

    def test_m5_tampered_ledger_header_gives_no_mission_scope(self):
        """NEG-8: goals.json still parses, but no longer matches its audit chain: no mission session from the header."""
        import status_truth as st
        self.seed()
        self.assertEqual(st._ledger_header_mission(), SESSION)  # control: a verified header names the session
        pointer = st._pointer_path()
        pointer.unlink(missing_ok=True)
        path = mc.goals_path(self.home)
        doc = json.loads(path.read_text())
        doc["mission_session"] = OTHER
        path.write_text(json.dumps(doc))
        self.assertEqual(mc.load_goals(self.home)["state"], "ok")
        self.assertFalse(mc.verify_audit(self.home).get("ok"))
        self.assertEqual(st._ledger_header_mission(), "")
        self.assertFalse(pointer.exists())

    def test_m10_spaced_tool_result_ends_the_call(self):
        self.seed()
        args = ["attach", "--goal", "prod-move", "--evidence", "wd0000000009", "--kind", "deploy"]
        tid = self.tool_id()
        self.pretool("python3 ~/.claude/hooks/mission_coverage.py " + " ".join(args), tid)
        self.assertEqual(len(self.stamps()), 1)
        with open(self.transcript, "a") as fh:
            fh.write('{"type": "user", "message": {"content": [{"tool_use_id" : "%s", "type": "tool_result"}]}}\n'
                     % tid)
        mc.claim_main(args, self.home)
        self.assertIsNone(mc._PROOF.get("stamp"))


class M1StampNotBurnedByAProbe(Base):
    """review M1 side effect: take_stamp claimed the stamp before its checks, so any process that failed them (it cannot
    read main's transcript, its TTL differs) still burned main's stamp and main's own command then failed main-only."""

    def test_failed_check_leaves_the_stamp_for_main(self):
        self.seed()
        args = ["attach", "--goal", "prod-move", "--evidence", "wd0000000009", "--kind", "deploy"]
        tid = self.tool_id()
        self.pretool("python3 ~/.claude/hooks/mission_coverage.py " + " ".join(args), tid)
        self.assertEqual(len(self.stamps()), 1)
        with mock.patch.object(caller_identity, "call_still_running", return_value=False):
            mc.claim_main(args, self.home)  # a probe that cannot prove the call
        self.assertIsNone(mc._PROOF.get("stamp"))
        self.assertEqual(len(self.stamps()), 1)  # f4cbf628: 0 (burned)
        mc.claim_main(args, self.home)  # main's own process, still inside its call
        self.assertIsNotNone(mc._PROOF.get("stamp"))
        self.assertEqual(self.stamps(), [])

    def test_wrong_purpose_or_expired_stamp_is_not_consumed(self):
        caller_identity.put_stamp("mission-main", ["x", "y"], session=SESSION, home=self.home)
        self.assertIsNone(caller_identity.take_stamp("mission-main", ["x", "y"], home=self.home, ttl=-1))
        self.assertEqual(len(self.stamps()), 1)
        self.assertIsNotNone(caller_identity.take_stamp("mission-main", ["x", "y"], home=self.home))
        self.assertEqual(self.stamps(), [])


class L2CanonicalDigest(Base):
    def test_lone_surrogates_and_question_mark_digest_differently(self):
        a = json.loads('{"id":"w0","note":"x\\ud800"}')
        b = json.loads('{"id":"w0","note":"x\\udc00"}')
        c = {"id": "w0", "note": "x?"}
        self.assertEqual(len({mc.row_digest(a), mc.row_digest(b), mc.row_digest(c)}), 3)  # f4cbf628: 1

    def test_pin_made_with_the_old_digest_still_matches_a_non_ascii_row(self):
        import hashlib
        rec = {"id": "w0", "note": "REALLY_TESTED x PASS: café — ok"}
        old = hashlib.sha256(json.dumps(rec, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
                             .encode("utf-8", "replace")).hexdigest()
        self.assertNotEqual(old, mc.row_digest(rec))
        self.assertTrue(mc.row_matches(old, rec))
        self.assertTrue(mc.row_matches(mc.row_digest(rec), rec))
        bad = json.loads('{"id":"w0","note":"x\\ud800"}')  # the old digest collides here: never accepted for it
        old_bad = hashlib.sha256(json.dumps(bad, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
                                 .encode("utf-8", "replace")).hexdigest()
        self.assertFalse(mc.row_matches(old_bad, bad))
        # (a legacy pin cannot say whether it was taken over "x?" or "x\ud800"; it keeps matching "x?". No legacy pin
        # exists outside this branch, and the review found no verdict-changing use.)


if __name__ == "__main__":
    unittest.main()
