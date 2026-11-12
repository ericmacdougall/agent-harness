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


if __name__ == "__main__":
    unittest.main()
