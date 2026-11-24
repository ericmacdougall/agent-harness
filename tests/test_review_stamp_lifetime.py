"""goodqa#16811 round 1 (F2): a review-auth stamp lives only as long as the review run it was minted for.

peer_review.py takes main's stamp right after parsing its arguments, so a run that exits early (here a HEAD
mismatch) leaves nothing for a later process to take; and a stamp older than REVIEW_STAMP_TTL_SECONDS was left by
a run that never started, so it is never honoured. Before this change the stamp was taken only after the PR binding
was verified and lived 600 s, so a subagent's bound run could take a stamp a failed main run left behind.

The repository, PR and providers are local fixtures (test_review_merge_authorization's end-to-end setup).
"""
import json
import os
import subprocess
import sys
import time
import unittest
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "harness" / "hooks"))
sys.path.insert(0, str(HERE))
import caller_identity  # noqa: E402
import merge_gate as mg  # noqa: E402
import mission_gate  # noqa: E402
import test_merge_gate as fixture  # noqa: E402
import test_review_merge_authorization as e2e  # noqa: E402


class StampLifetime(unittest.TestCase):
    setUp = e2e.EndToEndTests.setUp
    fake = e2e.EndToEndTests.fake
    run_review = e2e.EndToEndTests.run_review

    def stamp(self, age=0):
        e2e.main_call_stamp(self.root, age=age)

    def left(self):
        return caller_identity.take_stamp("review-auth", ["o/r", 5], home=self.root)

    def test_a_run_that_exits_early_consumes_the_stamp(self):
        self.stamp()
        self.head, real = "b" * 40, self.head  # --expected-head no longer matches the repo
        try:
            result = self.run_review("--author-harness", "claude")
        finally:
            self.head = real
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("repo HEAD differs from --expected-head", result.stderr)
        self.assertIsNone(self.left(), "the failed run took the stamp, so no later run can")

    def test_a_usage_error_consumes_the_stamp_too(self):
        self.stamp()
        result = self.run_review("--reviewer", "codex-only", "--secondary", "kimi")
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIsNone(self.left())

    def test_an_argparse_refusal_consumes_the_stamp_too(self):
        # argparse exits inside parse_args, before the take that follows it.
        for extra in (("--no-such-option",), ("--author-harness", "nobody"), ("--help",)):
            with self.subTest(extra=extra):
                self.stamp()
                result = self.run_review(*extra)
                self.assertIn(result.returncode, (0, 2), result.stdout + result.stderr)
                self.assertIsNone(self.left(), extra)

    def test_an_argparse_refusal_with_no_main_stamp_leaves_the_stamp(self):
        # Control: the opt-out holds on the refusal path too.
        self.stamp()
        result = self.run_review("--no-main-stamp", "--no-such-option")
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIsNotNone(self.left())

    def test_a_stamp_older_than_the_review_window_is_not_honoured(self):
        self.stamp(age=300)
        result = self.run_review("--author-harness", "claude")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("Merge authorization:", result.stdout)
        self.assertIn("no main-agent stamp", result.stderr)
        self.assertIn("honoured only within 120 s", result.stderr)

    def test_a_fresh_stamp_still_authorizes(self):
        # Control: the same run with a stamp minted now authorizes the merge and consumes the stamp.
        self.stamp(age=5)
        result = self.run_review("--author-harness", "claude")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("Merge authorization:", result.stdout)
        self.assertIsNone(self.left())

    def test_no_main_stamp_never_touches_the_stamp_even_when_the_run_fails(self):
        # Control (goodqa#16049): the ahc daemon's run neither takes nor burns main's stamp.
        self.stamp()
        self.head, real = "b" * 40, self.head
        try:
            result = self.run_review("--no-main-stamp")
        finally:
            self.head = real
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIsNotNone(self.left())

    def test_an_unbound_stamp_never_authorizes(self):
        # Round 2 (F2): a stamp that names no call of main's (the only kind before this round) is not honoured.
        caller_identity.put_stamp("review-auth", ["o/r", 5], home=self.root)
        result = self.run_review("--author-harness", "claude")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("Merge authorization:", result.stdout)
        self.assertIn("no main-agent stamp", result.stderr)


def tool_result(call, result, is_error=False, more=()):
    """A record Claude Code appends to main's transcript when a Bash call ends, is refused or starts in the
    background: a "user" message whose content is the call's tool_result block, plus toolUseResult."""
    block = {"tool_use_id": call, "type": "tool_result", "content": "fixture output", "is_error": is_error}
    return {"type": "user", "message": {"role": "user", "content": [block, *more]}, "toolUseResult": result}


def started(call, task="b7f3k2q9x", **changes):
    """The one accepted shape: Claude Code's "started in the background" result (field set from real transcripts)."""
    result = {"stdout": "", "stderr": "", "interrupted": False, "isImage": False, "noOutputExpected": False,
              "backgroundTaskId": task}
    result.update(changes)
    return tool_result(call, result)


def copy_of(call):
    """Claude Code's own copy of an already logged message (an api-request-blob record), which names the call too."""
    return {"type": "api-request-blob", "sessionId": e2e.MAIN_SID, "hash": "0" * 16,
            "message": {"role": "user", "content": [{"tool_use_id": call, "type": "tool_result", "content": "x"}]}}


class StampBoundToMainsCall(unittest.TestCase):
    """goodqa#16811 round 2 (F2): main's hook mints the stamp for one call, and only a process that runs while that
    call is still running may take it. Each must-fail case below mints the stamp through the real merge_gate hook for
    a main call, writes what Claude Code writes when that call is refused or fails, and then starts the bound review
    as another process: before this change the review took the stamp and authorized the merge."""

    setUp = e2e.EndToEndTests.setUp
    fake = e2e.EndToEndTests.fake
    COMMAND = ("python3 ~/.claude/hooks/peer_review.py pr --repo /w --packet /p --expected-head " + "a" * 40
               + " --github-repo o/r --pr 5 --author-harness claude")

    def run_review(self, *extra):
        """e2e's run, with a fresh report path and usage store per run: one test runs the review several times, and
        the usage store refuses an identical invocation that already completed."""
        self.runs = getattr(self, "runs", 0) + 1
        env = dict(os.environ, HOME=str(self.root), PATH=str(self.bin) + os.pathsep + "/usr/bin:/bin",
                   AGENT_HARNESS_USAGE_DIR=str(self.root / ("usage-%d" % self.runs)),
                   AGENT_HARNESS_REVIEW_POLICY=str(e2e.ROOT / "harness" / "hooks" / "review_policy.json"))
        return subprocess.run([
            sys.executable, str(e2e.HOOKS / "peer_review.py"), "pr", "--repo", str(self.repo),
            "--packet", str(self.packet), "--output", str(self.root / ("review-%d.md" % self.runs)),
            "--expected-head", self.head, "--github-repo", "o/r", "--pr", "5", *extra],
            text=True, capture_output=True, env=env, timeout=45)

    def environment(self):
        values = {"HOME": str(self.root)}
        patcher = mock.patch.dict(os.environ, values)
        patcher.start()
        self.addCleanup(patcher.stop)
        for name in ("CLAUDE_CONFIG_DIR", "AH_HOME", "CODEX_THREAD_ID"):
            os.environ.pop(name, None)

    def mint(self, call, background=False, now=None):
        """main's PreToolUse(Bash) payload for the review command, through merge_gate.decide."""
        self.environment()
        transcript = e2e.main_transcript(self.root)
        tool_input = {"command": self.COMMAND}
        if background:
            tool_input["run_in_background"] = True
        payload = fixture.bash(self.COMMAND, tool_input=tool_input, session_id=e2e.MAIN_SID, tool_use_id=call,
                               transcript_path=str(transcript), hook_event_name="PreToolUse")
        notes = []
        code, text = mg.decide(payload, fixture.FakeGh(fixture.SCENARIOS["green"]), self.root / "gate", now=now,
                               notes=notes)
        self.assertEqual(code, 0, text)
        self.assertEqual(notes, [], "the fixture call must mint a stamp")
        return transcript

    def append(self, transcript, *records):
        with open(str(transcript), "a", encoding="utf-8") as handle:
            for record in records:
                handle.write(json.dumps(record) + "\n")

    def post(self, call, event):
        """mission_gate's PostToolUse / PostToolUseFailure / PermissionDenied hook for main's call."""
        mission_gate.cmd_posttool({"tool_name": "Bash", "hook_event_name": event, "tool_use_id": call,
                                   "session_id": e2e.MAIN_SID})

    def authorizes(self):
        result = self.run_review("--author-harness", "claude")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return "Merge authorization:" in result.stdout

    # --- a call in the foreground: any record naming it means it is over ---------------------------------------

    def test_a_call_that_is_over_leaves_nothing_another_process_can_take(self):
        cases = {
            "denied by another PreToolUse hook": tool_result("C", "Error: blocked by a PreToolUse hook", True),
            "rejected at the permission prompt": tool_result("C", "User rejected tool use", True),
            "failed to launch": tool_result("C", "Error: spawn /bin/zsh ENOENT", True),
            "already finished": tool_result("C", {"stdout": "", "stderr": "", "interrupted": False}),
        }
        for index, (name, record) in enumerate(cases.items()):
            call = "toolu_01FOREGROUND%014d" % index
            with self.subTest(name):
                transcript = self.mint(call)
                self.append(transcript, json.loads(json.dumps(record).replace('"C"', json.dumps(call))))
                self.assertFalse(self.authorizes(), name)

    def test_a_call_still_running_authorizes(self):
        # Positive control: the same mint with nothing written for the call yet.
        self.mint("toolu_01FOREGROUNDRUNNING0001")
        self.assertTrue(self.authorizes())

    def test_a_copy_record_before_the_result_does_not_end_a_foreground_call(self):
        # Positive control from real transcripts: Claude Code can write a data-flow-records line naming the call
        # before the call's own result (3 of 5255 foreground calls in a replay over 40 main transcripts).
        call = "toolu_01FOREGROUNDFLOW000001"
        transcript = self.mint(call)
        self.append(transcript, {"type": "data-flow-records", "v": 1, "sessionId": e2e.MAIN_SID,
                                 "records": [{"tool_name": "Bash", "tool_use_id": call, "event_id": "e1"}]})
        self.assertTrue(self.authorizes())

    def test_a_record_for_another_call_does_not_end_this_one(self):
        # Positive control: main's other calls finishing meanwhile do not matter.
        transcript = self.mint("toolu_01FOREGROUNDOTHER00001")
        self.append(transcript, tool_result("toolu_01SOMEOTHERCALL0000001", "Error: denied", True))
        self.assertTrue(self.authorizes())

    # --- a call started with run_in_background (main's ruling Q1 = b) ------------------------------------------

    def test_a_background_start_authorizes_after_its_post_tool_use(self):
        # Positive control: the accepted shape, and PostToolUse (which fires at once for a background start) keeps it.
        call = "toolu_01BACKGROUNDSTART00001"
        transcript = self.mint(call, background=True)
        self.append(transcript, started(call))
        self.post(call, "PostToolUse")
        self.assertTrue(self.authorizes())

    def test_a_background_start_with_the_transcripts_own_copies_authorizes(self):
        # Positive control: Claude Code's copy records name the call too and are skipped.
        call = "toolu_01BACKGROUNDCOPIES0001"
        transcript = self.mint(call, background=True)
        self.append(transcript, started(call), copy_of(call), {"type": "data-flow-records", "records": [
            {"tool_name": "Bash", "tool_use_id": call, "event_id": "e1"}]})
        self.assertTrue(self.authorizes())

    def test_every_neighbour_of_the_background_start_shape_is_refused(self):
        # Main's condition: one must-fail case per neighbouring shape.
        def cases(call):
            return {
                "hook denial": [tool_result(call, "Error: blocked by a PreToolUse hook", True)],
                "permission rejection": [tool_result(call, "User rejected tool use", True)],
                "launch error": [tool_result(call, "Error: spawn /bin/zsh ENOENT", True)],
                "is_error true with a background id": [tool_result(call, started(call)["toolUseResult"], True)],
                "empty backgroundTaskId": [started(call, task="")],
                "blank backgroundTaskId": [started(call, task="   ")],
                "backgroundTaskId not a string": [started(call, task=12345)],
                "backgroundTaskId missing": [tool_result(call, {"stdout": "", "stderr": "", "interrupted": False})],
                "interrupted": [started(call, interrupted=True)],
                "toolUseResult a string": [tool_result(call, "Command running in background")],
                "a second content block": [tool_result(call, started(call)["toolUseResult"],
                                                       more=({"type": "text", "text": "x"},))],
                "a second start record": [started(call), started(call, task="c8g4l3r0y")],
                "a start, then the call refused": [started(call), tool_result(call, "Error: denied", True)],
                "a record of another type naming the call": [started(call), {"type": "assistant", "message": {
                    "content": [{"type": "tool_result", "tool_use_id": call}]}}],
            }
        for index, name in enumerate(cases("x")):
            call = "toolu_01NEIGHBOUR%015d" % index
            with self.subTest(name):
                transcript = self.mint(call, background=True)
                self.append(transcript, *cases(call)[name])
                self.assertFalse(self.authorizes(), name)

    def test_a_line_naming_the_call_that_does_not_parse_is_refused(self):
        call = "toolu_01BACKGROUNDTORN000001"
        transcript = self.mint(call, background=True)
        line = json.dumps(started(call))
        with open(str(transcript), "a", encoding="utf-8") as handle:
            handle.write(line[: len(line) // 2 + 40] + "\n")
        self.assertIn(call, line[: len(line) // 2 + 40], "fixture: the torn line names the call")
        self.assertFalse(self.authorizes())

    def test_post_tool_use_failure_and_permission_denied_still_delete_a_background_stamp(self):
        for index, event in enumerate(("PostToolUseFailure", "PermissionDenied")):
            call = "toolu_01BACKGROUNDPOST%010d" % index
            with self.subTest(event):
                transcript = self.mint(call, background=True)
                self.append(transcript, started(call))
                self.post(call, event)
                self.assertFalse(self.authorizes(), event)

    def test_a_background_stamp_still_dies_at_the_window_and_at_first_take(self):
        # Regression guard (this window predates round 2, so it also holds on f54937a): the background flag
        # never lengthens a stamp's life.
        call = "toolu_01BACKGROUNDWINDOW0001"
        transcript = self.mint(call, background=True, now=time.time() - 121)
        self.append(transcript, started(call))
        self.assertFalse(self.authorizes(), "older than 120 s")
        call = "toolu_01BACKGROUNDONCE000001"
        transcript = self.mint(call, background=True)
        self.append(transcript, started(call))
        self.assertTrue(self.authorizes(), "control: the first take")
        self.assertFalse(self.authorizes(), "a second run finds nothing")


if __name__ == "__main__":
    unittest.main()
