"""caller_identity: positive main proof (#134 red-team B7) and main-only stamps (B2, B4)."""
import json
import os
import sys
import tempfile
import time
import unittest
from unittest import mock
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "harness" / "hooks"))
import caller_identity as ci  # noqa: E402

SID = "11111111-2222-3333-4444-555555555555"


class IsMain(unittest.TestCase):
    def setUp(self):
        # These fixtures model genuinely Claude calls, independent of test-host ancestry.
        non_native = mock.patch.object(ci, "native_deny_reason", return_value=None)
        non_native.start()
        self.addCleanup(non_native.stop)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.claude = Path(os.path.realpath(self.tmp.name)) / ".claude"
        self.main = self.claude / "projects" / "-Users-x" / (SID + ".jsonl")
        self.main.parent.mkdir(parents=True)
        self.main.write_text("{}\n")

    def payload(self, **extra):
        base = {"session_id": SID, "transcript_path": str(self.main), "tool_name": "Bash"}
        base.update(extra)
        return base

    def test_a_main_transcript_proves_main(self):
        self.assertTrue(ci.is_main(self.payload(), self.claude))

    def test_anything_else_is_not_main(self):
        sub = self.main.parent / SID / "subagents" / "agent-a1.jsonl"
        sub.parent.mkdir(parents=True)
        sub.write_text("{}\n")
        codex = Path(self.tmp.name) / ".codex" / "sessions" / (SID + ".jsonl")
        codex.parent.mkdir(parents=True)
        codex.write_text("{}\n")
        link = self.main.parent / ("22222222-2222-3333-4444-555555555555.jsonl")
        link.symlink_to(codex)
        cases = {
            "agent_id": self.payload(agent_id="a1"),
            "agent_type": self.payload(agent_type="general-purpose"),
            "subagent transcript": self.payload(transcript_path=str(sub)),
            "codex rollout": self.payload(transcript_path=str(codex)),
            "no transcript (a Codex payload)": {"session_id": SID, "tool_name": "Bash"},
            "other session's transcript": self.payload(session_id="22222222-2222-3333-4444-555555555556"),
            "missing file": self.payload(transcript_path=str(self.main.parent / ("3" * 8 + SID[8:] + ".jsonl")),
                                         session_id="3" * 8 + SID[8:]),
            "symlink out of projects": self.payload(transcript_path=str(link),
                                                    session_id="22222222-2222-3333-4444-555555555555"),
            "not a session id": self.payload(session_id="../../x"),
            "not a dict": None,
        }
        for name, payload in cases.items():
            with self.subTest(name=name):
                self.assertFalse(ci.is_main(payload, self.claude))


class NativeMainPrecedence(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.claude = Path(self.tmp.name).resolve() / ".claude"
        transcript = self.claude / "projects" / "fixture" / (SID + ".jsonl")
        transcript.parent.mkdir(parents=True)
        transcript.write_text("{}\n")
        self.payload = {"session_id": SID, "transcript_path": str(transcript), "tool_name": "Bash"}

    def test_native_marker_cannot_claim_an_existing_claude_root(self):
        with mock.patch.dict(os.environ, {"CODEX_THREAD_ID": "native-test-fixture"}):
            self.assertFalse(ci.is_main(self.payload, self.claude))

    def test_verified_native_origin_precedes_claude_transcript(self):
        with mock.patch.object(ci, "native_deny_reason", return_value="verified_openai_origin", create=True):
            self.assertFalse(ci.is_main(self.payload, self.claude))

    def test_native_child_and_root_looking_payloads_cannot_inherit_claude_main(self):
        with mock.patch.object(ci, "native_deny_reason", return_value="native_origin_has_no_main_admission"):
            for fields in ({"agent_id": "child"}, {"agent_type": "worker"},
                           {"agentType": "child", "role": "main"}, {"role": "main", "generation": "claimed"}):
                with self.subTest(fields=fields):
                    self.assertFalse(ci.is_main(dict(self.payload, **fields), self.claude))


class Stamps(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name)

    def test_single_use_bound_to_purpose_and_key(self):
        ci.put_stamp("review-auth", ["O/R", 5], home=self.home)
        self.assertIsNone(ci.take_stamp("review-auth", ["o/r", 6], home=self.home))
        self.assertIsNone(ci.take_stamp("ack-handoff", ["o/r", 5], home=self.home))
        self.assertIsNotNone(ci.take_stamp("review-auth", ["o/r", 5], home=self.home))
        self.assertIsNone(ci.take_stamp("review-auth", ["o/r", 5], home=self.home))

    def test_an_old_stamp_is_refused(self):
        ci.put_stamp("ack-handoff", ["agent-1"], home=self.home, now=time.time() - ci.STAMP_TTL_SECONDS - 5)
        self.assertIsNone(ci.take_stamp("ack-handoff", ["agent-1"], home=self.home))


if __name__ == "__main__":
    unittest.main()
