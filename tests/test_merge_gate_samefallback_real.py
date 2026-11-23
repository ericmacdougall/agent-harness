"""The same-harness fallback against the REAL self_serve library (no fake module).

The sibling suite (test_merge_gate_samefallback) fakes self_serve to pin this gate's own rules. This file closes the
integration gap: a temp-HOME signed policy, the real grant/consume, the actor built the way peer_review builds it from
main's stamp, and the merge-time recheck through the real status(). Source of the path rule under test:
answer:1471f671-0ed0-40c3-8506-255cb670e4de/44bc4b2f-436b-4711-a4d8-9d7bd7cf0a06 "Allow every path".
Run: python3 -m unittest tests.test_merge_gate_samefallback_real   (from the repository root)
"""
import copy
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from tests import test_merge_gate_samefallback as base
from tests.test_self_serve import SID, body, ci, make_key, ss

mg = base.mg
CAP = base.CAP
GATE_PATHS = ["docs/ok.md", "harness/hooks/merge_gate.py", "db/migrations/0001.sql"]


class RealPolicy(base.FallbackBase):
    """FallbackBase with the real library instead of the fake: setUp builds a signed policy under a throwaway HOME."""

    def setUp(self):
        super().setUp()
        self.patch_stop = None
        # replace the fake that FallbackBase installed with the real module
        patcher = mock.patch.dict(sys.modules, {"self_serve": ss})
        patcher.start()
        self.addCleanup(patcher.stop)
        self.home = os.path.realpath(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(self.home, ignore_errors=True))
        self.claude = Path(self.home) / ".claude"
        self.transcript = self.claude / "projects" / "-x" / (SID + ".jsonl")
        self.transcript.parent.mkdir(parents=True)
        self.transcript.write_text("{}\n")
        native = mock.patch.object(ci, "native_deny_reason", return_value=None)
        native.start()
        self.addCleanup(native.stop)
        seam = mock.patch.dict(ss._SEAM, {"home": self.home, "claude_dir": str(self.claude), "clock": True})
        seam.start()
        self.addCleanup(seam.stop)
        self.key, self.pub = make_key()
        self.key_id = ss.key_id_of(self.pub)
        pol = ss.policy_dir(self.home)
        pol.mkdir(parents=True, mode=0o700)
        os.chmod(pol, 0o700)
        self.actor = {"kind": "claude_main", "payload": {"session_id": SID, "transcript_path": str(self.transcript)}}
        self.install({})

    def install(self, scope, caps=None, **extra):
        now = time.time()
        capabilities = caps if caps is not None else {CAP: {"scope": scope, "ttl_seconds": 900}}
        policy = body(key_id=self.key_id, issued_at=ss.iso(now - 600), expires_at=ss.iso(now + 86400),
                      capabilities=capabilities, **extra)
        for path, data in ((ss.pubkeys_path(self.home), {"schema": "self-serve-pubkeys/1",
                                                        "keys": [ss.public_record(self.pub)]}),
                           (ss.policy_path(self.home), ss.sign_policy(policy, self.key))):
            Path(path).write_bytes(json.dumps(data).encode())
            os.chmod(path, 0o600)

    def block(self, paths):
        return base.good_block(changed_paths=list(paths), changed_paths_sha256=base.paths_digest(paths))


class AcceptanceFlow(RealPolicy):
    def test_ac4_default_policy_mints_for_every_path_including_the_gate_itself(self):
        record = self.mint(actor=self.actor, block=self.block(GATE_PATHS))
        self.assertEqual(record["approval_source"], mg.FALLBACK_SOURCE)
        self.assertEqual(record["denylist_paths"], [])

    def test_the_actor_peer_review_builds_from_main_s_stamp_is_accepted(self):
        import peer_review
        stamp = {"session": SID, "transcript": str(self.transcript)}
        actor = peer_review.fallback_actor_for(stamp, "claude")
        self.assertEqual(self.mint(actor=actor, block=self.block(GATE_PATHS))["approval_source"], mg.FALLBACK_SOURCE)

    def test_the_old_actor_shape_gets_no_grant(self):
        old = {"kind": "main", "proof": "review-auth-stamp", "session": SID, "harness": "claude"}
        with self.assertRaisesRegex(ValueError, "no self-serve grant"):
            self.mint(actor=old)

    def test_actor_needs_a_stamp_with_a_transcript_and_a_claude_author(self):
        import peer_review
        for stamp, author in ((None, "claude"), ({}, "claude"), ({"session": SID}, "claude"),
                              ({"session": "", "transcript": "x"}, "claude"),
                              ({"session": SID, "transcript": str(self.transcript)}, "openai")):
            self.assertIsNone(peer_review.fallback_actor_for(stamp, author), (stamp, author))

    def test_a_helper_payload_gets_no_grant(self):
        helper = copy.deepcopy(self.actor)
        helper["payload"]["agent_id"] = "a1"
        with self.assertRaisesRegex(ValueError, "no self-serve grant"):
            self.mint(actor=helper)

    def test_a_forged_transcript_outside_the_real_claude_dir_gets_no_grant(self):
        forged = copy.deepcopy(self.actor)
        other = Path(self.home) / "elsewhere" / (SID + ".jsonl")
        other.parent.mkdir()
        other.write_text("{}\n")
        forged["payload"]["transcript_path"] = str(other)
        with self.assertRaisesRegex(ValueError, "no self-serve grant"):
            self.mint(actor=forged)

    def test_no_policy_capability_means_no_authorization(self):
        self.install({}, caps={"merge_reviewed_pr": {"scope": {}, "ttl_seconds": 900}})
        with self.assertRaisesRegex(ValueError, "no self-serve grant"):
            self.mint(actor=self.actor)

    def test_a_signed_denylist_is_enforced_by_the_library_and_the_gate(self):
        self.install({"denylist_paths": ["*/migrations/*"]})
        with self.assertRaisesRegex(ValueError, "no self-serve grant|cross-harness"):
            self.mint(actor=self.actor, block=self.block(GATE_PATHS))
        record = self.mint(actor=self.actor, block=self.block(["docs/ok.md", "harness/hooks/merge_gate.py"]))
        self.assertEqual(record["denylist_paths"], ["*/migrations/*"])

    def test_a_repo_scope_that_excludes_this_repo_refuses(self):
        self.install({"repos": ["o/other"]})
        with self.assertRaisesRegex(ValueError, "no self-serve grant"):
            self.mint(actor=self.actor)

    def test_single_use_scope_is_spent_by_the_first_mint(self):
        self.install({"single_use": True})
        self.assertEqual(self.mint(actor=self.actor)["approval_source"], mg.FALLBACK_SOURCE)
        with self.assertRaisesRegex(ValueError, "no self-serve grant"):
            self.mint(actor=self.actor, block=self.block(["docs/other.md"]))

    def test_kill_switch_stops_the_merge_time_recheck(self):
        record = self.mint(actor=self.actor)
        self.assertTrue(mg._fallback_live(record))
        Path(ss.kill_switch_path(self.home)).write_text("off\n")
        self.assertFalse(mg._fallback_live(record))

    def test_the_review_stamp_carries_main_s_transcript(self):
        import caller_identity
        folder = Path(self.home) / "stamps"
        payload = {"session_id": SID, "transcript_path": str(self.transcript), "tool_use_id": "toolu_01ABC"}
        command = "python3 ~/.claude/hooks/peer_review.py pr --github-repo o/r --pr 5"
        with mock.patch.object(caller_identity, "is_main", return_value=True), \
                mock.patch.object(caller_identity, "stamp_dir", return_value=folder):
            mg._stamp_review(command, payload, time.time())
            stamp = caller_identity.take_stamp("review-auth", ["o/r", 5])
        self.assertEqual((stamp["session"], stamp["transcript"]), (SID, str(self.transcript)))


if __name__ == "__main__":
    unittest.main()
