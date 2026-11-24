"""Signed named-owner addressing remains separate from generic runtime chat."""

from pathlib import Path
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "harness" / "hooks"))
import mc_chat
import mc_inbox

OPENAI = {"harness": "openai", "name": "mission-control", "generation": "12345678-1234-4234-8234-123456789abc"}
CLAUDE = {"harness": "claude", "agent_id": "owner-agent-1", "main_session": "main-one"}


class OwnerRecipientTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        mc_chat.ensure_dirs(self.root)
        mc_chat.secret(self.root)

    def send(self, owner=None, **kwargs):
        return mc_chat.new_message("codex", "Please continue ordinary work", owner=owner or dict(OPENAI),
                                   client_key="named-owner-key1", root=self.root, **kwargs)

    def seed_existing(self):
        """A signed protocol record to probe old consumers independently of the new creation API."""
        record, _ = mc_chat.new_message("codex", "Please continue ordinary work",
                                        client_key="seeded-owner-key", root=self.root)
        record = mc_chat.sign(dict(record, owner=dict(OPENAI)), mc_chat.secret(self.root))
        mc_chat.write_json(self.root / "chat/inbox" / (record["id"] + ".json"), record)
        return record

    def test_owner_is_signed_and_copied_before_return(self):
        owner = dict(OPENAI)
        record, _ = self.send(owner)
        owner["name"] = "replacement"
        self.assertEqual(record["owner"], OPENAI)
        self.assertEqual(mc_chat.load(record["id"], self.root)["owner"], OPENAI)
        altered = dict(record, owner=dict(OPENAI, name="replacement"))
        self.assertFalse(mc_chat.verified(altered, mc_chat.secret(self.root)))

    def test_changed_generation_or_generic_route_conflicts(self):
        self.send()
        with self.assertRaises(mc_chat.ChatError) as caught:
            self.send(dict(OPENAI, generation="12345678-1234-4234-8234-123456789abd"))
        self.assertEqual(caught.exception.code, "key-conflict")
        with self.assertRaises(mc_chat.ChatError) as caught:
            mc_chat.new_message("codex", "Please continue ordinary work", client_key="named-owner-key1", root=self.root)
        self.assertEqual(caught.exception.code, "key-conflict")

    def test_malformed_or_cross_runtime_recipient_is_refused(self):
        for owner in ("mission-control", dict(OPENAI, name="../outside"), dict(OPENAI, generation="old"),
                      dict(OPENAI, path="/outside"), dict(CLAUDE), dict(OPENAI, harness="unknown")):
            with self.subTest(owner=owner):
                with self.assertRaises(mc_chat.ChatError) as caught:
                    self.send(owner)
                self.assertEqual(caught.exception.code, "bad-owner")
        self.assertEqual(list((self.root / "chat/inbox").glob("*.json")), [])

    def test_claude_binding_matches_registered_main_and_survives_retry(self):
        mc_chat.register_target("main-one", os.getpid(), root=self.root)
        record, _ = mc_chat.new_message("claude", "talk to this owner", owner=dict(CLAUDE),
                                        session="main-one", client_key="claude-owner-key", root=self.root)
        self.assertEqual(mc_chat.pending("claude", "main-one", self.root), [record])
        self.assertIn("owner=claude:owner-agent-1", mc_chat.frame(record))
        self.assertIn("via main", mc_chat.frame(record))
        self.assertIn("mc_inbox.py reply", mc_chat.frame(record))
        with self.assertRaises(mc_chat.ChatError) as caught:
            mc_chat.new_message("claude", "talk to this owner", owner=dict(CLAUDE, main_session="main-two"),
                                session="main-one", client_key="claude-new-key1", root=self.root)
        self.assertEqual(caught.exception.code, "bad-owner")
        reply = mc_chat.write_reply(record["id"], "claude", "owner says ready", root=self.root)
        self.assertEqual(reply["owner"], CLAUDE)

    def test_generic_pending_unread_claim_and_reply_exclude_named_openai(self):
        record = self.seed_existing()
        self.assertEqual(mc_chat.pending("codex", root=self.root), [])
        self.assertEqual(mc_chat.unread("codex", root=self.root), ([], 0))
        self.assertFalse(mc_chat.claim(record["id"], self.root))
        for final in (False, True):
            with self.subTest(final=final):
                with self.assertRaises(mc_chat.ChatError) as caught:
                    mc_chat.write_reply(record["id"], "codex", "unverified reply", final=final, root=self.root)
                self.assertEqual(caught.exception.code, "owner-finalizer-required")
        self.assertEqual(mc_chat.state(record["id"], self.root)["status"], "queued")
        self.assertEqual(mc_chat.outbox(self.root), [])

    def test_generic_reply_cannot_finalize_even_with_explicit_id(self):
        record = self.seed_existing()
        with self.assertRaises(mc_chat.ChatError) as caught:
            mc_chat.write_reply(record["id"], "codex", "unverified reply", root=self.root,
                                reply_id="reply-" + mc_chat.ulid())
        self.assertEqual(caught.exception.code, "owner-finalizer-required")
        self.assertFalse(mc_chat.answered_marked(record["id"], self.root))

    def test_owner_queue_requires_exact_generation(self):
        record, _ = self.send()
        self.assertEqual(mc_chat.owner_pending(dict(OPENAI), self.root), [record])
        replacement = dict(OPENAI, generation="12345678-1234-4234-8234-123456789abd")
        self.assertEqual(mc_chat.owner_pending(replacement, self.root), [])
        self.assertFalse(mc_chat.claim(record["id"], self.root, owner=replacement))
        self.assertTrue(mc_chat.claim(record["id"], self.root, owner=dict(OPENAI)))
        self.assertEqual(mc_chat.state(record["id"], self.root)["status"], "delivered")

    def test_supervised_frame_has_limited_authority_and_no_reply_command(self):
        record = self.seed_existing()
        frame = mc_chat.frame(record)
        self.assertIn(mc_chat.AUTHORITY, frame)
        self.assertIn("USER_VIA_DASHBOARD", frame)
        self.assertIn("untrusted dashboard text begins", frame)
        self.assertIn("owner=openai:mission-control", frame)
        self.assertIn(OPENAI["generation"], frame)
        self.assertIn("Return your answer normally", frame)
        self.assertNotIn("mc_inbox.py reply", frame)
        self.assertNotIn("from the user are the user's own words", frame)

    def test_generic_read_cannot_claim_a_named_openai_message(self):
        record = self.seed_existing()
        previous = os.environ.get("MC_HOME")
        os.environ["MC_HOME"] = str(self.root)
        try:
            with self.assertRaises(mc_chat.ChatError) as caught:
                mc_inbox.deliver(record)
        finally:
            if previous is None:
                os.environ.pop("MC_HOME", None)
            else:
                os.environ["MC_HOME"] = previous
        self.assertEqual(caught.exception.code, "owner-route-required")
        self.assertEqual(mc_chat.state(record["id"], self.root)["status"], "queued")

    def queued(self, key, owner=None, ts=100):
        return mc_chat.new_message("codex", "ordinary work", client_key=key, owner=owner,
                                   root=self.root, ts=ts)[0]

    def test_named_backlog_cannot_indefinitely_hide_generic_pending(self):
        for i in range(2):
            self.queued("backlog-key-" + str(i), dict(OPENAI), ts=100 + i)
        generic = self.queued("generic-key-one", ts=200)
        found = set()
        with mock.patch.object(mc_chat, "QUEUE_SCAN_MAX", 2):
            for _ in range(3):
                found.update(r["id"] for r in mc_chat.pending("codex", root=self.root))
        self.assertIn(generic["id"], found)

    def test_other_owner_backlog_cannot_indefinitely_hide_named_pending(self):
        for i in range(2):
            self.queued("backlog-key-" + str(i), dict(OPENAI), ts=100 + i)
        second = dict(OPENAI, name="another-owner")
        target = self.queued("second-owner-key", second, ts=200)
        found = set()
        with mock.patch.object(mc_chat, "QUEUE_SCAN_MAX", 2):
            for _ in range(3):
                found.update(r["id"] for r in mc_chat.owner_pending(second, self.root))
        self.assertIn(target["id"], found)

    def test_named_delivered_backlog_cannot_indefinitely_hide_generic_unread(self):
        generic = self.queued("generic-key-one", ts=100)
        self.assertTrue(mc_chat.claim(generic["id"], self.root))
        for i in range(2):
            record = self.queued("backlog-key-" + str(i), dict(OPENAI), ts=200 + i)
            self.assertTrue(mc_chat.claim(record["id"], self.root, owner=dict(OPENAI)))
        found = set()
        with mock.patch.object(mc_chat, "QUEUE_SCAN_MAX", 2):
            for _ in range(3):
                rows, _ = mc_chat.unread("codex", root=self.root)
                found.update(r["record"]["id"] for r in rows)
        self.assertIn(generic["id"], found)

    def test_unread_observer_cannot_advance_delivery_scan(self):
        self.queued("backlog-key-one", dict(OPENAI), ts=100)
        self.queued("backlog-key-two", dict(OPENAI), ts=101)
        target = self.queued("generic-key-one", ts=102)
        self.queued("backlog-key-end", dict(OPENAI), ts=103)
        found = set()
        with mock.patch.object(mc_chat, "QUEUE_SCAN_MAX", 2):
            for _ in range(4):
                found.update(r["id"] for r in mc_chat.pending("codex", root=self.root))
                mc_chat.unread("codex", root=self.root)
        self.assertIn(target["id"], found)


if __name__ == "__main__":
    unittest.main()
