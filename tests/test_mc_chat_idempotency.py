"""Regression tests for durable, payload-bound dashboard message creation."""

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import os
import stat
import sys
import tempfile
import threading
import unittest
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "harness" / "hooks"))
import mc_chat


class DurableCreationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        mc_chat.ensure_dirs(self.root)
        mc_chat.secret(self.root)

    def send(self, text="first message", **kwargs):
        return mc_chat.new_message("codex", text, client_key="stable-client-key",
                                   root=self.root, **kwargs)

    def test_identical_retry_returns_original_but_changed_text_conflicts(self):
        first, created = self.send()
        repeat, repeated = self.send()
        self.assertTrue(created)
        self.assertFalse(repeated)
        self.assertEqual(first, repeat)
        with self.assertRaises(mc_chat.ChatError) as caught:
            self.send("different instruction")
        self.assertEqual(caught.exception.code, "key-conflict")

    def test_changed_thread_conflicts(self):
        self.send(thread="initiative-a")
        with self.assertRaises(mc_chat.ChatError) as caught:
            self.send(thread="initiative-b")
        self.assertEqual(caught.exception.code, "key-conflict")

    def test_changed_runtime_or_claude_session_conflicts(self):
        self.send()
        mc_chat.register_target("main-one", os.getpid(), root=self.root)
        mc_chat.register_target("main-two", os.getpid(), root=self.root)
        with self.assertRaises(mc_chat.ChatError) as caught:
            mc_chat.new_message("claude", "first message", client_key="stable-client-key",
                                session="main-one", root=self.root)
        self.assertEqual(caught.exception.code, "key-conflict")
        mc_chat.new_message("claude", "first message", client_key="claude-key-0001",
                            session="main-one", root=self.root)
        with self.assertRaises(mc_chat.ChatError) as caught:
            mc_chat.new_message("claude", "first message", client_key="claude-key-0001",
                                session="main-two", root=self.root)
        self.assertEqual(caught.exception.code, "key-conflict")

    def test_existing_reservation_retries_after_target_expires(self):
        mc_chat.register_target("main-one", os.getpid(), root=self.root)
        first, _ = mc_chat.new_message("claude", "first message", client_key="claude-key-0001",
                                       session="main-one", root=self.root)
        with mock.patch.object(mc_chat, "target_registered", return_value=False):
            repeat, created = mc_chat.new_message("claude", "first message", client_key="claude-key-0001",
                                                  session="main-one", root=self.root)
            with self.assertRaises(mc_chat.ChatError) as caught:
                mc_chat.new_message("claude", "new send", client_key="claude-key-0002",
                                    session="main-one", root=self.root)
        self.assertFalse(created)
        self.assertEqual(repeat, first)
        self.assertEqual(caught.exception.code, "no-target")

    def test_concurrent_retries_publish_one_message(self):
        barrier = threading.Barrier(12)

        def send(_):
            barrier.wait(timeout=5)
            return self.send()

        with ThreadPoolExecutor(max_workers=12) as pool:
            results = list(pool.map(send, range(12)))
        self.assertEqual(len({record["id"] for record, _ in results}), 1)
        self.assertEqual(sum(created for _, created in results), 1)
        self.assertEqual(len(list((self.root / "chat/inbox").glob("*.json"))), 1)

    def test_reservation_survives_interrupted_inbox_publication(self):
        original = mc_chat.write_json

        def interrupted(path, value):
            if path.parent.name == "inbox":
                raise OSError("injected interruption")
            return original(path, value)

        with mock.patch.object(mc_chat, "write_json", side_effect=interrupted):
            with self.assertRaises(OSError):
                self.send()
        reservations = list((self.root / "chat/keys").glob("*.json"))
        self.assertEqual(len(reservations), 1)
        reserved = mc_chat.read_json(reservations[0])["record"]
        self.assertTrue(mc_chat.verified(reserved, mc_chat.secret(self.root)))
        recovered, created = self.send()
        self.assertFalse(created)
        self.assertEqual(recovered, reserved)
        self.assertEqual(mc_chat.state(recovered["id"], self.root)["status"], "queued")
        self.assertEqual(len(mc_chat.pending("codex", root=self.root)), 1)

    def test_retry_repairs_interrupted_initial_state(self):
        with mock.patch.object(mc_chat, "set_state", side_effect=OSError("interrupted state")):
            with self.assertRaises(OSError):
                self.send()
        record, created = self.send()
        self.assertFalse(created)
        self.assertEqual(mc_chat.state(record["id"], self.root)["status"], "queued")
        self.assertEqual(len(mc_chat.pending("codex", root=self.root)), 1)

    def test_retry_repairs_interrupted_queue_marker(self):
        with mock.patch.object(mc_chat, "_mark", side_effect=OSError("interrupted queue")):
            with self.assertRaises(OSError):
                self.send()
        record, created = self.send()
        self.assertFalse(created)
        self.assertEqual(mc_chat.state(record["id"], self.root)["status"], "queued")
        self.assertEqual(len(mc_chat.pending("codex", root=self.root)), 1)

    def test_publication_syncs_containing_directories(self):
        synced = []
        original = os.fsync

        def sync(fd):
            synced.append(stat.S_ISDIR(os.fstat(fd).st_mode))
            original(fd)

        with mock.patch.object(mc_chat.os, "fsync", side_effect=sync):
            self.send()
        self.assertGreaterEqual(sum(synced), 4)  # reservation, inbox, state, queue

    def test_nonregular_creation_lock_is_refused(self):
        lock = mc_chat._key_path(self.root, "stable-client-key").with_suffix(".lock")
        os.mkfifo(lock)
        with self.assertRaises(mc_chat.ChatError) as caught:
            self.send()
        self.assertEqual(caught.exception.code, "unsafe-path")
        self.assertEqual(list((self.root / "chat/inbox").glob("*.json")), [])

    def test_legacy_index_still_checks_signature_and_payload(self):
        first, _ = self.send()
        index = next((self.root / "chat/keys").glob("*.json"))
        mc_chat.write_json(index, {"id": first["id"]})
        repeat, created = self.send()
        self.assertEqual(repeat, first)
        self.assertFalse(created)
        forged = dict(first, text="forged replacement")
        mc_chat.write_json(self.root / "chat/inbox" / (first["id"] + ".json"), forged)
        with self.assertRaises(mc_chat.ChatError) as caught:
            self.send()
        self.assertEqual(caught.exception.code, "key-conflict")

    def test_corrupt_key_index_fails_closed_without_second_message(self):
        first, _ = self.send()
        index = next((self.root / "chat/keys").glob("*.json"))
        index.write_text("{truncated", encoding="utf-8")
        with self.assertRaises(mc_chat.ChatError) as caught:
            self.send()
        self.assertEqual(caught.exception.code, "key-conflict")
        self.assertEqual([p.stem for p in (self.root / "chat/inbox").glob("*.json")], [first["id"]])

    def test_retry_never_reopens_answered_message(self):
        first, _ = self.send()
        mc_chat.write_reply(first["id"], "codex", "answer", root=self.root)
        repeat, created = self.send()
        self.assertFalse(created)
        self.assertEqual(repeat, first)
        self.assertEqual(mc_chat.state(first["id"], self.root)["status"], "answered")
        self.assertEqual(mc_chat.pending("codex", root=self.root), [])


if __name__ == "__main__":
    unittest.main()
