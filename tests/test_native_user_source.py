"""Native citations retain actual source identity without granting authority."""
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

HOOKS = Path(__file__).resolve().parents[1] / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
import native_user_source as ns
import ah_kill as ak
from native_context import decode_candidate_json


def snapshot():
    # Sanitized observed read_thread shape; labels are fixture identities only.
    return {"thread": {"id": "thread-opaque-1", "hostId": "local", "kind": "main"},
            "turns": [{"id": "turn-opaque-2", "items": [
                {"id": "item-opaque-3", "type": "userMessage",
                 "content": [{"type": "text", "text": "Stop the old jobs after reviewing their work."}]}]}]}


class NativeCandidates(unittest.TestCase):
    def test_actual_ids_and_exact_excerpt_are_preserved_without_invented_time(self):
        value = ns.list_candidates(snapshot())[0]
        self.assertEqual(value["citation"], "codex:local/thread-opaque-1/turn-opaque-2/item-opaque-3")
        self.assertTrue(value["weak"])
        self.assertIsNone(value["event_time"])
        self.assertEqual(value["human_origin"], "unverified")
        self.assertFalse(value["strong_user_source"])
        self.assertFalse(value["main_authority"])
        self.assertEqual(ns.resolve_candidate(snapshot(), value["citation"], "old jobs")["excerpt"], "old jobs")

    def test_wrong_host_thread_turn_item_or_excerpt_does_not_resolve(self):
        citation = ns.list_candidates(snapshot())[0]["citation"]
        for old in ("local", "thread-opaque-1", "turn-opaque-2", "item-opaque-3"):
            with self.subTest(field=old), self.assertRaises(ValueError):
                ns.resolve_candidate(snapshot(), citation.replace(old, "other"), "old jobs")
        with self.assertRaises(ValueError):
            ns.resolve_candidate(snapshot(), citation, "stop pid 4242")

    def test_assistant_tool_hook_automation_and_compaction_are_not_users(self):
        for kind in ("agentMessage", "tool", "hook", "compaction", "automation"):
            data = snapshot(); data["turns"][0]["items"][0]["type"] = kind
            self.assertEqual(ns.list_candidates(data), [])
        for origin in ("automation", "scheduled", "hook", "tool"):
            data = snapshot(); data["turns"][0]["items"][0]["origin"] = origin
            self.assertEqual(ns.list_candidates(data), [])

    def test_claimed_human_time_root_and_injected_provider_never_upgrade(self):
        data = snapshot(); item = data["turns"][0]["items"][0]
        item.update(origin="human", timestamp="2099-01-01T00:00:00Z", strong=True, main_authority=True)
        class Adapter:
            trusted = True
            def snapshot(self): return data
        with mock.patch.dict(os.environ, {"CODEX_NATIVE_TRUSTED": "1", "NATIVE_STRONG_PROVIDER": "fixture"}):
            result = ns.list_from_provider(Adapter())[0]
        self.assertTrue(result["weak"])
        self.assertFalse(result["strong_user_source"])
        self.assertIsNone(result["event_time"])
        self.assertEqual(result["human_origin"], "unverified")
        self.assertFalse(hasattr(ns, "register_strong_provider"))

    def test_ambiguous_duplicates_and_unbounded_inputs_reject(self):
        data = snapshot(); data["turns"][0]["items"] *= 2
        with self.assertRaises(ValueError): ns.list_candidates(data)
        data = snapshot(); data["turns"] *= 2
        with self.assertRaises(ValueError): ns.list_candidates(data)
        data = snapshot(); data["thread"]["id"] = "../forged"
        with self.assertRaises(ValueError): ns.list_candidates(data)
        for raw in ('{"a":1,"a":2}', '{"a":NaN}', '[' * 33 + ']' * 33, 'x' * (1024 * 1024 + 1)):
            with self.subTest(shape=raw[:20]), self.assertRaises(ValueError): decode_candidate_json(raw)

    def test_excerpts_are_redacted_and_listing_cannot_register_authority(self):
        data = snapshot()
        data["turns"][0]["items"][0]["content"][0]["text"] = "password=" + "fixture-value"
        self.assertNotIn("fixture-value", ns.list_candidates(data)[0]["excerpt"])
        run = subprocess.run([sys.executable, str(HOOKS / "native_user_source.py"), "list"],
                             input=json.dumps(snapshot()), text=True, capture_output=True, timeout=5)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertTrue(json.loads(run.stdout)[0]["weak"])
        bad = subprocess.run([sys.executable, str(HOOKS / "native_user_source.py"), "register-strong"],
                             input="{}", text=True, capture_output=True, timeout=5)
        self.assertNotEqual(bad.returncode, 0)

    def test_weak_native_candidate_cannot_approve_even_an_exact_pid_stop(self):
        data = snapshot()
        data["turns"][0]["items"][0]["content"][0]["text"] = "Stop pid 4242"
        candidate = ns.list_candidates(data)[0]
        class ImportedLedger:
            def ledger(self, session, home):
                return [{"id": "ask-fixture", "_closed": {"source": candidate["citation"]}}]
            def resolve(self, source, options):
                # Even a permissive external resolver cannot lift the existing
                # strong-human requirement from this weak candidate.
                return {"ok": True, "origin": "user", "weak": candidate["weak"],
                        "chain": [{"kind": "user", "timestamp": "2026-01-01T00:00:00Z", "text": "Stop pid 4242"}]}
        with self.assertRaises(ak.KillError) as caught:
            ak.resolve_approval("ask-fixture", "fixture-session", Path("/nonexistent"), prov=ImportedLedger())
        self.assertEqual(caught.exception.code, "approval_invalid")


if __name__ == "__main__": unittest.main()
