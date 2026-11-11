"""The admission preview has no policy, grant, enrollment or stamp side effect."""
import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

HOOKS = Path(__file__).resolve().parents[1] / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
import native_admission as na


def proposal():
    return {"schema": 1, "state": "PROPOSED_NOT_ADMITTED", "generation": None,
            "activation_profile": "operator_exact_operation_only", "automatic_native_main": False,
            "operation_grants": [], "runtime_observation": {},
            "proposed_roles": [{"host": "local", "thread": "thread-opaque-1", "role": "orchestrator", "admitted": False}],
            "user_source_evidence": {"platform": "codex", "host": "local", "thread": "thread-opaque-1",
                                     "turn": "turn-opaque-2", "item": "item-opaque-3", "evidence_only": True,
                                     "individual_message_time": None, "native_human_origin_attestation": None},
            "bootstrap_status": "Proposed only; no active registry exists."}


class InertPreview(unittest.TestCase):
    def test_digest_binds_candidate_but_grants_nothing_and_does_not_write(self):
        data = proposal(); original = copy.deepcopy(data)
        with tempfile.TemporaryDirectory() as home, mock.patch.dict(os.environ, {"HOME": home}):
            result = na.preview(data)
            self.assertEqual(list(Path(home).iterdir()), [])
        self.assertEqual(data, original)
        self.assertEqual(result["state"], "PREVIEW_ONLY")
        self.assertEqual(result["authority"], "none")
        self.assertIsNone(result["active_generation"])
        self.assertEqual(result["operation_grants"], [])
        self.assertEqual(result["installed_changes"], [])
        data["bootstrap_status"] = "Different bounded proposal."
        self.assertNotEqual(result["candidate_sha256"], na.preview(data)["candidate_sha256"])

    def test_activation_generation_grants_and_self_enrollment_reject(self):
        mutations = [("state", "ADMITTED"), ("generation", "g1"), ("automatic_native_main", True),
                     ("operation_grants", [{"purpose": "review-auth"}]), ("registry", "/tmp/registry"),
                     ("schema", True), ("activation_profile", "automatic")]
        for key, value in mutations:
            with self.subTest(field=key):
                data = proposal(); data[key] = value
                with self.assertRaises(ValueError): na.preview(data)
        for changes in ({"admitted": True}, {"role": "main"}, {"registry_path": "/tmp/registry"}):
            data = proposal(); data["proposed_roles"][0].update(changes)
            with self.assertRaises(ValueError): na.preview(data)

    def test_native_claims_do_not_become_strong_proof(self):
        for key, value in (("individual_message_time", "2099-01-01"),
                           ("native_human_origin_attestation", "model-claimed"), ("evidence_only", False)):
            data = proposal(); data["user_source_evidence"][key] = value
            with self.assertRaises(ValueError): na.preview(data)
        data = proposal(); data["proposed_roles"] *= 2
        with self.assertRaises(ValueError): na.preview(data)
        data = proposal(); data["bootstrap_status"] = "password=" + "fixture-value"
        with self.assertRaises(ValueError): na.preview(data)

    def test_cli_preview_is_only_operation_and_cannot_read_a_registry(self):
        with tempfile.TemporaryDirectory() as home:
            env = dict(os.environ, HOME=home)
            good = subprocess.run([sys.executable, str(HOOKS / "native_admission.py"), "preview"],
                                  input=json.dumps(proposal()), text=True, capture_output=True, env=env, timeout=5)
            self.assertEqual(good.returncode, 0, good.stderr)
            self.assertEqual(json.loads(good.stdout)["installed_changes"], [])
            for operation in ("apply", "enroll", "activate"):
                bad = subprocess.run([sys.executable, str(HOOKS / "native_admission.py"), operation],
                                     input=json.dumps(proposal()), text=True, capture_output=True, env=env, timeout=5)
                self.assertNotEqual(bad.returncode, 0)
            # File/registry options do not exist; symlinks and writable registries
            # cannot be loaded as admission policy by this stdin-only preview.
            link = Path(home) / "registry"; link.symlink_to("missing")
            bad = subprocess.run([sys.executable, str(HOOKS / "native_admission.py"), "preview", "--registry", str(link)],
                                 input="{}", text=True, capture_output=True, env=env, timeout=5)
            self.assertNotEqual(bad.returncode, 0)
            # macOS creates ~/Library for any process using CoreFoundation; nothing else may appear.
            self.assertEqual([p for p in Path(home).iterdir() if p.name != "Library"], [link])


if __name__ == "__main__": unittest.main()
