"""General-purpose domain checklists (auth, delete, money, devices, release) and file-name detection (goodqa#15253, B4.18)."""

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

HOOKS = Path(__file__).resolve().parents[1] / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
import domain_gates as dg  # noqa: E402
import provenance  # noqa: E402
import spec_flow as sf  # noqa: E402

NEW = {
    "auth": ["pre-account-hijack", "lookalike-identifier", "request-device-binding", "link-expiry-single-use",
             "session-fixation", "rate-limit-enumeration", "store-billing-exposure"],
    "delete": ["backup-before-delete", "unpushed-work-detection", "dry-run-diff", "scope-pinning",
               "cross-host-approval-portability", "idempotent-retry"],
    "money": ["idempotency-key", "double-submit", "currency-precision", "refund-reversal-path",
              "ledger-reconciliation", "authorization-vs-capture"],
    "devices": ["device-identity-binding", "unattended-recovery", "grant-durability", "remote-exec-audit",
                "factory-reset-guard"],
    "release": ["derived-gate-floor-with-ratchet", "artifact-inventory-mirrored", "self-update-e2e",
                "transport-proof", "rollback-not-blocked", "staging-exists"],
}


def make_repo(files):
    root = Path(tempfile.mkdtemp(prefix="dg-gen-"))
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    for name in files:
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("x\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(root), "add", "-A"], check=True)
    return root


def domains(root):
    return {d["domain"] for d in dg.detect(root)}


class Checklists(unittest.TestCase):
    def test_items_resolve_for_every_new_domain(self):
        for name, ids in NEW.items():
            got = [i["id"] for i in dg.checklist(name)]
            self.assertEqual(got, ids, name)
            for item in dg.checklist(name):
                self.assertNotIn("{", item["neg"], item["id"])
                self.assertTrue(item["verify"] and item["keywords"], item["id"])


class Detection(unittest.TestCase):
    def test_two_auth_paths_detect_auth_and_spec_has_hijack_item(self):
        root = make_repo(["src/auth/login.ts", "src/auth/session.ts"])
        self.assertIn("auth", domains(root))
        text = sf.append_domain_block("# Spec\n", root, {})
        self.assertIn("## Domain checklist", text)
        self.assertIn("pre-account-hijack", text)

    def test_single_doc_path_detects_nothing(self):
        self.assertEqual(domains(make_repo(["README-release.md"])), set())

    def test_single_source_path_outside_domain_dir_detects_nothing(self):
        self.assertEqual(domains(make_repo(["src/lib/token.ts"])), set())

    def test_single_path_under_exact_domain_directory_detects(self):
        self.assertIn("release", domains(make_repo(["release/notes.sh"])))

    def test_two_paths_per_domain(self):
        cases = {
            "delete": ["tools/purge_old.py", "tools/cleanup_cache.py"],
            "money": ["svc/stripe_client.py", "svc/refund.py"],
            "devices": ["app/adb_bridge.kt", "app/pairing.kt"],
            "release": ["ci/deploy.sh", "ci/rollback.sh"],
        }
        for name, files in cases.items():
            self.assertIn(name, domains(make_repo(files)), name)

    def test_docs_do_not_count_and_words_need_boundaries(self):
        self.assertEqual(domains(make_repo(["docs/release.md", "docs/deploy.md"])), set())
        self.assertEqual(domains(make_repo(["src/author.ts", "src/authority.ts"])), set())


if __name__ == "__main__":
    unittest.main()
