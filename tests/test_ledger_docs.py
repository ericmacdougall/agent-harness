"""The ledger docs must keep the promises the tests and the contract rely on (docs/ledger*.md)."""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CONTRACT = ROOT / "docs" / "ledger-goodqa-import-api.md"
LEDGER = ROOT / "docs" / "ledger.md"


class Contract(unittest.TestCase):
    def setUp(self):
        self.text = CONTRACT.read_text(encoding="utf-8")

    def test_required_sections_exist(self):
        for heading in ("Goals and non-goals", "Documents", "Endpoints", "Mapping", "Idempotency",
                        "Conflicts and resolutions", "Freeze and delta sync", "Redacted imports",
                        "Limits and errors", "Trust and privacy", "What GoodQA has to build"):
            self.assertRegex(self.text, rf"(?m)^## {re.escape(heading)}$", heading)

    def test_signed_receipt_format_is_specified(self):
        for needle in ("goodqa-ledger-receipt-signed/v1", "key_id", "base64url", "sort_keys=True", "ensure_ascii=True", "--goodqa-key",
                       "authenticated: true", "[A-Za-z0-9._:-]{1,64}"):
            self.assertIn(needle, self.text, needle)

    def test_it_says_plainly_that_the_server_side_is_not_built(self):
        self.assertRegex(self.text, r"(?i)\*\*Status: proposal")
        self.assertIn("not built", self.text)

    def test_conflict_policy_never_merges_silently_and_defaults_to_goodqa(self):
        self.assertIn("Nothing is merged silently", self.text)
        self.assertIn("GoodQA wins", self.text)
        self.assertIn("resolutions", self.text)

    def test_receipt_fields_match_what_bind_accepts(self):
        fields = ("format", "goodqa_project", "import_id", "ledger_project", "export_digest", "base_digest",
                  "redacted", "frontier", "tickets", "imported_at_ms")
        block = re.search(r"```json\n(.*?)```", self.text, re.S).group(1)
        for field in fields:
            self.assertIn(f'"{field}"', block, field)
        self.assertIn("advisory", self.text)


class LedgerDoc(unittest.TestCase):
    def setUp(self):
        self.text = " ".join(LEDGER.read_text(encoding="utf-8").split())  # line wraps do not matter

    def test_privacy_rule_and_bounds_are_stated(self):
        for needle in ("everyone who can read the remote", "cannot be undone", "16 MiB and 4096 commits",
                       "64 MiB total", "more than 128 is refused", "ordinary `git push` and `git fetch`",
                       "never forced", "A HOME copied", "not ledger-mcp tools"):
            self.assertIn(needle, self.text, needle)

    def test_it_no_longer_claims_the_ledger_never_travels(self):
        self.assertNotIn("travels with this machine only", self.text)
        self.assertNotIn("are later phases", self.text)

    def test_every_sync_state_is_documented(self):
        for state in ("none", "local-only", "pending", "synced", "diverged", "tracked"):
            self.assertRegex(self.text, rf"\| `{state}` \|", state)


if __name__ == "__main__":
    unittest.main()
