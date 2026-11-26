"""GoodQA #15565: install.py renders CLAUDE.md from HARNESS.md, so a stale number there silently reverted the user's owner cap.
HARNESS.md and codex/AGENTS.md must state the one owner cap, model_tiers.json caps.session_owner_agents (release 1001;
until then resource_limits.json max_live_owners)."""

import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class CapDocsAgree(unittest.TestCase):
    def cap(self):
        return json.loads((ROOT / "harness" / "hooks" / "model_tiers.json").read_text())["caps"]["session_owner_agents"]

    def test_the_users_cap_is_sixteen(self):
        self.assertEqual(self.cap(), 16)  # the user: "up to 16 live owners per session"

    def test_harness_md_states_the_policy_cap(self):
        text = (ROOT / "HARNESS.md").read_text()
        found = re.search(r"owner cap is (\d+) live owners", text)
        self.assertTrue(found, "HARNESS.md must state the owner cap")
        self.assertEqual(int(found.group(1)), self.cap())

    def test_codex_agents_states_the_policy_cap(self):
        text = (ROOT / "codex" / "AGENTS.md").read_text()
        found = re.search(r"owner cap \((\d+) live owners", text)
        self.assertTrue(found, "codex/AGENTS.md must state the owner cap")
        self.assertEqual(int(found.group(1)), self.cap())


if __name__ == "__main__":
    unittest.main()
