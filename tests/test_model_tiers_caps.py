"""One owner cap (the user: "fix the agent caps/threshold crap"): resource_limits.json max_live_owners is the only
number. model_tiers.json no longer carries session_owner_agents or session_live_agents; load_policy copies the one cap
into caps.session_owner_agents for older readers (successor.py)."""
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock
import sys

HOOKS = Path(__file__).resolve().parents[1] / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
import model_tiers  # noqa: E402
import resource_budget  # noqa: E402


class OneCap(unittest.TestCase):
    def test_tier_table_has_no_cap_numbers_of_its_own(self):
        caps = json.loads((HOOKS / "model_tiers.json").read_text(encoding="utf-8"))["caps"]
        self.assertNotIn("session_owner_agents", caps)
        self.assertNotIn("session_live_agents", caps)

    def test_policy_carries_the_one_cap_and_follows_a_local_change(self):
        home = tempfile.mkdtemp()
        with mock.patch.dict(os.environ, {"AH_HOME": home}):
            self.assertEqual(model_tiers.load_policy()["caps"]["session_owner_agents"], 16)
            resource_budget.set_limit("max_live_owners", 10, "user", "the owner tightened it")
            self.assertEqual(model_tiers.load_policy()["caps"]["session_owner_agents"], 10)
            self.assertEqual(resource_budget.owner_cap(), {"max": 10, "enforce": False})


if __name__ == "__main__":
    unittest.main()
