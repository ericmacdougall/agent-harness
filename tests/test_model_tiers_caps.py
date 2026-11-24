"""The repo model_tiers.json owner caps match the user's decision and the installed copy (GoodQA #15585).

The user raised the owner cap from 4 to 8 ("up owner slots to 8", main WAL decision wd89d1d837e0); main
changed the installed ~/.claude/hooks/model_tiers.json, and the repo copy must carry the same values so the
next install does not silently lower the cap again.
"""
import json
import os
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1] / "harness" / "hooks" / "model_tiers.json"
INSTALLED = Path(os.environ.get("HARNESS_INSTALLED_TIERS", str(Path.home() / ".claude" / "hooks" / "model_tiers.json")))
CAP_KEYS = ("session_owner_agents", "session_live_agents")


def caps(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))["caps"]


class ModelTiersCapsTest(unittest.TestCase):
    def test_repo_caps_are_the_user_decision(self):
        repo = caps(REPO)
        self.assertEqual(repo["session_owner_agents"], 8)
        self.assertEqual(repo["session_live_agents"], 16)
        self.assertGreater(repo["session_live_agents"], repo["session_owner_agents"],
                           "helpers must still fit beside a full owner set")

    def test_repo_and_installed_caps_agree(self):
        if not INSTALLED.is_file():
            self.skipTest(f"no installed harness at {INSTALLED} (CI host)")
        repo, installed = caps(REPO), caps(INSTALLED)
        for key in CAP_KEYS:
            self.assertEqual(repo[key], installed[key],
                             f"{key}: repo {repo[key]} != installed {installed[key]}; reinstall or commit the change")


if __name__ == "__main__":
    unittest.main()
