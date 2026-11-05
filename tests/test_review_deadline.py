"""The per-provider review deadline is configurable per rung (default 720 s, up to 1800 s on high, xhigh and max) and receipted."""
import copy
import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HOOKS = ROOT / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
sys.path.insert(0, str(ROOT))
import model_tiers as tiers  # noqa: E402
import peer_review  # noqa: E402


class Table(unittest.TestCase):
    def setUp(self):
        self.policy = tiers.load_policy()

    def with_section(self, section):
        policy = copy.deepcopy(self.policy)
        policy["review_deadlines"] = section
        return policy

    def test_the_default_is_720_everywhere_and_the_shipped_table_sets_no_longer_default(self):
        for rung in self.policy["rungs"]:
            for harness in ("claude", "openai"):
                got = tiers.review_deadline(self.policy, rung, harness)
                self.assertEqual((got["seconds"], got["source"]), (720, "default"), (rung, harness))
        self.assertEqual(tiers.DEFAULT_REVIEW_DEADLINE, 720)
        self.assertEqual(tiers.MAX_REVIEW_DEADLINE, 1800)

    def test_high_xhigh_and_max_rungs_allow_up_to_1800_and_the_others_stay_at_720(self):
        for rung, ceiling in (("R0", 720), ("R1", 720), ("R2", 1800), ("R3", 1800), ("R4", 1800)):
            self.assertEqual(self.policy["rungs"][rung]["effort"] in ("high", "xhigh", "max"), ceiling == 1800, rung)
            self.assertEqual(tiers.review_deadline(self.policy, rung, "openai")["ceiling"], ceiling, rung)

    def test_a_requested_deadline_within_the_ceiling_is_used_and_labelled(self):
        for rung in ("R2", "R3", "R4"):
            for seconds in (1, 720, 1500, 1800):
                got = tiers.review_deadline(self.policy, rung, "openai", seconds)
                self.assertEqual((got["seconds"], got["source"]), (seconds, "--timeout"), (rung, seconds))
        self.assertEqual(tiers.review_deadline(self.policy, "R1", "claude", 720)["seconds"], 720)

    def test_a_requested_deadline_over_the_rungs_ceiling_is_refused(self):
        for rung, seconds in (("R3", 1801), ("R4", 3600), ("R1", 721), ("R0", 1500)):
            with self.assertRaises(tiers.TierError, msg=(rung, seconds)) as raised:
                tiers.review_deadline(self.policy, rung, "openai", seconds)
            self.assertIn(str(tiers.review_deadline(self.policy, rung, "openai")["ceiling"]), str(raised.exception))

    def test_a_bad_requested_deadline_is_refused(self):
        for bad in (0, -5, True, "300", 1.5, 10 ** 9):
            with self.assertRaises(tiers.TierError, msg=repr(bad)):
                tiers.review_deadline(self.policy, "R3", "openai", bad)

    def test_the_tier_table_sets_a_default_per_rung_and_provider(self):
        policy = self.with_section({"seconds": {"R3": {"openai": 1500}, "R4": {"claude": 1800}}})
        tiers.validate(policy)
        self.assertEqual(tiers.review_deadline(policy, "R3", "openai"), {"seconds": 1500, "source": "tier table", "ceiling": 1800})
        self.assertEqual(tiers.review_deadline(policy, "R3", "claude")["seconds"], 720)
        self.assertEqual(tiers.review_deadline(policy, "R4", "claude")["seconds"], 1800)
        self.assertEqual(tiers.review_deadline(policy, "R3", "openai", 900)["seconds"], 900)  # the request wins

    def test_the_table_can_move_the_default_but_never_past_a_ceiling(self):
        tiers.validate(self.with_section({"default_seconds": 900}))
        policy = self.with_section({"default_seconds": 900})
        self.assertEqual(tiers.review_deadline(policy, "R3", "openai")["seconds"], 900)
        self.assertEqual(tiers.review_deadline(policy, "R1", "openai")["seconds"], 720)  # clipped by the rung's own ceiling

    def test_malformed_sections_are_rejected_when_the_table_loads(self):
        bad_sections = [
            [], "x", {"unknown_key": 1}, {"default_seconds": 0}, {"default_seconds": 1801}, {"default_seconds": True},
            {"seconds": []}, {"seconds": {"R9": {"openai": 100}}}, {"seconds": {"R3": {"gemini": 100}}},
            {"seconds": {"R3": {"openai": 0}}}, {"seconds": {"R3": {"openai": 1801}}}, {"seconds": {"R3": {"openai": "9"}}},
            {"seconds": {"R1": {"openai": 900}}},          # over the medium rung's 720 ceiling
            {"ceiling_seconds_by_effort": {"turbo": 900}}, {"ceiling_seconds_by_effort": {"high": 1801}},
        ]
        for section in bad_sections:
            with self.assertRaises(tiers.TierError, msg=repr(section)):
                tiers.validate(self.with_section(section))


class Plan(unittest.TestCase):
    def setUp(self):
        self.policy = tiers.load_policy()
        self.selection = tiers.reviewer_for(self.policy, "R2", "claude", {"openai": True, "claude": True})

    def test_both_planned_providers_get_a_deadline_and_a_failover_run_only_the_one_it_launches(self):
        planned = peer_review.review_deadlines(self.policy, self.selection, 1500, no_fallback=False)
        self.assertEqual(sorted(planned), ["claude", "codex"])
        self.assertEqual({p["seconds"] for p in planned.values()}, {1500})
        failover = dict(self.selection, harness="claude")
        only = peer_review.review_deadlines(self.policy, failover, None, no_fallback=True)
        self.assertEqual(list(only), ["claude"])
        self.assertEqual(only["claude"]["source"], "default")

    def test_the_run_budget_grows_with_the_deadlines_and_never_shrinks_below_1440(self):
        def budget(seconds, count):
            return peer_review.review_budget({("codex", "claude")[i]: {"seconds": seconds} for i in range(count)})
        self.assertEqual((budget(720, 2), budget(720, 1)), (1440, 1440))
        self.assertEqual((budget(1800, 2), budget(1800, 1)), (3600, 1800))
        self.assertEqual(budget(100, 2), 1440)

    def test_a_provider_never_runs_past_its_deadline_or_the_time_left(self):
        options = {"deadlines": {"codex": {"seconds": 1500}, "claude": {"seconds": 400}}}
        self.assertEqual(peer_review.provider_deadline(options, "codex", 3000), 1500)
        self.assertEqual(peer_review.provider_deadline(options, "codex", 100), 100)
        self.assertEqual(peer_review.provider_deadline(options, "claude", 3000), 400)
        self.assertEqual(peer_review.provider_deadline({}, "codex", 5000), 720)  # direct callers keep the old default
        self.assertEqual(peer_review.provider_deadline({"timeout": 60}, "codex", 5000), 60)

    def test_the_header_line_names_each_provider_its_seconds_and_where_the_value_came_from(self):
        line = peer_review.deadline_line({"codex": {"seconds": 1500, "source": "--timeout", "ceiling": 1800},
                                          "claude": {"seconds": 720, "source": "default", "ceiling": 1800}})
        self.assertEqual(line, "Review-Deadline: codex 1500 s (--timeout, ceiling 1800 s); claude 720 s (default, ceiling 1800 s)\n")
        self.assertEqual(peer_review.deadline_line({}), "")


import tests.test_peer_review as _base  # noqa: E402


class EndToEnd(unittest.TestCase):
    """Drive peer_review.py with the fake providers: the receipt shows the deadline that was used."""
    fake = _base.PeerReviewTests.fake
    evidence = staticmethod(_base.PeerReviewTests.evidence)

    def setUp(self):
        _base.PeerReviewTests.setUp(self)
        self.ladder = self.root / "ladder"
        self.ladder.mkdir(mode=0o700)
        self.launches = self.root / "launches.log"
        body = f'''import os, sys
from pathlib import Path
with open({str(self.launches)!r}, 'a') as stream: stream.write(os.path.basename(sys.argv[0]) + '\\n')
text = 'CODE_INSPECTION_RESULT: ACCEPT\\nReviewed.'
if '--output-last-message' in sys.argv:
    Path(sys.argv[sys.argv.index('--output-last-message') + 1]).write_text(text)
else:
    print(text)
'''
        self.fake("codex", body)
        self.fake("claude", body)
        self.tools = self.root / "tools"
        self.tools.mkdir(mode=0o700)
        for name in ("git", "python3", "sh", "env", "cat", "mkdir", "rm", "cp", "mv", "ln", "ls", "chmod", "sed", "grep", "awk",
                     "tr", "sort", "head", "tail", "wc", "date", "sleep", "dirname", "basename", "uname", "mktemp", "readlink",
                     "true", "false", "find", "xargs", "diff", "tar"):
            found = shutil.which(name, path="/usr/bin:/bin:/usr/local/bin")
            if found:
                (self.tools / name).symlink_to(found)

    def review(self, *extra):
        return _base.PeerReviewTests.invoke(self, stage="code-inspection", extra=list(extra), env={
            "AGENT_HARNESS_ESCALATION_DIR": str(self.ladder), "PATH": str(self.bin) + os.pathsep + str(self.tools)})

    def launched(self):
        return self.launches.read_text().split() if self.launches.exists() else []

    def receipt(self):
        return json.loads(next((self.ladder / "selections").glob("*.json")).read_text())

    def test_the_default_run_records_720_for_both_providers(self):
        result = self.review("--task", "dl-1", "--author-rung", "R2", "--author-harness", "claude")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Review-Deadline: codex 720 s (default, ceiling 1800 s); claude 720 s (default, ceiling 1800 s)\n",
                      self.output.read_text())
        self.assertEqual({k: v["seconds"] for k, v in self.receipt()["deadlines"].items()}, {"codex": 720, "claude": 720})

    def test_a_longer_deadline_on_a_high_rung_is_used_and_receipted(self):
        result = self.review("--task", "dl-2", "--author-rung", "R2", "--author-harness", "claude", "--timeout", "1500")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Review-Deadline: codex 1500 s (--timeout, ceiling 1800 s)", self.output.read_text())
        self.assertEqual(self.receipt()["deadlines"]["codex"], {"seconds": 1500, "source": "--timeout", "ceiling": 1800})

    def run_records(self):
        runs = self.root / "usage-state" / "runs"
        (directory,) = list(runs.iterdir())
        return json.loads((directory / "start.json").read_text()), json.loads((directory / "final.json").read_text())

    def test_the_run_budget_and_the_final_usage_carry_the_deadlines(self):
        result = self.review("--task", "dl-5", "--author-rung", "R2", "--author-harness", "claude", "--timeout", "1800")
        self.assertEqual(result.returncode, 0, result.stderr)
        start, final = self.run_records()
        self.assertEqual((start["timeout"], start["aggregate_timeout"]), (3600, 7200))  # two providers at 1800 s each
        self.assertEqual({k: v["seconds"] for k, v in final["usage"]["deadlines"].items()}, {"codex": 1800, "claude": 1800})

    def test_the_default_run_keeps_the_historical_budget(self):
        result = self.review("--task", "dl-6", "--author-rung", "R2", "--author-harness", "claude")
        self.assertEqual(result.returncode, 0, result.stderr)
        start, final = self.run_records()
        self.assertEqual((start["timeout"], start["aggregate_timeout"]), (1440, 2880))
        self.assertEqual({k: v["seconds"] for k, v in final["usage"]["deadlines"].items()}, {"codex": 720, "claude": 720})

    def test_a_longer_deadline_on_a_medium_rung_is_refused_before_anything_launches(self):
        result = self.review("--task", "dl-3", "--author-rung", "R0", "--author-harness", "claude", "--timeout", "1500")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("720", result.stderr)
        self.assertEqual(self.launched(), [])
        self.assertFalse(self.output.exists())

    def test_nothing_above_1800_is_ever_accepted(self):
        for value in ("1801", "86400", "0", "-3", "x"):
            result = self.review("--task", "dl-4", "--author-rung", "R3", "--author-harness", "claude", "--timeout", value)
            self.assertEqual(result.returncode, 2, (value, result.stderr))
        self.assertEqual(self.launched(), [])


if __name__ == "__main__":
    unittest.main()
