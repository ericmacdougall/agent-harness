"""Check focus proof against literal logs derived from the pinned test declarations."""

import json
import runpy
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent
VERIFY = runpy.run_path(str(ROOT / "verify-focused.py"))["verify"]
LOGS = json.loads((ROOT / "focused-log-fixtures.json").read_text())


class FocusedProofTests(unittest.TestCase):
    def test_accepts_all_eight_literal_fixture_groups(self):
        totals = {
            "tracker": 2, "sse": 1, "websocket": 1, "compaction": 1,
            "app-server": 8, "schema-export-0": 1, "schema-export-1": 1, "schema-verify": 4,
        }
        self.assertEqual(set(LOGS), set(totals))
        for group, total in totals.items():
            with self.subTest(group=group):
                self.assertEqual(VERIFY(group, LOGS[group]), total)

    def test_rejects_zero_tests(self):
        with self.assertRaises(ValueError):
            VERIFY("sse", "running 0 tests\ntest result: ok. 0 passed; 0 failed;\n")

    def test_rejects_an_unrelated_pass_with_the_right_count(self):
        with self.assertRaises(ValueError):
            VERIFY("sse", "test unrelated_response_parser ... ok\ntest result: ok. 1 passed; 0 failed;\n")

    def test_rejects_a_missing_required_name_even_with_the_right_summary(self):
        log = LOGS["schema-verify"].replace(
            "test schema_fixtures_tests::json_schema_fixtures_match_generated ... ok\n", ""
        )
        self.assertNotEqual(log, LOGS["schema-verify"])
        with self.assertRaises(ValueError):
            VERIFY("schema-verify", log)

    def test_rejects_a_duplicate_instead_of_another_required_name(self):
        log = LOGS["tracker"].replace(
            "response_model_observation_is_consumed_by_its_terminal_event",
            "response_model_observation_requires_bound_unambiguous_provider_metadata",
        )
        self.assertNotEqual(log, LOGS["tracker"])
        with self.assertRaises(ValueError):
            VERIFY("tracker", log)

    def test_rejects_an_incorrect_pass_count_even_with_the_right_name(self):
        log = LOGS["sse"].replace("ok. 1 passed; ", "ok. 2 passed; ")
        self.assertNotEqual(log, LOGS["sse"])
        with self.assertRaises(ValueError):
            VERIFY("sse", log)


if __name__ == "__main__":
    unittest.main()
