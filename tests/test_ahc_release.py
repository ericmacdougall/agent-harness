"""The checked-in harness/hooks/ahc_release.json matches the repo's ahc modules and legacy helpers.

The CI step that runs `scripts/ahc_release_hashes.py --check` is dormant while Actions are off, and the PR review
refuses a stale list only at the merge gate. This test makes a stale list fail in any focused or full local run, so
a change to ah.py, ops_watch.py or an ahc_*.py module cannot ship without `ahc_release_hashes.py --write`.
"""
import contextlib
import importlib.util
import io
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load_script():
    spec = importlib.util.spec_from_file_location("ahc_release_hashes_repo", str(ROOT / "scripts" / "ahc_release_hashes.py"))
    script = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(script)
    return script


class ReleaseListTests(unittest.TestCase):
    def test_checked_in_list_matches_the_repo(self):
        script = load_script()
        self.assertEqual(script.LIST, ROOT / "harness" / "hooks" / "ahc_release.json")
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            rc = script.main(["--check"])
        self.assertEqual(rc, 0, "ahc_release.json is stale; run `python3 scripts/ahc_release_hashes.py --write` "
                                "and commit it with the change: " + out.getvalue())

    def test_list_covers_the_helpers_this_stream_changes(self):
        # ah.py and ops_watch.py are legacy helpers bound by hash; a guard that silently dropped them would pass
        script = load_script()
        self.assertTrue({"ah", "ops_watch"} <= set(script.helpers()), sorted(script.helpers()))


if __name__ == "__main__":
    unittest.main()
