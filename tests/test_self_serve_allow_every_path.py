"""Allow every path: the fallback denylist is an optional policy scope, empty by default, with no built-in floor.

Source: answer:1471f671-0ed0-40c3-8506-255cb670e4de/44bc4b2f-436b-4711-a4d8-9d7bd7cf0a06 "Allow every path".
Replaces the FALLBACK_FLOOR guards of the earlier repair round (tests.test_self_serve_repair.FallbackFloor).
Run: python3 -m unittest tests.test_self_serve_allow_every_path   (from the repository root)
"""
import unittest

from tests.test_self_serve import ss
from tests.test_self_serve_repair import Repair


class FallbackAllowsEveryPath(Repair):
    CAP = "same_harness_fallback_review"
    ANY = ("harness/hooks/auth.py", "db/migrations/001.sql", "config/secrets.env", "harness/hooks/command_guard.py",
           "harness/hooks/merge_gate.py", "harness/hooks/self_serve.py", "keys/id.pem", ".env",
           ".github/workflows/ci.yml", "harness/hooks/peer_review.py", "docs/readme.md")

    def test_a_policy_with_no_denylist_grants_for_every_path(self):
        self.scoped({}, self.CAP)
        for path in self.ANY:
            self.assertIsNotNone(self.grant(self.CAP, evidence={"changed_paths": [path]}), repr(path))

    def test_changed_paths_are_not_required_without_a_denylist(self):
        self.scoped({}, self.CAP)
        for ev in (None, {}):
            self.assertIsNotNone(self.grant(self.CAP, evidence=ev), ev)

    def test_an_optional_denylist_still_refuses_and_then_needs_the_paths(self):
        self.scoped({"denylist_paths": ["*migrations/*"]}, self.CAP)
        self.assertEqual(self.why(self.CAP, evidence={"changed_paths": ["db/migrations/1.sql"]}), "path_denylisted")
        self.assertIsNotNone(self.grant(self.CAP, evidence={"changed_paths": ["harness/hooks/merge_gate.py"]}))
        for ev in (None, {}, {"changed_paths": []}, {"changed_paths": [1]}):
            self.assertIsNone(self.grant(self.CAP, evidence=ev), ev)

    def test_a_repo_narrowing_still_only_narrows(self):
        self.scoped({}, self.CAP)
        ev = {"changed_paths": ["db/migrations/1.sql"], "repo_narrowing": {"denylist_paths": ["*migrations/*"]}}
        self.assertEqual(self.why(self.CAP, evidence=ev), "path_denylisted")

    def test_no_built_in_floor_is_exported(self):
        self.assertFalse(hasattr(ss, "FALLBACK_FLOOR"))
        self.assertFalse(hasattr(ss, "fallback_path_denied"))

    def test_the_glob_helper_is_public_and_matches_the_policy_rule(self):
        self.assertTrue(ss.paths_denied(["./DB/Migrations/1.sql"], ["db/migrations/*"]))
        self.assertFalse(ss.paths_denied(["src/x.py"], ["db/migrations/*"]))
        self.assertFalse(ss.paths_denied(["src/x.py"], []))


if __name__ == "__main__":
    unittest.main()
