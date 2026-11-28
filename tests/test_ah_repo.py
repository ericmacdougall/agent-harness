"""ah_repo: the merge rule as a GitHub ruleset and the `harness/review` status (docs/merge-rule.md).

Every test uses a fake `gh` runner that records each argv and answers with canned JSON; nothing reaches GitHub.
"""
from __future__ import annotations

import contextlib
import copy
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

HOOKS = Path(__file__).resolve().parents[1] / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
import ah_repo  # noqa: E402

SHA = "a" * 40
OTHER_SHA = "b" * 40
AGENT_VARS = ("CLAUDECODE", "CODEX_THREAD_ID", "CODEX_TOOL_CALL_ID", "CODEX_SANDBOX", "AI_AGENT")

EXPECTED_BODY = {
    "name": "harness-merge-rule", "target": "branch", "enforcement": "active",
    "conditions": {"ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []}},
    "bypass_actors": [],
    "rules": [
        {"type": "pull_request", "parameters": {
            "required_approving_review_count": 0, "dismiss_stale_reviews_on_push": False,
            "require_code_owner_review": False, "require_last_push_approval": False,
            "required_review_thread_resolution": False}},
        {"type": "non_fast_forward"},
        {"type": "deletion"},
        {"type": "required_status_checks", "parameters": {
            "strict_required_status_checks_policy": False,
            "required_status_checks": [{"context": "harness/review"}]}}]}


def as_github_returns(body, ruleset_id):
    """What GitHub answers for a ruleset: our fields plus the ones it adds."""
    value = copy.deepcopy(body)
    value.update(id=ruleset_id, source_type="Repository", source="o/r", node_id="RRS_x",
                 created_at="2026-11-25T00:00:00Z", updated_at="2026-11-25T00:00:00Z", current_user_can_bypass="never")
    for rule in value["rules"]:
        if rule["type"] == "pull_request":
            rule["parameters"]["allowed_merge_methods"] = ["merge", "squash", "rebase"]
            rule["parameters"]["automatic_copilot_code_review_enabled"] = False
        if rule["type"] == "required_status_checks":
            rule["parameters"]["do_not_enforce_on_create"] = False
            for check in rule["parameters"]["required_status_checks"]:
                check["integration_id"] = None
    return value


class FakeGh:
    """A `gh` stand-in: (args, timeout, cwd=None, stdin=None) -> (code, stdout, stderr), recording every call."""

    def __init__(self):
        self.calls = []
        self.routes = {}
        self.rulesets = {}
        self.statuses = []
        self.admin = True
        self.private = True
        self.write_error = None
        self.readback_override = None
        self.status_override = None
        self.pr_value = {"number": 5, "url": "https://github.com/o/r/pull/5", "headRefOid": SHA, "state": "OPEN"}

    @staticmethod
    def method_and_path(args):
        method = args[args.index("-X") + 1] if "-X" in args else "GET"
        path = next(a for a in args if a.startswith("repos/"))
        return method, path

    def writes(self):
        return [c for c in self.calls if c["args"][:1] == ["api"] and self.method_and_path(c["args"])[0] != "GET"]

    def __call__(self, args, timeout, cwd=None, stdin=None):
        args = list(args)
        self.calls.append({"args": args, "stdin": stdin, "timeout": timeout})
        if args[:2] == ["pr", "view"]:
            return 0, json.dumps(self.pr_value), ""
        if args[:1] != ["api"]:
            return 1, "", "unexpected gh call"
        method, path = self.method_and_path(args)
        body = json.loads(stdin) if stdin else None
        base = path.split("?")[0]
        if (method, base) in self.routes:
            return self.routes[(method, base)]
        if method == "GET" and base == "repos/o/r":
            return 0, json.dumps({"full_name": "o/r", "default_branch": "main", "private": self.private,
                                  "visibility": "private" if self.private else "public",
                                  "permissions": {"admin": self.admin, "push": True, "pull": True}}), ""
        if method == "GET" and base == "repos/o/r/rulesets":
            return 0, json.dumps([{"id": i, "name": r["name"], "source_type": "Repository", "source": "o/r",
                                   "enforcement": r["enforcement"]} for i, r in sorted(self.rulesets.items())]), ""
        if method in ("POST", "PUT") and base.startswith("repos/o/r/rulesets"):
            if self.write_error:
                return self.write_error
            ruleset_id = int(base.rsplit("/", 1)[1]) if method == "PUT" else 900 + len(self.rulesets)
            if method == "PUT" and ruleset_id not in self.rulesets:
                return 1, json.dumps({"message": "Not Found"}), "gh: Not Found (HTTP 404)"
            self.rulesets[ruleset_id] = body
            return 0, json.dumps(as_github_returns(body, ruleset_id)), ""
        if method == "GET" and base.startswith("repos/o/r/rulesets/"):
            ruleset_id = int(base.rsplit("/", 1)[1])
            if self.readback_override is not None:
                return 0, json.dumps(self.readback_override), ""
            if ruleset_id not in self.rulesets:
                return 1, json.dumps({"message": "Not Found"}), "gh: Not Found (HTTP 404)"
            return 0, json.dumps(as_github_returns(self.rulesets[ruleset_id], ruleset_id)), ""
        if method == "POST" and base.startswith("repos/o/r/statuses/"):
            if self.write_error:
                return self.write_error
            entry = dict(body, id=7000 + len(self.statuses), created_at="2026-11-25T00:00:0%dZ" % len(self.statuses),
                         sha=base.rsplit("/", 1)[1])
            entry.setdefault("target_url", None)
            self.statuses.insert(0, entry)
            return 0, json.dumps(entry), ""
        if method == "GET" and base.startswith("repos/o/r/commits/") and base.endswith("/statuses"):
            if self.status_override is not None:
                return 0, json.dumps(self.status_override), ""
            sha = base.split("/")[4]
            return 0, json.dumps([s for s in self.statuses if s["sha"] == sha]), ""
        return 1, json.dumps({"message": "Not Found"}), "gh: Not Found (HTTP 404)"


def run_main(argv, gh, function=None):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = (function or ah_repo.main)(argv, runner=gh)
        except SystemExit as stop:  # argparse's own usage errors
            code = stop.code
    return code, out.getvalue(), err.getvalue()


class RulesetBodyTests(unittest.TestCase):
    def test_body_equals_the_documented_rule(self):
        self.assertEqual(ah_repo.ruleset_body(), EXPECTED_BODY)

    def test_check_adds_contexts_after_the_review_status_once_each(self):
        body = ah_repo.ruleset_body(checks=["ci/test", "harness/review", "ci/test", "lint"])
        contexts = body["rules"][3]["parameters"]["required_status_checks"]
        self.assertEqual(contexts, [{"context": "harness/review"}, {"context": "ci/test"}, {"context": "lint"}])

    def test_admin_bypass_is_off_by_default_and_pull_request_only_when_asked(self):
        self.assertEqual(ah_repo.ruleset_body()["bypass_actors"], [])
        self.assertEqual(ah_repo.ruleset_body(admin_bypass=True)["bypass_actors"],
                         [{"actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "pull_request"}])

    def test_a_bad_check_name_is_refused(self):
        for name in ("", " ", "x" * 300, "a\nb"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                ah_repo.ruleset_body(checks=[name])


class ProtectTests(unittest.TestCase):
    def setUp(self):
        self.gh = FakeGh()

    def test_creates_the_ruleset_when_absent_and_reads_it_back(self):
        code, out, err = run_main(["protect", "o/r"], self.gh)
        self.assertEqual(code, 0, err)
        posts = [c for c in self.gh.writes() if c["args"][c["args"].index("-X") + 1] == "POST"]
        self.assertEqual(len(posts), 1)
        self.assertEqual(FakeGh.method_and_path(posts[0]["args"]), ("POST", "repos/o/r/rulesets"))
        self.assertEqual(json.loads(posts[0]["stdin"]), EXPECTED_BODY)
        self.assertIn("protected o/r: pr, no-force-push, no-delete, status harness/review (ruleset 900)", out)
        gets = [FakeGh.method_and_path(c["args"]) for c in self.gh.calls]
        self.assertEqual(gets[-1], ("GET", "repos/o/r/rulesets/900"))  # read back after the write

    def test_updates_in_place_when_present_and_keeps_the_id(self):
        self.gh.rulesets[42] = dict(EXPECTED_BODY, enforcement="disabled")
        self.gh.rulesets[7] = {"name": "someone-elses", "enforcement": "active", "rules": []}
        code, out, err = run_main(["protect", "o/r", "--check", "ci/test"], self.gh)
        self.assertEqual(code, 0, err)
        writes = self.gh.writes()
        self.assertEqual([FakeGh.method_and_path(c["args"]) for c in writes], [("PUT", "repos/o/r/rulesets/42")])
        sent = json.loads(writes[0]["stdin"])
        self.assertEqual(sent["enforcement"], "active")
        self.assertEqual(sent["rules"][3]["parameters"]["required_status_checks"],
                         [{"context": "harness/review"}, {"context": "ci/test"}])
        self.assertEqual(self.gh.rulesets[7]["name"], "someone-elses")  # another ruleset is never touched
        self.assertIn("status harness/review, ci/test (ruleset 42)", out)

    def test_running_twice_is_idempotent(self):
        self.assertEqual(run_main(["protect", "o/r"], self.gh)[0], 0)
        self.assertEqual(run_main(["protect", "o/r"], self.gh)[0], 0)
        self.assertEqual(sorted(self.gh.rulesets), [900])

    def test_readback_mismatch_raises_and_exits_one(self):
        wrong = as_github_returns(EXPECTED_BODY, 900)
        wrong["rules"] = [r for r in wrong["rules"] if r["type"] != "deletion"]
        self.gh.readback_override = wrong
        with self.assertRaises(ah_repo.GitHubError) as caught:
            ah_repo.protect("o/r", runner=self.gh)
        self.assertIn("deletion", str(caught.exception))
        code, out, err = run_main(["protect", "o/r"], self.gh)
        self.assertEqual(code, 1)
        self.assertIn("not protected", err)
        self.assertNotIn("protected o/r:", out)

    def test_readback_with_a_changed_parameter_or_enforcement_is_a_mismatch(self):
        for change in ("enforcement", "approvals", "status", "bypass", "extra-rule", "branch"):
            with self.subTest(change=change):
                gh = FakeGh()
                wrong = as_github_returns(EXPECTED_BODY, 900)
                if change == "enforcement":
                    wrong["enforcement"] = "evaluate"
                elif change == "approvals":
                    wrong["rules"][0]["parameters"]["required_approving_review_count"] = 1
                elif change == "status":
                    wrong["rules"][3]["parameters"]["required_status_checks"] = [{"context": "harness/reviewx"}]
                elif change == "bypass":
                    wrong["bypass_actors"] = [{"actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "always"}]
                elif change == "extra-rule":
                    wrong["rules"].append({"type": "required_signatures"})
                else:
                    wrong["conditions"]["ref_name"]["include"] = ["refs/heads/other"]
                gh.readback_override = wrong
                self.assertEqual(run_main(["protect", "o/r"], gh)[0], 1)

    def test_plan_refusal_on_a_private_repository_is_not_protected_with_exit_three(self):
        message = "Upgrade to GitHub Pro or make this repository public to enable this feature."
        self.gh.write_error = (1, json.dumps({"message": message, "status": "403"}), "gh: %s (HTTP 403)" % message)
        code, out, err = run_main(["protect", "o/r"], self.gh)
        self.assertEqual(code, 3)
        self.assertIn("not protected: " + message, err)
        self.assertNotIn("protected o/r", out)

    def test_another_403_is_a_plain_failure(self):
        self.gh.write_error = (1, json.dumps({"message": "Resource not accessible by integration"}),
                               "gh: Resource not accessible by integration (HTTP 403)")
        code, _, err = run_main(["protect", "o/r"], self.gh)
        self.assertEqual(code, 1)
        self.assertIn("not protected", err)

    def test_without_admin_permission_nothing_is_written(self):
        self.gh.admin = False
        code, _, err = run_main(["protect", "o/r"], self.gh)
        self.assertEqual(code, 1)
        self.assertIn("admin", err)
        self.assertEqual(self.gh.writes(), [])

    def test_dry_run_prints_the_body_and_calls_nothing(self):
        code, out, err = run_main(["protect", "o/r", "--dry-run", "--check", "ci"], self.gh)
        self.assertEqual(code, 0, err)
        self.assertEqual(self.gh.calls, [])
        printed = json.loads(out)
        self.assertEqual(printed["rules"][3]["parameters"]["required_status_checks"],
                         [{"context": "harness/review"}, {"context": "ci"}])

    def test_malformed_slugs_are_refused_before_any_call(self):
        for slug in ("o", "o/r/x", "../r", "o/..", "-o/r", "o/r?x", "o r/x", "", "o/.", "https://github.com/o/r"):
            with self.subTest(slug=slug):
                gh = FakeGh()
                code, _, err = run_main(["protect", slug], gh)
                self.assertEqual(code, 2, err)
                self.assertEqual(gh.calls, [])

    def test_status_reads_only(self):
        self.assertEqual(run_main(["protect", "o/r"], self.gh)[0], 0)
        before = len(self.gh.writes())
        code, out, err = run_main(["status", "o/r"], self.gh)
        self.assertEqual(code, 0, err)
        self.assertEqual(len(self.gh.writes()), before)
        self.assertIn("protected o/r: pr, no-force-push, no-delete, status harness/review (ruleset 900)", out)

    def test_status_without_the_ruleset_says_not_protected(self):
        code, out, err = run_main(["status", "o/r"], self.gh)
        self.assertEqual(code, 1)
        self.assertIn("not protected", err)
        self.assertEqual(self.gh.writes(), [])

    def test_status_reports_a_drifted_ruleset(self):
        self.gh.rulesets[3] = dict(EXPECTED_BODY, enforcement="disabled")
        code, _, err = run_main(["status", "o/r"], self.gh)
        self.assertEqual(code, 1)
        self.assertIn("enforcement", err)

    def test_json_output(self):
        code, out, _ = run_main(["status", "o/r", "--json"], self.gh)
        self.assertEqual(code, 1)
        value = json.loads(out)
        self.assertEqual((value["repo"], value["protected"]), ("o/r", False))
        run_main(["protect", "o/r"], self.gh)
        code, out, _ = run_main(["status", "o/r", "--json"], self.gh)
        value = json.loads(out)
        self.assertEqual((code, value["protected"], value["ruleset"]), (0, True, 900))


AGENT_ENV_NAMES = AGENT_VARS + ("CLAUDE_CODE_SESSION_ID", "CLAUDE_SESSION_ID", "AH_ROLE")


class PostReviewStatusTests(unittest.TestCase):
    def setUp(self):
        self.gh = FakeGh()
        patcher = mock.patch.dict(os.environ, {k: v for k, v in os.environ.items() if k not in AGENT_ENV_NAMES},
                                  clear=True)   # the owner's terminal, whatever session runs the suite
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_an_agent_cannot_post_a_passing_review_from_the_command_line(self):
        """The release 1001 red team: any agent could post success with one advertised command. The runner posts
        in-process; failure and pending stay open to agents (they unlock nothing)."""
        for name, value in (("CLAUDECODE", "1"), ("CODEX_THREAD_ID", "t"), ("AH_ROLE", "worker"),
                            ("CLAUDE_CODE_SESSION_ID", "11111111-2222-3333-4444-555555555555")):
            with self.subTest(name=name), mock.patch.dict(os.environ, {name: value}):
                code, _, err = run_main(["post", "--repo", "o/r", "--sha", SHA, "--state", "success",
                                         "--description", "PASS"], self.gh, ah_repo.review_status_main)
                self.assertEqual(code, 2)
                self.assertIn("peer_review.py pr", err)
        self.assertEqual(self.gh.calls, [])
        with mock.patch.dict(os.environ, {"CLAUDECODE": "1"}):
            code, _, err = run_main(["post", "--repo", "o/r", "--sha", SHA, "--state", "failure", "--description",
                                     "BLOCK"], self.gh, ah_repo.review_status_main)
        self.assertEqual(code, 0, err)
        code, _, err = run_main(["post", "--repo", "o/r", "--sha", SHA, "--state", "success", "--description",
                                 "PASS"], self.gh, ah_repo.review_status_main)
        self.assertEqual(code, 0, err)   # the owner's own terminal

    def test_posts_the_harness_review_context_for_the_exact_sha_and_reads_it_back(self):
        entry = ah_repo.post_review_status("o/r", SHA, "success", "PASS by Codex; receipt " + "e" * 32,
                                           target_url="https://example.invalid/r", runner=self.gh)
        post = self.gh.writes()[0]
        self.assertEqual(FakeGh.method_and_path(post["args"]), ("POST", "repos/o/r/statuses/" + SHA))
        sent = json.loads(post["stdin"])
        self.assertEqual(sent, {"state": "success", "context": "harness/review",
                                "description": "PASS by Codex; receipt " + "e" * 32,
                                "target_url": "https://example.invalid/r"})
        self.assertEqual(FakeGh.method_and_path(self.gh.calls[-1]["args"])[1].split("?")[0],
                         "repos/o/r/commits/%s/statuses" % SHA)
        self.assertEqual((entry["state"], entry["context"]), ("success", "harness/review"))

    def test_refuses_a_sha_that_is_not_forty_lowercase_hex(self):
        for sha in ("a" * 39, "a" * 41, "a" * 64, "g" * 40, "A" * 40, "", "HEAD", "a" * 40 + "\n"):
            with self.subTest(sha=sha), self.assertRaises(ValueError):
                ah_repo.post_review_status("o/r", sha, "success", "x", runner=self.gh)
        self.assertEqual(self.gh.calls, [])

    def test_refuses_a_malformed_slug_state_or_url(self):
        bad = (("o/r/x", "success", None), ("../r", "success", None), ("o/r", "passed", None),
               ("o/r", "success", "http://plain.example"), ("o/r", "success", "javascript:x"))
        for repo, state, url in bad:
            with self.subTest(repo=repo, state=state, url=url), self.assertRaises(ValueError):
                ah_repo.post_review_status(repo, SHA, state, "x", target_url=url, runner=self.gh)
        self.assertEqual(self.gh.calls, [])

    def test_long_description_is_cut_to_githubs_limit_before_sending(self):
        entry = ah_repo.post_review_status("o/r", SHA, "failure", "x" * 500, runner=self.gh)
        sent = json.loads(self.gh.writes()[0]["stdin"])
        self.assertLessEqual(len(sent["description"]), 140)
        self.assertEqual(entry["description"], sent["description"])

    def test_readback_that_differs_raises(self):
        for label, override in (
                ("no entry", []),
                ("other state", [{"id": 1, "context": "harness/review", "state": "failure", "description": "d",
                                  "sha": SHA, "target_url": None}]),
                ("other description", [{"id": 1, "context": "harness/review", "state": "success",
                                        "description": "something else", "sha": SHA, "target_url": None}]),
                ("only another context", [{"id": 1, "context": "ci/test", "state": "success", "description": "d",
                                           "sha": SHA, "target_url": None}])):
            with self.subTest(label):
                gh = FakeGh()
                gh.status_override = override
                with self.assertRaises(ah_repo.GitHubError):
                    ah_repo.post_review_status("o/r", SHA, "success", "d", runner=gh)

    def test_a_newer_status_from_someone_else_is_a_mismatch(self):
        newer = {"id": 99999, "context": "harness/review", "state": "failure", "description": "d", "sha": SHA,
                 "target_url": None}
        self.gh.statuses.insert(0, newer)
        original = self.gh.__call__

        def racing(args, timeout, cwd=None, stdin=None):
            result = original(args, timeout, cwd, stdin)
            if stdin:  # right after our post, another writer posts a newer status
                self.gh.statuses.insert(0, dict(newer, id=100000))
            return result
        with self.assertRaises(ah_repo.GitHubError):
            ah_repo.post_review_status("o/r", SHA, "success", "d", runner=racing)

    def test_a_failed_post_raises(self):
        self.gh.write_error = (1, json.dumps({"message": "No commit found for SHA"}), "gh: No commit (HTTP 422)")
        with self.assertRaises(ah_repo.GitHubError):
            ah_repo.post_review_status("o/r", SHA, "success", "d", runner=self.gh)

    def test_the_command_line_post_and_show(self):
        code, out, err = run_main(["post", "--repo", "o/r", "--sha", SHA, "--state", "failure", "--description",
                                   "BLOCK by Claude"], self.gh, ah_repo.review_status_main)
        self.assertEqual(code, 0, err)
        self.assertIn("harness/review failure", out)
        code, out, err = run_main(["show", "--repo", "o/r", "--sha", SHA], self.gh, ah_repo.review_status_main)
        self.assertEqual(code, 0, err)
        self.assertIn("failure", out)
        self.assertIn("BLOCK by Claude", out)
        code, out, _ = run_main(["show", "--repo", "o/r", "--sha", OTHER_SHA], self.gh, ah_repo.review_status_main)
        self.assertEqual(code, 1)
        self.assertIn("no harness/review status", out)

    def test_the_command_line_reports_a_readback_mismatch(self):
        self.gh.status_override = []
        code, _, err = run_main(["post", "--repo", "o/r", "--sha", SHA, "--state", "success", "--description", "d"],
                                self.gh, ah_repo.review_status_main)
        self.assertEqual(code, 1)
        self.assertIn("read back", err)

    def test_a_bad_sha_on_the_command_line_exits_two(self):
        code, _, _ = run_main(["post", "--repo", "o/r", "--sha", "abc", "--state", "success", "--description", "d"],
                              self.gh, ah_repo.review_status_main)
        self.assertEqual(code, 2)
        self.assertEqual(self.gh.calls, [])


class OwnerOverrideTests(unittest.TestCase):
    def setUp(self):
        self.gh = FakeGh()
        self.home = tempfile.mkdtemp(prefix="ah-repo-home-")
        self.addCleanup(lambda: __import__("shutil").rmtree(self.home, ignore_errors=True))
        clean = {k: v for k, v in os.environ.items() if k not in AGENT_ENV_NAMES}
        clean.update(HOME=self.home, AH_HOME=self.home)
        patcher = mock.patch.dict(os.environ, clean, clear=True)
        patcher.start()
        self.addCleanup(patcher.stop)
        import ah_approvals
        self.approvals = ah_approvals

    def override(self, approval, *extra):
        return run_main(["post", "--repo", "o/r", "--sha", SHA, "--state", "success", "--description",
                         "owner merges after the block", "--owner-override", "--approval", approval, "--pr", "5",
                         *extra], self.gh, ah_repo.review_status_main)

    def test_refused_inside_an_agent_even_with_a_live_approval(self):
        record = self.approvals.grant("merge", {"project": "o/r", "pr": "5"}, "user", "ok", home=self.home)
        for marker in AGENT_VARS:
            with self.subTest(marker=marker), mock.patch.dict(os.environ, {marker: "1"}):
                code, _, err = self.override(record["id"])
                self.assertEqual(code, 2)
                self.assertIn("outside an agent", err)
        self.assertEqual(self.gh.calls, [])

    def test_refused_without_a_live_merge_approval_for_that_pull_request(self):
        code, _, err = self.override("deadbeef")
        self.assertEqual(code, 2)
        self.assertIn("ah approve merge --project o/r --pr 5", err)
        other = self.approvals.grant("merge", {"project": "o/r", "pr": "6"}, "user", "other pr", home=self.home)
        self.assertEqual(self.override(other["id"])[0], 2)
        revoked = self.approvals.grant("merge", {"project": "o/r", "pr": "5"}, "user", "then revoked", home=self.home)
        self.approvals.revoke(revoked["id"], "user", home=self.home)
        self.assertEqual(self.override(revoked["id"])[0], 2)
        kind = self.approvals.grant("delete", {"project": "o/r", "pr": "5"}, "user", "wrong kind", home=self.home)
        self.assertEqual(self.override(kind["id"])[0], 2)
        self.assertEqual(self.gh.calls, [])

    def test_override_needs_its_approval_and_pr(self):
        code, _, _ = run_main(["post", "--repo", "o/r", "--sha", SHA, "--state", "success", "--description", "d",
                               "--owner-override"], self.gh, ah_repo.review_status_main)
        self.assertEqual(code, 2)
        self.assertEqual(self.gh.calls, [])

    def test_with_the_approval_the_description_names_it(self):
        record = self.approvals.grant("merge", {"project": "o/r", "pr": "5"}, "user", "ship it", home=self.home)
        code, out, err = self.override(record["id"])
        self.assertEqual(code, 0, err)
        sent = json.loads(self.gh.writes()[0]["stdin"])
        self.assertIn("approval " + record["id"], sent["description"])
        self.assertTrue(sent["description"].startswith("owner override"))
        self.assertEqual(sent["state"], "success")


class PrHeadTests(unittest.TestCase):
    def test_returns_repo_pr_head_and_state(self):
        gh = FakeGh()
        value = ah_repo.pr_head("o/r", 5, runner=gh)
        self.assertEqual(value, {"repo": "o/r", "pr": 5, "head": SHA, "state": "OPEN"})
        self.assertEqual(gh.calls[0]["args"], ["pr", "view", "5", "-R", "o/r", "--json", "number,url,headRefOid,state"])

    def test_repo_names_compare_ascii_case_insensitive_only(self):
        gh = FakeGh()
        gh.pr_value["url"] = "https://github.com/O/R/pull/5"
        self.assertEqual(ah_repo.pr_head("o/R", 5, runner=gh)["repo"], "o/r")

    def test_identity_mismatches_raise(self):
        for change in ({"number": 6}, {"url": "https://github.com/o/other/pull/5"},
                       {"url": "https://github.com/o/r/pull/6"}, {"url": "https://github.com.evil/o/r/pull/5"},
                       {"url": "http://github.com/o/r/pull/5"}, {"url": "https://github.com/o/r/pull/5/"},
                       {"headRefOid": "zz"}, {"number": "5"}, {"url": None}):
            with self.subTest(change=change):
                gh = FakeGh()
                gh.pr_value.update(change)
                with self.assertRaises(ah_repo.GitHubError):
                    ah_repo.pr_head("o/r", 5, runner=gh)

    def test_gh_failure_and_bad_input_raise(self):
        failing = lambda args, timeout, cwd=None, stdin=None: (1, "", "gh: not logged in")  # noqa: E731
        with self.assertRaises(ah_repo.GitHubError):
            ah_repo.pr_head("o/r", 5, runner=failing)
        not_json = lambda args, timeout, cwd=None, stdin=None: (0, "nope", "")  # noqa: E731
        with self.assertRaises(ah_repo.GitHubError):
            ah_repo.pr_head("o/r", 5, runner=not_json)
        for repo, number in (("o/r/x", 5), ("o/r", 0), ("o/r", True), ("o/r", "5")):
            with self.subTest(repo=repo, number=number), self.assertRaises(ValueError):
                ah_repo.pr_head(repo, number, runner=FakeGh())


class SubprocessRunnerTests(unittest.TestCase):
    def test_the_default_runner_never_raises_and_disables_prompts(self):
        seen = {}

        def fake_run(argv, **kwargs):
            seen.update(argv=argv, env=kwargs["env"], input=kwargs.get("input"))
            return mock.Mock(returncode=0, stdout="{}", stderr="")
        with mock.patch.object(ah_repo.subprocess, "run", fake_run):
            self.assertEqual(ah_repo.gh_runner(["api", "x"], 5, stdin="{}"), (0, "{}", ""))
        self.assertEqual(seen["argv"][0], "gh")
        self.assertEqual(seen["env"]["GH_PROMPT_DISABLED"], "1")
        self.assertEqual(seen["input"], "{}")
        with mock.patch.object(ah_repo.subprocess, "run", side_effect=FileNotFoundError("gh")):
            code, _, err = ah_repo.gh_runner(["api", "x"], 5)
        self.assertNotEqual(code, 0)
        self.assertIn("gh", err)


if __name__ == "__main__":
    unittest.main()
