"""Fresh, independently bound PR PASS evidence is a one-shot merge authorization."""
import json
import os
import shlex
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
from pathlib import Path
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
HOOKS = ROOT / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
sys.path.insert(0, str(HERE))
import merge_gate as mg  # noqa: E402
import peer_review as review  # noqa: E402
import usage_guard as guard  # noqa: E402
import test_merge_gate as fixture  # noqa: E402

HEAD = "a" * 40
OTHER = "b" * 40
REPORT_SHA = "c" * 64
FINAL_SHA = "d" * 64


class FakePr:
    def __init__(self, value=None, rc=0):
        self.value = value if value is not None else {
            "number": 5, "url": "https://github.com/o/r/pull/5", "headRefOid": HEAD, "state": "OPEN"}
        self.rc = rc

    def __call__(self, args, timeout, cwd=None):
        self.args = list(args)
        if self.rc:
            return self.rc, "", "fixture lookup failed"
        return 0, json.dumps(self.value), ""


class BindingTests(unittest.TestCase):
    def test_verified_binding_requires_exact_repo_pr_head_and_open_state(self):
        bound = review.verify_pr_binding("o/r", 5, HEAD, runner=FakePr())
        self.assertEqual(bound, {"repo": "o/r", "pr": 5})
        cases = (
            {"number": 6},
            {"url": "https://github.com/o/other/pull/5"},
            {"url": "https://github.com/o/r/pull/6"},
            {"headRefOid": OTHER},
            {"headRefOid": HEAD.upper()},
            {"state": "MERGED"},
            {"state": "CLOSED"},
        )
        for changed in cases:
            with self.subTest(changed=changed):
                value = {"number": 5, "url": "https://github.com/o/r/pull/5", "headRefOid": HEAD, "state": "OPEN"}
                value.update(changed)
                with self.assertRaises(OSError):
                    review.verify_pr_binding("o/r", 5, HEAD, runner=FakePr(value))
        with self.assertRaises(OSError):
            review.verify_pr_binding("o/r", 5, HEAD, runner=FakePr(rc=1))

    # GoodQA #15565: GitHub owner/repo names are ASCII and case-insensitive; the binding must match them that way
    # and only that way (no Unicode folding, no prefix/suffix, github.com only).
    REPO = "ericmacdougall/android-security"
    PR_URL = "https://github.com/ericmacdougall/Android-security/pull/768"

    def bind(self, expected, url, number=768, head=HEAD, **changes):
        value = {"number": 768, "url": url, "headRefOid": HEAD, "state": "OPEN"}
        value.update(changes)
        return review.verify_pr_binding(expected, number, head, runner=FakePr(value))

    def test_repo_case_differences_bind_to_the_same_repository(self):
        accepted = (
            (self.REPO, self.PR_URL),                                              # ParentProof PR 768
            ("ericmacdougall/Android-security", "https://github.com/ericmacdougall/android-security/pull/768"),
            ("EricMacDougall/ANDROID-SECURITY", "https://github.com/ericmacdougall/Android-Security/pull/768"),
            (self.REPO, "https://github.com/ERICMACDOUGALL/ANDROID-SECURITY/pull/768"),
        )
        for expected, url in accepted:
            with self.subTest(expected=expected, url=url):
                self.assertEqual(self.bind(expected, url), {"repo": self.REPO, "pr": 768})

    def test_case_insensitive_repo_match_keeps_every_other_check_strict(self):
        rejected = (
            ("different repo suffix", self.REPO, "https://github.com/ericmacdougall/Android-security2/pull/768", {}),
            ("homoglyph digit", self.REPO, "https://github.com/ericmacdougall/Android-secur1ty/pull/768", {}),
            ("fork-like suffix", self.REPO,
             "https://github.com/ericmacdougall/android-security-fork/pull/768", {}),
            ("other owner", self.REPO, "https://github.com/someoneelse/Android-security/pull/768", {}),
            ("owner prefix", self.REPO, "https://github.com/ericmacdougall2/Android-security/pull/768", {}),
            ("url pr number", self.REPO, "https://github.com/ericmacdougall/Android-security/pull/769", {}),
            ("json pr number", self.REPO, self.PR_URL, {"number": 769}),
            ("head", self.REPO, self.PR_URL, {"headRefOid": OTHER}),
            ("closed", self.REPO, self.PR_URL, {"state": "CLOSED"}),
            ("merged", self.REPO, self.PR_URL, {"state": "MERGED"}),
            ("lookalike host suffix", self.REPO,
             "https://github.com.evil.example/ericmacdougall/Android-security/pull/768", {}),
            ("lookalike host typo", self.REPO, "https://githuh.com/ericmacdougall/Android-security/pull/768", {}),
            ("uppercase host", self.REPO, "https://GITHUB.com/ericmacdougall/Android-security/pull/768", {}),
            ("plain http", self.REPO, "http://github.com/ericmacdougall/Android-security/pull/768", {}),
            ("userinfo host", self.REPO,
             "https://github.com@evil.example/ericmacdougall/Android-security/pull/768", {}),
            ("trailing path", self.REPO, self.PR_URL + "/files", {}),
            ("trailing slash", self.REPO, self.PR_URL + "/", {}),
            ("trailing newline", self.REPO, self.PR_URL + "\n", {}),
            ("query", self.REPO, self.PR_URL + "?x=1", {}),
            ("nested path", self.REPO,
             "https://github.com/ericmacdougall/Android-security/x/pull/768", {}),
            ("unicode digits in number", self.REPO,
             "https://github.com/ericmacdougall/Android-security/pull/٧٦٨", {}),
            # Unicode case rules must never widen equality: str.lower() maps KELVIN SIGN to "k",
            # str.casefold() maps SHARP S to "ss"; dotless/dotted Turkish i must not become "i".
            ("kelvin sign", "o/k", "https://github.com/o/K/pull/768", {}),
            ("kelvin owner", "k/r", "https://github.com/K/r/pull/768", {}),
            ("sharp s", "o/strasse", "https://github.com/o/straße/pull/768", {}),
            ("dotless i", "o/ripo", "https://github.com/o/rıpo/pull/768", {}),
            ("dotted capital I", "o/ripo", "https://github.com/o/RİPO/pull/768", {}),
            ("long s", "o/sec", "https://github.com/o/ſec/pull/768", {}),
        )
        for label, expected, url, changes in rejected:
            with self.subTest(label):
                with self.assertRaises(OSError):
                    self.bind(expected, url, **changes)
        for label, expected in (("expected kelvin", "o/K"), ("expected sharp s", "o/straße"),
                                ("expected path", "o/r/x"), ("expected url", "https://github.com/o/r")):
            with self.subTest(label):
                with self.assertRaises(OSError):
                    self.bind(expected, "https://github.com/o/r/pull/768")
        with self.subTest("requested head differs"), self.assertRaises(OSError):
            self.bind(self.REPO, self.PR_URL, head=OTHER)
        with self.subTest("requested number differs"), self.assertRaises(OSError):
            self.bind(self.REPO, self.PR_URL, number=769)

    def test_only_pure_cross_harness_pr_pass_is_eligible(self):
        args = SimpleNamespace(stage="pr", author_harness="claude", main_stamp={"purpose": "review-auth"})
        binding = {"repo": "o/r", "pr": 5}
        selection = {"harness": "openai"}
        self.assertTrue(review.review_merge_eligible(args, binding, "VERDICT: PASS\nReviewed", selection))
        unstamped = SimpleNamespace(stage="pr", author_harness="claude", main_stamp=None)  # #134 red-team B2
        self.assertFalse(review.review_merge_eligible(unstamped, binding, "VERDICT: PASS\nReviewed", selection))
        negatives = (
            ("pr", "claude", binding, "VERDICT: BLOCK\nF1: defect", selection),
            ("pr", "claude", binding, "VERDICT: PASS-WITH-TICKETS\nF1: ticketed", selection),
            ("pr", "claude", binding, "VERDICT: PASS\nF1: unresolved finding", selection),
            ("pr", "unknown", binding, "VERDICT: PASS", selection),
            ("pr", "claude", binding, "VERDICT: PASS", {"harness": "claude"}),
            ("pr", "claude", None, "VERDICT: PASS", selection),
            ("code-inspection", "claude", binding, "CODE_INSPECTION_RESULT: ACCEPT", selection),
            ("pr", "claude", binding, "KIMI_ADVISORY: ACCEPT\nVERDICT: PASS", selection),
        )
        for stage, author, bound, report, selected in negatives:
            with self.subTest(stage=stage, author=author, bound=bound, report=report, selected=selected):
                local = SimpleNamespace(stage=stage, author_harness=author, main_stamp={"purpose": "review-auth"})
                self.assertFalse(review.review_merge_eligible(local, bound, report, selected))


class AuthorizationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.state = self.root / "state"
        self.counter = 0
        self.default_evidence = None

    def evidence(self, review_changes=None, *, result="CHECK_OK", reason="NONE", settle=True, typed=True):
        self.counter += 1
        root = self.root / ("evidence-" + str(self.counter))
        repo = root / "repo"
        repo.mkdir(parents=True)
        store = guard.UsageStore(root / "usage")
        subject = guard.Subject(schema=1, fingerprint="e" * 64, reusable=True, head=HEAD, tree="f" * 40)
        subject.repo, subject.manifest = repo, {}
        subject.probe = lambda: subject
        invocation = guard.invocation_identity(
            subject, purpose="peer-review-pr", argv=["peer_review", "pr", str(self.counter)],
            cwd=repo, stage="PR", provider="codex")
        run = store.begin(subject, invocation, owner="fixture", label="peer-review-pr",
                          timeout=10, kind="review", minimum_bytes=0)
        metadata = {"stage": "PR", "verdict": "ACCEPT", "findings": [], "repo": "o/r", "pr": 5,
                    "head": HEAD, "report_sha256": REPORT_SHA, "reviewer": "Codex fixture",
                    "reviewer_harness": "openai", "author_harness": "claude"}
        metadata.update(review_changes or {})
        reference = run.finish(execution="COMPLETED", result=result, reason=reason, exit_code=0,
                               review=metadata if typed else None,
                               usage={"provider_launches": 1, "reported": [], "executables": {}})
        if settle:
            store.settle_review(reference)
        return store, reference

    def authorize(self, **changes):
        if not changes:
            if self.default_evidence is None:
                self.default_evidence = self.evidence()
            store, reference = self.default_evidence
        else:
            store, reference = self.evidence(**changes)
        return mg.add_review_waiver(self.state, reference, store=store)

    def decide(self, scenario="red_netwatch", command=None):
        gh = fixture.FakeGh(fixture.SCENARIOS[scenario])
        command = command or "gh pr merge 5 --match-head-commit " + HEAD
        return mg.decide(fixture.bash(command), gh, self.state)

    def test_pass_authorization_covers_unreadable_protection_without_waive_command(self):
        waiver = self.authorize()
        self.assertEqual((waiver["repo"], waiver["pr"], waiver["head"], waiver["report_sha256"]),
                         ("o/r", 5, HEAD, REPORT_SHA))
        self.assertEqual(mg.decide(fixture.bash("gh pr merge 5 --match-head-commit " + HEAD),
                                   fixture.FakeGh(fixture.SCENARIOS["green_protection_unreadable"]),
                                   self.root / "none")[0], 2, "control: blocked without the authorization")
        code, text = self.decide("green_protection_unreadable")
        self.assertEqual(code, 0, text)
        code, text = self.decide("green_protection_unreadable")
        self.assertEqual(code, 2, "the same PASS authorization must not replay: " + text)

    def test_pass_authorization_never_passes_failing_pending_or_missing_checks(self):
        # #134 red-team P1 and B1: a review covers soft reasons, never CI that failed, has not finished or never ran
        self.authorize()
        for scenario in ("red_netwatch", "pending_run", "queued_run", "status_pending", "required_missing",
                         "zero_unprotected_workflows"):
            with self.subTest(scenario=scenario):
                code, text = self.decide(scenario)
                self.assertEqual(code, 2, text)
        self.assertEqual(self.decide("green_protection_unreadable")[0], 0,
                         "the refused merges must not have used the authorization")

    def test_wrong_head_repo_pr_and_reviewer_binding_are_refused(self):
        with self.assertRaises(ValueError):
            self.authorize(review_changes={"head": OTHER})  # FINAL subject still names HEAD
        for changes in ({"repo": "o/other"}, {"pr": 6}):
            with self.subTest(changes=changes):
                self.state = self.root / (list(changes)[0])
                self.authorize(review_changes=changes)
                self.assertEqual(self.decide()[0], 2)
        for changes in ({"author_harness": "openai"}, {"reviewer_harness": "unknown"},
                        {"reviewer": "Claude fixture"}):
            with self.subTest(changes=changes):
                with self.assertRaises(ValueError):
                    self.authorize(review_changes=changes)

    def test_replayed_evidence_does_not_mint_a_second_authorization(self):
        first = self.authorize()
        second = self.authorize()
        self.assertEqual(first["id"], second["id"])
        records = mg._read_waivers(self.state)
        self.assertEqual(sum(row.get("event") == "waive" for row in records), 1)
        self.assertEqual(self.decide("green_protection_unreadable")[0], 0)
        self.assertEqual(self.decide("green_protection_unreadable")[0], 2)

    def test_arbitrary_hashes_cannot_forge_review_approval(self):
        with self.assertRaises(TypeError):
            mg.add_review_waiver(self.state, "o/r", 5, HEAD, REPORT_SHA, FINAL_SHA, "Codex fixture")
        store, _ = self.evidence()
        forged = {"run_id": "0" * 32, "record": "final", "sha256": FINAL_SHA}
        with self.assertRaises(guard.GuardError):
            mg.add_review_waiver(self.state, forged, store=store)
        store, reference = self.evidence()
        with self.assertRaises(TypeError):
            mg.add_review_waiver(self.state, reference, store=store, repo="o/other")

    def test_block_advisory_and_unsettled_evidence_cannot_authorize(self):
        with self.assertRaises(ValueError):
            self.authorize(review_changes={"verdict": "BLOCK", "findings": ["F1"]},
                           result="CHECK_FAILED", reason="CODE_FINDINGS")
        with self.assertRaises(ValueError):
            self.authorize(result="NO_RESULT", reason="ADVISORY", settle=False, typed=False)
        with self.assertRaises(ValueError):
            self.authorize(settle=False)

    def test_existing_ticket_waiver_validation_is_unchanged(self):
        with self.assertRaises(ValueError):
            mg.add_waiver(self.state, "o/r", 5, HEAD, "peer-review: forged", "reason is long enough",
                          "main:fixture")


class EndToEndTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        subprocess.run(["git", "init", "-q", "-b", "main", str(self.repo)], check=True)
        subprocess.run(["git", "-C", str(self.repo), "config", "user.name", "Fixture"], check=True)
        subprocess.run(["git", "-C", str(self.repo), "config", "user.email", "fixture@example.invalid"], check=True)
        (self.repo / "app.txt").write_text("baseline\n")
        subprocess.run(["git", "-C", str(self.repo), "add", "app.txt"], check=True)
        subprocess.run(["git", "-C", str(self.repo), "commit", "-qm", "baseline"], check=True)
        subprocess.run(["git", "-C", str(self.repo), "update-ref", "refs/remotes/origin/main", "HEAD"], check=True)
        (self.repo / "app.txt").write_text("change\n")
        subprocess.run(["git", "-C", str(self.repo), "commit", "-qam", "feat: change\n\nRefs: none (fixture)\n\n"
                        "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"], check=True)
        self.head = subprocess.check_output(["git", "-C", str(self.repo), "rev-parse", "HEAD"], text=True).strip()
        self.packet = self.root / "packet.md"
        self.packet.write_text("Scope and evidence.\nReviewed HEAD " + self.head +
                               "\n$ python3 -m unittest discover tests\nRan 1 test in 0.1s\nOK\nexit 0\n")
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.fake("codex", "import sys\nfrom pathlib import Path\nsys.stdin.read()\n"
                           "Path(sys.argv[sys.argv.index('--output-last-message') + 1]).write_text('VERDICT: PASS\\nReviewed.')\n")
        self.fake("claude", "import sys\nsys.stdin.read()\nprint('VERDICT: PASS\\nReviewed.')\n")
        value = {"number": 5, "url": "https://github.com/o/r/pull/5", "headRefOid": self.head, "state": "OPEN"}
        self.fake("gh", "import json\nprint(json.dumps(" + repr(value) + "))\n")

    def fake(self, name, body):
        path = self.bin / name
        # A managed Python path can contain spaces, which a shebang cannot quote.
        path.write_text("#!/bin/sh\nexec " + shlex.quote(sys.executable) + " -c " + shlex.quote(body) + ' "$@"\n')
        path.chmod(0o700)

    def test_review_pass_then_merge_without_separate_waive(self):
        import caller_identity
        caller_identity.put_stamp("review-auth", ["o/r", 5], home=self.root)  # what main's hook writes
        output = self.root / "review.md"
        env = dict(os.environ, HOME=str(self.root), PATH=str(self.bin) + os.pathsep + "/usr/bin:/bin",
                   AGENT_HARNESS_USAGE_DIR=str(self.root / "usage"),
                   AGENT_HARNESS_REVIEW_POLICY=str(ROOT / "harness" / "hooks" / "review_policy.json"))
        result = subprocess.run([
            sys.executable, str(HOOKS / "peer_review.py"), "pr", "--repo", str(self.repo),
            "--packet", str(self.packet), "--output", str(output), "--expected-head", self.head,
            "--github-repo", "o/r", "--pr", "5", "--author-harness", "claude"],
            text=True, capture_output=True, env=env, timeout=45)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("Merge authorization:", result.stdout)
        state = self.root / ".agent-harness" / "state"
        records = mg._read_waivers(state)
        waiver = next(row for row in records if row.get("event") == "waive")
        report = output.read_text()
        self.assertIn("Reviewed repository: o/r", report)
        self.assertIn("Reviewed PR: 5", report)
        self.assertEqual(waiver["repo"], "o/r")
        self.assertEqual(waiver["pr"], 5)
        self.assertEqual(waiver["head"], self.head)
        self.assertEqual(waiver["approval_source"], "settled-review")
        final = json.loads(next((self.root / "usage" / "runs").glob("*/final.json")).read_text())
        self.assertEqual(final["review"]["report_sha256"], waiver["report_sha256"])
        self.assertEqual(final["review"]["repo"], "o/r")
        self.assertEqual(final["review"]["pr"], 5)
        self.assertEqual(final["review"]["head"], self.head)
        original_head = fixture.HEAD
        fixture.HEAD = self.head
        try:
            code, text = mg.decide(fixture.bash("gh pr merge 5 --match-head-commit " + self.head),
                                   fixture.FakeGh(fixture.SCENARIOS["green_protection_unreadable"]), state)
            self.assertEqual(code, 0, text)
            code, text = mg.decide(fixture.bash("gh pr merge 5 --match-head-commit " + self.head),
                                   fixture.FakeGh(fixture.SCENARIOS["green_protection_unreadable"]), state)
            self.assertEqual(code, 2, text)
        finally:
            fixture.HEAD = original_head

    def test_unstamped_review_mints_nothing(self):
        # #134 red-team B2: a run no main hook saw (copied script, script file, sub-agent) gets no stamp
        output = self.root / "unstamped.md"
        env = dict(os.environ, HOME=str(self.root), PATH=str(self.bin) + os.pathsep + "/usr/bin:/bin",
                   AGENT_HARNESS_USAGE_DIR=str(self.root / "usage"),
                   AGENT_HARNESS_REVIEW_POLICY=str(ROOT / "harness" / "hooks" / "review_policy.json"))
        result = subprocess.run([
            sys.executable, str(HOOKS / "peer_review.py"), "pr", "--repo", str(self.repo),
            "--packet", str(self.packet), "--output", str(output), "--expected-head", self.head,
            "--github-repo", "o/r", "--pr", "5", "--author-harness", "claude"],
            text=True, capture_output=True, env=env, timeout=45)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("Merge authorization:", result.stdout)
        self.assertIn("no main-agent stamp", result.stderr)

    def test_same_harness_fallback_does_not_inherit_primary_eligibility(self):
        self.fake("codex", "import sys\nsys.stdin.read()\n"
                           "sys.stderr.write('HARNESS_PROVIDER_UNAVAILABLE')\nsys.exit(127)\n")
        output = self.root / "fallback-review.md"
        env = dict(os.environ, HOME=str(self.root), PATH=str(self.bin) + os.pathsep + "/usr/bin:/bin",
                   AGENT_HARNESS_USAGE_DIR=str(self.root / "usage"),
                   AGENT_HARNESS_REVIEW_POLICY=str(ROOT / "harness" / "hooks" / "review_policy.json"))
        result = subprocess.run([
            sys.executable, str(HOOKS / "peer_review.py"), "pr", "--repo", str(self.repo),
            "--packet", str(self.packet), "--output", str(output), "--expected-head", self.head,
            "--github-repo", "o/r", "--pr", "5", "--author-harness", "claude"],
            text=True, capture_output=True, env=env, timeout=45)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("Reviewer: Claude", output.read_text())
        self.assertNotIn("Merge authorization:", result.stdout)
        self.assertFalse((self.root / ".agent-harness" / "state").exists())


    def run_review(self, *extra):
        output = self.root / "probe-review.md"
        env = dict(os.environ, HOME=str(self.root), PATH=str(self.bin) + os.pathsep + "/usr/bin:/bin",
                   AGENT_HARNESS_USAGE_DIR=str(self.root / "usage"),
                   AGENT_HARNESS_REVIEW_POLICY=str(ROOT / "harness" / "hooks" / "review_policy.json"))
        return subprocess.run([
            sys.executable, str(HOOKS / "peer_review.py"), "pr", "--repo", str(self.repo),
            "--packet", str(self.packet), "--output", str(output), "--expected-head", self.head,
            "--github-repo", "o/r", "--pr", "5", *extra], text=True, capture_output=True, env=env, timeout=45)

    def test_declared_author_harness_that_contradicts_the_commits_is_refused(self):
        # #134 red-team P1: a Claude-authored change declared as openai would get a Claude reviewer
        self.fake("claude", "import sys\nsys.exit(99)\n")
        result = self.run_review("--author-harness", "openai")
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("co-authored by claude", result.stderr)
        self.assertNotIn("Merge authorization:", result.stdout)

    def test_commits_without_author_evidence_cannot_authorize(self):
        subprocess.run(["git", "-C", str(self.repo), "commit", "-q", "--allow-empty", "-m",
                        "chore: no trailer\n\nRefs: none (fixture)"], check=True)
        self.head = subprocess.check_output(["git", "-C", str(self.repo), "rev-parse", "HEAD"], text=True).strip()
        self.packet.write_text("Scope and evidence.\nReviewed HEAD " + self.head +
                               "\n$ python3 -m unittest discover tests\nRan 1 test in 0.1s\nOK\nexit 0\n")
        value = {"number": 5, "url": "https://github.com/o/r/pull/5", "headRefOid": self.head, "state": "OPEN"}
        self.fake("gh", "import json\nprint(json.dumps(" + repr(value) + "))\n")
        result = self.run_review("--author-harness", "claude")
        self.assertNotIn("Merge authorization:", result.stdout, result.stdout + result.stderr)
        self.assertIn("do not prove the author harness", result.stderr)


class SubagentAuthorization(unittest.TestCase):
    """#134 red-team P2: a subagent cannot mint a merge authorization."""

    def test_subagent_pr_review_with_a_github_binding_is_blocked(self):
        with tempfile.TemporaryDirectory() as d:
            for cmd in ("python3 /x/.claude/hooks/peer_review.py pr --repo /w --packet /p --output /o "
                        "--expected-head " + "a" * 40 + " --github-repo o/r --pr 5",
                        "python3 ~/.claude/hooks/peer_review.py pr --repo /w --pr 5 --packet /p --output /o"):
                payload = dict(fixture.bash(cmd), agent_id="sub1")
                code, text = mg.decide(payload, fixture.FakeGh(fixture.SCENARIOS["red_netwatch"]), Path(d))
                self.assertEqual(code, 2, cmd)
                self.assertIn("subagent cannot run the PR review", text)

    def test_options_before_the_stage_are_matched_too(self):
        # #134 red-team B2
        with tempfile.TemporaryDirectory() as d:
            for cmd in ("python3 /x/.claude/hooks/peer_review.py --github-repo o/r --pr 5 pr --repo /w",
                        "python3 /x/.claude/hooks/peer_review.py --pr=5 --github-repo=o/r pr --repo /w"):
                payload = dict(fixture.bash(cmd), agent_id="sub1")
                code, _ = mg.decide(payload, fixture.FakeGh(fixture.SCENARIOS["red_netwatch"]), Path(d))
                self.assertEqual(code, 2, cmd)

    def test_only_a_proven_main_payload_gets_the_review_stamp(self):
        import caller_identity
        sid = "11111111-2222-3333-4444-555555555555"
        with tempfile.TemporaryDirectory() as home:
            transcript = Path(home) / ".claude" / "projects" / "-x" / (sid + ".jsonl")
            transcript.parent.mkdir(parents=True)
            transcript.write_text("{}\n")
            cmd = "python3 ~/.claude/hooks/peer_review.py pr --repo /w --github-repo o/r --pr 5 --packet /p"
            with mock.patch.dict(os.environ, {"HOME": home}):
                mg.decide(fixture.bash(cmd), fixture.FakeGh(fixture.SCENARIOS["green"]), Path(home) / "s")
                self.assertIsNone(caller_identity.take_stamp("review-auth", ["o/r", 5], home=home))  # no proof
                main = dict(fixture.bash(cmd), session_id=sid, transcript_path=str(transcript))
                mg.decide(main, fixture.FakeGh(fixture.SCENARIOS["green"]), Path(home) / "s")
                self.assertIsNotNone(caller_identity.take_stamp("review-auth", ["o/r", 5], home=home))

    def test_text_that_only_mentions_the_options_mints_no_stamp(self):
        # delta red-team D-F6
        import caller_identity
        sid = "11111111-2222-3333-4444-555555555555"
        with tempfile.TemporaryDirectory() as home:
            transcript = Path(home) / ".claude" / "projects" / "-x" / (sid + ".jsonl")
            transcript.parent.mkdir(parents=True)
            transcript.write_text("{}\n")
            for cmd in ("echo peer_review.py pr --github-repo o/r --pr 5",
                        "cat <<'EOF'\npython3 ~/.claude/hooks/peer_review.py pr --github-repo o/r --pr 5\nEOF",
                        "true; python3 ~/.claude/hooks/peer_review.py pr --github-repo o/r --pr 5",
                        "python3 ~/.claude/hooks/peer_review.py pr --github-repo o/r --pr 5 | tee /tmp/x",
                        "git log # peer_review --github-repo o/r --pr 5"):
                with self.subTest(cmd=cmd), mock.patch.dict(os.environ, {"HOME": home}):
                    main = dict(fixture.bash(cmd), session_id=sid, transcript_path=str(transcript))
                    mg.decide(main, fixture.FakeGh(fixture.SCENARIOS["green"]), Path(home) / "s")
                    self.assertIsNone(caller_identity.take_stamp("review-auth", ["o/r", 5], home=home))
            cmd = "python3 -I /x/.claude/hooks/peer_review.py pr --repo /w --github-repo o/r --pr 5 --packet /p"
            with mock.patch.dict(os.environ, {"HOME": home}):
                main = dict(fixture.bash(cmd), session_id=sid, transcript_path=str(transcript))
                mg.decide(main, fixture.FakeGh(fixture.SCENARIOS["green"]), Path(home) / "s")
                self.assertIsNotNone(caller_identity.take_stamp("review-auth", ["o/r", 5], home=home))

    def test_main_and_unbound_subagent_reviews_still_run(self):
        with tempfile.TemporaryDirectory() as d:
            bound = ("python3 /x/.claude/hooks/peer_review.py pr --repo /w --packet /p --output /o "
                     "--expected-head " + "a" * 40 + " --github-repo o/r --pr 5")
            self.assertEqual(mg.decide(fixture.bash(bound), fixture.FakeGh(fixture.SCENARIOS["red_netwatch"]),
                                       Path(d))[0], 0)
            unbound = dict(fixture.bash("python3 /x/.claude/hooks/peer_review.py pr --repo /w --packet /p "
                                        "--output /o --expected-head " + "a" * 40), agent_id="sub1")
            self.assertEqual(mg.decide(unbound, fixture.FakeGh(fixture.SCENARIOS["red_netwatch"]), Path(d))[0], 0)


if __name__ == "__main__":
    unittest.main()
