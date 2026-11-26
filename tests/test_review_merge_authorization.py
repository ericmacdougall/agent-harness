"""PR review receipts and the merge gate (2026-11-24 redesign): a settled PASS receipt that peer_review.py writes to
the usage store is the merge evidence; merge_gate reads it directly (no stamp, no waiver row, not single use).
The peer_review binding, eligibility and snapshot-base tests are unchanged."""
import json
import os
import shlex
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock
from pathlib import Path
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
HOOKS = ROOT / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
sys.path.insert(0, str(HERE))
import peer_review as review  # noqa: E402
import usage_guard as guard  # noqa: E402

HEAD = "a" * 40
OTHER = "b" * 40
REPORT_SHA = "c" * 64
FINAL_SHA = "d" * 64
MAIN_SID = "11111111-2222-4333-8444-555555555555"
MAIN_CALL = "toolu_01MAINREVIEWCALL0000000001"


def main_transcript(root):
    """Main's transcript under a temporary HOME: a real top-level Claude transcript, so is_main proves main."""
    transcript = Path(root) / ".claude" / "projects" / "-x" / (MAIN_SID + ".jsonl")
    transcript.parent.mkdir(parents=True, exist_ok=True)
    if not transcript.exists():
        transcript.write_text("{}\n")
    return transcript




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


class EvidenceFixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.state = self.root / "state"
        self.counter = 0
        self.default_evidence = None

    def evidence(self, review_changes=None, *, result="CHECK_OK", reason="NONE", settle=True, typed=True,
                 subject_head=HEAD, subject_tree="f" * 40):
        self.counter += 1
        root = self.root / ("evidence-" + str(self.counter))
        repo = root / "repo"
        repo.mkdir(parents=True)
        store = guard.UsageStore(root / "usage")
        subject = guard.Subject(schema=1, fingerprint="e" * 64, reusable=True, head=subject_head, tree=subject_tree)
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




class SnapshotBaseTests(EvidenceFixture):
    """B_r (goodqa#16049 spec ahc-m1-v2g, main's ruling option a): the PR FINAL may carry the reviewer's snapshot
    base; usage_guard validates it. BOUNDARY: main merges this."""

    BR = "9" * 40

    def meta(self, **changes):
        m = {"stage": "PR", "verdict": "ACCEPT", "findings": [], "repo": "o/r", "pr": 5, "head": HEAD,
             "report_sha256": REPORT_SHA, "reviewer": "Codex fixture", "reviewer_harness": "openai",
             "author_harness": "claude", "snapshot_base": self.BR}
        m.update(changes)
        return m

    def test_metadata_accepts_a_full_snapshot_base_and_legacy_receipts_without_one(self):
        guard.validate_review_metadata(self.meta(), result="CHECK_OK")
        legacy = self.meta()
        legacy.pop("snapshot_base")
        guard.validate_review_metadata(legacy, result="CHECK_OK")

    def test_metadata_refuses_a_malformed_snapshot_base(self):
        for name, changes in {"short": {"snapshot_base": "9" * 12}, "upper": {"snapshot_base": "A" * 40},
                              "not a string": {"snapshot_base": 9}, "equals head": {"snapshot_base": HEAD},
                              "length differs from head": {"snapshot_base": "9" * 64},
                              "no head": {"head": None}, "plan stage": {"stage": "PLAN"}}.items():
            with self.subTest(name):
                m = self.meta(**changes)
                if m.get("head") is None:
                    m.pop("head")
                if m["stage"] != "PR":
                    for k in ("repo", "pr", "reviewer", "reviewer_harness", "author_harness"):
                        m.pop(k)
                with self.assertRaises(guard.GuardError):
                    guard.validate_review_metadata(m, result="CHECK_OK")

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
        self.baseline = subprocess.check_output(["git", "-C", str(self.repo), "rev-parse", "HEAD"], text=True).strip()
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
        self.fake_gh(value)

    def fake_gh(self, value):
        """`gh pr view` answers `value`; a bound PR review also posts harness/review and reads it back (2026-11-25)."""
        statuses = str(self.root / "gh-statuses.json")
        self.fake("gh", "import json, os, sys\nargs = sys.argv[1:]\nstate = " + repr(statuses) + "\n"
                        "rows = json.load(open(state)) if os.path.exists(state) else []\n"
                        "if args[:1] == ['api'] and 'POST' in args:\n"
                        "    row = dict(json.loads(sys.stdin.read()), id=len(rows) + 1)\n"
                        "    json.dump([row] + rows, open(state, 'w'))\n    print(json.dumps(row))\n"
                        "elif args[:1] == ['api']:\n    print(json.dumps(rows))\n"
                        "else:\n    print(json.dumps(" + repr(value) + "))\n")

    def fake(self, name, body):
        path = self.bin / name
        # A managed Python path can contain spaces, which a shebang cannot quote.
        path.write_text("#!/bin/sh\nexec " + shlex.quote(sys.executable) + " -c " + shlex.quote(body) + ' "$@"\n')
        path.chmod(0o700)



    def reviewed_two_commit_pr(self, *extra):
        # a second PR commit, so the merge-base (baseline) differs from head^1 (self.head)
        (self.repo / "app.txt").write_text("second\n")
        subprocess.run(["git", "-C", str(self.repo), "commit", "-qam", "feat: second\n\nRefs: none (fixture)\n\n"
                        "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"], check=True)
        head = subprocess.check_output(["git", "-C", str(self.repo), "rev-parse", "HEAD"], text=True).strip()
        self.packet.write_text("Scope and evidence.\nReviewed HEAD " + head +
                               "\n$ python3 -m unittest discover tests\nRan 1 test in 0.1s\nOK\nexit 0\n")
        value = {"number": 5, "url": "https://github.com/o/r/pull/5", "headRefOid": head, "state": "OPEN"}
        self.fake_gh(value)
        output = self.root / "two.md"
        env = dict(os.environ, HOME=str(self.root), PATH=str(self.bin) + os.pathsep + "/usr/bin:/bin",
                   AGENT_HARNESS_USAGE_DIR=str(self.root / "usage"),
                   AGENT_HARNESS_REVIEW_POLICY=str(ROOT / "harness" / "hooks" / "review_policy.json"))
        result = subprocess.run([
            sys.executable, str(HOOKS / "peer_review.py"), "pr", "--repo", str(self.repo),
            "--packet", str(self.packet), "--output", str(output), "--expected-head", head,
            "--github-repo", "o/r", "--pr", "5", "--no-main-stamp", *extra],
            text=True, capture_output=True, env=env, timeout=45)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        line = next(l for l in result.stdout.splitlines() if l.startswith("Usage receipt: "))
        evidence = guard.UsageStore(self.root / "usage").inspect(json.loads(line[len("Usage receipt: "):]))
        review = evidence["review"]
        return head, (review["repo"], review["pr"], review["head"], review["report_sha256"], review["snapshot_base"])

    def test_explicit_base_off_the_merge_base_is_recorded_not_inferred(self):
        head, binding = self.reviewed_two_commit_pr("--snapshot-base", self.head)
        self.assertEqual(binding[2], head)
        self.assertEqual(binding[4], self.head, "B_r is the base the reviewer diffed against, not the merge-base")

    def test_default_base_is_recorded_as_reviewed_not_the_merge_base(self):
        head, binding = self.reviewed_two_commit_pr()
        self.assertEqual(binding[4], self.head, "no flag: the head^1 snapshot base, never an inferred merge-base")

    def reviewed_evidence(self, repo, head, *extra):
        """Run the bound daemon-style PR review of `head` in `repo`; return its settled FINAL evidence."""
        self.packet.write_text("Scope and evidence.\nReviewed HEAD " + head +
                               "\n$ python3 -m unittest discover tests\nRan 1 test in 0.1s\nOK\nexit 0\n")
        value = {"number": 5, "url": "https://github.com/o/r/pull/5", "headRefOid": head, "state": "OPEN"}
        self.fake_gh(value)
        output = self.root / ("review-%s.md" % head[:12])
        env = dict(os.environ, HOME=str(self.root), PATH=str(self.bin) + os.pathsep + "/usr/bin:/bin",
                   AGENT_HARNESS_USAGE_DIR=str(self.root / "usage"),
                   AGENT_HARNESS_REVIEW_POLICY=str(ROOT / "harness" / "hooks" / "review_policy.json"))
        result = subprocess.run([
            sys.executable, str(HOOKS / "peer_review.py"), "pr", "--repo", str(repo),
            "--packet", str(self.packet), "--output", str(output), "--expected-head", head,
            "--github-repo", "o/r", "--pr", "5", "--no-main-stamp", *extra],
            text=True, capture_output=True, env=env, timeout=45)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        line = next(l for l in result.stdout.splitlines() if l.startswith("Usage receipt: "))
        return guard.UsageStore(self.root / "usage").inspect(json.loads(line[len("Usage receipt: "):]))

    def assert_no_base(self, evidence, head):
        self.assertNotIn("snapshot_base", evidence["review"], "no base: the key is absent, never defaulted")
        self.assertEqual(evidence["review"]["head"], head)

    def test_root_commit_pr_without_a_flag_has_no_base(self):
        root = self.root / "rootrepo"
        root.mkdir()
        for args in (["init", "-q", "-b", "main"], ["config", "user.name", "Fixture"],
                     ["config", "user.email", "fixture@example.invalid"]):
            subprocess.run(["git", "-C", str(root)] + args, check=True)
        (root / "app.txt").write_text("only\n")
        subprocess.run(["git", "-C", str(root), "add", "app.txt"], check=True)
        subprocess.run(["git", "-C", str(root), "commit", "-qm", "feat: root\n\nRefs: none (fixture)\n\n"
                        "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"], check=True)
        head = subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()
        self.assertEqual(subprocess.run(["git", "-C", str(root), "rev-parse", "--verify", "--quiet", head + "^1"],
                                        capture_output=True).returncode, 1, "fixture: a parentless commit")
        self.assert_no_base(self.reviewed_evidence(root, head), head)

    def test_explicit_base_equal_to_head_is_omitted(self):
        evidence = self.reviewed_evidence(self.repo, self.head, "--snapshot-base", self.head)
        self.assert_no_base(evidence, self.head)

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
        self.fake_gh(value)
        result = self.run_review("--author-harness", "claude")
        self.assertNotIn("Merge authorization:", result.stdout, result.stdout + result.stderr)
        self.assertIn("do not prove the author harness", result.stderr)




if __name__ == "__main__":
    unittest.main()
