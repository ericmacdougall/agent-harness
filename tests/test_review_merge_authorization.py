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


class PrPassEvidenceTests(AuthorizationTests):
    """merge_gate.pr_pass_evidence: the pure predicate add_review_waiver and the ahc daemon share (goodqa#16049
    M-1). It classifies evidence only; it never writes a waiver or any other state."""

    def inspected(self, **changes):
        store, reference = self.evidence(**changes)
        return store.inspect(reference)

    def test_settled_independent_pass_returns_its_binding(self):
        self.assertEqual(mg.pr_pass_evidence(self.inspected()), ("o/r", 5, HEAD, REPORT_SHA))

    def test_each_guard_clause_refuses(self):
        good = self.inspected()
        mutations = {
            "unsettled": lambda e: e.update(review_finalization="PENDING"),
            "not completed": lambda e: e.update(execution="TIMEOUT"),
            "not CHECK_OK": lambda e: e.update(result="CHECK_FAILED"),
            "reason set": lambda e: e.update(reason="ADVISORY"),
            "wrong purpose": lambda e: e["invocation"].update(purpose="peer-review-code-inspection"),
            "stage": lambda e: e["review"].update(stage="CODE_INSPECTION"),
            "verdict": lambda e: e["review"].update(verdict="BLOCK"),
            "findings": lambda e: e["review"].update(findings=["F1"]),
            "ticketed": lambda e: e["review"].update(ticketed=True),
            "missing report sha": lambda e: e["review"].pop("report_sha256"),
            "subject head differs": lambda e: e["subject"].update(head=OTHER),
            "author unknown": lambda e: e["review"].update(author_harness="unknown"),
            "reviewer unknown": lambda e: e["review"].update(reviewer_harness="kimi"),
            "same harness": lambda e: e["review"].update(reviewer_harness="claude", reviewer="Claude fixture"),
            "prefix mismatch": lambda e: e["review"].update(reviewer="Claude fixture"),
            "no provider launch": lambda e: e["usage"].update(provider_launches=0),
            "launches not int": lambda e: e["usage"].update(provider_launches="1"),
            "no review": lambda e: e.pop("review"),
            "invocation not a mapping": lambda e: e.update(invocation="peer-review-pr"),
        }
        for name, mutate in mutations.items():
            with self.subTest(name):
                evidence = json.loads(json.dumps(good))
                mutate(evidence)
                with self.assertRaises((ValueError, guard.GuardError)):
                    mg.pr_pass_evidence(evidence)
        with self.assertRaises(ValueError):
            mg.pr_pass_evidence(None)

    def test_predicate_writes_nothing(self):
        evidence = self.inspected()
        before = sorted(str(p) for p in self.root.rglob("*"))
        mg.pr_pass_evidence(evidence)
        self.assertEqual(sorted(str(p) for p in self.root.rglob("*")), before)
        self.assertFalse(self.state.exists(), "classifying evidence never creates merge_gate state")

    def test_add_review_waiver_decides_through_the_predicate(self):
        store, reference = self.evidence()
        with mock.patch.object(mg, "pr_pass_evidence", side_effect=ValueError("refused by predicate")):
            with self.assertRaisesRegex(ValueError, "refused by predicate"):
                mg.add_review_waiver(self.state, reference, store=store)
        self.assertEqual(mg._read_waivers(self.state) if self.state.exists() else [], [])


class BoundPassTests(AuthorizationTests):
    """merge_gate.ahc_bound_pass (spec ahc-m1-v2g2 R4/E2, v2g6 scope: cross-vendor only): the PASS must be for the
    reviewed head H, carry B_r, and B_r must be the current default-branch tip B or an ancestor of it. It replaces
    the withdrawn candidate-M binding. BOUNDARY: main merges this and the security review reads it."""

    H, B, BR, B2, H2 = "2" * 40, "1" * 40, "7" * 40, "8" * 40, "3" * 40

    def final(self, head=None, snapshot_base=None, **review):
        review.setdefault("head", head or self.H)
        if snapshot_base is not False:
            review["snapshot_base"] = snapshot_base or self.BR
        store, reference = self.evidence(review, subject_head=review["head"])
        return store.inspect(reference)

    @staticmethod
    def cmp(base, head, status="ahead"):
        return {"base": base, "head": head, "status": status}

    def binding(self, br=None, base_status="ahead", head_status="ahead", **changes):
        b = {"repo": "o/r", "pr": 5, "head": self.H, "base": self.B, "pr_head": self.H,
             "base_compare": self.cmp(br or self.BR, self.B, base_status),
             "head_compare": self.cmp(self.B, self.H, head_status)}
        b.update(changes)
        return b

    def test_pass_for_h_with_b_r_an_ancestor_of_b_or_equal_binds(self):
        self.assertEqual(mg.ahc_bound_pass(self.final(), self.binding()), ("o/r", 5, self.H, self.BR, REPORT_SHA))
        same = self.final(snapshot_base=self.B)
        self.assertEqual(mg.ahc_bound_pass(same, self.binding(br=self.B, base_status="identical"))[3], self.B)
        self.assertEqual(mg.ahc_bound_pass(self.final(), self.binding(repo="O/R"))[0], "o/r")

    def test_each_binding_condition_refuses(self):
        final = self.final()
        bad = {
            "legacy receipt without B_r": (self.final(snapshot_base=False), self.binding()),
            "other repo": (final, self.binding(repo="o/other")),
            "lookalike repo": (final, self.binding(repo="o/r\u0435")),
            "other PR": (final, self.binding(pr=6)),
            "PR as a string": (final, self.binding(pr="5")),
            "Reviewed HEAD is not H": (self.final(head=self.H2), self.binding()),
            "PR head read back moved": (final, self.binding(pr_head=self.H2)),
            "PR head unread": (final, self.binding(pr_head=None)),
            "B_r diverged from B": (final, self.binding(base_status="diverged")),
            "B_r ahead of B": (final, self.binding(base_status="behind")),
            "compare unread": (final, self.binding(base_compare=None)),
            "compare a bare status": (final, self.binding(base_compare="ahead")),
            "identical but B_r is not B": (final, self.binding(base_status="identical")),
            "ahead but B_r is B": (self.final(snapshot_base=self.B), self.binding(br=self.B)),
            "compare base is not B_r": (final, self.binding(br=self.B2)),
            "compare head is not B": (final, self.binding(base_compare=self.cmp(self.BR, self.B2))),
            "compare pair swapped": (final, self.binding(base_compare=self.cmp(self.B, self.BR))),
            "compare sha short": (final, self.binding(base_compare=self.cmp(self.BR[:12], self.B))),
            "compare status missing": (final, self.binding(base_compare={"base": self.BR, "head": self.B})),
            "H not ahead of B": (final, self.binding(head_status="diverged")),
            "H behind B": (final, self.binding(head_status="behind")),
            "H identical to B by compare": (final, self.binding(head_status="identical")),
            "B...H unread": (final, self.binding(head_compare=None)),
            "B...H base is not B": (final, self.binding(head_compare=self.cmp(self.B2, self.H))),
            "B...H head is not H": (final, self.binding(head_compare=self.cmp(self.B, self.H2))),
            "B...H pair swapped": (final, self.binding(head_compare=self.cmp(self.H, self.B))),
            "malformed H": (final, self.binding(head="xyz")),
            "malformed B": (final, self.binding(base="B" * 40)),
            "H equals B": (final, self.binding(base=self.H, head_compare=self.cmp(self.H, self.H),
                                               base_compare=self.cmp(self.BR, self.H))),
            "not a mapping": (final, None),
        }
        for name, (evidence, binding) in bad.items():
            with self.subTest(name), self.assertRaises(ValueError):
                mg.ahc_bound_pass(evidence, binding)

    def test_cross_vendor_only_and_the_author_harness_must_be_known(self):
        """v2g6 AC-17 scope: no same-vendor fallback in this change; an unknown author harness fails closed."""
        for name, review in {"same vendor": {"reviewer_harness": "claude", "reviewer": "Claude x"},
                             "author unknown": {"author_harness": "unknown"},
                             "reviewer unknown": {"reviewer_harness": "kimi"}}.items():
            with self.subTest(name), self.assertRaises((ValueError, guard.GuardError)):
                mg.ahc_bound_pass(self.final(**review), self.binding())
        with self.assertRaises((ValueError, guard.GuardError)):
            mg.ahc_bound_pass(self.final(verdict="BLOCK"), self.binding())
        self.assertNotIn("same_vendor", mg.ahc_bound_pass.__code__.co_varnames, "no fallback argument yet")

    def test_mains_predicate_still_refuses_a_same_vendor_final(self):
        """v2g6 AC-17: main's path, pr_pass_evidence, refuses a same-vendor FINAL, with and without B_r."""
        for with_base in (False, True):
            with self.subTest(with_base=with_base), self.assertRaises((ValueError, guard.GuardError)):
                mg.pr_pass_evidence(self.final(reviewer_harness="claude", reviewer="Claude x"), with_base=with_base)

    def test_binding_writes_nothing(self):
        evidence = self.final()
        before = sorted(str(p) for p in self.root.rglob("*"))
        mg.ahc_bound_pass(evidence, self.binding())
        self.assertEqual(sorted(str(p) for p in self.root.rglob("*")), before)

    def test_the_withdrawn_candidate_binding_is_gone(self):
        self.assertFalse(hasattr(mg, "ahc_candidate_pass"), "v2g withdrew the candidate-M binding")


class SnapshotBaseTests(AuthorizationTests):
    """B_r (goodqa#16049 spec ahc-m1-v2g, main's ruling option a): the PR FINAL may carry the reviewer's snapshot
    base; usage_guard validates it and pr_pass_evidence exposes it. BOUNDARY: main merges this."""

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

    def test_pr_pass_evidence_exposes_the_base_only_when_asked(self):
        store, reference = self.evidence({"snapshot_base": self.BR})
        evidence = store.inspect(reference)
        self.assertEqual(mg.pr_pass_evidence(evidence), ("o/r", 5, HEAD, REPORT_SHA), "default shape unchanged")
        self.assertEqual(mg.pr_pass_evidence(evidence, with_base=True), ("o/r", 5, HEAD, REPORT_SHA, self.BR))

    def test_with_base_refuses_a_legacy_receipt_without_a_snapshot_base(self):
        # main's ruling: absence is legacy, never "same as the merge-base"; the 4-tuple path still accepts it
        store, reference = self.evidence()
        legacy = store.inspect(reference)
        self.assertEqual(mg.pr_pass_evidence(legacy), ("o/r", 5, HEAD, REPORT_SHA))
        with self.assertRaisesRegex(ValueError, "LEGACY_NO_SNAPSHOT_BASE"):
            mg.pr_pass_evidence(legacy, with_base=True)


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

    def test_no_main_stamp_leaves_mains_stamp_and_mints_nothing(self):
        # goodqa#16049: the ahc daemon's bound run on a host where main has a stamp for this exact repo and PR
        import caller_identity
        caller_identity.put_stamp("review-auth", ["o/r", 5], home=self.root)
        folder = caller_identity.stamp_dir(self.root)
        before = sorted(p.name for p in folder.iterdir())
        output = self.root / "daemon.md"
        env = dict(os.environ, HOME=str(self.root), PATH=str(self.bin) + os.pathsep + "/usr/bin:/bin",
                   AGENT_HARNESS_USAGE_DIR=str(self.root / "usage"),
                   AGENT_HARNESS_REVIEW_POLICY=str(ROOT / "harness" / "hooks" / "review_policy.json"))
        result = subprocess.run([
            sys.executable, str(HOOKS / "peer_review.py"), "pr", "--repo", str(self.repo),
            "--packet", str(self.packet), "--output", str(output), "--expected-head", self.head,
            "--github-repo", "o/r", "--pr", "5", "--no-main-stamp", "--snapshot-base", self.baseline],
            text=True, capture_output=True, env=env, timeout=45)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("Merge authorization:", result.stdout)
        self.assertEqual(sorted(p.name for p in folder.iterdir()), before, "main's stamp is neither taken nor burnt")
        state = self.root / ".agent-harness" / "state"
        self.assertEqual([r for r in mg._read_waivers(state) if r.get("event") == "waive"], [])
        self.assertIn("Reviewed PR: 5", output.read_text(), "the run still binds to the PR")
        self.assertIsNotNone(caller_identity.take_stamp("review-auth", ["o/r", 5], home=self.root),
                             "main can still use its stamp afterwards")
        # the daemon's own settled FINAL is still merge-eligible evidence for the shared predicate (M-1 C6 needs it)
        line = next(l for l in result.stdout.splitlines() if l.startswith("Usage receipt: "))
        reference = json.loads(line[len("Usage receipt: "):])
        evidence = guard.UsageStore(self.root / "usage").inspect(reference)
        self.assertEqual(mg.pr_pass_evidence(evidence)[:3], ("o/r", 5, self.head))
        self.assertEqual(evidence["review"]["author_harness"], "claude", "derived from the trailers")
        merge_base = subprocess.check_output(["git", "-C", str(self.repo), "merge-base", self.head,
                                              "refs/remotes/origin/main"], text=True).strip()
        self.assertEqual(merge_base, self.baseline, "fixture: the explicit base IS the merge-base")
        self.assertEqual(mg.pr_pass_evidence(evidence, with_base=True)[4], self.baseline,
                         "explicit base == merge-base still records the key (v2g, main's ruling)")

    def reviewed_two_commit_pr(self, *extra):
        # a second PR commit, so the merge-base (baseline) differs from head^1 (self.head)
        (self.repo / "app.txt").write_text("second\n")
        subprocess.run(["git", "-C", str(self.repo), "commit", "-qam", "feat: second\n\nRefs: none (fixture)\n\n"
                        "Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>"], check=True)
        head = subprocess.check_output(["git", "-C", str(self.repo), "rev-parse", "HEAD"], text=True).strip()
        self.packet.write_text("Scope and evidence.\nReviewed HEAD " + head +
                               "\n$ python3 -m unittest discover tests\nRan 1 test in 0.1s\nOK\nexit 0\n")
        value = {"number": 5, "url": "https://github.com/o/r/pull/5", "headRefOid": head, "state": "OPEN"}
        self.fake("gh", "import json\nprint(json.dumps(" + repr(value) + "))\n")
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
        return head, mg.pr_pass_evidence(evidence, with_base=True)

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
        self.fake("gh", "import json\nprint(json.dumps(" + repr(value) + "))\n")
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

    def assert_no_base_and_refused(self, evidence, head):
        self.assertNotIn("snapshot_base", evidence["review"], "no base: the key is absent, never defaulted")
        self.assertEqual(mg.pr_pass_evidence(evidence)[2], head, "the legacy 4-tuple path still accepts it")
        with self.assertRaisesRegex(ValueError, "LEGACY_NO_SNAPSHOT_BASE"):
            mg.pr_pass_evidence(evidence, with_base=True)

    def test_root_commit_pr_without_a_flag_has_no_base_and_is_refused_with_base(self):
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
        self.assert_no_base_and_refused(self.reviewed_evidence(root, head), head)

    def test_explicit_base_equal_to_head_is_omitted_and_refused_with_base(self):
        evidence = self.reviewed_evidence(self.repo, self.head, "--snapshot-base", self.head)
        self.assert_no_base_and_refused(evidence, self.head)

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


class NativeReviewReceiptScope(unittest.TestCase):
    COMMAND = "python3 ~/.claude/hooks/peer_review.py pr --repo /w --github-repo o/r --pr 5 --packet /p"
    PAYLOAD = {"session_id": "11111111-2222-4333-8444-555555555555", "agent_id": None}

    def check_path(self, command, native, claude=False):
        import caller_identity

        adapter = SimpleNamespace(is_desktop_review_root=native)
        with mock.patch.dict(sys.modules, {"native_main": adapter}), \
                mock.patch.object(caller_identity, "is_main", return_value=claude), \
                mock.patch.object(caller_identity, "put_stamp") as stamp:
            mg._stamp_review(command, self.PAYLOAD, 123)
        return stamp

    def test_native_root_can_write_only_the_existing_review_receipt(self):
        native = mock.Mock(return_value=True)
        stamp = self.check_path(self.COMMAND, native)
        native.assert_called_once_with(self.PAYLOAD)
        stamp.assert_called_once_with("review-auth", ["o/r", 5], session=self.PAYLOAD["session_id"], now=123)

    def test_nonplain_commands_do_not_reach_native_admission(self):
        for command in ("echo " + self.COMMAND, self.COMMAND + " | tee output", "true; " + self.COMMAND):
            with self.subTest(command=command):
                native = mock.Mock(return_value=True)
                self.check_path(command, native).assert_not_called()
                native.assert_not_called()

    def test_native_denial_or_error_writes_no_receipt(self):
        for native in (mock.Mock(return_value=False), mock.Mock(side_effect=OSError)):
            self.check_path(self.COMMAND, native).assert_not_called()

    def test_genuine_claude_success_short_circuits_native_lookup(self):
        native = mock.Mock(side_effect=AssertionError)
        self.check_path(self.COMMAND, native, claude=True).assert_called_once()
        native.assert_not_called()


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


class StampRefusalNotes(unittest.TestCase):
    """goodqa#16811: when main's PR review mints no review-auth stamp, the agent is told why; the rule is unchanged."""

    SID = "11111111-2222-3333-4444-555555555555"
    PLAIN = "python3 ~/.claude/hooks/peer_review.py pr --repo /w --github-repo o/r --pr 5 --packet /p"
    SEMICOLON = PLAIN + " --repeat-reason 'first run timed out; lane was held'"

    def run_hook(self, home, command, **extra):
        transcript = Path(home) / ".claude" / "projects" / "-x" / (self.SID + ".jsonl")
        transcript.parent.mkdir(parents=True, exist_ok=True)
        transcript.write_text("{}\n")
        payload = dict(fixture.bash(command), session_id=self.SID, transcript_path=str(transcript), **extra)
        stdin = __import__("io").BytesIO(json.dumps(payload).encode())
        stdout, stderr = __import__("io").StringIO(), __import__("io").StringIO()
        with mock.patch.dict(os.environ, {"HOME": home}):
            code = mg.hook_main(Path(home) / "s", fixture.FakeGh(fixture.SCENARIOS["green"]), stdin, stdout, stderr)
        return code, stdout.getvalue(), stderr.getvalue()

    def context(self, stdout):
        if not stdout.strip():
            return None
        return json.loads(stdout)["hookSpecificOutput"]["additionalContext"]

    def test_main_quoted_semicolon_mints_nothing_and_says_why(self):
        import caller_identity
        with tempfile.TemporaryDirectory() as home:
            code, out, _ = self.run_hook(home, self.SEMICOLON)
            self.assertEqual(code, 0)
            self.assertIsNone(caller_identity.take_stamp("review-auth", ["o/r", 5], home=home))  # rule unchanged
            note = self.context(out)
            self.assertIsNotNone(note)
            offset = self.SEMICOLON.index(";")
            self.assertIn("review-auth stamp not minted", note)
            self.assertIn("shell syntax ';' at offset %d" % offset, note)
            self.assertNotIn("run it from the main agent)", note)

    def test_plain_main_command_mints_and_emits_nothing(self):
        import caller_identity
        with tempfile.TemporaryDirectory() as home:
            code, out, err = self.run_hook(home, self.PLAIN)
            self.assertEqual((code, out, err), (0, "", ""))
            self.assertIsNotNone(caller_identity.take_stamp("review-auth", ["o/r", 5], home=home))

    def test_not_main_is_named_as_the_reason(self):
        import caller_identity
        with tempfile.TemporaryDirectory() as home:
            with mock.patch.object(caller_identity, "is_main", return_value=False), \
                    mock.patch.dict(sys.modules, {"native_main": SimpleNamespace(is_desktop_review_root=lambda p: False)}):
                code, out, _ = self.run_hook(home, self.PLAIN)
            self.assertEqual(code, 0)
            self.assertIn("not the proven main agent", self.context(out))
            self.assertIsNone(caller_identity.take_stamp("review-auth", ["o/r", 5], home=home))

    def test_mentions_without_a_launch_get_no_note_and_subagents_keep_the_block(self):
        with tempfile.TemporaryDirectory() as home:
            for command in ("grep -n -- --github-repo peer_review.py; echo --pr 5",
                            "git log # peer_review --github-repo o/r --pr 5",
                            "echo peer_review.py pr --github-repo o/r --pr 5"):
                with self.subTest(command=command):
                    code, out, _ = self.run_hook(home, command)
                    self.assertEqual((code, out), (0, ""))
            code, out, err = self.run_hook(home, self.SEMICOLON, agent_id="sub1")
            self.assertEqual((code, out), (2, ""))
            self.assertIn("subagent cannot run the PR review", err)

    def test_reason_exists_exactly_when_the_command_is_not_plain(self):
        corpus = [self.PLAIN, self.SEMICOLON, "python3 -I /x/peer_review.py pr --pr 5", "python3.12 peer_review.py",
                  "python3 peer_review.py pr 'unbalanced", "true && " + self.PLAIN, self.PLAIN + " | tee x",
                  self.PLAIN + " > out", "python3 $(which peer_review.py)", "bash peer_review.py",
                  "python3 other.py --github-repo o/r --pr 5", self.PLAIN + " --repeat-reason 'a\nb'",
                  "python3 -u -B peer_review.py --pr=5 --github-repo=o/r", "env python3 peer_review.py", "",
                  "python3 peer_review.py `id`", "python3 peer_review.py --repeat-reason 'x & y'"]
        for command in corpus:
            with self.subTest(command=command):
                self.assertEqual(mg._not_plain_reason(command) is None, mg._plain_peer_review(command))

    def test_peer_review_note_names_the_option_and_lists_the_conditions(self):
        argv = ["pr", "--github-repo", "o/r", "--pr", "5", "--repeat-reason", "first run timed out; lane was held"]
        note = review.no_stamp_note(argv)
        self.assertIn("no main-agent stamp", note)
        self.assertIn("--repeat-reason contains ';'", note)
        self.assertIn("single-use stamp, valid 600 s", note)
        self.assertIn("even inside quotes", note)
        plain = review.no_stamp_note(["pr", "--github-repo", "o/r", "--pr", "5"])
        self.assertNotIn("Likely reason", plain)
        self.assertIn("no main-agent stamp", review.no_stamp_note([], opted_out=True))

    def test_peer_review_and_merge_gate_share_one_shell_syntax_set(self):
        import caller_identity
        self.assertEqual(review.STAMP_SHELL_SYNTAX.pattern, mg._SHELL_SYNTAX.pattern)
        self.assertEqual(caller_identity.STAMP_TTL_SECONDS, 600)  # the note says "valid 600 s"


if __name__ == "__main__":
    unittest.main()
