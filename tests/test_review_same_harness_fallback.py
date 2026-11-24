"""goodqa#17129: while Codex is out, a Claude PASS at a strictly higher rung than a Claude author may authorize a merge.

Source: answer:1eaed05e-9884-44ca-a537-09a25d215e7c/1c875d08-df35-421b-90e6-8f0667464a40 "Yes, while Codex is out
(Recommended)". Everything else (cross-harness, the ahc daemon's cross-vendor-only path, unknown authors) is unchanged.
"""
import copy
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
HOOKS = ROOT / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
sys.path.insert(0, str(HERE))
import merge_gate as mg  # noqa: E402
import model_tiers as tiers  # noqa: E402
import peer_review as review  # noqa: E402
import usage_guard as guard  # noqa: E402
import test_merge_gate as fixture  # noqa: E402
import test_review_merge_authorization as base  # noqa: E402

HEAD, REPORT_SHA = base.HEAD, base.REPORT_SHA
RUN = "a1" * 16
OTHER_RUN = "b2" * 16
ROUTING = {"requested_mode": "auto", "attempt_order": ["codex", "claude"], "effective_fallback": "claude",
           "actual_reviewer": "claude"}


def outage(run_id=RUN, **changes):
    return dict({"run_id": run_id, "provider": "codex", "reason": "QUOTA", "basis": "structured"}, **changes)


def claude_review(**changes):
    """Review metadata of a Claude-reviewed, Claude-authored PASS that fell back from Codex (author R1, reviewer R2)."""
    value = {"author_harness": "claude", "reviewer_harness": "claude", "author_rung": "R1", "reviewer_rung": "R2",
             "primary_unavailable": outage()}
    value.update(changes)
    return {key: item for key, item in value.items() if item is not None}


class IndependenceFunction(unittest.TestCase):
    """The one decision both callers use."""

    def decide(self, review_value=None, routing=ROUTING, run_id=RUN, **kwargs):
        return tiers.review_independence(review_value if review_value is not None else claude_review(),
                                         routing, run_id, **kwargs)

    def test_fallback_at_a_higher_rung_is_independent(self):
        self.assertIsNone(self.decide())
        self.assertIsNone(self.decide(claude_review(author_rung="R0", reviewer_rung="R3")))
        self.assertIsNone(self.decide(claude_review(primary_unavailable=outage(reason="AUTH", basis="prose"))))
        self.assertIsNone(self.decide(claude_review(primary_unavailable=outage(reason="TRANSIENT_INFRA"))))

    def test_cross_harness_stays_independent_without_any_fallback_record(self):
        for author, reviewer in (("claude", "openai"), ("openai", "claude")):
            with self.subTest(author=author):
                self.assertIsNone(tiers.review_independence(
                    {"author_harness": author, "reviewer_harness": reviewer}, None, None))

    def test_refusals_name_their_reason(self):
        cases = {
            "same rung": (claude_review(reviewer_rung="R1"), "reviewer rung is not above"),
            "lower rung": (claude_review(author_rung="R3", reviewer_rung="R2"), "reviewer rung is not above"),
            "no reviewer rung": (claude_review(reviewer_rung=None), "reviewer rung is not above"),
            "unknown author rung": (claude_review(author_rung=None), "author rung is unknown"),
            "garbage author rung": (claude_review(author_rung="R1; drop"), "author rung is unknown"),
            "no fallback recorded": (claude_review(primary_unavailable=None), "no recorded fallback"),
            "fallback is not a mapping": (claude_review(primary_unavailable="QUOTA"), "no recorded fallback"),
            "other run": (claude_review(primary_unavailable=outage(OTHER_RUN)), "different run"),
            "run id missing": (claude_review(primary_unavailable=outage(None)), "different run"),
            "timeout is not an outage": (claude_review(primary_unavailable=outage(reason="TIMEOUT")), "not a Codex outage"),
            "claude was the primary": (claude_review(primary_unavailable=outage(provider="claude")), "not a Codex outage"),
            "unknown basis": (claude_review(primary_unavailable=outage(basis="asserted")), "not a Codex outage"),
            "extra field": (claude_review(primary_unavailable=outage(extra=1)), "not a Codex outage"),
            "openai author": (claude_review(author_harness="openai", reviewer_harness="openai"), "only Claude-authored"),
            "unknown author": (claude_review(author_harness="unknown"), "author harness unknown"),
            "unknown reviewer": (claude_review(reviewer_harness="kimi"), "reviewer harness unknown"),
        }
        for name, (value, expected) in cases.items():
            with self.subTest(name):
                reason = self.decide(value)
                self.assertIsNotNone(reason)
                self.assertIn(expected, reason)

    def test_run_must_have_fallen_back_from_codex_to_claude(self):
        for name, routing in {"claude was first": dict(ROUTING, attempt_order=["claude", "codex"]),
                              "claude only": dict(ROUTING, attempt_order=["claude"], effective_fallback=None),
                              "codex answered": dict(ROUTING, actual_reviewer="codex"),
                              "no routing": None, "routing not a mapping": "codex"}.items():
            with self.subTest(name):
                self.assertIn("did not fall back", self.decide(routing=routing))

    def test_a_caller_that_forbids_same_harness_gets_a_refusal_even_for_a_valid_record(self):
        self.assertEqual(self.decide(allow_same_harness=False), "same harness as author")

    def test_decision_does_not_mutate_its_inputs(self):
        value, routing = claude_review(), copy.deepcopy(ROUTING)
        before = copy.deepcopy(value)
        self.decide(value, routing)
        self.assertEqual((value, routing), (before, ROUTING))


class FinalEvidence(unittest.TestCase):
    """merge_gate.pr_pass_evidence / add_review_waiver, read from a real usage-store FINAL."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.state = self.root / "state"
        self.counter = 0

    decide = base.AuthorizationTests.decide

    def fallback_final(self, review_changes=None, usage_changes=None, run_id_for_record=True, subject_head=HEAD,
                       settle=True, drop=()):
        self.counter += 1
        root = self.root / ("fallback-" + str(self.counter))
        repo = root / "repo"
        repo.mkdir(parents=True)
        store = guard.UsageStore(root / "usage")
        subject = guard.Subject(schema=1, fingerprint="e" * 64, reusable=True, head=subject_head, tree="f" * 40)
        subject.repo, subject.manifest = repo, {}
        subject.probe = lambda: subject
        invocation = guard.invocation_identity(subject, purpose="peer-review-pr", argv=["peer_review", "pr", "x"],
                                               cwd=repo, stage="PR", provider="claude")
        run = store.begin(subject, invocation, owner="fixture", label="peer-review-pr", timeout=10, kind="review",
                          minimum_bytes=0)
        metadata = {"stage": "PR", "verdict": "ACCEPT", "findings": [], "repo": "o/r", "pr": 5, "head": HEAD,
                    "report_sha256": REPORT_SHA, "reviewer": "Claude fixture", "reviewer_harness": "claude",
                    "author_harness": "claude", "author_rung": "R1", "reviewer_rung": "R2",
                    "primary_unavailable": outage(run.run_id if run_id_for_record else OTHER_RUN)}
        metadata.update(review_changes or {})
        for key in drop:
            metadata.pop(key)
        usage = {"provider_launches": 2, "reported": [], "executables": {}, "review_routing": dict(ROUTING)}
        usage.update(usage_changes or {})
        reference = run.finish(execution="COMPLETED", result="CHECK_OK", reason="NONE", exit_code=0,
                               review=metadata, usage=usage)
        if settle:
            store.settle_review(reference)
        return store, reference

    def authorize_fallback(self, **kwargs):
        store, reference = self.fallback_final(**kwargs)
        return mg.add_review_waiver(self.state, reference, store=store)

    def test_claude_pass_after_a_codex_outage_at_a_higher_rung_authorizes_the_merge(self):
        waiver = self.authorize_fallback()
        self.assertEqual((waiver["repo"], waiver["pr"], waiver["head"], waiver["report_sha256"]),
                         ("o/r", 5, HEAD, REPORT_SHA))
        self.assertEqual(waiver["approval_source"], "settled-review")
        code, text = self.decide("green_protection_unreadable")
        self.assertEqual(code, 0, text)

    def test_negative_cases_mint_nothing_and_say_why(self):
        cases = {
            "same rung": (dict(review_changes={"reviewer_rung": "R1"}), "reviewer rung is not above"),
            "lower rung": (dict(review_changes={"author_rung": "R3", "reviewer_rung": "R2"}), "reviewer rung is not above"),
            "no recorded fallback (primary was the same harness)": (dict(drop=("primary_unavailable",)),
                                                                    "no recorded fallback"),
            "fallback recorded for a different run": (dict(run_id_for_record=False), "different run"),
            "routing shows no codex primary": (
                dict(usage_changes={"review_routing": dict(ROUTING, attempt_order=["claude"])}), "did not fall back"),
            "no routing evidence": (dict(usage_changes={"review_routing": None}), "did not fall back"),
            "no author rung": (dict(drop=("author_rung",)), "author rung is unknown"),
            "unknown author harness": (dict(review_changes={"author_harness": "unknown"}), "harness unknown"),
        }
        for index, (name, (kwargs, expected)) in enumerate(cases.items()):
            with self.subTest(name):
                self.state = self.root / ("state-" + str(index))
                with self.assertRaises(ValueError) as raised:
                    self.authorize_fallback(**kwargs)
                self.assertIn("PASS not merge-eligible: ", str(raised.exception))
                self.assertIn(expected, str(raised.exception))
                self.assertFalse((self.state / mg.WAIVER_FILE).exists(), "nothing may be minted")

    def test_block_and_stale_head_still_refuse(self):
        with self.assertRaises((ValueError, guard.GuardError)):
            self.authorize_fallback(review_changes={"verdict": "BLOCK", "findings": ["F1"]})
        with self.assertRaises((ValueError, guard.GuardError)):
            self.authorize_fallback(subject_head=HEAD.replace("a", "9"))  # FINAL subject differs from Reviewed HEAD
        with self.assertRaises((ValueError, guard.GuardError)):
            self.authorize_fallback(settle=False)
        self.assertFalse((self.state / mg.WAIVER_FILE).exists())

    def test_a_forged_final_field_breaks_the_receipt_binding(self):
        """FINAL is bound by the sha256 in its reference: editing the fallback record (or adding it) afterwards fails."""
        store, reference = self.fallback_final(review_changes={"reviewer_rung": "R1"})  # honest: same rung, refused
        path = self.root / ("fallback-" + str(self.counter)) / "usage" / "runs" / reference["run_id"] / "final.json"
        final = json.loads(path.read_text())
        self.assertEqual(final["review"]["reviewer_rung"], "R1")
        final["review"]["reviewer_rung"] = "R2"  # the forgery: it would now satisfy the independence decision
        path.write_text(json.dumps(final))
        with self.assertRaises(guard.GuardError):
            mg.add_review_waiver(self.state, reference, store=store)
        self.assertFalse((self.state / mg.WAIVER_FILE).exists())

    def test_a_copied_record_from_another_run_is_refused(self):
        """The record names its own run; lifting a valid record from run A into run B's FINAL does not bind."""
        store, ref_a = self.fallback_final()
        record_a = store.inspect(ref_a)["review"]["primary_unavailable"]
        with self.assertRaises(ValueError) as raised:
            self.authorize_fallback(review_changes={"primary_unavailable": record_a})
        self.assertIn("different run", str(raised.exception))

    def test_malformed_records_are_rejected_when_the_final_is_written(self):
        for bad in (outage(RUN, reason="TIMEOUT"), outage("short"), outage(RUN, provider="gpt"),
                    outage(RUN, basis="flag"), {"run_id": RUN}):
            with self.subTest(bad=bad), self.assertRaises(guard.GuardError):
                self.fallback_final(review_changes={"primary_unavailable": bad})
        for key in ("author_rung", "reviewer_rung"):
            with self.subTest(key=key), self.assertRaises(guard.GuardError):
                self.fallback_final(review_changes={key: "opus"})

    def test_the_ahc_daemon_stays_cross_vendor_only(self):
        store, reference = self.fallback_final(review_changes={"snapshot_base": "7" * 40, "head": HEAD})
        evidence = store.inspect(reference)
        self.assertEqual(mg.pr_pass_evidence(evidence)[0], "o/r")  # main's predicate accepts the fallback
        binding = {"repo": "o/r", "pr": 5, "head": HEAD, "base": "1" * 40, "pr_head": HEAD,
                   "base_compare": {"base": "7" * 40, "head": "1" * 40, "status": "ahead"},
                   "head_compare": {"base": "1" * 40, "head": HEAD, "status": "ahead"}}
        with self.assertRaises(ValueError) as raised:
            mg.ahc_bound_pass(evidence, binding)
        self.assertIn("same harness as author", str(raised.exception))


class EligibilityAndReason(unittest.TestCase):
    ARGS = SimpleNamespace(stage="pr", author_harness="claude", main_stamp={"purpose": "review-auth"})
    BINDING = {"repo": "o/r", "pr": 5}
    SELECTION = {"harness": "claude", "rung": "R2"}

    def reason(self, report="VERDICT: PASS\nReviewed", args=None, binding=BINDING, review_value=None, **kwargs):
        return review.merge_eligibility(args or self.ARGS, binding, report, self.SELECTION,
                                        review_value if review_value is not None else claude_review(),
                                        kwargs.get("routing", ROUTING), kwargs.get("run_id", RUN))

    def test_valid_fallback_is_eligible_and_the_boolean_wrapper_agrees(self):
        self.assertIsNone(self.reason())
        self.assertTrue(review.review_merge_eligible(self.ARGS, self.BINDING, "VERDICT: PASS\nReviewed", self.SELECTION,
                                                     claude_review(), ROUTING, RUN))

    def test_same_harness_without_a_fallback_record_is_refused_with_the_reason(self):
        legacy = review.merge_eligibility(self.ARGS, self.BINDING, "VERDICT: PASS\nReviewed", self.SELECTION)
        self.assertEqual(legacy, "same harness as author and no recorded fallback")
        self.assertFalse(review.review_merge_eligible(self.ARGS, self.BINDING, "VERDICT: PASS\nReviewed", self.SELECTION))

    def test_every_other_gate_is_unchanged_and_named(self):
        unstamped = SimpleNamespace(stage="pr", author_harness="claude", main_stamp=None)
        self.assertEqual(self.reason(args=unstamped), "no main-agent stamp")
        self.assertEqual(self.reason(binding=None), "no --github-repo/--pr binding")
        self.assertEqual(self.reason(report="VERDICT: BLOCK\nF1: defect"), "verdict is not a pure PASS")
        self.assertEqual(self.reason(report="VERDICT: PASS\nF1: unresolved"), "verdict is not a pure PASS")
        plan = SimpleNamespace(stage="plan", author_harness="claude", main_stamp={"purpose": "review-auth"})
        self.assertEqual(self.reason(args=plan), "not a PR review")


class EndToEnd(unittest.TestCase):
    """The real peer_review.py with fake provider CLIs: the flag cannot be set from outside the attempt loop."""

    def setUp(self):
        base.EndToEndTests.setUp(self)
        self.state = self.root / ".agent-harness" / "state"

    fake = base.EndToEndTests.fake

    def review(self, *extra, no_codex_anywhere=False):
        base.main_call_stamp(self.root)
        policy = ROOT / "harness" / "hooks" / "review_policy.json"
        if no_codex_anywhere:  # a machine-installed Codex must not be discovered by this hermetic run
            value = json.loads(policy.read_text())
            value["known_install_locations"]["codex"] = []
            policy = self.root / "review_policy.json"
            policy.write_text(json.dumps(value))
        env = dict(os.environ, HOME=str(self.root), PATH=str(self.bin) + os.pathsep + "/usr/bin:/bin",
                   AGENT_HARNESS_USAGE_DIR=str(self.root / "usage"), AGENT_HARNESS_REVIEW_POLICY=str(policy))
        return subprocess.run([
            sys.executable, str(HOOKS / "peer_review.py"), "pr", "--repo", str(self.repo),
            "--packet", str(self.packet), "--output", str(self.root / "probe-review.md"),
            "--expected-head", self.head, "--github-repo", "o/r", "--pr", "5", "--author-harness", "claude", *extra],
            text=True, capture_output=True, env=env, timeout=60)

    def codex_out(self, code=127, message="HARNESS_PROVIDER_UNAVAILABLE"):
        self.fake("codex", "import sys\nsys.stdin.read()\nsys.stderr.write(%r)\nsys.exit(%d)\n" % (message, code))

    def test_codex_unavailable_and_a_higher_claude_rung_authorizes(self):
        self.codex_out()
        result = self.review("--author-rung", "R1")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("Merge authorization:", result.stdout)
        self.assertNotIn("not merge-eligible", result.stderr)
        final = json.loads(next((self.root / "usage" / "runs").glob("*/final.json")).read_text())
        record = final["review"]["primary_unavailable"]
        self.assertEqual((record["run_id"], record["provider"], record["reason"]),
                         (final["run_id"], "codex", "TRANSIENT_INFRA"))
        self.assertEqual((final["review"]["author_rung"], final["review"]["reviewer_rung"]), ("R1", "R2"))

    def test_unknown_author_rung_is_refused_and_the_reason_is_printed_and_noted_for_the_gate(self):
        self.codex_out()
        result = self.review()  # no --author-rung and no --task: the author rung is unknown
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("Merge authorization:", result.stdout)
        self.assertIn("PASS not merge-eligible: same harness as author and the author rung is unknown", result.stderr)
        note = mg.review_refusal_note(self.state, "o/r", 5, self.head)
        self.assertEqual(note, "PASS not merge-eligible: same harness as author and the author rung is unknown")
        self.assertIsNone(mg.review_refusal_note(self.state, "o/r", 5, "0" * 40), "a note binds to the exact head")
        self.assertIsNone(mg.review_refusal_note(self.state, "o/r", 6, self.head))
        # the gate's refusal on a CI-off repository carries the reason
        original = fixture.HEAD
        fixture.HEAD = self.head
        try:
            scenario = dict(fixture.SCENARIOS["green_protection_unreadable"])
            code, text = mg.decide(fixture.bash("gh pr merge 5 --match-head-commit " + self.head),
                                   fixture.FakeGh(scenario), self.state)
        finally:
            fixture.HEAD = original
        self.assertEqual(code, 2, text)

    def test_same_rung_claim_cannot_use_a_higher_author_rung_it_does_not_have(self):
        self.codex_out()
        result = self.review("--author-rung", "R4")  # R4 is review-only: the table gives no reviewer at all
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertNotIn("Merge authorization:", result.stdout)

    def test_claude_as_the_primary_records_no_fallback_and_is_refused(self):
        (self.bin / "codex").unlink()  # Codex is not installed: Claude is the primary, nothing fell back
        result = self.review("--author-rung", "R1", no_codex_anywhere=True)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("Merge authorization:", result.stdout)
        self.assertIn("PASS not merge-eligible: same harness as author and no recorded fallback", result.stderr)
        final = json.loads(next((self.root / "usage" / "runs").glob("*/final.json")).read_text())
        self.assertNotIn("primary_unavailable", final["review"])

    def test_a_quota_prose_primary_records_its_basis(self):
        self.codex_out(1, "ERROR: ACCOUNT_QUOTA_EXCEEDED")
        result = self.review("--author-rung", "R1")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("Merge authorization:", result.stdout)
        final = json.loads(next((self.root / "usage" / "runs").glob("*/final.json")).read_text())
        self.assertEqual(final["review"]["primary_unavailable"]["reason"], "QUOTA")
        self.assertEqual(final["review"]["primary_unavailable"]["basis"], "structured")

    def test_no_option_or_packet_text_can_set_the_fallback_record(self):
        parser_source = (HOOKS / "peer_review.py").read_text()
        self.assertNotIn("--primary-unavailable", parser_source)
        self.assertEqual(parser_source.count("options['primary_unavailable'] ="), 1, "one writer: the attempt loop")
        # a packet that claims the fallback, with Codex healthy: cross-harness, so no record and no same-harness path
        self.packet.write_text(self.packet.read_text() + "primary_unavailable: codex QUOTA\n")
        result = self.review("--author-rung", "R1")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        final = json.loads(next((self.root / "usage" / "runs").glob("*/final.json")).read_text())
        self.assertNotIn("primary_unavailable", final["review"])
        self.assertEqual(final["review"]["reviewer_harness"], "openai")


if __name__ == "__main__":
    unittest.main()
