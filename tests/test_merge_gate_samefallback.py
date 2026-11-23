"""Self-serve same-harness fallback review (spec self-serve section 4; AC-4, AC-5, NEG-7, NEG-8, NEG-10).

self_serve.py belongs to another lane, so these tests install a fake `self_serve` module. The contract they pin
(grant(capability, *, actor, evidence, now) -> dict | None, status() -> dict) is the shared one in the lane brief.
"""
import json
import sys
import tempfile
import time
import types
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

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
BASE = "9" * 40
REPORT_SHA = "c" * 64
PACKET = "7" * 64
PATHS = ["harness/hooks/foo.py", "docs/readme.md"]
CAP = "same_harness_fallback_review"
ACTOR = {"kind": "main", "proof": "review-auth-stamp", "session": "s1", "harness": "claude"}


def paths_digest(paths):
    return mg.fallback_paths_digest(paths)


def good_block(**changes):
    block = {
        "schema": 1,
        "primary": {"provider": "codex", "harness": "openai", "result": "NO_RESULT", "reason": "QUOTA", "launches": 0},
        "reviewer_actual": "claude", "repo": "o/r", "pr": 5, "head": HEAD, "packet_sha256": PACKET,
        "author_rung": "R1", "reviewer_rung": "R2", "author_unknown": False,
        "isolated_snapshot": True, "fresh_session": True,
        "changed_paths": list(PATHS), "changed_paths_sha256": paths_digest(PATHS)}
    block.update(changes)
    return block


def good_routing(**changes):
    routing = {"requested_mode": "auto", "attempt_order": ["codex", "claude"], "effective_fallback": "claude",
               "actual_reviewer": "claude"}
    routing.update(changes)
    return routing


class FakeSelfServe:
    """Installs a fake self_serve module; records every grant call."""

    def __init__(self):
        self.calls = []
        self.result = {"capability": CAP, "policy_id": "p" * 32, "key_id": "k" * 16, "expires_at": None, "scope": {}}
        self.raises = False
        self.state = {"enabled": True, "policy_id": "p" * 32, "capabilities": [CAP], "disabled": [],
                      "key_id": "k" * 16, "kill_switch": False}
        module = types.ModuleType("self_serve")
        module.grant = self.grant
        module.status = lambda home=None: dict(self.state)
        self.module = module

    def grant(self, capability, *, actor, evidence=None, now=None, home=None):
        self.calls.append((capability, actor, evidence))
        if self.raises:
            raise RuntimeError("boom")
        return dict(self.result) if self.result is not None else None


class FallbackBase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.state = self.root / "state"
        self.counter = 0
        self.ss = FakeSelfServe()
        patcher = mock.patch.dict(sys.modules, {"self_serve": self.ss.module})
        patcher.start()
        self.addCleanup(patcher.stop)

    def final(self, *, block="default", routing="default", review_changes=None, result="CHECK_OK", reason="NONE",
              settle=True, packet=PACKET, usage_extra=None):
        self.counter += 1
        root = self.root / ("evidence-%d" % self.counter)
        repo = root / "repo"
        repo.mkdir(parents=True)
        store = guard.UsageStore(root / "usage")
        subject = guard.Subject(schema=1, fingerprint="e" * 64, reusable=True, head=HEAD, tree="f" * 40)
        subject.repo, subject.manifest = repo, {}
        subject.probe = lambda: subject
        invocation = guard.invocation_identity(
            subject, purpose="peer-review-pr", argv=["peer_review", "pr", str(self.counter)], cwd=repo,
            stage="PR", packet_digest=packet, provider="claude")
        run = store.begin(subject, invocation, owner="fixture", label="peer-review-pr", timeout=10,
                          kind="review", minimum_bytes=0)
        metadata = {"stage": "PR", "verdict": "ACCEPT", "findings": [], "repo": "o/r", "pr": 5, "head": HEAD,
                    "report_sha256": REPORT_SHA, "reviewer": "Claude fixture opus high (rung R2)",
                    "reviewer_harness": "claude", "author_harness": "claude"}
        metadata.update(review_changes or {})
        usage = {"provider_launches": 1, "reported": [], "executables": {},
                 "review_routing": good_routing() if routing == "default" else routing}
        chosen = good_block() if block == "default" else block
        if chosen is not None:
            usage["same_harness_fallback"] = chosen
        usage.update(usage_extra or {})
        reference = run.finish(execution="COMPLETED", result=result, reason=reason, exit_code=0,
                               review=metadata, usage=usage)
        if settle:
            store.settle_review(reference)
        return store, reference

    def mint(self, actor=ACTOR, **changes):
        store, reference = self.final(**changes)
        return mg.add_review_waiver(self.state, reference, store=store, fallback_actor=actor)

    def decide(self, scenario="green_protection_unreadable", command=None, trailer=None):
        gh = fixture.FakeGh(fixture.SCENARIOS[scenario])
        command = command or "gh pr merge 5 --match-head-commit " + HEAD
        if trailer:
            command += " --squash --body '%s'" % trailer
        return mg.decide(fixture.bash(command), gh, self.state)


class AcceptTests(FallbackBase):
    def test_ac4_fixture_receipts_mint_a_fallback_authorization(self):
        record = self.mint()
        self.assertEqual(record["approval_source"], "policy:self-serve-fallback")
        self.assertEqual(record["label"], "SAME_HARNESS_FALLBACK")
        self.assertEqual(record["merge_trailer"].split()[0], "SAME_HARNESS_FALLBACK")
        self.assertEqual((record["repo"], record["pr"], record["head"]), ("o/r", 5, HEAD))
        self.assertEqual((record["policy_id"], record["key_id"]), ("p" * 32, "k" * 16))
        capability, actor, evidence = self.ss.calls[0]
        self.assertEqual((capability, actor), (CAP, ACTOR))
        self.assertEqual(evidence["head"], HEAD)

    def test_merge_needs_the_label_and_receipt_id_and_is_single_use(self):
        record = self.mint()
        code, text = self.decide()
        self.assertEqual(code, 2, "control: a bare merge is not covered")
        self.assertIn(record["merge_trailer"], text, "the block names the trailer main must add")
        code, text = self.decide(trailer="SAME_HARNESS_FALLBACK 0000000000000000")
        self.assertEqual(code, 2, "a wrong receipt id is not covered: " + text)
        code, text = self.decide(trailer=record["merge_trailer"])
        self.assertEqual(code, 0, text)
        self.assertEqual(self.decide(trailer=record["merge_trailer"])[0], 2, "no replay")

    def test_replay_of_the_same_evidence_is_idempotent(self):
        store, reference = self.final()
        first = mg.add_review_waiver(self.state, reference, store=store, fallback_actor=ACTOR)
        second = mg.add_review_waiver(self.state, reference, store=store, fallback_actor=ACTOR)
        self.assertEqual(first["id"], second["id"])
        rows = [r for r in mg._read_waivers(self.state) if r.get("event") == "waive"]
        self.assertEqual(len(rows), 1)

    def test_cross_harness_pass_never_asks_for_a_grant(self):
        store, reference = self.final(review_changes={"reviewer_harness": "openai", "reviewer": "Codex fixture"},
                                      block=None)
        record = mg.add_review_waiver(self.state, reference, store=store, fallback_actor=ACTOR)
        self.assertEqual(record["approval_source"], "settled-review")
        self.assertEqual(self.ss.calls, [])

    def test_grant_expiry_bounds_the_authorization(self):
        now = time.time()
        self.ss.result["expires_at"] = now + 600
        record = self.mint()
        self.assertAlmostEqual(record["expires_at"], now + 600, delta=5)
        with mock.patch.object(mg.time, "time", return_value=now + 900):
            self.assertEqual(self.decide(trailer=record["merge_trailer"])[0], 2)

    def test_expired_grant_mints_nothing(self):
        self.ss.result["expires_at"] = time.time() - 5
        with self.assertRaisesRegex(ValueError, "expired"):
            self.mint()
        self.ss.result["expires_at"] = "not a time"
        with self.assertRaises(ValueError):
            self.mint()

    def test_scope_narrows_repos_and_denylist(self):
        self.ss.result["scope"] = {"repos": ["o/r"], "deny_paths": [r"^docs/"]}
        with self.assertRaisesRegex(ValueError, "paths need"):
            self.mint()
        self.ss.result["scope"] = {"repos": ["o/other"]}
        with self.assertRaisesRegex(ValueError, "scope does not cover"):
            self.mint()
        self.ss.result["scope"] = {"repos": ["O/R"]}
        self.assertEqual(self.mint()["approval_source"], mg.FALLBACK_SOURCE)


class RefusalTests(FallbackBase):
    """AC-5 and NEG-8: every refusal below fails on a build with the corresponding check removed."""

    def refused(self, label, pattern=None, **changes):
        with self.subTest(label):
            with self.assertRaises(ValueError) as caught:
                self.mint(**changes)
            if pattern:
                self.assertRegex(str(caught.exception), pattern)
        self.assertEqual([r for r in mg._read_waivers(self.state) if r.get("event") == "waive"], [])

    def test_no_quota_receipt(self):
        self.refused("no block", "no same-harness fallback receipt", block=None)
        self.refused("transient reason", "QUOTA or AUTH",
                     block=good_block(primary={**good_block()["primary"], "reason": "TRANSIENT_INFRA"}))
        self.refused("timeout reason", "QUOTA or AUTH",
                     block=good_block(primary={**good_block()["primary"], "reason": "TIMEOUT"}))
        self.refused("launched", "zero launches", block=good_block(primary={**good_block()["primary"], "launches": 1}))
        self.refused("launch count not an int", "zero launches",
                     block=good_block(primary={**good_block()["primary"], "launches": False}))
        self.refused("primary produced a result", "QUOTA or AUTH",
                     block=good_block(primary={**good_block()["primary"], "result": "CHECK_OK"}))
        self.refused("wrong harness failed", "QUOTA or AUTH",
                     block=good_block(primary={**good_block()["primary"], "harness": "claude", "provider": "claude"}))
        self.refused("wrong schema", "no same-harness", block=good_block(schema=2))

    def test_receipt_for_another_head_pr_repo_or_packet(self):
        self.refused("head", "another repo, PR, head or packet", block=good_block(head=OTHER))
        self.refused("pr", "another repo", block=good_block(pr=6))
        self.refused("repo", "another repo", block=good_block(repo="o/other"))
        self.refused("packet", "another repo", block=good_block(packet_sha256="8" * 64))
        self.refused("packet missing in invocation", "another repo", packet=None)

    def test_reviewer_must_be_strictly_above_the_author(self):
        self.refused("same rung", "one rung above", block=good_block(reviewer_rung="R1"))
        self.refused("below", "one rung above", block=good_block(author_rung="R2", reviewer_rung="R1"))
        self.refused("unknown rung", "tier table", block=good_block(reviewer_rung="R99"))
        self.refused("author unknown flag", "author rung is unknown", block=good_block(author_unknown=True))
        self.refused("gated rung", "cannot be a fallback", block=good_block(reviewer_rung="R5"))

    def test_routing_must_try_the_other_harness_first(self):
        self.refused("claude first", "routing", routing=good_routing(attempt_order=["claude", "codex"]))
        self.refused("single attempt", "routing", routing=good_routing(attempt_order=["claude"]))
        self.refused("other harness not first", "routing",
                     routing=good_routing(attempt_order=["kimi", "codex", "claude"]))
        self.refused("actual codex", "routing", routing=good_routing(actual_reviewer="codex"))
        self.refused("actual unknown", "routing", routing=good_routing(actual_reviewer=None))
        self.refused("block disagrees with routing", "routing", block=good_block(reviewer_actual="codex"))

    def test_findings_tickets_and_unsettled_evidence(self):
        self.refused("block verdict", "settled independent pure PR PASS", result="CHECK_FAILED", reason="CODE_FINDINGS",
                     review_changes={"verdict": "BLOCK", "findings": ["F1"]})
        self.refused("unsettled", "settled independent pure PR PASS", settle=False)
        self.refused("no launch", "settled independent pure PR PASS", usage_extra={"provider_launches": 0})

    def test_fresh_isolated_review_only(self):
        self.refused("not isolated", "fresh session", block=good_block(isolated_snapshot=False))
        self.refused("not fresh", "fresh session", block=good_block(fresh_session=False))

    def test_changed_paths_are_required_and_bound(self):
        self.refused("none", "changed paths", block=good_block(changed_paths=None))
        self.refused("empty", "changed paths", block=good_block(changed_paths=[], changed_paths_sha256=paths_digest([])))
        self.refused("digest mismatch", "digest", block=good_block(changed_paths_sha256="0" * 64))
        many = ["f%03d.txt" % i for i in range(mg.FALLBACK_MAX_PATHS + 1)]
        self.refused("too many", "too many", block=good_block(changed_paths=many, changed_paths_sha256=paths_digest(many)))

    def test_neg8_denylisted_paths_refuse(self):
        for path in ("harness/hooks/merge_gate.py", "harness/hooks/command_guard_hook.py", "harness/hooks/self_serve.py",
                     "harness/hooks/peer_review.py", "src/auth/login.py", "app/oauth_callback.py",
                     "db/migrations/0001_init.sql", "config/secrets.json", ".env", "deploy/.env.prod",
                     "scripts/gen_key.sh", "keys/dev.pem", ".github/workflows/ci.yml", "x/ed25519.py", "a/../b.py",
                     "/etc/passwd", "ＭＥＲＧＥ＿ＧＡＴＥ.py".replace("ＭＥＲＧＥ＿ＧＡＴＥ", "merge_gate")):
            paths = ["docs/ok.md", path]
            self.refused(path, "cross-harness review", block=good_block(
                changed_paths=paths, changed_paths_sha256=paths_digest(paths)))

    def test_allowed_paths_are_not_over_blocked(self):
        for path in ("docs/readme.md", "harness/hooks/foo.py", "tests/test_foo.py", "README.md", "src/monkeypatch.py"):
            self.assertEqual(mg.fallback_denied_paths([path]), [], path)

    def test_no_grant_means_no_authorization(self):
        for label, setup in (("none", lambda: setattr(self.ss, "result", None)),
                             ("raises", lambda: setattr(self.ss, "raises", True)),
                             ("not a dict", lambda: setattr(self.ss, "result", ["x"])),
                             ("no policy id", lambda: self.ss.result.pop("policy_id")),
                             ("unknown scope key", lambda: self.ss.result.update(scope={"widen": True}))):
            with self.subTest(label):
                self.ss = FakeSelfServe()
                self.setUpModules()
                setup()
                with self.assertRaisesRegex(ValueError, "grant|scope"):
                    self.mint()
        with self.subTest("module absent"):
            with mock.patch.dict(sys.modules, {"self_serve": None}):
                with self.assertRaisesRegex(ValueError, "no self-serve policy"):
                    self.mint()

    def setUpModules(self):
        patcher = mock.patch.dict(sys.modules, {"self_serve": self.ss.module})
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_same_harness_without_fallback_actor_stays_refused(self):
        store, reference = self.final()
        with self.assertRaises(ValueError):
            mg.add_review_waiver(self.state, reference, store=store)
        with self.assertRaises(ValueError):
            mg.pr_pass_evidence(store.inspect(reference))
        self.assertEqual(self.ss.calls, [])


class MergeTimeTests(FallbackBase):
    def test_neg7_failing_pending_or_missing_checks_still_block(self):
        record = self.mint()
        for scenario in ("red_netwatch", "pending_run", "queued_run", "status_pending", "required_missing",
                         "zero_unprotected_workflows"):
            with self.subTest(scenario=scenario):
                self.assertEqual(self.decide(scenario, trailer=record["merge_trailer"])[0], 2)
        self.assertEqual(self.decide(trailer=record["merge_trailer"])[0], 0, "the refused merges did not spend it")

    def test_neg7_hard_reasons_still_block(self):
        record = self.mint()
        trailer = record["merge_trailer"]
        code, _ = self.decide(command="gh pr merge 5 --squash --body '%s'" % trailer)  # no verified head
        self.assertEqual(code, 2)
        code, _ = self.decide(command="gh pr merge 5 --match-head-commit %s --squash --body '%s'" % (OTHER, trailer))
        self.assertEqual(code, 2)
        # a merge that cannot be tied to one PR is hard-blocked (here: a target built at run time)
        code, _ = self.decide(command="gh pr merge $N --match-head-commit %s --body '%s'" % (HEAD, trailer))
        self.assertEqual(code, 2)
        self.assertEqual(self.decide(trailer=trailer)[0], 0, "the refused merges did not spend it")

    def test_neg7_a_compound_command_with_an_unverifiable_second_merge_blocks(self):
        trailer = self.mint()["merge_trailer"]
        code, _ = self.decide(command="gh pr merge 5 --match-head-commit %s --body '%s' && gh pr merge $N" % (HEAD, trailer))
        self.assertEqual(code, 2)

    def test_revoked_disabled_or_replaced_policy_refuses_at_merge_time(self):
        record = self.mint()
        trailer = record["merge_trailer"]
        for label, change in (("kill switch", {"kill_switch": True}), ("disabled", {"disabled": [CAP]}),
                              ("revoked", {"enabled": False}), ("new policy", {"policy_id": "q" * 32}),
                              ("capability gone", {"capabilities": []})):
            with self.subTest(label):
                saved = dict(self.ss.state)
                self.ss.state.update(change)
                self.assertEqual(self.decide(trailer=trailer)[0], 2)
                self.ss.state.clear()
                self.ss.state.update(saved)
        with self.subTest("status raises"):
            self.ss.module.status = mock.Mock(side_effect=RuntimeError("x"))
            self.assertEqual(self.decide(trailer=trailer)[0], 2)
        with self.subTest("module gone"):
            with mock.patch.dict(sys.modules, {"self_serve": None}):
                self.assertEqual(self.decide(trailer=trailer)[0], 2)

    def test_report_text_shows_the_source(self):
        self.mint()
        self.assertIn("policy:self-serve-fallback", mg.report_text(self.state))


class EligibilityTests(unittest.TestCase):
    """peer_review.review_merge_eligible: the first filter; NEG-10 needs the main stamp."""
    BINDING = {"repo": "o/r", "pr": 5}
    PASS = "VERDICT: PASS\nReviewed"

    def args(self, stamp=True, author="claude"):
        return SimpleNamespace(stage="pr", author_harness=author, main_stamp={"purpose": "review-auth"} if stamp else None)

    def test_same_harness_needs_the_fallback_block(self):
        same = {"harness": "claude"}
        self.assertFalse(review.review_merge_eligible(self.args(), self.BINDING, self.PASS, same), "unchanged default")
        self.assertFalse(review.review_merge_eligible(self.args(), self.BINDING, self.PASS, same, None))
        self.assertFalse(review.review_merge_eligible(self.args(), self.BINDING, self.PASS, same, {"schema": 2}))
        self.assertTrue(review.review_merge_eligible(self.args(), self.BINDING, self.PASS, same, {"schema": 1}))

    def test_neg10_no_main_stamp_never_authorizes(self):
        same = {"harness": "claude"}
        self.assertFalse(review.review_merge_eligible(self.args(stamp=False), self.BINDING, self.PASS, same,
                                                      {"schema": 1}))

    def test_fallback_block_never_loosens_the_pure_pass_rules(self):
        same, block = {"harness": "claude"}, {"schema": 1}
        for report in ("VERDICT: BLOCK\nF1: x", "VERDICT: PASS-WITH-TICKETS\nF1: x", "VERDICT: PASS\nF1: open",
                       "KIMI_ADVISORY: ACCEPT\nVERDICT: PASS"):
            with self.subTest(report=report):
                self.assertFalse(review.review_merge_eligible(self.args(), self.BINDING, report, same, block))
        self.assertFalse(review.review_merge_eligible(self.args(), None, self.PASS, same, block))
        self.assertFalse(review.review_merge_eligible(self.args(author="unknown"), self.BINDING, self.PASS, same, block))
        code = SimpleNamespace(stage="code-inspection", author_harness="claude", main_stamp={"purpose": "x"})
        self.assertFalse(review.review_merge_eligible(code, self.BINDING, "CODE_INSPECTION_RESULT: ACCEPT", same, block))

    def test_cross_harness_is_unchanged(self):
        self.assertTrue(review.review_merge_eligible(self.args(), self.BINDING, self.PASS, {"harness": "openai"}))


class BuildBlockTests(unittest.TestCase):
    def options(self, **changes):
        options = {"primary_attempt": {"provider": "codex", "harness": "openai", "result": "NO_RESULT",
                                       "reason": "QUOTA", "launches": 0},
                   "actual_reviewer": "claude", "reviewer_harness": "claude"}
        options.update(changes)
        return options

    def build(self, options=None, paths="docs/a.md\0src/b.py\0", base=BASE, stage="pr", binding="default", author="claude"):
        args = SimpleNamespace(stage=stage, author_harness=author)
        binding = {"repo": "o/r", "pr": 5} if binding == "default" else binding
        selection = {"rung": "R2", "author_unknown": False}
        with mock.patch.object(review, "git", return_value=paths) as git:
            block = review.build_fallback_block(args, binding, self.options() if options is None else options,
                                                selection, "R1", PACKET, HEAD, base, Path("."))
        return block, git

    def test_builds_the_block_merge_gate_accepts(self):
        block, git = self.build()
        self.assertEqual(git.call_args[0][1:], ("diff", "--name-only", "--no-renames", "-z", BASE, HEAD))
        self.assertEqual(block["changed_paths"], ["docs/a.md", "src/b.py"])
        self.assertEqual(block["changed_paths_sha256"], mg.fallback_paths_digest(block["changed_paths"]))
        self.assertEqual((block["author_rung"], block["reviewer_rung"], block["packet_sha256"]), ("R1", "R2", PACKET))
        evidence = {"review": {"head": HEAD}}
        self.assertEqual(mg.fallback_denied_paths(block["changed_paths"]), [])
        self.assertEqual(block["primary"]["launches"], 0)
        del evidence

    def test_not_a_fallback_run_records_nothing(self):
        for label, kwargs in (("no primary attempt", {"options": self.options(primary_attempt=None)}),
                              ("primary was the reviewer", {"options": self.options(actual_reviewer="codex")}),
                              ("cross harness result", {"options": self.options(reviewer_harness="openai")}),
                              ("no base", {"base": None}), ("base is head", {"base": HEAD}),
                              ("plan stage", {"stage": "plan"}), ("unbound", {"binding": None}),
                              ("author unknown", {"author": "unknown"})):
            with self.subTest(label):
                self.assertIsNone(self.build(**kwargs)[0])

    def test_oversized_or_empty_diff_records_no_paths(self):
        many = "".join("f%d\0" % i for i in range(review.FALLBACK_PATH_CAP + 1))
        for raw in (many, ""):
            self.assertIsNone(self.build(paths=raw)[0]["changed_paths"])

    def test_git_failure_records_nothing(self):
        args = SimpleNamespace(stage="pr", author_harness="claude")
        with mock.patch.object(review, "git", side_effect=OSError("x")):
            self.assertIsNone(review.build_fallback_block(
                args, {"repo": "o/r", "pr": 5}, self.options(), {"rung": "R2", "author_unknown": False},
                "R1", PACKET, HEAD, BASE, Path(".")))


class PrimaryAttemptRecording(unittest.TestCase):
    """review_snapshot records what the first-choice reviewer returned, with zero launches only when none started."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.policy = review.tiers.load_policy()
        self.selection = review.tiers.reviewer_for(self.policy, "R1", "claude")
        self.refuse = None
        outer = self

        class Store:
            def acquire_pool(inner, provider, pool, run):
                if provider == "codex" and outer.refuse:
                    raise guard.GuardError(outer.refuse, "pool refused")

            def release_pool(inner, *args, **kwargs):
                pass

        self.options = {
            "reviewer": "auto", "secondary": "default", "selection": self.selection,
            "codex_model": self.policy["rungs"][self.selection["rung"]]["models"]["openai"],
            "claude_model": self.policy["rungs"][self.selection["rung"]]["models"]["claude"],
            "resolutions": {"codex": {"path": "/fixture/codex"}, "claude": {"path": "/fixture/claude"}},
            "store": Store(), "run_record": SimpleNamespace(timeout=60, run_id="fixture", note_child=lambda p: None)}
        self.codex_failure = None

        def run(command, prompt, cwd, timeout, **kwargs):
            provider = Path(command[0]).name
            if provider == "codex":
                return self.codex_failure
            text = "VERDICT: PASS\nFixture reviewed."
            return 0, json.dumps({"type": "result", "is_error": False, "subtype": "success", "result": text}), ""
        patcher = mock.patch.object(review, "run", side_effect=run)
        patcher.start()
        self.addCleanup(patcher.stop)

    def invoke(self):
        return review.review_snapshot(Path(self.tmp.name), HEAD, "pr", "Fixture rules", "Fixture packet", self.options)

    def test_pool_cooldown_is_a_zero_launch_quota_attempt(self):
        self.assertEqual(self.selection["harness"], "openai", "author claude is reviewed by codex first")
        for reason in ("QUOTA", "AUTH"):
            with self.subTest(reason=reason):
                self.refuse = reason
                self.invoke()
                self.assertEqual(self.options["actual_reviewer"], "claude")
                self.assertEqual(self.options["primary_attempt"],
                                 {"provider": "codex", "harness": "openai", "result": "NO_RESULT",
                                  "reason": reason, "launches": 0})

    def test_a_launched_quota_failure_is_not_zero_launch(self):
        record = {"type": "error", "error": {"code": "account_quota_exceeded", "scope": "account"}}
        self.codex_failure = (1, json.dumps(record), "")
        self.invoke()
        attempt = self.options["primary_attempt"]
        self.assertEqual((attempt["reason"], attempt["launches"]), ("QUOTA", 1))

    def test_a_successful_primary_records_no_attempt(self):
        self.codex_failure = (0, "\n".join(json.dumps(r) for r in (
            {"type": "item.completed", "item": {"type": "agent_message", "text": "VERDICT: PASS\nok"}},
            {"type": "turn.completed"})), "")
        self.invoke()
        self.assertNotIn("primary_attempt", self.options)
        self.assertEqual(self.options["actual_reviewer"], "codex")

    def test_followup_ticket_is_best_effort(self):
        waiver = {"id": "mgw-fallback-x", "head": HEAD, "merge_trailer": "SAME_HARNESS_FALLBACK abc"}
        binding = {"repo": "o/r", "pr": 5}
        seen = []

        def ok(argv):
            seen.append(argv)
            return SimpleNamespace(returncode=0, stdout='{"ticket": "GoodQA goodqa#1"}')
        self.assertEqual(review.file_followup_ticket(binding, waiver, runner=ok), "GoodQA goodqa#1")
        self.assertIn("ticket", seen[0])
        self.assertIsNone(review.file_followup_ticket(binding, waiver, runner=lambda a: SimpleNamespace(returncode=1, stdout="")))

        def broken(argv):
            raise OSError("no ah")
        self.assertIsNone(review.file_followup_ticket(binding, waiver, runner=broken))


if __name__ == "__main__":
    unittest.main()
