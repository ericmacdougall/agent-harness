"""Self-serve same-harness fallback review (spec self-serve section 4; AC-4, AC-5, NEG-7, NEG-8, NEG-10).

self_serve.py belongs to another lane, so these tests install a fake `self_serve` module. The contract they pin
(grant(capability, *, actor, evidence, now) -> dict | None, status() -> dict) is the shared one in the lane brief.
"""
import io
import json
import os
import re
import subprocess
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
PATHS = ["docs/readme.md", "tests/test_foo.py"]
PR_BASE = "8" * 40
DROP = object()  # a review-metadata value that removes the key
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
        "changed_paths": list(PATHS), "changed_paths_sha256": paths_digest(PATHS),
        # the paths are the whole PR: the diff from the PR merge-base (GitHub's own compare answer), which is also the
        # reviewer's snapshot base, and the list equals GitHub's PR file list
        "pr_base_oid": PR_BASE, "merge_base": BASE, "snapshot_base": BASE, "paths_basis": "merge-base+github-files"}
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


class LiveGh(fixture.FakeGh):
    """The merge gate's fake gh plus GitHub's PR file list (pulls/N/files, 100 per page)."""

    def __init__(self, scenario, files):
        super().__init__(scenario)
        self.files = list(files)
        self.files_error = False
        self.files_calls = 0

    def __call__(self, args, timeout, cwd=None):
        joined = " ".join(args)
        if args[:1] == ["api"] and "/pulls/5/files" in joined:
            self.files_calls += 1
            if self.files_error:
                return 1, "", "gh: HTTP 500"
            page = int(re.search(r"&page=(\d+)", joined).group(1))
            rows = self.files[(page - 1) * 100:page * 100]
            return 0, json.dumps([{"filename": p, "status": "modified"} for p in rows]), ""
        return super().__call__(args, timeout, cwd)


class FallbackBase(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.state = self.root / "state"
        self.counter = 0
        self.live_files = list(PATHS)
        self.gh = None
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
                    "reviewer_harness": "claude", "author_harness": "claude", "snapshot_base": BASE}
        metadata.update(review_changes or {})
        metadata = {k: v for k, v in metadata.items() if v is not DROP}
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
        gh = self.gh = LiveGh(fixture.SCENARIOS[scenario], self.live_files)
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

    # Finding 2 (the path policy is a class, not a list of names): two independent layers, tested separately.
    # Layer 1, the allowlist: a path that is not docs, tests or named by the grant's allow_paths needs a
    # cross-harness review, whatever its name. Layer 2, the control-file denylist: these names refuse even when the
    # grant allows every path, so a broken deny pattern cannot hide behind the default-deny of layer 1.
    CONTROL = (
        "harness/hooks/merge_gate.py", "harness/hooks/command_guard_hook.py", "harness/hooks/self_serve.py",
        "harness/hooks/peer_review.py", "harness/hooks/ah.py", "ah.py", "deliver.py", "spec_flow.py",
        "provenance.py", "wal_note.py", "run_probe.py", "spec_policy.json", "commit_policy.json",
        "model_tiers.json", "provenance_policy.json", "settings.json", ".claude/settings.json",
        "settings.local.json", "hooks.json", "CLAUDE.md", "docs/CLAUDE.md", "AGENTS.md", "SKILL.md",
        "skills/x/SKILL.md", ".claude/commands/x.md", ".codex/config.toml", "install.sh", "scripts/install.sh",
        "deploy/release.sh", "deploy/ci.txt", "bin/tool", "Dockerfile", "Makefile", ".github/CODEOWNERS",
        ".github/workflows/ci.yml", "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
        "requirements.txt", "poetry.lock", "pyproject.toml", "Cargo.lock", "go.sum", "Gemfile.lock",
        "src/auth/login.py", "app/oauth_callback.py", "AuthController.ts", "UserAuth.ts", "authentication.py",
        "authorization.py", "permissions.py", "session.py", "jwt.py", "crypto.py", "config/secrets.json",
        "db/migrations/0001_init.sql", ".env", "deploy/.env.prod", "scripts/gen_key.sh", "keys/dev.pem",
        "x/ed25519.py", "Credentials.kt", "passwords.txt", "tokenizer.py", "mcp.json", ".mcp.json")
    BAD_SHAPE = ("a/../b.py", "/etc/passwd", "./docs/a.md", "docs//a.md", "docs/a.md/", "docs\\..\\a.md", "")

    def test_neg8_control_files_refuse_even_when_the_grant_allows_every_path(self):
        self.ss.result["scope"] = {"allow_paths": [".*"]}
        for path in self.CONTROL + self.BAD_SHAPE:
            paths = ["docs/ok.md", path]
            self.refused(path or "<empty>", "cross-harness review", block=good_block(
                changed_paths=paths, changed_paths_sha256=paths_digest(paths)))
        self.assertEqual(mg.fallback_denied_paths(list(self.CONTROL), allow_patterns=[".*"]), list(self.CONTROL))

    def test_neg8_unknown_paths_refuse_by_default_and_a_grant_names_the_source_dirs(self):
        unknown = ("src/app.py", "lib/util.js", "harness/foo.py", "main.go", "config/app.yaml", "src/monkeypatch.py")
        for path in unknown:
            paths = ["docs/ok.md", path]
            self.refused(path, "cross-harness review", block=good_block(
                changed_paths=paths, changed_paths_sha256=paths_digest(paths)))
        self.assertEqual(mg.fallback_denied_paths(list(unknown)), list(unknown))
        self.ss.result["scope"] = {"allow_paths": [r"src/", r"lib/"]}
        paths = ["src/app.py", "main.go"]
        self.refused("outside the named dirs", "cross-harness review", block=good_block(
            changed_paths=paths, changed_paths_sha256=paths_digest(paths)))
        paths = ["docs/ok.md", "src/app.py", "lib/util.js"]
        record = self.mint(block=good_block(changed_paths=paths, changed_paths_sha256=paths_digest(paths)))
        self.assertEqual(record["allow_paths"], [r"src/", r"lib/"])
        # allow patterns are anchored at the start: a nested dir of the same name is not the named dir
        self.assertEqual(mg.fallback_denied_paths(["vendor/src/app.py"], allow_patterns=[r"src/"]), ["vendor/src/app.py"])

    def test_bad_scope_patterns_refuse_with_a_value_error(self):
        for scope in ({"allow_paths": ["("]}, {"deny_paths": ["("]}, {"allow_paths": "src/"}, {"allow_paths": [3]},
                      {"allow_paths": ["a" * 600]}):
            with self.subTest(scope=scope):
                self.ss.result["scope"] = scope
                with self.assertRaises(ValueError):
                    self.mint()

    def test_allowed_paths_are_not_over_blocked(self):
        for path in ("docs/readme.md", "docs/guide/setup.md", "README.md", "CHANGELOG.md", "docs/img/a.png",
                     "tests/test_foo.py", "tests/fixtures/data.json", "src/foo_test.go", "web/app.test.ts"):
            self.assertEqual(mg.fallback_denied_paths([path]), [], path)

    def test_the_review_must_have_seen_the_whole_pr(self):
        """Finding 1 at the gate: the paths are bound to the PR merge-base, which must be the reviewer's snapshot base."""
        other = "7" * 40
        self.refused("snapshot base is not the merge-base", "merge-base", block=good_block(snapshot_base=other))
        self.refused("review metadata disagrees", "merge-base", review_changes={"snapshot_base": other})
        self.refused("review has no snapshot base", "merge-base", review_changes={"snapshot_base": DROP})
        self.refused("no merge-base", "merge-base", block=good_block(merge_base=None))
        self.refused("merge-base not a sha", "merge-base", block=good_block(merge_base="main", snapshot_base="main"))
        self.refused("no PR base", "merge-base", block=good_block(pr_base_oid=None))
        self.refused("paths basis missing", "merge-base", block=good_block(paths_basis=None))
        self.refused("paths basis is the old head^1 diff", "merge-base", block=good_block(paths_basis="snapshot-base"))

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

    # Finding 1 at merge time: whatever the receipt says, the merge gate asks GitHub for the PR's files now.
    def test_live_pr_files_must_equal_the_reviewed_paths(self):
        trailer = self.mint()["merge_trailer"]
        self.live_files = PATHS + ["harness/hooks/merge_gate.py"]  # the PR now changes more than was reviewed
        self.assertEqual(self.decide(trailer=trailer)[0], 2)
        self.live_files = PATHS[:1]                                # or less: the head did not move but the diff did
        self.assertEqual(self.decide(trailer=trailer)[0], 2)
        self.live_files = ["docs/other.md", "tests/test_foo.py"]
        self.assertEqual(self.decide(trailer=trailer)[0], 2)
        self.live_files = list(PATHS)
        self.assertEqual(self.decide(trailer=trailer)[0], 0, "the refused merges did not spend it")

    def test_a_pr_retargeted_to_another_base_after_the_review_is_refused(self):
        """Same head, same receipt, but the PR now carries a denylisted file the reviewer never saw."""
        trailer = self.mint()["merge_trailer"]
        self.live_files = ["docs/readme.md", "tests/test_foo.py", "harness/hooks/settings.json"]
        code, text = self.decide(trailer=trailer)
        self.assertEqual(code, 2, text)

    def test_unreadable_pr_files_fail_closed_and_do_not_spend_the_record(self):
        trailer = self.mint()["merge_trailer"]
        scenario = fixture.SCENARIOS["green_protection_unreadable"]
        for label, change in (("error", lambda gh: setattr(gh, "files_error", True)),
                              ("too many", lambda gh: setattr(gh, "files", ["docs/f%d.md" % i for i in range(450)]))):
            with self.subTest(label):
                gh = LiveGh(scenario, PATHS)
                change(gh)
                command = "gh pr merge 5 --match-head-commit %s --body '%s'" % (HEAD, trailer)
                self.assertEqual(mg.decide(fixture.bash(command), gh, self.state)[0], 2)
        self.assertEqual(self.decide(trailer=trailer)[0], 0)

    def test_the_files_call_is_only_for_fallback_records(self):
        """A merge that no fallback record covers makes no extra gh call (other suites see no new traffic)."""
        self.decide()
        self.assertEqual(self.gh.files_calls, 0)
        self.mint()
        self.decide()  # a record could apply, so GitHub's list is read once (to name a trailer that will work)
        self.assertEqual(self.gh.files_calls, 1)

    def test_a_fallback_record_is_unusable_without_a_live_file_list(self):
        """Every caller must supply GitHub's live list; one that does not gets no authorization (fail closed)."""
        record = self.mint()
        records = mg._read_waivers(self.state)
        now = time.time()
        args = (records, "o/r", 5, HEAD, now)
        self.assertIsNone(mg._active(*args, command=record["merge_trailer"]))
        self.assertIsNone(mg._active(*args, command=record["merge_trailer"], live_paths="not callable"))
        self.assertIsNone(mg.pending_fallback_trailer(self.state, "o/r", 5, HEAD, now))
        self.assertIsNone(mg._active(*args, command=record["merge_trailer"], live_paths=lambda: PATHS + ["ah.py"]))
        self.assertEqual(mg._active(*args, command=record["merge_trailer"], live_paths=lambda: list(PATHS))["id"],
                         record["id"], "control: the same call with the reviewed list is usable")

    def test_live_paths_use_the_same_policy_as_the_mint(self):
        """The contract: every name the mint refuses, the merge-time check refuses too, and vice versa."""
        names = list(RefusalTests.CONTROL) + list(RefusalTests.BAD_SHAPE) + ["src/app.py", "main.go"]
        good = ["docs/readme.md", "tests/test_foo.py", "README.md"]
        record = {"changed_paths_sha256": paths_digest(good)}
        self.assertTrue(mg.fallback_live_paths_ok(record, good))
        for name in names:
            live = good + [name]
            with self.subTest(name):
                self.assertTrue(mg.fallback_denied_paths(live), "the mint-time policy refuses it")
                self.assertFalse(mg.fallback_live_paths_ok({"changed_paths_sha256": paths_digest(live)}, live))
        self.assertFalse(mg.fallback_live_paths_ok(record, None))
        self.assertFalse(mg.fallback_live_paths_ok(record, []))
        self.assertFalse(mg.fallback_live_paths_ok({}, good))

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


class FakeGitHub:
    """GitHub as peer_review sees it: the PR view, the compare answer and the PR file list, nothing else."""

    def __init__(self, base_oid, merge_base, files, head=None):
        self.base_oid, self.merge_base, self.files, self.head = base_oid, merge_base, list(files), head
        self.calls = []
        self.fail = None

    def __call__(self, args, timeout, cwd=None):
        args = list(args)
        self.calls.append(args)
        joined = " ".join(args)
        if self.fail:
            return 1, "", "gh: " + self.fail
        if args[:2] == ["pr", "view"]:
            return 0, json.dumps({"baseRefOid": self.base_oid, "headRefOid": self.head, "state": "OPEN"}), ""
        if args[:1] == ["api"] and "/compare/" in joined:
            assert self.base_oid + "..." in joined, joined
            return 0, json.dumps({"sha": self.merge_base}), ""
        if args[:1] == ["api"] and "/pulls/5/files" in joined:
            page = int(re.search(r"&page=(\d+)", joined).group(1))
            rows = self.files[(page - 1) * 100:page * 100]
            return 0, json.dumps([row if isinstance(row, dict) else {"filename": row} for row in rows]), ""
        raise AssertionError("unexpected gh call: " + joined)


class BuildBlockTests(unittest.TestCase):
    """build_fallback_block against a real two-commit PR, with GitHub faked. Finding 1: the denylist must see the
    whole PR, not the head^1..head view a snapshot base can narrow."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name) / "repo"
        self.repo.mkdir()
        self.git("init", "-q", "-b", "main")
        self.write("README.md", "one\n")
        self.base = self.commit("base")          # the PR merge-base (main's tip)
        self.write("harness/hooks/merge_gate.py", "# the PR changes the gate here\n")
        self.first = self.commit("first commit touches the gate")
        self.write("README.md", "two\n")
        self.head = self.commit("last commit edits only the README")
        self.files = ["README.md", "harness/hooks/merge_gate.py"]

    def git(self, *args):
        env = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.com", GIT_COMMITTER_NAME="t",
                   GIT_COMMITTER_EMAIL="t@example.com", GIT_CONFIG_GLOBAL="/dev/null", GIT_CONFIG_SYSTEM="/dev/null")
        done = subprocess.run(["git", "-C", str(self.repo), *args], capture_output=True, text=True, env=env)
        self.assertEqual(done.returncode, 0, done.stderr)
        return done.stdout.strip()

    def write(self, name, text):
        path = self.repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    def commit(self, message):
        self.git("add", "-A")
        self.git("commit", "-q", "-m", message)
        return self.git("rev-parse", "HEAD")

    def options(self, **changes):
        options = {"primary_attempt": {"provider": "codex", "harness": "openai", "result": "NO_RESULT",
                                       "reason": "QUOTA", "launches": 0},
                   "actual_reviewer": "claude", "reviewer_harness": "claude"}
        options.update(changes)
        return options

    def build(self, base=None, files="default", options=None, stage="pr", binding="default", author="claude",
              merge_base="default", github=None):
        github = github or FakeGitHub(PR_BASE, self.base if merge_base == "default" else merge_base,
                                      self.files if files == "default" else files, head=self.head)
        self.github = github
        args = SimpleNamespace(stage=stage, author_harness=author)
        binding = {"repo": "o/r", "pr": 5} if binding == "default" else binding
        selection = {"rung": "R2", "author_unknown": False}
        with mock.patch.object(mg, "SubprocessGh", return_value=github), \
                mock.patch.object(sys, "stderr", new=io.StringIO()) as err:
            block = review.build_fallback_block(args, binding, self.options() if options is None else options,
                                                selection, "R1", PACKET, self.head,
                                                self.base if base is None else base, self.repo)
        self.stderr = err.getvalue()
        return block

    def test_builds_the_block_merge_gate_accepts(self):
        block = self.build()
        self.assertEqual(block["changed_paths"], ["README.md", "harness/hooks/merge_gate.py"],
                         "the whole PR, including the first commit")
        self.assertEqual(block["changed_paths_sha256"], mg.fallback_paths_digest(block["changed_paths"]))
        self.assertEqual((block["merge_base"], block["snapshot_base"], block["pr_base_oid"]),
                         (self.base, self.base, PR_BASE))
        self.assertEqual(block["paths_basis"], "merge-base+github-files")
        self.assertEqual((block["author_rung"], block["reviewer_rung"], block["packet_sha256"]), ("R1", "R2", PACKET))
        self.assertEqual(block["primary"]["launches"], 0)
        self.assertEqual(mg.fallback_denied_paths(block["changed_paths"]), ["harness/hooks/merge_gate.py"],
                         "the first commit's gate file reaches the policy")

    def test_a_denylisted_file_in_an_earlier_commit_is_never_hidden(self):
        """The snapshot base defaults to head^1, which skips the first commit. That must refuse, not mint."""
        block = self.build(base=self.first)
        self.assertIsNone(block, "head^1..head shows only README.md; the PR also changes the gate")
        self.assertIn("--snapshot-base " + self.base, self.stderr, "the refusal names the base to rerun with")

    def test_the_whole_pr_must_match_githubs_file_list(self):
        for label, files in (("github shows fewer", ["README.md"]),
                             ("github shows more", self.files + ["config/other.yaml"]),
                             ("github shows another file", ["README.md", "docs/a.md"]),
                             ("github lists nothing", [])):
            with self.subTest(label):
                self.assertIsNone(self.build(files=files))
                self.assertIn("file list", self.stderr)

    def test_the_snapshot_base_must_be_githubs_merge_base(self):
        self.assertIsNone(self.build(merge_base=self.first), "GitHub says the PR forked later than the snapshot base")
        self.assertIn("merge-base", self.stderr)
        self.assertIsNone(self.build(merge_base="not a sha"))

    def test_a_single_commit_pr_works_with_the_default_base(self):
        self.git("checkout", "-q", "-b", "single", self.base)
        self.write("docs/a.md", "doc\n")
        head = self.commit("single")
        github = FakeGitHub(PR_BASE, self.base, ["docs/a.md"], head=head)
        args = SimpleNamespace(stage="pr", author_harness="claude")
        with mock.patch.object(mg, "SubprocessGh", return_value=github):
            block = review.build_fallback_block(args, {"repo": "o/r", "pr": 5}, self.options(),
                                                {"rung": "R2", "author_unknown": False}, "R1", PACKET, head,
                                                self.base, self.repo)
        self.assertEqual(block["changed_paths"], ["docs/a.md"])
        self.assertEqual(mg.fallback_denied_paths(block["changed_paths"]), [])

    def test_a_renamed_file_counts_under_both_names(self):
        self.git("checkout", "-q", "-b", "rename", self.base)
        self.git("mv", "README.md", "docs_readme.md")
        head = self.commit("rename")
        files = [{"filename": "docs_readme.md", "previous_filename": "README.md", "status": "renamed"}]
        github = FakeGitHub(PR_BASE, self.base, files, head=head)
        args = SimpleNamespace(stage="pr", author_harness="claude")
        with mock.patch.object(mg, "SubprocessGh", return_value=github):
            block = review.build_fallback_block(args, {"repo": "o/r", "pr": 5}, self.options(),
                                                {"rung": "R2", "author_unknown": False}, "R1", PACKET, head,
                                                self.base, self.repo)
        self.assertEqual(block["changed_paths"], ["README.md", "docs_readme.md"])

    def test_github_trouble_never_raises_and_records_nothing(self):
        for label, fail in (("http error", "HTTP 500"), ("not found", "HTTP 404")):
            with self.subTest(label):
                github = FakeGitHub(PR_BASE, self.base, self.files, head=self.head)
                github.fail = fail
                self.assertIsNone(self.build(github=github))
        for label, exc in (("timeout", subprocess.TimeoutExpired(["gh"], 1)), ("os error", OSError("no gh")),
                           ("odd error", RuntimeError("odd"))):
            with self.subTest(label):
                github = mock.Mock(side_effect=exc)
                self.assertIsNone(self.build(github=github))

    def test_a_pr_view_for_another_head_is_refused(self):
        github = FakeGitHub(PR_BASE, self.base, self.files, head="d" * 40)
        self.assertIsNone(self.build(github=github))

    def test_not_a_fallback_run_records_nothing_and_asks_github_nothing(self):
        for label, kwargs in (("no primary attempt", {"options": self.options(primary_attempt=None)}),
                              ("primary was the reviewer", {"options": self.options(actual_reviewer="codex")}),
                              ("cross harness result", {"options": self.options(reviewer_harness="openai")}),
                              ("plan stage", {"stage": "plan"}), ("unbound", {"binding": None}),
                              ("author unknown", {"author": "unknown"})):
            with self.subTest(label):
                self.assertIsNone(self.build(**kwargs))
                self.assertEqual(self.github.calls, [])
        self.assertIsNone(self.build(base=self.head))
        self.assertEqual(self.github.calls, [])

    def test_oversized_pr_records_nothing(self):
        many = ["f%d.md" % i for i in range(review.FALLBACK_PATH_CAP + 1)]
        self.assertIsNone(self.build(files=many))


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
