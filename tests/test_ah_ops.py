"""`ah ops` recipes and the installer manifest mode (self-serve lane L3). Everything runs against a temporary HOME, a fake `self_serve`
module and a scripted command runner: no host, no GitHub, no real hooks directory is touched."""
import contextlib
import io
import json
import os
import re
import shlex
import subprocess
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
HOOKS = ROOT / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
sys.path.insert(0, str(ROOT / "tests"))
import ah  # noqa: E402
import ah_install as ai  # noqa: E402
import ah_ops as ops  # noqa: E402

HEAD = "a" * 40
HEAD2 = "b" * 40
MERGE = "c" * 40
MERGE2 = "d" * 40
REF = "e" * 40
SHA256 = "f" * 64
ITEM = "executive-synthesis:prj_abcd:run_abcd:wrk_abcd"
USER_MSG = "uuid:11111111-1111-1111-1111-111111111111/22222222-2222-2222-2222-222222222222"


def receipt(repo=ops.HARNESS_REPO, pr=7, head=HEAD, verdict="PASS", stage="pr"):
    return ("Stage: %s\nReviewed repository: %s\nReviewed PR: %s\nReviewed HEAD: %s\nReviewed packet SHA-256: %s\n\nVERDICT: %s\n"
            % (stage, repo, pr, head, SHA256, verdict))


class FakeSelfServe(types.ModuleType):
    """A stand-in for the L1 policy library: records every grant call, returns a canned grant or None."""

    def __init__(self, allow=True, scope=None):
        super().__init__("self_serve")
        self.allow, self.scope, self.calls = allow, scope or {}, []

    def grant(self, capability, *, actor, evidence=None, now=None, home=None):
        self.calls.append((capability, actor, evidence))
        if not self.allow:
            return None
        return {"capability": capability, "policy_id": "a1" * 16, "key_id": "b2" * 8, "expires_at": "2099-01-01T00:00:00Z", "scope": self.scope}


class Done(subprocess.CompletedProcess):
    def __init__(self, out="", rc=0, err=""):
        super().__init__([], rc, out, err)


class Fake:
    """Scripted runner: answers gh, ssh, repair-harness and local python3 calls and records every argv."""

    def __init__(self):
        self.calls = []
        self.pr = {7: self.pr_state(HEAD), 8: self.pr_state(HEAD2)}
        self.merge_commits = {7: MERGE, 8: MERGE2}
        self.parent = None  # override the second parent gh api answers
        self.repair_rc = {"--check": 0, "--apply": 0}
        self.ssh_rc = {}
        self.blob = {}
        self.files = {7: [["docs/a.md", None], ["tests/test_a.py", None]], 8: [["docs/b.md", None], ["tests/test_b.py", None]]}

    @staticmethod
    def pr_state(head, **kw):
        out = {"state": "OPEN", "isDraft": False, "headRefOid": head, "baseRefName": "main", "mergeCommit": None, "changedFiles": 2,
               "statusCheckRollup": [{"__typename": "CheckRun", "name": "ci", "status": "COMPLETED", "conclusion": "SUCCESS"}]}
        out.update(kw)
        return out

    def words(self):
        return [" ".join(c) for c in self.calls]

    def __call__(self, argv, input=None, timeout=None):
        self.calls.append(list(argv))
        prog = os.path.basename(argv[0])
        if prog == "gh" and argv[1:3] == ["pr", "view"]:
            return Done(json.dumps(self.pr[int(argv[3])]))
        if prog == "gh" and argv[1:3] == ["pr", "merge"]:
            pr = int(argv[3])
            self.pr[pr] = dict(self.pr[pr], state="MERGED", mergeCommit={"oid": self.merge_commits[pr]})
            return Done("")
        if prog == "gh" and argv[1] == "api" and "--paginate" in argv:
            pr = int(re.search(r"/pulls/(\d+)/files", " ".join(argv)).group(1))
            return Done("".join(json.dumps(row) + "\n" for row in self.files.get(pr, [])))
        if prog == "gh" and argv[1] == "api":
            sha = argv[2].rsplit("/", 1)[1]
            pr = next(n for n, m in self.merge_commits.items() if m == sha)
            return Done((self.parent or self.pr[pr]["headRefOid"]) + "\n")
        if prog == "repair-harness":
            return Done("preview ok\n" if argv[-1] == "--check" else "applied\n", self.repair_rc[argv[-1]])
        if prog == "ssh":
            remote = argv[-1]
            for needle, rc in self.ssh_rc.items():
                if needle in remote:
                    return Done("", rc, "link")
            if "hashlib" in remote:
                names = json.loads(shlex.split(remote)[-1])
                return Done(json.dumps({n: self.blob.get(n, ops.blob_id(b"hook-" + n.encode())) for n in names}))
            if remote.startswith("bash -s"):
                return Done("previous trusted checkout: %s\nadapter: installed\n" % ("9" * 40))
            return Done("")
        return Done("")


class Refusal(Exception):
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


class Base(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ah-ops-")
        self.addCleanup(self.temp.cleanup)
        self.home = Path(os.path.realpath(self.temp.name))
        (self.home / ".agent-harness" / "bin").mkdir(parents=True)
        repair = self.home / ".agent-harness" / "bin" / "repair-harness"
        repair.write_text("#!/bin/sh\n")
        repair.chmod(0o755)
        (self.home / ".claude" / "hooks").mkdir(parents=True)
        self.fake = Fake()
        self.ss = FakeSelfServe()
        for name, value in (("policy_library", lambda: self.ss), ("store_problems", lambda *a, **k: [])):  # seams; the real ones are in Real*
            patch = mock.patch.object(ops, name, value)
            patch.start()
            self.addCleanup(patch.stop)
        env = mock.patch.dict(os.environ, {}, clear=False)
        env.start()
        self.addCleanup(env.stop)
        for key in ("AH_AGENT_ID", "CLAUDE_AGENT_ID"):
            os.environ.pop(key, None)
        self.rpath = self.home / "receipt-7.md"
        self.rpath.write_text(receipt())
        self.rpath8 = self.home / "receipt-8.md"
        self.rpath8.write_text(receipt(repo=ops.T2SCAN_REPO, pr=8, head=HEAD2))
        # canonical-main proof and blob source are patched at the one seam (`_fetch`)
        self.listed = ["ah.py", "ah_ops.py", "central_decisions.py", "ah_install.py", "self_serve.py", "command_guard.py"]
        self.proof_ok = True
        for name in self.listed:
            (self.home / ".claude" / "hooks" / name).write_bytes(b"hook-" + name.encode())
        patcher = mock.patch.object(ops, "_fetch", self.fetch)
        patcher.start()
        self.addCleanup(patcher.stop)

    def fetch(self, ctx, ref, names):
        if not self.proof_ok:
            ops.refuse("canonical-main proof failed: not an ancestor", "not_on_main")
        return ({n: (b"", ops.blob_id(b"hook-" + n.encode()), "100644") for n in names}, self.listed, "9" * 40)

    def run_ops(self, *argv):
        return ops.run(list(argv), self.home, runner=self.fake, sleep=lambda s: None)

    def refused(self, *argv, code=None):
        """A refusal is an OpsError (bad input, before the journal) or a stopped report (ok False, with the code and the reason)."""
        try:
            report = self.run_ops(*argv)
        except ops.OpsError as error:
            if code:
                self.assertEqual(error.code, code)
            return error
        self.assertFalse(report["ok"], report)
        if code:
            self.assertEqual(report["code"], code)
        return Refusal(report["code"], report["reason"])

    def merged_calls(self):
        return [w for w in self.fake.words() if " pr merge " in " " + w + " "]

    def journal_rows(self, run):
        return ops.Journal(self.home, run).rows()


class GrantGate(Base):
    def test_no_grant_refuses_merge_apply_and_names_the_user_step(self):
        self.ss.allow = False
        error = self.refused("merge", "--pr", "7", "--receipt", str(self.rpath), "--apply", code="no_grant")
        self.assertIn("ah_enable_self_serve.py --apply", str(error))
        self.assertIn("Nothing was changed", str(error))
        self.assertEqual(self.merged_calls(), [])  # reads only: the PR, its files; the grant is asked last, right before the merge

    def test_missing_self_serve_library_is_no_grant(self):
        with mock.patch.object(ops, "policy_library", mock.Mock(side_effect=ImportError("not installed"))):
            self.refused("repair", "--ref", REF, "--apply", code="no_grant")
        self.assertEqual([w for w in self.fake.words() if "repair-harness" in w and w.endswith("--apply")], [])

    def test_grant_that_raises_is_no_grant(self):
        self.ss.grant = mock.Mock(side_effect=RuntimeError("boom"))
        self.refused("merge", "--pr", "7", "--receipt", str(self.rpath), "--apply", code="no_grant")

    def test_grant_for_another_capability_is_refused(self):
        self.ss.grant = lambda capability, **kw: {"capability": "pool_cleanup"}
        self.refused("merge", "--pr", "7", "--receipt", str(self.rpath), "--apply", code="no_grant")

    def test_helper_agent_never_reaches_the_policy_library(self):
        os.environ["AH_AGENT_ID"] = "helper-1"
        self.refused("merge", "--pr", "7", "--receipt", str(self.rpath), "--apply", code="no_grant")
        self.assertEqual(self.ss.calls, [])  # NEG-10

    def test_actor_facts_reach_the_library(self):
        self.run_ops("merge", "--pr", "7", "--receipt", str(self.rpath), "--apply")
        capability, actor, evidence = self.ss.calls[0]
        self.assertEqual(capability, "merge_reviewed_pr")
        self.assertEqual(evidence, {"repo": ops.HARNESS_REPO, "pr": 7, "head": HEAD, "changed_paths": ["docs/a.md", "tests/test_a.py"],
                                    "use_key": "%s#7@%s" % (ops.HARNESS_REPO, HEAD)})
        self.assertIn("pid", actor)

    def test_check_mode_needs_no_grant_and_changes_nothing(self):
        self.ss.allow = False
        out = self.run_ops("merge", "--pr", "7", "--receipt", str(self.rpath))
        self.assertTrue(out["ok"])
        self.assertEqual(out["mode"], "check")
        self.assertEqual(self.merged_calls(), [])
        self.assertEqual(self.ss.calls, [])


class Merge(Base):
    def apply(self, **kw):
        return self.run_ops("merge", "--pr", "7", "--receipt", str(self.rpath), "--apply")

    def test_merges_at_the_reviewed_head_and_checks_the_second_parent(self):
        out = self.apply()
        self.assertTrue(out["ok"], out)
        call = self.merged_calls()[0]
        self.assertIn("--match-head-commit " + HEAD, call)
        self.assertIn("--merge", call)
        self.assertNotIn("--admin", call)
        self.assertEqual(out["steps"]["merge"]["merge_commit"], MERGE)

    def test_receipt_for_another_head_refuses_before_any_merge(self):
        self.rpath.write_text(receipt(head=HEAD2))
        self.assertIn("is not the PR head", str(self.refused("merge", "--pr", "7", "--receipt", str(self.rpath), "--apply", code="receipt")))
        self.assertEqual(self.merged_calls(), [])

    def test_block_verdict_stage_and_repo_mismatch_refuse(self):
        for text in (receipt(verdict="BLOCK"), receipt(stage="code-inspection"), receipt(repo="x/y"), receipt(pr=9)):
            self.rpath.write_text(text)
            self.refused("merge", "--pr", "7", "--receipt", str(self.rpath), "--apply", code="receipt")
        self.assertEqual(self.merged_calls(), [])

    def test_failing_pending_or_missing_checks_block(self):
        for rollup in ([{"__typename": "CheckRun", "name": "ci", "status": "COMPLETED", "conclusion": "FAILURE"}],
                       [{"__typename": "CheckRun", "name": "ci", "status": "IN_PROGRESS", "conclusion": None}],
                       [{"__typename": "StatusContext", "context": "x", "state": "PENDING"}], []):
            self.fake.pr[7] = Fake.pr_state(HEAD, statusCheckRollup=rollup)
            self.refused("merge", "--pr", "7", "--receipt", str(self.rpath), "--apply", code="checks")
        self.assertEqual(self.merged_calls(), [])

    def test_only_the_signed_scope_may_allow_a_pr_without_checks(self):
        self.fake.pr[7] = Fake.pr_state(HEAD, statusCheckRollup=[])
        self.ss.scope = {"allow_no_checks": True}
        self.assertTrue(self.apply()["ok"])

    def test_draft_and_non_main_base_refuse(self):
        self.fake.pr[7] = Fake.pr_state(HEAD, isDraft=True)
        self.refused("merge", "--pr", "7", "--receipt", str(self.rpath), "--apply", code="draft")
        self.fake.pr[7] = Fake.pr_state(HEAD, baseRefName="develop")
        self.refused("merge", "--pr", "7", "--receipt", str(self.rpath), "--apply", code="refused")
        self.assertEqual(self.merged_calls(), [])

    def test_repo_outside_the_grant_scope_refuses(self):
        self.ss.scope = {"repos": ["someone/else"]}
        self.refused("merge", "--pr", "7", "--receipt", str(self.rpath), "--apply", code="out_of_scope")

    def test_merge_whose_second_parent_is_not_the_reviewed_head_fails(self):
        self.fake.parent = "9" * 40
        out = self.apply()
        self.assertFalse(out["ok"])
        self.assertEqual(out["code"], "merge_parent")

    def test_already_merged_pr_is_only_reverified(self):
        self.fake.pr[7] = Fake.pr_state(HEAD, state="MERGED", mergeCommit={"oid": MERGE})
        out = self.apply()
        self.assertTrue(out["ok"])
        self.assertEqual(self.merged_calls(), [])

    def crash_at(self, step, phase):
        def hook(name, when):
            if (name, when) == (step, phase):
                raise OSError("crash")
        return mock.patch.object(ops, "HOOK", hook)

    def test_resume_after_the_merge_only_reverifies_and_asks_nothing(self):
        with self.crash_at("merge", "after"), self.assertRaises(OSError):
            self.apply()
        run = os.listdir(self.home / ".agent-harness" / "work" / "self-serve")[0]
        self.assertEqual(len(self.merged_calls()), 1)
        grants_before = len(self.ss.calls)
        self.ss.allow = False  # revoked meanwhile: nothing is left to change, so the resume only checks the merge
        out = self.run_ops("merge", "--resume", run)
        self.assertTrue(out["ok"])
        self.assertEqual(len(self.merged_calls()), 1)
        self.assertEqual(len(self.ss.calls), grants_before)

    def test_resume_before_the_merge_asks_for_the_grant_again(self):
        with self.crash_at("merge", "before"), self.assertRaises(OSError):
            self.apply()
        run = os.listdir(self.home / ".agent-harness" / "work" / "self-serve")[0]
        self.assertEqual(self.merged_calls(), [])
        self.ss.allow = False  # revoked meanwhile: the resume must not run on the old grant
        self.refused("merge", "--resume", run, code="no_grant")
        self.assertEqual(self.merged_calls(), [])
        self.ss.allow = True
        self.assertTrue(self.run_ops("merge", "--resume", run)["ok"])
        self.assertEqual(len(self.merged_calls()), 1)

    def test_journal_holds_statuses_and_no_secret_text(self):
        out = self.apply()
        text = (Path(out["journal"])).read_text()
        self.assertNotIn("token", text.lower())
        rows = [json.loads(line) for line in text.splitlines()]
        self.assertEqual(rows[0]["event"], "start")
        self.assertEqual(rows[-1], dict(rows[-1], event="end", state="done"))
        self.assertEqual(oct(Path(out["journal"]).stat().st_mode & 0o777), "0o600")

    def test_secret_shaped_failure_text_is_redacted_in_the_journal(self):
        self.assertNotIn("ghp_", ops.scrub("boom ghp_" + "A" * 30 + " Authorization: Bearer abc.def"))
        self.assertIn("[redacted]", ops.scrub("password=hunter2"))


class Repair(Base):
    def test_check_runs_the_ancestor_proof_and_the_preview_only(self):
        out = self.run_ops("repair", "--ref", REF)
        self.assertTrue(out["ok"])
        self.assertEqual(out["mode"], "check")
        self.assertEqual([w.split()[-1] for w in self.fake.words() if "repair-harness" in w], ["--check"])
        self.assertEqual(self.ss.calls, [])

    def test_ref_off_canonical_main_refuses_before_any_repair_call(self):
        self.proof_ok = False
        report = self.run_ops("repair", "--ref", REF, "--apply")
        self.assertFalse(report["ok"])
        self.assertEqual(report["code"], "not_on_main")
        self.assertEqual([w for w in self.fake.words() if "repair-harness" in w], [])
        self.assertEqual(self.ss.calls, [])  # the proof comes before the grant is spent

    def test_apply_needs_the_grant(self):
        self.ss.allow = False
        self.refused("repair", "--ref", REF, "--apply", code="no_grant")
        self.assertEqual([w for w in self.fake.words() if "--apply" in w], [])

    def test_bad_ref_and_host_are_refused(self):
        self.refused("repair", "--ref", "main")
        self.refused("repair", "--ref", REF[:39])
        self.refused("repair", "--ref", REF, "--host", "evil;host")

    def test_apply_runs_preview_apply_and_verify(self):
        out = self.run_ops("repair", "--ref", REF, "--apply")
        self.assertTrue(out["ok"], out)
        self.assertEqual(list(out["steps"]), ["ancestor", "preview", "apply", "verify"])
        self.assertEqual(out["steps"]["apply"]["policy_id"], "a1" * 16)
        self.assertEqual([w.split()[-1] for w in self.fake.words() if "repair-harness" in w], ["--check", "--apply"])
        self.assertEqual(out["steps"]["verify"]["equal"], out["steps"]["verify"]["compared"])

    def test_drift_after_apply_is_reported(self):
        (self.home / ".claude" / "hooks" / "ah.py").write_bytes(b"edited")
        out = self.run_ops("repair", "--ref", REF, "--apply")
        self.assertFalse(out["ok"])
        self.assertEqual(out["code"], "drift")

    def test_failed_apply_is_remote_uncertain_and_never_falls_back_to_a_local_copy(self):  # NEG-12
        self.fake.repair_rc["--apply"] = 2
        out = self.run_ops("repair", "--ref", REF, "--apply")
        self.assertFalse(out["ok"])
        self.assertEqual(out["state"], "uncertain")
        self.assertIn("REMOTE_UNCERTAIN", out["reason"])
        programs = {os.path.basename(c[0]) for c in self.fake.calls}
        self.assertLessEqual(programs, {"repair-harness", "ssh", "gh", "python3", "git"})
        self.assertEqual([w for w in self.fake.words() if w.startswith(("cp ", "scp ", "rsync ", "install "))], [])
        self.assertNotIn("verify", out["steps"])

    def test_timeout_is_uncertain_not_failed(self):
        def slow(argv, input=None, timeout=None):
            raise subprocess.TimeoutExpired(argv, 1)
        with mock.patch.object(self.fake, "__call__", slow, create=True):
            out = ops.run(["repair", "--ref", REF, "--apply"], self.home, runner=slow, sleep=lambda s: None)
        self.assertEqual(out["state"], "uncertain")

    def test_mid_run_failure_resumes_without_repeating_finished_steps(self):  # AC-7
        def crash(step, phase):
            if (step, phase) == ("apply", "before"):
                raise OSError("injected")
        with mock.patch.object(ops, "HOOK", crash):
            with self.assertRaises(OSError):
                self.run_ops("repair", "--ref", REF, "--apply")
        run = os.listdir(self.home / ".agent-harness" / "work" / "self-serve")[0]
        previews = [w for w in self.fake.words() if w.endswith("--check")]
        grants = len(self.ss.calls)
        out = self.run_ops("repair", "--resume", run)
        self.assertTrue(out["ok"], out)
        self.assertEqual(out["steps"]["ancestor"]["state"], "skipped_done")
        self.assertEqual(out["steps"]["preview"]["state"], "skipped_done")
        self.assertEqual(out["steps"]["apply"]["state"], "done")  # the grant is asked again, inside the step that needs it
        self.assertEqual(len(self.ss.calls), grants + 1)
        self.assertEqual([w for w in self.fake.words() if w.endswith("--check")], previews)
        self.assertEqual([w for w in self.fake.words() if w.endswith("--apply")].__len__(), 1)

    def test_resume_takes_the_run_id_only_and_the_right_recipe(self):
        self.run_ops("repair", "--ref", REF)
        run = os.listdir(self.home / ".agent-harness" / "work" / "self-serve")[0]
        self.refused("repair", "--resume", run, "--ref", REF)
        self.refused("merge", "--resume", run)
        self.refused("repair", "--resume", "../../etc")

    def test_unregistered_repair_harness_is_a_user_step(self):
        (self.home / ".agent-harness" / "bin" / "repair-harness").unlink()
        out = self.run_ops("repair", "--ref", REF)
        self.assertFalse(out["ok"])
        self.assertIn("user step", out["reason"])


class Central(Base):
    def args(self, *extra, t2=True):
        a = ["central-decisions", "--harness-pr", "7", "--harness-receipt", str(self.rpath), "--item", ITEM,
             "--user-msg", USER_MSG, "--wal", "/Users/x/.claude/wals/s/main.jsonl"]
        if t2:
            a += ["--t2scan-pr", "8", "--t2scan-receipt", str(self.rpath8)]
        return a + list(extra)

    def test_apply_runs_every_agent_step_then_stops_at_the_users_approve_top(self):  # AC-8
        out = self.run_ops(*self.args("--apply"))
        self.assertTrue(out["ok"], out)
        self.assertEqual(list(out["steps"]), ["grant", "preconditions", "merge_harness", "merge_t2scan", "repair", "verify", "enable", "adapter", "stop"])
        self.assertEqual(out["stopped_before"], "approve-top")
        self.assertEqual(out["user_command"].count("approve-top"), 1)
        self.assertIn("--user-msg " + USER_MSG, out["user_command"])
        self.assertIn(out["task"], out["user_command"])
        self.assertEqual(out["steps"]["adapter"]["previous_head"], "9" * 40)
        self.assertEqual(self.ss.calls[0][0], "central_decisions_agent_steps")
        self.assertEqual([w.split()[-1] for w in self.fake.words() if "repair-harness" in w], ["--check", "--apply"])

    def test_nothing_the_agent_ran_is_an_approval_key_pin_or_publish(self):  # NEG-4
        self.run_ops(*self.args("--apply"))
        everything = "\n".join(self.fake.words())
        for word in ("approve-top", "keygen", "decision pin", "decision publish", "withdraw", "--admin", "waive"):
            self.assertNotIn(word, everything)
        self.assertIn("decision enable", everything)

    def test_choke_point_refuses_the_users_steps_however_they_are_wrapped(self):
        ctx = ops.Context(self.home, self.fake)
        for argv in (["python3", "ah.py", "approve-top", "--task", "t"],
                     ["ssh", "--", "t2-dev", 'python3 "$HOME/.claude/hooks/ah.py" decision publish --task t'],
                     ["ssh", "--", "t2-dev", "python3 ah.py decision   pin --pubkey-file /dev/stdin"],
                     ["python3", "ah.py", "decision", "keygen"], ["gh", "pr", "merge", "1", "--admin"],
                     ["python3", "merge_gate.py", "waive"], ["bash", "-c", "true"], ["gcloud", "secrets", "list"]):
            with self.assertRaises(ops.OpsError) as caught:
                ctx.cmd(argv)
            self.assertEqual(caught.exception.code, "forbidden", argv)
        self.assertEqual(self.fake.calls, [])

    def test_one_item_exactly_and_well_formed(self):
        self.refused("central-decisions", "--harness-pr", "7", "--harness-receipt", str(self.rpath), "--item", "x-synthesis:prj_a:run_b:wrk_c")
        self.refused("central-decisions", "--harness-pr", "7", "--harness-receipt", str(self.rpath))
        self.refused("central-decisions", "--harness-pr", "7", "--harness-receipt", str(self.rpath), "--item", ITEM + ",extra")

    def test_no_grant_stops_before_any_merge(self):
        self.ss.allow = False
        self.refused(*self.args("--apply"), code="no_grant")
        self.assertEqual(self.merged_calls(), [])
        self.assertEqual([w for w in self.fake.words() if "repair-harness" in w], [])

    def test_check_mode_inspects_both_prs_and_changes_nothing(self):
        self.ss.allow = False
        out = self.run_ops(*self.args())
        self.assertTrue(out["ok"], out)
        self.assertEqual(list(out["steps"]), ["preconditions", "merge_harness", "merge_t2scan"])
        self.assertEqual(self.merged_calls(), [])
        self.assertNotIn("user_command", out)

    def test_lost_link_during_enable_is_uncertain(self):
        self.fake.ssh_rc["decision enable"] = 255
        out = self.run_ops(*self.args("--apply"))
        self.assertEqual(out["state"], "uncertain")
        self.assertEqual(out["stopped_at"], "enable")
        self.assertNotIn("adapter", out["steps"])

    def test_resume_after_failure_skips_the_merges_and_finishes(self):
        self.fake.ssh_rc["decision enable"] = 255
        first = self.run_ops(*self.args("--apply"))
        self.fake.ssh_rc.clear()
        out = self.run_ops("central-decisions", "--resume", first["run"])
        self.assertTrue(out["ok"], out)
        self.assertEqual(out["steps"]["merge_harness"]["state"], "skipped_done")
        self.assertEqual(len(self.merged_calls()), 2)
        self.assertEqual(out["stopped_before"], "approve-top")

    def test_without_the_scanner_pr_there_is_no_adapter_step(self):
        out = self.run_ops(*self.args("--apply", t2=False))
        self.assertNotIn("adapter", out["steps"])
        self.assertNotIn("merge_t2scan", out["steps"])

    def test_central_hooks_do_not_name_the_gated_tiers(self):
        import escalation  # the gated-tier pattern lives there; this test never spells the names
        for path in (HOOKS / "ah_ops.py", Path(__file__)):
            self.assertIsNone(escalation.TOP_TERMS.search(path.read_text()), path.name)
            self.assertIsNone(re.search(r"top (rung|model|tier)", path.read_text(), re.I), path.name)


class Cli(Base):
    def call(self, *argv):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), mock.patch.dict(os.environ, {"AH_HOME": str(self.home)}):
            code = ah.main(list(argv))
        return code, out.getvalue()

    def test_ops_is_registered_and_refuses_without_a_grant(self):
        self.ss.allow = False
        code, text = self.call("ops", "repair", "--ref", REF, "--apply")
        self.assertNotEqual(code, 0)
        self.assertEqual(json.loads(text)["code"] == "no_grant" or json.loads(text).get("ok") is False, True)

    def test_ops_check_through_the_real_dispatcher(self):
        with mock.patch.object(ops, "_default_runner", self.fake):
            code, text = self.call("ops", "repair", "--ref", REF)
        self.assertEqual(code, 0, text)
        self.assertTrue(json.loads(text)["ok"])

    def test_ops_doctor_dispatch_says_not_available_until_the_parity_lane_lands(self):
        with mock.patch.dict(sys.modules, {"ah_parity": None}):
            code, text = self.call("ops", "doctor")
        self.assertEqual(json.loads(text)["code"], "not_available")
        self.assertNotEqual(code, 0)

    def test_ops_doctor_dispatches_to_ah_parity_when_present(self):
        parity = types.ModuleType("ah_parity")
        parity.doctor = lambda rest, home: {"ok": True, "args": rest}
        with mock.patch.dict(sys.modules, {"ah_parity": parity}):
            code, text = self.call("ops", "doctor", "--probe")
        self.assertEqual(json.loads(text), {"ok": True, "args": ["--probe"]})

    def test_bad_arguments_are_one_json_refusal(self):
        code, text = self.call("ops", "merge", "--pr", "x")
        self.assertNotEqual(code, 0)
        self.assertEqual(json.loads(text)["code"], "bad_arguments")

    def test_install_files_accepts_manifest_flag(self):
        args = ah.build_parser().parse_args(["install-files", "--host", "t2-dev", "--from-ref", REF, "--manifest", "--dry-run"])
        self.assertTrue(args.manifest)


# ----------------------------------------------------------------------------- the installer's manifest mode
import test_ah_install as tai  # noqa: E402


class ManifestMode(tai.Base):
    def setUp(self):
        super().setUp()
        self.ss = FakeSelfServe()
        for name, value in (("policy_library", lambda: self.ss), ("store_problems", lambda *a, **k: [])):  # seams; the real ones are in Real*
            patch = mock.patch.object(ops, name, value)
            patch.start()
            self.addCleanup(patch.stop)
        for key in ("AH_AGENT_ID", "CLAUDE_AGENT_ID"):
            os.environ.pop(key, None)

    HEALTHY = {"guard": {"allow": {"exit": 0, "verdict": "allow", "rule": ""}, "deny_wal": {"exit": 0, "verdict": "block", "rule": "x"},
                         "deny_hooks_copy": {"exit": 0, "verdict": "block", "rule": "y"}}, "doctor": {"flags": True, "failing": []}}

    def runner(self, argv, input=None, capture_output=True, timeout=None, **kw):
        """The installer test's fake ssh, except that the host self-test (about a minute of real guard probes) answers a fixed healthy
        result: these tests are about WHICH files are installed and WHO may install them, not about the self-test."""
        if re.search(r" selftest '\{\}'\s*$", argv[-1]):
            self.calls.append(list(argv))
            return Done(json.dumps(self.HEALTHY))
        return super().runner(argv, input=input, capture_output=capture_output, timeout=timeout, **kw)

    def manifest(self, dry_run=False, **kw):
        return ai.install_files("t2-dev", kw.pop("ref", self.c1), None, kw.pop("ticket", tai.TICKET), dry_run, self.mac, "sess", "agent-x",
                                self.runner, lambda t, text: None, manifest=True)

    def test_dry_run_lists_every_manifest_file_and_needs_no_grant(self):
        self.ss.allow = False
        out = self.manifest(dry_run=True, ticket=None)
        self.assertEqual(sorted(out["files"]), sorted(tai.NAMES))
        self.assertEqual(self.ss.calls, [])

    def test_real_manifest_install_without_a_grant_changes_nothing(self):
        self.ss.allow = False
        before = {n: self.live(n) for n in tai.NAMES}
        with self.assertRaises(ai.InstallError) as caught:
            self.manifest()
        self.assertEqual(caught.exception.code, "no_grant")
        self.assertIn("ah_enable_self_serve.py", str(caught.exception))
        self.assertEqual({n: self.live(n) for n in tai.NAMES}, before)
        self.assertEqual(self.calls, [])

    def test_real_manifest_install_with_a_grant_installs_every_listed_file(self):
        out = self.manifest()
        self.assertEqual(out["result"], "installed", out)
        for name in tai.NAMES:
            self.assertEqual(self.live(name), tai.sha(self.base_bytes(name) + b"\n# c1\n"))
        self.assertEqual(self.ss.calls[0][0], "install_files_manifest")
        self.assertTrue(self.rows("start")[-1]["manifest"])

    def test_manifest_cannot_be_combined_with_file_resume_or_rollback(self):
        for kw in ({"files": ["ah.py"]}, {"resume": "ins-0123456789ab"}, {"rollback": "ins-0123456789ab"}):
            with self.assertRaises(ai.InstallError):
                ai.check_inputs("t2-dev", self.c1, kw.get("files"), tai.TICKET, False, kw.get("resume"), kw.get("rollback"), (), False, True)

    def test_resume_of_a_manifest_run_asks_for_the_grant_again(self):
        self.inject = ("commit", 1)
        with self.assertRaises(ai.InstallError):
            self.manifest()
        run = self.rows("start")[-1]["run"]
        self.inject = None
        self.ss.allow = False
        with self.assertRaises(ai.InstallError) as caught:
            ai.resume(run, tai.TICKET, self.mac, "sess", "agent-x", self.runner, lambda t, text: None)
        self.assertEqual(caught.exception.code, "no_grant")

    def test_explicit_file_install_still_needs_no_grant(self):
        self.ss.allow = False
        self.assertEqual(self.install()["result"], "installed")
        self.assertEqual(self.ss.calls, [])


if __name__ == "__main__":
    unittest.main()
