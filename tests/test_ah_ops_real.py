"""`ah ops` against the REAL policy library, the REAL review store and the REAL stamp proof (self-serve lane L3, repair round).

test_ah_ops.py stubs the policy library, so it cannot say whether a grant can be had at all. These tests stub nothing on the grant
path: a signed policy in a temporary HOME, main's PreToolUse stamp written by ah_ops.pretool and claimed by ah_ops.claim_main, the
real self_serve.grant, a real usage store with a settled review FINAL, and merge_gate.pr_pass_evidence. Only the command runner
(gh, ssh, repair-harness) is scripted. The one patched seam is the native-runtime probe, as in the policy library's own tests."""
import hashlib
import json
import os
import shutil
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
HOOKS = ROOT / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
sys.path.insert(0, str(ROOT / "tests"))
import ah_ops as ops  # noqa: E402
import caller_identity as ci  # noqa: E402
import self_serve as ss  # noqa: E402
import usage_guard as guard  # noqa: E402
from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ed25519  # noqa: E402
from test_ah_ops import HEAD, HEAD2, MERGE, REF, Fake  # noqa: E402

SID = "11111111-2222-3333-4444-555555555555"
POLICY_ID = "ab" * 16
REPO = ops.HARNESS_REPO
TOOL_USE = "toolu_01ABCDEFGHIJKLMN"
GATE_FILE = "harness/hooks/merge_gate.py"


def receipt_text(repo=REPO, pr=7, head=HEAD, verdict="VERDICT: PASS"):
    return ("Reviewer: Codex fixture\nStage: pr\nReviewed HEAD: %s\nReviewed repository: %s\nReviewed PR: %s\n"
            "Reviewed packet SHA-256: %s\n\n%s\nF-none\n" % (head, repo, pr, "f" * 64, verdict))


class Env(unittest.TestCase):
    """A throwaway HOME: a signed policy, a pinned key, a main transcript, a scripted runner. Nothing outside it is touched."""

    capabilities = None  # {cap: scope}; default every capability with an empty scope

    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="ah-ops-real-")
        self.addCleanup(tmp.cleanup)
        self.home = Path(os.path.realpath(tmp.name))
        (self.home / ".agent-harness" / "bin").mkdir(parents=True)
        repair = self.home / ".agent-harness" / "bin" / "repair-harness"
        repair.write_text("#!/bin/sh\n")
        repair.chmod(0o755)
        self.claude = self.home / ".claude"
        self.transcript = self.claude / "projects" / "-x" / (SID + ".jsonl")
        self.transcript.parent.mkdir(parents=True)
        self.transcript.write_text("{}\n")
        self.patch(mock.patch.object(ci, "native_deny_reason", return_value=None))  # the policy library's own tests do the same
        env = mock.patch.dict(os.environ, {"CLAUDE_CONFIG_DIR": str(self.claude), "CLAUDE_CODE_SESSION_ID": SID})
        self.patch(env)
        for key in ("AH_AGENT_ID", "CLAUDE_AGENT_ID", "AGENT_HARNESS_USAGE_DIR", "PYTHONPATH") + tuple(k for k in os.environ if k.startswith("CODEX_")):
            os.environ.pop(key, None)
        ops._PROOF.clear()
        self.addCleanup(ops._PROOF.clear)
        self.key = ed25519.Ed25519PrivateKey.generate()
        self.pub = self.key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.install_policy(self.capabilities)
        self.fake = Fake()
        self.fake.files = {7: [["docs/a.md", None], ["tests/test_a.py", None]], 8: [["docs/b.md", None], ["tests/test_b.py", None]]}
        self.counter = 0

    def patch(self, patcher):
        patcher.start()
        self.addCleanup(patcher.stop)

    # --- the signed policy
    def write(self, path, data):
        Path(path).parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        Path(path).write_bytes(json.dumps(data).encode())
        os.chmod(path, 0o600)

    def install_policy(self, capabilities=None, **over):
        pol = ss.policy_dir(str(self.home))
        pol.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(pol, 0o700)
        caps = {c: {"scope": (capabilities or {}).get(c, {}), "ttl_seconds": None} for c in (capabilities or ss.CAPABILITIES)}
        body = {"schema": "self-serve/1", "purpose": "self-serve", "policy_id": POLICY_ID, "key_id": ss.key_id_of(self.pub),
                "issued_at": ss.iso(__import__("time").time() - 3600), "expires_at": ss.iso(__import__("time").time() + 86400),
                "capabilities": caps, "disabled": []}
        body.update(over)
        self.write(ss.pubkeys_path(str(self.home)), {"schema": "self-serve-pubkeys/1", "keys": [ss.public_record(self.pub)]})
        self.write(ss.policy_path(str(self.home)), ss.sign_policy(body, self.key))

    # --- main's stamp, written by the hook half and claimed by the process half
    def hook_payload(self, command, **over):
        payload = {"tool_name": "Bash", "tool_input": {"command": command}, "session_id": SID, "transcript_path": str(self.transcript),
                   "tool_use_id": TOOL_USE}
        payload.update(over)
        return payload

    def as_main(self, *argv):
        """Main's hook sees the command, then the process claims the stamp: the real two halves of the proof."""
        command = "python3 ~/.claude/hooks/ah.py " + " ".join(argv)
        written = ops.pretool(self.hook_payload(command), home=self.home)
        ops.claim_main(list(argv), self.home)
        return written

    def run_ops(self, *argv, main=True):
        if main:
            self.as_main(*argv)
        try:
            return ops.run(list(argv[1:]), self.home, runner=self.fake, sleep=lambda s: None)  # ah.py hands `ops` the words after it
        finally:
            ops._PROOF.clear()

    def refused(self, *argv, main=True, code=None):
        try:
            report = self.run_ops(*argv, main=main)
        except ops.OpsError as error:
            if code:
                self.assertEqual(error.code, code, str(error))
            return error
        self.assertFalse(report["ok"], report)
        if code:
            self.assertEqual(report["code"], code, report)
        return SimpleNamespace(code=report["code"], message=report["reason"])

    def merged_calls(self):
        return [w for w in self.fake.words() if " pr merge " in " " + w + " "]

    def grant_rows(self):
        path = ss.audit_path(str(self.home))
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    # --- a real review store with a settled independent PASS FINAL
    def add_review(self, text, repo=REPO, pr=7, head=HEAD, settle=True, **changes):
        data = text.encode() if isinstance(text, str) else text
        self.counter += 1
        base = self.home / ("evidence-%d" % self.counter)
        work = base / "repo"
        work.mkdir(parents=True)
        store = guard.UsageStore(self.home / ".agent-harness" / "usage")
        subject = guard.Subject(schema=1, fingerprint="e" * 64, reusable=True, head=head, tree="f" * 40)
        subject.repo, subject.manifest = work, {}
        subject.probe = lambda: subject
        invocation = guard.invocation_identity(subject, purpose="peer-review-pr", argv=["peer_review", "pr", str(self.counter)],
                                               cwd=work, stage="PR", provider="codex")
        run = store.begin(subject, invocation, owner="fixture", label="peer-review-pr", timeout=10, kind="review", minimum_bytes=0)
        metadata = {"stage": "PR", "verdict": "ACCEPT", "findings": [], "repo": repo, "pr": pr, "head": head,
                    "report_sha256": hashlib.sha256(data).hexdigest(), "reviewer": "Codex fixture", "reviewer_harness": "openai",
                    "author_harness": "claude"}
        metadata.update(changes)
        reference = run.finish(execution="COMPLETED", result="CHECK_OK", reason="NONE", exit_code=0, review=metadata,
                               usage={"provider_launches": 1, "reported": [], "executables": {}})
        if settle:
            store.settle_review(reference)
        return reference

    def receipt(self, name="receipt-7.md", text=None, review=True, **kw):
        text = text if text is not None else receipt_text(**{k: v for k, v in kw.items() if k in ("repo", "pr", "head", "verdict")})
        path = self.home / name
        path.write_text(text)
        if review:
            self.add_review(text, **{k: v for k, v in kw.items() if k in ("repo", "pr", "head", "settle")})
        return str(path)

    def merge_args(self, path, pr="7", extra=("--apply",)):
        return ("ops", "merge", "--pr", pr, "--receipt", path) + tuple(extra)


class RealGrant(Env):
    """Finding 1: the acceptance flow works against the real library, and its refusals are the library's."""

    def test_main_with_a_stamp_gets_the_grant_and_merges(self):
        path = self.receipt()
        out = self.run_ops(*self.merge_args(path))
        self.assertTrue(out["ok"], out)
        self.assertEqual(len(self.merged_calls()), 1)
        step = out["steps"]["merge"]
        self.assertEqual(step["policy_id"], POLICY_ID)
        self.assertEqual(step["key_id"], ss.key_id_of(self.pub))
        rows = self.grant_rows()
        self.assertEqual([(r["event"], r["capability"], r["actor"]) for r in rows], [("grant", "merge_reviewed_pr", "claude_main")])

    def test_the_real_dispatcher_claims_the_stamp_before_parsing(self):
        import contextlib
        import io

        import ah
        path = self.receipt()
        argv = self.merge_args(path)
        ops.pretool(self.hook_payload("python3 ~/.claude/hooks/ah.py " + " ".join(argv)), home=self.home)
        out = io.StringIO()
        with contextlib.redirect_stdout(out), mock.patch.dict(os.environ, {"AH_HOME": str(self.home)}), \
                mock.patch.object(ops, "_default_runner", self.fake):
            code = ah.main(list(argv))
        self.assertEqual(code, 0, out.getvalue())
        self.assertEqual(len(self.merged_calls()), 1)
        out = io.StringIO()
        self.fake.pr[7] = Fake.pr_state(HEAD)
        with contextlib.redirect_stdout(out), mock.patch.dict(os.environ, {"AH_HOME": str(self.home)}), \
                mock.patch.object(ops, "_default_runner", self.fake):
            code = ah.main(list(argv))  # no stamp this time: the same command is refused
        self.assertNotEqual(code, 0)
        self.assertEqual(json.loads(out.getvalue())["code"], "no_grant")
        self.assertEqual(len(self.merged_calls()), 1)

    def test_actor_facts_carry_a_kind_and_a_payload_main_can_prove_only_with_a_stamp(self):
        self.assertNotIn("kind", ops.actor_facts(home=self.home))
        self.as_main("ops", "merge", "--pr", "7", "--receipt", "r.md", "--apply")
        facts = ops.actor_facts(home=self.home)
        self.assertEqual(facts["kind"], "claude_main")
        self.assertEqual(facts["payload"], {"session_id": SID, "transcript_path": str(self.transcript)})
        self.assertTrue(ci.is_main(facts["payload"], facts["claude_dir"]))
        self.assertNotIn("agent_id", facts["payload"])

    def test_without_a_stamp_there_is_no_grant_even_when_the_helper_variable_is_absent(self):  # finding 4
        path = self.receipt()
        self.assertTrue(all(k not in os.environ for k in ("AH_AGENT_ID", "CLAUDE_AGENT_ID")))
        self.refused(*self.merge_args(path), main=False, code="no_grant")
        self.assertEqual(self.merged_calls(), [])
        self.assertEqual(self.grant_rows(), [])  # the library was asked and said no; it never granted

    def test_a_helper_subagent_gets_no_stamp_and_so_no_grant(self):  # NEG-10
        path = self.receipt()
        argv = self.merge_args(path)
        command = "python3 ~/.claude/hooks/ah.py " + " ".join(argv)
        for extra in ({"agent_id": "a1"}, {"agent_type": "general"}):
            self.assertEqual(ops.pretool(self.hook_payload(command, **extra), home=self.home), 0, extra)
        ops.claim_main(list(argv), self.home)
        self.refused(*argv, main=False, code="no_grant")
        self.assertEqual(self.merged_calls(), [])

    def test_a_stamp_is_for_one_exact_command_and_one_use(self):
        path = self.receipt()
        argv = self.merge_args(path)
        ops.pretool(self.hook_payload("python3 ~/.claude/hooks/ah.py " + " ".join(argv)), home=self.home)
        ops.claim_main(list(argv) + ["--check"], self.home)  # another command: nothing to claim
        self.assertNotIn("kind", ops.actor_facts(home=self.home))
        ops.claim_main(list(argv), self.home)
        self.assertEqual(ops.actor_facts(home=self.home)["kind"], "claude_main")
        ops._PROOF.clear()
        ops.claim_main(list(argv), self.home)  # already taken
        self.assertNotIn("kind", ops.actor_facts(home=self.home))

    def test_no_stamp_for_a_command_the_shell_computes_or_that_only_mentions_ah(self):
        for command in ('echo python3 ah.py ops merge --apply', 'python3 ~/.claude/hooks/ah.py ops merge --pr $N --apply',
                        'grep ops ~/.claude/hooks/ah.py', 'python3 ~/.claude/hooks/ah.py status --apply'):
            self.assertEqual(ops.pretool(self.hook_payload(command), home=self.home), 0, command)

    def test_a_stamp_for_a_call_that_has_ended_is_dead(self):
        path = self.receipt()
        argv = self.merge_args(path)
        ops.pretool(self.hook_payload("python3 ~/.claude/hooks/ah.py " + " ".join(argv)), home=self.home)
        with open(self.transcript, "a") as handle:  # the tool_result of that call lands in main's transcript
            handle.write(json.dumps({"tool_use_id": TOOL_USE}) + "\n")
        ops.claim_main(list(argv), self.home)
        self.assertNotIn("kind", ops.actor_facts(home=self.home))

    def test_codex_root_is_proved_by_the_library_not_by_a_stamp(self):
        path = self.receipt()
        os.environ.pop("CLAUDE_CODE_SESSION_ID")
        os.environ["CODEX_THREAD_ID"] = "t"
        verified = SimpleNamespace(origin="openai", reason="running_code_verified")
        with mock.patch.object(ss, "_origin_probe", return_value=verified):
            self.assertTrue(self.run_ops(*self.merge_args(path), main=False)["ok"])
        self.assertEqual(self.grant_rows()[-1]["actor"], "codex_root")
        self.fake.pr[7] = Fake.pr_state(HEAD)
        with mock.patch.object(ss, "_origin_probe", return_value=SimpleNamespace(origin="claude", reason="running_claude_code_verified")):
            self.refused(*self.merge_args(path), main=False, code="no_grant")

    def test_policy_denylist_is_enforced_because_the_changed_paths_are_passed(self):
        self.install_policy({"merge_reviewed_pr": {"denylist_paths": ["docs/*"]}})
        path = self.receipt()
        self.refused(*self.merge_args(path), code="no_grant")  # docs/a.md is in the PR; the library says path_denylisted
        self.assertEqual(self.merged_calls(), [])
        self.install_policy({"merge_reviewed_pr": {"denylist_paths": ["secrets/*"]}})
        self.assertTrue(self.run_ops(*self.merge_args(path))["ok"])  # the same scope merges a PR that stays clear of it

    def test_the_floor_refuses_a_gate_file_before_the_grant_is_asked(self):
        self.fake.files[7] = [["docs/a.md", None], [GATE_FILE, None]]
        path = self.receipt()
        error = self.refused(*self.merge_args(path), code="denylisted")
        self.assertIn(GATE_FILE, error.message)
        self.assertEqual(self.merged_calls(), [])
        self.assertEqual(self.grant_rows(), [])

    def test_the_floor_sees_the_old_path_of_a_rename(self):
        self.fake.files[7] = [["docs/new-name.py", "harness/hooks/command_guard.py"], ["docs/a.md", None]]
        self.fake.pr[7] = Fake.pr_state(HEAD, changedFiles=2)
        self.refused(*self.merge_args(self.receipt()), code="denylisted")

    def test_an_unknown_or_short_file_list_fails_closed(self):
        path = self.receipt()
        for files, count in (([], 0), ([["docs/a.md", None]], 2), ([["docs/a.md", None]] * 3, 2)):
            self.fake.files[7] = files
            self.fake.pr[7] = Fake.pr_state(HEAD, changedFiles=count)
            self.refused(*self.merge_args(path), code="no_paths")
        self.assertEqual(self.merged_calls(), [])

    def test_single_use_scope_is_spent_by_the_merge_and_by_nothing_earlier(self):
        self.install_policy({"merge_reviewed_pr": {"single_use": True}})
        path = self.receipt()
        self.fake.pr[7] = Fake.pr_state(HEAD, isDraft=True)
        self.refused(*self.merge_args(path), code="draft")  # refused before the grant: nothing spent
        self.fake.pr[7] = Fake.pr_state(HEAD)
        self.assertTrue(self.run_ops(*self.merge_args(path))["ok"])
        self.fake.pr[7] = Fake.pr_state(HEAD)  # the same head, open again: the key is spent
        self.refused(*self.merge_args(path), code="no_grant")
        self.assertEqual(len(self.merged_calls()), 1)

    def test_resume_of_a_merged_pr_under_a_single_use_scope_only_reverifies(self):
        self.install_policy({"merge_reviewed_pr": {"single_use": True}})
        path = self.receipt()

        def crash(step, phase):
            if (step, phase) == ("merge", "after"):
                raise OSError("crash")
        with mock.patch.object(ops, "HOOK", crash), self.assertRaises(OSError):
            self.run_ops(*self.merge_args(path))
        run = os.listdir(self.home / ".agent-harness" / "work" / "self-serve")[0]
        out = self.run_ops("ops", "merge", "--resume", run)  # the spent key is not asked for again
        self.assertTrue(out["ok"], out)
        self.assertEqual(len(self.merged_calls()), 1)

    def test_central_merges_need_the_merge_capability_and_keep_the_floor(self):
        item = "executive-synthesis:prj_abcd:run_abcd:wrk_abcd"
        hpath = self.receipt("h.md")
        self.install_policy({"central_decisions_agent_steps": {}})  # the recipe's own capability only
        args = ("ops", "central-decisions", "--harness-pr", "7", "--harness-receipt", hpath, "--item", item, "--apply")
        self.refused(*args, code="no_grant")
        self.assertEqual(self.merged_calls(), [])
        self.install_policy({"central_decisions_agent_steps": {}, "merge_reviewed_pr": {}})
        self.fake.files[7] = [["docs/a.md", None], ["scripts/trust-central-decisions.sh", None]]
        self.refused(*args, code="denylisted")
        self.assertEqual(self.merged_calls(), [])


class Receipts(Env):
    """Finding 2: the receipt is believed only when the review store has the matching settled FINAL."""

    def merge(self, path):
        return self.run_ops(*self.merge_args(path))

    def test_a_hand_written_receipt_with_the_right_header_is_refused(self):
        path = self.receipt(review=False)
        self.assertIn("no review store", self.refused(*self.merge_args(path), code="receipt").message)
        self.add_review("some other report")  # a store now exists, but nothing in it names these bytes
        self.assertIn("no settled review FINAL", self.refused(*self.merge_args(path), code="receipt").message)
        self.assertEqual(self.merged_calls(), [])
        self.assertEqual(self.grant_rows(), [])

    def test_a_genuine_receipt_is_accepted(self):
        self.assertTrue(self.merge(self.receipt())["ok"])

    def test_one_changed_byte_breaks_the_binding(self):
        path = self.receipt()
        Path(path).write_text(receipt_text() + " ")
        self.refused(*self.merge_args(path), code="receipt")

    def test_a_final_for_another_head_pr_or_repository_is_refused(self):
        for changes in ({"head": HEAD2}, {"pr": 8}, {"repo": ops.T2SCAN_REPO}):
            with self.subTest(changes=changes):
                text = receipt_text()  # the file says PR 7 at HEAD in the harness repo
                path = self.home / "r.md"
                path.write_text(text)
                self.add_review(text, **changes)
                self.refused(*self.merge_args(str(path)), code="receipt")
        self.assertEqual(self.merged_calls(), [])

    def test_an_unsettled_review_is_refused(self):
        self.refused(*self.merge_args(self.receipt(settle=False)), code="receipt")

    def test_a_same_harness_review_is_refused_by_the_shared_predicate(self):
        text = receipt_text()
        path = self.home / "r.md"
        path.write_text(text)
        self.add_review(text, reviewer="Claude fixture", reviewer_harness="claude")
        self.refused(*self.merge_args(str(path)), code="receipt")

    def test_a_forged_store_named_by_the_environment_is_ignored(self):
        text = receipt_text()
        path = self.home / "r.md"
        path.write_text(text)
        forged = self.home / "forged-home"
        self.add_review("an unrelated report")  # this machine's own store exists, and holds nothing for these bytes
        with mock.patch.dict(os.environ, {"AGENT_HARNESS_USAGE_DIR": str(forged / ".agent-harness" / "usage")}):
            real, self.home = self.home, forged
            try:
                self.add_review(text)  # a perfect FINAL, in a store the caller named
            finally:
                self.home = real
            self.refused(*self.merge_args(str(path)), code="receipt")

    def test_a_block_that_quotes_a_pass_line_is_refused(self):
        head = receipt_text(verdict="VERDICT: BLOCK\nThe author wrote:\nVERDICT: PASS")
        self.assertTrue(ops.receipt_problems(head.encode(), REPO, 7, HEAD))
        self.assertFalse(ops.receipt_problems(receipt_text().encode(), REPO, 7, HEAD))
        self.assertTrue(ops.receipt_problems(receipt_text(verdict="VERDICT: PASS-WITH-TICKETS").encode(), REPO, 7, HEAD))
        path = self.receipt(text=head)
        self.refused(*self.merge_args(path), code="receipt")


class Loader(Env):
    """Finding 3: the policy and gate code load from this file's directory, never from sys.path."""

    def test_a_planted_library_on_the_path_is_never_asked_when_the_real_one_is_missing(self):
        planted = self.home / "planted"
        planted.mkdir()
        marker = self.home / "planted-was-called"
        (planted / "self_serve.py").write_text(
            "def grant(cap, **kw):\n    open(%r, 'w').write('x')\n    return {'capability': cap, 'policy_id': 'a'*32, 'key_id': 'b'*16, 'scope': {}}\n" % str(marker))
        empty = self.home / "empty-hooks"
        empty.mkdir()
        for name in ("native_context.py", "caller_identity.py", "safe_input.py"):
            shutil.copy(HOOKS / name, empty / name)
        saved = sys.modules.pop("self_serve")
        self.addCleanup(sys.modules.__setitem__, "self_serve", saved)
        with mock.patch.object(ops, "LIB_DIR", empty), mock.patch.object(sys, "path", [str(planted)] + sys.path), \
                mock.patch.dict(os.environ, {"PYTHONPATH": str(planted)}):
            with self.assertRaises(ops.OpsError) as caught:
                ops.require_grant("merge_reviewed_pr", home=self.home, actor={"kind": "claude_main"})
        self.assertEqual(caught.exception.code, "no_grant")
        self.assertFalse(marker.exists())
        self.assertNotIn("self_serve", sys.modules)

    def test_a_foreign_module_already_in_sys_modules_is_refused(self):
        fake = SimpleNamespace(grant=mock.Mock(return_value={"capability": "merge_reviewed_pr"}), __file__="/tmp/elsewhere/self_serve.py")
        with mock.patch.dict(sys.modules, {"self_serve": fake}):
            with self.assertRaises(ImportError):
                ops.load_sibling("self_serve")
            with self.assertRaises(ops.OpsError):
                ops.require_grant("merge_reviewed_pr", home=self.home, actor={"kind": "claude_main"})
        fake.grant.assert_not_called()

    def test_a_symlinked_or_writable_or_foreign_file_is_refused(self):
        for make in ("symlink", "writable"):
            with self.subTest(make=make):
                lib = Path(tempfile.mkdtemp(dir=self.home))
                if make == "symlink":
                    (lib / "gadget.py").symlink_to(HOOKS / "caller_identity.py")
                else:
                    shutil.copy(HOOKS / "caller_identity.py", lib / "gadget.py")
                    os.chmod(lib / "gadget.py", 0o666)
                with mock.patch.object(ops, "LIB_DIR", lib), self.assertRaises(ImportError):
                    ops.load_sibling("gadget")
        lib = Path(tempfile.mkdtemp(dir=self.home))
        shutil.copy(HOOKS / "caller_identity.py", lib / "gadget.py")
        with mock.patch.object(ops, "LIB_DIR", lib), mock.patch.object(ops.os, "getuid", return_value=os.getuid() + 1), \
                self.assertRaises(ImportError):
            ops.load_sibling("gadget")

    def test_a_grant_that_is_not_the_contract_is_refused(self):
        good = {"capability": "merge_reviewed_pr", "policy_id": "a" * 32, "key_id": "b" * 16, "expires_at": None, "scope": {}}
        for bad in (dict(good, policy_id=None), dict(good, policy_id="x"), dict(good, key_id="short"), dict(good, scope=None),
                    {"capability": "merge_reviewed_pr", "scope": {}}, "yes"):
            stub = SimpleNamespace(grant=lambda *a, _bad=bad, **k: _bad)
            with mock.patch.object(ops, "policy_library", lambda s=stub: s), self.assertRaises(ops.OpsError):
                ops.require_grant("merge_reviewed_pr", actor={"kind": "claude_main"})
        with mock.patch.object(ops, "policy_library", lambda: SimpleNamespace(grant=lambda *a, **k: good)):
            self.assertEqual(ops.require_grant("merge_reviewed_pr", actor={"kind": "claude_main"}), good)

    def test_the_installer_gate_loads_ops_from_its_own_directory_too(self):
        import ah_install as ai
        planted = self.home / "planted"
        planted.mkdir()
        (planted / "ah_ops.py").write_text("def require_grant(*a, **k):\n    return {}\nHARNESS_REPO = 'x/y'\n")
        saved = sys.modules.pop("ah_ops")
        self.addCleanup(sys.modules.__setitem__, "ah_ops", saved)
        with mock.patch.object(sys, "path", [str(planted)] + sys.path):
            module = ai._ops_module()
        self.assertEqual(os.path.realpath(module.__file__), os.path.realpath(HOOKS / "ah_ops.py"))
        sys.modules["ah_ops"] = SimpleNamespace(__file__=str(planted / "ah_ops.py"))
        with self.assertRaises(ImportError):
            ai._ops_module()


class ManifestGate(Env):
    """The install gate passes the same actor proof and evidence through the real library (the claim is made in ah.main)."""

    def test_manifest_grant_through_the_real_library(self):
        import ah_install as ai
        self.as_main("install-files", "--host", "t2-dev", "--from-ref", REF, "--manifest")
        ai.require_manifest_grant("t2-dev", REF, self.home)
        self.assertEqual([r["capability"] for r in self.grant_rows()], ["install_files_manifest"])
        ops._PROOF.clear()
        with self.assertRaises(ai.InstallError) as caught:  # a second process without a stamp
            ai.require_manifest_grant("t2-dev", REF, self.home)
        self.assertEqual(caught.exception.code, "no_grant")

    def test_manifest_single_use_key_and_resume_key_differ(self):
        import ah_install as ai
        self.install_policy({"install_files_manifest": {"single_use": True}})
        self.as_main("install-files", "--host", "t2-dev", "--from-ref", REF, "--manifest")
        ai.require_manifest_grant("t2-dev", REF, self.home)
        self.as_main("install-files", "--resume", "ins-0123456789ab")
        ai.require_manifest_grant("t2-dev", REF, self.home, resume_of="ins-0123456789ab")
        self.as_main("install-files", "--host", "t2-dev", "--from-ref", REF, "--manifest")
        with self.assertRaises(ai.InstallError):  # the same install again: the key is spent
            ai.require_manifest_grant("t2-dev", REF, self.home)


if __name__ == "__main__":
    unittest.main()
