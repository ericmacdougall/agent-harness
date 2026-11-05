"""deliver.py finish accepts a test_scope-approved focused check (GoodQA #14582); GIT_EDITOR no longer refuses the run."""
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
HOOKS = ROOT / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
sys.path.insert(0, str(ROOT))
import integrate_local as il  # noqa: E402
import test_scope as ts  # noqa: E402
from tests.test_test_scope import give_evidence, make_repo, run  # noqa: E402


def load_deliver():
    spec = importlib.util.spec_from_file_location("deliver_under_test", HOOKS / "deliver.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


deliver = load_deliver()
WHOLE = ["python3", "-m", "unittest", "discover", "-s", "tests"]


class Syntax(unittest.TestCase):
    def test_focused_unittest_shapes(self):
        self.assertEqual(il.focused_unittest(["python3", "-m", "unittest", "tests.test_a", "tests.test_b"]),
                         ["tests.test_a", "tests.test_b"])
        self.assertEqual(il.focused_unittest(["python", "-m", "unittest", "-v", "tests.test_a"]), ["tests.test_a"])
        for bad in (["python3", "-m", "unittest", "tests.test_a\n"], WHOLE, ["python3", "-m", "unittest"], ["python3", "-m", "unittest", "tests.test_a;rm"],
                    ["python3", "-m", "unittest", "tests.test_a", "--failfast"], ["python3", "-m", "unittest", "test_a"],
                    ["python3", "-m", "unittest", "tests.test_a", "tests.test_a"], ["python3", "-c", "x"],
                    ["python3", "-m", "unittest", "tests.helpers"], ["python3", "-m", "unittest", "tests.test_a.Case.test_x"],
                    ["python3", "-m", "unittest", "../tests.test_a"], ["pytest", "tests/test_a.py"],
                    ["python3", "-m", "unittest"] + [f"tests.test_m{i}" for i in range(61)], []):
            self.assertIsNone(il.focused_unittest(bad), bad)

    def test_approved_check_needs_the_explicit_flag_for_focused_commands(self):
        focused = ["python3", "-m", "unittest", "tests.test_a"]
        self.assertFalse(il.approved_check(focused))
        self.assertFalse(il.approved_check(focused, False))
        self.assertTrue(il.approved_check(focused, True))
        self.assertFalse(il.approved_check(["python3", "-m", "unittest", "tests.test_a;x"], True))
        self.assertTrue(il.approved_check(WHOLE))  # whole-suite approvals are unchanged
        self.assertTrue(il.approved_check(WHOLE, True))
        self.assertFalse(il.approved_check(["rm", "-rf", "x"], True))

    def test_integrate_local_refuses_a_focused_check_without_the_flag(self):
        base = [sys.executable, str(HOOKS / "integrate_local.py"), "--repo", "/nonexistent", "--original-branch", "main",
                "--expected-head", "a" * 40, "--source", "feat", "--expected-source-head", "b" * 40,
                "--check", "python3 -m unittest tests.test_a"]
        refused = subprocess.run(base, capture_output=True, text=True, timeout=30)
        self.assertEqual(refused.returncode, 2)
        self.assertIn("outside the approved", refused.stdout + refused.stderr)
        allowed = subprocess.run(base + ["--allow-focused-checks"], capture_output=True, text=True, timeout=30)
        self.assertNotIn("outside the approved", allowed.stdout + allowed.stderr)  # it gets past the gate (and fails later: no repository)

    def test_deliver_parses_focused_only_when_asked(self):
        value = "python3 -m unittest tests.test_a tests.test_b"
        with self.assertRaises(deliver.DeliveryError) as ctx:
            deliver.approved_commands([value])
        self.assertEqual(ctx.exception.status, "BLOCKED_POLICY")
        self.assertEqual(deliver.approved_commands([value], allow_focused=True), [value.split()])
        with self.assertRaises(deliver.DeliveryError):
            deliver.approved_commands(["python3 -m unittest tests.test_a; rm x"], allow_focused=True)
        self.assertEqual(deliver.approved_commands([" ".join(WHOLE)], allow_focused=True), [WHOLE])


class Fixture(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name).resolve()
        self.repo = make_repo(self.dir)
        self.base = run(self.repo, "git", "rev-parse", "HEAD")
        run(self.repo, "git", "checkout", "-q", "-b", "feat")
        (self.repo / "harness" / "hooks" / "a.py").write_text("VALUE = 7\n")
        run(self.repo, "git", "commit", "-q", "-am", "delta to a (b and d import it)")
        self.head = run(self.repo, "git", "rev-parse", "HEAD")
        patcher = mock.patch.dict(os.environ, {"HARNESS_TEST_SCOPE_ROOT": str(self.dir / "store")})
        patcher.start()
        self.addCleanup(patcher.stop)
        self.store = ts.Store(self.dir / "store")
        self.repo_id = ts.repo_context(str(self.repo))["repo_id"]

    def full_run(self, result="pass", head=None):
        head = head or self.head
        give_evidence(self.store, self.repo_id, head, self.dir)
        ts.reserve_full(self.store, self.repo_id, head, "run-full:1")
        ts.finish_full(self.store, self.repo_id, head, result, "900 tests")

    def approve(self, modules):
        return ts.approve_focused(str(self.repo), self.base, self.head,
                                  ["python3", "-m", "unittest", *modules])


class Approve(Fixture):
    REQUIRED = ["tests.test_a", "tests.test_b", "tests.test_d"]

    def test_approved_with_a_passing_full_run_and_every_mapped_test(self):
        self.full_run()
        approval = self.approve(self.REQUIRED)
        self.assertTrue(approval["approved"])
        self.assertEqual(approval["required"], self.REQUIRED)
        self.assertEqual(approval["full_run"]["result"], "pass")
        self.assertEqual(approval["head"], self.head)
        self.assertEqual(self.approve(self.REQUIRED + ["tests.test_c"])["tests"], self.REQUIRED + ["tests.test_c"])

    def test_omitting_a_mapped_test_is_refused_and_names_it(self):
        self.full_run()
        with self.assertRaises(ts.Refused) as ctx:
            self.approve(["tests.test_a", "tests.test_b"])
        self.assertEqual(ctx.exception.code, "scope-incomplete")
        self.assertIn("tests.test_d", ctx.exception.message)

    def test_no_full_run_a_failed_one_or_one_at_another_head_never_approve(self):
        for setup, text in ((lambda: None, "none"), (lambda: self.full_run("fail"), "finished/fail")):
            setup()
            with self.assertRaises(ts.Refused) as ctx:
                self.approve(self.REQUIRED)
            self.assertEqual(ctx.exception.code, "no-full-run")
            self.assertIn(text, ctx.exception.message)
            self.setUp() if text == "none" else None
        # a passing run recorded for the base, not for the frozen head
        self.full_run("pass", head=self.base)
        with self.assertRaises(ts.Refused) as ctx:
            self.approve(self.REQUIRED)
        self.assertEqual(ctx.exception.code, "no-full-run")

    def test_a_reserved_but_unfinished_full_run_does_not_approve(self):
        give_evidence(self.store, self.repo_id, self.head, self.dir)
        ts.reserve_full(self.store, self.repo_id, self.head, "t")
        with self.assertRaises(ts.Refused) as ctx:
            self.approve(self.REQUIRED)
        self.assertEqual(ctx.exception.code, "no-full-run")

    def test_malformed_commands_are_refused(self):
        self.full_run()
        for argv in (["python3", "-m", "unittest", "discover"], ["python3", "-m", "unittest", "tests.test_a; rm x"],
                     ["pytest"], ["python3", "-m", "unittest", "tests.helpers", *self.REQUIRED]):
            with self.assertRaises(ts.Refused) as ctx:
                ts.approve_focused(str(self.repo), self.base, self.head, argv)
            self.assertEqual(ctx.exception.code, "bad-focused-command", argv)

    def test_unreachable_store_refuses_rather_than_approves(self):
        with self.assertRaises(ts.Refused) as ctx:
            ts.approve_focused(str(self.repo), self.base, self.head, ["python3", "-m", "unittest", *self.REQUIRED],
                               call=lambda policy, args: None)
        self.assertEqual(ctx.exception.code, "store-unreachable")

    SUITE = ["python3", "-m", "unittest", "discover", "-s", "tests"]

    def cli(self, *args):
        r = subprocess.run([sys.executable, "-I", str(HOOKS / "test_scope.py"), "--root", str(self.dir / "store"), *args],
                           capture_output=True, text=True, timeout=240,
                           env={**os.environ, "PYTHONPATH": str(self.repo / "harness" / "hooks")})  # the stand-in suite imports a, b, c
        return r.returncode, json.loads(r.stdout)

    def write_test(self, name, body):
        (self.repo / "tests" / name).write_text("import unittest\n\nclass T(unittest.TestCase):\n    def test_x(self):\n"
                                                f"        {body}\n")  # untracked: the tracked tree stays clean

    def test_cli_round_trip_full_get_run_full_and_approve_check(self):
        self.assertEqual(self.cli("full-get", "--repo-id", self.repo_id, "--head", self.head)[0], 1)
        give_evidence(self.store, self.repo_id, self.head, self.dir)
        self.write_test("test_zzok.py", "pass")
        code, data = self.cli("run-full", "--repo", str(self.repo), "--", *self.SUITE)
        self.assertEqual((code, data["finished"]), (0, True))
        code, data = self.cli("full-get", "--repo-id", self.repo_id, "--head", self.head)
        self.assertEqual((code, data["record"]["result"], data["record"]["state"]), (0, "pass", "finished"))
        code, data = self.cli("approve-check", "--repo", str(self.repo), "--base", self.base, "--head", self.head,
                              "--command", "python3 -m unittest " + " ".join(self.REQUIRED))
        self.assertEqual((code, data["approved"]), (0, True))
        code, data = self.cli("run-full", "--repo", str(self.repo), "--", *self.SUITE)
        self.assertEqual((code, data["code"]), (2, "duplicate-full"))  # one full run per head

    def test_a_failing_run_full_records_fail_and_returns_its_exit_code(self):
        give_evidence(self.store, self.repo_id, self.head, self.dir)
        self.write_test("test_zzfail.py", "self.fail('red')")
        code, _ = self.cli("run-full", "--repo", str(self.repo), "--", *self.SUITE)
        self.assertEqual(code, 1)
        self.assertEqual(ts.full_get(self.store, self.repo_id, self.head)["result"], "fail")

    def test_run_full_without_evidence_is_refused(self):
        code, data = self.cli("run-full", "--repo", str(self.repo), "--", *self.SUITE)
        self.assertEqual((code, data["code"]), (2, "no-evidence"))
        self.assertIsNone(ts.full_get(self.store, self.repo_id, self.head))

    def test_run_full_refuses_a_subset_a_dirty_tree_and_records_an_interrupted_run(self):  # review F4
        give_evidence(self.store, self.repo_id, self.head, self.dir)
        for cmd in (["true"], ["python3", "-m", "unittest", "tests.test_a"], [sys.executable, "-c", "pass"]):
            code, data = self.cli("run-full", "--repo", str(self.repo), "--", *cmd)
            self.assertEqual(code, 3, cmd)
            self.assertIn("whole-suite", data["error"])
        (self.repo / "harness" / "hooks" / "a.py").write_text("VALUE = 99\n")  # tracked change: dirty
        code, data = self.cli("run-full", "--repo", str(self.repo), "--", *self.SUITE)
        self.assertEqual(code, 3)
        self.assertIn("not clean", data["error"])
        run(self.repo, "git", "checkout", "-q", "--", "harness/hooks/a.py")
        self.assertIsNone(ts.full_get(self.store, self.repo_id, self.head))  # nothing was reserved by the refusals
        self.write_test("test_zzslow.py", "__import__('time').sleep(30)")
        r = subprocess.run([sys.executable, "-I", str(HOOKS / "test_scope.py"), "--root", str(self.dir / "store"), "run-full",
                            "--repo", str(self.repo), "--", *self.SUITE], capture_output=True, text=True, timeout=120,
                           env={**os.environ, "HARNESS_RUN_FULL_TIMEOUT_S": "2", "PYTHONPATH": str(self.repo / "harness" / "hooks")})
        self.assertNotEqual(r.returncode, 0)
        rec = ts.full_get(self.store, self.repo_id, self.head)
        self.assertEqual((rec["state"], rec["result"]), ("finished", "fail"))  # not left reserved for 12 hours

    def test_no_mapped_tests_refuses_a_focused_check(self):  # review F7
        give_evidence(self.store, self.repo_id, self.head, self.dir)
        ts.reserve_full(self.store, self.repo_id, self.head, "t")
        ts.finish_full(self.store, self.repo_id, self.head, "pass", "ok")
        run(self.repo, "git", "checkout", "-q", "-b", "docsonly", self.base)
        (self.repo / "docs.md").write_text("changed\n")
        run(self.repo, "git", "commit", "-q", "-am", "docs")
        docs_head = run(self.repo, "git", "rev-parse", "HEAD")
        give_evidence(self.store, self.repo_id, docs_head, self.dir)
        ts.reserve_full(self.store, self.repo_id, docs_head, "t2")
        ts.finish_full(self.store, self.repo_id, docs_head, "pass", "ok")
        with self.assertRaises(ts.Refused) as ctx:
            ts.approve_focused(str(self.repo), self.base, docs_head, ["python3", "-m", "unittest", "tests.test_a"])
        self.assertEqual(ctx.exception.code, "no-mapped-tests")


class ScopeFromGitObjects(Fixture):
    """Review F1: the mapping is read from the head's tree, never from whatever is checked out."""

    def setUp(self):
        super().setUp()
        run(self.repo, "git", "checkout", "-q", "-b", "newtest", self.head)
        (self.repo / "harness" / "hooks" / "n.py").write_text("N = 1\n")
        (self.repo / "tests" / "test_n.py").write_text("import n\n")
        run(self.repo, "git", "add", "-A")
        run(self.repo, "git", "commit", "-q", "-m", "add module n and its test")
        self.new_head = run(self.repo, "git", "rev-parse", "HEAD")

    def test_a_test_added_by_the_head_is_required_even_when_the_checkout_is_at_the_baseline(self):
        for checkout in (self.new_head, self.base):
            run(self.repo, "git", "checkout", "-q", "--detach", checkout)
            out = ts.focused_scope(str(self.repo), self.base, self.new_head)
            self.assertIn("test_n", out["tests"], checkout)
            self.assertTrue((self.repo / "tests" / "test_n.py").exists() == (checkout == self.new_head))

    def test_a_dirty_checkout_does_not_change_the_answer(self):
        run(self.repo, "git", "checkout", "-q", "--detach", self.new_head)
        clean = ts.focused_scope(str(self.repo), self.base, self.new_head)
        (self.repo / "tests" / "test_b.py").write_text("# gutted: imports nothing\n")
        (self.repo / "tests" / "test_extra.py").write_text("import a\n")  # untracked
        self.assertEqual(ts.focused_scope(str(self.repo), self.base, self.new_head), clean)

    def test_proof_from_the_baseline_checkout_refuses_a_check_that_omits_the_new_test(self):
        ts.reserve_full  # silence linters: the store is prepared below
        give_evidence(self.store, self.repo_id, self.new_head, self.dir)
        ts.reserve_full(self.store, self.repo_id, self.new_head, "t")
        ts.finish_full(self.store, self.repo_id, self.new_head, "pass", "ok")
        run(self.repo, "git", "checkout", "-q", "--detach", self.base)
        flow = SimpleNamespace(state={"source": str(self.dir / "gone"), "baseline": self.base, "source_head": self.new_head},
                               original=self.repo)
        with self.assertRaises(deliver.DeliveryError) as ctx:
            deliver.focused_proof(flow, [["python3", "-m", "unittest", "tests.test_a", "tests.test_b", "tests.test_d"]])
        self.assertIn("tests.test_n", ctx.exception.message)


class RemoteTarget(Fixture):
    """Review F2: remote mode checks out the merge target, so the focused tests must cover baseline..target."""

    def test_recheck_requires_coverage_of_commits_that_landed_after_the_delta(self):
        run(self.repo, "git", "checkout", "-q", "--detach", self.head)
        (self.repo / "harness" / "hooks" / "c.py").write_text("Y = 11\n")
        run(self.repo, "git", "commit", "-q", "-am", "someone else changed c")
        target = run(self.repo, "git", "rev-parse", "HEAD")
        flow = SimpleNamespace(original=self.repo, state={"baseline": self.base},
                               focused_checks=[{"tests": ["tests.test_a", "tests.test_b", "tests.test_d"]}])
        with self.assertRaises(deliver.DeliveryError) as ctx:
            deliver.focused_recheck(flow, target)
        self.assertIn("tests.test_c", ctx.exception.message)
        flow.focused_checks = [{"tests": ["tests.test_a", "tests.test_b", "tests.test_c", "tests.test_d"]}]
        deliver.focused_recheck(flow, target)  # covered: no error
        deliver.focused_recheck(SimpleNamespace(original=self.repo, state={"baseline": self.base}), target)  # none: no-op

    def test_resolve_baseline_refuses_a_focused_check(self):  # review F3
        state = {"source": str(self.repo), "baseline": self.base, "source_head": self.head, "kit_digest": "x", "phase": "PR_READY"}
        flow = SimpleNamespace(state=state, original=self.repo, load=lambda: state, completed=lambda: None, args=SimpleNamespace())
        manager = mock.MagicMock()
        manager.__enter__.return_value = flow
        args = SimpleNamespace(prepare=[], check=["python3 -m unittest tests.test_a tests.test_b tests.test_d"], kit_file=None,
                               resolve_baseline="a" * 40, resume=False, mode="remote")
        with mock.patch.object(deliver, "Workflow", return_value=manager), mock.patch.object(deliver, "require_check_interpreters"):
            with self.assertRaises(deliver.DeliveryError) as ctx:
                deliver.finish(args)
        self.assertIn("whole-suite", ctx.exception.message)


class ReceiptShape(unittest.TestCase):
    """Review F8: a receipt may carry focused_checks (a list of objects) and nothing else extra."""

    def completed(self, **extra):
        head = "b" * 40
        directory = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(directory, ignore_errors=True))
        os.chmod(directory, 0o700)
        receipt = directory / "receipt.json"
        value = {"schema": 1, "kind": "delivery_receipt", "scope": "s", "task": "t", "generation": "g", "source_head": "a" * 40,
                 "head": head, "mode": "remote", "repository": "r", "pr_number": 7, "checks_digest": "c" * 64,
                 "guard_key": "k", **extra}
        receipt.write_text(json.dumps(value))
        os.chmod(receipt, 0o600)
        state = {"phase": "DELIVERED", "source_head": "a" * 40, "repository": "r", "pr_number": 7, "guard_key": "k",
                 "baseline": "a" * 40, "target": head, "checks_digest": "c" * 64}
        flow = SimpleNamespace(receipt=receipt, state=state, scope="s", task="t", generation="g", original=Path("/o"), branch="main")
        with mock.patch.object(deliver, "snapshot", return_value=head), mock.patch.object(deliver, "ancestry", return_value=True):
            return deliver.Workflow.completed(flow)

    def test_valid_old_and_new_receipts_load_and_malformed_ones_do_not(self):
        self.assertEqual(self.completed()["head"], "b" * 40)
        self.assertEqual(self.completed(focused_checks=[{"approved": True}])["focused_checks"], [{"approved": True}])
        for extra in ({"focused_checks": "text"}, {"focused_checks": [1]}, {"focused_checks": [{}] * 21},
                      {"surprise": 1}, {"focused_checks": [], "surprise": 1}):
            with self.assertRaises(deliver.DeliveryError, msg=str(extra)[:40]):
                self.completed(**extra)


class DeliverProof(Fixture):
    def flow(self):
        return SimpleNamespace(state={"source": str(self.repo), "baseline": self.base, "source_head": self.head},
                               original=self.repo)

    def test_focused_proof_returns_the_approvals(self):
        self.full_run()
        focused = [["python3", "-m", "unittest", "tests.test_a", "tests.test_b", "tests.test_d"]]
        approvals = deliver.focused_proof(self.flow(), focused)
        self.assertEqual(len(approvals), 1)
        self.assertTrue(approvals[0]["approved"])

    def test_focused_proof_refusals_become_blocked_policy(self):
        focused = [["python3", "-m", "unittest", "tests.test_a", "tests.test_b", "tests.test_d"]]
        with self.assertRaises(deliver.DeliveryError) as ctx:  # no full run recorded
            deliver.focused_proof(self.flow(), focused)
        self.assertEqual((ctx.exception.status, ctx.exception.code), ("BLOCKED_POLICY", 2))
        self.assertIn("full run", ctx.exception.message)
        self.full_run()
        with self.assertRaises(deliver.DeliveryError) as ctx:  # omits a mapped test
            deliver.focused_proof(self.flow(), [["python3", "-m", "unittest", "tests.test_a"]])
        self.assertIn("omits tests", ctx.exception.message)

    def test_focused_proof_falls_back_to_the_original_checkout_when_the_source_is_gone(self):
        self.full_run()
        run(self.repo, "git", "checkout", "-q", "--detach", self.base)  # after cleanup the original is NOT at the head
        flow = self.flow()
        flow.state["source"] = str(self.dir / "removed-worktree")
        self.assertEqual(len(deliver.focused_proof(flow, [["python3", "-m", "unittest", "tests.test_a", "tests.test_b",
                                                           "tests.test_d"]])), 1)

    def test_focused_proof_with_no_usable_checkout_is_blocked(self):
        flow = SimpleNamespace(state={"source": None, "baseline": self.base, "source_head": self.head},
                               original=self.dir / "nothing-here")
        with self.assertRaises(deliver.DeliveryError) as ctx:
            deliver.focused_proof(flow, [["python3", "-m", "unittest", "tests.test_a"]])
        self.assertEqual(ctx.exception.status, "BLOCKED_POLICY")

    def test_facts_and_receipt_carry_the_approval_and_old_receipts_still_load(self):
        flow = SimpleNamespace(generation="g", directory=Path("/d"), original=Path("/o"), state={"source_head": self.head})
        self.assertNotIn("focused_checks", deliver.Workflow.facts(flow))
        flow.focused_checks = [{"approved": True}]
        self.assertEqual(deliver.Workflow.facts(flow)["focused_checks"], [{"approved": True}])
        flow.focused_checks = []
        self.assertNotIn("focused_checks", deliver.Workflow.facts(flow))


class FinishWiring(Fixture):
    """finish() proves focused checks after the flow loads and before any delivery step runs."""

    def run_finish(self, check):
        state = {"source": str(self.repo), "baseline": self.base, "source_head": self.head, "kit_digest": "x", "phase": "PR_READY"}
        flow = SimpleNamespace(state=state, original=self.repo, load=lambda: state, completed=lambda: None,
                               args=SimpleNamespace())
        manager = mock.MagicMock()
        manager.__enter__.return_value = flow
        args = SimpleNamespace(prepare=[], check=[check], kit_file=None, resolve_baseline=None, resume=False, mode="remote")
        seen = {}

        def remote(flow_, preparations, checks):
            seen["focused_checks"] = list(flow_.focused_checks)
            seen["checks"] = checks
            return 0
        with mock.patch.object(deliver, "Workflow", return_value=manager), \
                mock.patch.object(deliver, "require_check_interpreters"), \
                mock.patch.object(deliver, "remote_finish", remote):
            return deliver.finish(args), seen

    CMD = "python3 -m unittest tests.test_a tests.test_b tests.test_d"

    def test_no_proof_means_blocked_before_any_delivery_step(self):
        with self.assertRaises(deliver.DeliveryError) as ctx:
            self.run_finish(self.CMD)
        self.assertEqual(ctx.exception.status, "BLOCKED_POLICY")
        self.assertIn("Focused check is not approved", ctx.exception.message)

    def test_with_proof_the_approval_reaches_remote_finish(self):
        self.full_run()
        code, seen = self.run_finish(self.CMD)
        self.assertEqual(code, 0)
        self.assertEqual(len(seen["focused_checks"]), 1)
        self.assertEqual(seen["focused_checks"][0]["full_run"]["result"], "pass")
        self.assertEqual(seen["checks"], [self.CMD.split()])

    def test_whole_suite_checks_need_no_proof_and_record_none(self):
        code, seen = self.run_finish("python3 -m unittest discover -s tests")
        self.assertEqual(code, 0)
        self.assertEqual(seen["focused_checks"], [])


class GitEditor(unittest.TestCase):
    def main_with(self, env, result=0):
        args = SimpleNamespace(phase="finish")
        with mock.patch.object(deliver, "parse_args", return_value=args), \
                mock.patch.object(deliver, "finish", return_value=result) as finish, \
                mock.patch.dict(os.environ, env, clear=False):
            code = deliver.main()
            return code, finish.called, dict(os.environ)

    def test_editor_variables_are_ignored_and_removed_for_children(self):
        code, called, environ = self.main_with({"GIT_EDITOR": "vim", "GIT_SEQUENCE_EDITOR": "vim"})
        self.assertEqual((code, called), (0, True))
        self.assertNotIn("GIT_EDITOR", environ)
        self.assertNotIn("GIT_SEQUENCE_EDITOR", environ)

    def test_routing_variables_still_refuse_and_the_message_names_them(self):
        out = []
        with mock.patch.object(deliver, "report", lambda status, message, **kw: out.append((status, message))):
            code, called, _ = self.main_with({"GIT_DIR": "/x", "GIT_WORK_TREE": "/y"})
        self.assertEqual((code, called), (2, False))
        self.assertEqual(out[0][0], "BLOCKED_POLICY")
        self.assertIn("GIT_DIR", out[0][1])
        self.assertIn("GIT_WORK_TREE", out[0][1])

    def test_store_redirection_variables_are_removed_before_a_real_run(self):  # review F5
        code, called, environ = self.main_with({"HARNESS_TEST_SCOPE_ROOT": "/tmp/x", "HARNESS_TEST_SCOPE_HOST": "evil"})
        self.assertEqual((code, called), (0, True))
        self.assertNotIn("HARNESS_TEST_SCOPE_ROOT", environ)
        self.assertNotIn("HARNESS_TEST_SCOPE_HOST", environ)

    def test_allowed_variables_are_untouched(self):
        code, called, environ = self.main_with({"GIT_AUTHOR_NAME": "t", "GIT_PAGER": "cat"})
        self.assertEqual((code, called), (0, True))
        self.assertEqual(environ["GIT_AUTHOR_NAME"], "t")


if __name__ == "__main__":
    unittest.main()
