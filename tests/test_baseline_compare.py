"""deliver.py --baseline-compare (GoodQA #14582): exact-id subset of a complete suite baseline for exactly the pinned HEAD."""
import copy
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
import test_scope as ts  # noqa: E402


def load_deliver():
    spec = importlib.util.spec_from_file_location("deliver_cmp", HOOKS / "deliver.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


deliver = load_deliver()
SHA = "a" * 40
OTHER = "b" * 40
BASE_IDS = ["test_old.Old.test_one", "test_old.Old.test_two", "test_loss.Loss.test_x"]


def report(head=SHA, ran=100, ids=None, **over):
    r = {"schema": 1, "kind": "suite-report", "runner": "suite_report", "runner_version": 1,
         "command": "python3 -m unittest discover -s tests", "whole_suite": True, "start": "tests", "head": head, "clean": True,
         "python": "3.12.3", "host": "dev2", "ran": ran, "skipped": 0, "failing_ids": sorted(BASE_IDS if ids is None else ids),
         "complete": True, "nonce": "n"}
    r.update(over)
    return r


def record(sha=SHA, **over):
    """A baseline record as the store returns it, built through the real recorder."""
    with tempfile.TemporaryDirectory() as d:
        store = ts.Store(d)
        rep = report(head=sha, **over)
        ts.record_suite_baseline(store, "r", rep, "c" * 64)
        return json.loads((Path(d) / "r" / f"baseline-{sha}.json").read_text())


MISSING = object()


def compare(rep=MISSING, rec=MISSING, expected=SHA, checked=SHA):
    return ts.compare_suite(report() if rep is MISSING else rep, record() if rec is MISSING else rec, expected, checked)


class Passes(unittest.TestCase):
    def test_same_subset_fewer_failures_and_more_tests_pass(self):
        for rep in (report(), report(ids=BASE_IDS[:1]), report(ids=[]), report(ran=140), report(ran=100, ids=BASE_IDS)):
            r = compare(rep)
            self.assertTrue(r["ok"], r["problems"])
        r = compare(report(ids=BASE_IDS[:2], ran=120))
        self.assertEqual((r["baseline_sha"], r["baseline_ran"], r["checked_ran"]), (SHA, 100, 120))
        self.assertEqual(r["accepted_failing_ids"], sorted(BASE_IDS[:2]))
        self.assertEqual(r["new_failing_ids"], [])

    def test_the_checked_head_may_differ_from_the_baseline_sha(self):
        self.assertTrue(compare(report(head=OTHER), checked=OTHER)["ok"])  # the merged tree is not the pinned original


class Fails(unittest.TestCase):
    def bad(self, **kw):
        r = compare(**kw)
        self.assertFalse(r["ok"], kw)
        self.assertTrue(r["problems"])
        return " | ".join(r["problems"])

    def test_any_new_failing_test_fails_and_is_named(self):
        text = self.bad(rep=report(ids=BASE_IDS + ["test_new.New.test_regression"]))
        self.assertIn("test_new.New.test_regression", text)
        self.assertEqual(compare(report(ids=["test_new.New.test_regression"]))["new_failing_ids"], ["test_new.New.test_regression"])

    def test_no_baseline_for_exactly_the_pinned_head(self):
        self.assertIn("no baseline", self.bad(rec=None))
        self.assertIn("exactly", self.bad(rec=record(sha=OTHER)))  # a baseline recorded for another commit
        self.assertIn("exactly", self.bad(rec={**record(), "main_sha": OTHER}))
        self.assertIn("exactly", self.bad(rec={**record(), "kind": "control"}))

    def test_baseline_not_recorded_from_a_real_complete_suite_run(self):
        old_style = {k: v for k, v in record().items() if k != "suite"}
        self.assertIn("no suite block", self.bad(rec=old_style))
        for field, value in (("complete", False), ("whole_suite", False), ("clean", False), ("runner", "hand"), ("ran", 0),
                             ("head", OTHER), ("command", "python3 -m pytest"), ("start", "tests/test_a"), ("kind", "x"),
                             ("failing_ids", "not a list"), ("failing_ids", [1, 2]), ("failing_ids", ["a", "a"])):
            rec = record()
            rec["suite"][field] = value
            self.assertFalse(compare(rec=rec)["ok"], (field, value))
        rec = record()
        del rec["suite"]["complete"]
        self.assertFalse(compare(rec=rec)["ok"])

    def test_a_crashed_or_early_stopped_or_smaller_run_fails(self):
        self.assertIn("did not complete", self.bad(rep=report(complete=False)))
        self.assertIn("did not complete", self.bad(rep={k: v for k, v in report().items() if k != "complete"}))
        self.assertIn("fewer than the baseline", self.bad(rep=report(ran=99)))
        self.assertIn("fewer than the baseline", self.bad(rep=report(ran=10, ids=[])))  # a smaller failing set from fewer tests
        self.assertIn("no tests ran", self.bad(rep=report(ran=0, ids=[])))
        self.assertFalse(compare("nonsense")["ok"])
        self.assertFalse(compare({})["ok"])

    def test_a_focused_or_partial_run_is_not_a_whole_suite_run(self):
        for over in (dict(whole_suite=False), dict(command="python3 -m unittest tests.test_a"), dict(start="tests/sub"),
                     dict(command="python3 -m pytest")):
            self.assertIn("whole-suite", self.bad(rep=report(**over)), over)

    def test_ids_match_exactly_never_loosely(self):
        base = "tests.test_a.A.test_x"
        rec = record(ids=[base])
        for near in (base + "2", base[:-1], "TESTS.TEST_A.A.TEST_X", base + " ", " " + base, "test_a.A.test_x", "A.test_x",
                     base + "\n", base.replace("tests.", "tests/"), base + ".sub", "tests.test_a.A.test_x (i=1)"):
            r = compare(rep=report(ids=[near]), rec=rec)
            self.assertFalse(r["ok"], repr(near))
            self.assertEqual(r["new_failing_ids"], [near])
        self.assertTrue(compare(rep=report(ids=[base]), rec=rec)["ok"])

    def test_the_run_must_belong_to_the_checked_checkout(self):
        self.assertIn("different commit", self.bad(rep=report(head=OTHER)))
        self.assertIn("not clean", self.bad(rep=report(clean=False)))
        for bad in (None, [], "x", 5):
            self.assertFalse(compare(rep=bad)["ok"])

    def test_report_not_from_the_runner_is_refused(self):
        for over in (dict(runner="other"), dict(schema=2), dict(kind="hand")):
            self.assertIn("not produced by suite_report", self.bad(rep=report(**over)), over)


class Record(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.store = ts.Store(self.tmp.name)

    def test_only_a_real_complete_whole_suite_report_is_recorded_once(self):
        rec = ts.record_suite_baseline(self.store, "r", report(), "d" * 64)
        self.assertEqual((rec["main_sha"], rec["suite"]["ran"], rec["result"]), (SHA, 100, "fail"))
        self.assertEqual(rec["suite"]["failing_ids"], sorted(BASE_IDS))
        self.assertEqual(ts.baseline_get(self.store, "r", SHA)["suite"]["report_sha256"], "d" * 64)
        with self.assertRaises(ts.Refused) as ctx:
            ts.record_suite_baseline(self.store, "r", report(), "d" * 64)
        self.assertEqual(ctx.exception.code, "baseline-exists")
        for over in (dict(complete=False), dict(whole_suite=False), dict(clean=False), dict(ran=0), dict(runner="x"),
                     dict(head="short"), dict(failing_ids=["a"] * 2)):
            with self.assertRaises(ts.Refused, msg=str(over)) as c2:
                ts.record_suite_baseline(self.store, "r2", report(**over), "d" * 64)
            self.assertEqual(c2.exception.code, "bad-suite-report")
        self.assertIsNone(ts.baseline_get(self.store, "r2", SHA))

    def test_exact_ids_are_stored_untruncated_and_too_many_are_refused(self):
        long_id = "tests.test_x." + "A" * 400 + ".test_y"
        rec = ts.record_suite_baseline(self.store, "r", report(ids=[long_id]), "d" * 64)
        self.assertEqual(rec["suite"]["failing_ids"], [long_id])
        many = [f"tests.test_{i}.T.test_x" for i in range(ts.MAX_IDS + 1)]
        with self.assertRaises(ts.Refused):
            ts.record_suite_baseline(self.store, "r3", report(ids=many), "d" * 64)

    def test_the_old_way_of_recording_never_qualifies(self):
        ts.baseline_record(self.store, "r", SHA, "make test", "pass", {"tests": 900}, [])
        r = compare(rec=ts.baseline_get(self.store, "r", SHA))
        self.assertFalse(r["ok"])
        self.assertIn("no suite block", " ".join(r["problems"]))


def make_repo(base: Path, tests: dict):
    repo = base / "repo"
    (repo / "tests").mkdir(parents=True)
    (repo / "tests" / ".gitkeep").write_text("")
    for name, body in tests.items():
        (repo / "tests" / name).write_text(body)
    env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t"}
    for cmd in (["git", "init", "-q", "-b", "main"], ["git", "add", "-A"], ["git", "commit", "-q", "-m", "base"]):
        subprocess.run(cmd, cwd=repo, check=True, env=env, capture_output=True)
    return repo


def commit_all(repo, msg="change"):
    env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t"}
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True, env=env, capture_output=True)
    subprocess.run(["git", "commit", "-q", "-m", msg], cwd=repo, check=True, env=env, capture_output=True)
    return subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo, capture_output=True, text=True).stdout.strip()


PASS = "import unittest\nclass P(unittest.TestCase):\n    def test_ok(self):\n        pass\n    def test_ok2(self):\n        pass\n"
RED = "import unittest\nclass R(unittest.TestCase):\n    def test_known_red(self):\n        self.fail('known')\n"
NEWRED = "import unittest\nclass N(unittest.TestCase):\n    def test_regression(self):\n        self.fail('new')\n"


def run_runner(repo, out, *extra):
    return subprocess.run([sys.executable, str(HOOKS / "suite_report.py"), "--repo", str(repo), "--out", str(out), *extra],
                          capture_output=True, text=True, timeout=120)


class Runner(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name).resolve()

    def test_report_has_exact_ids_counts_head_and_completion(self):
        repo = make_repo(self.dir, {"test_a.py": PASS, "test_b.py": RED, "test_broken.py": "import nonexistent_module_zz\n"})
        out = self.dir / "r.json"
        r = run_runner(repo, out, "--nonce", "abc")
        self.assertEqual(r.returncode, 0, r.stderr)
        rep = json.loads(out.read_text())
        self.assertEqual((rep["complete"], rep["clean"], rep["whole_suite"], rep["nonce"], rep["start"]), (True, True, True, "abc", "tests"))
        self.assertEqual(rep["head"], subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo, capture_output=True, text=True).stdout.strip())
        self.assertEqual(rep["ran"], 4)  # two passing, one red, one import failure
        self.assertIn("test_b.R.test_known_red", rep["failing_ids"])
        self.assertTrue(any("test_broken" in i for i in rep["failing_ids"]), rep["failing_ids"])
        self.assertEqual(oct(out.stat().st_mode & 0o777), "0o600")
        self.assertEqual(ts._report_problems(rep, "r"), [])

    def test_dirty_tree_is_recorded_as_not_clean_and_never_a_baseline(self):
        repo = make_repo(self.dir, {"test_a.py": PASS})
        (repo / "tests" / "test_a.py").write_text(PASS + "# changed\n")
        out = self.dir / "r.json"
        self.assertEqual(run_runner(repo, out).returncode, 0)
        rep = json.loads(out.read_text())
        self.assertFalse(rep["clean"])
        self.assertTrue(any("clean" in p for p in ts._report_problems(rep, "r")))

    def test_a_crash_or_a_test_that_kills_the_interpreter_leaves_no_report(self):
        repo = make_repo(self.dir, {"test_a.py": PASS, "test_kill.py": "import os, unittest\nclass K(unittest.TestCase):\n"
                                    "    def test_k(self):\n        os._exit(0)\n"})
        out = self.dir / "r.json"
        r = run_runner(repo, out)
        self.assertFalse(out.exists(), "an early-exiting suite must leave no report")
        self.assertEqual(r.returncode, 0)  # the interpreter exited 0 itself: the missing report is what fails the compare
        missing = run_runner(self.dir / "nope", self.dir / "x.json")
        self.assertEqual(missing.returncode, 4)
        self.assertFalse((self.dir / "x.json").exists())

    def test_an_empty_test_dir_reports_zero_tests(self):
        repo = make_repo(self.dir, {})
        out = self.dir / "r.json"
        self.assertEqual(run_runner(repo, out).returncode, 0)
        rep = json.loads(out.read_text())
        self.assertEqual(rep["ran"], 0)
        self.assertFalse(compare(rep=rep | {"head": SHA})["ok"])


class Wiring(unittest.TestCase):
    """configure_compare, run_checks under compare, the receipt and the resolve path."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name).resolve()
        self.addCleanup(deliver.ACTIVE_COMPARE.clear)
        deliver.ACTIVE_COMPARE.clear()

    def args(self, **kw):
        base = dict(baseline_compare=True, use_recorded_baseline=False, resolve_baseline=None, mode="remote", resume=False)
        return SimpleNamespace(**{**base, **kw})

    WHOLE = [deliver.WHOLE_SUITE_ARGV]

    def test_without_the_flag_nothing_is_armed_and_exit_zero_stays_required(self):
        deliver.configure_compare(self.args(baseline_compare=False), self.WHOLE, {"baseline": SHA})
        self.assertEqual(deliver.ACTIVE_COMPARE, {})
        with self.assertRaises(deliver.DeliveryError):
            deliver.configure_compare(self.args(baseline_compare=False, use_recorded_baseline=True), self.WHOLE, {"baseline": SHA})
        repo = make_repo(self.dir, {"test_a.py": PASS})
        failing = [["python3", "-c", "raise SystemExit(1)"]]
        with mock.patch.object(deliver, "run_check", lambda r, c, **k: subprocess.run([sys.executable, *c[1:]], cwd=r)):
            with self.assertRaises(deliver.DeliveryError) as ctx:
                deliver.run_checks(repo, [], failing, 60, self.dir / "checks")
        self.assertIn("check failed", ctx.exception.message)
        self.assertEqual(deliver.checks_digest([], self.WHOLE), deliver.checks_digest([], self.WHOLE))

    def test_every_unsupported_shape_is_refused_before_anything_runs(self):
        state = {"baseline": SHA}
        focused = [["python3", "-m", "unittest", "tests.test_a"]]
        for checks in (focused, [["python3", "-m", "pytest"]], [["pytest"]], [], self.WHOLE * 2,
                       [["python3", "-m", "unittest", "discover", "-s", "tests", "-v"]],
                       [["python3", "-m", "unittest", "discover", "-s", "tests", "-p", "test_a*.py"]]):
            with self.assertRaises(deliver.DeliveryError, msg=str(checks)) as ctx:
                deliver.configure_compare(self.args(), checks, state)
            self.assertEqual(ctx.exception.status, "BLOCKED_POLICY")
            self.assertEqual(deliver.ACTIVE_COMPARE, {})
        for kw, text in ((dict(mode="local"), "remote"),
                         (dict(use_recorded_baseline=True), "resolve-baseline")):
            with self.assertRaises(deliver.DeliveryError, msg=str(kw)) as ctx:
                deliver.configure_compare(self.args(**kw), self.WHOLE, state)
            self.assertIn(text, ctx.exception.message)

    def test_resume_is_allowed_under_compare(self):
        deliver.configure_compare(self.args(resume=True), self.WHOLE, {"baseline": SHA})
        self.assertEqual(deliver.ACTIVE_COMPARE["expected_sha"], SHA)

    def test_expected_sha_is_the_pinned_original_head_or_the_confirmed_baseline(self):
        deliver.configure_compare(self.args(), self.WHOLE, {"baseline": SHA})
        self.assertEqual(deliver.ACTIVE_COMPARE["expected_sha"], SHA)
        deliver.configure_compare(self.args(resolve_baseline=OTHER, mode=None, use_recorded_baseline=True), self.WHOLE, {"baseline": SHA})
        self.assertEqual((deliver.ACTIVE_COMPARE["expected_sha"], deliver.ACTIVE_COMPARE["recorded_only"]), (OTHER, True))
        self.assertNotEqual(deliver.checks_digest([], self.WHOLE), hashlib_digest([], self.WHOLE))

    def end_to_end(self, tests_then, tests_now, rec_override=None, ran_now_extra=None):
        """Record a real baseline at HEAD, change the tree, then run run_checks under compare in the changed checkout."""
        repo = make_repo(self.dir, tests_then)
        store_dir = self.dir / "store"
        env = {**os.environ, "HARNESS_TEST_SCOPE_ROOT": str(store_dir)}
        run = subprocess.run([sys.executable, str(HOOKS / "test_scope.py"), "--root", str(store_dir), "run-baseline", "--repo", str(repo)],
                             capture_output=True, text=True, timeout=180, env=env)
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        base_sha = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo, capture_output=True, text=True).stdout.strip()
        for name, body in tests_now.items():
            (repo / "tests" / name).write_text(body)
        for name in [n for n in tests_then if n not in tests_now]:
            (repo / "tests" / name).unlink()
        commit_all(repo)
        deliver.ACTIVE_COMPARE.update(expected_sha=base_sha, recorded_only=False)
        with mock.patch.dict(os.environ, env), \
                mock.patch.object(deliver, "run_check", lambda r, c, **k: subprocess.run([sys.executable, *c[1:]], cwd=r, capture_output=True)):
            deliver.run_checks(repo, [], self.WHOLE, 120, self.dir / "checks")
        return base_sha

    def test_end_to_end_same_known_failures_pass_and_the_result_is_recorded(self):
        base = self.end_to_end({"test_a.py": PASS, "test_b.py": RED}, {"test_a.py": PASS, "test_b.py": RED, "test_c.py": PASS})
        res = deliver.ACTIVE_COMPARE["result"]
        self.assertEqual((res["baseline_sha"], res["baseline_ran"], res["checked_ran"]), (base, 3, 5))
        self.assertEqual(res["accepted_failing_ids"], ["test_b.R.test_known_red"])
        self.assertEqual(res["source"], "run")
        self.assertTrue(res["helper"]["tree"].endswith(ROOT.name) or res["helper"]["head"])
        self.assertEqual(deliver.Workflow.facts(SimpleNamespace(
            generation="g", directory=Path("/d"), original=Path("/o"), state={"source_head": SHA}, target_overrides=lambda: [],
            policy_waivers=lambda: ([], 0)))["baseline_compare"], res)

    def test_end_to_end_a_new_failure_a_dropped_test_and_a_crash_fail(self):
        with self.assertRaises(deliver.DeliveryError) as ctx:
            self.end_to_end({"test_a.py": PASS, "test_b.py": RED}, {"test_a.py": PASS, "test_b.py": RED, "test_n.py": NEWRED})
        self.assertEqual(ctx.exception.facts["check_status"], "baseline-compare")
        self.assertIn("test_regression", ctx.exception.message)
        self.setUp()
        with self.assertRaises(deliver.DeliveryError) as ctx:  # the red test is "fixed" by deleting a passing file: fewer tests
            self.end_to_end({"test_a.py": PASS, "test_b.py": RED, "test_c.py": PASS}, {"test_b.py": RED})
        self.assertIn("fewer than the baseline", ctx.exception.message)
        self.setUp()
        with self.assertRaises(deliver.DeliveryError) as ctx:  # a test kills the interpreter: no report
            self.end_to_end({"test_a.py": PASS}, {"test_a.py": PASS, "test_k.py": "import os, unittest\nclass K(unittest.TestCase):\n"
                                                  "    def test_k(self):\n        os._exit(0)\n"})
        self.assertIn("no readable suite report", ctx.exception.message)

    def test_a_stale_report_in_the_log_directory_is_never_trusted(self):
        repo = make_repo(self.dir, {"test_a.py": PASS})
        checks = self.dir / "checks"
        checks.mkdir(mode=0o700)
        stale = checks / "suite-report.json"
        stale.write_text(json.dumps(report(head=subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo, capture_output=True, text=True).stdout.strip(),
                                           ids=[], ran=1, nonce="old")))
        os.chmod(stale, 0o600)
        deliver.ACTIVE_COMPARE.update(expected_sha=SHA, recorded_only=False)
        import suite_compare as sc
        with mock.patch.object(deliver, "run_check", lambda r, c, **k: subprocess.CompletedProcess(c, 0)), \
                mock.patch.object(sc, "baseline_record_for", return_value=record()):  # runner "succeeds", writes nothing
            with self.assertRaises(deliver.DeliveryError) as ctx:
                deliver.run_checks(repo, [], self.WHOLE, 60, checks)
        self.assertIn("no readable suite report", ctx.exception.message)

    def record_baseline(self, repo):
        store_dir = self.dir / "store"
        env = {**os.environ, "HARNESS_TEST_SCOPE_ROOT": str(store_dir)}
        run = subprocess.run([sys.executable, str(HOOKS / "test_scope.py"), "--root", str(store_dir), "run-baseline", "--repo", str(repo)],
                             capture_output=True, text=True, timeout=180, env=env)
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        return env, subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo, capture_output=True, text=True).stdout.strip()

    def test_a_report_with_another_runs_nonce_is_refused(self):
        repo = make_repo(self.dir, {"test_a.py": PASS, "test_b.py": RED})
        env, head = self.record_baseline(repo)
        deliver.ACTIVE_COMPARE.update(expected_sha=head, recorded_only=False)

        def fake(r, c, **k):  # a runner that writes a perfectly good report, but with a nonce this run did not issue
            argv = [sys.executable, *c[1:]]
            argv[argv.index("--nonce") + 1] = "not-the-issued-nonce"
            return subprocess.run(argv, cwd=r, capture_output=True)
        with mock.patch.dict(os.environ, env), mock.patch.object(deliver, "run_check", fake):
            with self.assertRaises(deliver.DeliveryError) as ctx:
                deliver.run_checks(repo, [], self.WHOLE, 120, self.dir / "checks")
        self.assertIn("not from this run", ctx.exception.message)

    def test_a_runner_that_exits_non_zero_fails_even_if_it_left_a_good_report(self):
        repo = make_repo(self.dir, {"test_a.py": PASS, "test_b.py": RED})
        env, head = self.record_baseline(repo)
        deliver.ACTIVE_COMPARE.update(expected_sha=head, recorded_only=False)

        def fake(r, c, **k):
            real = subprocess.run([sys.executable, *c[1:]], cwd=r, capture_output=True)
            return subprocess.CompletedProcess(c, 3, real.stdout, real.stderr)
        with mock.patch.dict(os.environ, env), mock.patch.object(deliver, "run_check", fake):
            with self.assertRaises(deliver.DeliveryError) as ctx:
                deliver.run_checks(repo, [], self.WHOLE, 120, self.dir / "checks")
        self.assertIn("crashed or stopped early", ctx.exception.message)

    def test_the_receipt_written_on_delivery_carries_the_compare_result(self):
        written = {}
        flow = SimpleNamespace(
            save=lambda **kw: None, assert_context=lambda: None, scope="s", task="t", generation="g",
            state={"source_head": SHA, "repository": "r", "pr_number": 7, "guard_key": "k"},
            receipt=self.dir / "rec" / "receipt.json", focused_checks=[])
        result = {"baseline_sha": SHA, "baseline_ran": 3, "checked_ran": 5, "accepted_failing_ids": ["x.Y.test_z"], "source": "run"}
        deliver.ACTIVE_COMPARE.update(expected_sha=SHA, result=result)
        with mock.patch.object(deliver, "private_directory", lambda p: None), \
                mock.patch.object(deliver, "write_journal", lambda d, data, first=False: written.update(data)):
            deliver.Workflow.complete(flow, "remote", OTHER, "e" * 64)
        self.assertEqual(written["baseline_compare"], result)
        deliver.ACTIVE_COMPARE.clear()
        written.clear()
        with mock.patch.object(deliver, "private_directory", lambda p: None), \
                mock.patch.object(deliver, "write_journal", lambda d, data, first=False: written.update(data)):
            deliver.Workflow.complete(flow, "remote", OTHER, "e" * 64)
        self.assertNotIn("baseline_compare", written)  # the default path records nothing new

    def test_no_baseline_recorded_for_the_pinned_head_fails_the_delivery_check(self):
        repo = make_repo(self.dir, {"test_a.py": PASS})
        deliver.ACTIVE_COMPARE.update(expected_sha=SHA, recorded_only=False)
        env = {**os.environ, "HARNESS_TEST_SCOPE_ROOT": str(self.dir / "store")}
        with mock.patch.dict(os.environ, env), mock.patch.object(deliver, "run_check", lambda r, c, **k: subprocess.run(
                [sys.executable, *c[1:]], cwd=r, capture_output=True)):
            with self.assertRaises(deliver.DeliveryError) as ctx:
                deliver.run_checks(repo, [], self.WHOLE, 120, self.dir / "checks")
        self.assertIn("no baseline is recorded", ctx.exception.message)

    def test_unreachable_store_fails_rather_than_passes(self):
        repo = make_repo(self.dir, {"test_a.py": PASS})
        deliver.ACTIVE_COMPARE.update(expected_sha=SHA, recorded_only=False)
        import test_scope
        with mock.patch.object(test_scope, "store_call", return_value=None), mock.patch.object(
                deliver, "run_check", lambda r, c, **k: subprocess.run([sys.executable, *c[1:]], cwd=r, capture_output=True)):
            with self.assertRaises(deliver.DeliveryError) as ctx:
                deliver.run_checks(repo, [], self.WHOLE, 120, self.dir / "checks")
        self.assertIn("unreachable", ctx.exception.message)

    def test_resolve_accepts_the_recorded_real_run_at_that_head_only(self):
        repo = make_repo(self.dir, {"test_a.py": PASS, "test_b.py": RED})
        store_dir = self.dir / "store"
        env = {**os.environ, "HARNESS_TEST_SCOPE_ROOT": str(store_dir)}
        run = subprocess.run([sys.executable, str(HOOKS / "test_scope.py"), "--root", str(store_dir), "run-baseline", "--repo", str(repo)],
                             capture_output=True, text=True, timeout=180, env=env)
        self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
        head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo, capture_output=True, text=True).stdout.strip()
        with mock.patch.dict(os.environ, env):
            deliver.ACTIVE_COMPARE.update(expected_sha=head, recorded_only=True)
            deliver.accept_recorded_baseline(repo, head)
            self.assertEqual(deliver.ACTIVE_COMPARE["result"]["source"], "recorded")
            self.assertEqual(deliver.ACTIVE_COMPARE["result"]["accepted_failing_ids"], ["test_b.R.test_known_red"])
            for sha in (OTHER, SHA):  # a HEAD with no recorded real run
                with self.assertRaises(deliver.DeliveryError, msg=sha):
                    deliver.accept_recorded_baseline(repo, sha)

    def test_receipt_accepts_a_compare_record_and_only_a_dict(self):
        from tests.test_finish_focused import ReceiptShape
        case = ReceiptShape()
        case.addCleanup = lambda f: None
        ok = case.completed(baseline_compare={"baseline_sha": SHA, "baseline_ran": 3, "checked_ran": 4, "accepted_failing_ids": []})
        self.assertEqual(ok["baseline_compare"]["baseline_ran"], 3)
        for bad in ("text", [1], 5):
            with self.assertRaises(Exception, msg=str(bad)) as ctx:
                case.completed(baseline_compare=bad)
            self.assertEqual(type(ctx.exception).__name__, "DeliveryError")


def hashlib_digest(preparations, checks):
    import hashlib
    return hashlib.sha256(json.dumps([preparations, checks], separators=(",", ":")).encode()).hexdigest()


class Cli(unittest.TestCase):
    def test_finish_exposes_the_flags_and_refuses_misuse_before_any_work(self):
        r = subprocess.run([sys.executable, str(HOOKS / "deliver.py"), "finish", "--help"], capture_output=True, text=True, timeout=60)
        self.assertIn("--baseline-compare", r.stdout)
        self.assertIn("--use-recorded-baseline", r.stdout)


if __name__ == "__main__":
    unittest.main()


class Round2(unittest.TestCase):
    def test_baseline_from_report_is_gone_and_helpers_are_installed(self):
        self.assertFalse(hasattr(ts, "record_from_report"))
        self.assertNotIn("baseline-from-report", (HOOKS / "test_scope.py").read_text())
        import install
        for name in ("suite_report.py", "suite_compare.py"):
            self.assertIn(name, [str(h) for h in install.HOOKS], name)

    def test_gate_refuses_non_whole_suite_check_for_resolve_journal(self):
        import integrate_local as il
        log = mock.Mock()
        args = SimpleNamespace(expected_head=SHA, baseline_compare=True)
        for checks in ([], [["python3", "-m", "unittest", "tests.test_a"]]):
            with mock.patch.object(il, "report") as rep:
                code = il.baseline_compare_gate(args, Path("."), Path("."), checks, log)
            self.assertEqual(code, 2)
            self.assertEqual(rep.call_args[0][0], "BLOCKED_POLICY")

    def test_gate_keeps_journal_unresolved_when_compare_fails(self):
        import integrate_local as il, suite_compare as sc
        args = SimpleNamespace(expected_head=SHA, baseline_compare=True, check_timeout=None, timeout=60)
        with mock.patch.object(sc, "run_compare", side_effect=sc.CompareFailure(["no baseline"])), \
                mock.patch.object(il, "report") as rep, mock.patch.object(il, "observed_head", return_value=SHA):
            code = il.baseline_compare_gate(args, Path("."), Path("/x"), [sc.WHOLE_SUITE_ARGV], mock.Mock())
        self.assertEqual(code, 3)
        self.assertEqual(rep.call_args[0][0], "RECOVERY_REQUIRED")

    def test_gate_passes_when_compare_passes(self):
        import integrate_local as il, suite_compare as sc
        args = SimpleNamespace(expected_head=SHA, baseline_compare=True, check_timeout=None, timeout=60)
        with tempfile.TemporaryDirectory() as d, mock.patch.object(sc, "run_compare", return_value={"baseline_sha": SHA}):
            self.assertEqual(il.baseline_compare_gate(args, Path("."), Path(d), [sc.WHOLE_SUITE_ARGV], mock.Mock()), 0)
            saved = json.loads((Path(d) / "baseline-compare.json").read_text())
            self.assertEqual(saved["baseline_sha"], SHA)
            self.assertIn("integrate_local.py", saved["helper"]["files"])
            self.assertEqual(args.compare_result["baseline_sha"], SHA)

    def test_accept_recorded_rejects_ids_outside_pinned_baseline(self):
        import suite_compare as sc
        def suite(ids, ran=10):
            return {"failing_ids": ids, "ran": ran, "skipped": 0}
        recs = {"A": "ra", "B": "rb"}
        def bs(rec, sha):
            return ({"A": suite(["t.a"]), "B": suite(["t.a", "t.b"])}[sha], [])
        with mock.patch.object(sc, "baseline_record_for", side_effect=lambda r, s: recs[s]), \
                mock.patch.object(ts, "baseline_suite_for", side_effect=bs):
            with self.assertRaises(sc.CompareFailure):
                sc.accept_recorded(".", "B", "A")
            self.assertEqual(sc.accept_recorded(".", "A", "B")["accepted_failing_ids"], ["t.a"])


class Round2b(unittest.TestCase):
    def test_count_floor_applies_even_when_fewer_tests_are_skipped(self):
        # baseline ran 10 (5 skipped); the checked run ran only 8 but skipped none: active count is higher, total is lower.
        out = compare(rep=report(ran=8, skipped=0), rec=record(ran=10, skipped=5))
        self.assertFalse(out["ok"])
        self.assertTrue(any("fewer than the baseline's 10" in p for p in out["problems"]), out["problems"])

    def test_finish_blocks_on_a_missing_baseline_before_any_effect(self):
        import suite_compare as sc

        class Flow:
            original = "/nonexistent"
            effects = []

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def load(self):
                return {"baseline": SHA, "kit_digest": "x"}

            def __getattr__(self, name):
                Flow.effects.append(name)
                raise AssertionError(f"effect before preflight: {name}")

        args = SimpleNamespace(baseline_compare=True, use_recorded_baseline=False, resolve_baseline=None, mode="remote",
                               resume=False, kit_file=None)
        with mock.patch.object(deliver, "Workflow", lambda a: Flow()), mock.patch.object(deliver, "require_check_interpreters"), \
                mock.patch.object(sc, "preflight", side_effect=sc.CompareFailure(["no baseline recorded"])):
            with self.assertRaises(deliver.DeliveryError) as ctx:
                deliver._finish(args, [], [deliver.WHOLE_SUITE_ARGV], [])
        self.assertEqual(ctx.exception.status, "BLOCKED_POLICY")
        self.assertIn("cannot start", ctx.exception.message)
        self.assertEqual(Flow.effects, [])

    def test_recorded_run_needs_a_baseline_for_the_pinned_head(self):
        import suite_compare as sc
        good = {"failing_ids": ["t.a"], "ran": 10, "skipped": 0}
        def bs(rec, sha):
            return (good, []) if sha == "B" else (None, ["no baseline for pinned"])
        with mock.patch.object(sc, "baseline_record_for", return_value="r"), mock.patch.object(ts, "baseline_suite_for", side_effect=bs):
            with self.assertRaises(sc.CompareFailure):
                sc.accept_recorded(".", "B", "A")

    def test_skipping_tests_does_not_keep_the_total_up(self):
        out = compare(rep=report(ran=10, skipped=5), rec=record(ran=10, skipped=0))
        self.assertFalse(out["ok"])
        self.assertTrue(any("non-skipped" in p for p in out["problems"]), out["problems"])


class Round3(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name).resolve()

    # F1: the pinned-HEAD bound applies on the run path and carries a count floor
    def pinned_run(self, ran=10, ids=("t.a",), pinned_ids=("t.a",), pinned_ran=10, base_ids=("t.a", "t.new"), base_ran=10, drop_pinned=False, pinned_skipped=0):
        import suite_compare as sc
        recs = {SHA: record(sha=SHA, ran=base_ran, ids=list(base_ids)), OTHER: None if drop_pinned else record(sha=OTHER, ran=pinned_ran, ids=list(pinned_ids), skipped=pinned_skipped)}

        def run_fn(repo, argv, **kw):
            nonce = argv[argv.index("--nonce") + 1]
            out = argv[argv.index("--out") + 1]
            rep = report(head=SHA, ran=ran, ids=list(ids), nonce=nonce)
            fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as handle:
                json.dump(rep, handle)
            return subprocess.CompletedProcess(argv, 0)

        log = mock.Mock()
        log.facts.return_value = {}
        with mock.patch.object(sc, "baseline_record_for", side_effect=lambda r, s: recs[s]), \
                mock.patch.object(sc, "head_of", return_value=SHA):
            return sc.run_compare(".", SHA, 60, self.dir, run_fn, log, pinned_sha=OTHER)

    def test_run_path_refuses_a_failure_outside_the_pinned_baseline(self):
        import suite_compare as sc
        self.assertEqual(self.pinned_run()["pinned_sha"], OTHER)
        with self.assertRaises(sc.CompareFailure) as ctx:
            self.pinned_run(ids=("t.a", "t.new"))  # known in the re-pin's own baseline, but not in the pinned HEAD's
        self.assertIn("t.new", str(ctx.exception))

    def test_run_path_and_recorded_path_apply_the_pinned_count_floor(self):
        import suite_compare as sc
        with self.assertRaises(sc.CompareFailure) as ctx:  # the re-pin's own baseline is low, so only the pinned floor can catch it
            self.pinned_run(ran=4, base_ran=4, pinned_ran=10)
        self.assertIn("pinned HEAD baseline", str(ctx.exception))
        with self.assertRaises(sc.CompareFailure) as ctx:  # total below the pinned total although the active count is above its
            self.pinned_run(ran=4, base_ran=4, pinned_ran=10, pinned_skipped=8)
        self.assertIn("fewer than the pinned HEAD baseline's 10", str(ctx.exception))
        with self.assertRaises(sc.CompareFailure) as ctx:
            self.pinned_run(drop_pinned=True)
        self.assertIn("pinned original HEAD has no complete", str(ctx.exception))
        suite = {"failing_ids": ["t.a"], "ran": 1, "skipped": 0}
        pinned = {"failing_ids": ["t.a"], "ran": 4, "skipped": 0}
        with mock.patch.object(sc, "baseline_record_for", return_value="r"), \
                mock.patch.object(ts, "baseline_suite_for", side_effect=lambda rec, sha: (suite if sha == "X" else pinned, [])):
            with self.assertRaises(sc.CompareFailure):
                sc.accept_recorded(".", "X", "P")

    def test_result_carries_the_baseline_provenance_and_reads_it_once(self):
        import suite_compare as sc
        base = record(sha=SHA)
        base["suite"]["note"] = {"reason": "accepted"}
        calls = []
        def lookup(repo, sha):
            calls.append(sha)
            return base
        def run_fn(repo, argv, **kw):
            nonce = argv[argv.index("--nonce") + 1]
            fd = os.open(argv[argv.index("--out") + 1], os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as handle:
                json.dump(report(head=SHA, nonce=nonce), handle)
            return subprocess.CompletedProcess(argv, 0)
        log = mock.Mock()
        with mock.patch.object(sc, "baseline_record_for", side_effect=lookup), mock.patch.object(sc, "head_of", return_value=SHA):
            out = sc.run_compare(".", SHA, 60, self.dir, run_fn, log)
        self.assertEqual(calls, [SHA])
        self.assertEqual(out["baseline_provenance"]["note"], {"reason": "accepted"})
        self.assertIn("report_sha256", out["baseline_provenance"])

    def test_a_directory_in_place_of_the_report_fails_closed(self):
        import suite_compare as sc
        (self.dir / "suite-report.json").mkdir()
        (self.dir / "suite-report.json" / "x").write_text("x")
        with mock.patch.object(sc, "baseline_record_for", return_value=record()):
            with self.assertRaises(sc.CompareFailure):
                sc.run_compare(".", SHA, 60, self.dir, mock.Mock(), mock.Mock())

    # F2: the resolve path ignores a caller-supplied store
    def test_resolve_gate_scrubs_the_store_override_and_takes_the_pinned_head(self):
        import integrate_local as il, suite_compare as sc
        seen = {}
        def fake(repo, expected, timeout, d, run_fn, log, pinned_sha=None):
            seen.update(root=os.environ.get("HARNESS_TEST_SCOPE_ROOT"), host=os.environ.get("HARNESS_TEST_SCOPE_HOST"), pinned=pinned_sha)
            return {"baseline_sha": expected}
        args = SimpleNamespace(expected_head=SHA, baseline_compare=True, check_timeout=None, timeout=60, pinned_head=OTHER)
        with mock.patch.dict(os.environ, {"HARNESS_TEST_SCOPE_ROOT": "/x", "HARNESS_TEST_SCOPE_HOST": "evil"}), \
                mock.patch.object(sc, "run_compare", side_effect=fake):
            self.assertEqual(il.baseline_compare_gate(args, Path("."), self.dir, [sc.WHOLE_SUITE_ARGV], mock.Mock()), 0)
        self.assertEqual(seen, {"root": None, "host": None, "pinned": OTHER})

    # F3: the helper source is real on a checkout and on an installed copy
    def test_helper_source_identifies_the_code_in_both_layouts(self):
        here = deliver.helper_source()
        self.assertRegex(here["head"], r"^[0-9a-f]{40}$")
        self.assertTrue(all(len(v) == 64 for v in here["files"].values()), here)
        import shutil
        copy = self.dir / "hooks"
        shutil.copytree(HOOKS, copy, ignore=shutil.ignore_patterns("__pycache__"))
        spec = importlib.util.spec_from_file_location("deliver_installed_copy", copy / "deliver.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        installed = module.helper_source()
        self.assertEqual(installed["head"], "installed-copy")
        self.assertEqual(installed["files"], here["files"])  # same bytes, identified by digest
        self.assertEqual(installed["tree"], str(copy))

    # F5: the Codex install ships every runtime file the mode imports
    def test_codex_install_ships_the_baseline_compare_files(self):
        import install_codex
        for name in ("suite_report.py", "suite_compare.py", "test_scope.py", "test_scope_policy.json"):
            self.assertIn(name, install_codex.DELIVERY_HELPERS)

    # F7 / F9: runner
    def test_an_ignored_test_file_makes_the_run_not_clean(self):
        repo = make_repo(self.dir, {"test_a.py": PASS})
        (repo / ".git" / "info" / "exclude").write_text("test_pad.py\n")
        (repo / "tests" / "test_pad.py").write_text(PASS.replace("class", "class Pad", 1) if "class" in PASS else PASS)
        out = self.dir / "r.json"
        self.assertEqual(run_runner(repo, out).returncode, 0)
        rep = json.loads(out.read_text())
        self.assertFalse(rep["clean"])
        self.assertFalse(ts._report_problems(rep, "r") == [])

    def test_skipped_subtests_count_once_and_never_exceed_ran(self):
        body = ("import unittest\nclass S(unittest.TestCase):\n    def test_s(self):\n        for i in range(5):\n"
                "            with self.subTest(i=i):\n                self.skipTest('no')\n")
        repo = make_repo(self.dir, {"test_s.py": body, "test_a.py": PASS})
        out = self.dir / "r.json"
        self.assertEqual(run_runner(repo, out).returncode, 0)
        rep = json.loads(out.read_text())
        self.assertLessEqual(rep["skipped"], rep["ran"], rep)
        self.assertEqual(rep["skipped"], 1)
