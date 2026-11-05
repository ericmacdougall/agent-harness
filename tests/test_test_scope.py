"""harness/hooks/test_scope.py: baseline cache, accepted-evidence gate, one full run per head, focused scope, hook."""
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
HOOKS = ROOT / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
import test_scope as ts  # noqa: E402

SHA_A, SHA_B = "a" * 40, "b" * 40
FULL_CMD = "python3 -m unittest discover -s tests"


class Tmp(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name).resolve()
        self.store = ts.Store(self.dir / "store")


def report(head, stage="code-inspection", verdict="CODE_INSPECTION_RESULT: ACCEPT", worktree="clean", packet_sha="0" * 64):
    return (f"Reviewer: x\nStage: {stage}\nReviewed HEAD: {head}\nReviewed packet SHA-256: {packet_sha}\n"
            f"Review input: isolated committed snapshot\nWorktree status: {worktree}\n\n{verdict}\nbody\n")


class Baseline(Tmp):
    def test_record_get_and_second_control_refused_with_the_recorded_result(self):
        self.assertIsNone(ts.baseline_get(self.store, "r", SHA_A))
        ts.baseline_record(self.store, "r", SHA_A, "make test", "pass", {"tests": 900}, [])
        got = ts.baseline_get(self.store, "r", SHA_A)
        self.assertEqual((got["result"], got["counts"]["tests"]), ("pass", 900))
        with self.assertRaises(ts.Refused) as ctx:
            ts.reserve_control(self.store, "r", SHA_A, "owner2")
        self.assertEqual(ctx.exception.code, "baseline-exists")
        self.assertEqual(ctx.exception.facts["record"]["command"], "make test")

    def test_other_sha_or_repo_is_not_covered_by_a_baseline(self):
        ts.baseline_record(self.store, "r", SHA_A, "c", "pass")
        self.assertTrue(ts.reserve_control(self.store, "r", SHA_B, "t")["allowed"])
        self.assertTrue(ts.reserve_control(self.store, "other", SHA_A, "t")["allowed"])

    def test_control_in_flight_blocks_others_but_is_idempotent_for_its_owner(self):
        self.assertFalse(ts.reserve_control(self.store, "r", SHA_A, "t1")["idempotent"])
        self.assertTrue(ts.reserve_control(self.store, "r", SHA_A, "t1")["idempotent"])
        with self.assertRaises(ts.Refused) as ctx:
            ts.reserve_control(self.store, "r", SHA_A, "t2")
        self.assertEqual(ctx.exception.code, "control-in-flight")

    def test_stale_reservation_expires_and_released_one_is_retakable(self):
        ts.reserve_control(self.store, "r", SHA_A, "t1")
        path = self.store.dir("r") / f"control-{SHA_A}.json"
        rec = json.loads(path.read_text())
        rec["at"] = time.time() - ts.CONTROL_TTL - 5
        path.write_text(json.dumps(rec))
        self.assertTrue(ts.reserve_control(self.store, "r", SHA_A, "t2")["allowed"])
        ts.release(self.store, "r", "control", SHA_A, "infrastructure failure: host rebooted")
        self.assertTrue(ts.reserve_control(self.store, "r", SHA_A, "t3")["allowed"])

    def test_tampered_misfiled_or_symlinked_records_are_ignored_not_trusted(self):
        ts.baseline_record(self.store, "r", SHA_A, "c", "pass")
        good = self.store.dir("r") / f"baseline-{SHA_A}.json"
        rec = json.loads(good.read_text())
        # a record for another SHA copied under this SHA's name
        rec["main_sha"] = SHA_B
        good.write_text(json.dumps(rec))
        self.assertIsNone(ts.baseline_get(self.store, "r", SHA_A))
        # wrong schema, garbage, oversize
        for content in (json.dumps({**rec, "main_sha": SHA_A, "schema": 99}), "{not json", "x" * (ts.MAX_RECORD + 1)):
            good.write_text(content)
            self.assertIsNone(ts.baseline_get(self.store, "r", SHA_A), content[:20])
        # symlink
        good.unlink()
        victim = self.dir / "victim.json"
        victim.write_text(json.dumps({"schema": 1, "repo_id": "r", "main_sha": SHA_A, "kind": "baseline", "result": "pass"}))
        good.symlink_to(victim)
        self.assertIsNone(ts.baseline_get(self.store, "r", SHA_A))

    def test_second_baseline_record_needs_replace(self):
        ts.baseline_record(self.store, "r", SHA_A, "c", "pass")
        with self.assertRaises(ts.Refused):
            ts.baseline_record(self.store, "r", SHA_A, "c", "fail")
        self.assertEqual(ts.baseline_record(self.store, "r", SHA_A, "c", "fail", replace=True)["result"], "fail")

    def test_inputs_are_validated(self):
        for bad in ("short", "A" * 40, "../" + "a" * 37, ""):
            with self.assertRaises(ValueError):
                ts.baseline_get(self.store, "r", bad)
        for repo in ("../x", "a/b", "", ".", ".."):
            with self.assertRaises(ValueError):
                ts.baseline_get(self.store, repo, SHA_A)
        with self.assertRaises(ValueError):
            ts.baseline_record(self.store, "r", SHA_A, "c", "maybe")

    def test_concurrent_controls_admit_exactly_one(self):
        procs = [subprocess.Popen([sys.executable, "-I", str(HOOKS / "test_scope.py"), "--root", str(self.dir / "store"),
                                   "control", "--repo-id", "r", "--main-sha", SHA_A, "--token", f"t{i}"],
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) for i in range(10)]
        codes = sorted(p.wait(timeout=60) for p in procs)
        for p in procs:
            p.stdout.close()
            p.stderr.close()
        self.assertEqual(codes, [0] + [2] * 9)


class RaceWindow(Tmp):
    """A slowed write widens the read-then-write window, so only a real per-repo lock admits one owner."""

    def slow_write(self):
        original = ts.Store.write

        def slow(store, repo_id, name, record):
            time.sleep(0.15)
            return original(store, repo_id, name, record)
        return mock.patch.object(ts.Store, "write", slow)

    def race(self, fn):
        import threading
        results = []

        def attempt(i):
            try:
                results.append(fn(i)["allowed"])
            except ts.Refused:
                results.append(False)
        threads = [threading.Thread(target=attempt, args=(i,)) for i in range(6)]
        with self.slow_write():
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=30)
        return results.count(True)

    def test_exactly_one_control_is_admitted(self):
        self.assertEqual(self.race(lambda i: ts.reserve_control(self.store, "r", SHA_A, f"t{i}")), 1)

    def test_exactly_one_full_run_is_admitted(self):
        path = self.dir / "rep.txt"
        path.write_text(report(SHA_A))
        ts.accept_evidence(self.store, "r", SHA_A, path)
        self.assertEqual(self.race(lambda i: ts.reserve_full(self.store, "r", SHA_A, f"t{i}")), 1)


class Evidence(Tmp):
    def accept(self, text, packet=None, head=SHA_A):
        path = self.dir / "report.txt"
        path.write_text(text)
        return ts.accept_evidence(self.store, "r", head, path, packet)

    def test_accepted_report_registers_the_head_only(self):
        self.accept(report(SHA_A))
        self.assertIsNotNone(ts.has_evidence(self.store, "r", SHA_A))
        self.assertIsNone(ts.has_evidence(self.store, "r", SHA_B))

    def test_every_defect_is_refused(self):
        for text in (report(SHA_B), report(SHA_A, stage="plan"), report(SHA_A, stage="pr"),
                     report(SHA_A, verdict="CODE_INSPECTION_RESULT: BLOCK"), report(SHA_A, verdict="VERDICT: PASS"),
                     report(SHA_A, worktree="dirty"), "", "CODE_INSPECTION_RESULT: ACCEPT\nno header"):
            with self.assertRaises(ts.Refused, msg=text[:60]) as ctx:
                self.accept(text)
            self.assertEqual(ctx.exception.code, "bad-evidence")
        self.assertIsNone(ts.has_evidence(self.store, "r", SHA_A))

    def test_packet_digest_must_match_the_packet_bytes(self):
        packet = self.dir / "packet.md"
        packet.write_bytes(b"scope and results")
        digest = hashlib.sha256(b"scope and results").hexdigest()
        self.accept(report(SHA_A, packet_sha=digest), packet)
        with self.assertRaises(ts.Refused):
            self.accept(report(SHA_A, packet_sha="1" * 64), packet)

    def test_symlinked_or_missing_report_is_refused(self):
        real = self.dir / "real.txt"
        real.write_text(report(SHA_A))
        link = self.dir / "link.txt"
        link.symlink_to(real)
        for path in (link, self.dir / "none.txt"):
            with self.assertRaises(ts.Refused):
                ts.accept_evidence(self.store, "r", SHA_A, path)


class OneFullPerHead(Tmp):
    def setUp(self):
        super().setUp()
        path = self.dir / "r.txt"
        path.write_text(report(SHA_A))
        ts.accept_evidence(self.store, "r", SHA_A, path)

    def test_no_evidence_refuses_and_carries_the_focused_commands(self):
        with self.assertRaises(ts.Refused) as ctx:
            ts.reserve_full(self.store, "r", SHA_B, "t", focused=["python3 -m unittest tests.test_a"])
        self.assertEqual(ctx.exception.code, "no-evidence")
        self.assertEqual(ctx.exception.facts["focused"], ["python3 -m unittest tests.test_a"])

    def test_first_run_allowed_duplicate_refused_same_token_idempotent(self):
        self.assertFalse(ts.reserve_full(self.store, "r", SHA_A, "t1")["idempotent"])
        self.assertTrue(ts.reserve_full(self.store, "r", SHA_A, "t1")["idempotent"])
        with self.assertRaises(ts.Refused) as ctx:
            ts.reserve_full(self.store, "r", SHA_A, "t2")
        self.assertEqual(ctx.exception.code, "duplicate-full")

    def test_finished_run_blocks_even_the_same_token_until_released(self):
        ts.reserve_full(self.store, "r", SHA_A, "t1")
        ts.finish_full(self.store, "r", SHA_A, "pass", "900 tests")
        for token in ("t1", "t2"):
            with self.assertRaises(ts.Refused):
                ts.reserve_full(self.store, "r", SHA_A, token)
        ts.release(self.store, "r", "full", SHA_A, "infrastructure failure: dev2 OOM-killed the run")
        self.assertTrue(ts.reserve_full(self.store, "r", SHA_A, "t3")["allowed"])

    def test_abandoned_reservation_expires(self):
        ts.reserve_full(self.store, "r", SHA_A, "t1")
        path = self.store.dir("r") / f"full-{SHA_A}.json"
        rec = json.loads(path.read_text())
        rec["at"] = time.time() - ts.FULL_TTL - 5
        path.write_text(json.dumps(rec))
        self.assertTrue(ts.reserve_full(self.store, "r", SHA_A, "t2")["allowed"])

    def test_release_needs_a_real_reason_and_an_existing_reservation(self):
        with self.assertRaises(ts.Refused):
            ts.release(self.store, "r", "full", SHA_A, "infrastructure failure: none yet")
        ts.reserve_full(self.store, "r", SHA_A, "t1")
        with self.assertRaises(ValueError):
            ts.release(self.store, "r", "full", SHA_A, "short")

    def test_guarded_path_shares_the_same_records(self):
        ts.guarded_full_start(SHA_A, "usage_guard:o1", root=self.store.root)
        ts.guarded_full_start(SHA_A, "usage_guard:o1", root=self.store.root)  # same token: idempotent
        with self.assertRaises(ts.Refused):
            ts.guarded_full_start(SHA_A, "usage_guard:o2", root=self.store.root)
        with self.assertRaises(ts.Refused):  # the hook path sees the guarded reservation
            ts.reserve_full(self.store, "r", SHA_A, "hook-token")
        ts.finish_full(self.store, "_guarded", SHA_A, "pass")
        with self.assertRaises(ts.Refused):
            ts.guarded_full_start(SHA_A, "usage_guard:o1", root=self.store.root)

    def test_hook_reservation_is_seen_by_the_guarded_path(self):
        ts.reserve_full(self.store, "r", SHA_A, "hook-token")
        with self.assertRaises(ts.Refused):
            ts.guarded_full_start(SHA_A, "usage_guard:o1", root=self.store.root)


def run(cwd, *cmd):
    env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t",
           "GIT_COMMITTER_EMAIL": "t@t"}
    return subprocess.run(cmd, cwd=str(cwd), check=True, capture_output=True, text=True, env=env).stdout.strip()


def make_repo(base: Path):
    remote, repo = base / "remote.git", base / "repo"
    subprocess.run(["git", "init", "-q", "--bare", "-b", "main", str(remote)], check=True)
    subprocess.run(["git", "init", "-q", "-b", "main", str(repo)], check=True)
    (repo / "harness" / "hooks").mkdir(parents=True)
    (repo / "tests").mkdir()
    files = {"harness/hooks/a.py": "VALUE = 1\n", "harness/hooks/b.py": "import a\nX = a.VALUE\n",
             "harness/hooks/c.py": "Y = 2\n", "harness/hooks/d.py": "import b\nZ = b.X\n",
             "harness/hooks/c_policy.json": "{}\n", "tests/test_a.py": "import a\n", "tests/test_b.py": "import b\n",
             "tests/test_c.py": "import c\n", "tests/test_d.py": "import d\n", "docs.md": "x\n"}
    for name, body in files.items():
        (repo / name).write_text(body)
    run(repo, "git", "add", "-A")
    run(repo, "git", "commit", "-q", "-m", "base")
    run(repo, "git", "remote", "add", "origin", str(remote))
    run(repo, "git", "push", "-q", "origin", "main")
    run(repo, "git", "fetch", "-q", "origin")
    return repo


class Scope(Tmp):
    def setUp(self):
        super().setUp()
        self.repo = make_repo(self.dir)
        self.base = run(self.repo, "git", "rev-parse", "HEAD")

    def delta(self, **changes):
        for name, body in changes.items():
            path = self.repo / name.replace("__", "/").replace("_py", ".py").replace("_json", ".json").replace("_md", ".md")
            path.write_text(body)
        run(self.repo, "git", "add", "-A")
        run(self.repo, "git", "commit", "-q", "-m", "delta")
        return ts.focused_scope(str(self.repo), self.base, run(self.repo, "git", "rev-parse", "HEAD"))

    def test_changed_module_selects_its_test_and_every_transitive_dependent(self):
        out = self.delta(harness__hooks__a_py="VALUE = 2\n")
        self.assertEqual(out["dependents"], ["a", "b", "d"])
        self.assertEqual(out["tests"], ["test_a", "test_b", "test_d"])
        self.assertEqual(out["commands"], ["python3 -m unittest tests.test_a tests.test_b tests.test_d"])

    def test_leaf_module_selects_only_its_own_test(self):
        out = self.delta(harness__hooks__c_py="Y = 3\n")
        self.assertEqual(out["tests"], ["test_c"])

    def test_policy_json_maps_to_its_module_and_a_changed_test_runs_itself(self):
        self.assertEqual(self.delta(harness__hooks__c_policy_json='{"a": 1}\n')["tests"], ["test_c"])

    def test_docs_only_change_needs_no_tests(self):
        out = self.delta(docs_md="y\n")
        self.assertEqual((out["tests"], out["commands"]), ([], []))
        self.assertIn("no mapped tests", out["note"])


class Hook(Tmp):
    """The PreToolUse decision, with the store in a temp dir (HARNESS_TEST_SCOPE_ROOT) and real git repos."""

    def setUp(self):
        super().setUp()
        self.repo = make_repo(self.dir)
        self.main = run(self.repo, "git", "rev-parse", "HEAD")
        patcher = mock.patch.dict(os.environ, {"HARNESS_TEST_SCOPE_ROOT": str(self.dir / "store")})
        patcher.start()
        self.addCleanup(patcher.stop)
        self.repo_id = ts.repo_context(str(self.repo))["repo_id"]

    def call(self, command=FULL_CMD, session="s1", cwd=None):
        return ts.hook_decision({"tool_name": "Bash", "tool_input": {"command": command}, "session_id": session,
                                 "cwd": str(cwd or self.repo)}, ts.load_policy())

    def feature(self):
        run(self.repo, "git", "checkout", "-q", "-b", "feat")
        (self.repo / "harness" / "hooks" / "a.py").write_text("VALUE = 5\n")
        run(self.repo, "git", "commit", "-q", "-am", "delta")
        return run(self.repo, "git", "rev-parse", "HEAD")

    def accept(self, head):
        path = self.dir / "rep.txt"
        path.write_text(report(head))
        ts.accept_evidence(ts.Store(self.dir / "store"), self.repo_id, head, path)

    def test_non_suite_commands_and_other_tools_are_untouched(self):
        for cmd in ("ls", "git status", "python3 -m unittest tests.test_a", "python3 harness/hooks/test_scope.py scope"):
            self.assertEqual(self.call(cmd), (0, ""), cmd)
        self.assertEqual(ts.hook_decision({"tool_name": "Read", "tool_input": {}}, ts.load_policy()), (0, ""))

    def test_main_control_first_owner_allowed_second_refused_then_baseline_is_quoted(self):
        self.assertEqual(self.call(session="s1"), (0, ""))
        code, text = self.call(session="s2")
        self.assertEqual(code, 2)
        self.assertIn("another owner is already running the main control", text)
        ts.baseline_record(ts.Store(self.dir / "store"), self.repo_id, self.main, "make test", "pass", {"tests": 900})
        code, text = self.call(session="s3")
        self.assertEqual(code, 2)
        self.assertIn("result=pass", text)
        self.assertIn("baseline-get", text)

    def test_feature_head_without_evidence_is_refused_with_focused_commands(self):
        self.feature()
        code, text = self.call()
        self.assertEqual(code, 2)
        self.assertIn("[evidence]", text)
        self.assertIn("python3 -m unittest tests.test_a tests.test_b tests.test_d", text)
        self.assertIn("HARNESS_SCOPE_OK", text)

    def test_with_evidence_one_run_then_duplicates_are_refused(self):
        head = self.feature()
        self.accept(head)
        self.assertEqual(self.call(session="s1"), (0, ""))
        self.assertEqual(self.call(session="s1"), (0, ""))  # same owner retrying the launch
        code, text = self.call(session="s2")
        self.assertEqual(code, 2)
        self.assertIn("one full run per head", text)

    def test_new_commit_after_evidence_needs_new_evidence(self):
        self.accept(self.feature())
        (self.repo / "harness" / "hooks" / "c.py").write_text("Y = 9\n")
        run(self.repo, "git", "commit", "-q", "-am", "repair delta")
        code, text = self.call()
        self.assertEqual(code, 2)
        self.assertIn("[evidence]", text)
        self.assertIn("tests.test_c", text)

    def test_investigation_hatch_needs_a_reason_and_is_logged(self):
        self.feature()
        self.assertEqual(self.call("HARNESS_SCOPE_OK=short " + FULL_CMD)[0], 2)
        self.assertEqual(self.call("HARNESS_SCOPE_OK='bisecting a flaky hook test on dev2' " + FULL_CMD), (0, ""))
        log = (self.dir / "store" / self.repo_id / "ungated.jsonl").read_text()
        self.assertIn("bisecting a flaky hook test", log)

    def test_unreachable_store_warns_and_allows(self):
        self.feature()
        with mock.patch.object(ts, "store_call", return_value=None):
            code, text = self.call()
        self.assertEqual(code, 0)
        self.assertIn("store unreachable", text)

    def test_not_a_git_repo_fails_open_through_the_entry_point(self):
        payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": FULL_CMD}, "cwd": str(self.dir)})
        r = subprocess.run([sys.executable, "-I", str(HOOKS / "test_scope.py"), "hook"], input=payload,
                           capture_output=True, text=True, timeout=30)
        self.assertEqual(r.returncode, 0)
        self.assertIn("failing open", r.stderr)

    def test_garbage_payloads_exit_zero(self):
        for raw in ("not json", "", "[1]", "null"):
            r = subprocess.run([sys.executable, "-I", str(HOOKS / "test_scope.py"), "hook"], input=raw,
                               capture_output=True, text=True, timeout=30)
            self.assertEqual(r.returncode, 0, raw)


class Cli(Tmp):
    def test_cli_round_trip_and_exit_codes(self):
        def cli(*args):
            r = subprocess.run([sys.executable, "-I", str(HOOKS / "test_scope.py"), "--root", str(self.dir / "s"), *args],
                               capture_output=True, text=True, timeout=30)
            return r.returncode, json.loads(r.stdout)
        self.assertEqual(cli("baseline-get", "--repo-id", "r", "--main-sha", SHA_A)[0], 1)
        self.assertEqual(cli("baseline-record", "--repo-id", "r", "--main-sha", SHA_A, "--command", "make test",
                             "--result", "pass", "--counts", '{"tests": 3}')[0], 0)
        code, data = cli("control", "--repo-id", "r", "--main-sha", SHA_A, "--token", "t")
        self.assertEqual((code, data["code"]), (2, "baseline-exists"))
        self.assertEqual(cli("baseline-get", "--repo-id", "r", "--main-sha", "zz")[0], 3)

    def test_run_token_comes_from_the_ah_run_environment_when_not_given(self):
        env = {**os.environ, "AGENT_HARNESS_RUN_ID": "f" * 32}
        cmd = [sys.executable, "-I", str(HOOKS / "test_scope.py"), "--root", str(self.dir / "s"), "control",
               "--repo-id", "r", "--main-sha", SHA_A]
        first = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=30)
        second = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=30)
        self.assertEqual((first.returncode, second.returncode), (0, 0))
        self.assertTrue(json.loads(second.stdout)["idempotent"])
        no_token = subprocess.run(cmd, capture_output=True, text=True, timeout=30,
                                  env={k: v for k, v in os.environ.items() if k != "AGENT_HARNESS_RUN_ID"})
        self.assertEqual(no_token.returncode, 2)  # argparse: --token required without the environment variable


class Wiring(unittest.TestCase):
    def test_installer_registers_the_hook_and_ships_the_files(self):
        import install
        hooks = install.managed_hooks(Path("/h/.claude"), True)
        groups = [g for g in hooks["PreToolUse"] if "test_scope.py" in json.dumps(g)]
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0]["matcher"], "Bash")
        self.assertNotIn("onFailure", json.dumps(groups[0]))
        self.assertIn("test_scope.py", install.HOOKS)
        self.assertIn("test_scope_policy.json", install.HOOKS)

    def test_usage_guard_refuses_a_second_full_run_for_a_head(self):
        import usage_guard
        with tempfile.TemporaryDirectory() as d, mock.patch.dict(os.environ, {"HARNESS_TEST_SCOPE_ROOT": d}):
            usage_guard.UsageStore._one_full_per_head(SHA_A, "o1")
            usage_guard.UsageStore._one_full_per_head(SHA_A, "o1")
            with self.assertRaises(usage_guard.GuardError):
                usage_guard.UsageStore._one_full_per_head(SHA_A, "o2")
            usage_guard.UsageStore._one_full_per_head("not-a-sha", "o2")  # bad head: not this guard's job, no raise

    def test_heavy_guard_deny_text_points_at_the_focused_scope(self):
        import heavy_job_guard
        self.assertIn("test_scope.py scope", heavy_job_guard.RULE_HELP["full-suite"])


if __name__ == "__main__":
    unittest.main()
