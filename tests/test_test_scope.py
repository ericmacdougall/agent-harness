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


PACKET_BYTES = b"scope, base head, results"
PACKET_SHA = hashlib.sha256(PACKET_BYTES).hexdigest()


def give_evidence(store, repo_id, head, directory):
    """Register accepted evidence the way an owner would: a packet and a report whose digest matches it."""
    packet = Path(directory) / "evidence-packet.md"
    packet.write_bytes(PACKET_BYTES)
    path = Path(directory) / f"evidence-{head[:8]}.txt"
    path.write_text(report(head))
    return ts.accept_evidence(store, repo_id, head, path, packet)


def report(head, stage="code-inspection", verdict="CODE_INSPECTION_RESULT: ACCEPT", worktree="clean", packet_sha=PACKET_SHA):
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
        give_evidence(self.store, "r", SHA_A, self.dir)
        self.assertEqual(self.race(lambda i: ts.reserve_full(self.store, "r", SHA_A, f"t{i}")), 1)


class Evidence(Tmp):
    def accept(self, text, packet=True, head=SHA_A):
        path = self.dir / "report.txt"
        path.write_text(text)
        pkt = self.dir / "packet.md"
        pkt.write_bytes(PACKET_BYTES)
        return ts.accept_evidence(self.store, "r", head, path, pkt if packet else self.dir / "missing.md")

    def test_accepted_report_registers_the_head_only(self):
        self.accept(report(SHA_A))
        self.assertIsNotNone(ts.has_evidence(self.store, "r", SHA_A))
        self.assertIsNone(ts.has_evidence(self.store, "r", SHA_B))

    def test_every_defect_is_refused(self):
        for text in (report(SHA_B), report(SHA_A, stage="plan"), report(SHA_A, stage="pr"),
                     report(SHA_A, verdict="CODE_INSPECTION_RESULT: BLOCK"), report(SHA_A, verdict="VERDICT: PASS"),
                     report(SHA_A, worktree="dirty"), "", "CODE_INSPECTION_RESULT: ACCEPT\nno header",
                     report(SHA_A).replace("\n\nCODE_INSPECTION_RESULT: ACCEPT", "\n\npreamble\nCODE_INSPECTION_RESULT: ACCEPT"),
                     report(SHA_A).replace(f"Reviewed packet SHA-256: {PACKET_SHA}\n", "")):
            with self.assertRaises(ts.Refused, msg=text[:60]) as ctx:
                self.accept(text)
            self.assertEqual(ctx.exception.code, "bad-evidence")
        self.assertIsNone(ts.has_evidence(self.store, "r", SHA_A))

    def test_packet_digest_must_match_the_packet_bytes_and_a_packet_is_required(self):
        self.accept(report(SHA_A))
        with self.assertRaises(ts.Refused):
            self.accept(report(SHA_A, packet_sha="1" * 64))
        with self.assertRaises(ts.Refused):
            self.accept(report(SHA_A), packet=False)  # no packet file: the digest can not be checked

    def test_symlinked_or_missing_report_is_refused(self):
        real = self.dir / "real.txt"
        real.write_text(report(SHA_A))
        link = self.dir / "link.txt"
        link.symlink_to(real)
        packet = self.dir / "packet.md"
        packet.write_bytes(PACKET_BYTES)
        for path in (link, self.dir / "none.txt"):
            with self.assertRaises(ts.Refused):
                ts.accept_evidence(self.store, "r", SHA_A, path, packet)


class OneFullPerHead(Tmp):
    def setUp(self):
        super().setUp()
        give_evidence(self.store, "r", SHA_A, self.dir)

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

    def test_guarded_path_adopts_the_hook_reservation_of_the_same_launch(self):
        ts.reserve_full(self.store, "r", SHA_A, "hook-token")  # the PreToolUse hook runs first
        ts.guarded_full_start(SHA_A, "usage_guard:o1", root=self.store.root)  # then usage_guard inside the command
        rec = self.store.read("r", f"full-{SHA_A}.json", {"repo_id": "r", "head": SHA_A, "kind": "full"})
        self.assertEqual(rec["source"], "both")
        with self.assertRaises(ts.Refused):  # a different owner is still a duplicate
            ts.reserve_full(self.store, "r", SHA_A, "other-hook-token")

    def test_guarded_only_reservations_refuse_other_owners_and_finished_runs(self):
        ts.guarded_full_start(SHA_B, "usage_guard:o1", root=self.store.root)
        ts.guarded_full_start(SHA_B, "usage_guard:o1", root=self.store.root)  # same owner retry
        with self.assertRaises(ts.Refused):
            ts.guarded_full_start(SHA_B, "usage_guard:o2", root=self.store.root)
        give_evidence(self.store, "r", SHA_B, self.dir)
        with self.assertRaises(ts.Refused):  # the hook path sees the guarded reservation
            ts.reserve_full(self.store, "r", SHA_B, "hook-token")
        ts.finish_full(self.store, "_guarded", SHA_B, "pass")
        with self.assertRaises(ts.Refused):
            ts.guarded_full_start(SHA_B, "usage_guard:o1", root=self.store.root)

    def test_same_owner_retry_rules(self):
        ts.reserve_full(self.store, "r", SHA_A, "t1")
        with mock.patch.object(ts, "IDEMPOTENT_S", -1):
            # unconfirmed: the owner's launch was denied or never started, so a retry is always fine (and keeps its TTL)
            self.assertTrue(ts.reserve_full(self.store, "r", SHA_A, "t1")["idempotent"])
            ts.confirm_reservation(self.store, "r", "full", SHA_A, "t1")
            with self.assertRaises(ts.Refused):  # confirmed and outside the retry window: a second launch is a duplicate
                ts.reserve_full(self.store, "r", SHA_A, "t1")


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
        give_evidence(ts.Store(self.dir / "store"), self.repo_id, head, self.dir)

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


class SecondReview(Tmp):
    """Findings of the independent review of 39dc4f9."""

    def hook_repo(self):
        self.repo = make_repo(self.dir)
        patcher = mock.patch.dict(os.environ, {"HARNESS_TEST_SCOPE_ROOT": str(self.dir / "store")})
        patcher.start()
        self.addCleanup(patcher.stop)
        run(self.repo, "git", "checkout", "-q", "-b", "feat")
        (self.repo / "harness" / "hooks" / "a.py").write_text("VALUE = 5\n")
        run(self.repo, "git", "commit", "-q", "-am", "delta")

    def call(self, command, cwd=None, **extra):
        return ts.hook_decision({"tool_name": "Bash", "tool_input": {"command": command}, "session_id": "s1",
                                 "cwd": str(cwd or self.repo), **extra}, ts.load_policy())

    def test_comments_and_earlier_segments_do_not_switch_the_hook_off(self):  # F1
        self.hook_repo()
        for cmd in (f"{FULL_CMD} # test_scope.py", f"echo test_scope.py; {FULL_CMD}", f"echo x && {FULL_CMD} test_scope.py"):
            self.assertEqual(self.call(cmd)[0], 2, cmd)

    def test_on_the_mac_every_store_command_goes_to_the_store_host(self):  # F2
        policy = ts.load_policy()
        calls = []

        def fake(host, argv, timeout):
            calls.append((host, argv))
            return 0, {"ok": True}
        packet = self.dir / "p.md"
        packet.write_bytes(PACKET_BYTES)
        rep = self.dir / "r.txt"
        rep.write_text(report(SHA_A))
        with mock.patch.object(ts, "store_is_remote", return_value=True), mock.patch.object(ts, "run_remote", fake), \
                mock.patch.dict(os.environ, {"HARNESS_TEST_SCOPE_ROOT": ""}):
            for argv in (["control", "--repo-id", "r", "--main-sha", SHA_A, "--token", "t"],
                         ["baseline-get", "--repo-id", "r", "--main-sha", SHA_A],
                         ["baseline-record", "--repo-id", "r", "--main-sha", SHA_A, "--command", "make test",
                          "--result", "pass"],
                         ["full", "--repo-id", "r", "--head", SHA_A, "--token", "t"],
                         ["finish", "--repo-id", "r", "--head", SHA_A, "--result", "pass"],
                         ["release", "--repo-id", "r", "--kind", "full", "--key", SHA_A, "--reason", "infra failure x"],
                         ["accept", "--repo-id", "r", "--head", SHA_A, "--report", str(rep), "--packet", str(packet)]):
                self.assertEqual(ts.cli(argv, capture=True)[0], 0, argv[0])
        self.assertEqual(len(calls), 7)
        self.assertTrue(all(host == "dev2" for host, _ in calls))
        accept = [a for _, a in calls if a[0] == "register-accepted"][0]
        self.assertIn(f"--report-sha256={hashlib.sha256(rep.read_text().encode()).hexdigest()}", accept)
        self.assertFalse((Path.home() / ".agent-harness" / "test-scope" / "r" / f"accepted-{SHA_A}.json").exists())
        with mock.patch.object(ts, "store_is_remote", return_value=True), mock.patch.object(ts, "run_remote", return_value=None):
            code, data = ts.cli(["baseline-get", "--repo-id", "r", "--main-sha", SHA_A], capture=True)
        self.assertEqual((code, data["error"]), (4, "store unreachable"))
        with mock.patch.object(ts, "store_is_remote", return_value=True):
            code, data = ts.cli(["run-control", "--", "true"], capture=True)
        self.assertEqual(code, 3)

    def test_store_host_comes_from_policy_not_from_the_operating_system(self):  # F3
        policy = {"host": "t2-dev", "local_hostnames": ["t2-dev"]}
        import socket
        with mock.patch.dict(os.environ, {"HARNESS_TEST_SCOPE_ROOT": ""}):
            for name, expect in (("t2-dev.example.com", False), ("dev2", True), ("macbook", True)):
                with mock.patch.object(socket, "gethostname", return_value=name):
                    self.assertEqual(ts.store_is_remote(policy), expect, name)
        with mock.patch.dict(os.environ, {"HARNESS_TEST_SCOPE_ROOT": "/x"}):
            self.assertFalse(ts.store_is_remote(policy))
        self.assertFalse(ts.store_is_remote(policy, root="/y"))

    def test_hook_with_no_identity_never_shares_a_token(self):  # F8
        self.hook_repo()
        head = run(self.repo, "git", "rev-parse", "HEAD")
        give_evidence(ts.Store(self.dir / "store"), ts.repo_context(str(self.repo))["repo_id"], head, self.dir)
        payload = {"tool_name": "Bash", "tool_input": {"command": FULL_CMD}, "cwd": str(self.repo)}
        first = ts.hook_decision(payload, ts.load_policy())
        second = ts.hook_decision(payload, ts.load_policy())
        self.assertEqual(first[0], 0)
        self.assertEqual(second[0], 2)

    def test_repo_ids_hide_credentials_and_never_collide(self):  # F9
        a = ts.repo_id_for("https://user:SECRETTOKEN@github.com/o/r2.git", "")
        self.assertNotIn("SECRET", a)
        self.assertNotIn("user", a)
        self.assertEqual(ts.repo_id_for("git@github.com:o/r.git", ""), ts.repo_id_for("https://github.com/o/r", ""))
        self.assertEqual(ts.repo_id_for("https://GitHub.com/O/R.git", ""), ts.repo_id_for("ssh://git@github.com/o/r", ""))
        self.assertNotEqual(ts.repo_id_for("https://github.com/a/b-c", ""), ts.repo_id_for("https://github.com/a-b/c", ""))
        self.assertNotEqual(ts.repo_id_for("", "1" * 40), ts.repo_id_for("", "2" * 40))
        for rid in (a, ts.repo_id_for("", "1" * 40)):
            self.assertTrue(ts.SAFE_RE.match(rid), rid)

    def test_remoteless_repos_with_the_same_directory_name_get_different_ids(self):  # F9
        ids = []
        for n in (1, 2):
            repo = self.dir / f"d{n}" / "repo"
            repo.mkdir(parents=True)
            subprocess.run(["git", "init", "-q", "-b", "main", str(repo)], check=True)
            (repo / "f.txt").write_text(str(n))
            run(repo, "git", "add", "-A")
            run(repo, "git", "commit", "-q", "-m", f"root {n}")
            ids.append(ts.repo_context(str(repo))["repo_id"])
        self.assertNotEqual(*ids)

    def test_cd_prefix_selects_the_repo_the_suite_runs_in(self):  # F10
        self.hook_repo()
        other = self.dir / "other"
        other.mkdir()
        subprocess.run(["git", "init", "-q", "-b", "main", str(other)], check=True)
        (other / "f.txt").write_text("x")
        run(other, "git", "add", "-A")
        run(other, "git", "commit", "-q", "-m", "root")
        self.assertEqual(ts.effective_cwd(f"cd {self.repo} && {FULL_CMD}", str(other)), str(self.repo))
        self.assertEqual(ts.effective_cwd(f"FOO=1 cd '{other}'; {FULL_CMD}", str(self.repo)), str(other))
        self.assertEqual(ts.effective_cwd(FULL_CMD, "/x"), "/x")
        self.assertEqual(ts.effective_cwd("cd /nonexistent/zzz && ls", "/x"), "/x")
        # judged against the repo cd selects: `other` has no origin/main, so it is a feature head without evidence
        self.assertEqual(self.call(f"cd {other} && {FULL_CMD}", cwd=self.repo)[0], 2)

    def test_hatch_after_a_cd_prefix_and_argparse_errors_fail_open(self):  # F11
        self.hook_repo()
        self.assertEqual(self.call(f"cd . && HARNESS_SCOPE_OK='bisecting a flaky test on dev2' {FULL_CMD}"), (0, ""))
        env = {**os.environ, "HARNESS_TEST_SCOPE_ROOT": str(self.dir / "store")}
        payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": f"HARNESS_SCOPE_OK=-xxxxxxxxxxxx {FULL_CMD}"},
                              "cwd": str(self.repo)})
        r = subprocess.run([sys.executable, "-I", str(HOOKS / "test_scope.py"), "hook"], input=payload, capture_output=True,
                           text=True, timeout=30, env=env)
        self.assertEqual(r.returncode, 0, r.stderr)

    def test_scope_mapper_handles_deleted_relative_and_aliased_imports_and_root_modules(self):  # F12
        repo = make_repo(self.dir)
        base = run(repo, "git", "rev-parse", "HEAD")
        (repo / "harness" / "hooks" / "e.py").write_text("from . import a\nfrom .c import Y\nimport a as x, b\n")
        (repo / "tests" / "test_e.py").write_text("import e\n")
        (repo / "install.py").write_text("import a\n")
        (repo / "tests" / "test_install.py").write_text("import install\n")
        run(repo, "git", "add", "-A")
        run(repo, "git", "commit", "-q", "-m", "more modules")
        base = run(repo, "git", "rev-parse", "HEAD")
        (repo / "harness" / "hooks" / "a.py").unlink()
        run(repo, "git", "add", "-A")
        run(repo, "git", "commit", "-q", "-m", "delete a")
        out = ts.focused_scope(str(repo), base, run(repo, "git", "rev-parse", "HEAD"))
        self.assertTrue({"a", "b", "d", "e", "install"} <= set(out["dependents"]), out["dependents"])
        self.assertTrue({"test_b", "test_d", "test_e", "test_install"} <= set(out["tests"]), out["tests"])
        for bad in ("--output=/tmp/x", "-p", "a b", ""):
            with self.assertRaises(ValueError):
                ts.focused_scope(str(repo), bad, "HEAD")


class ThirdReview(Tmp):
    """Findings of the delta review of cb4168f."""

    def age(self, repo_id, name, seconds):
        path = self.store.dir(repo_id) / name
        rec = json.loads(path.read_text())
        rec["at"] = time.time() - seconds
        path.write_text(json.dumps(rec))

    def test_ssh_launches_are_judged_by_the_inner_command(self):  # F1
        for cmd, inner in (("ssh dev2 'cd r && python3 -m unittest discover -s tests'", "cd r && python3 -m unittest discover -s tests"),
                           ("ssh -i ~/.ssh/k -p 22 dev2 make test", "make test"),
                           ("FOO=1 ssh -o BatchMode=yes dev2 'pytest'", "pytest"), ("ssh dev2", ""), ("ls", "")):
            self.assertEqual(ts.ssh_inner(cmd), inner, cmd)
        self.assertTrue(ts.suite_launch("ssh dev2 'cd r && python3 -m unittest discover -s tests'", "/tmp"))
        self.assertFalse(ts.suite_launch("ssh dev2 'uptime'", "/tmp"))
        repo = make_repo(self.dir)
        run(repo, "git", "checkout", "-q", "-b", "feat")
        (repo / "harness" / "hooks" / "a.py").write_text("VALUE = 5\n")
        run(repo, "git", "commit", "-q", "-am", "delta")
        with mock.patch.dict(os.environ, {"HARNESS_TEST_SCOPE_ROOT": str(self.dir / "store")}):
            code, text = ts.hook_decision({"tool_name": "Bash", "session_id": "s", "cwd": str(repo),
                                           "tool_input": {"command": "ssh dev2 'cd r && python3 -m unittest discover -s tests'"}},
                                          ts.load_policy())
        self.assertEqual(code, 2)
        self.assertIn("[evidence]", text)

    def test_unconfirmed_reservations_free_themselves_confirmed_ones_do_not(self):  # F2
        ts.reserve_control(self.store, "r", SHA_A, "t1")
        with self.assertRaises(ts.Refused):
            ts.reserve_control(self.store, "r", SHA_A, "t2")
        self.age("r", f"control-{SHA_A}.json", ts.UNCONFIRMED_TTL + 5)
        self.assertTrue(ts.reserve_control(self.store, "r", SHA_A, "t2")["allowed"])  # t1 never started
        self.assertTrue(ts.confirm_reservation(self.store, "r", "control", SHA_A, "t2")["confirmed"])
        self.age("r", f"control-{SHA_A}.json", ts.UNCONFIRMED_TTL + 5)
        with self.assertRaises(ts.Refused) as ctx:
            ts.reserve_control(self.store, "r", SHA_A, "t3")
        self.assertIn(f"release --kind control --key {SHA_A}", ctx.exception.message)

    def test_full_reservation_lifecycle_and_release_text(self):  # F2
        give_evidence(self.store, "r", SHA_A, self.dir)
        ts.reserve_full(self.store, "r", SHA_A, "t1")
        self.age("r", f"full-{SHA_A}.json", ts.UNCONFIRMED_TTL + 5)
        self.assertTrue(ts.reserve_full(self.store, "r", SHA_A, "t2")["allowed"])
        ts.confirm_reservation(self.store, "r", "full", SHA_A, "t2")
        self.age("r", f"full-{SHA_A}.json", ts.UNCONFIRMED_TTL + 5)
        with self.assertRaises(ts.Refused) as ctx:
            ts.reserve_full(self.store, "r", SHA_A, "t3")
        self.assertIn(f"release --kind full --key {SHA_A}", ctx.exception.message)
        self.assertEqual(ts.confirm_reservation(self.store, "r", "full", SHA_A, "wrong")["confirmed"], False)

    def test_post_hook_confirms_a_launch_that_really_ran(self):  # F2
        repo = make_repo(self.dir)
        run(repo, "git", "checkout", "-q", "-b", "feat")
        (repo / "harness" / "hooks" / "a.py").write_text("VALUE = 5\n")
        run(repo, "git", "commit", "-q", "-am", "delta")
        head = run(repo, "git", "rev-parse", "HEAD")
        with mock.patch.dict(os.environ, {"HARNESS_TEST_SCOPE_ROOT": str(self.dir / "store")}):
            rid = ts.repo_context(str(repo))["repo_id"]
            give_evidence(self.store, rid, head, self.dir)
            payload = {"tool_name": "Bash", "session_id": "s1", "agent_id": "a1", "cwd": str(repo),
                       "tool_input": {"command": FULL_CMD}}
            self.assertEqual(ts.hook_decision(payload, ts.load_policy()), (0, ""))
            rec = self.store.read(rid, f"full-{head}.json", {"repo_id": rid, "head": head, "kind": "full"})
            self.assertFalse(rec.get("confirmed"))
            ts.post_decision(payload, ts.load_policy())
            rec = self.store.read(rid, f"full-{head}.json", {"repo_id": rid, "head": head, "kind": "full"})
            self.assertTrue(rec["confirmed"])
            ts.post_decision({**payload, "session_id": "", "agent_id": ""}, ts.load_policy())  # anonymous: ignored

    def test_post_hook_entry_point_fails_open(self):  # F2
        for raw in ("not json", "", "[1]"):
            r = subprocess.run([sys.executable, "-I", str(HOOKS / "test_scope.py"), "post"], input=raw, capture_output=True,
                               text=True, timeout=30)
            self.assertEqual(r.returncode, 0, raw)

    def test_guarded_reservation_that_never_starts_frees_itself_and_confirm_pins_it(self):  # F3
        ts.guarded_full_start(SHA_A, "usage_guard:o1", root=self.store.root)
        with self.assertRaises(ts.Refused):
            ts.guarded_full_start(SHA_A, "usage_guard:o2", root=self.store.root)
        self.age("_guarded", f"full-{SHA_A}.json", ts.UNCONFIRMED_TTL + 5)
        ts.guarded_full_start(SHA_A, "usage_guard:o2", root=self.store.root)  # o1's start failed after reserving
        ts.guarded_full_confirm(SHA_A, "usage_guard:o2", root=self.store.root)
        self.age("_guarded", f"full-{SHA_A}.json", ts.UNCONFIRMED_TTL + 5)
        with self.assertRaises(ts.Refused):
            ts.guarded_full_start(SHA_A, "usage_guard:o3", root=self.store.root)

    def test_hook_reservation_is_adopted_only_moments_after_it_was_made(self):  # F4
        give_evidence(self.store, "r", SHA_A, self.dir)
        ts.reserve_full(self.store, "r", SHA_A, "hook-owner-A")
        self.age("r", f"full-{SHA_A}.json", ts.ADOPT_S + 5)
        with self.assertRaises(ts.Refused):  # another owner's later launch is a duplicate, not the same launch
            ts.guarded_full_start(SHA_A, "usage_guard:B", root=self.store.root)

    def test_ssh_hop_is_marked_local_and_cli_obeys_it(self):  # F5
        seen = []

        def fake_run(cmd, **kw):
            seen.append(cmd[-1])
            return subprocess.CompletedProcess(cmd, 0, stdout='{"ok": true}', stderr="")
        with mock.patch.object(subprocess, "run", fake_run):
            ts.run_remote("dev2", ["control", "--repo-id=r"], 8)
        self.assertIn("test_scope.py --local control", seen[0])
        with mock.patch.object(ts, "store_is_remote", return_value=True), mock.patch.object(ts, "run_remote") as rr:
            code, data = ts.cli(["--local", "--root", str(self.dir / "s"), "baseline-get", "--repo-id", "r",
                                 "--main-sha", SHA_A], capture=True)
        self.assertEqual(code, 1)
        rr.assert_not_called()

    def test_guarded_path_creates_no_store_on_a_non_store_host(self):  # F6
        root = self.dir / "should-not-exist"
        policy = ts.load_policy()
        with mock.patch.object(ts, "store_is_remote", return_value=True):
            ts.guarded_full_start(SHA_A, "usage_guard:o1")
            ts.guarded_full_confirm(SHA_A, "usage_guard:o1")
        self.assertFalse(root.exists())
        self.assertFalse((Path.home() / ".agent-harness" / "test-scope" / "_guarded" / f"full-{SHA_A}.json").exists())

    def test_real_peer_review_header_with_a_note_line_is_accepted(self):  # F8
        packet = self.dir / "p.md"
        packet.write_bytes(PACKET_BYTES)
        header = (f"Reviewer: codex\nStage: code-inspection\nReviewed HEAD: {SHA_A}\nReviewed packet SHA-256: {PACKET_SHA}\n"
                  "Review input: isolated committed snapshot (depth 1)\nWorktree status: clean\n")
        for note in ("", "note: second reviewer unavailable"):
            path = self.dir / "r.txt"
            path.write_text(f"{header}{note}\nCODE_INSPECTION_RESULT: ACCEPT\nbody\n")
            self.assertEqual(len(ts.validate_report(SHA_A, path, packet)), 64, repr(note))
        path.write_text(f"{header}\nsome preamble\nCODE_INSPECTION_RESULT: ACCEPT\n")
        with self.assertRaises(ts.Refused):
            ts.validate_report(SHA_A, path, packet)

    def test_repo_id_credentials_with_an_at_sign_and_ports(self):  # F7
        for url in ("https://u:p@ss@github.com/o/r", "https://u:p%40ss@github.com/o/r.git"):
            rid = ts.repo_id_for(url, "")
            self.assertNotIn("ss-github", rid)
            self.assertNotIn("u-p", rid)
        self.assertEqual(ts.repo_id_for("ssh://git@github.com:22/o/r.git", ""), ts.repo_id_for("git@github.com:o/r", ""))

    def test_package_qualified_imports_select_dependents(self):  # F7
        repo = make_repo(self.dir)
        (repo / "harness" / "hooks" / "core.py").write_text("V = 1\n")
        (repo / "tests" / "test_other.py").write_text("from harness.hooks.core import V\n")
        (repo / "tests" / "test_other2.py").write_text("from harness.hooks import core\n")
        (repo / "tests" / "test_other3.py").write_text("import harness.hooks.core as c\n")
        run(repo, "git", "add", "-A")
        run(repo, "git", "commit", "-q", "-m", "core")
        base = run(repo, "git", "rev-parse", "HEAD")
        (repo / "harness" / "hooks" / "core.py").write_text("V = 2\n")
        run(repo, "git", "commit", "-q", "-am", "change core")
        out = ts.focused_scope(str(repo), base, run(repo, "git", "rev-parse", "HEAD"))
        self.assertTrue({"test_other", "test_other2", "test_other3"} <= set(out["tests"]), out["tests"])

    def test_installer_registers_the_post_hook(self):  # F2
        import install
        hooks = install.managed_hooks(Path("/h/.claude"), True)
        groups = [g for g in hooks.get("PostToolUse", []) if "test_scope.py" in json.dumps(g)]
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0]["matcher"], "Bash")
        self.assertIn('"post"', json.dumps(groups[0]))


class FourthReview(Tmp):
    """Findings of the delta review of d5cc7bf."""

    def test_usage_guard_start_adopt_then_confirm_does_not_strand_the_run(self):  # F1
        give_evidence(self.store, "r", SHA_A, self.dir)
        ts.reserve_full(self.store, "r", SHA_A, "sid:agent")  # the PreToolUse hook
        ts.guarded_full_start(SHA_A, "usage_guard:own", root=self.store.root)  # begin(): reserve (adopts)
        ts.guarded_full_start(SHA_A, "usage_guard:own", root=self.store.root, confirm=True)  # begin(): confirm
        ts.guarded_full_confirm(SHA_A, "usage_guard:own", root=self.store.root)
        rec = self.store.read("r", f"full-{SHA_A}.json", {"repo_id": "r", "head": SHA_A, "kind": "full"})
        self.assertTrue(rec["confirmed"])
        with self.assertRaises(ts.Refused):  # still a duplicate for anyone else
            ts.guarded_full_start(SHA_A, "usage_guard:other", root=self.store.root)

    def test_guarded_only_start_then_confirm_by_the_same_owner(self):  # F1
        ts.guarded_full_start(SHA_B, "usage_guard:o1", root=self.store.root)
        ts.guarded_full_start(SHA_B, "usage_guard:o1", root=self.store.root, confirm=True)
        rec = self.store.read("_guarded", f"full-{SHA_B}.json", {"repo_id": "_guarded", "head": SHA_B, "kind": "full"})
        self.assertTrue(rec["confirmed"])

    def test_denied_launch_does_not_block_its_own_owner_for_ten_minutes(self):  # F2
        give_evidence(self.store, "r", SHA_A, self.dir)
        ts.reserve_full(self.store, "r", SHA_A, "owner")
        path = self.store.dir("r") / f"full-{SHA_A}.json"
        rec = json.loads(path.read_text())
        rec["at"] = time.time() - 300
        path.write_text(json.dumps(rec))
        self.assertTrue(ts.reserve_full(self.store, "r", SHA_A, "owner")["allowed"])  # 5 minutes later, same owner
        ts.reserve_control(self.store, "r", SHA_B, "owner")
        path = self.store.dir("r") / f"control-{SHA_B}.json"
        rec = json.loads(path.read_text())
        rec["at"] = time.time() - 300
        path.write_text(json.dumps(rec))
        self.assertTrue(ts.reserve_control(self.store, "r", SHA_B, "owner")["allowed"])
        with self.assertRaises(ts.Refused):  # another owner still waits
            ts.reserve_control(self.store, "r", SHA_B, "someone-else")

    def test_failed_suites_are_confirmed_too(self):  # F3
        import install
        hooks = install.managed_hooks(Path("/h/.claude"), True)
        for event in ("PostToolUse", "PostToolUseFailure"):
            groups = [g for g in hooks.get(event, []) if "test_scope.py" in json.dumps(g)]
            self.assertEqual(len(groups), 1, event)
            self.assertIn('"post"', json.dumps(groups[0]))

    def test_ssh_forms_through_wrappers_segments_clusters_and_double_dash(self):  # F4
        for cmd, expect in (("cd /tmp && ssh dev2 'pytest'", ["pytest"]), ("time ssh dev2 pytest", ["pytest"]),
                            ("nohup ssh dev2 pytest &", ["pytest"]), ("timeout 900 ssh dev2 pytest", ["pytest"]),
                            ("ssh dev2 'echo a' && ssh dev2 pytest", ["echo a", "pytest"]), ("bash -c 'ssh dev2 pytest'", ["pytest"]),
                            ("ssh dev2 -- pytest", ["pytest"]), ("ssh -tp 22 dev2 pytest", ["pytest"]),
                            ("FOO=1 ssh -o BatchMode=yes dev2 make test", ["make test"]), ("ls", []), ("ssh dev2", [])):
            self.assertEqual(ts.ssh_inners(cmd), expect, cmd)
        for cmd in ("cd /tmp && ssh dev2 'python3 -m unittest discover -s tests'", "time ssh dev2 pytest",
                    "ssh -tp 22 dev2 make test", "bash -c 'ssh dev2 pytest'"):
            self.assertTrue(ts.suite_launch(cmd, "/tmp"), cmd)
        self.assertFalse(ts.suite_launch("ssh dev2 uptime", "/tmp"))

    def test_prefilter_skips_the_classifier_for_ordinary_commands(self):  # F7
        for cmd in ("ls -la", "git status", "cat README.md", "echo hi", "rg foo src"):
            self.assertFalse(ts.SUITE_HINT.search(cmd), cmd)
        for cmd in ("python3 -m unittest discover", "pytest", "make test", "ssh dev2 uptime", "npm run build"):
            self.assertTrue(ts.SUITE_HINT.search(cmd), cmd)
        with mock.patch.dict(sys.modules, {"heavy_job_guard": None}):  # import would fail: the prefilter must come first
            self.assertFalse(ts.suite_launch("ls -la", "/tmp"))


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
