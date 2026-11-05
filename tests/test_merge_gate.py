"""merge_gate.py: block PR merges unless every required and reported check on the exact head is green.

Corpora live in tests/data/*.json (safety rule S1: data read here, never run through a shell). Every gh call goes
through a fake runner; the fake raises if the gate ever tries a merge, so no test can merge anything."""

import io
import json
import os
import shlex
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
HOOKS = Path(os.environ.get("MERGE_GATE_HOOKS_DIR") or ROOT / "harness" / "hooks")  # override: failing-first run on old code
sys.path.insert(0, str(HOOKS))
import merge_gate as mg  # noqa: E402

HEAD = "a" * 40
OTHER = "b" * 40
SQ = "'"
CORPUS = json.loads((HERE / "data" / "merge_gate_corpus.json").read_text())
SCENARIOS = json.loads((HERE / "data" / "merge_gate_scenarios.json").read_text())["scenarios"]
URL = "https://github.com/o/r/pull/5"


def expand(text):
    return text.replace("{HEAD}", HEAD).replace("{OTHER}", OTHER).replace("{SQ}", SQ)


class FakeGh:
    """Fake gh. Raises AssertionError if asked to merge: the gate must only read."""

    def __init__(self, scenario):
        self.sc = scenario
        self.calls = []
        self.timeouts = []
        self.pr_views = 0

    def _fail(self, key, args, timeout):
        if self.sc.get("timeout") == key:
            raise subprocess.TimeoutExpired(args, timeout)
        if self.sc.get("bad_json") == key:
            return 0, "{not json", ""
        return None

    def __call__(self, args, timeout, cwd=None):
        args = list(args)
        self.calls.append(args)
        self.timeouts.append(timeout)
        sc = self.sc
        joined = " ".join(args)
        assert args[:2] != ["pr", "merge"], "gate tried to merge"
        assert not ("-X" in args and "PUT" in args) and "--method" not in args, "gate tried a write: " + joined
        head = HEAD
        if args[:2] == ["pr", "view"]:
            self.pr_views += 1
            hit = self._fail("pr_view", args, timeout)
            if hit:
                return hit
            if sc.get("pr_view_fail"):
                return 1, "", "no pull requests found"
            if sc.get("head_moves") and self.pr_views > 1:
                head = OTHER
            rollup = []
            for c in sc["checks"]:
                if c["t"] == "run":
                    rollup.append({"__typename": "CheckRun", "name": c["name"], "status": c["status"],
                                   "conclusion": c["conclusion"], "workflowName": "ci",
                                   "startedAt": c.get("started", "")})
                else:
                    rollup.append({"__typename": "StatusContext", "context": c["context"], "state": c["state"]})
            return 0, json.dumps({"number": 5, "url": URL, "headRefOid": head, "baseRefName": "main",
                                  "state": "OPEN", "mergeStateStatus": sc.get("merge_state", "CLEAN"),
                                  "statusCheckRollup": rollup}), ""
        if args[:2] == ["repo", "view"]:
            return 0, json.dumps({"nameWithOwner": "o/r"}), ""
        if args[:2] == ["pr", "checks"]:
            if sc.get("pr_required_error"):
                return 1, "", "HTTP 403"
            required = sc.get("pr_required")
            if required is None:
                required = list((sc["protection"] or {}).get("contexts", [])) if isinstance(sc["protection"], dict) else []
                required += sc.get("rules", [])
            if not required:
                return 1, "", "no required checks reported on the 'main' branch"
            return 0, json.dumps([{"name": n, "bucket": "pass", "state": "SUCCESS"} for n in required]), ""
        if args[0] == "api":
            path = next((a for a in args[1:] if not a.startswith("-")), "")
            if path == "graphql":
                if sc.get("node_fail"):
                    return 1, "", "Could not resolve to a node"
                return 0, json.dumps({"data": {"node": {"number": 5, "url": URL, "headRefOid": HEAD}}}), ""
            if "/check-runs" in path:
                hit = self._fail("check_runs", args, timeout)
                if hit:
                    return hit
                runs = []
                for c in sc["checks"]:
                    if c["t"] == "run":
                        runs.append({"name": c["name"], "status": c["status"].lower(),
                                     "conclusion": (sc.get("api_conclusion") or c["conclusion"] or None) and
                                     (sc.get("api_conclusion") or c["conclusion"]).lower() or None,
                                     "head_sha": OTHER if sc.get("head_mismatch_runs") else HEAD,
                                     "started_at": c.get("started"), "app": {"id": c.get("app_id", 15368)}})
                total = len(runs) + (5 if sc.get("truncate_runs") else 0)
                return 0, json.dumps({"total_count": total, "check_runs": runs}), ""
            if path.endswith("/status") or "/status?" in path:
                hit = self._fail("statuses", args, timeout)
                if hit:
                    return hit
                sts = [{"context": c["context"], "state": c["state"].lower()} for c in sc["checks"] if c["t"] == "status"]
                total = 0 if sc.get("status_total_zero") else len(sts)
                state = "pending" if total == 0 else ("success" if all(s["state"] == "success" for s in sts) else "failure")
                return 0, json.dumps({"state": state, "sha": HEAD, "total_count": total, "statuses": sts}), ""
            if "/protection/required_status_checks" in path:
                hit = self._fail("protection", args, timeout)
                if hit:
                    return hit
                prot = sc["protection"]
                if prot == "none":
                    return 1, '{"message":"Branch not protected","status":"404"}', "gh: Branch not protected (HTTP 404)"
                if prot == "error":
                    return 1, "", "gh: Resource not accessible by integration (HTTP 403)"
                apps = prot.get("app_ids", {})
                return 0, json.dumps({"strict": True, "contexts": prot["contexts"],
                                      "checks": [{"context": n, "app_id": apps.get(n, -1)} for n in prot["contexts"]]}), ""
            if "/rules/branches/" in path:
                if sc.get("rules_error"):
                    return 1, "", "HTTP 500"
                rules = [{"type": "required_status_checks",
                          "parameters": {"required_status_checks": [{"context": n} for n in sc.get("rules", [])]}}] if sc.get("rules") else []
                return 0, json.dumps(rules), ""
            if "/actions/workflows" in path:
                return 0, json.dumps({"total_count": sc.get("workflows", 1), "workflows": []}), ""
        raise AssertionError("unexpected gh call: " + joined)


def bash(command, **extra):
    payload = {"tool_name": "Bash", "tool_input": {"command": command}, "cwd": "/work", "session_id": "sess-main"}
    payload.update(extra)
    return payload


class Base(unittest.TestCase):
    def setUp(self):
        self.state = Path(tempfile.mkdtemp(prefix="mg-state-"))
        self.addCleanup(__import__("shutil").rmtree, self.state, True)

    def decide(self, command, scenario="green", **extra):
        gh = FakeGh(SCENARIOS[scenario])
        code, text = mg.decide(bash(expand(command), **extra), gh, self.state)
        return code, text, gh


class Corpus(unittest.TestCase):
    def test_corpus_is_not_empty(self):
        self.assertGreaterEqual(len(CORPUS["detection"]), 50)
        self.assertGreaterEqual(len(CORPUS["decisions"]), 60)
        self.assertGreaterEqual(len(SCENARIOS), 35)
        for category in ("pr_merge", "rest", "graphql", "unverifiable"):
            self.assertGreaterEqual(sum(category in e["kinds"] for e in CORPUS["detection"]), 4, category)
        self.assertGreaterEqual(sum(e["kinds"] == [] for e in CORPUS["detection"]), 10)
        self.assertGreaterEqual(sum(e["expect"] == "allow" for e in CORPUS["decisions"]), 10)
        self.assertGreaterEqual(sum(e["expect"] == "block" for e in CORPUS["decisions"]), 40)

    def test_detection_corpus(self):
        for entry in CORPUS["detection"]:
            with self.subTest(entry["id"]):
                kinds = sorted({m.kind for m in mg.find_merges(expand(entry["command"]), cwd="/work")})
                self.assertEqual(kinds, sorted(set(entry["kinds"])), entry["command"])


class Decisions(Base):
    def test_decision_corpus(self):
        for entry in CORPUS["decisions"]:
            with self.subTest(entry["id"]):
                code, text, gh = self.decide(entry["command"], entry["scenario"])
                want = 0 if entry["expect"] == "allow" else 2
                self.assertEqual(code, want, f"{entry['id']}: {text}")
                if entry.get("text"):
                    self.assertIn(entry["text"], text)
                self.assertTrue(all(t <= mg.CALL_TIMEOUT_MAX for t in gh.timeouts), gh.timeouts)
                if entry["expect"] == "block":
                    self.assertIn("merge-gate", text)

    def test_block_text_is_sanitized(self):
        _, text, _ = self.decide("gh pr merge 5 --match-head-commit {HEAD}", "evil_names")
        self.assertNotIn("\x1b", text)
        self.assertNotIn("\x07", text)
        self.assertLess(len(text), 4000)

    def test_no_waiver_attaches_to_unverifiable_shapes(self):
        for entry in CORPUS["decisions"]:
            if not entry.get("nowaiver"):
                continue
            with self.subTest(entry["id"]):
                for repo, pr in (("o/r", 5), ("o/r", 6)):
                    mg.add_waiver(self.state, repo, pr, HEAD, "GoodQA #1", "waiver should not attach here",
                                  approved_by="main:agent-1")
                code, text, _ = self.decide(entry["command"], entry["scenario"])
                self.assertEqual(code, 2, text)

    def test_every_gh_call_is_read_only_and_bounded(self):
        _, _, gh = self.decide("gh pr merge 5 --squash --match-head-commit {HEAD}", "green")
        self.assertGreaterEqual(len(gh.calls), 4)
        self.assertEqual(max(gh.timeouts) <= mg.CALL_TIMEOUT_MAX, True)

    def test_depth_limit_blocks(self):
        command = "gh pr merge 5 --match-head-commit " + HEAD
        for _ in range(8):
            command = "bash -c " + shlex.quote(command)
        code, text, _ = self.decide(command, "green")
        self.assertEqual(code, 2, text)

    def test_oversize_command_with_gh_blocks_without_gh_allows(self):
        big = "echo " + "x" * (mg.MAX_COMMAND_CHARS + 10)
        self.assertEqual(self.decide(big)[0], 0)
        self.assertEqual(self.decide(big + " ; gh pr merge 5")[0], 2)

    def test_old_harness_stub_is_the_failing_control(self):
        """The fake-gh red scenario must be blocked; an allow-everything gate (old harness) would return 0."""
        code, _, _ = self.decide("gh pr merge 5 --match-head-commit {HEAD}", "red_netwatch")
        self.assertEqual(code, 2)
        code, _, _ = self.decide("gh pr merge 5 --match-head-commit {HEAD}", "pending_run")
        self.assertEqual(code, 2)
        code, _, _ = self.decide("gh pr merge 5 --match-head-commit {HEAD}", "zero_required")
        self.assertEqual(code, 2)


class Waivers(Base):
    CMD = "gh pr merge 5 --match-head-commit {HEAD}"

    def waive(self, **over):
        args = dict(repo="o/r", pr=5, head=HEAD, ticket="GoodQA #14502",
                    reason="owner approved after manual review", approved_by="main:agent-1")
        args.update(over)
        return mg.add_waiver(self.state, **args)

    def test_waiver_allows_red_merge_exactly_once(self):
        self.waive()
        code, text, _ = self.decide(self.CMD, "red_netwatch")
        self.assertEqual(code, 0, text)
        code, text, _ = self.decide(self.CMD, "red_netwatch")
        self.assertEqual(code, 2, "replayed waiver must not work: " + text)

    def test_waiver_for_other_sha_pr_repo(self):
        for name, over in (("sha", {"head": OTHER}), ("pr", {"pr": 6}), ("repo", {"repo": "o/other"})):
            with self.subTest(name):
                self.waive(**over)
                code, text, _ = self.decide(self.CMD, "red_netwatch")
                self.assertEqual(code, 2, text)

    def test_waived_merge_still_needs_head_binding(self):
        self.waive()
        code, text, _ = self.decide("gh pr merge 5", "red_netwatch")
        self.assertEqual(code, 2, text)

    def test_expired_waiver(self):
        self.waive()
        gh = FakeGh(SCENARIOS["red_netwatch"])
        code, _ = mg.decide(bash(expand(self.CMD)), gh, self.state, now=time.time() + 25 * 3600)
        self.assertEqual(code, 2)

    def test_validation(self):
        for over in ({"repo": "nope"}, {"pr": 0}, {"head": "abc"}, {"ticket": "ticket 5"}, {"reason": "short"},
                     {"approved_by": "alice"}):
            with self.subTest(over), self.assertRaises(ValueError):
                self.waive(**over)

    def test_forged_line_corrupts_log(self):
        self.waive()
        path = self.state / mg.WAIVER_FILE
        with open(path, "a") as handle:
            handle.write(json.dumps({"v": 1, "event": "waive", "id": "mgw-forged", "repo": "o/r", "pr": 5,
                                     "head": HEAD, "ticket": "GoodQA #1", "reason": "forged forged forged",
                                     "approved_by": "main:x", "ts": time.time(), "prev": "0" * 64}) + "\n")
        code, text, _ = self.decide(self.CMD, "red_netwatch")
        self.assertEqual(code, 2, text)
        self.assertIn("CORRUPT", mg.report_text(self.state))

    def test_truncated_used_record_does_not_revive(self):
        self.waive()
        self.assertEqual(self.decide(self.CMD, "red_netwatch")[0], 0)
        path = self.state / mg.WAIVER_FILE
        lines = path.read_bytes().splitlines(True)
        path.write_bytes(b"".join(lines[:-1]))
        self.assertEqual(self.decide(self.CMD, "red_netwatch")[0], 2)

    def test_concurrent_consume_one_winner(self):
        wid = self.waive()["id"]
        results = []

        def worker():
            results.append(mg.consume_waiver(self.state, "o/r", 5, HEAD, "cmdhash"))

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(sum(1 for r in results if r == wid), 1, results)

    def test_report_lists_waivers(self):
        self.waive()
        self.waive(pr=6, approved_by="main:agent-2")
        self.decide(self.CMD, "red_netwatch")
        text = mg.report_text(self.state)
        self.assertIn("GoodQA #14502", text)
        self.assertIn("used", text)
        self.assertIn("unused", text)
        self.assertIn("asserted", text)

    def test_audit_has_command_hash_not_text(self):
        self.decide("gh pr merge 5 --match-head-commit {HEAD} --body SECRETTOKEN123", "red_netwatch")
        audit = (self.state / mg.AUDIT_FILE).read_text()
        self.assertNotIn("SECRETTOKEN123", audit)
        self.assertIn("block", audit)

    def test_cli_waive_requires_approval(self):
        out, err = io.StringIO(), io.StringIO()
        base = ["waive", "--state-dir", str(self.state), "--repo", "o/r", "--pr", "5", "--head", HEAD,
                "--ticket", "GoodQA #14502", "--reason", "approved by main after review"]
        self.assertEqual(mg.main(base, runner=FakeGh(SCENARIOS["green"]), stdout=out, stderr=err), 3)
        self.assertEqual(mg.main(base + ["--approved-by", "main:agent-9"], runner=FakeGh(SCENARIOS["green"]),
                                 stdout=out, stderr=err), 0, err.getvalue())
        self.assertIn("asserted", mg.report_text(self.state))

    def test_hook_stamp_gives_hook_approval_and_subagent_cannot_waive(self):
        cmd = ("python3 ~/.claude/hooks/merge_gate.py waive --repo o/r --pr 5 --head " + HEAD +
               " --ticket 'GoodQA #14502' --reason 'approved by main after review'")
        code, text = mg.decide(bash(cmd), FakeGh(SCENARIOS["green"]), self.state)
        self.assertEqual(code, 0, text)
        out, err = io.StringIO(), io.StringIO()
        argv = ["waive", "--state-dir", str(self.state), "--repo", "o/r", "--pr", "5", "--head", HEAD,
                "--ticket", "GoodQA #14502", "--reason", "approved by main after review"]
        self.assertEqual(mg.main(argv, runner=FakeGh(SCENARIOS["green"]), stdout=out, stderr=err), 0, err.getvalue())
        self.assertIn("hook", mg.report_text(self.state))
        sub = bash(cmd, agent_id="agent-sub-1", agent_type="task-owner")
        code, text = mg.decide(sub, FakeGh(SCENARIOS["green"]), self.state)
        self.assertEqual(code, 2, text)

    def test_state_files_cannot_be_written_by_tools(self):
        gh = FakeGh(SCENARIOS["green"])
        for command in ("echo x >> ~/.agent-harness/state/merge-gate-waivers.jsonl",
                        "tee -a ~/.agent-harness/state/merge-gate-audit.jsonl < /dev/null",
                        "cp f ~/.agent-harness/state/merge-gate/approvals/k.json"):
            with self.subTest(command):
                self.assertEqual(mg.decide(bash(command), gh, self.state)[0], 2)
        for tool in ("Write", "Edit", "MultiEdit", "NotebookEdit"):
            with self.subTest(tool):
                payload = {"tool_name": tool, "tool_input": {"file_path": "/home/u/.agent-harness/state/merge-gate-waivers.jsonl"}}
                self.assertEqual(mg.decide(payload, gh, self.state)[0], 2)
        payload = {"tool_name": "Write", "tool_input": {"file_path": "/home/u/notes.txt"}}
        self.assertEqual(mg.decide(payload, gh, self.state)[0], 0)


class Hostile(Base):
    def run_main(self, data, runner=None):
        out, err = io.StringIO(), io.StringIO()
        code = mg.main(["hook", "--state-dir", str(self.state)], runner=runner or FakeGh(SCENARIOS["green"]),
                       stdin=io.BytesIO(data), stdout=out, stderr=err)
        return code, err.getvalue()

    def test_bad_inputs_fail_closed(self):
        self.assertEqual(self.run_main(b"not json")[0], 2)
        self.assertEqual(self.run_main(b"x" * (mg.MAX_STDIN_BYTES + 5))[0], 2)
        self.assertEqual(self.run_main(b"[" * 5000 + b"]" * 5000)[0], 2)
        self.assertEqual(self.run_main(b"")[0], 2)

    def test_command_types(self):
        argv = {"tool_name": "shell", "tool_input": {"command": ["gh", "pr", "merge", "5", "--match-head-commit", HEAD]}}
        code, _ = self.run_main(json.dumps(argv).encode(), FakeGh(SCENARIOS["red_netwatch"]))
        self.assertEqual(code, 2)
        bashc = {"tool_name": "local_shell", "tool_input": {"command": ["bash", "-lc", "gh pr merge 5 --match-head-commit " + HEAD]}}
        self.assertEqual(self.run_main(json.dumps(bashc).encode(), FakeGh(SCENARIOS["red_netwatch"]))[0], 2)
        self.assertEqual(self.run_main(json.dumps(bashc).encode(), FakeGh(SCENARIOS["green"]))[0], 0)
        weird = {"tool_name": "Bash", "tool_input": {"command": {"a": 1}}}
        self.assertEqual(self.run_main(json.dumps(weird).encode())[0], 2)
        other = {"tool_name": "Read", "tool_input": {"command": {"a": 1}}}
        self.assertEqual(self.run_main(json.dumps(other).encode())[0], 0)

    def test_internal_fault_blocks_merge_text_but_not_other_commands(self):
        original = mg.evaluate_merge

        def boom(*a, **k):
            raise RuntimeError("injected")

        mg.evaluate_merge = boom
        try:
            code, _ = self.run_main(json.dumps(bash("gh pr merge 5 --match-head-commit " + HEAD)).encode())
            self.assertEqual(code, 2)
            code, _ = self.run_main(json.dumps(bash("echo hello")).encode())
            self.assertEqual(code, 0)
        finally:
            mg.evaluate_merge = original

    def test_recursion_error_blocks(self):
        original = mg.find_merges

        def deep(*a, **k):
            raise RecursionError("injected")

        mg.find_merges = deep
        try:
            code, _ = self.run_main(json.dumps(bash("gh pr merge 5")).encode())
            self.assertEqual(code, 2)
        finally:
            mg.find_merges = original


class RedTeam(Base):
    """Findings of the code red-team (review-redteam.md) as failing controls."""

    def test_subagent_cannot_evade_waiver_guard_by_spelling(self):
        for command in ("python3 /h/merge_gate.py \"waive\" --repo o/r --pr 5 --head " + HEAD,
                        "python3 /h/merge_gate.py w''aive --repo o/r --approved-by main:x",
                        "python3 -c \"import merge_gate; merge_gate.add_waiver(1)\"",
                        "printf x >> ~/.agent-harness/state/merge-gate-w*",
                        "cp f ~/.agent-harness/state/merge-gate-wai\"\"vers.jsonl",
                        "M=merge_gate.py; python3 /h/$M waive --repo o/r"):
            with self.subTest(command):
                code, text = mg.decide(bash(command, agent_id="sub-1"), FakeGh(SCENARIOS["green"]), self.state)
                self.assertEqual(code, 2, text)

    def test_subagent_may_run_the_merge_gate_tests(self):
        code, _ = mg.decide(bash("python3 -m unittest tests.test_merge_gate -v", agent_id="sub-1"),
                            FakeGh(SCENARIOS["green"]), self.state)
        self.assertEqual(code, 0)

    def test_large_command_is_not_quadratic(self):
        command = "git add " + " ".join("file%d.txt" % i for i in range(4000))
        start = time.time()
        self.assertEqual(self.decide(command)[0], 0)
        self.assertLess(time.time() - start, 3.0)

    def test_non_object_payload_blocks(self):
        out, err = io.StringIO(), io.StringIO()
        code = mg.main(["hook", "--state-dir", str(self.state)], runner=FakeGh(SCENARIOS["green"]),
                       stdin=io.BytesIO(b"[]"), stdout=out, stderr=err)
        self.assertEqual(code, 2)

    def test_missing_helper_module_blocks_instead_of_exit_one(self):
        folder = Path(tempfile.mkdtemp(prefix="mg-broken-"))
        self.addCleanup(__import__("shutil").rmtree, folder, True)
        (folder / "merge_gate.py").write_bytes((HOOKS / "merge_gate.py").read_bytes())
        result = subprocess.run([sys.executable, str(folder / "merge_gate.py"), "hook"],
                                input=b"{}", capture_output=True, env={"PATH": "/usr/bin:/bin", "HOME": str(folder)})
        self.assertEqual(result.returncode, 2, result.stderr)

    def test_graphql_query_file_rewritten_by_same_command_blocks(self):
        folder = Path(tempfile.mkdtemp(prefix="mg-q-"))
        self.addCleanup(__import__("shutil").rmtree, folder, True)
        (folder / "q.graphql").write_text("query { viewer { login } }")
        kinds = {m.kind for m in mg.find_merges("printf x > q.graphql && gh api graphql -F query=@q.graphql",
                                                cwd=str(folder))}
        self.assertEqual(kinds, {"unverifiable"})
        kinds = {m.kind for m in mg.find_merges("gh api graphql -F query=@q.graphql", cwd=str(folder))}
        self.assertEqual(kinds, set())


class Subprocess(unittest.TestCase):
    """Real processes with a fake gh binary on a scratch PATH; no candidate command is executed."""

    def make_env(self, script):
        home = Path(tempfile.mkdtemp(prefix="mg-home-"))
        self.addCleanup(__import__("shutil").rmtree, home, True)
        bindir = home / "bin"
        bindir.mkdir()
        gh = bindir / "gh"
        gh.write_text(script)
        gh.chmod(0o755)
        env = {"HOME": str(home), "PATH": f"{bindir}:/usr/bin:/bin", "MERGE_GATE_CALL_TIMEOUT": "1",
               "MERGE_GATE_DEADLINE": "6"}
        return home, env

    def hook(self, env, payload=None, stdin=None, timeout=20):
        data = stdin if stdin is not None else json.dumps(payload).encode()
        return subprocess.run([sys.executable, str(HOOKS / "merge_gate.py"), "hook"], input=data, env=env,
                              capture_output=True, timeout=timeout)

    def test_sleeping_gh_times_out_and_blocks(self):
        marker_dir = tempfile.mkdtemp(prefix="mg-marker-")
        self.addCleanup(__import__("shutil").rmtree, marker_dir, True)
        script = "#!/bin/sh\n(sleep 30; echo late > %s/late) &\nsleep 30\n" % marker_dir
        home, env = self.make_env(script)
        start = time.time()
        result = self.hook(env, bash("gh pr merge 5 -R o/r --match-head-commit " + HEAD))
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertLess(time.time() - start, 15)
        self.assertIn(b"merge-gate", result.stderr)

    def test_huge_gh_output_is_cut_off(self):
        home, env = self.make_env("#!/bin/sh\nyes 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'\n")
        result = self.hook(env, bash("gh pr merge 5 -R o/r --match-head-commit " + HEAD))
        self.assertEqual(result.returncode, 2, result.stderr)

    def test_stdin_that_never_closes_blocks(self):
        home, env = self.make_env("#!/bin/sh\nexit 1\n")
        env["MERGE_GATE_DEADLINE"] = "2"
        proc = subprocess.Popen([sys.executable, str(HOOKS / "merge_gate.py"), "hook"], stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        try:
            proc.stdin.write(b'{"tool_name":"Bash","tool_input":{"command":"gh pr merge 5')
            proc.stdin.flush()
            code = proc.wait(timeout=15)
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()
        self.assertEqual(code, 2)

    def test_non_merge_command_passes_without_gh(self):
        home, env = self.make_env("#!/bin/sh\nexit 99\n")
        result = self.hook(env, bash("ls -la"))
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_gh_failure_blocks(self):
        home, env = self.make_env("#!/bin/sh\necho boom >&2\nexit 1\n")
        result = self.hook(env, bash("gh pr merge 5 -R o/r --match-head-commit " + HEAD))
        self.assertEqual(result.returncode, 2, result.stderr)


class Wiring(unittest.TestCase):
    def test_install_claude(self):
        sys.path.insert(0, str(ROOT))
        import install
        claude = Path("/home/example/.claude")
        groups = install.managed_hooks(claude)["PreToolUse"]
        gate = [h for g in groups for h in g["hooks"] if (h.get("args") or [""])[0].endswith("merge_gate.py")]
        self.assertEqual(len(gate), 1)
        self.assertEqual(gate[0]["onFailure"], "block")
        self.assertGreater(gate[0]["timeout"], mg.DEADLINE_SECONDS)
        group = next(g for g in groups if gate[0] in g["hooks"])
        for tool in ("Bash", "Write", "Edit", "MultiEdit", "NotebookEdit"):
            self.assertIn(tool, group["matcher"])
        self.assertIn("merge_gate.py", install.HOOKS)

    def test_install_codex(self):
        sys.path.insert(0, str(ROOT))
        import install_codex
        home = Path("/home/example/.codex")
        hooks = install_codex.merge_hooks({}, home)
        hooks = install_codex.merge_hooks(hooks, home)
        commands = [h["command"] for g in hooks["hooks"]["PreToolUse"] for h in g["hooks"]]
        gate = [c for c in commands if "merge_gate.py" in c]
        self.assertEqual(len(gate), 1)
        self.assertIn("|| exit 2", gate[0])
        self.assertIn("merge_gate.py", install_codex.DELIVERY_HELPERS)

    def test_deny_shape_is_exit_two_with_stderr(self):
        out, err = io.StringIO(), io.StringIO()
        data = json.dumps(bash("gh pr merge 5 --match-head-commit " + HEAD)).encode()
        code = mg.main(["hook", "--state-dir", tempfile.mkdtemp(prefix="mg-s-")], runner=FakeGh(SCENARIOS["red_netwatch"]),
                       stdin=io.BytesIO(data), stdout=out, stderr=err)
        self.assertEqual(code, 2)
        self.assertIn("merge-gate", err.getvalue())
        self.assertEqual(out.getvalue(), "")

    def test_rules_registry_entry(self):
        entry = json.loads((ROOT / "docs" / "rules" / "merge-gate.json").read_text())
        rules = entry["rules"] if "rules" in entry else [entry]
        self.assertTrue(rules)
        for rule in rules:
            for key in ("id", "rule", "mechanism", "test", "source"):
                self.assertTrue(rule.get(key), key)
            module, _, name = rule["test"].partition(".")
            self.assertTrue(hasattr(globals()[module], name), rule["test"])
        self.assertIn("ticket:GoodQA", json.dumps(rules))

    def test_policy_documented(self):
        text = (ROOT / "docs" / "operations.md").read_text().lower()
        for needle in ("merge gate", "skipped", "neutral", "--match-head-commit", "waive"):
            self.assertIn(needle, text)


class Receipts(Base):
    """AC-10 / NEG-20..24: with no GitHub CI the merge needs a local validation receipt bound to the exact head."""

    CMD = "gh pr merge 5 --match-head-commit {HEAD}"
    ZERO = ("zero_unprotected", "zero_unprotected_workflows")

    def setUp(self):
        super().setUp()
        self.work = Path(tempfile.mkdtemp(prefix="mg-evidence-"))
        self.addCleanup(__import__("shutil").rmtree, self.work, True)

    def report(self, head=HEAD, stage="pr", body="VERDICT: PASS\n\nLooks fine.\n", packet="c" * 64, name="report.md"):
        path = self.work / name
        path.write_text(f"Reviewer: Blind\nStage: {stage}\nReviewed HEAD: {head}\nReviewed packet SHA-256: {packet}\n"
                        f"Review input: isolated committed snapshot (depth 1)\nWorktree status: clean\n\n{body}",
                        encoding="utf-8")
        return path

    def log(self, text="Ran 1045 tests in 1578.1s\n\nOK (skipped=8)\n", name="suite.log"):
        path = self.work / name
        path.write_text(text, encoding="utf-8")
        return path

    def write(self, head=HEAD, pr=5, repo="o/r", exit_code=0, report=None, log=None, by="main:agent-9"):
        return mg.write_receipt(self.state, repo, pr, head, str(log or self.log()), exit_code, "1045 tests OK",
                                str(report or self.report(head=head)), by)

    def receipt_path(self, head=HEAD, pr=5, repo="o/r"):
        return self.state / mg.RECEIPTS_DIR / (mg.stamp_key(repo, pr, head, "receipt") + ".json")

    def forge(self, head=HEAD, report=None, log=None, exit_code=0, reviewed=None, packet="c" * 64):
        """A receipt written by hand with correct hashes: the gate must still read the evidence itself."""
        import hashlib
        report, log = report or self.report(head=head), log or self.log()
        sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
        record = {"v": 1, "repo": "o/r", "pr": 5, "head": head, "approved_by": "main:forged", "ts": time.time(),
                  "suite": {"log_path": str(log), "log_sha256": sha(log), "exit_code": exit_code, "summary": "ok"},
                  "review": {"report_path": str(report), "report_sha256": sha(report),
                             "reviewed_head": reviewed or head, "packet_sha256": packet}}
        path = self.receipt_path(head)
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        os.write(fd, json.dumps(record).encode())
        os.close(fd)
        return path

    def merge(self, scenario):
        code, text, _ = self.decide(self.CMD, scenario)
        return code, text

    def assertBlocked(self, scenario="zero_unprotected", needle="receipt"):
        code, text = self.merge(scenario)
        self.assertEqual(code, 2, text)
        self.assertIn(needle, text)
        return text

    def test_no_receipt_blocks_even_without_workflows(self):
        for scenario in self.ZERO:
            with self.subTest(scenario):
                self.assertBlocked(scenario)

    def test_valid_receipt_allows_both_zero_check_shapes(self):
        self.write()
        for scenario in self.ZERO:
            with self.subTest(scenario):
                code, text = self.merge(scenario)
                self.assertEqual(code, 0, text)

    def test_receipt_file_is_private(self):
        self.write()
        path = self.receipt_path()
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual((self.state / mg.RECEIPTS_DIR).stat().st_mode & 0o777, 0o700)

    def test_receipt_for_other_head_pr_or_repo_blocks(self):
        for name, over in (("head", {"head": OTHER}), ("pr", {"pr": 6}), ("repo", {"repo": "o/other"})):
            with self.subTest(name):
                self.write(**over)
                self.assertBlocked()

    def test_receipt_renamed_to_the_current_head_blocks(self):
        old = self.write(head=OTHER)
        src = self.receipt_path(head=OTHER)
        dst = self.receipt_path(head=HEAD)
        os.replace(str(src), str(dst))
        self.assertBlocked()

    def test_stale_receipt_after_head_moves(self):
        self.write(head=OTHER)  # the receipt belongs to the head before the push
        self.assertBlocked()

    def test_edited_report_blocks(self):
        report = self.report()
        self.write(report=report)
        report.write_text(report.read_text() + "\nVERDICT: PASS\n", encoding="utf-8")
        self.assertBlocked(needle="report")

    def test_edited_or_missing_log_blocks(self):
        log = self.log()
        self.write(log=log)
        log.write_text("Ran 1 tests\n\nOK\n", encoding="utf-8")
        self.assertBlocked(needle="log")
        log.unlink()
        self.assertBlocked(needle="log")

    def test_report_swapped_for_symlink_blocks(self):
        report = self.report()
        self.write(report=report)
        copy = self.work / "copy.md"
        copy.write_bytes(report.read_bytes())
        report.unlink()
        os.symlink(str(copy), str(report))
        self.assertBlocked(needle="report")

    def test_report_or_log_path_must_be_absolute_file(self):
        with self.assertRaises(ValueError):
            mg.write_receipt(self.state, "o/r", 5, HEAD, "suite.log", 0, "ok", str(self.report()), "main:agent-9")
        with self.assertRaises(ValueError):
            mg.write_receipt(self.state, "o/r", 5, HEAD, str(self.work), 0, "ok", str(self.report()), "main:agent-9")

    def test_loose_receipt_permissions_block(self):
        self.write()
        path = self.receipt_path()
        for mode in (0o644, 0o640, 0o660, 0o606, 0o666):
            with self.subTest(oct(mode)):
                os.chmod(str(path), mode)
                self.assertBlocked(needle="permission")
        os.chmod(str(path), 0o600)
        code, text = self.merge("zero_unprotected")
        self.assertEqual(code, 0, text)

    def test_receipt_owned_by_someone_else_blocks(self):
        from unittest import mock
        self.write()
        with mock.patch.object(mg.os, "geteuid", return_value=os.geteuid() + 1):
            self.assertBlocked(needle="current user")

    def test_symlink_oversized_and_garbage_receipts_block(self):
        path = self.forge()
        real = self.work / "real.json"
        real.write_bytes(path.read_bytes())
        os.chmod(str(real), 0o600)
        path.unlink()
        os.symlink(str(real), str(path))
        self.assertBlocked()
        path.unlink()
        for junk in (b"{not json", b"[]", b"null", b"x" * (mg.MAX_RECEIPT_BYTES + 10)):
            with self.subTest(junk[:12]):
                fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                os.write(fd, junk)
                os.close(fd)
                self.assertBlocked()

    def test_report_naming_a_different_head_is_refused_and_blocks(self):
        bad = self.report(head=OTHER)
        with self.assertRaises(ValueError):
            self.write(report=bad)
        self.assertFalse(self.receipt_path().exists())
        self.forge(report=bad, reviewed=HEAD)  # the receipt lies about it; the gate reads the report itself
        self.assertBlocked(needle="Reviewed HEAD")

    def test_wrong_stage_or_verdict_is_refused_and_blocks(self):
        cases = {
            "plan-stage": self.report(stage="plan", name="r1.md"),
            "code-inspection": self.report(stage="code-inspection", body="CODE_INSPECTION_RESULT: ACCEPT\n", name="r2.md"),
            "block": self.report(body="VERDICT: BLOCK\n\nF1 high\n", name="r3.md"),
            "pass-in-body": self.report(body="Summary.\n\nVERDICT: PASS\n", name="r4.md"),
            "pass-in-header": self.work / "r5.md",
        }
        cases["pass-in-header"].write_text(f"Stage: pr\nReviewed HEAD: {HEAD}\nReviewed packet SHA-256: {'c' * 64}\n"
                                           "Fallback reason: VERDICT: PASS\n\nVERDICT: BLOCK\n")
        for name, report in cases.items():
            with self.subTest(name):
                with self.assertRaises(ValueError):
                    self.write(report=report)
                self.forge(report=report)
                self.assertBlocked(needle="report")

    def test_failing_suite_is_refused_and_blocks(self):
        with self.assertRaises(ValueError):
            self.write(exit_code=1)
        self.forge(exit_code=1)
        self.assertBlocked(needle="suite")

    def test_missing_packet_sha_in_report_blocks(self):
        report = self.work / "nopacket.md"
        report.write_text(f"Stage: pr\nReviewed HEAD: {HEAD}\n\nVERDICT: PASS\n")
        with self.assertRaises(ValueError):
            self.write(report=report)

    def test_receipt_never_overrides_a_reported_failure_or_missing_required_check(self):
        self.write()
        for scenario in ("red_netwatch", "zero_required", "status_pending"):
            with self.subTest(scenario):
                code, text, _ = self.decide(self.CMD, scenario)
                self.assertEqual(code, 2, text)

    def test_receipt_does_not_replace_the_head_binding(self):
        self.write()
        code, text, _ = self.decide("gh pr merge 5", "zero_unprotected")
        self.assertEqual(code, 2, text)

    def test_waiver_still_works_without_receipt(self):
        mg.add_waiver(self.state, "o/r", 5, HEAD, "GoodQA #14502", "approved by main after review", "main:agent-9")
        code, text = self.merge("zero_unprotected")
        self.assertEqual(code, 0, text)

    def test_gate_and_check_never_write_a_receipt(self):
        self.merge("zero_unprotected")
        out, err = io.StringIO(), io.StringIO()
        mg.main(["check", "--state-dir", str(self.state), "--repo", "o/r", "--pr", "5"],
                runner=FakeGh(SCENARIOS["zero_unprotected"]), stdout=out, stderr=err)
        self.assertFalse((self.state / mg.RECEIPTS_DIR).exists() and any((self.state / mg.RECEIPTS_DIR).iterdir()))

    def test_audit_records_receipt_use(self):
        self.write()
        self.merge("zero_unprotected")
        tail = (self.state / mg.AUDIT_FILE).read_text().splitlines()[-1]
        self.assertTrue(json.loads(tail).get("receipt"))

    def receipt_command(self, path=None):
        return ("python3 ~/.claude/hooks/merge_gate.py receipt --repo o/r --pr 5 --head " + HEAD +
                " --suite-log /x/suite.log --suite-exit 0 --suite-summary ok --review-report /x/r.md "
                "--approved-by main:agent-9")

    def test_subagent_cannot_write_a_receipt_by_any_route(self):
        sub = dict(agent_id="agent-sub-1", agent_type="task-owner")
        gh = FakeGh(SCENARIOS["green"])
        routes = [
            self.receipt_command(),
            "python3 ~/.claude/hooks/merge_gate.py 're''ceipt' --repo o/r",
            "echo '{}' > ~/.agent-harness/state/merge-gate-receipts/x.json",
            "cp /tmp/r.json ~/.agent-harness/state/merge-gate-receipts/",
            "cat > ~/.agent-harness/state/merge-gate-rec*/abc.json",
            "python3 -c \"import merge_gate as m; m.write_receipt(1)\"",
        ]
        for command in routes:
            with self.subTest(command):
                code, text = mg.decide(bash(command, **sub), gh, self.state)
                self.assertEqual(code, 2, text)
        for tool in ("Write", "Edit"):
            payload = {"tool_name": tool, "agent_id": "agent-sub-1",
                       "tool_input": {"file_path": "/Users/x/.agent-harness/state/merge-gate-receipts/a.json", "content": "{}"}}
            self.assertEqual(mg.decide(payload, gh, self.state)[0], 2)

    def test_main_may_run_the_receipt_command(self):
        code, text = mg.decide(bash(self.receipt_command()), FakeGh(SCENARIOS["green"]), self.state)
        self.assertEqual(code, 0, text)

    def test_cli_receipt_needs_approval_and_writes_private_file(self):
        out, err = io.StringIO(), io.StringIO()
        argv = ["receipt", "--state-dir", str(self.state), "--repo", "o/r", "--pr", "5", "--head", HEAD,
                "--suite-log", str(self.log()), "--suite-exit", "0", "--suite-summary", "1045 tests OK",
                "--review-report", str(self.report())]
        self.assertEqual(mg.main(argv, stdout=out, stderr=err), 3)
        self.assertFalse(self.receipt_path().exists())
        self.assertEqual(mg.main(argv + ["--approved-by", "main:agent-9"], stdout=out, stderr=err), 0, err.getvalue())
        self.assertEqual(self.receipt_path().stat().st_mode & 0o777, 0o600)
        code, text = self.merge("zero_unprotected")
        self.assertEqual(code, 0, text)
        self.assertEqual(mg.main(argv + ["--approved-by", "agent-9"], stdout=out, stderr=err), 3)

    def test_receipts_directory_must_be_a_private_real_directory(self):
        self.write()
        folder = self.state / mg.RECEIPTS_DIR
        os.chmod(str(folder), 0o755)
        self.assertBlocked(needle="directory")
        os.chmod(str(folder), 0o700)
        code, text = self.merge("zero_unprotected")
        self.assertEqual(code, 0, text)
        moved = self.state / "elsewhere"
        os.replace(str(folder), str(moved))
        os.symlink(str(moved), str(folder))
        self.assertBlocked(needle="directory")
        with self.assertRaises(ValueError):
            self.write(head=OTHER)

    def test_guard_does_not_block_ordinary_subagent_commands_about_receipts(self):
        sub = dict(agent_id="agent-sub-1", agent_type="task-owner")
        for command in ("python3 -m unittest tests.test_merge_gate.Receipts", "grep -n receipt harness/hooks/merge_gate.py"):
            with self.subTest(command):
                code, text = mg.decide(bash(command, **sub), FakeGh(SCENARIOS["green"]), self.state)
                self.assertEqual(code, 0, text)

    def test_receipt_policy_documented(self):
        text = (ROOT / "docs" / "operations.md").read_text().lower()
        for needle in ("receipt", "merge-gate-receipts", "reviewed head", "sha256"):
            self.assertIn(needle, text)


if __name__ == "__main__":
    unittest.main()
