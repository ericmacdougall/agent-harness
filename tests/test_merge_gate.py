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
        self.content_refs = []

    def workflow_files(self):
        sc = self.sc
        if "workflow_files" in sc:
            files = sc["workflow_files"]
        else:  # legacy shape: N active workflows triggered by pull_request
            files = [{"name": "ci%d" % i, "state": "active", "content": "on:\n  pull_request:\n  push:\n"}
                     for i in range(sc.get("workflows", 1))]
        return [dict(f, **{".path": ".github/workflows/%s.yml" % f.get("file", f["name"].replace(" ", "-"))}) for f in files]

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
                hit = self._fail("workflows", args, timeout)
                if hit:
                    return hit
                files = self.workflow_files()
                return 0, json.dumps({"total_count": sc.get("workflow_total", len([f for f in files if not f.get("head_only")])), "workflows": [
                    {"name": f["name"], "path": f[".path"], "state": f["state"]} for f in files if not f.get("head_only")]}), ""
            if "/contents/" in path:
                import base64
                hit = self._fail("contents", args, timeout)
                if hit:
                    return hit
                want = path.split("/contents/", 1)[1].split("?", 1)[0]
                ref = path.split("ref=", 1)[-1]
                self.content_refs.append(ref)
                if want == ".github/workflows":  # directory listing at a ref
                    if sc.get("dir_error"):
                        return 1, "", "HTTP 500"
                    files = [f for f in self.workflow_files() if ref == HEAD or not f.get("head_only")]
                    if not files:
                        return 1, '{"message":"Not Found"}', "gh: Not Found (HTTP 404)"
                    return 0, json.dumps([{"name": f[".path"].split("/")[-1], "path": f[".path"], "type": "file"} for f in files]), ""
                for f in self.workflow_files():
                    if f[".path"] == want and (ref == HEAD or not f.get("head_only")):
                        body = f["content"] if ref == HEAD else f.get("base_content", f["content"])
                        return 0, json.dumps({"content": base64.b64encode(body.encode()).decode()}), ""
                return 1, "", "gh: Not Found (HTTP 404)"
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


class ActiveWorkflows(Base):
    """GoodQA #14669: with GitHub CI switched off (no ACTIVE workflow that can run on a PR head) zero checks pass."""

    CMD = "gh pr merge 5 --match-head-commit {HEAD}"
    RELEASE = "name: Release\non:\n  push:\n    tags: [\"v*\"]\npermissions:\n  contents: read\n"

    def scenario(self, files, **extra):
        return dict({"checks": [], "protection": "none", "workflow_files": files}, **extra)

    def merge(self, sc, command=None):
        gh = FakeGh(sc)
        code, text = mg.decide(bash(expand(command or self.CMD)), gh, self.state)
        return code, text, gh

    def test_real_agent_harness_shape_is_allowed(self):
        files = [{"name": "CI", "state": "disabled_manually", "content": "on: [push, pull_request]\n"},
                 {"name": "Console", "state": "disabled_manually", "content": "on:\n  pull_request:\n"},
                 {"name": "Release harness binary", "file": "release", "state": "active", "content": self.RELEASE}]
        code, text, gh = self.merge(self.scenario(files))
        self.assertEqual(code, 0, text)
        self.assertIn(HEAD, gh.content_refs)  # files are read at the verified head (and the base)

    def test_all_disabled_and_no_workflows_allowed(self):
        for state in ("disabled_manually", "disabled_inactivity", "disabled_fork"):
            with self.subTest(state):
                code, text, _ = self.merge(self.scenario([{"name": "CI", "state": state, "content": "on: pull_request\n"}]))
                self.assertEqual(code, 0, text)
        self.assertEqual(self.merge(self.scenario([]))[0], 0)

    def test_active_workflow_that_can_run_on_a_pr_head_blocks(self):
        triggers = {
            "pull_request": "on:\n  pull_request:\n", "inline": "on: [push, pull_request]\n", "scalar": "on: push\n",
            "push-branches": "on:\n  push:\n    branches: [main]\n    tags: [v*]\n", "push-bare": "on:\n  push:\n",
            "pr-target": "on:\n  pull_request_target:\n", "merge-group": "on:\n  merge_group:\n",
            "workflow-run": "on:\n  workflow_run:\n    workflows: [x]\n", "list-form": "on:\n  - push\n",
            "flow-map": "on: {push: {tags: ['v*']}}\n", "no-on": "name: x\njobs: {}\n", "empty": "",
            "quoted-on": "\"on\":\n  pull_request:\n",
            "col0-comment": "on:\n  workflow_dispatch:\n# also on PRs\n  pull_request:\n",
            "branches-ignore": "on:\n  push:\n    tags: [\"v*\"]\n    branches-ignore: [gh-pages]\n",
            "paths-with-tags": "on:\n  push:\n    tags: [v*]\n    paths: [src/**]\n",
            "quoted-trigger": "on:\n  workflow_dispatch:\n  \"pull_request\":\n",
            "quoted-subkey": "on:\n  push:\n    tags: [v*]\n    \"branches\": [main]\n",
            "explicit-key": "on:\n  workflow_dispatch:\n  ? pull_request\n",
            "multiline-flow": "on: [workflow_dispatch,\n  pull_request]\n",
            "two-on": "on: workflow_dispatch\non: pull_request\n",
            "anchor": "on: &x\n  pull_request:\n", "alias": "on: *x\n", "multi-doc": "on: workflow_dispatch\n---\non: pull_request\n",
            "decoy-flow": "{ env: {\non: workflow_dispatch\n}, on: [pull_request], jobs: {} }\n",
            "explicit-on": "? on\n: [pull_request]\n", "empty-tags": "on:\n  push:\n    tags:\n",
            "empty-tags-list": "on:\n  push:\n    tags: []\n",
            "tab": "on:\n\tpull_request:\n", "push-list": "on:\n  push:\n    - tags\n",
            "dedent-garbage": "on:\n    workflow_dispatch:\n  pull_request:\n",
        }
        for name, content in triggers.items():
            with self.subTest(name):
                code, text, _ = self.merge(self.scenario([{"name": "CI", "state": "active", "content": content}]))
                self.assertEqual(code, 2, name + ": " + text)
                self.assertIn("can run (at the PR", text)

    def test_inert_triggers_alone_are_allowed(self):
        for name, content in {"dispatch": "on: workflow_dispatch\n", "schedule": "on:\n  schedule:\n    - cron: '0 0 * * *'\n",
                              "release": "on:\n  release:\n    types: [published]\n", "tags-only": self.RELEASE,
                              "comments": "# header\non:\n  # note\n  push:  # tags only\n    tags: [\"v*\"]  # releases\n  workflow_dispatch:\n",
                              "inline-list": "on: [workflow_dispatch, schedule]\n",
                              "tags-block-list": "on:\n  push:\n    tags:\n      - 'v*'\n"}.items():
            with self.subTest(name):
                code, text, _ = self.merge(self.scenario([{"name": "W", "state": "active", "content": content}]))
                self.assertEqual(code, 0, text)

    def test_one_capable_workflow_among_inert_ones_blocks(self):
        files = [{"name": "Release", "file": "release", "state": "active", "content": self.RELEASE},
                 {"name": "CI", "state": "active", "content": "on:\n  pull_request:\n"}]
        self.assertEqual(self.merge(self.scenario(files))[0], 2)

    def test_unreadable_listing_or_file_fails_closed(self):
        active = [{"name": "Release", "file": "release", "state": "active", "content": self.RELEASE}]
        for label, sc in {
                "list-timeout": self.scenario(active, timeout="workflows"), "list-bad-json": self.scenario(active, bad_json="workflows"),
                "file-timeout": self.scenario(active, timeout="contents"), "file-bad-json": self.scenario(active, bad_json="contents"),
                "truncated": self.scenario(active, workflow_total=5),
                "no-state": self.scenario([{"name": "x", "state": None, "content": ""}])}.items():
            with self.subTest(label):
                code, text, _ = self.merge(sc)
                self.assertEqual(code, 2, text)

    def test_head_binding_and_short_sha_still_required(self):
        sc = self.scenario([])
        for command in ("gh pr merge 5", "gh pr merge 5 --match-head-commit aaaaaaa"):
            with self.subTest(command):
                self.assertEqual(self.merge(sc, command)[0], 2)

    def test_red_or_pending_checks_still_block_without_active_workflows(self):
        for name in ("red_netwatch", "status_pending"):
            with self.subTest(name):
                sc = dict(SCENARIOS[name], workflow_files=[])
                self.assertEqual(self.merge(sc)[0], 2)

    def test_required_check_that_has_not_reported_still_blocks(self):
        self.assertEqual(self.merge(dict(SCENARIOS["zero_required"], workflow_files=[]))[0], 2)

    def test_pr_cannot_switch_off_its_own_ci_by_editing_the_workflow(self):
        pr_ci = {"name": "CI", "state": "active", "content": "on: workflow_dispatch\n", "base_content": "on:\n  pull_request:\n"}
        code, text, gh = self.merge(self.scenario([pr_ci]))
        self.assertEqual(code, 2, text)
        self.assertIn("PR base", text)
        self.assertEqual(sorted(set(gh.content_refs)), sorted({"main", HEAD}) if "main" in gh.content_refs else sorted({HEAD}))
        pr_target = {"name": "T", "state": "active", "content": "on: workflow_dispatch\n", "base_content": "on:\n  pull_request_target:\n"}
        self.assertEqual(self.merge(self.scenario([pr_target]))[0], 2)
        both_inert = {"name": "R", "state": "active", "content": self.RELEASE, "base_content": self.RELEASE}
        self.assertEqual(self.merge(self.scenario([both_inert]))[0], 0)

    def test_workflow_added_by_the_pr_is_classified(self):
        added = {"name": "New", "file": "ci2", "state": "active", "head_only": True, "content": "on:\n  pull_request:\n"}
        inert = {"name": "Release", "file": "release", "state": "active", "content": self.RELEASE}
        code, text, _ = self.merge(self.scenario([inert, added]))
        self.assertEqual(code, 2, text)
        self.assertIn("ci2.yml", text)
        added_inert = dict(added, content="on: workflow_dispatch\n")
        self.assertEqual(self.merge(self.scenario([inert, added_inert]))[0], 0)

    def test_directory_listing_error_fails_closed(self):
        self.assertEqual(self.merge(self.scenario([], dir_error=True))[0], 2)

    def test_unknown_workflow_state_fails_closed(self):
        for state in ("Active", "future_state", 7):
            with self.subTest(state):
                self.assertEqual(self.merge(self.scenario([{"name": "x", "state": state, "content": ""}]))[0], 2)
        self.assertEqual(self.merge(self.scenario([{"name": "x", "state": "deleted", "content": "on: pull_request\n"}]))[0], 0)

    def test_operations_doc_states_the_rule(self):
        text = (ROOT / "docs" / "operations.md").read_text().lower()
        self.assertIn("no active workflow", text)
        self.assertNotIn("has no workflows at all", text)


if __name__ == "__main__":
    unittest.main()
