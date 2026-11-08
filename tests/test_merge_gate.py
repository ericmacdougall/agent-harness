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

    @staticmethod
    def served(f, ref):
        if f.get("gone"):
            return False
        if f.get("head_only"):
            return ref == HEAD
        if f.get("base_only"):
            return ref != HEAD
        return True

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
                    if sc.get("dir_error_nocommit"):
                        return 1, "", "gh: No commit found for the ref aaaa (HTTP 404)"
                    if sc.get("dir_error_404digits"):
                        return 1, "", "gh: API rate limit exceeded for user ID 1404 (HTTP 403)"
                    files = [f for f in self.workflow_files() if self.served(f, ref)]
                    if not files:
                        return 1, '{"message":"Not Found"}', "gh: Not Found (HTTP 404)"
                    return 0, json.dumps([{"name": f[".path"].split("/")[-1], "path": f[".path"], "type": "file"} for f in files]), ""
                if sc.get("file_error_nocommit"):
                    return 1, "", "gh: No commit found for the ref aaaa (HTTP 404)"
                if sc.get("file_error_404digits"):
                    return 1, "", "gh: Bad Gateway 5041404 (HTTP 502)"
                for f in self.workflow_files():
                    if f[".path"] == want and self.served(f, ref):
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
    """GoodQA #14669, amended by goodqa#15282: with GitHub CI switched off (no ACTIVE workflow that can run on a PR
    head) zero checks are not a failure, but nothing was checked either, so the merge needs an exact-head waiver (or
    the one a bound PR review authorization writes) and is refused without one."""

    CMD = "gh pr merge 5 --match-head-commit {HEAD}"
    RELEASE = "name: Release\non:\n  push:\n    tags: [\"v*\"]\npermissions:\n  contents: read\n"

    def scenario(self, files, **extra):
        return dict({"checks": [], "protection": "none", "workflow_files": files}, **extra)

    def merge(self, sc, command=None, waived=False):
        if waived:
            mg.add_waiver(self.state, "o/r", 5, HEAD, "GoodQA #15282", "reviewed by main; CI is off here",
                          approved_by="main:agent-1")
        gh = FakeGh(sc)
        code, text = mg.decide(bash(expand(command or self.CMD)), gh, self.state)
        return code, text, gh

    def test_ci_off_merge_without_a_waiver_is_refused(self):
        # goodqa#15282: PR 137 merged in ericmacdougall/agent-harness with no waiver because CI is off
        code, text, _ = self.merge(self.scenario([]))
        self.assertEqual(code, 2, text)
        self.assertIn("GitHub CI is switched off", text)
        self.assertIn("waive --repo o/r --pr 5 --head " + HEAD, text)

    def test_ci_off_waiver_is_exact_head_and_single_use(self):
        mg.add_waiver(self.state, "o/r", 5, "b" * 40, "GoodQA #15282", "a waiver for another head",
                      approved_by="main:agent-1")
        self.assertEqual(self.merge(self.scenario([]))[0], 2)  # NEG-1: another head does not count
        self.assertEqual(self.merge(self.scenario([]), waived=True)[0], 0)
        self.assertEqual(self.merge(self.scenario([]))[0], 2)  # consumed

    def test_ci_off_outside_reports_are_not_ci(self):
        # red-team H3: an outside commit status, an app check or a lone skipped run is not CI. With no workflow that
        # can run, the merge still needs exact-head evidence; anyone with push access can post a status.
        reports = {"status-success": [{"t": "status", "context": "ok", "state": "SUCCESS"}],
                   "app-run-success": [{"t": "run", "name": "ext", "status": "COMPLETED", "conclusion": "SUCCESS",
                                        "app_id": 999}],
                   "skipped-run": [{"t": "run", "name": "ext", "status": "COMPLETED", "conclusion": "SKIPPED"}]}
        for label, checks in reports.items():
            for command in (self.CMD, "gh pr merge 5 --auto --match-head-commit {HEAD}",
                            "gh pr merge 5 --admin --squash --match-head-commit {HEAD}"):
                with self.subTest(label, command=command):
                    code, text, _ = self.merge(self.scenario([], checks=checks), command=command)
                    self.assertEqual(code, 2, text)
                    self.assertIn("GitHub CI is switched off", text)
            with self.subTest(label, evidence=True):
                self.assertEqual(self.merge(self.scenario([], checks=checks), waived=True)[0], 0)

    def test_ci_on_needs_one_success_when_nothing_is_required(self):
        ci = [{"name": "CI", "state": "active", "content": "on:\n  pull_request:\n"}]
        skipped = [{"t": "run", "name": "test", "status": "COMPLETED", "conclusion": "SKIPPED"}]
        code, text, _ = self.merge(self.scenario(ci, checks=skipped))
        self.assertEqual(code, 2, text)  # red-team H3: only skipped runs is not a pass
        green = [{"t": "run", "name": "test", "status": "COMPLETED", "conclusion": "SUCCESS"}]
        code, text, _ = self.merge(self.scenario(ci, checks=green))
        self.assertEqual(code, 0, text)  # normal CI: no evidence needed
        code, text, _ = self.merge(self.scenario(ci, checks=green, timeout="workflows"))
        self.assertEqual(code, 2, text)  # the workflow list must be readable (fail closed)

    def test_check_command_never_spends_the_evidence(self):
        # red-team M1: `merge_gate.py check` used to consume the single-use evidence and print green
        import io
        mg.add_waiver(self.state, "o/r", 5, HEAD, "GoodQA #15282", "reviewed by main; CI is off here",
                      approved_by="main:agent-1")
        out = io.StringIO()
        rc = mg.main(["check", "--state-dir", str(self.state), "--repo", "o/r", "--pr", "5"],
                     runner=FakeGh(self.scenario([])), stdout=out, stderr=io.StringIO())
        self.assertEqual(rc, 2, out.getvalue())
        self.assertNotIn("all checks green", out.getvalue())
        self.assertEqual(self.merge(self.scenario([]))[0], 0)  # still available for the real merge
        self.assertEqual(self.merge(self.scenario([]))[0], 2)  # then spent

    def test_a_head_with_a_trailing_newline_is_rejected(self):
        # red-team L1: the head check is a full match
        with self.assertRaises(Exception):
            mg.add_waiver(self.state, "o/r", 5, HEAD + "\n", "GoodQA #15282", "trailing newline",
                          approved_by="main:agent-1")

    def test_real_agent_harness_shape_is_allowed(self):
        files = [{"name": "CI", "state": "disabled_manually", "content": "on: [push, pull_request]\n"},
                 {"name": "Console", "state": "disabled_manually", "content": "on:\n  pull_request:\n"},
                 {"name": "Release harness binary", "file": "release", "state": "active", "content": self.RELEASE}]
        code, text, gh = self.merge(self.scenario(files))
        self.assertEqual(code, 2, text)  # goodqa#15282: no waiver, no merge
        code, text, gh = self.merge(self.scenario(files), waived=True)
        self.assertEqual(code, 0, text)
        self.assertIn(HEAD, gh.content_refs)  # files are read at the verified head (and the base)

    def test_all_disabled_and_no_workflows_allowed(self):
        for state in ("disabled_manually", "disabled_inactivity", "disabled_fork"):
            with self.subTest(state):
                code, text, _ = self.merge(self.scenario([{"name": "CI", "state": state, "content": "on: pull_request\n"}]),
                                           waived=True)
                self.assertEqual(code, 0, text)
        self.assertEqual(self.merge(self.scenario([]), waived=True)[0], 0)

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
            "indented-root": "  name: \"x\non: workflow_dispatch\n  y\"\n  on:\n    pull_request:\n  jobs: {}\n",
            "brace-variant": "  name: {a: \"x\non: workflow_dispatch\n  y\"}\n  on:\n    pull_request:\n",
            "escaped-key": "on:\n  workflow_dispatch:\n  \"pull_\\x72equest\":\n",
            "multiline-scalar": "name: >\n  text\non: workflow_dispatch\n",
            "tags-spaced-list": "on:\n  push:\n    tags: [ ]\n", "tags-spaced-map": "on:\n  push:\n    tags: { }\n",
            "tags-NULL": "on:\n  push:\n    tags: NULL\n", "tags-Null": "on:\n  push:\n    tags: Null\n",
            "tags-null-tag": "on:\n  push:\n    tags: !!null ''\n", "tags-empty-str": "on:\n  push:\n    tags: ''\n",
            "tags-list-empty-str": "on:\n  push:\n    tags: [\"\"]\n", "tags-block-null": "on:\n  push:\n    tags:\n      null\n",
            "tags-block-empty-list": "on:\n  push:\n    tags:\n      []\n", "tags-open-bracket": "on:\n  push:\n    tags: [\n      ]\n",
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
                code, text, _ = self.merge(self.scenario([{"name": "W", "state": "active", "content": content}]),
                                           waived=True)
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
        self.assertEqual(self.merge(self.scenario([both_inert]), waived=True)[0], 0)

    def test_workflow_added_by_the_pr_is_classified(self):
        added = {"name": "New", "file": "ci2", "state": "active", "head_only": True, "content": "on:\n  pull_request:\n"}
        inert = {"name": "Release", "file": "release", "state": "active", "content": self.RELEASE}
        code, text, _ = self.merge(self.scenario([inert, added]))
        self.assertEqual(code, 2, text)
        self.assertIn("ci2.yml", text)
        added_inert = dict(added, content="on: workflow_dispatch\n")
        self.assertEqual(self.merge(self.scenario([inert, added_inert]), waived=True)[0], 0)

    def test_audit_marks_allows_that_rest_on_no_ci(self):
        self.assertEqual(self.merge(self.scenario([]), waived=True)[0], 0)
        last = json.loads((self.state / mg.AUDIT_FILE).read_text().splitlines()[-1])
        self.assertTrue(last["no_ci"])
        self.assertTrue(last.get("waiver"))
        self.assertEqual(self.merge(dict(SCENARIOS["green"], workflow_files=[]))[0], 0)
        self.assertFalse(json.loads((self.state / mg.AUDIT_FILE).read_text().splitlines()[-1])["no_ci"])

    def test_directory_listing_error_fails_closed(self):
        self.assertEqual(self.merge(self.scenario([], dir_error=True))[0], 2)

    def test_unknown_workflow_state_fails_closed(self):
        for state in ("Active", "future_state", 7, None):
            with self.subTest(state):
                self.assertEqual(self.merge(self.scenario([{"name": "x", "state": state, "content": ""}]))[0], 2)
        # `deleted` only records that the file was gone: if it exists at either ref it is classified
        restored = {"name": "x", "state": "deleted", "content": "on: pull_request\n"}
        self.assertEqual(self.merge(self.scenario([restored]))[0], 2)
        self.assertEqual(self.merge(self.scenario([dict(restored, gone=True)]), waived=True)[0], 0)

    def test_error_text_containing_404_is_not_a_missing_file(self):
        inert = [{"name": "Release", "file": "release", "state": "active", "content": self.RELEASE}]
        self.assertEqual(self.merge(self.scenario(inert, dir_error_404digits=True))[0], 2)
        self.assertEqual(self.merge(self.scenario(inert, file_error_404digits=True))[0], 2)

    def test_unresolvable_ref_is_not_a_missing_file(self):
        inert = [{"name": "Release", "file": "release", "state": "active", "content": self.RELEASE}]
        self.assertEqual(self.merge(self.scenario(inert, file_error_nocommit=True))[0], 2)
        self.assertEqual(self.merge(self.scenario(inert, dir_error_nocommit=True))[0], 2)

    def test_workflow_only_on_the_base_branch_is_classified(self):
        only_base = {"name": "B", "file": "b", "state": "active", "base_only": True, "content": "on: pull_request\n"}
        self.assertEqual(self.merge(self.scenario([only_base]))[0], 2)

    def test_operations_doc_states_the_rule(self):
        text = (ROOT / "docs" / "operations.md").read_text().lower()
        self.assertIn("no active workflow", text)
        self.assertNotIn("has no workflows at all", text)


if __name__ == "__main__":
    unittest.main()


class FalsePositives15122(Base):
    """goodqa#15122: false positives seen during the prod move, each with the block that must stay."""

    SUB = {"agent_id": "sub-1", "agent_type": "task-owner"}

    def kinds(self, command):
        return sorted({m.kind for m in mg.find_merges(expand(command), cwd="/work")})

    def test_ac4_push_of_a_feature_branch_to_a_remote_named_gh_is_not_a_merge(self):
        cases = ["git push gh {HEAD}:refs/heads/fix/guard-false-positives-15122",
                 'git push gh "${H}:refs/heads/feat/x"',
                 "git -C /r push -u gh HEAD:refs/heads/feat",
                 "git push --force-with-lease gh feat",
                 "H=abc; git push gh $H:refs/heads/feat",
                 "git fetch gh main",
                 "git remote add gh https://github.com/o/r.git",
                 "git log gh/main --oneline"]
        for command in cases:
            with self.subTest(command):
                self.assertEqual(self.kinds(command), [], command)
                code, text, gh = self.decide(command, scenario="red_netwatch")
                self.assertEqual(code, 0, text)
                self.assertEqual(gh.calls, [])

    def test_neg4_push_to_main_or_master_and_gh_merges_stay_blocked(self):
        for command in ("git push origin main", "git push gh {HEAD}:refs/heads/main", "git push gh +feat:master",
                        "git push origin --delete main", "git push origin :main", "git push --mirror gh",
                        "git push gh --all", 'git push origin "$B"', "git -C /r push origin HEAD:refs/heads/main",
                        "B=main; git push gh feat:$B"):
            with self.subTest(command):
                self.assertEqual(self.kinds(command), ["unverifiable"], command)
                self.assertEqual(self.decide(command)[0], 2, command)
        for command in ("git push gh feat && gh pr merge 5 --match-head-commit {HEAD}",
                        "git submodule foreach gh pr merge 5", "gh pr merge 5"):
            with self.subTest(command):
                self.assertTrue({"pr_merge", "unverifiable"} & set(self.kinds(command)), command)
                self.assertEqual(self.decide(command, scenario="red_netwatch")[0], 2, command)

    def test_ac3_read_only_gh_built_from_literal_variables_is_not_a_merge(self):
        for command in ("SUB=view; gh pr $SUB 5", "GH=gh; $GH pr view 5 --json headRefOid",
                        "G=gh; $G api repos/o/r/pulls/5", "S=list; gh pr ${S}"):
            with self.subTest(command):
                self.assertEqual(self.kinds(command), [], command)
                self.assertEqual(self.decide(command, scenario="red_netwatch")[0], 0, command)

    def test_neg3_gh_merge_built_from_variables_stays_blocked(self):
        for command in ("SUB=merge; gh pr $SUB 5", "GH=gh; $GH pr merge 5", "SUB=$(echo merge); gh pr $SUB 5",
                        "SUB=view; SUB=merge; gh pr $SUB 5", "if true; then SUB=view; fi; gh pr $SUB 5",
                        "SUB=view gh pr $SUB 5", "(SUB=view); gh pr $SUB 5", "false && SUB=view; gh pr $SUB 5",
                        "SUB=view | true; gh pr $SUB 5", "for S in merge; do gh pr $S 5; done",
                        "SUB=view; eval SUB=merge; gh pr $SUB 5", "SUB=view; unset SUB; gh pr $SUB 5",
                        "SUB=view; source f; gh pr $SUB 5", "f() { SUB=view; }; f; gh pr $SUB 5",
                        "GH=echo; $GH 'gh pr merge 5' | sh", "gh pr $SUB 5", "gh pr view 5; SUB=view; X=$SUB"):
            with self.subTest(command):
                kinds = self.kinds(command)
                if command.endswith("X=$SUB"):
                    self.assertEqual(kinds, [], command)  # control: a read, no gh word from a variable
                    continue
                self.assertIn("unverifiable", kinds, command)
                self.assertEqual(self.decide(command)[0], 2, command)

    def test_redteam_f1_other_bash_reassignments_make_a_variable_unknown(self):
        # fixture red-team finding 1: these change X after X=view; the resolver must not read X as view.
        for command in ("X=view; declare -n R=X; R=merge; gh pr $X 5", "X=view; printf -vX merge; gh pr $X 5",
                        "X=view; trap ': ; X=merge' DEBUG; gh pr $X 5", "X=view; read -aX <<< merge; gh pr $X 5",
                        "X=view; local -n R=X; R=merge; gh pr $X 5", "X=view; mapfile -tX < f; gh pr $X 5"):
            with self.subTest(command):
                self.assertIn("unverifiable", self.kinds(command), command)
                self.assertEqual(self.decide(command)[0], 2, command)

    def test_redteam_f2_more_pushes_to_main_stay_blocked(self):
        # fixture red-team finding 2: short refs, git aliases, push config and xargs-supplied refspecs.
        for command in ("git push origin HEAD:heads/main", "git push origin feat:refs/heads/master",
                        "git -c alias.p='push origin main' p", "echo main | xargs git push origin",
                        "git -c remote.origin.push=HEAD:main push origin", "git -c push.default=current push origin"):
            with self.subTest(command):
                self.assertEqual(self.kinds(command), ["unverifiable"], command)
                self.assertEqual(self.decide(command)[0], 2, command)
        for command in ("git push origin HEAD:refs/heads/feat/main", "git -c core.hooksPath=/dev/null push gh feat"):
            with self.subTest(command):
                self.assertEqual(self.kinds(command), [], command)

    def test_redteam_f4_exception_record_through_any_other_program_stays_blocked(self):
        # fixture red-team finding 4: only known free-text forms are exempt; every other program keeps the text rule.
        for command in ("awk 'BEGIN{system(\"python3 /h/merge_gate.py waive\")}'",
                        "gh issue comment 1 --body \"$(python3 /h/merge_gate.py waive)\"",
                        "git -c alias.w='!python3 /h/merge_gate.py waive' w",
                        "find . -name x -exec python3 /h/merge_gate.py waive \\;",
                        "make -f /h/Makefile merge_gate_waive",
                        "sed -n '1e python3 /h/merge_gate.py waive' f",
                        "python3 /h/wal_note.py --note 'merge_gate waive'",
                        "python3 -I ~/.claude/hooks/wal_note.py; python3 /h/merge_gate.py waive",
                        "> f python3 /h/merge_gate.py waive",
                        "echo merge_gate waive > f; perl f"):
            with self.subTest(command):
                code, text = mg.decide(bash(command, **self.SUB), FakeGh(SCENARIOS["green"]), self.state)
                self.assertEqual(code, 2, text)
        for command in ("git -c core.hooksPath=/dev/null commit -q -F msg.txt -m 'merge_gate waive check'",
                        "grep -n 'waive' harness/hooks/merge_gate.py | head -5",
                        "N='merge_gate waive note'; python3 ~/.claude/hooks/wal_note.py --note \"$N\"",
                        "python3 ~/.claude/hooks/ah.py ticket comment 'goodqa#1' --body 'merge_gate waive fixed' 2>&1",
                        "cd /r && git log --grep 'merge_gate waive' --oneline"):
            with self.subTest(command):
                code, text = mg.decide(bash(command, **self.SUB), FakeGh(SCENARIOS["green"]), self.state)
                self.assertEqual(code, 0, text)

    def test_redteam_f4_allow_list_forms_that_can_run_code_stay_blocked(self):
        # re-review leads on 3823c5e: options, environment and file writes that turn a free-text form into code.
        hook = "~/.claude/hooks/wal_note.py --note 'merge_gate waive'"
        for command in ("rg --pre /h/x merge_gate_waive f", "git log --output=/h/x --grep 'merge_gate waive'",
                        "git grep -O/h/x 'merge_gate waive'", "git push --receive-pack=/h/x origin feat # merge_gate waive",
                        "gh run view 1 # merge_gate waive", "gh repo clone o/r # merge_gate waive",
                        "python3 -m pytest -p evil -k 'merge_gate waive'",
                        "python3 -m unittest x # merge_gate waive",
                        "HOME=/x python3 " + hook, "PATH=/x python3 " + hook, "PYTHONPATH=/x python3 " + hook,
                        "printf -v HOME /x; python3 " + hook, "python3 $HOME/.claude/hooks/wal_note.py --note 'merge_gate waive'",
                        "echo merge_gate waive >(python3 /h/x)",
                        "echo merge_gate waive > .git/hooks/pre-commit; git commit -m x",
                        "echo x | tee " + hook.split(" ")[0] + "; python3 " + hook,
                        "cd ~/.claude/hooks && cat > wal_note.py <<'EOF'\nx\nEOF\npython3 " + hook):
            with self.subTest(command):
                code, text = mg.decide(bash(command, **self.SUB), FakeGh(SCENARIOS["green"]), self.state)
                self.assertEqual(code, 2, text)
        for command in ("cat > notes.md <<'EOF'\nmerge_gate waive notes\nEOF",
                        "python3 ~/.claude/hooks/ah.py ticket comment 'goodqa#1' --body 'merge_gate waive' 2>&1 | tail -3",
                        "git log -p --grep 'merge_gate waive' | head"):
            with self.subTest(command):
                code, text = mg.decide(bash(command, **self.SUB), FakeGh(SCENARIOS["green"]), self.state)
                self.assertEqual(code, 0, text)

    def test_review_gfp5_git_options_outside_the_per_subcommand_list_stay_blocked(self):
        # Opus-high review of 6305aee F1/F2/F3: keyword-prefixed git, abbreviated or joined long/short options, -C,
        # commits with hooks on, gh --web and checkout.
        for command in ("echo merge_gate waive > .git/hooks/pre-commit; if git commit -m x; then true; fi",
                        "echo merge_gate waive | tee f; while git status; do break; done",
                        "git grep --open-files /p 'merge_gate waive'", "git grep -nO/p 'merge_gate waive'",
                        "git log --ext --grep 'merge_gate waive'", "git log --outp=/f --grep 'merge_gate waive'",
                        "git -C /r log --grep 'merge_gate waive'",
                        "git commit -m 'merge_gate waive note'", "git commit --no-verify -m 'merge_gate waive note'",
                        "git tag -s v1 -m 'merge_gate waive'", "git add -p # merge_gate waive",
                        "gh pr view 5 --web # merge_gate waive", "gh pr checkout 5 # merge_gate waive",
                        "gh issue view 5 -w # merge_gate waive"):
            with self.subTest(command):
                code, text = mg.decide(bash(command, **self.SUB), FakeGh(SCENARIOS["green"]), self.state)
                self.assertEqual(code, 2, text)
        for command in ("git grep -n -e 'merge_gate waive' -- harness", "git grep -nix 'merge_gate waive'",
                        "git log -n5 --oneline --grep 'merge_gate waive'",
                        "git -c core.hooksPath=/dev/null commit -q -F msg.txt  # merge_gate waive",
                        "git diff --stat HEAD~1 -- 'merge_gate waive'", "gh pr comment 5 --body 'merge_gate waive'"):
            with self.subTest(command):
                code, text = mg.decide(bash(command, **self.SUB), FakeGh(SCENARIOS["green"]), self.state)
                self.assertEqual(code, 0, text)

    def test_review_gfp6_run_time_words_and_hooks_stay_blocked(self):
        # Opus-xhigh delta review of 72417e1: N1 a variable, substitution or glob word can become a git/gh option at
        # run time; N2 add/status/branch/tag run hooks; N3 gh joins short flags.
        for command in ("git log $X --grep 'merge_gate waive'", 'git log "$X" --grep \'merge_gate waive\'',
                        "git grep -n 'merge_gate waive' -*", "git grep -n 'merge_gate waive' ?O*",
                        "X='merge_gate waive'; git log --grep \"$X\" $Y",
                        "gh pr view 5 $W # merge_gate waive", "gh pr view 5 -cw # merge_gate waive",
                        "gh pr comment 5 --body x $(echo y) # merge_gate waive",
                        "git add f # merge_gate waive", "git status # merge_gate waive",
                        "git branch feat # merge_gate waive", "git tag v1 # merge_gate waive"):
            with self.subTest(command):
                code, text = mg.decide(bash(command, **self.SUB), FakeGh(SCENARIOS["green"]), self.state)
                self.assertEqual(code, 2, text)
        for command in ("git -c core.hooksPath=/dev/null add f # merge_gate waive",
                        "git -c core.hooksPath=/dev/null status --short # merge_gate waive",
                        "git --no-pager log --grep 'merge_gate waive'", "git -P log --no-textconv --grep 'merge_gate waive'",
                        "git diff --no-ext-diff -- 'merge_gate waive'",
                        "gh pr comment 5 --body \"$(cat <<'EOF'\nmerge_gate waive is main-only\nEOF\n)\""):
            with self.subTest(command):
                code, text = mg.decide(bash(command, **self.SUB), FakeGh(SCENARIOS["green"]), self.state)
                self.assertEqual(code, 0, text)

    def test_main_closure_brace_expansion_next_to_git_stays_blocked(self):
        # main's closure check of 684b5b4: bash expands {a,b} into separate words, so an option can hide in a brace.
        for command in ('git log {--output=/tmp/x,--oneline} --grep "merge_gate.py waive"',
                        "git grep -n {-O/p,-e} 'merge_gate waive'", "gh pr view {5,--web} # merge_gate waive",
                        "git log {--outp..--oneline} --grep 'merge_gate waive'"):
            with self.subTest(command):
                code, text = mg.decide(bash(command, **self.SUB), FakeGh(SCENARIOS["green"]), self.state)
                self.assertEqual(code, 2, text)
        # a tilde expands to a home path, never to an option
        for command in ("git -c core.hooksPath=/dev/null add ~/notes.md # merge_gate waive",
                        "git log --grep 'merge_gate waive' -- ~/r", "git log --format='{x}' --grep 'merge_gate waive'"):
            with self.subTest(command):
                code, text = mg.decide(bash(command, **self.SUB), FakeGh(SCENARIOS["green"]), self.state)
                self.assertEqual(code, 0, text)

    def test_ac2_subagent_free_text_about_the_exception_record_is_allowed(self):
        for command in ("python3 ~/.claude/hooks/wal_note.py --wal /w/a.jsonl --event status "
                        "--note 'fixed the merge_gate.py waive false positive'",
                        "git -c core.hooksPath=/dev/null commit -m 'fix(merge_gate): the subagent waive check is structural'",
                        "gh issue comment 15122 --body 'merge_gate waive block fired on a WAL note'",
                        "cat > notes.md <<'EOF'\nrun merge_gate.py waive only from main\nEOF",
                        "grep -n waive harness/hooks/merge_gate.py",
                        "gh pr create --title t --body \"$(cat <<'EOF'\nmerge_gate.py waive is main-only\nEOF\n)\"",
                        "python3 -m unittest tests.test_merge_gate -v"):
            with self.subTest(command):
                code, text = mg.decide(bash(command, **self.SUB), FakeGh(SCENARIOS["green"]), self.state)
                self.assertEqual(code, 0, text)

    def test_neg1_subagent_real_exception_record_stays_blocked(self):
        for command in ("bash -c 'python3 /h/merge_gate.py waive --repo o/r'",
                        "echo 'import merge_gate; merge_gate.add_waiver(1)' | python3",
                        "python3 - <<'EOF'\nimport merge_gate\nmerge_gate.add_waiver(1)\nEOF",
                        "python3 <<'EOF'\nimport merge_gate\nmerge_gate.add_waiver(1)\nEOF",
                        "eval 'python3 /h/merge_gate.py waive'",
                        "ssh host python3 /h/merge_gate.py waive --repo o/r",
                        "ssh host 'python3 /h/merge_gate.py waive --repo o/r'",
                        "sudo -u eric python3 -c 'import merge_gate; merge_gate.add_waiver(1)'",
                        "cd /h && ./merge_gate.py waive --repo o/r",
                        "python3 -m merge_gate waive --repo o/r",
                        "printf 'import merge_gate\\nmerge_gate.add_waiver(1)\\n' > x.py && python3 x.py",
                        "cat > x.py <<'EOF'\nimport merge_gate\nmerge_gate.add_waiver(1)\nEOF\npython3 x.py",
                        "M=merge_gate.py; W=waive; python3 /h/$M $W",
                        "X=python3; $X /h/merge_gate.py waive",
                        "echo /h/merge_gate.py waive | xargs python3",
                        "C='import merge_gate; merge_gate.add_waiver(1)'; python3 -c \"$C\"",
                        "C='python3 /h/merge_gate.py waive'; bash -c \"$C\"",
                        "env python3 /h/merge_gate.py waive --repo o/r",
                        "X=merge_gate; python3 -m $X waive",
                        "python3 ~/.claude/hooks/merge_gate.py waive --repo o/r --pr 5 --head " + HEAD):
            with self.subTest(command):
                code, text = mg.decide(bash(command, **self.SUB), FakeGh(SCENARIOS["green"]), self.state)
                self.assertEqual(code, 2, text)
