"""merge_gate.py (2026-11-24 redesign): one real check, a PASS review or an approval, and nothing refused for form.

Every case runs the hook as the agent harness does (`merge_gate.py hook`, JSON on stdin) with a fake `gh` first on
PATH, a private HOME, a private usage store and a private state directory. The fake refuses to merge anything.
MERGE_GATE_HOOKS_DIR points the suite at another copy of the hooks (the failing-first run on the old code).
"""

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HOOKS = Path(os.environ.get("MERGE_GATE_HOOKS_DIR") or ROOT / "harness" / "hooks")
GATE = HOOKS / "merge_gate.py"
H1, H2, H3 = "1" * 40, "2" * 40, "3" * 40

FAKE_GH = r'''#!/usr/bin/env python3
import json, os, sys
args = sys.argv[1:]
scenario = json.load(open(os.environ["FAKE_GH_SCENARIO"]))
with open(os.environ["FAKE_GH_SCENARIO"] + ".calls", "a") as log:
    log.write(json.dumps(args) + "\n")
if args[:2] == ["pr", "merge"] or ("-X" in args and "PUT" in args):
    sys.exit("fake gh: the gate must never merge")
if args[:2] == ["pr", "view"] and "pr" in scenario:
    print(json.dumps(scenario["pr"])); sys.exit(0)
if args[:2] == ["pr", "list"]:
    print(json.dumps(scenario.get("prs", []))); sys.exit(0)
if args[:1] == ["api"] and "/compare/" in args[1]:
    base = args[1].split("/compare/")[1].split("...")[0]
    if base in scenario.get("compare", {}):
        print(json.dumps(scenario["compare"][base])); sys.exit(0)
sys.stderr.write("fake gh: no answer for %s\n" % args); sys.exit(1)
'''


def pr(head=H2, commits=(H1, H2), base="main", number=12):
    return {"number": number, "url": "https://github.com/o/r/pull/%d" % number, "headRefOid": head,
            "baseRefName": base, "state": "OPEN", "commits": [{"oid": c} for c in commits]}


class GateCase(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(dir=ROOT / "tests")
        self.addCleanup(temp.cleanup)
        self.tmp = Path(temp.name)
        self.home = self.tmp / "home"
        self.state = self.tmp / "state"
        self.usage = self.tmp / "usage"
        (self.usage / "runs").mkdir(parents=True)
        self.home.mkdir()
        bin_dir = self.tmp / "bin"
        bin_dir.mkdir()
        (bin_dir / "gh").write_text(FAKE_GH.replace("/usr/bin/env python3", sys.executable))
        (bin_dir / "gh").chmod(0o755)
        self.scenario = self.tmp / "scenario.json"
        self.scenario.write_text("{}")
        self.env = {"HOME": str(self.home), "PATH": "%s:/usr/bin:/bin" % bin_dir, "FAKE_GH_SCENARIO": str(self.scenario),
                    "AGENT_HARNESS_USAGE_DIR": str(self.usage), "MERGE_GATE_DEADLINE": "10"}

    def scene(self, **values):
        self.scenario.write_text(json.dumps(values))

    def calls(self):
        path = Path(str(self.scenario) + ".calls")
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def receipt(self, head, repo="o/r", number=12, verdict="ACCEPT", run="r%d" % 0):
        run = run + head[:6] + verdict[:3]
        folder = self.usage / "runs" / run
        folder.mkdir(parents=True)
        review = {"stage": "PR", "verdict": verdict, "findings": [], "head": head, "report_sha256": "f" * 64,
                  "reviewer": "Claude opus high (rung R2)", "reviewer_harness": "claude", "author_harness": "claude"}
        if repo:
            review.update(repo=repo, pr=number)
        final = {"schema": 1, "kind": "final", "run_id": run, "execution": "COMPLETED",
                 "result": "CHECK_OK" if verdict != "BLOCK" else "CHECK_FAILED", "reason": "NONE",
                 "evidence": "EXECUTED", "subject": {"head": head}, "invocation": {"purpose": "peer-review-pr"},
                 "review": review, "usage": {"provider_launches": 1}, "ended_at": "2026-11-24T00:00:00+00:00"}
        body = json.dumps(final, sort_keys=True, separators=(",", ":")).encode()
        (folder / "final.json").write_bytes(body)
        ref = {"run_id": run, "record": "final", "sha256": hashlib.sha256(body).hexdigest()}
        (folder / "settled.json").write_text(json.dumps({"schema": 1, "kind": "review_settlement", "reference": ref,
                                                         "at": "2026-11-24T00:00:00+00:00"}))

    def hook(self, command, **payload):
        payload = dict({"tool_name": "Bash", "tool_input": {"command": command}, "cwd": str(self.tmp),
                        "session_id": "0" * 8 + "-0000-0000-0000-" + "0" * 12}, **payload)
        started = time.monotonic()
        done = subprocess.run([sys.executable, str(GATE), "hook", "--state-dir", str(self.state)],
                              input=json.dumps(payload).encode(), capture_output=True, env=self.env, timeout=60)
        self.elapsed = time.monotonic() - started
        return done.returncode, done.stderr.decode()

    def cli(self, *args):
        done = subprocess.run([sys.executable, str(GATE), *args, "--state-dir", str(self.state)], capture_output=True,
                              env=self.env, timeout=60)
        return done.returncode, done.stdout.decode() + done.stderr.decode()


class TextIsNotACommand(GateCase):
    def test_large_heredoc_with_merge_prose_is_allowed_fast(self):
        prose = "Then we run gh pr merge 12 --squash; and git push origin main later.\n" * 3000  # ~210 KB
        command = "cat > notes.md <<'EOF'\n" + prose + "EOF\ngit add notes.md && git status --short"
        self.assertGreater(len(command), 200_000)
        code, err = self.hook(command)
        self.assertEqual(code, 0, err)
        self.assertLess(self.elapsed, 1.0, "a 200 KB heredoc command must be decided well under a second")
        self.assertEqual(self.calls(), [], "prose must not reach GitHub")

    def test_quoted_mentions_and_help_are_allowed(self):
        for command in ("echo 'gh pr merge 12'", "git commit -m 'gh pr merge 12 fixed'", "gh pr merge --help",
                        "grep -n 'gh pr merge' docs/operations.md", "gh api repos/o/r/pulls/12/merge"):
            with self.subTest(command=command):
                self.assertEqual(self.hook(command)[0], 0)
        self.assertEqual(self.calls(), [])

    def test_unparsable_command_is_allowed_with_one_log_line(self):
        code, err = self.hook("gh pr merge 12 'unbalanced")
        self.assertEqual(code, 0, err)
        log = (self.home / ".agent-harness" / "logs" / "merge-gate.log").read_text()
        self.assertEqual(len(log.splitlines()), 1)
        self.assertIn("could not parse", log)
        self.assertIn("could not parse", err)


class ReviewIsTheCheck(GateCase):
    def test_merge_without_review_is_refused_with_one_message(self):
        self.scene(pr=pr())
        code, err = self.hook("gh pr merge 12 --squash")
        self.assertEqual(code, 2)
        self.assertEqual(err.count("merge-gate: refused"), 1, err)
        self.assertIn("Missing: a passing independent review of o/r#12", err)
        self.assertIn("peer_review.py pr", err)
        self.assertIn("--github-repo o/r --pr 12", err)
        self.assertIn("waive --repo o/r --pr 12", err)
        self.assertFalse(any(call[:2] == ["pr", "merge"] for call in self.calls()))

    def test_receipt_for_the_current_head_allows(self):
        self.scene(pr=pr())
        self.receipt(H2)
        self.assertEqual(self.hook("gh pr merge 12 --squash")[0], 0)

    def test_head_moved_by_a_small_fix_after_pass_is_allowed(self):
        self.scene(pr=pr(), compare={H1: {"status": "ahead", "files": [
            {"filename": "harness/hooks/x.py", "additions": 12, "deletions": 3}]}})
        self.receipt(H1)
        code, err = self.hook("cd %s && gh pr merge 12 --squash --delete-branch" % self.tmp)
        self.assertEqual(code, 0, err)

    def test_head_moved_by_a_large_change_is_refused_naming_the_size(self):
        self.scene(pr=pr(), compare={H1: {"status": "ahead", "files": [
            {"filename": "src/app.py", "additions": 300, "deletions": 100}]}})
        self.receipt(H1)
        code, err = self.hook("gh pr merge 12")
        self.assertEqual(code, 2)
        self.assertIn("400 lines changed since (limit 150)", err)

    def test_head_moved_touching_a_sensitive_path_is_refused(self):
        self.scene(pr=pr(), compare={H1: {"status": "ahead", "files": [
            {"filename": ".github/workflows/ci.yml", "additions": 1, "deletions": 1}]}})
        self.receipt(H1)
        code, err = self.hook("gh pr merge 12")
        self.assertEqual(code, 2)
        self.assertIn(".github/workflows/ci.yml", err)

    def test_blocking_review_does_not_count(self):
        self.scene(pr=pr())
        self.receipt(H2, verdict="BLOCK")
        self.assertEqual(self.hook("gh pr merge 12")[0], 2)

    def test_unbound_receipt_for_a_pr_commit_counts(self):
        self.scene(pr=pr())
        self.receipt(H2, repo=None)
        self.assertEqual(self.hook("gh pr merge https://github.com/o/r/pull/12")[0], 0)

    def test_unprotected_base_needs_nothing(self):
        self.scene(pr=pr(base="feature/x"))
        self.assertEqual(self.hook("gh pr merge 12")[0], 0)

    def test_variable_target_is_resolved_or_named(self):
        self.scene(pr=pr())
        self.receipt(H2)
        self.assertEqual(self.hook("N=12; gh pr merge $N -R o/r")[0], 0)
        code, err = self.hook("gh pr list | xargs -n1 gh pr merge")
        self.assertEqual(code, 2)
        self.assertIn("gh pr merge <number> -R owner/repo", err)

    def test_push_to_a_feature_branch_is_not_a_merge(self):
        self.assertEqual(self.hook("git push -u origin redesign/merge-commit")[0], 0)
        self.assertEqual(self.calls(), [])

    def test_push_to_main_needs_a_pr_or_a_head_waiver_and_a_no_op_push_passes(self):
        repo = self.tmp / "repo"
        env = dict(self.env, GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=str(self.tmp / "gitconfig"))

        def git(*args):
            return subprocess.run(["git", "-C", str(repo), *args], env=env, capture_output=True, text=True,
                                  check=True).stdout.strip()
        subprocess.run(["git", "init", "-q", "-b", "main", str(repo)], env=env, check=True)
        git("config", "user.name", "Fixture")
        git("config", "user.email", "fixture@example.invalid")
        git("commit", "-q", "--allow-empty", "-m", "base")
        git("remote", "add", "origin", "https://github.com/o/r.git")
        git("update-ref", "refs/remotes/origin/main", "HEAD")
        self.env = env
        self.scene(prs=[])
        self.assertEqual(self.hook("git push origin main", cwd=str(repo))[0], 0, "nothing new lands")
        git("commit", "-q", "--allow-empty", "-m", "direct")
        code, err = self.hook("git push origin main", cwd=str(repo))
        self.assertEqual(code, 2)
        self.assertIn("Missing: a pull request", err)
        head = git("rev-parse", "HEAD")
        self.assertEqual(self.cli("waive", "--repo", "o/r", "--head", head, "--reason", "release tag fix")[0], 0)
        self.assertEqual(self.hook("git push origin HEAD:main", cwd=str(repo))[0], 0)


class Waivers(GateCase):
    def test_waiver_with_semicolon_and_odd_approver_is_recorded_first_try(self):
        code, out = self.cli("waive", "--repo", "o/r", "--pr", "12", "--head", H2, "--ticket", "GoodQA #1",
                             "--reason", "hotfix; CI is down, reviewed by hand", "--approved-by", "Eric (in chat)")
        self.assertEqual(code, 0, out)
        rows = [json.loads(line) for line in (self.state / "merge-gate-waivers.jsonl").read_text().splitlines()]
        self.assertEqual(rows[-1]["reason"], "hotfix; CI is down, reviewed by hand")
        self.assertEqual(rows[-1]["approved_by"], "Eric (in chat)")

    def test_pr_waiver_survives_a_moved_head(self):
        code, out = self.cli("waive", "--repo", "https://github.com/O/R", "--pr", "#12", "--reason", "ok")
        self.assertEqual(code, 0, out)
        self.scene(pr=pr(head=H3, commits=(H1, H2, H3)))
        self.assertEqual(self.hook("gh pr merge 12")[0], 0)

    def test_exact_head_waiver_does_not_cover_a_new_head(self):
        self.assertEqual(self.cli("waive", "--repo", "o/r", "--pr", "12", "--head", H1, "--reason", "x")[0], 0)
        self.scene(pr=pr())
        self.assertEqual(self.hook("gh pr merge 12")[0], 2)

    def test_top_rung_may_record_a_waiver_and_a_subagent_may_not(self):
        command = "python3 %s waive --repo o/r --pr 12 --reason 'fine; really'" % GATE
        self.assertEqual(self.hook(command, model="claude-fable-5-2")[0], 0)
        code, err = self.hook(command, agent_id="abcd1234", agent_type="task-owner")
        self.assertEqual(code, 2)
        self.assertIn("may record a merge waiver", err)


if __name__ == "__main__":
    unittest.main()
