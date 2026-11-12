"""`ah worktree-remove` and the verifier it runs (goodqa#15565): real temporary repositories, fake network and ssh.

The removal under test only ever touches temporary directories under a temporary HOME."""
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
HOOKS = ROOT / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
import ah  # noqa: E402
import ah_worktree  # noqa: E402
import command_guard as cg  # noqa: E402

URL = "https://github.com/acme/widgets.git"
GIT_ENV = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
GIT_ENV.update(GIT_CONFIG_GLOBAL="/dev/null", GIT_CONFIG_NOSYSTEM="1", GIT_AUTHOR_NAME="t",
               GIT_AUTHOR_EMAIL="t@example.invalid", GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@example.invalid")


def git(cwd, *args):
    done = subprocess.run(["git", *args], cwd=str(cwd), env=GIT_ENV, capture_output=True, text=True)
    if done.returncode:
        raise AssertionError("git %s: %s" % (" ".join(args), done.stderr))
    return done.stdout.strip()


class Repo(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ah-wt-")
        self.addCleanup(self.temp.cleanup)
        self.home = Path(os.path.realpath(self.temp.name))
        patch = mock.patch.dict(os.environ, {"HOME": str(self.home)})
        patch.start()
        self.addCleanup(patch.stop)
        self.base = self.home / ".agent-harness/work/S/T"
        self.primary, self.linked = self.base / "primary", self.base / "linked"
        self.primary.mkdir(parents=True)
        git(self.primary, "init", "-q", "-b", "main")
        (self.primary / "a.txt").write_text("one\n")
        git(self.primary, "add", "a.txt")
        git(self.primary, "commit", "-q", "-m", "one")
        git(self.primary, "remote", "add", "origin", URL)
        git(self.primary, "worktree", "add", "-q", "-b", "linked", str(self.linked))
        self.head = git(self.linked, "rev-parse", "HEAD")
        git(self.primary, "update-ref", "refs/remotes/origin/main", self.head)
        git(self.primary, "update-ref", "refs/remotes/origin/linked", self.head)
        self.live = {"refs/heads/main": self.head, "refs/heads/linked": self.head}
        patch = mock.patch.object(cg, "REMOTE_LS", lambda url, repo, timeout: dict(self.live))
        patch.start()
        self.addCleanup(patch.stop)
        self.policy = cg.load_policy(path=str(self.home / "missing-policy.json"))


class Verifier(Repo):
    def test_a_clean_published_linked_worktree_is_removed_and_reported(self):
        report = cg.remove_worktree(str(self.linked), policy=self.policy)
        self.assertTrue(report["removed"], report)
        self.assertEqual(report["head"], self.head)
        self.assertFalse(self.linked.exists())
        self.assertNotIn(str(self.linked), git(self.primary, "worktree", "list", "--porcelain"))
        self.assertTrue(self.primary.exists())

    def test_the_removal_is_the_plain_non_forced_git_command_from_the_primary_worktree(self):
        real, seen = subprocess.run, []

        def spy(argv, *args, **kwargs):
            if "worktree" in argv and "remove" in argv:
                seen.append(list(argv))
            return real(argv, *args, **kwargs)
        with mock.patch.object(cg.subprocess, "run", spy):
            self.assertTrue(cg.remove_worktree(str(self.linked), policy=self.policy)["removed"])
        self.assertEqual(len(seen), 1)
        self.assertNotIn("--force", seen[0])
        self.assertNotIn("-f", seen[0])
        self.assertEqual(seen[0][seen[0].index("-C") + 1], str(self.primary))
        self.assertEqual(seen[0][-2:], ["--", str(self.linked)])

    def test_verify_alone_removes_nothing(self):
        report = cg.verify_worktree(str(self.linked), policy=self.policy)
        self.assertTrue(report["removable"], report)
        self.assertEqual(report["repo"], str(self.primary))
        self.assertEqual(report["urls"], {"origin": [URL]})
        self.assertTrue(self.linked.exists())

    def refused(self, path, fragment, **kwargs):
        report = cg.remove_worktree(str(path), policy=self.policy, **kwargs)
        self.assertFalse(report["removable"], report)
        self.assertFalse(report["removed"])
        self.assertIn(fragment, report["reason"])
        return report

    def test_the_primary_worktree_is_never_removable(self):
        self.refused(self.primary, "not a plain file")
        self.assertTrue(self.primary.exists())

    def test_paths_outside_scope_are_refused(self):
        outside = Path(tempfile.mkdtemp(prefix="outside-"))
        self.addCleanup(lambda: __import__("shutil").rmtree(outside, ignore_errors=True))
        self.refused(outside, "outside the home")
        (self.home / ".claude").mkdir()
        self.refused(self.home / ".claude", "protected state")
        (self.home / ".agent-harness/logs").mkdir(parents=True)
        self.refused(self.home / ".agent-harness/logs", "inside work/")
        self.refused(self.home, "outside the home")
        report = cg.verify_worktree("relative/path", policy=self.policy)
        self.assertFalse(report["removable"])

    def test_dirty_untracked_unpublished_symlinked_and_nested_are_refused(self):
        (self.linked / "a.txt").write_text("changed\n")
        self.refused(self.linked, "not clean")
        git(self.linked, "checkout", "-q", "--", "a.txt")
        (self.linked / "new.txt").write_text("x\n")
        self.refused(self.linked, "not clean")
        (self.linked / "new.txt").unlink()
        git(self.linked, "checkout", "-q", "--detach")
        (self.linked / "local.txt").write_text("local\n")
        git(self.linked, "add", "local.txt")
        git(self.linked, "commit", "-q", "-m", "local only")
        self.refused(self.linked, "not present on a live")
        link = self.base / "alias"
        link.symlink_to(self.linked)
        self.refused(link, "symlink")

    def test_the_head_must_still_match_the_expected_head(self):
        self.refused(self.linked, "HEAD moved", expect_head="0" * 40)
        self.assertTrue(self.linked.exists())

    def test_a_path_swapped_between_verification_and_removal_is_refused(self):
        real = cg.verify_worktree

        def swapping(path, heads=None, policy=None):
            report = real(path, heads, policy)
            os.rename(path, path + ".old")
            os.mkdir(path)
            return report
        with mock.patch.object(cg, "verify_worktree", swapping):
            report = cg.remove_worktree(str(self.linked), policy=self.policy)
        self.assertFalse(report["removed"])
        self.assertIn("changed while", report["reason"])
        self.assertTrue(Path(str(self.linked) + ".old").exists())

    def test_a_private_remote_is_reported_as_unanswered_and_heads_from_a_credentialed_host_decide(self):
        def refuses(url, repo, timeout):
            raise ValueError("git ls-remote failed")
        with mock.patch.object(cg, "REMOTE_LS", refuses):
            report = cg.verify_worktree(str(self.linked), policy=self.policy)
            self.assertFalse(report["removable"])
            self.assertIn("did not answer (private, unreachable or deleted", report["reason"])
            ok = cg.verify_worktree(str(self.linked), {URL: dict(self.live)}, self.policy)
            self.assertTrue(ok["removable"], ok)
            # supplied heads that do not contain the HEAD prove nothing
            stale = cg.verify_worktree(str(self.linked), {URL: {"refs/heads/main": "1" * 40}}, self.policy)
            self.assertFalse(stale["removable"])
            empty = cg.verify_worktree(str(self.linked), {URL: {}}, self.policy)
            self.assertFalse(empty["removable"])
            unknown_url = cg.verify_worktree(str(self.linked), {"https://github.com/other/repo.git": dict(self.live)},
                                             self.policy)
            self.assertFalse(unknown_url["removable"])

    def run_cli(self, *argv, stdin=""):
        out = io.StringIO()
        with redirect_stdout(out), mock.patch.object(sys, "stdin", io.StringIO(stdin)):
            code = cg.main(list(argv))
        return code, json.loads(out.getvalue())

    def test_the_cli_prints_json_and_its_exit_code_follows_the_verdict(self):
        code, data = self.run_cli("verify-worktree", "--path", str(self.linked))
        self.assertEqual((code, data["removable"]), (0, True))
        code, data = self.run_cli("remove-worktree", "--path", str(self.primary))
        self.assertEqual((code, data["removed"]), (1, False))
        code, data = self.run_cli("remove-worktree", "--path", str(self.linked), "--heads-stdin", stdin="not json")
        self.assertEqual((code, data["removed"]), (2, False))
        self.assertTrue(self.linked.exists())
        code, data = self.run_cli("remove-worktree", "--path", str(self.linked))
        self.assertEqual((code, data["removed"]), (0, True))


class GuardMessage(Repo):
    def test_the_refusal_text_carries_the_verifier_reason_and_the_next_step(self):
        (self.linked / "a.txt").write_text("changed\n")
        compiled = cg.Compiled(self.policy, home=str(self.home), cwd=str(self.primary))
        verdict, text = cg.decide("git worktree remove %s" % self.linked, compiled, cwd=str(self.primary))
        self.assertEqual(verdict, "block")
        self.assertIn("verifier: the working tree is not clean", text)
        self.assertIn("commit or clean the worktree", text)
        git(self.linked, "checkout", "-q", "--", "a.txt")

        def refuses(url, repo, timeout):
            raise ValueError("no credentials")
        with mock.patch.object(cg, "REMOTE_LS", refuses):
            verdict, text = cg.decide("git worktree remove %s" % self.linked, compiled, cwd=str(self.primary))
        self.assertEqual(verdict, "block")
        self.assertIn("the remote did not answer (private, unreachable or deleted", text)
        self.assertIn("--remote-heads-from local", text)
        self.assertNotIn(str(self.home), text.replace(str(self.linked), ""))


class FakeRun:
    """Stands in for subprocess.run: records argv, returns scripted answers."""

    def __init__(self, *answers):
        self.answers, self.calls = list(answers), []

    def __call__(self, argv, **kwargs):
        self.calls.append((argv, kwargs))
        answer = self.answers.pop(0)
        if isinstance(answer, Exception):
            raise answer
        return subprocess.CompletedProcess(argv, answer.get("code", 0), answer.get("out", ""), answer.get("err", ""))


def verdict(**kw):
    base = {"removable": True, "removed": True, "head": "a" * 40, "reason": None, "urls": {"origin": [URL]},
            "freed_bytes": 10}
    base.update(kw)
    return {"out": json.dumps(base)}


class Delegation(unittest.TestCase):
    PATH = "/Users/u/tools/wt-one"

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)

    def remove(self, runner, host="t2-dev", path=None, reason="merged and published", heads_from=None):
        return ah_worktree.remove(host, path or self.PATH, reason, heads_from, "s1", "agent-x", self.home, runner)

    def audit_rows(self):
        file = self.home / ".agent-harness" / "worktree-audit.jsonl"
        return [json.loads(line) for line in file.read_text().splitlines()] if file.exists() else []

    def test_a_remote_removal_runs_one_fixed_verifier_over_ssh_and_audits_before_and_after(self):
        run = FakeRun(verdict())
        result = self.remove(run)
        self.assertTrue(result["ok"] and result["removed"])
        argv = run.calls[0][0]
        self.assertEqual(argv[:6], ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "--"])
        self.assertEqual(argv[6], "t2-dev")
        self.assertEqual(argv[7], "python3 -I .claude/hooks/command_guard.py remove-worktree --path " + self.PATH)
        self.assertNotIn("--force", " ".join(argv))
        events = [row["event"] for row in self.audit_rows()]
        self.assertEqual(events, ["start", "result"])

    def test_local_runs_the_verifier_from_the_hooks_directory_with_isolation(self):
        run = FakeRun(verdict())
        self.remove(run, host="local")
        argv = run.calls[0][0]
        self.assertEqual(argv[1], "-I")
        self.assertTrue(argv[2].endswith("command_guard.py"))
        self.assertEqual(argv[3:], ["remove-worktree", "--path", self.PATH])

    def test_bad_requests_fail_before_any_process_or_audit_row(self):
        for kwargs in ({"host": "dev2"}, {"host": "t2-dev; id"}, {"path": "relative/p"}, {"path": "/a/../b"},
                       {"path": "/a/b/"}, {"path": "/a/b c"}, {"path": "/a/$(x)"}, {"path": "/a/b;rm"}, {"path": "/"},
                       {"path": "/a//b"}, {"path": "/a/é"}, {"reason": ""}, {"reason": "x" * 501},
                       {"reason": "bad\x01reason"}, {"heads_from": "dev2"}):
            with self.subTest(kwargs=str(kwargs)[:40]):
                run = FakeRun()
                with self.assertRaises(ah_worktree.WorktreeError):
                    self.remove(run, **kwargs)
                self.assertEqual(run.calls, [])
                self.assertEqual(self.audit_rows(), [])

    def test_there_is_no_force_or_second_path_flag(self):
        parser = ah.build_parser()
        base = ["worktree-remove", "--host", "t2-dev", "--path", self.PATH, "--reason", "r"]
        parser.parse_args(base)
        for extra in (["--force"], ["-f"], ["--path", "/a/b"][:0] + ["--forc"], ["--no-verify"]):
            with self.subTest(extra=extra), self.assertRaises(SystemExit), redirect_stderr_null():
                parser.parse_args(base + extra)

    def test_an_unanswerable_or_malformed_verifier_removes_nothing(self):
        for answer in ({"out": ""}, {"out": "not json"}, {"out": "[]"}, {"out": json.dumps({"removed": True})},
                       {"out": json.dumps({"removable": "yes"})}, OSError("ssh failed"),
                       subprocess.TimeoutExpired("ssh", 1),
                       {"out": json.dumps({"removable": True, "removed": "maybe"})}):
            with self.subTest(answer=str(answer)[:40]):
                with self.assertRaises(ah_worktree.WorktreeError):
                    self.remove(FakeRun(answer))

    def test_a_refusal_from_the_verifier_is_reported_not_overridden(self):
        run = FakeRun(verdict(removable=False, removed=False, reason="the working tree is not clean"))
        result = self.remove(run)
        self.assertFalse(result["ok"])
        self.assertFalse(result["removed"])
        self.assertIn("not clean", result["reason"])
        self.assertEqual(len(run.calls), 1)

    def test_the_audit_start_row_is_written_before_the_verifier_runs_and_a_failed_audit_stops_everything(self):
        seen = []

        def spying(argv, **kwargs):
            seen.append([row["event"] for row in self.audit_rows()])
            return subprocess.CompletedProcess(argv, 0, verdict()["out"], "")
        self.remove(spying)
        self.assertEqual(seen, [["start"]])
        run = FakeRun(verdict())
        with mock.patch.object(ah_worktree, "audit", side_effect=OSError("disk full")):
            with self.assertRaises(ah_worktree.WorktreeError):
                self.remove(run)
        self.assertEqual(run.calls, [])

    def test_the_current_directory_inside_a_local_target_is_refused(self):
        run = FakeRun()
        with mock.patch.object(os, "getcwd", return_value=self.PATH + "/sub"):
            with self.assertRaises(ah_worktree.WorktreeError):
                self.remove(run, host="local")
        self.assertEqual(run.calls, [])

    def test_heads_from_a_credentialed_host_pass_the_refs_to_the_verifier_on_stdin(self):
        sha = "a" * 40
        refs = {"out": "%s\trefs/heads/main\n%s\trefs/heads/feature\n" % (sha, sha)}
        run = FakeRun(verdict(removable=False, removed=False,
                              reason="the remote did not answer (private, unreachable or deleted: x)"), refs, verdict())
        result = self.remove(run, host="t2-dev", heads_from="local")
        self.assertTrue(result["ok"], result)
        ls_argv, ls_kwargs = run.calls[1]
        self.assertEqual(ls_argv[-3:], ["ls-remote", "--heads", "--"][:0] + ["--heads", "--", URL])
        self.assertEqual(ls_kwargs["env"]["GIT_TERMINAL_PROMPT"], "0")
        final_argv, final_kwargs = run.calls[2]
        self.assertIn("--heads-stdin", final_argv[-1])
        self.assertIn("--expect-head " + sha, final_argv[-1])
        self.assertEqual(json.loads(final_kwargs["input"]), {URL: {"refs/heads/main": sha, "refs/heads/feature": sha}})

    def test_heads_from_reads_only_github_and_fails_closed(self):
        evil = ["https://evil.example/x/y.git", "file:///etc", "ext::sh -c id", "https://github.com/a/b;id", "-oProxy=x"]
        for url in evil:
            with self.subTest(url=url):
                run = FakeRun(verdict(removable=False, removed=False, reason="the remote did not answer (x)",
                                      urls={"origin": [url]}))
                with self.assertRaises(ah_worktree.WorktreeError):
                    self.remove(run, heads_from="local")
                self.assertEqual(len(run.calls), 1)
        for ls in ({"code": 128, "err": "denied"}, {"out": ""}, {"out": "zz\trefs/heads/x\n"}, OSError("no git")):
            with self.subTest(ls=str(ls)[:30]):
                run = FakeRun(verdict(removable=False, removed=False, reason="the remote did not answer (x)"), ls)
                with self.assertRaises(ah_worktree.WorktreeError):
                    self.remove(run, heads_from="local")
                self.assertEqual(len(run.calls), 2)

    def test_heads_from_is_not_used_when_the_verifier_refuses_for_another_reason(self):
        run = FakeRun(verdict(removable=False, removed=False, reason="the working tree is not clean"))
        result = self.remove(run, heads_from="local")
        self.assertFalse(result["ok"])
        self.assertEqual(len(run.calls), 1)
        self.assertEqual([r["event"] for r in self.audit_rows()], ["start", "refused"])

    def test_the_command_is_wired_into_ah_and_installed(self):
        with mock.patch.object(ah_worktree, "remove", return_value={"ok": True}) as remove:
            out = io.StringIO()
            with redirect_stdout(out):
                code = ah.main(["worktree-remove", "--host", "local", "--path", self.PATH, "--reason", "why"])
        self.assertEqual(code, 0)
        self.assertEqual(remove.call_args[0][:3], ("local", self.PATH, "why"))
        text = (ROOT / "install.py").read_text() + (ROOT / "install_codex.py").read_text()
        self.assertIn("ah_worktree.py", text)


class redirect_stderr_null:
    def __enter__(self):
        self.old, sys.stderr = sys.stderr, io.StringIO()

    def __exit__(self, *exc):
        sys.stderr = self.old
        return False


if __name__ == "__main__":
    unittest.main()
