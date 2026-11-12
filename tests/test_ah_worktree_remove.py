"""`ah worktree-remove` and the verifier it runs (goodqa#15565): real temporary repositories, fake network and ssh.

The removal under test only ever touches temporary directories under a temporary HOME."""
import errno
import io
import json
import os
import shutil
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
        self.assertEqual(report["verifier"], cg.VERIFIER_VERSION)
        self.assertFalse(self.linked.exists())
        self.assertNotIn(str(self.linked), git(self.primary, "worktree", "list", "--porcelain"))
        self.assertTrue(self.primary.exists())

    def test_the_target_host_audits_a_removal_itself(self):
        cg.remove_worktree(str(self.linked), policy=self.policy)
        rows = [json.loads(line) for line in (self.home / ".agent-harness/worktree-audit.jsonl").read_text().splitlines()]
        self.assertEqual([row["event"] for row in rows], ["remove", "result"])
        self.assertEqual(rows[0]["path"], str(self.linked))
        self.assertTrue(rows[1]["removed"])

    def test_verify_alone_removes_nothing(self):
        report = cg.verify_worktree(str(self.linked), policy=self.policy)
        self.assertTrue(report["removable"], report)
        self.assertEqual(report["repo"], str(self.primary))
        self.assertEqual(report["urls"], {"origin": [URL]})
        self.assertTrue(self.linked.exists())

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

    def refused(self, path, fragment, **kwargs):
        report = cg.remove_worktree(str(path), policy=self.policy, **kwargs)
        self.assertFalse(report["removable"], report)
        self.assertFalse(report["removed"])
        self.assertIn(fragment, report["reason"])
        return report

    def test_the_primary_worktree_is_never_removable(self):
        self.refused(self.primary, "not a plain file")
        self.assertTrue(self.primary.exists())

    def test_paths_outside_scope_are_refused_including_other_case_spellings(self):
        outside = Path(tempfile.mkdtemp(prefix="outside-"))
        self.addCleanup(lambda: shutil.rmtree(outside, ignore_errors=True))
        self.refused(outside, "outside the home")
        (self.home / ".claude").mkdir()
        self.refused(self.home / ".claude", "protected state")
        (self.home / ".agent-harness/logs").mkdir(parents=True)
        self.refused(self.home / ".agent-harness/logs", "inside work/")
        self.refused(self.home, "outside the home")
        self.assertFalse(cg.verify_worktree("relative/path", policy=self.policy)["removable"])
        # red-team L1: a case spelling must not slip past the deny list (APFS is case insensitive)
        for spelling in (".CLAUDE", ".Codex", ".SSH", "LIBRARY", ".Agent-Harness/logs"):
            self.assertIsNotNone(cg.worktree_scope_refusal(str(self.home / spelling / "x")), spelling)
        self.assertIsNone(cg.worktree_scope_refusal(str(self.home / ".AGENT-HARNESS" / "WORK" / "s" / "t")))

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

        def swapping(path, authenticated=False, policy=None):
            report = real(path, authenticated, policy)
            os.rename(path, path + ".old")
            os.mkdir(path)
            return report
        with mock.patch.object(cg, "verify_worktree", swapping):
            report = cg.remove_worktree(str(self.linked), policy=self.policy)
        self.assertFalse(report["removed"])
        self.assertIn("changed while", report["reason"])
        self.assertTrue(Path(str(self.linked) + ".old").exists())

    # red-team F4: a worktree somebody is working in
    def test_a_process_working_inside_the_worktree_blocks_the_removal(self):
        sleeper = subprocess.Popen(["sleep", "60"], cwd=str(self.linked))
        self.addCleanup(lambda: (sleeper.kill(), sleeper.wait()))
        sub = self.linked / "deeper"
        sub.mkdir()
        report = self.refused(self.linked, "process is using the worktree")
        self.assertIn("pid %d" % sleeper.pid, report["reason"])
        self.assertTrue(self.linked.exists())
        sleeper.kill()
        sleeper.wait()
        sub.rmdir()
        self.assertTrue(cg.remove_worktree(str(self.linked), policy=self.policy)["removed"])

    def test_a_process_check_that_cannot_run_fails_closed(self):
        with mock.patch.object(cg, "busy_processes", return_value=None):
            self.refused(self.linked, "could not check for processes")
        self.assertTrue(self.linked.exists())

    def test_busy_processes_reads_lsof_output_and_ignores_other_directories(self):
        out = "p123\ncsleep\nn%s/sub\np124\ncvim\nn/elsewhere/x\np%d\ncself\nn%s\n" % (self.linked, os.getpid(), self.linked)
        fake = subprocess.CompletedProcess([], 0, out, "")
        real_isdir = os.path.isdir
        with mock.patch.object(cg.os.path, "isdir", lambda p: False if p == "/proc/self" else real_isdir(p)), \
                mock.patch.object(cg.subprocess, "run", return_value=fake):
            self.assertEqual(cg.busy_processes(str(self.linked)), [(123, "sleep")])

    # red-team F1: refs can no longer be supplied by the caller
    def test_forged_refs_cannot_publish_an_unpublished_head(self):
        git(self.linked, "checkout", "-q", "--detach")
        (self.linked / "local.txt").write_text("local\n")
        git(self.linked, "add", "local.txt")
        git(self.linked, "commit", "-q", "-m", "local only")
        forged = git(self.linked, "rev-parse", "HEAD")
        out = io.StringIO()
        with redirect_stdout(out), mock.patch.object(sys, "stdin", io.StringIO(json.dumps({URL: {"refs/heads/main": forged}}))):
            with self.assertRaises(SystemExit), mock.patch.object(sys, "stderr", io.StringIO()):
                cg.main(["remove-worktree", "--path", str(self.linked), "--heads-stdin"])
        self.assertTrue(self.linked.exists())
        report = cg.remove_worktree(str(self.linked), policy=self.policy)  # the real remote still lacks the commit
        self.assertFalse(report["removed"])
        self.assertIn("not present on a live", report["reason"])

    def test_a_private_remote_is_unanswered_anonymously_and_answered_with_the_hosts_own_credentials(self):
        def refuses(url, repo, timeout):
            raise ValueError("git ls-remote failed")
        with mock.patch.object(cg, "REMOTE_LS", refuses):
            report = cg.verify_worktree(str(self.linked), policy=self.policy)
            self.assertFalse(report["removable"])
            self.assertIn("did not answer (private, unreachable or deleted", report["reason"])
            with mock.patch.object(cg, "authenticated_remote_refs", lambda url, repo, timeout: dict(self.live)):
                ok = cg.verify_worktree(str(self.linked), authenticated=True, policy=self.policy)
                self.assertTrue(ok["removable"], ok)
            with mock.patch.object(cg, "authenticated_remote_refs", lambda url, repo, timeout: {"refs/heads/main": "1" * 40}):
                self.assertFalse(cg.verify_worktree(str(self.linked), authenticated=True, policy=self.policy)["removable"])

    def test_the_credentialed_ls_remote_runs_in_a_scrubbed_environment_from_slash(self):
        seen = {}

        def fake(argv, **kwargs):
            seen.update(argv=argv, **kwargs)
            return subprocess.CompletedProcess(argv, 0, ("%s\trefs/heads/main\n" % ("a" * 40)).encode(), b"")
        poisoned = {"GIT_CONFIG_COUNT": "1", "GIT_CONFIG_KEY_0": "url.ssh://evil/.insteadOf",
                    "GIT_CONFIG_VALUE_0": "https://github.com/", "GIT_SSH_COMMAND": "evil", "GIT_DIR": "/x",
                    "SSH_AUTH_SOCK": "/tmp/agent.sock"}
        with mock.patch.dict(os.environ, poisoned), mock.patch.object(cg.subprocess, "run", fake):
            refs = cg.authenticated_remote_refs(URL, str(self.linked), 5)
        self.assertEqual(refs, {"refs/heads/main": "a" * 40})
        self.assertEqual(seen["cwd"], os.sep)
        env = seen["env"]
        self.assertEqual(sorted(k for k in env if k.startswith("GIT_")),
                         ["GIT_ASKPASS", "GIT_CONFIG_GLOBAL", "GIT_CONFIG_NOSYSTEM", "GIT_TERMINAL_PROMPT"])
        self.assertEqual(env["GIT_CONFIG_GLOBAL"], "/dev/null")
        self.assertEqual(env["SSH_AUTH_SOCK"], "/tmp/agent.sock")
        self.assertEqual(seen["argv"][-3:], ["--tags", "--", URL])
        self.assertNotIn("-C", seen["argv"])

    def test_the_credentialed_ls_remote_reads_only_github_remotes(self):
        for url in ("https://evil.example/a/b.git", "file:///etc", "ext::sh -c id", "https://github.com/a/b;id", "-oProxy=x",
                    "ssh://git@github.com/a/b.git", "git@evil.com:a/b.git", "", None):
            with self.subTest(url=url), mock.patch.object(cg.subprocess, "run") as run:
                with self.assertRaises(ValueError):
                    cg.authenticated_remote_refs(url, "/", 5)
                run.assert_not_called()
        with mock.patch.object(cg.subprocess, "run",
                               return_value=subprocess.CompletedProcess([], 128, b"", b"denied")):
            with self.assertRaises(ValueError):
                cg.authenticated_remote_refs("git@github.com:a/b.git", "/", 5)

    def run_cli(self, *argv):
        out = io.StringIO()
        with redirect_stdout(out):
            code = cg.main(list(argv))
        return code, json.loads(out.getvalue())

    def test_the_cli_prints_json_and_its_exit_code_follows_the_verdict(self):
        code, data = self.run_cli("verify-worktree", "--path", str(self.linked))
        self.assertEqual((code, data["removable"], data["verifier"]), (0, True, cg.VERIFIER_VERSION))
        code, data = self.run_cli("remove-worktree", "--path", str(self.primary))
        self.assertEqual((code, data["removed"]), (1, False))
        self.assertTrue(self.linked.exists())
        code, data = self.run_cli("remove-worktree", "--path", str(self.linked))
        self.assertEqual((code, data["removed"]), (0, True))

    def test_a_removal_that_deletes_the_directory_but_fails_is_reported_in_two_states(self):
        real = subprocess.run

        def half(argv, *args, **kwargs):
            if "worktree" in argv and "remove" in argv:
                shutil.rmtree(self.linked)
                return subprocess.CompletedProcess(argv, 1, "", "error: failed to delete registry")
            return real(argv, *args, **kwargs)
        with mock.patch.object(cg.subprocess, "run", half):
            report = cg.remove_worktree(str(self.linked), policy=self.policy)
        self.assertFalse(report["removed"])
        self.assertTrue(report["directory_removed"])
        self.assertTrue(report["registry_entry_left"])
        self.assertIn("directory gone, registry entry left", report["reason"])


class MoreVerifier(Repo):
    def test_git_saying_ok_while_the_directory_is_still_there_is_not_a_removal(self):
        real = subprocess.run

        def lying(argv, *args, **kwargs):
            if "worktree" in argv and "remove" in argv:
                return subprocess.CompletedProcess(argv, 0, "", "")
            return real(argv, *args, **kwargs)
        with mock.patch.object(cg.subprocess, "run", lying):
            report = cg.remove_worktree(str(self.linked), policy=self.policy)
        self.assertFalse(report["removed"])
        self.assertFalse(report["directory_removed"])
        self.assertTrue(report["registry_entry_left"])

    def test_busy_processes_on_a_proc_filesystem_host_reads_cwd_links(self):
        cwd = {"111": str(self.linked) + "/deep", "222": "/elsewhere", "333": str(self.linked) + "x"}

        def link(path):
            pid = path.split("/")[2]
            if pid not in cwd:
                raise OSError(errno.ENOENT, "gone")
            return cwd[pid]
        real_isdir = os.path.isdir
        with mock.patch.object(cg.os.path, "isdir", lambda p: True if p == "/proc/self" else real_isdir(p)), \
                mock.patch.object(cg.os, "listdir", lambda p: ["111", "222", "333", "444", "self"] if p == "/proc" else []), \
                mock.patch.object(cg.os, "readlink", link):
            self.assertEqual(cg.busy_processes(str(self.linked)), [(111, "pid")])


class RedTeamRound2(Repo):
    # F1: git killed partway through the removal
    def test_a_timeout_partway_through_the_removal_still_reports_what_is_left_and_writes_the_result_row(self):
        real = subprocess.run

        def killed(argv, *args, **kwargs):
            if "worktree" in argv and "remove" in argv:
                (self.linked / "a.txt").unlink()  # half the tree is gone, the registry entry is not
                raise subprocess.TimeoutExpired(argv, 900)
            return real(argv, *args, **kwargs)
        with mock.patch.object(cg.subprocess, "run", killed):
            report = cg.remove_worktree(str(self.linked), policy=self.policy)
        self.assertIs(report["removed"], False)
        self.assertFalse(report["directory_removed"])  # the directory is still there, half emptied
        self.assertIs(report["registry_entry_left"], True)
        self.assertIn("TimeoutExpired", report["reason"])
        rows = [json.loads(line) for line in (self.home / ".agent-harness/worktree-audit.jsonl").read_text().splitlines()]
        self.assertEqual([row["event"] for row in rows], ["remove", "result"])
        self.assertEqual(rows[1]["problem"], "TimeoutExpired")

    def test_the_cli_prints_json_even_when_git_times_out(self):
        real = subprocess.run

        def killed(argv, *args, **kwargs):
            if "worktree" in argv and "remove" in argv:
                shutil.rmtree(self.linked)  # the directory went, then the call timed out before the registry cleanup
                raise subprocess.TimeoutExpired(argv, 900)
            return real(argv, *args, **kwargs)
        out = io.StringIO()
        with redirect_stdout(out), mock.patch.object(cg.subprocess, "run", killed):
            code = cg.main(["remove-worktree", "--path", str(self.linked)])
        data = json.loads(out.getvalue())
        self.assertEqual(code, 1)
        self.assertTrue(data["directory_removed"])
        self.assertIs(data["removed"], False)

    def test_a_failing_registry_check_or_disk_probe_is_reported_unknown_not_a_crash(self):
        with mock.patch.object(cg, "registry_lists", side_effect=ValueError("git failed")), \
                mock.patch.object(cg.shutil, "disk_usage", side_effect=OSError("no")):
            report = cg.remove_worktree(str(self.linked), policy=self.policy)
        self.assertIsNone(report["registry_entry_left"])
        self.assertIs(report["removed"], False)  # an unknown registry state is never a confirmed removal
        self.assertIsNone(report["freed_bytes"])
        self.assertIn("registry entry unknown", report["reason"])

    # F5: exact registry compare
    def test_the_registry_check_compares_whole_paths_not_substrings(self):
        listing = "worktree /x/primary\nHEAD aaa\n\nworktree /x/wt-10\nHEAD bbb\n\nworktree /x/wt-1x\n"
        with mock.patch.object(cg, "_git_out", return_value=listing):
            self.assertFalse(cg.registry_lists("/x/primary", "/x/wt-1"))
            self.assertTrue(cg.registry_lists("/x/primary", "/x/wt-10"))
            self.assertFalse(cg.registry_lists("/x/primary", "/x/primary/sub"))
        with mock.patch.object(cg, "_git_out", side_effect=ValueError("git failed")):
            with self.assertRaises(ValueError):
                cg.registry_lists("/x/primary", "/x/wt-1")

    # F3: processes the check cannot see
    def test_a_process_it_cannot_inspect_fails_closed_but_an_exited_one_is_skipped(self):
        real_isdir = os.path.isdir

        def denied(path):
            raise PermissionError(errno.EACCES, "denied")

        def exited(path):
            raise OSError(errno.ESRCH, "no such process")
        same_user = {"name": "bash", "uid": os.getuid()}
        for link, expected in ((denied, None), (exited, [])):
            with mock.patch.object(cg.os.path, "isdir", lambda p: True if p == "/proc/self" else real_isdir(p)), \
                    mock.patch.object(cg.os, "listdir", lambda p: ["555"] if p == "/proc" else []), \
                    mock.patch.object(cg.os, "readlink", link), mock.patch.object(cg, "_proc_status", lambda pid: same_user):
                self.assertEqual(cg.busy_processes(str(self.linked)), expected)

    def test_lsof_exit_one_means_nothing_found_only_when_it_said_nothing_else(self):
        real_isdir = os.path.isdir
        for code, out, err, expected in ((1, "", "", []), (1, "", "lsof: WARNING: can't stat() fuse file system", None),
                                         (0, "", "", []), (2, "", "", None), (1, "p9\ncx\nn/elsewhere\n", "", [])):
            with self.subTest(code=code, err=err[:10]), \
                    mock.patch.object(cg.os.path, "isdir", lambda p: False if p == "/proc/self" else real_isdir(p)), \
                    mock.patch.object(cg.subprocess, "run", return_value=subprocess.CompletedProcess([], code, out, err)):
                self.assertEqual(cg.busy_processes(str(self.linked)), expected)

    # F6: the delegated verifier has its own, larger, budget
    def test_the_nested_repository_scan_is_bounded_by_what_is_left_of_the_budget(self):
        (self.primary / ".git/info/exclude").write_text("node_modules/\n")
        (self.linked / "node_modules").mkdir()
        (self.linked / "node_modules" / "x.js").write_text("x\n")
        seen = []
        real = cg._nested_repo

        def spy(directory, limit=250000, deep=False, seconds=1.5):
            seen.append(seconds)
            return real(directory, limit=limit, deep=deep, seconds=seconds)
        tight = {"reproducible_clone": {"total_seconds": 6.0, "remote_seconds": 2.0, "scale": 15.0}}
        with mock.patch.object(cg, "_nested_repo", spy):
            self.assertIsNone(cg.linked_worktree_remove_refusal(str(self.linked), os.sep, tight))
        self.assertTrue(seen, "the ignored build directory was not scanned")
        self.assertLessEqual(max(seen), 6.0)  # never more than the budget has left, not 1.5 * 15 = 22.5 s
        self.assertGreater(min(seen), 0.1)

    def test_the_verifier_uses_its_own_scaled_budget_and_the_hook_default_is_unchanged(self):
        seen = []
        real = cg._git_out

        def spy(repo, args, timeout, stdin=None):
            seen.append(timeout)
            return real(repo, args, timeout, stdin)
        with mock.patch.object(cg, "_git_out", spy):
            self.assertIsNone(cg.linked_worktree_remove_refusal(str(self.linked), os.sep, cg.WORKTREE_POLICY))
            scaled = max(seen)
            seen.clear()
            self.assertIsNone(cg.linked_worktree_remove_refusal(str(self.linked), str(self.primary), self.policy))
            default = max(seen)
        self.assertLessEqual(default, 3.0)
        self.assertGreater(scaled, 30.0)
        self.assertGreaterEqual(cg.WORKTREE_POLICY["reproducible_clone"]["total_seconds"], 120)
        used = []
        real_refusal = cg.linked_worktree_remove_refusal
        with mock.patch.object(cg, "linked_worktree_remove_refusal",
                               lambda path, cwd, policy=None, remote_ls=None: used.append(policy) or real_refusal(path, cwd, policy, remote_ls)):
            cg.verify_worktree(str(self.linked))
        self.assertEqual(used[0]["reproducible_clone"], cg.WORKTREE_POLICY["reproducible_clone"])  # the delegated rules, laid over the user policy


class GuardMessage(Repo):
    def test_the_refusal_text_carries_the_verifier_reason_and_the_next_step_without_advising_discard(self):
        (self.linked / "a.txt").write_text("changed\n")
        compiled = cg.Compiled(self.policy, home=str(self.home), cwd=str(self.primary))
        verdict, text = cg.decide("git worktree remove %s" % self.linked, compiled, cwd=str(self.primary))
        self.assertEqual(verdict, "block")
        self.assertIn("verifier: the working tree is not clean", text)
        self.assertIn("commit and push what you need", text)
        self.assertIn("belongs to another owner, leave it", text)
        for harmful in ("git clean", "discard", "reset --hard", "clean the worktree"):
            self.assertNotIn(harmful, text)
        git(self.linked, "checkout", "-q", "--", "a.txt")

        def refuses(url, repo, timeout):
            raise ValueError("no credentials")
        with mock.patch.object(cg, "REMOTE_LS", refuses):
            verdict, text = cg.decide("git worktree remove %s" % self.linked, compiled, cwd=str(self.primary))
        self.assertEqual(verdict, "block")
        self.assertIn("the remote did not answer (private, unreachable or deleted", text)
        self.assertIn("--remote-auth", text)
        self.assertNotIn("--remote-heads-from", text)
        self.assertNotIn(str(self.home), text.replace(str(self.linked), ""))

    def test_a_reason_belongs_to_its_own_segment_only(self):
        dirty = self.base / "dirty"
        git(self.primary, "worktree", "add", "-q", "-b", "dirty", str(dirty))
        git(self.primary, "update-ref", "refs/remotes/origin/dirty", git(dirty, "rev-parse", "HEAD"))
        self.live["refs/heads/dirty"] = git(dirty, "rev-parse", "HEAD")
        (dirty / "a.txt").write_text("changed\n")
        compiled = cg.Compiled(self.policy, home=str(self.home), cwd=str(self.primary))

        def text(command):
            return cg.decide(command, compiled, cwd=str(self.primary))

        # The exemption (and so a verifier reason) exists only for ONE standalone remove command; any multi-segment line
        # is judged by the generic rule and must never carry a reason from another segment or an earlier command.
        for command in ("git worktree remove %s ; git worktree prune" % dirty,
                        "git worktree prune ; git worktree remove %s" % dirty,
                        "git worktree remove %s ; git worktree remove %s" % (self.linked, dirty),
                        "git worktree remove %s %s" % (self.linked, dirty)):
            with self.subTest(command=command.replace(str(self.base), "~")):
                verdict, message = text(command)
                self.assertEqual(verdict, "block")
                self.assertNotIn("verifier:", message)
        # the standalone form still explains itself, and a later standalone command does not inherit it
        verdict, message = text("git worktree remove %s" % dirty)
        self.assertEqual(message.count("verifier: the working tree is not clean"), 1)
        verdict, message = text("git worktree remove %s" % self.linked)
        self.assertEqual(verdict, "allow")
        verdict, message = text("git worktree prune")
        self.assertNotIn("verifier:", message)

    def test_a_reason_from_one_segment_is_not_shown_for_another(self):
        self.assertIsNone(cg._worktree_instead(None))
        self.assertIsNone(cg._worktree_instead(""))
        self.assertIn("verifier: x", cg._worktree_instead("x"))


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
            "freed_bytes": 10, "verifier": 2}
    base.update(kw)
    return {"out": json.dumps(base)}


class Delegation(unittest.TestCase):
    PATH = "/Users/u/tools/wt-one"

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)

    def remove(self, runner, host="t2-dev", path=None, reason="merged and published", authenticated=False):
        return ah_worktree.remove(host, path or self.PATH, reason, authenticated, "s1", "agent-x", self.home, runner)

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
        self.assertEqual([row["event"] for row in self.audit_rows()], ["start", "result"])
        self.assertEqual(len(run.calls), 1)

    def test_remote_auth_adds_one_flag_and_never_any_refs(self):
        run = FakeRun(verdict())
        self.remove(run, authenticated=True)
        self.assertEqual(run.calls[0][0][7], "python3 -I .claude/hooks/command_guard.py remove-worktree --path "
                         + self.PATH + " --remote-auth")
        self.assertNotIn("input", run.calls[0][1])
        self.assertNotIn("ls-remote", " ".join(run.calls[0][0]))

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
                       {"reason": "bad\x01reason"}):
            with self.subTest(kwargs=str(kwargs)[:40]):
                run = FakeRun()
                with self.assertRaises(ah_worktree.WorktreeError):
                    self.remove(run, **kwargs)
                self.assertEqual(run.calls, [])
                self.assertEqual(self.audit_rows(), [])

    def test_there_is_no_force_second_path_or_caller_supplied_refs_flag(self):
        parser = ah.build_parser()
        base = ["worktree-remove", "--host", "t2-dev", "--path", self.PATH, "--reason", "r"]
        parser.parse_args(base)
        parser.parse_args(base + ["--remote-auth"])
        for extra in (["--force"], ["-f"], ["--forc"], ["--no-verify"], ["--heads-stdin"], ["--remote-heads-from", "local"],
                      ["--remote-aut"]):
            with self.subTest(extra=extra), self.assertRaises(SystemExit), redirect_stderr_null():
                parser.parse_args(base + extra)

    def test_an_unknown_outcome_after_the_runner_started_is_recorded_as_unknown_never_as_not_removed(self):
        for answer in ({"out": ""}, {"out": "not json"}, {"out": "[]"}, {"out": json.dumps({"removed": True})},
                       {"out": json.dumps({"removable": "yes", "verifier": 2})}, OSError("ssh failed"),
                       subprocess.TimeoutExpired("ssh", 1),
                       {"out": json.dumps({"removable": True, "removed": "maybe", "verifier": 2})}):
            with self.subTest(answer=str(answer)[:40]):
                before = len(self.audit_rows())
                with self.assertRaises(ah_worktree.WorktreeError) as caught:
                    self.remove(FakeRun(answer))
                self.assertNoRemovalClaim(str(caught.exception))
                rows = self.audit_rows()[before:]
                self.assertEqual([row["event"] for row in rows], ["start", "result"])
                self.assertIsNone(rows[1]["removed"])  # unknown: the remote command may have run
                self.assertIn("unknown", rows[1]["why"])

    def assertNoRemovalClaim(self, text):
        """After the runner started the host may already have removed the tree: the message must say the outcome is
        unknown and point at the host, and must never say that nothing was removed (red-team r4 F1)."""
        lowered = text.lower()
        for claim in ("nothing removed", "nothing was removed", "nothing is assumed removed", "not removed"):
            self.assertNotIn(claim, lowered)
        self.assertIn("unknown", lowered)
        self.assertIn("check the host", lowered)

    # red-team r4 F2: a null `removed` beside removable true is not a definite answer
    def test_a_null_removed_beside_removable_true_is_an_unknown_outcome_not_a_failure(self):
        for removed in (None, "missing"):
            body = {"removable": True, "verifier": 2, "head": "a" * 40}
            if removed != "missing":
                body["removed"] = None
            with self.subTest(removed=removed):
                result = self.remove(FakeRun({"out": json.dumps(body)}))
                row = self.audit_rows()[-1]
                self.assertIsNone(row["removed"])
                self.assertIsNone(result["removed"])
                self.assertFalse(result["ok"])
                self.assertIn("unknown", (row["why"] or "").lower())
        # removable false with no removed key is a definite refusal: False
        result = self.remove(FakeRun({"out": json.dumps({"removable": False, "verifier": 2, "reason": "not clean"})}))
        self.assertIs(self.audit_rows()[-1]["removed"], False)
        self.assertIs(result["removed"], False)

    # receipt r5 N1: a self-contradicting answer is malformed, so the outcome is unknown
    def test_removable_false_with_removed_true_is_a_malformed_answer_and_an_unknown_outcome(self):
        before = len(self.audit_rows())
        with self.assertRaises(ah_worktree.WorktreeError) as caught:
            self.remove(FakeRun(verdict(removable=False, removed=True, reason="not clean")))
        self.assertNoRemovalClaim(str(caught.exception))
        rows = self.audit_rows()[before:]
        self.assertIsNone(rows[-1]["removed"])
        self.assertIn("unknown", rows[-1]["why"])

    # receipt r5 N2: a removal that started and did not complete may have deleted part of the tree
    def test_a_removal_that_started_and_did_not_complete_is_recorded_as_unknown_not_as_not_removed(self):
        answer = verdict(removable=True, removed=False, directory_removed=False, registry_entry_left=True,
                         reason="git worktree remove did not complete cleanly (TimeoutExpired; directory still there, "
                                "registry entry left): ")
        result = self.remove(FakeRun(answer))
        row = self.audit_rows()[-1]
        self.assertIsNone(row["removed"])
        self.assertIsNone(result["removed"])
        self.assertFalse(result["ok"])
        self.assertIs(result["directory_removed"], False)
        self.assertIs(result["registry_entry_left"], True)
        for text in (row["why"], result["reason"]):
            self.assertIn("partly deleted", text)
            self.assertIn("check the host", text)
        # a verifier refusal (nothing ran) stays a definite False
        self.remove(FakeRun(verdict(removable=False, removed=False, reason="not clean")))
        self.assertIs(self.audit_rows()[-1]["removed"], False)

    def test_a_definite_answer_is_recorded_as_a_definite_outcome(self):
        self.remove(FakeRun(verdict(removable=False, removed=False, reason="the working tree is not clean")))
        self.assertIs(self.audit_rows()[-1]["removed"], False)
        self.remove(FakeRun(verdict()))
        self.assertIs(self.audit_rows()[-1]["removed"], True)

    def test_the_call_timeout_covers_the_verifiers_own_worst_case(self):
        self.assertEqual(ah_worktree.VERIFY_SECONDS, cg.VERIFY_SECONDS)
        self.assertEqual(ah_worktree.REMOVE_SECONDS, cg.REMOVE_SECONDS)
        self.assertGreater(ah_worktree.CALL_TIMEOUT, cg.VERIFY_SECONDS + cg.REMOVE_SECONDS + 20 + 10)
        run = FakeRun(verdict())
        self.remove(run)
        self.assertEqual(run.calls[0][1]["timeout"], ah_worktree.CALL_TIMEOUT)

    def test_an_old_verifier_on_the_target_is_refused_by_version(self):
        for answer in (verdict(verifier=1), {"out": json.dumps({"removable": True, "removed": True})},
                       verdict(verifier="2")):
            with self.subTest(answer=str(answer)[:50]):
                with self.assertRaises(ah_worktree.WorktreeError) as caught:
                    self.remove(FakeRun(answer))
                self.assertEqual(caught.exception.code, "verifier_outdated")
                self.assertNoRemovalClaim(str(caught.exception))  # {"removed": true} said it WAS removed
                self.assertEqual(self.audit_rows()[-1]["removed"], None)

    def test_a_refusal_from_the_verifier_is_reported_not_overridden(self):
        run = FakeRun(verdict(removable=False, removed=False, reason="the working tree is not clean"))
        result = self.remove(run)
        self.assertFalse(result["ok"])
        self.assertFalse(result["removed"])
        self.assertIn("not clean", result["reason"])
        self.assertEqual(len(run.calls), 1)

    def test_the_outcome_row_redacts_the_reason_and_survives_a_failing_audit_after_the_removal(self):
        run = FakeRun(verdict(removable=False, removed=False, reason="failed: token=ghp_abc123 bad"))
        result = self.remove(run)
        self.assertNotIn("ghp_abc123", json.dumps(self.audit_rows()))
        self.assertNotIn("ghp_abc123", json.dumps(result))
        real, calls = ah_worktree.audit, []

        def second_fails(home, record):
            calls.append(record["event"])
            if record["event"] == "result":
                raise OSError("disk full")
            return real(home, record)
        with mock.patch.object(ah_worktree, "audit", second_fails):
            result = self.remove(FakeRun(verdict()))
        self.assertTrue(result["removed"])  # the removal happened and is still reported
        self.assertIn("audit_warning", result)

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

    def test_the_command_is_wired_into_ah_and_installed(self):
        with mock.patch.object(ah_worktree, "remove", return_value={"ok": True}) as remove:
            out = io.StringIO()
            with redirect_stdout(out):
                code = ah.main(["worktree-remove", "--host", "local", "--path", self.PATH, "--reason", "why",
                                "--remote-auth"])
        self.assertEqual(code, 0)
        self.assertEqual(remove.call_args[0][:4], ("local", self.PATH, "why", True))
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
