"""goodqa#15739: the delegated worktree verifier ignores the hand-written-hooks refusal and scans only same-user processes.

Real temporary repositories; fake network. A marker hook must never run, and every git process of the delegated route must
carry core.hooksPath=/dev/null."""
import errno
import os
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_ah_worktree_remove import GIT_ENV, Repo, git  # noqa: E402

import command_guard as cg  # noqa: E402

HOOK_NAMES = ("pre-push", "post-checkout", "pre-commit", "reference-transaction", "post-index-change", "fsmonitor-watchman",
              "commit-msg", "post-merge")


class Hooks(Repo):
    def setUp(self):
        super().setUp()
        self.hooks = self.primary / ".git" / "hooks"
        self.hooks.mkdir(exist_ok=True)
        self.marker = self.home / "HOOK-RAN"
        for name in HOOK_NAMES:
            hook = self.hooks / name
            hook.write_text("#!/bin/sh\necho %s >> %s\nexit 0\n" % (name, self.marker))
            hook.chmod(0o755)

    def verify(self, policy="delegated"):
        return cg.verify_worktree(str(self.linked), policy=None if policy == "delegated" else policy)

    # ---- AC-1
    def test_the_delegated_verifier_ignores_hand_written_hooks_and_no_hook_runs_in_a_real_removal(self):
        report = self.verify()
        self.assertTrue(report["removable"], report)
        removed = cg.remove_worktree(str(self.linked), policy=None)
        self.assertTrue(removed["removed"], removed)
        self.assertFalse(self.marker.exists(), "a hook ran: %s" % (self.marker.read_text() if self.marker.exists() else ""))

    # The real proof on t2-dev showed the CLI never used the delegated policy: main() loads the user policy and passed it
    # down, so verify_worktree used the hook defaults (no scaled budget, hooks refused). Run the actual CLI.
    def run_cli(self, *argv):
        import io
        import json
        from contextlib import redirect_stdout
        out = io.StringIO()
        with redirect_stdout(out):
            code = cg.main(list(argv))
        return code, json.loads(out.getvalue())

    def test_the_command_line_uses_the_delegated_policy_not_the_hook_default(self):
        code, report = self.run_cli("verify-worktree", "--path", str(self.linked))
        self.assertEqual((code, report["removable"]), (0, True), report)
        used = []
        real = cg.linked_worktree_remove_refusal
        with mock.patch.object(cg, "linked_worktree_remove_refusal",
                               lambda path, cwd, policy=None, remote_ls=None: used.append(policy) or real(path, cwd, policy, remote_ls)):
            self.run_cli("verify-worktree", "--path", str(self.linked))
        cfg = used[0]["reproducible_clone"]
        self.assertIs(cfg["allow_hooks"], True)
        self.assertEqual(cfg["scale"], 15.0)
        self.assertEqual(cfg["total_seconds"], cg.VERIFY_SECONDS)
        code, report = self.run_cli("remove-worktree", "--path", str(self.linked))
        self.assertEqual((code, report["removed"]), (0, True), report)
        self.assertFalse(self.marker.exists())

    def test_a_user_policy_is_the_base_but_cannot_loosen_the_delegated_rules_or_turn_the_route_back_on(self):
        for base in (None, {}, {"reproducible_clone": {"allow_hooks": False, "scale": 1.0, "total_seconds": 4.0}}):
            used = []
            real = cg.linked_worktree_remove_refusal
            with mock.patch.object(cg, "linked_worktree_remove_refusal",
                                   lambda path, cwd, policy=None, remote_ls=None: used.append(policy) or real(path, cwd, policy, remote_ls)):
                cg.verify_worktree(str(self.linked), policy=base)
            self.assertIs(used[0]["reproducible_clone"]["allow_hooks"], True)
            self.assertEqual(used[0]["reproducible_clone"]["scale"], 15.0)
        # the user policy can still switch the exemption off
        off = {"reproducible_clone": {"enabled": False}}
        self.assertFalse(cg.verify_worktree(str(self.linked), policy=off)["removable"])
        self.assertIn("switched off", cg.verify_worktree(str(self.linked), policy=off)["reason"])

    # ---- NEG-5
    def test_hook_files_of_odd_shapes_are_ignored_and_nothing_runs(self):
        (self.hooks / "pre-rebase").symlink_to(self.hooks / "pre-push")
        (self.hooks / "post-update").mkdir()
        (self.hooks / "prepare-commit-msg").write_text("#!/bin/sh\necho x >> %s\n" % self.marker)  # not executable
        (self.hooks / "pre-push.local").write_text("data\n")
        self.assertTrue(self.verify()["removable"])
        self.assertTrue(cg.remove_worktree(str(self.linked), policy=None)["removed"])
        self.assertFalse(self.marker.exists())

    # ---- AC-2 and NEG-3: the strict callers stay strict
    def test_the_default_policy_the_hook_form_and_the_clone_verifier_still_refuse_hooks(self):
        self.assertEqual(cg.linked_worktree_remove_refusal(str(self.linked), str(self.primary), self.policy),
                         "it has hand-written git hooks")
        compiled = cg.Compiled(self.policy, home=str(self.home), cwd=str(self.primary))
        verdict, text = cg.decide("git worktree remove %s" % self.linked, compiled, cwd=str(self.primary))
        self.assertEqual(verdict, "block")
        self.assertIn("hand-written git hooks", text)
        self.assertFalse(self.marker.exists())

    def test_only_a_real_true_allows_hooks(self):
        for value in (1, "yes", "true", "", None, 0, [True]):
            with self.subTest(value=repr(value)):
                policy = {"reproducible_clone": {"allow_hooks": value}}
                self.assertEqual(cg.linked_worktree_remove_refusal(str(self.linked), os.sep, policy),
                                 "it has hand-written git hooks")
        policy = {"reproducible_clone": {"allow_hooks": True}}
        self.assertIsNone(cg.linked_worktree_remove_refusal(str(self.linked), os.sep, policy))
        self.assertIs(cg.WORKTREE_POLICY["reproducible_clone"]["allow_hooks"], True)

    def test_the_clone_verifier_refuses_hooks_even_when_given_the_allow_key(self):
        clone = self.home / "clone"
        clone.mkdir()
        git(clone, "init", "-q", "-b", "main")
        (clone / "a.txt").write_text("x\n")
        git(clone, "add", "a.txt")
        git(clone, "commit", "-q", "-m", "x")
        git(clone, "remote", "add", "origin", "https://github.com/acme/widgets.git")
        head = git(clone, "rev-parse", "HEAD")
        git(clone, "update-ref", "refs/remotes/origin/main", head)
        self.live = {"refs/heads/main": head}
        policy = {"reproducible_clone": {"allow_hooks": True}}
        with mock.patch.object(cg, "REMOTE_LS", lambda url, repo, timeout: dict(self.live)):
            for name in os.listdir(clone / ".git" / "hooks"):
                if not name.endswith(".sample"):
                    os.unlink(clone / ".git" / "hooks" / name)
            self.assertIsNone(cg.reproducible_clone_refusal(str(clone), policy), "the fixture clone must pass without a hook")
            hook = clone / ".git" / "hooks" / "pre-push"
            hook.write_text("#!/bin/sh\nexit 0\n")
            hook.chmod(0o755)
            self.assertEqual(cg.reproducible_clone_refusal(str(clone), policy), "it has hand-written git hooks")

    # ---- NEG-1, NEG-2
    def test_a_redirected_hooks_path_is_still_refused_by_the_config_rule(self):
        with open(self.primary / ".git" / "config", "a") as handle:
            handle.write("[core]\n\thooksPath = /tmp/elsewhere\n")
        report = self.verify()
        self.assertFalse(report["removable"])
        self.assertIn("core.hookspath", report["reason"])

    def test_the_other_checks_still_decide_for_a_hooked_repository(self):
        (self.linked / "a.txt").write_text("changed\n")
        self.assertIn("not clean", self.verify()["reason"])
        git(self.linked, "checkout", "-q", "--", "a.txt")
        self.assertIn("not a plain file", cg.verify_worktree(str(self.primary))["reason"])
        self.live.pop("refs/heads/linked")
        git(self.linked, "checkout", "-q", "--detach")
        (self.linked / "local.txt").write_text("l\n")
        git(self.linked, "add", "local.txt")
        git(self.linked, "commit", "-q", "-m", "local")
        self.assertIn("not present on a live", self.verify()["reason"])

    # ---- AC-3 and NEG-4
    def git_argvs_of(self, action):
        seen = []
        real = subprocess.run

        def spy(argv, *args, **kwargs):
            if isinstance(argv, (list, tuple)) and argv and argv[0] == "git":
                seen.append(list(argv))
            return real(argv, *args, **kwargs)
        with mock.patch.object(cg.subprocess, "run", spy):
            action()
        return seen

    def test_every_git_process_of_the_delegated_route_carries_hooks_path_dev_null(self):
        def route():
            cg.verify_worktree(str(self.linked), policy=None)
            cg.remove_worktree(str(self.linked), policy=None)
        argvs = self.git_argvs_of(route)
        self.assertGreater(len(argvs), 10)
        for argv in argvs:
            self.assertIn("core.hooksPath=/dev/null", argv, " ".join(argv)[:120])
        self.assertTrue(any("remove" in argv and "worktree" in argv for argv in argvs))

    def test_the_credentialed_ls_remote_and_the_caller_lookup_carry_it_too(self):
        def lookups():
            cg._git_try(str(self.primary), ["rev-parse", "--git-dir"], 5)
            with mock.patch.object(cg.shutil, "which", return_value=None):
                try:
                    cg.authenticated_remote_refs("https://github.com/acme/widgets.git", str(self.primary), 5)
                except ValueError:
                    pass  # no network here: only the command line matters
        argvs = self.git_argvs_of(lookups)
        self.assertTrue(any("ls-remote" in argv for argv in argvs), "ls-remote was not started")
        for argv in argvs:
            self.assertIn("core.hooksPath=/dev/null", argv, " ".join(argv)[:120])


class OtherUsersProcesses(Repo):
    def scan(self, readlinks, owners, listing=("111", "222", "333", "self")):
        """busy_processes on a faked /proc: readlinks {pid: path or errno}, owners {pid: uid or errno}."""
        real_isdir = os.path.isdir

        def link(path):
            pid = path.split("/")[2]
            value = readlinks[pid]
            if isinstance(value, int):
                raise OSError(value, "fake")
            return value

        def owner(path):
            pid = path.split("/")[2]
            value = owners[pid]
            if isinstance(value, int) and value < 0:
                raise OSError(-value, "fake")
            return mock.Mock(st_uid=value)
        with mock.patch.object(cg.os.path, "isdir", lambda p: True if p == "/proc/self" else real_isdir(p)), \
                mock.patch.object(cg.os, "listdir", lambda p: list(listing) if p == "/proc" else []), \
                mock.patch.object(cg.os, "readlink", link), mock.patch.object(cg.os, "stat", owner):
            return cg.busy_processes(str(self.linked))

    def test_an_unreadable_process_of_another_user_is_skipped_but_a_same_user_one_fails_closed(self):
        me, other = os.getuid(), os.getuid() + 1
        self.assertEqual(self.scan({"111": errno.EACCES}, {"111": other}, ["111"]), [])
        self.assertIsNone(self.scan({"111": errno.EACCES}, {"111": me}, ["111"]))
        self.assertIsNone(self.scan({"111": errno.EPERM}, {"111": me}, ["111"]))
        self.assertIsNone(self.scan({"111": errno.EACCES}, {"111": -errno.ENOENT}, ["111"]))  # owner lookup fails
        self.assertIsNone(self.scan({"111": errno.EIO}, {"111": other}, ["111"]))  # any other error
        # an exited process is skipped, as before
        self.assertEqual(self.scan({"111": errno.ENOENT}, {}, ["111"]), [])
        self.assertEqual(self.scan({"111": errno.ESRCH}, {}, ["111"]), [])

    # the real t2-dev scan: same-user daemons (ssh-agent, gpg-agent, tailscaled, systemd, sd-pam, docker) cannot be read
    def scan_names(self, readlinks, owners, names, skip, listing):
        real_isdir = os.path.isdir

        def link(path):
            value = readlinks[path.split("/")[2]]
            if isinstance(value, int):
                raise OSError(value, "fake")
            return value

        def owner(path):
            return mock.Mock(st_uid=owners[path.split("/")[2]])
        with mock.patch.object(cg.os.path, "isdir", lambda p: True if p == "/proc/self" else real_isdir(p)), \
                mock.patch.object(cg.os, "listdir", lambda p: list(listing) if p == "/proc" else []), \
                mock.patch.object(cg.os, "readlink", link), mock.patch.object(cg.os, "stat", owner), \
                mock.patch.object(cg, "_proc_name", lambda pid: names.get(str(pid))):
            return cg.busy_processes(str(self.linked), skip)

    def test_a_same_user_unreadable_process_is_skipped_only_when_its_name_is_in_the_skip_list(self):
        me = os.getuid()
        args = ({"111": errno.EACCES, "222": errno.EACCES}, {"111": me, "222": me}, {"111": "ssh-agent", "222": "bash"})
        self.assertIsNone(self.scan_names(*args, (), ["111", "222"]))  # no list: fail closed as before
        self.assertIsNone(self.scan_names(*args, ("ssh-agent",), ["111", "222"]))  # bash is not a daemon: still closed
        self.assertEqual(self.scan_names({"111": errno.EACCES}, {"111": me}, {"111": "ssh-agent"}, ("ssh-agent",), ["111"]), [])
        # the name must match exactly, a name lookup that fails closes, and a readable busy process still blocks
        self.assertIsNone(self.scan_names({"111": errno.EACCES}, {"111": me}, {"111": "ssh-agent2"}, ("ssh-agent",), ["111"]))
        self.assertIsNone(self.scan_names({"111": errno.EACCES}, {"111": me}, {}, ("ssh-agent",), ["111"]))
        self.assertEqual(self.scan_names({"111": errno.EACCES, "222": str(self.linked) + "/x"}, {"111": me, "222": me},
                                         {"111": "ssh-agent"}, ("ssh-agent",), ["111", "222"]), [(222, "pid")])

    def test_the_delegated_policy_carries_the_standard_daemon_names_and_the_hook_default_has_none(self):
        names = cg.WORKTREE_POLICY["reproducible_clone"]["busy_skip_names"]
        for daemon in ("systemd", "(sd-pam)", "ssh-agent", "gpg-agent", "tailscaled", "docker"):
            self.assertIn(daemon, names)
        for shell in ("bash", "zsh", "sh", "node", "python3", "claude", "git", "vim", "tmux"):
            self.assertNotIn(shell, names)
        self.assertNotIn("busy_skip_names", cg.DEFAULT_POLICY["reproducible_clone"])
        seen = []
        real = cg.busy_processes
        with mock.patch.object(cg, "busy_processes", lambda path, skip=(): seen.append(skip) or real(path, skip)):
            cg.verify_worktree(str(self.linked))
        self.assertEqual(tuple(seen[0]), tuple(names))

    def test_a_readable_process_inside_the_worktree_blocks_whoever_owns_it(self):
        inside = str(self.linked) + "/src"
        self.assertEqual(self.scan({"111": inside, "222": "/elsewhere"}, {"111": os.getuid() + 1, "222": os.getuid()},
                                   ["111", "222"]), [(111, "pid")])
        self.assertEqual(self.scan({"111": str(self.linked)}, {"111": os.getuid()}, ["111"]), [(111, "pid")])

    def test_mixed_processes_unreadable_foreign_ones_do_not_hide_a_readable_busy_one(self):
        other = os.getuid() + 1
        found = self.scan({"111": errno.EACCES, "222": str(self.linked) + "/x", "333": errno.EACCES},
                          {"111": other, "222": os.getuid(), "333": other}, ["111", "222", "333"])
        self.assertEqual(found, [(222, "pid")])

    def test_the_verifier_itself_is_skipped(self):
        self.assertEqual(self.scan({str(os.getpid()): str(self.linked)}, {}, [str(os.getpid())]), [])

    def test_a_real_proc_host_scan_of_a_clean_directory_returns_a_list_not_a_refusal(self):
        if not os.path.isdir("/proc/self"):
            self.skipTest("no /proc on this host: the lsof path is covered by the other suite")
        self.assertEqual(cg.busy_processes(str(self.linked)), [])


if __name__ == "__main__":
    unittest.main()
