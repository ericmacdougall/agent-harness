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

    def test_a_config_defined_hook_is_refused_by_the_config_rule_which_is_what_stops_it(self):
        # git 2.54 reads hook.NAME.event and hook.NAME.command from config and hooksPath does not switch them off, so the
        # [hook] section refusal is the real control (red-team F2)
        with open(self.primary / ".git" / "config", "a") as handle:
            handle.write('[hook "x"]\n\tevent = pre-push\n\tcommand = /bin/true\n')
        report = self.verify()
        self.assertFalse(report["removable"])
        self.assertIn("[hook] section", report["reason"])

    def test_a_plain_removal_does_run_a_hook_which_is_why_the_route_forces_its_safeguards(self):
        # red-team F1/F3: the bare command DOES run post-index-change through the status it starts; the route is safe only
        # because of core.hooksPath=/dev/null and GIT_OPTIONAL_LOCKS=0, and the hook form (a bare command) must stay strict
        done = subprocess.run(["git", "-C", str(self.primary), "worktree", "remove", "--", str(self.linked)],
                              env=dict(GIT_ENV, GIT_OPTIONAL_LOCKS="1"), capture_output=True, text=True,
                              stdin=subprocess.DEVNULL, timeout=60)
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertTrue(self.marker.exists(), "git no longer runs hooks in a plain removal: revisit the strict hook form")
        self.assertIn("GIT_OPTIONAL_LOCKS", cg._clone_env())
        self.assertEqual(cg._clone_env()["GIT_OPTIONAL_LOCKS"], "0")

    # the real t2-dev finding: same-user shells run through sg or sudo cannot be inspected; the refusal must name them
    def test_the_refusal_for_an_uninspectable_same_user_process_names_its_pid_and_name_and_what_to_do(self):
        real_isdir = os.path.isdir
        me = os.getuid()

        def link(path):
            raise OSError(errno.EACCES, "denied")
        with mock.patch.object(cg.os.path, "isdir", lambda p: True if p == "/proc/self" else real_isdir(p)), \
                mock.patch.object(cg.os, "listdir", lambda p: ["4242", "4243"] if p == "/proc" else []), \
                mock.patch.object(cg.os, "readlink", link), \
                mock.patch.object(cg, "_proc_status", lambda pid: {"name": "bash" if pid == "4242" else "sg", "uid": me}):
            report = self.verify()
            scan = cg.busy_scan(str(self.linked))
        self.assertFalse(report["removable"])
        self.assertIn("could not check for processes using the worktree", report["reason"])
        self.assertIn("pid 4242 (bash)", report["reason"])
        self.assertIn("pid 4243 (sg)", report["reason"])
        self.assertIn("end", report["reason"])  # tells the operator to let them finish
        self.assertEqual(sorted(scan["unreadable"]), [(4242, "bash"), (4243, "sg")])
        self.assertEqual(scan["busy"], [])
        self.assertFalse(scan["failed"])
        many = [str(1000 + i) for i in range(12)]
        with mock.patch.object(cg.os.path, "isdir", lambda p: True if p == "/proc/self" else real_isdir(p)), \
                mock.patch.object(cg.os, "listdir", lambda p: many if p == "/proc" else []), \
                mock.patch.object(cg.os, "readlink", link), \
                mock.patch.object(cg, "_proc_status", lambda pid: {"name": "bash", "uid": me}):
            reason = self.verify()["reason"]
        self.assertLess(len(reason), 400)  # bounded: only the first few are named
        self.assertIn("and 9 more", reason)

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

        def status(pid):
            value = owners[str(pid)]
            if isinstance(value, int) and value < 0:
                return "gone" if -value in (errno.ENOENT, errno.ESRCH) else None
            return {"name": "x", "uid": value}
        with mock.patch.object(cg.os.path, "isdir", lambda p: True if p == "/proc/self" else real_isdir(p)), \
                mock.patch.object(cg.os, "listdir", lambda p: list(listing) if p == "/proc" else []), \
                mock.patch.object(cg.os, "readlink", link), mock.patch.object(cg, "_proc_status", status):
            return cg.busy_processes(str(self.linked))

    def test_an_unreadable_process_of_another_user_is_skipped_but_a_same_user_one_fails_closed(self):
        me, other = os.getuid(), os.getuid() + 1
        self.assertEqual(self.scan({"111": errno.EACCES}, {"111": other}, ["111"]), [])
        self.assertIsNone(self.scan({"111": errno.EACCES}, {"111": me}, ["111"]))
        self.assertIsNone(self.scan({"111": errno.EPERM}, {"111": me}, ["111"]))
        self.assertEqual(self.scan({"111": errno.EACCES}, {"111": -errno.ENOENT}, ["111"]), [])  # exited between the two reads
        self.assertIsNone(self.scan({"111": errno.EACCES}, {"111": -errno.EIO}, ["111"]))  # an owner lookup that fails otherwise
        self.assertIsNone(self.scan({"111": errno.EIO}, {"111": other}, ["111"]))  # any other error
        # an exited process is skipped, as before
        self.assertEqual(self.scan({"111": errno.ENOENT}, {}, ["111"]), [])
        self.assertEqual(self.scan({"111": errno.ESRCH}, {}, ["111"]), [])

    # the real t2-dev scan: same-user daemons (ssh-agent, gpg-agent, tailscaled, systemd, sd-pam, docker) cannot be read
    def scan_names(self, readlinks, owners, names, skip, listing, cmds=None, ppids=None):
        real_isdir = os.path.isdir

        def link(path):
            value = readlinks[path.split("/")[2]]
            if isinstance(value, int):
                raise OSError(value, "fake")
            return value

        def status(pid):
            if str(pid) not in owners:
                return "gone"
            return {"name": names.get(str(pid)), "uid": owners[str(pid)], "ppid": (ppids or {}).get(str(pid), 1)}

        def cmd0(pid):
            return (cmds or {}).get(str(pid), names.get(str(pid)))
        with mock.patch.object(cg.os.path, "isdir", lambda p: True if p == "/proc/self" else real_isdir(p)), \
                mock.patch.object(cg.os, "listdir", lambda p: list(listing) if p == "/proc" else []), \
                mock.patch.object(cg.os, "readlink", link), mock.patch.object(cg, "_proc_status", status), \
                mock.patch.object(cg, "_proc_cmd0", cmd0, create=True):
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

    # receipt r1 on PR 214, F1: the docker CLIENT is a user workload, never a service
    def test_an_unreadable_same_user_docker_process_refuses_even_with_the_delegated_list(self):
        me = os.getuid()
        names = cg.WORKTREE_POLICY["reproducible_clone"]["busy_skip_names"]
        for name in ("docker", "docker-compose", "docker-buildx", "dockerd", "sg", "bash", "tailscaled", "gpg-agent", "(sd-pam)"):
            with self.subTest(name=name):
                self.assertIsNone(self.scan_names({"111": errno.EACCES}, {"111": me}, {"111": name}, names, ["111"]))
        # the two listed programs are skipped only when their command line agrees with the name
        for name in names:
            self.assertEqual(self.scan_names({"111": errno.EACCES}, {"111": me}, {"111": name}, names, ["111"]), [])

    # receipt r1 on PR 214, F3: comm can be set by the process, so the command line must agree too (a limit, not a proof)
    def test_a_listed_name_is_skipped_only_when_the_command_line_agrees_and_the_limit_is_documented(self):
        me = os.getuid()
        names = cg.WORKTREE_POLICY["reproducible_clone"]["busy_skip_names"]
        spoofed = self.scan_names({"111": errno.EACCES}, {"111": me}, {"111": "systemd"}, names, ["111"], cmds={"111": "bash"})
        self.assertIsNone(spoofed)
        unreadable_cmdline = self.scan_names({"111": errno.EACCES}, {"111": me}, {"111": "ssh-agent"}, names, ["111"],
                                             cmds={"111": None})
        self.assertIsNone(unreadable_cmdline)
        honest = self.scan_names({"111": errno.EACCES}, {"111": me}, {"111": "ssh-agent"}, names, ["111"], cmds={"111": "ssh-agent"})
        self.assertEqual(honest, [])
        source = (Path(cg.__file__)).read_text()
        self.assertIn("comm can be set by the process", source)  # the standing limit is written where the skip is decided

    def test_the_command_line_reader_returns_the_basename_of_argv_zero(self):
        import io

        def fake_open(path, mode="r", *args, **kwargs):
            self.assertEqual(path, "/proc/4242/cmdline")
            return io.BytesIO(b"/usr/bin/ssh-agent\x00-s\x00")
        with mock.patch.object(cg, "open", fake_open, create=True):
            self.assertEqual(cg._proc_cmd0("4242"), "ssh-agent")

        def empty(path, mode="r", *args, **kwargs):
            return io.BytesIO(b"")

        def broken(path, mode="r", *args, **kwargs):
            raise OSError(errno.EACCES, "denied")
        with mock.patch.object(cg, "open", empty, create=True):
            self.assertIsNone(cg._proc_cmd0("4242"))
        with mock.patch.object(cg, "open", broken, create=True):
            self.assertIsNone(cg._proc_cmd0("4242"))

    # receipt r1 on PR 214, F2: a root shell started from the callers own shell (sudo -s, sudo -i) is not another user's
    def test_an_unreadable_root_process_whose_parent_is_the_caller_refuses_but_a_boot_time_root_daemon_is_skipped(self):
        me = os.getuid()
        names = cg.WORKTREE_POLICY["reproducible_clone"]["busy_skip_names"]
        sudo_shell = self.scan_names({"500": errno.EACCES}, {"500": 0, "400": me}, {"500": "bash", "400": "sudo"}, names,
                                     ["500"], ppids={"500": 400})
        self.assertIsNone(sudo_shell)  # real uid 0, parent is the callers sudo: refused and named
        daemon = self.scan_names({"500": errno.EACCES}, {"500": 0, "1": 0}, {"500": "sshd", "1": "systemd"}, names, ["500"],
                                 ppids={"500": 1})
        self.assertEqual(daemon, [])
        kernel = self.scan_names({"500": errno.EACCES}, {"500": 0}, {"500": "kworker"}, names, ["500"], ppids={"500": 2})
        self.assertEqual(kernel, [])
        # a parent that cannot be read is not a reason to skip a root process: fail closed
        unknown_parent = self.scan_names({"500": errno.EACCES}, {"500": 0}, {"500": "bash"}, names, ["500"],
                                         ppids={"500": 400})
        self.assertIsNone(unknown_parent)
        other_user = self.scan_names({"500": errno.EACCES}, {"500": me + 1}, {"500": "bash"}, names, ["500"])
        self.assertEqual(other_user, [])  # another non-root user stays skipped

    def test_the_delegated_policy_carries_the_standard_daemon_names_and_the_hook_default_has_none(self):
        names = cg.WORKTREE_POLICY["reproducible_clone"]["busy_skip_names"]
        # only programs that are known to chdir to / at start (the user systemd manager and ssh-agent); the rest of the
        # first draft (docker, gpg-agent, tailscaled, (sd-pam)) had no such evidence: the docker CLIENT is a user workload
        # started inside project directories (receipt r1 on PR 214, F1)
        self.assertEqual(tuple(names), ("systemd", "ssh-agent"))
        for not_a_service in ("docker", "docker-compose", "dockerd", "gpg-agent", "tailscaled", "(sd-pam)", "bash", "zsh",
                              "sh", "node", "python3", "claude", "git", "vim", "tmux", "sg", "sudo"):
            self.assertNotIn(not_a_service, names)
        self.assertNotIn("busy_skip_names", cg.DEFAULT_POLICY["reproducible_clone"])
        seen = []
        real = cg.busy_scan
        with mock.patch.object(cg, "busy_scan", lambda path, skip=(): seen.append(skip) or real(path, skip)):
            cg.verify_worktree(str(self.linked))
        self.assertEqual(tuple(seen[0]), tuple(names))

    def test_the_status_reader_reads_the_world_readable_status_file_and_takes_the_real_uid(self):
        opened = []

        def fake_open(path, *args, **kwargs):
            opened.append(path)
            import io
            return io.StringIO("Name:\tssh-agent\nUmask:\t0022\nPPid:\t77\nUid:\t1000\t0\t0\t0\nGid:\t1000\t1000\t1000\t1000\n")
        with mock.patch.object(cg, "open", fake_open, create=True):
            self.assertEqual(cg._proc_status("4242"), {"name": "ssh-agent", "uid": 1000, "ppid": 77})
        self.assertEqual(opened, ["/proc/4242/status"])  # never /proc/PID/cwd, whose stat would follow the link and fail

        def gone(path, *args, **kwargs):
            raise FileNotFoundError(errno.ENOENT, "gone")

        def broken(path, *args, **kwargs):
            raise OSError(errno.EIO, "io")
        with mock.patch.object(cg, "open", gone, create=True):
            self.assertEqual(cg._proc_status("4242"), "gone")
        with mock.patch.object(cg, "open", broken, create=True):
            self.assertIsNone(cg._proc_status("4242"))

        def junk(path, *args, **kwargs):
            import io
            return io.StringIO("Name:\tx\nUid:\tnot-a-number\n")
        with mock.patch.object(cg, "open", junk, create=True):
            self.assertIsNone(cg._proc_status("4242"))

    def test_a_process_that_made_itself_non_inspectable_is_still_seen_as_the_callers_by_its_real_uid(self):
        # a same-user process that is not dumpable shows /proc/PID owned by root, but its real uid in status is the callers
        me = os.getuid()
        self.assertIsNone(self.scan({"111": errno.EACCES}, {"111": me}, ["111"]))

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
