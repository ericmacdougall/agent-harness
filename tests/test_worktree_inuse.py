"""goodqa#15870: `command_guard.py remove-worktree` could never succeed on t2-dev. It refused every worktree because of
unreadable same-user processes (systemd sd-pam helpers, tailscaled session helpers, the docker client started through
`sg docker` for the pgpool server) that never exit. "In use" is now judged from the worktree side: a process whose cwd is
readable and inside the worktree still blocks, an unreadable process blocks only when something ties it to the worktree
(its command line names it, it is a shell, interpreter, editor or wrapper, or a client workload started after the worktree
was created), and every other unreadable process is skipped and REPORTED. The refusal for ignored files lists them."""
import errno
import os
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_ah_worktree_remove import Repo, git  # noqa: E402

import command_guard as cg  # noqa: E402

ME = os.getuid()
REAL_SCAN = cg.busy_scan
# the real t2-dev unreadable set (read-only ps on 2026-11-13), with the command lines that matter
T2_DEV = {
    "2033": ("sg", "/usr/bin/sg docker -c exec /usr/bin/python3 /home/eric/repos/tools/pgpool.py serve"),
    "1738": ("(sd-pam)", "(sd-pam)"),
    "1988": ("(sd-pam)", "(sd-pam)"),
    "2060": ("docker", "docker run --rm --init --name testpg-pool --label pgpool.tool=testpg-pool --env-file "
                       "/home/eric/.local/state/pgpool/server.env -p 127.0.0.1:5543:5432 pgvector/pgvector:pg16"),
    "117050": ("tailscaled", "/usr/sbin/tailscaled be-child ssh --login-shell=/bin/bash --uid=1000 --gid=1000"),
    "3090": ("gpg-agent", "/usr/bin/gpg-agent --supervised"),
    "2204680": ("chrome", ""),
}


class FakeProc:
    """A fake /proc for busy_scan: cwd links, same-user status, command lines and start times."""

    def __init__(self, test, procs):
        self.test, self.procs = test, procs  # pid -> dict(link=path or errno, name, args, start, ppid)
        self.scanner_pid = 999999  # not a listed process, so it needs no entry of its own
        self.procs.setdefault("999999", {"link": "/tmp", "name": "python3", "args": "python3 command_guard.py", "start": 1.0,
                                         "ppid": 1})

    def scan(self, created=None, skip=()):
        real_isdir = os.path.isdir

        def link(path):
            value = self.procs[path.split("/")[2]]["link"]
            if isinstance(value, int):
                raise OSError(value, "fake")
            return value

        def status(pid):
            proc = self.procs[str(pid)]
            return {"name": proc["name"], "uid": ME, "ppid": proc.get("ppid", 1)}
        with mock.patch.object(cg.os.path, "isdir", lambda p: True if p == "/proc/self" else real_isdir(p)), \
                mock.patch.object(cg.os, "getpid", lambda: self.scanner_pid), \
                mock.patch.object(cg.os, "listdir", lambda p: list(self.procs) if p == "/proc" else []), \
                mock.patch.object(cg.os, "readlink", link), mock.patch.object(cg, "_proc_status", status), \
                mock.patch.object(cg, "_proc_args", lambda pid: self.procs[str(pid)].get("args"), create=True), \
                mock.patch.object(cg, "_proc_start", lambda pid: self.procs[str(pid)].get("start"), create=True), \
                mock.patch.object(cg, "_proc_cmd0", lambda pid: self.procs[str(pid)]["name"], create=True):
            return REAL_SCAN(str(self.test.linked), skip, created)


def unreadable(name, args, start=None):
    return {"link": errno.EACCES, "name": name, "args": args, "start": start}


class Inuse(Repo):
    def t2_dev(self, **extra):
        procs = {pid: unreadable(name, args, start=100.0) for pid, (name, args) in T2_DEV.items()}
        procs.update(extra)
        return FakeProc(self, procs)

    # AC-1: the real t2-dev helpers no longer block, and they are reported
    def test_the_t2_dev_sd_pam_sg_docker_and_session_helpers_do_not_block_and_are_reported(self):
        scan = self.t2_dev().scan(created=200.0)
        self.assertEqual(scan["busy"], [])
        self.assertEqual(scan["unreadable"], [])
        self.assertFalse(scan["failed"])
        self.assertEqual(sorted(pid for pid, _name in scan["skipped"]), sorted(int(p) for p in T2_DEV))
        self.assertIn((2060, "docker"), scan["skipped"])  # the pgpool client started before the worktree existed

    def test_the_whole_verifier_removes_a_clean_worktree_while_those_helpers_run_and_names_them(self):
        proc = self.t2_dev()
        report_scan = proc.scan(created=cg._worktree_created(str(self.linked)) or 200.0)
        self.assertEqual(report_scan["unreadable"], [])
        with mock.patch.object(cg, "busy_scan", lambda path, skip=(), created=None: proc.scan(created=created, skip=skip)):
            report = cg.verify_worktree(str(self.linked))
        self.assertTrue(report["removable"], report)
        self.assertIn("pid 2060 (docker)", report["skipped_processes"])
        self.assertIn("pid 1738 ((sd-pam))", report["skipped_processes"])

    # AC-2 (negative): a process whose cwd is inside the worktree still blocks
    def test_a_process_with_its_cwd_inside_the_worktree_still_blocks_whatever_else_is_skipped(self):
        procs = self.t2_dev(**{"777": {"link": str(self.linked) + "/src", "name": "node", "args": "node x.js", "start": 100.0}})
        scan = procs.scan(created=200.0)
        self.assertEqual(scan["busy"], [(777, "pid")])
        with mock.patch.object(cg, "busy_scan", lambda path, skip=(), created=None: procs.scan(created=created, skip=skip)):
            report = cg.verify_worktree(str(self.linked))
        self.assertFalse(report["removable"])
        self.assertIn("pid 777", report["reason"])

    # AC-3 (negative): an unreadable process tied to the worktree still blocks
    def test_an_unreadable_process_that_names_the_worktree_still_blocks(self):
        scan = self.t2_dev(**{"778": unreadable("docker", "docker compose -f %s/compose.yml up" % self.linked, 100.0)}).scan(created=200.0)
        self.assertEqual(scan["unreadable"], [(778, "docker")])

    def test_an_unreadable_shell_editor_or_interpreter_still_blocks_even_when_it_started_before_the_worktree(self):
        for name in ("bash", "python3", "vim", "git", "make", "node", "tmux"):
            with self.subTest(name=name):
                scan = self.t2_dev(**{"779": unreadable(name, name, 1.0)}).scan(created=200.0)
                self.assertEqual(scan["unreadable"], [(779, name)])

    def test_an_unreadable_docker_client_started_after_the_worktree_still_blocks(self):
        scan = self.t2_dev(**{"780": unreadable("docker", "docker run --rm busybox", 300.0)}).scan(created=200.0)
        self.assertEqual(scan["unreadable"], [(780, "docker")])

    # review H1: the real tree is sg (the long-lived pgpool wrapper) -> docker; sg must not block every worktree
    def test_the_real_sg_parent_of_the_pgpool_client_is_skipped_when_it_started_before_the_worktree(self):
        scan = self.t2_dev().scan(created=200.0)
        self.assertIn((2033, "sg"), scan["skipped"])
        self.assertEqual(scan["unreadable"], [])

    def test_an_sg_wrapper_started_after_the_worktree_blocks(self):
        scan = self.t2_dev(**{"784": unreadable("sg", "/usr/bin/sg docker -c exec /usr/bin/python3 run.py", 300.0)}).scan(created=200.0)
        self.assertEqual(scan["unreadable"], [(784, "sg")])

    # review H1: any other unreadable program is judged by time, not skipped by name
    def test_an_unreadable_agent_cli_test_runner_or_compiler_started_after_the_worktree_blocks_before_it_is_skipped(self):
        for name in ("claude", "pytest", "python3.12", "rg", "cc1", "vite", "headless_shell", "codex"):
            with self.subTest(name=name):
                after = self.t2_dev(**{"785": unreadable(name, name + " --watch", 300.0)}).scan(created=200.0)
                self.assertEqual(after["unreadable"], [(785, name)])
                before = self.t2_dev(**{"785": unreadable(name, name + " --watch", 100.0)}).scan(created=200.0)
                self.assertEqual(before["unreadable"], [])
                self.assertIn((785, name), before["skipped"])

    def test_the_known_helpers_are_skipped_whatever_their_start_time(self):
        scan = self.t2_dev().scan(created=50.0)  # every fixture process started AFTER this worktree was created
        skipped = {name for _pid, name in scan["skipped"]}
        self.assertEqual({"(sd-pam)", "tailscaled", "gpg-agent", "docker"} - skipped, set())
        # but the name must agree with the command line: a docker client without the pgpool label is a workload
        self.assertIn((2033, "sg"), scan["unreadable"])  # a wrapper has no such exemption
        other = self.t2_dev(**{"786": unreadable("docker", "docker run --rm busybox", 100.0)}).scan(created=50.0)
        self.assertIn((786, "docker"), other["unreadable"])
        spoof = self.t2_dev(**{"787": unreadable("tailscaled", "tailscaled serve", 100.0)}).scan(created=50.0)
        self.assertIn((787, "tailscaled"), spoof["unreadable"])

    # review H2: the scanner's own unreadable ancestors (an ssh login's tailscaled be-child carries the command) never block
    def test_the_scanners_own_ancestor_chain_is_not_a_reason_to_refuse(self):
        fake = self.t2_dev(**{"5000": unreadable("tailscaled", "/usr/sbin/tailscaled be-child ssh --cmd=remove-worktree %s" % self.linked, 300.0),
                              "5001": unreadable("sshd", "sshd: eric", 300.0)})
        fake.procs["5000"]["ppid"] = 5001
        fake.procs["999999"]["ppid"] = 5000
        fake.procs["5001"]["ppid"] = 1
        scan = fake.scan(created=200.0)
        self.assertEqual(scan["unreadable"], [])
        self.assertIn((5000, "tailscaled"), scan["skipped"])
        self.assertIn((5001, "sshd"), scan["skipped"])
        # a NON-ancestor process whose command line names the worktree still blocks
        stranger = self.t2_dev(**{"6000": unreadable("tailscaled", "tailscaled be-child ssh --cmd=%s" % self.linked, 300.0)}).scan(created=200.0)
        self.assertIn((6000, "tailscaled"), stranger["unreadable"])

    def test_unknown_times_or_an_unreadable_command_line_fail_closed(self):
        self.assertEqual(self.t2_dev(**{"781": unreadable("docker", "docker ps", None)}).scan(created=200.0)["unreadable"], [(781, "docker")])
        self.assertIn((782, "docker"), self.t2_dev(**{"782": unreadable("docker", "docker ps", 100.0)}).scan(created=None)["unreadable"])
        self.assertEqual(self.t2_dev(**{"783": unreadable("tailscaled", None, 100.0)}).scan(created=200.0)["unreadable"], [(783, "tailscaled")])

    # the readers of /proc and the worktree creation time
    def test_the_worktree_creation_time_is_the_time_of_its_git_file(self):
        created = cg._worktree_created(str(self.linked))
        self.assertAlmostEqual(created, os.lstat(os.path.join(str(self.linked), ".git")).st_mtime, places=3)
        self.assertIsNone(cg._worktree_created(str(self.linked) + "-missing"))

    def test_the_real_proc_readers_return_this_process_command_line_and_start_time(self):
        if not os.path.isdir("/proc/self"):
            self.skipTest("no /proc on this host")
        args = cg._proc_args(os.getpid())
        self.assertIsInstance(args, str)
        self.assertIn("python", args.lower())
        start = cg._proc_start(os.getpid())
        self.assertIsNotNone(start)
        self.assertLess(start, __import__("time").time() + 1)
        self.assertIsNone(cg._proc_args("99999999"))

    # AC-4: the ignored-files refusal lists the offending paths
    def test_the_ignored_file_refusal_lists_the_offending_paths(self):
        (self.linked / ".gitignore").write_text("*.secret\nkeep.log\nbuild-notes/\n")
        git(self.linked, "add", ".gitignore")
        git(self.linked, "commit", "-q", "-m", "ignore rules")
        (self.linked / "a.secret").write_text("x")
        (self.linked / "keep.log").write_text("x")
        report = cg.verify_worktree(str(self.linked))
        self.assertFalse(report["removable"])
        self.assertIn("not a whole regenerable build directory", report["reason"])
        self.assertIn("a.secret", report["reason"])
        self.assertIn("keep.log", report["reason"])

    def test_the_listing_is_bounded_and_printable(self):
        names = ["f%d.secret" % i for i in range(9)] + ["badéname"]
        text = cg._ignored_refusal(names)
        self.assertIn("(and 5 more)", text)
        self.assertLess(len(text), 400)
        self.assertTrue(text.isascii())


if __name__ == "__main__":
    unittest.main()
