"""ah kill (harness/hooks/ah_kill.py) and its kill_guard allow rule: refusals, pid reuse, audit rows, grace, tree."""
import json
import re
import shutil
import os
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

HOOKS = Path(__file__).resolve().parents[1] / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
import ah_kill as ak  # noqa: E402
import kill_guard as kg  # noqa: E402

ME = os.getuid()
OWN = 5000


def proc(pid, ppid=100, uid=ME, cmd="/usr/bin/sleep 300", comm=None, start="Thu Nov  5 17:00:00 2026", stat_="S"):
    return {"pid": pid, "ppid": ppid, "uid": uid, "stat": stat_, "start": start, "command": cmd,
            "comm": comm if comm is not None else cmd.split(" ")[0]}


class FakeProbe:
    def __init__(self, procs, ignore_term=(), on_info=None):
        self.procs = {p["pid"]: dict(p) for p in procs}
        self.ignore_term = set(ignore_term)
        self.sent = []
        self.on_info = on_info

    def info(self, pid):
        if self.on_info:
            self.on_info(self, pid)
        p = self.procs.get(pid)
        return dict(p) if p else None

    def user(self, uid):
        return "u%d" % uid

    cwds = {}

    def cwd(self, pid):
        return self.cwds.get(pid, "/work/%d" % pid)

    def git_top(self, path):
        if path and path.startswith("/work/nested"):
            return "/work/nested"  # a linked worktree inside the caller's checkout
        if path and path.startswith("/work"):
            return "/work"
        return "/elsewhere" if path and path.startswith("/elsewhere") else None

    def session_env(self, pid):
        return "owner-sess-%d" % pid

    def table(self):
        return {pid: p["ppid"] for pid, p in self.procs.items()}

    def signal(self, pid, sig):
        self.sent.append((pid, sig))
        if sig == signal.SIGKILL or pid not in self.ignore_term:
            self.procs.pop(pid, None)


class Clock:
    def __init__(self):
        self.t = 0.0

    def now(self):
        return self.t

    def sleep(self, s):
        self.t += s


class KillBase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name)
        self.clock = Clock()
        self.notices = []
        os.environ.pop("CLAUDE_PID", None)

    def run_kill(self, probe, pids, reason="runaway test", **kw):
        kw.setdefault("grace", 5)
        kw.setdefault("worktree", "/work")
        kw.setdefault("notify", lambda home, event: self.notices.append(event))
        return ak.kill_local(pids, reason, home=self.home, probe=probe, sleep=self.clock.sleep, clock=self.clock.now,
                             session="sess-1", agent="agent-x", own_pid=OWN, **kw)

    def audit(self):
        path = self.home / ".agent-harness" / "kill-audit.jsonl"
        return [json.loads(line) for line in path.read_text().splitlines()]

    def base(self, *extra):
        # OWN's chain: OWN -> 4000 (shell) -> 3000 (claude) -> 1
        return FakeProbe([proc(OWN, 4000, cmd="python3 ah.py"), proc(4000, 3000, cmd="-zsh", comm="-zsh"),
                          proc(3000, 1, cmd="claude", comm="claude"), *extra])


class Refusals(KillBase):
    def refused(self, p, reason_part=None):
        probe = self.base(p)
        out = self.run_kill(probe, [p["pid"]])
        self.assertEqual(out["results"][0]["status"], "refused", out)
        self.assertEqual(probe.sent, [], "a refused pid must never be signalled")
        self.assertFalse(out["ok"])
        if reason_part:
            self.assertIn(reason_part, out["results"][0]["detail"])

    def test_pid_1(self):
        self.refused(proc(1, 0, uid=0, cmd="/sbin/launchd", comm="/sbin/launchd"))

    def test_root_owned(self):
        self.refused(proc(200, 1, uid=0, cmd="/usr/bin/foo"), "root")

    def test_other_user(self):
        self.refused(proc(201, 100, uid=ME + 1), "another user")

    def test_system_paths(self):
        self.refused(proc(202, 1, cmd="/System/Library/CoreServices/x"), "system")
        self.refused(proc(203, 1, cmd="/usr/libexec/trustd"), "system")

    def test_callers_own_process_and_ancestors(self):
        for pid in (OWN, 4000, 3000):
            probe = self.base()
            out = self.run_kill(probe, [pid])
            self.assertEqual(out["results"][0]["status"], "refused", pid)
            self.assertEqual(probe.sent, [])

    def test_main_session_process(self):
        os.environ["CLAUDE_PID"] = "777"
        self.addCleanup(os.environ.pop, "CLAUDE_PID", None)
        self.refused(proc(777, 1, cmd="node server.js"), "main session")

    def test_gui_apps_and_daemons(self):
        apps = ["/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
                "/Applications/Google Chrome.app/Contents/Frameworks/X/Helpers/Google Chrome Helper (Renderer).app/Contents/MacOS/Google Chrome Helper (Renderer) --type=renderer",
                "/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal",
                "/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal",
                "/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder",
                "/Applications/GoodQA.app/Contents/MacOS/GoodQA",
                "/Applications/Tailscale.app/Contents/MacOS/Tailscale",
                "/Applications/Dropbox.app/Contents/MacOS/Dropbox",
                "/Applications/Solve.app/Contents/MacOS/Solve",
                "/usr/sbin/sshd -D", "/sbin/launchd"]
        for n, cmd in enumerate(apps):
            with self.subTest(cmd=cmd):
                self.refused(proc(300 + n, 1, cmd=cmd))

    def test_chrome_for_testing_is_not_the_users_chrome(self):
        p = proc(400, 100, cmd="/x/Google Chrome for Testing.app/Contents/MacOS/Google Chrome for Testing --headless")
        probe = self.base(p)
        out = self.run_kill(probe, [400])
        self.assertEqual(out["results"][0]["status"], "exited", out)

    def test_empty_reason_is_refused_before_anything_happens(self):
        probe = self.base(proc(500))
        for reason in ("", "   ", None):
            with self.assertRaises(ak.KillError) as cm:
                self.run_kill(probe, [500], reason=reason)
            self.assertEqual(cm.exception.code, "reason_required")
        self.assertEqual(probe.sent, [])
        self.assertFalse((self.home / ".agent-harness" / "kill-audit.jsonl").exists())

    def test_bad_pid_lists(self):
        for bad in ("", "abc", "1,,2", "-5", "1;2", "99999999999"):
            with self.assertRaises(ak.KillError):
                ak.parse_pids(bad)


class Signalling(KillBase):
    def test_term_then_exit(self):
        probe = self.base(proc(600))
        out = self.run_kill(probe, [600])
        self.assertEqual(probe.sent, [(600, signal.SIGTERM)])
        self.assertEqual(out["results"][0]["status"], "exited")
        self.assertTrue(out["ok"])

    def test_gone_already(self):
        out = self.run_kill(self.base(), [601])
        self.assertEqual(out["results"][0]["status"], "gone")
        self.assertTrue(out["ok"])

    def test_grace_then_sigkill(self):
        probe = self.base(proc(602))
        probe.ignore_term.add(602)
        out = self.run_kill(probe, [602], grace=3)
        self.assertEqual(probe.sent, [(602, signal.SIGTERM), (602, signal.SIGKILL)])
        self.assertEqual(out["results"][0]["status"], "killed")
        self.assertGreaterEqual(self.clock.t, 3, "SIGKILL must wait out the grace period")
        events = [r["event"] for r in self.audit()]
        self.assertEqual(events, ["intent", "signal", "signal", "result"])

    def test_survivor_is_reported(self):
        probe = self.base(proc(603))
        probe.ignore_term.add(603)
        probe.signal = lambda pid, sig: probe.sent.append((pid, sig))  # even SIGKILL does nothing
        out = self.run_kill(probe, [603], grace=1)
        self.assertEqual(out["results"][0]["status"], "survived")
        self.assertFalse(out["ok"])

    def test_pid_reuse_between_audit_and_signal(self):
        probe = self.base(proc(604))

        def swap(pr, pid):  # after the first look (snapshot), the pid is reused by a different process
            if pid == 604 and getattr(pr, "looks", 0) >= 1:
                pr.procs[604] = proc(604, 100, cmd="/usr/bin/vim notes.txt", start="Thu Nov  5 17:09:00 2026")
            pr.looks = getattr(pr, "looks", 0) + (1 if pid == 604 else 0)
        probe.on_info = swap
        out = self.run_kill(probe, [604])
        self.assertEqual(probe.sent, [], "the reused pid must not be signalled")
        self.assertEqual(out["results"][0]["status"], "changed")

    def test_pid_reuse_between_term_and_kill(self):
        probe = self.base(proc(605))
        probe.ignore_term.add(605)
        state = {"termed": False}
        orig = probe.signal

        def sig(pid, s):
            orig(pid, s)
            state["termed"] = True
        probe.signal = sig

        def swap(pr, pid):
            if state["termed"] and pid == 605:
                pr.procs[605] = proc(605, 100, cmd="/usr/bin/vim", start="Thu Nov  5 17:09:00 2026")
        probe.on_info = swap
        out = self.run_kill(probe, [605], grace=1)
        self.assertEqual(probe.sent, [(605, signal.SIGTERM)], "no SIGKILL for a reused pid")
        self.assertNotEqual(out["results"][0]["status"], "killed")

    def test_tree_children_first_and_only_in_tree(self):
        probe = self.base(proc(700, 100), proc(701, 700), proc(702, 701), proc(703, 700), proc(704, 100))
        out = self.run_kill(probe, [700], tree=True)
        order = [pid for pid, _ in probe.sent]
        self.assertEqual(order[-1], 700)
        self.assertEqual(set(order), {700, 701, 702, 703})
        self.assertLess(order.index(702), order.index(701))
        self.assertNotIn(704, order)
        self.assertTrue(out["ok"])

    def test_tree_does_not_reach_a_protected_child_and_refused_root_spares_children(self):
        probe = self.base(proc(710, 100), proc(711, 710, cmd="/Applications/Dropbox.app/Contents/MacOS/Dropbox"),
                          proc(712, 710))
        out = self.run_kill(probe, [710], tree=True)
        self.assertNotIn(711, [p for p, _ in probe.sent])
        self.assertIn(712, [p for p, _ in probe.sent])
        self.assertFalse(out["ok"])
        probe2 = self.base(proc(720, 1, uid=0, cmd="/usr/bin/daemon"), proc(721, 720))
        self.run_kill(probe2, [720], tree=True)
        self.assertEqual(probe2.sent, [], "children of a refused root are not a way around the refusal")

    def test_without_tree_children_are_untouched(self):
        probe = self.base(proc(730, 100), proc(731, 730))
        self.run_kill(probe, [730])
        self.assertEqual([p for p, _ in probe.sent], [730])


class AuditLog(KillBase):
    def test_rows_have_the_required_fields_and_mode(self):
        probe = self.base(proc(800, 4001, cmd="node server.js --api-key=sk-live-ABCDEF123456SECRETVALUE " + "x" * 600))
        self.run_kill(probe, [800], reason="eats 40 GB")
        path = self.home / ".agent-harness" / "kill-audit.jsonl"
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        rows = self.audit()
        intent = rows[0]
        self.assertEqual(intent["event"], "intent")
        for k in ("pid", "cmd", "cwd", "user", "start", "ppid", "reason", "at", "caller", "run", "id"):
            self.assertIn(k, intent)
        self.assertEqual(intent["cwd"], "/work/800")
        self.assertEqual(intent["ppid"], 4001)
        self.assertEqual(intent["reason"], "eats 40 GB")
        self.assertEqual(intent["caller"]["session"], "sess-1")
        self.assertEqual(intent["caller"]["agent"], "agent-x")
        self.assertNotIn("SECRETVALUE", json.dumps(rows))
        self.assertLessEqual(len(intent["cmd"]), ak.MAX_CMD + 20)
        self.assertEqual(rows[-1]["event"], "result")
        self.assertEqual(rows[-1]["status"], "exited")
        self.assertLess([r["event"] for r in rows].index("intent"), [r["event"] for r in rows].index("signal"))

    def test_refusals_are_logged_too(self):
        self.run_kill(self.base(proc(801, 1, uid=0)), [801])
        events = [(r["event"], r.get("status")) for r in self.audit()]
        self.assertIn(("refused", "refused"), events)
        self.assertIn(("result", "refused"), events)

    def test_append_only(self):
        self.run_kill(self.base(proc(802)), [802])
        n = len(self.audit())
        self.run_kill(self.base(proc(803)), [803])
        self.assertGreater(len(self.audit()), n)

    def test_audit_failure_fails_closed(self):
        (self.home / ".agent-harness").write_text("a file where the directory should be")
        probe = self.base(proc(804))
        with self.assertRaises(OSError):
            self.run_kill(probe, [804])
        self.assertEqual(probe.sent, [], "no audit row, no signal")

    def test_wal_gets_the_intent_and_result(self):
        wal_dir = self.home / ".claude" / "wals" / "sess-1"
        old = os.environ.get("HOME")
        os.environ["HOME"] = str(self.home)
        self.addCleanup(lambda: os.environ.__setitem__("HOME", old))
        out = self.run_kill(self.base(proc(805)), [805])
        notes = [json.loads(line)["note"] for line in (wal_dir / "main.jsonl").read_text().splitlines()]
        self.assertTrue(any("reason=runaway test" in n for n in notes), notes)
        self.assertTrue(any("805=exited" in n for n in notes), notes)
        self.assertTrue(out["wal"])


class RealProcesses(unittest.TestCase):
    def run_ah(self, home, *args):
        env = dict(os.environ, HOME=str(home), CLAUDE_CODE_SESSION_ID="real-sess")
        env.pop("CLAUDE_PID", None)
        r = subprocess.run([sys.executable, str(HOOKS / "ah.py"), "kill", *args], capture_output=True, text=True,
                           env=env, timeout=60)
        return r.returncode, json.loads(r.stdout)

    def test_sleep_is_stopped_and_audited(self):
        with tempfile.TemporaryDirectory() as home:
            p = subprocess.Popen(["sleep", "300"])
            try:
                code, out = self.run_ah(home, "--pid", str(p.pid), "--reason", "live test sleep", "--grace", "2")
                self.assertEqual(code, 0, out)
                self.assertEqual(out["results"][0]["status"], "exited")
                self.assertIsNotNone(p.wait(timeout=5))
                rows = [json.loads(x) for x in (Path(home) / ".agent-harness" / "kill-audit.jsonl").read_text().splitlines()]
                self.assertEqual(rows[0]["cmd"], "sleep 300")
                self.assertEqual(rows[0]["reason"], "live test sleep")
                self.assertEqual(rows[0]["ppid"], os.getpid())
            finally:
                p.kill()
                p.wait()

    def test_term_ignoring_process_gets_sigkill(self):
        with tempfile.TemporaryDirectory() as home:
            p = subprocess.Popen([sys.executable, "-c",
                                  "import signal,time;signal.signal(signal.SIGTERM,signal.SIG_IGN);print('up',flush=True);time.sleep(300)"],
                                 stdout=subprocess.PIPE, text=True)
            p.stdout.readline()
            try:
                t0 = time.time()
                code, out = self.run_ah(home, "--pid", str(p.pid), "--reason", "ignores term", "--grace", "1")
                self.assertEqual(out["results"][0]["status"], "killed", out)
                self.assertGreaterEqual(time.time() - t0, 1)
                self.assertEqual(p.wait(timeout=5), -signal.SIGKILL)
            finally:
                p.kill()
                p.wait()

    def test_cli_refuses_pid_1_and_missing_reason(self):
        with tempfile.TemporaryDirectory() as home:
            code, out = self.run_ah(home, "--pid", "1", "--reason", "x")
            self.assertNotEqual(code, 0)
            self.assertEqual(out["results"][0]["status"], "refused")
            code, out = self.run_ah(home, "--pid", "999999", "--reason", " ")
            self.assertEqual(out["code"], "reason_required")

    def test_cli_refuses_its_own_parent(self):
        with tempfile.TemporaryDirectory() as home:
            code, out = self.run_ah(home, "--pid", str(os.getpid()), "--reason", "self")
            self.assertEqual(out["results"][0]["status"], "refused")  # the test process is ah's ancestor


class ReviewFixes(KillBase):
    def test_tree_child_that_was_reparented_is_not_signalled(self):
        probe = self.base(proc(900, 100), proc(901, 900))

        def swap(pr, pid):
            if pid == 901 and getattr(pr, "n", 0) >= 1:
                pr.procs[901]["ppid"] = 777  # same start+command, but no longer under 900
            if pid == 901:
                pr.n = getattr(pr, "n", 0) + 1
        probe.on_info = swap
        self.run_kill(probe, [900], tree=True)
        self.assertNotIn(901, [p for p, _ in probe.sent])

    def test_ps_failure_is_an_error_not_a_pretend_success(self):
        class Broken(FakeProbe):
            def info(self, pid):
                raise ak.KillError("probe_failed", "ps failed")
        with self.assertRaises(ak.KillError):
            self.run_kill(Broken([]), [901])
        self.assertFalse((self.home / ".agent-harness" / "kill-audit.jsonl").exists())

    def test_interactive_shells_and_terminals_are_protected(self):
        for cmd, comm in (("-zsh", "-zsh"), ("zsh", "/bin/zsh"),
                          ("/opt/homebrew/bin/netwatch run", "/opt/homebrew/bin/netwatch"),
                          ("/Applications/iTerm.app/Contents/MacOS/iTerm2", "iTerm2"), ("ssh-agent -l", "ssh-agent")):
            probe = self.base(proc(950, 100, cmd=cmd, comm=comm))
            out = self.run_kill(probe, [950])
            self.assertEqual(out["results"][0]["status"], "refused", cmd)
        probe = self.base(proc(951, 100, cmd="/bin/zsh /w/run.sh", comm="/bin/zsh"))
        self.assertEqual(self.run_kill(probe, [951])["results"][0]["status"], "exited")

    def test_reason_secrets_are_redacted_in_the_audit(self):
        self.run_kill(self.base(proc(952)), [952], reason="stuck, token=sk-live-ABCDEF123456SECRETVALUE")
        self.assertNotIn("SECRETVALUE", (self.home / ".agent-harness" / "kill-audit.jsonl").read_text())

    def test_remote_run_writes_the_session_log(self):
        old = os.environ.get("HOME")
        os.environ["HOME"] = str(self.home)
        self.addCleanup(lambda: os.environ.__setitem__("HOME", old))
        runner = lambda argv, **kw: subprocess.CompletedProcess(  # noqa: E731
            argv, 0, stdout='{"ok": true, "run": "k1", "results": []}')
        ak.kill_remote("t2-dev", [5], "why", False, 5, "sess-1", "a", home=self.home, runner=runner, foreign=True,
                       notify=lambda h, e: None)
        text = next((self.home / ".claude").rglob("main.jsonl")).read_text()
        self.assertIn("t2-dev", text)
        self.assertIn("result", text)


class NarrowedScope(KillBase):
    def foreign(self, pid, cwd="/elsewhere/repo", ppid=1, **kw):
        p = proc(pid, ppid, cmd="/usr/bin/python3 -m pytest")
        probe = self.base(p)
        probe.cwds = {pid: cwd}
        return probe

    def test_daemons_and_backup_jobs_are_always_refused_even_with_foreign(self):
        for n, cmd in enumerate(("rclone sync /a b:", "/x/bin/harness-console", "/opt/netwatch/netwatch run",
                                 "python3 /h/hookd.py serve", "python3 /h/ahd.py", "/bin/bash /h/log_backup.sh",
                                 "/Users/someone/.agent-harness/bin/log-backup.sh")):
            with self.subTest(cmd=cmd):
                probe = self.base(proc(1000 + n, 100, cmd=cmd))
                out = self.run_kill(probe, [1000 + n], foreign=True)
                self.assertEqual(out["results"][0]["status"], "refused", out)
                self.assertRegex(out["results"][0]["detail"], "daemon|protected")
                self.assertEqual(probe.sent, [])

    def test_mcp_server_of_another_live_session_is_refused(self):
        probe = self.base(proc(3100, 1, cmd="claude", comm="claude"),
                          proc(3101, 3100, cmd="npm exec @modelcontextprotocol/server-x", comm="node"),
                          proc(3102, 3101, cmd="node /x/mcp-server.js", comm="node"))
        probe.cwds = {3102: "/work/x"}
        out = self.run_kill(probe, [3102], foreign=True)
        self.assertEqual(out["results"][0]["status"], "refused")
        self.assertIn("live claude/codex session", out["results"][0]["detail"])
        self.assertEqual(probe.sent, [])

    def test_mcp_server_of_my_own_session_is_refused_too(self):
        probe = self.base(proc(3201, 3000, cmd="node /x/mcp-server.js", comm="node"))
        out = self.run_kill(probe, [3201], foreign=True)
        self.assertEqual(out["results"][0]["status"], "refused")
        self.assertEqual(probe.sent, [])

    def test_daemon_name_variants(self):
        for n, cmd in enumerate(("/x/harness-console-asks.v2 --serve", "Python -X dev -W ignore -u -B /h/ahd.py run",
                                 "/bin/bash /x/log-backup.sh nightly")):
            probe = self.base(proc(3300 + n, 100, cmd=cmd))
            self.assertEqual(self.run_kill(probe, [3300 + n], foreign=True)["results"][0]["status"], "refused", cmd)

    def test_foreign_target_without_flag_is_refused(self):
        probe = self.foreign(1100)
        out = self.run_kill(probe, [1100])
        self.assertEqual(out["results"][0]["status"], "refused")
        self.assertIn("--foreign", out["results"][0]["detail"])
        self.assertEqual(probe.sent, [])
        self.assertEqual(self.notices, [])
        self.assertFalse(out["ok"])

    def test_foreign_with_flag_records_owner_and_notifies_main(self):
        probe = self.foreign(1101)
        out = self.run_kill(probe, [1101], foreign=True, reason="runaway pytest of another owner")
        self.assertEqual(out["results"][0]["status"], "exited")
        intent = self.audit()[0]
        self.assertTrue(intent["foreign"])
        self.assertEqual(intent["cwd"], "/elsewhere/repo")
        self.assertEqual(intent["target_worktree"], "/elsewhere")
        self.assertIn("owner_session", intent)
        self.assertEqual(len(self.notices), 1)
        ev = self.notices[0]
        self.assertEqual((ev["severity"], ev["event"], ev["source"]), ("high", "raise", "ops-watch"))
        self.assertIn("1101", ev["message"])
        self.assertEqual([r["event"] for r in self.audit()][:2], ["intent", "signal"])

    def test_failed_notice_means_no_signal(self):
        probe = self.foreign(1102)

        def boom(home, event):
            raise OSError("ring full")
        with self.assertRaises(ak.KillError) as cm:
            self.run_kill(probe, [1102], foreign=True, notify=boom)
        self.assertEqual(cm.exception.code, "notice_failed")
        self.assertEqual(probe.sent, [])
        self.assertIn("aborted", [r["event"] for r in self.audit()])

    def test_own_worktree_and_own_tree_need_no_flag_and_send_no_notice(self):
        probe = self.foreign(1103, cwd="/work/sub")  # cwd inside my worktree
        self.assertEqual(self.run_kill(probe, [1103])["results"][0]["status"], "exited")
        probe = self.base(proc(1104, OWN, cmd="sleep 5"))  # child of the caller
        probe.cwds = {1104: "/elsewhere/x"}
        self.assertEqual(self.run_kill(probe, [1104])["results"][0]["status"], "exited")
        self.assertEqual(self.notices, [])

    def test_nested_worktree_inside_my_checkout_is_foreign(self):
        probe = self.foreign(1120, cwd="/work/nested/sub")
        out = self.run_kill(probe, [1120])
        self.assertEqual(out["results"][0]["status"], "refused")
        self.assertIn("--foreign", out["results"][0]["detail"])

    def test_audit_row_records_the_callers_cwd(self):
        probe = self.foreign(1121, cwd="/work/sub")
        self.run_kill(probe, [1121])
        self.assertTrue(any(r.get("caller", {}).get("cwd") for r in self.audit() if r["event"] == "intent"),
                        self.audit())

    def test_other_agents_process_in_the_same_session_is_foreign(self):
        probe = self.base(proc(1105, 4000, cmd="sleep 5"))  # sibling under the same claude session, other worktree
        probe.cwds = {1105: "/elsewhere/x"}
        out = self.run_kill(probe, [1105])
        self.assertEqual(out["results"][0]["status"], "refused")
        self.assertIn("--foreign", out["results"][0]["detail"])
        probe = self.base(proc(1105, 4000, cmd="sleep 5"))
        probe.cwds = {1105: "/elsewhere/x"}
        self.assertEqual(self.run_kill(probe, [1105], foreign=True)["results"][0]["status"], "exited")
        self.assertEqual(len(self.notices), 1)

    def test_claude_pid_env_does_not_widen_scope(self):
        probe = self.base(proc(1107, 100, cmd="sleep 5"))
        probe.cwds = {1107: "/elsewhere/x"}
        os.environ["CLAUDE_PID"] = "100"
        self.addCleanup(os.environ.pop, "CLAUDE_PID", None)
        self.assertEqual(self.run_kill(probe, [1107])["results"][0]["status"], "refused")

    def test_flag_does_not_lift_hard_refusals(self):
        probe = self.base(proc(1106, 1, uid=0, cmd="/usr/bin/x"))
        self.assertEqual(self.run_kill(probe, [1106], foreign=True)["results"][0]["status"], "refused")
        self.assertEqual(self.notices, [])


class ReviewRound3(KillBase):
    def test_node_wrapped_session_is_refused(self):
        probe = self.base(proc(2000, 100, cmd="node /opt/homebrew/bin/claude --resume", comm="node"))
        out = self.run_kill(probe, [2000], foreign=True)
        self.assertEqual(out["results"][0]["status"], "refused")
        self.assertEqual(probe.sent, [])

    def test_mcp_under_a_node_wrapped_session_is_refused(self):
        probe = self.base(proc(2100, 1, cmd="node /opt/homebrew/bin/codex", comm="node"),
                          proc(2101, 2100, cmd="node /x/mcp-server.js", comm="node"))
        out = self.run_kill(probe, [2101], foreign=True)
        self.assertEqual(out["results"][0]["status"], "refused")

    def test_login_and_flagged_shells_are_interactive(self):
        for cmd in ("zsh -l", "bash -i", "zsh -il", "/bin/bash --login", "zsh"):
            probe = self.base(proc(2200, 100, cmd=cmd, comm="/bin/" + cmd.split()[0].split("/")[-1]))
            self.assertEqual(self.run_kill(probe, [2200], foreign=True)["results"][0]["status"], "refused", cmd)
        probe = self.base(proc(2201, 100, cmd="/bin/bash /w/run.sh", comm="/bin/bash"))
        self.assertEqual(self.run_kill(probe, [2201])["results"][0]["status"], "exited")

    def test_remote_requires_foreign_and_a_local_notice(self):
        calls = []
        runner = lambda argv, **kw: calls.append(argv) or subprocess.CompletedProcess(  # noqa: E731
            argv, 0, stdout='{"ok": true, "run": "k1", "results": []}')
        with self.assertRaises(ak.KillError) as cm:
            ak.kill_remote("dev2", [5], "r", False, 5, home=self.home, runner=runner)
        self.assertEqual(cm.exception.code, "foreign_required")
        self.assertEqual(calls, [])
        notices = []
        ak.kill_remote("dev2", [5], "r", False, 5, home=self.home, runner=runner, foreign=True,
                       notify=lambda h, e: notices.append(e))
        self.assertEqual(len(notices), 1)
        self.assertEqual(notices[0]["severity"], "high")

        def boom(h, e):
            raise OSError("ring")
        calls.clear()
        with self.assertRaises(ak.KillError) as cm:
            ak.kill_remote("dev2", [5], "r", False, 5, home=self.home, runner=runner, foreign=True, notify=boom)
        self.assertEqual(cm.exception.code, "notice_failed")
        self.assertEqual(calls, [], "no notice, no remote stop")

    def test_remote_validates_reason_and_answer(self):
        runner = lambda argv, **kw: subprocess.CompletedProcess(argv, 0, stdout="[1]")  # noqa: E731
        with self.assertRaises(ak.KillError):
            ak.kill_remote("dev2", [5], "  ", False, 5, home=self.home, runner=runner, foreign=True)
        with self.assertRaises(ak.KillError) as cm:
            ak.kill_remote("dev2", [5], "r", False, 5, home=self.home, runner=runner, foreign=True,
                           notify=lambda h, e: None)
        self.assertEqual(cm.exception.code, "host_unreachable")


class Remote(KillBase):
    def test_foreign_flag_is_forwarded(self):
        seen = {}

        def runner(argv, **kw):
            seen["cmd"] = argv[-1]
            return subprocess.CompletedProcess(argv, 0, stdout='{"ok": true, "run": "k1", "results": []}')
        ak.kill_remote("dev2", [5], "r", False, 5, home=self.home, runner=runner, foreign=True, notify=lambda h, e: None)
        self.assertIn("--foreign", seen["cmd"])
        self.assertIn("python3 -I ", seen["cmd"])

    def test_host_allowlist_and_quoting(self):
        seen = {}

        def runner(argv, **kw):
            seen["argv"] = argv
            return subprocess.CompletedProcess(argv, 0, stdout='{"ok": true, "run": "k1", "results": []}')
        out = ak.kill_remote("dev2", [5, 6], "it's $(bad); rm", True, 7, "s", "a", home=self.home, runner=runner,
                             foreign=True, notify=lambda h, e: None)
        self.assertEqual(out["host"], "dev2")
        cmd = seen["argv"][-1]
        self.assertIn("--pid 5,6", cmd)
        self.assertIn("'it'\"'\"'s $(bad); rm'", cmd)
        self.assertIn("--tree", cmd)
        self.assertEqual(seen["argv"][-3:-1], ["--", "dev2"])
        with self.assertRaises(ak.KillError):
            ak.kill_remote("evil;host", [5], "r", False, 5, home=self.home, runner=runner, foreign=True)
        self.assertTrue(any(r["event"] == "remote" for r in self.audit()))


class FakeWindowsRemote:
    """A Windows OpenSSH host: decodes the -EncodedCommand PowerShell and answers from a process table. The stop
    answer is computed from the creation time embedded in the real stop script, so a reused pid is detected only
    if the script carries the identity read earlier."""

    def __init__(self, table, reuse_after_read=None):
        self.table, self.reuse, self.calls, self.stopped = dict(table), reuse_after_read, [], []

    def __call__(self, argv, **kw):
        import base64
        self.calls.append(argv)
        assert argv[:6] == ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "--"], argv
        words = argv[-1].split()
        assert words[:4] == ["powershell", "-NoProfile", "-NonInteractive", "-EncodedCommand"], words
        script = base64.b64decode(words[4]).decode("utf-16-le")
        pid = int(re.search(r"ProcessId=(\d+)", script).group(1))
        proc = self.table.get(pid)
        if "Stop-Process" not in script:
            out = {"found": False} if proc is None else dict(proc, found=True, pid=pid)
            if self.reuse and proc is not None:
                self.table[pid] = dict(proc, created=self.reuse)  # the pid is reused before the stop
            return subprocess.CompletedProcess(argv, 0, stdout="#< CLIXML\n" + json.dumps(out) + "\n")
        self.script = script
        assert "Stop-Process -Id %d -Force" % pid in script
        expected = re.search(r"-ne '([^']+)'", script).group(1)
        if proc is None:
            status = "gone"
        elif proc["created"] != expected:
            status = "changed"
        else:
            status = "stopped"
            self.stopped.append(pid)
        return subprocess.CompletedProcess(argv, 0, stdout=json.dumps({"status": status}) + "\n")


class WindowsHost(unittest.TestCase):
    """goodqa#15275: ah kill --host ah-spectre stops one process with Stop-Process over ssh, with the same guards."""
    PS = {"ppid": 900, "name": "powershell.exe", "created": "2026-11-07T21:14:03.1234567Z",
          "cmd": "powershell.exe -NoProfile -File C:\\pp\\pp-lab.ps1 receipt"}

    def setUp(self):
        self.home = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.home, True)
        self.notices = []

    def run_kill(self, remote, pids=(4242,), foreign=True, tree=False):
        return ak.kill_remote("ah-spectre", list(pids), "orphaned after TaskStop", tree, 5, "sess-1", "a1",
                              home=self.home, runner=remote, foreign=foreign,
                              notify=lambda h, e: self.notices.append(e))

    def audit(self):
        rows = []
        for f in self.home.rglob("*.jsonl"):
            for line in f.read_text().splitlines():
                try:
                    rows.append(json.loads(line))
                except ValueError:
                    pass
        return rows

    def test_stops_one_owned_pid_and_records_its_command_line(self):
        remote = FakeWindowsRemote({4242: self.PS})
        out = self.run_kill(remote)
        self.assertTrue(out["ok"], out)
        self.assertEqual(remote.stopped, [4242])
        self.assertEqual(len(remote.calls), 2)
        self.assertEqual(remote.calls[0][6], "ah-spectre")
        self.assertIn("'2026-11-07T21:14:03.1234567Z'", remote.script)
        ident = [r for r in self.audit() if r.get("event") == "identity"]
        self.assertEqual(len(ident), 1, self.audit())
        self.assertEqual((ident[0]["host"], ident[0]["pid"], ident[0]["created"]),
                         ("ah-spectre", 4242, "2026-11-07T21:14:03.1234567Z"))
        self.assertIn("pp-lab.ps1 receipt", ident[0]["cmd"])
        self.assertEqual(len(self.notices), 1)
        self.assertIn("ah-spectre", self.notices[0]["message"])

    def test_neg1_a_reused_pid_is_not_stopped(self):
        remote = FakeWindowsRemote({4242: self.PS}, reuse_after_read="2026-11-08T01:00:00.0000000Z")
        out = self.run_kill(remote)
        self.assertFalse(out["ok"])
        self.assertEqual(out["results"][0]["status"], "changed")
        self.assertEqual(remote.stopped, [])

    def test_neg2_pid_shape_is_checked_before_ssh(self):
        for pids in ((1, 2), (4,), (0,), ()):
            with self.subTest(pids=pids):
                remote = FakeWindowsRemote({})
                with self.assertRaises(ak.KillError) as caught:
                    self.run_kill(remote, pids)
                self.assertEqual(caught.exception.code, "bad_request")
                self.assertEqual(remote.calls, [])
        remote = FakeWindowsRemote({})
        with self.assertRaises(ak.KillError):
            self.run_kill(remote, tree=True)
        self.assertEqual(remote.calls, [])

    def test_neg3_foreign_is_required_and_protected_names_are_refused(self):
        remote = FakeWindowsRemote({4242: self.PS})
        with self.assertRaises(ak.KillError) as caught:
            self.run_kill(remote, foreign=False)
        self.assertEqual(caught.exception.code, "foreign_required")
        self.assertEqual(remote.calls, [])
        for name in ("lsass.exe", "sshd.exe", "svchost.exe", "explorer.EXE"):
            with self.subTest(name=name):
                remote = FakeWindowsRemote({4242: dict(self.PS, name=name)})
                out = self.run_kill(remote)
                self.assertEqual(out["results"][0]["status"], "refused")
                self.assertEqual(len(remote.calls), 1)  # read only, no stop script sent
                self.assertEqual(remote.stopped, [])

    def test_unreachable_or_garbage_answers_stop_nothing(self):
        def down(argv, **kw):
            raise subprocess.TimeoutExpired(argv, 60)

        def garbage(argv, **kw):
            return subprocess.CompletedProcess(argv, 0, stdout='{"found": true, "pid": 4242, "created": "x; rm"}')
        for runner in (down, garbage):
            with self.subTest(runner=runner.__name__):
                with self.assertRaises(ak.KillError) as caught:
                    self.run_kill(runner)
                self.assertEqual(caught.exception.code, "host_unreachable")
        self.assertEqual(self.notices, [])

    def test_gone_process_is_reported_without_a_stop(self):
        remote = FakeWindowsRemote({})
        out = self.run_kill(remote)
        self.assertEqual(out["results"][0]["status"], "gone")
        self.assertEqual(len(remote.calls), 1)

    def test_guard_admits_the_windows_host(self):
        cmd = "python3 -I ~/.claude/hooks/ah.py kill --pid 4242 --reason orphaned --host ah-spectre --foreign"
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(kg.decide(cmd, cwd=tmp, policy=kg.load_policy(), home=tmp)[0], "allow")
            self.assertEqual(kg.decide(cmd.replace("ah-spectre", "ah-spectre2"), cwd=tmp, policy=kg.load_policy(),
                                       home=tmp)[0], "block")


class GuardRule(unittest.TestCase):
    A = "python3 -I ~/.claude/hooks/ah.py kill "

    def verdict(self, cmd):
        with tempfile.TemporaryDirectory() as tmp:
            return kg.decide(cmd, cwd=tmp, policy=kg.load_policy(), home=tmp)[0]

    def test_literal_forms_pass(self):
        for tail in ("--pid 4242 --reason 'runaway vite'", "--pid 4242,4243 --reason x --tree --foreign --grace 5",
                     "--pid=4242 --reason=stuck --host dev2", "--pid 12 --reason 'a b c' --agent a1b2 --session s-1"):
            self.assertEqual(self.verdict(self.A + tail), "allow", tail)
        self.assertEqual(self.verdict("python3 -I -B " + str(Path.home()) + "/.claude/hooks/ah.py kill --pid 9 --reason r"), "allow")

    def test_everything_else_stays_blocked(self):
        bad = [
            self.A + "--pid 1 --reason x", self.A + "--pid 0,5 --reason x", self.A + "--pid 4242",
            self.A + "--reason x", self.A + "--pid 4242 --reason ''", self.A + "--pid $PID --reason x",
            self.A + "--pid '$(pgrep x)' --reason x", self.A + "--pid `pgrep x` --reason x",
            self.A + "--pid 4,$X --reason x", self.A + "--pid 4242 --reason x --host evil",
            self.A + "--pid 4242 --reason x --wal /etc/passwd", self.A + "--pid 4242 --reason x extra",
            self.A + "--pid 4242 --pid 4243 --reason x", self.A + "--pid 4242 --reason $R",
            self.A + "--pid 4242 --reason x --grace $(echo 5)",
            "python3 -c 'import os; os.kill(4242, 9)'", "python3 /tmp/ah.py kill --pid 4242 --reason x",
            "python3 -c 'x' ~/.claude/hooks/ah.py kill --pid 4242 --reason x",
            "python3 ~/.claude/hooks/ah.py kill --pid 4242 --reason x <<EOF\nimport os;os.kill(1,9)\nEOF",
            "ssh dev2 python3 ~/.claude/hooks/ah.py kill --pid 4242 --reason x",
            "eval 'python3 ~/.claude/hooks/ah.py kill --pid 4242 --reason x'",
            "python3 ~/.claude/hooks/ah.py kill --pid 4242 --reason x",  # no -I
            "python3 -I .claude/hooks/ah.py kill --pid 4242 --reason x",
            "python3 -I ..claude/hooks/ah.py kill --pid 4242 --reason x",
            "python3 -I '~/.claude/hooks/ah.py' kill --pid 4242 --reason x",
            "python3 -I /Users/Shared/.claude/hooks/ah.py kill --pid 4242 --reason x",
            "python3 -I /Users/../.claude/hooks/ah.py kill --pid 4242 --reason x",
            "PYTHONPATH=/tmp/x python3 -I ~/.claude/hooks/ah.py kill --pid 4242 --reason x",
            "env PYTHONPATH=/tmp/x python3 -I ~/.claude/hooks/ah.py kill --pid 4242 --reason x",
            "bash -c 'pkill -f vite'", "pkill -f vite", "kill 4242",
        ]
        for cmd in bad:
            with self.subTest(cmd=cmd):
                self.assertEqual(self.verdict(cmd), "block")

    def test_help_is_allowed_but_only_alone(self):
        """goodqa#14864 P1: `ah.py kill --help` was blocked, so the form could not be discovered."""
        self.assertEqual(self.verdict(self.A + "--help"), "allow")
        self.assertEqual(self.verdict(self.A + "-h"), "allow")
        for cmd in (self.A + "--help --pid 4242", self.A + "--help; pkill x", "python3 ~/.claude/hooks/ah.py kill --help && pkill x"):
            with self.subTest(cmd=cmd):
                self.assertEqual(self.verdict(cmd), "block")

    def hook(self, cmd, cwd):
        payload = json.dumps({"tool_name": "Bash", "tool_input": {"command": cmd}, "cwd": cwd, "hook_event_name": "PreToolUse"})
        return subprocess.run([sys.executable, str(HOOKS / "kill_guard.py"), "hook"], input=payload, capture_output=True,
                              text=True, cwd=cwd)

    def test_documented_lines_pass_the_real_hook_from_any_cwd(self):
        lines = [self.A + "--help",
                 self.A + "--host t2-dev --pid 3821924,3822748 --reason 'stop leftover stubs' --foreign",
                 self.A + "--pid 4242 --reason 'my own test server'"]
        with tempfile.TemporaryDirectory() as tmp:
            sub = Path(tmp, ".claude", "wals", "sess")
            sub.mkdir(parents=True)
            for cwd in (tmp, str(sub)):
                for cmd in lines:
                    with self.subTest(cwd=cwd, cmd=cmd):
                        self.assertEqual(self.hook(cmd, cwd).returncode, 0)

    def test_block_message_names_the_audited_form(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = self.hook("python3 ~/.claude/hooks/ah.py kill --pid 4242 --reason x", tmp)
        self.assertEqual(out.returncode, 2)
        self.assertIn("python3 -I ~/.claude/hooks/ah.py kill", out.stderr)
        self.assertIn("--host", out.stderr)
        with tempfile.TemporaryDirectory() as tmp:  # unrelated signalling keeps the generic message
            other = self.hook("python3 -c 'import os; os.kill(4242, 9)'", tmp)
        self.assertEqual(other.returncode, 2)
        self.assertNotIn("audited stop", other.stderr)

    def test_chained_commands_are_each_judged(self):
        self.assertEqual(self.verdict(self.A + "--pid 4242 --reason x && pkill -f vite"), "block")
        self.assertEqual(self.verdict(self.A + "--pid 4242 --reason x; kill 99"), "block")


class SessionScope(KillBase):
    """goodqa#15253 item 4: main stops what its own owners spawned, without --foreign (no high notice).

    Exact ownership only: the pid and start time must be in an authenticated `kill_guard.py spawn` ledger entry for
    a worktree inside ~/.agent-harness/work/<session>/. A cwd or a path in argv never counts."""
    foreign = NarrowedScope.foreign
    START = "Thu Nov  5 17:00:00 2026"

    def sess(self, *parts):
        return os.path.join(os.path.realpath(str(self.home)), ".agent-harness", "work", "sess-1", *parts)

    def spawned(self, pid, root=None, start=None):
        kg.append_ledger(root or self.sess("agent-y", "tree"), pid, start or self.START, home=str(self.home))

    def probe_for(self, pid, cwd="/elsewhere/repo", cmd="/usr/bin/sleep 300", live_start=None):
        probe = self.base(proc(pid, 1, cmd=cmd))
        probe.cwds = {pid: cwd}
        probe.spawn_start = lambda q, _s=live_start or self.START: _s if q == pid else None
        return probe

    def test_a_process_spawned_in_the_session_needs_no_foreign(self):
        self.spawned(1201)
        self.assertEqual(self.run_kill(self.probe_for(1201), [1201])["results"][0]["status"], "refused")  # flag needed
        out = self.run_kill(self.probe_for(1201), [1201], session_scope=True)
        self.assertEqual(out["results"][0]["status"], "exited")
        self.assertEqual(self.notices, [])
        intents = [r for r in self.audit() if r.get("event") == "intent" and r.get("pid") == 1201]
        self.assertEqual(intents[0].get("scope"), "session-spawn")

    def test_cwd_or_argv_in_the_session_dir_is_not_ownership(self):
        # #133 accepted these; review round 1 and main's ruling: never by a shared directory or argv text
        for pid, cwd, cmd in ((1202, self.sess("agent-y", "tree"), "/usr/bin/sleep 300"),
                              (1203, "/elsewhere/repo", "/usr/bin/python3 " + self.sess("agent-y", "run.py"))):
            out = self.run_kill(self.probe_for(pid, cwd=cwd, cmd=cmd), [pid], session_scope=True)
            self.assertEqual(out["results"][0]["status"], "refused", (cwd, cmd))
        self.assertEqual(self.notices, [])

    def test_reused_pid_other_session_and_lookalike_roots_stay_foreign(self):
        other = os.path.join(os.path.realpath(str(self.home)), ".agent-harness", "work", "sess-2", "t")
        self.spawned(1210, start="Wed Nov  4 09:00:00 2026")                 # recorded start differs: pid reused
        self.spawned(1211, root=other)                                        # another session's worktree
        self.spawned(1212, root=self.sess() + "0/t")                          # work/sess-10: a prefix, not inside
        self.spawned(1213, root=self.sess("..", "sess-2", "t"))              # dot segments out of the session dir
        self.spawned(1214, root="remote:dev2")                                # a remote ledger root
        for pid in (1210, 1211, 1212, 1213, 1214, 1215):                      # 1215: never recorded
            out = self.run_kill(self.probe_for(pid), [pid], session_scope=True)
            self.assertEqual(out["results"][0]["status"], "refused", pid)
        self.assertEqual(self.notices, [])

    def test_a_forged_ledger_line_is_ignored(self):
        root = self.sess("agent-y", "tree")
        self.spawned(1299)  # creates the key and the ledger file
        path = kg.ledger_path(root, str(self.home))
        with open(path, "a") as handle:
            handle.write(json.dumps({"pid": 1220, "start": self.START, "ts": 1, "root": root, "mac": "0" * 64}) + "\n")
        out = self.run_kill(self.probe_for(1220), [1220], session_scope=True)
        self.assertEqual(out["results"][0]["status"], "refused")

    def test_protected_processes_are_still_refused(self):
        self.spawned(1230)
        probe = self.probe_for(1230, cmd="/usr/sbin/cron -f")
        probe.procs[1230]["comm"] = "/usr/sbin/cron"
        self.assertEqual(self.run_kill(probe, [1230], session_scope=True)["results"][0]["status"], "refused")

    def test_a_session_id_is_required(self):
        probe = self.foreign(1240, cwd=self.sess("x"))
        with self.assertRaises(ak.KillError):
            ak.kill_local([1240], "why", home=self.home, probe=probe, sleep=self.clock.sleep, clock=self.clock.now,
                          session="", agent="", own_pid=OWN, worktree="/work", session_scope=True,
                          notify=lambda h, e: None)
        self.assertEqual(probe.sent, [])


class ApprovedBy(KillBase):
    """goodqa#15253 (11-07): the user asked main to stop a harness-console from 11-04 and its codex app-server child;
    `ah kill` refused both with no path the user could authorize. --approved-by is that path, and it is bounded."""
    STALE = "Wed Nov  4 10:00:00 2026"   # before the session process 3000 (Thu Nov  5 17:00) and days old
    NOW = time.mktime(time.strptime("Sat Nov  7 12:00:00 2026", "%a %b %d %H:%M:%S %Y"))
    TEXT = "please stop the stale harness-console 6101 and its codex child 6102, they have been idle for days"

    def approval(self, text=None):
        return lambda ask, session, home: {"ask": ask, "source": "answer:x", "uuid": "u", "at": "t",
                                           "text": self.TEXT if text is None else text}

    def stale(self, *extra, cpu=0.0):
        probe = self.base(proc(6101, 1, cmd="/Users/me/.agent-harness/bin/harness-console --port 0",
                               comm="harness-console", start=self.STALE),
                          proc(6102, 6101, cmd="/opt/codex/bin/codex app-server", comm="codex", start=self.STALE),
                          *extra)
        probe.cwds = {6101: "/elsewhere/a", 6102: "/elsewhere/a"}
        probe.cpu = lambda pid: cpu
        return probe

    def approved(self, probe, pids, text=None, **kw):
        return self.run_kill(probe, pids, approved_by="wa1b2c3d4e5f", approval_resolver=self.approval(text),
                             now=self.NOW, **kw)

    def test_control_without_approval_both_are_refused(self):
        out = self.run_kill(self.stale(), [6101, 6102], foreign=True)
        self.assertEqual([r["status"] for r in out["results"]], ["refused", "refused"])

    def test_a_named_stale_idle_console_and_codex_child_stop_with_a_notice(self):
        probe = self.stale()
        out = self.approved(probe, [6101], tree=True)
        self.assertEqual(sorted((r["pid"], r["status"]) for r in out["results"]), [(6101, "exited"), (6102, "exited")])
        self.assertEqual(len(self.notices), 1)
        self.assertTrue(self.notices[0]["key"].startswith("ah-kill:approved:"))
        self.assertEqual(self.notices[0]["severity"], "high")
        self.assertEqual(self.notices[0]["detail"]["ask"], "wa1b2c3d4e5f")
        intents = {r["pid"]: r for r in self.audit() if r.get("event") == "intent"}
        self.assertEqual({intents[6101]["scope"], intents[6102]["scope"]}, {"approved"})
        self.assertEqual(intents[6102]["lifted"], "protected process (codex)")

    def test_each_bound_refuses(self):
        cases = {
            "not named": dict(text="please stop the stale processes"),
            "too young": dict(start="Sat Nov  7 06:00:00 2026"),
            "after the session started": dict(start="Fri Nov  6 09:00:00 2026"),
            "running": dict(stat_="R"),
            "using cpu": dict(cpu=3.5),
            "cpu unknown": dict(cpu=None),
        }
        for name, case in cases.items():
            with self.subTest(name=name):
                self.notices.clear()
                probe = self.base(proc(6201, 1, cmd="/opt/codex/bin/codex app-server", comm="codex",
                                       start=case.get("start", self.STALE), stat_=case.get("stat_", "S")))
                probe.cwds = {6201: "/elsewhere/b"}
                probe.cpu = lambda pid, c=case.get("cpu", 0.0): c
                text = case.get("text", "stop codex 6201 please, it is stale")
                out = self.approved(probe, [6201], text=text)
                self.assertEqual(out["results"][0]["status"], "refused")
                self.assertIn("--approved-by", out["results"][0]["detail"])
                self.assertEqual(probe.sent, [])
                self.assertEqual(self.notices, [])

    def test_other_refusals_are_never_lifted(self):
        text = "stop 6301 6302 6303 6304 6305 6306 rclone netwatch hookd sshd zsh"
        for pid, kw in ((6301, dict(cmd="rclone sync /a b:", comm="rclone")),
                        (6302, dict(cmd="/opt/netwatch/netwatch run", comm="netwatch")),
                        (6303, dict(cmd="python3 /h/hookd.py serve", comm="python3")),
                        (6304, dict(cmd="/usr/sbin/sshd -D", comm="sshd")),
                        (6305, dict(cmd="/opt/codex/bin/codex", comm="codex", uid=ME + 1)),
                        (6306, dict(cmd="/System/Library/x", comm="/System/Library/x"))):
            with self.subTest(pid=pid):
                probe = self.base(proc(pid, 1, start=self.STALE, **kw))
                probe.cwds = {pid: "/elsewhere/c"}
                probe.cpu = lambda q: 0.0
                out = self.approved(probe, [pid], text=text)
                self.assertEqual(out["results"][0]["status"], "refused")
                self.assertEqual(probe.sent, [])
        probe = self.stale()
        out = self.approved(probe, [3000], text="stop 3000 claude")  # the caller's own session process
        self.assertEqual(out["results"][0]["status"], "refused")

    def test_no_notice_means_no_signal(self):
        probe = self.stale()

        def broken(home, event):
            raise OSError("ops-watch down")
        with self.assertRaises(ak.KillError):
            self.approved(probe, [6101], notify=broken)
        self.assertEqual(probe.sent, [])


class ApprovalResolution(unittest.TestCase):
    """resolve_approval reads the real asks ledger and transcript through provenance."""
    SID = "11111111-2222-3333-4444-555555555555"
    UID = "00000000-0000-0000-0000-0000000000a1"
    ASK = "wa1b2c3d4e5f"

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name)

    def world(self, text="please stop the stale harness-console 6101 now", at="2026-11-07T10:00:00Z",
              source=None, resolved=True, origin="human"):
        projects = self.home / ".claude" / "projects" / "-x"
        projects.mkdir(parents=True)
        record = {"type": "user", "uuid": self.UID, "timestamp": at, "sessionId": self.SID,
                  "origin": {"kind": origin}, "message": {"role": "user", "content": text}}
        (projects / (self.SID + ".jsonl")).write_text(json.dumps(record, separators=(",", ":")) + "\n")
        wals = self.home / ".claude" / "wals" / self.SID
        wals.mkdir(parents=True)
        rows = [{"at": "2026-11-07T09:59:00Z", "event": "ask", "id": self.ASK, "note": "stop 6101?", "reason": "user asked"}]
        if resolved:
            rows.append({"at": "2026-11-07T10:01:00Z", "event": "ask_resolved", "ref": self.ASK, "id": "wffffffffff1",
                         "source": source or 'user:%s/%s "stop the stale harness-console 6101"' % (self.SID, self.UID)})
        (wals / "main.jsonl").write_text("".join(json.dumps(r, separators=(",", ":")) + "\n" for r in rows))

    NOW = 1794045600.0 + 7200  # 2026-11-07T12:00:00Z

    def resolve(self, ask=None, session=None):
        return ak.resolve_approval(ask or self.ASK, session or self.SID, self.home, now=self.NOW)

    def test_a_user_resolved_ask_verifies_and_carries_the_human_text(self):
        self.world()
        got = self.resolve()
        self.assertIn("harness-console 6101", got["text"])
        self.assertEqual(got["ask"], self.ASK)

    def test_unverified_or_stale_approvals_are_refused(self):
        bad = {
            "unresolved": (dict(resolved=False), "no ask_resolved"),
            "stale": (dict(at="2026-11-05T10:00:00Z"), "older than"),
            "not human": (dict(origin="peer"), "verified human turn"),
            "pasted": (dict(text="look <pasted_content>stop the stale harness-console 6101</pasted_content>",
                            source='pasted:%s/%s "stop the stale harness-console 6101"' % (SID_, UID_)),
                       "verified human turn"),
            "excerpt not in turn": (dict(text="hello there, nothing to stop today"), "verified human turn"),
        }
        for name, (kw, why) in bad.items():
            with self.subTest(name=name):
                self.tearDown_world()
                self.world(**kw)
                with self.assertRaises(ak.KillError) as caught:
                    self.resolve()
                self.assertIn(why, str(caught.exception))
        self.tearDown_world()
        self.world()
        for ask, session, why in (("wzzzzzzzzzzz", None, "no ask"),
                                  (None, "99999999-2222-3333-4444-555555555555", "no ask"),
                                  ("bad id!", None, "needs the id")):
            with self.subTest(ask=ask, session=session):
                with self.assertRaises(ak.KillError) as caught:
                    self.resolve(ask, session)
                self.assertIn(why, str(caught.exception))

    def tearDown_world(self):
        import shutil
        shutil.rmtree(self.home / ".claude", ignore_errors=True)


SID_, UID_ = ApprovalResolution.SID, ApprovalResolution.UID


class ApprovedByGuard(unittest.TestCase):
    A = "python3 -I ~/.claude/hooks/ah.py kill --pid 4242 --reason stale --approved-by wa1b2c3d4e5f"

    def verdict(self, cmd, main):
        with tempfile.TemporaryDirectory() as tmp:
            return kg.decide(cmd, cwd=tmp, policy=kg.load_policy(), home=tmp, main=main)[0]

    def test_main_only_and_a_plain_id(self):
        self.assertEqual(self.verdict(self.A, True), "allow")
        self.assertEqual(self.verdict(self.A, False), "block")
        self.assertEqual(self.verdict(self.A.replace("wa1b2c3d4e5f", "'x y'"), True), "block")


class SessionScopeGuard(unittest.TestCase):
    """kill_guard admits --session-scope only from main (caller_identity.is_main on the hook payload)."""
    A = "python3 -I ~/.claude/hooks/ah.py kill --pid 4242 --reason stuck --session-scope"

    def verdict(self, cmd, subagent):
        with tempfile.TemporaryDirectory() as tmp:
            return kg.decide(cmd, cwd=tmp, policy=kg.load_policy(), home=tmp, main=not subagent)[0]

    def test_main_may_pass_the_flag(self):
        self.assertEqual(self.verdict(self.A, subagent=False), "allow")

    def test_a_subagent_may_not(self):
        self.assertEqual(self.verdict(self.A, subagent=True), "block")
        self.assertEqual(self.verdict(self.A.replace(" --session-scope", ""), subagent=True), "allow")

    def test_hook_reads_agent_id_from_the_payload(self):
        # after step 1 (B7) main is proven by caller_identity.is_main: a session id and its own transcript file
        sid = "11111111-2222-3333-4444-555555555555"
        with tempfile.TemporaryDirectory() as home:
            transcript = Path(home) / ".claude" / "projects" / "-x" / (sid + ".jsonl")
            transcript.parent.mkdir(parents=True)
            transcript.write_text("{}\n")
            proof = {"session_id": sid, "transcript_path": str(transcript)}
            for extra, code in ((proof, 0), (dict(proof, agent_id="a1"), 2), ({}, 2)):
                body = json.dumps(dict({"tool_name": "Bash", "tool_input": {"command": self.A}, "cwd": home}, **extra))
                done = subprocess.run([sys.executable, "-I", str(Path(kg.__file__)), "hook"], input=body.encode(),
                                      capture_output=True, timeout=60, env={"HOME": home, "PATH": "/usr/bin:/bin"})
                self.assertEqual(done.returncode, code, (extra, done.stderr[-300:]))


if __name__ == "__main__":
    unittest.main()
