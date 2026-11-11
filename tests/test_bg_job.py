"""bg_job.py and bg_lint.py (GoodQA #14513 Z12, #14472 Z11).

Real-process tests start only harmless scripts this test writes itself (sleepers, exit-N scripts) inside a private
temp dir, and only ever signal PIDs this test started. Corpora are data files read by Python (never via a shell).
"""
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
HOOKS = ROOT / "harness" / "hooks"
DATA = ROOT / "tests" / "data"
BG_JOB = HOOKS / "bg_job.py"
sys.path.insert(0, str(HOOKS))


def run_bg(*args, cwd=None):
    return subprocess.run([sys.executable, str(BG_JOB), *args], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                          universal_newlines=True, cwd=cwd, timeout=60)


class Base(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.jobs = self.tmp / "jobs"
        self.started = []
        # launch records its wrapper in kill_guard's ledger under HOME when run inside a git worktree (goodqa#15565):
        # keep that in a scratch HOME, never the real one
        home = mock.patch.dict(os.environ, {"HOME": str(self.tmp)})
        home.start()
        self.addCleanup(home.stop)

    def tearDown(self):
        if self.started:
            import bg_job
        for name in self.started:  # stop only jobs this test launched, via the identity-checked helper
            rec, _ = bg_job.load_record(str(self.jobs), name)
            if rec:
                bg_job.stop_group(rec["pid"], rec["nonce"])
        self._tmp.cleanup()

    def script(self, name, text):
        path = self.tmp / name
        path.write_text(text)
        return str(path)

    def launch(self, name, log, deadline, *argv):
        if name not in self.started:
            self.started.append(name)
        return run_bg("launch", "--name", name, "--log", str(log), "--deadline", str(deadline),
                      "--dir", str(self.jobs), "--", *argv)


class OldPatternControl(Base):
    """Failing control: the shell pattern from the incident reports started although the prerequisite failed."""

    def test_old_chain_prints_started_after_failed_prerequisite(self):
        marker = self.tmp / "suite-ran"
        path = self.script("old.sh", "false; (touch %s) & echo started\nwait\n" % marker)
        out = subprocess.run(["sh", path], stdout=subprocess.PIPE, universal_newlines=True, timeout=30).stdout
        self.assertIn("started", out)  # the bug: success printed with no evidence

    def test_bg_job_refuses_when_prerequisite_fails(self):
        marker = self.tmp / "suite-ran"
        path = self.script("new.sh", "false && touch %s && sleep 30\n" % marker)
        res = self.launch("prereq", self.tmp / "prereq.log", 3, "sh", path)
        self.assertNotEqual(res.returncode, 0, res.stdout)
        self.assertIn("FAILED_TO_START", res.stdout)
        self.assertNotIn("STARTED name", res.stdout)
        self.assertFalse(marker.exists())


class LaunchEvidence(Base):
    def test_started_when_alive_log_grows(self):
        path = self.script("ok.sh", "echo hello\nsleep 30\n")
        res = self.launch("ok", self.tmp / "ok.log", 10, "sh", path)
        self.assertEqual(res.returncode, 0, res.stdout)
        self.assertRegex(res.stdout, r"^STARTED name=ok pid=\d+ ")
        rec = json.loads((self.jobs / "ok.json").read_text())
        self.assertTrue(len(rec["argv_sha256"]) == 64 and rec["log"] and rec["status"] and rec["pid"] > 1)
        self.assertEqual(run_bg("status", "--name", "ok", "--dir", str(self.jobs)).stdout.split()[0], "RUNNING")

    def test_dies_at_once(self):
        res = self.launch("die", self.tmp / "die.log", 5, sys.executable, "-c", "raise SystemExit(7)")
        self.assertEqual(res.returncode, 3)
        self.assertIn("FAILED_TO_START", res.stdout)
        self.assertIn("status 7", res.stdout)

    def test_dies_at_once_even_after_output(self):
        path = self.script("shout.sh", "echo boom\nexit 5\n")
        res = self.launch("shout", self.tmp / "shout.log", 5, "sh", path)
        self.assertEqual(res.returncode, 3, res.stdout)
        self.assertIn("FAILED_TO_START", res.stdout)

    def test_command_not_found(self):
        res = self.launch("nf", self.tmp / "nf.log", 5, str(self.tmp / "no-such-binary"))
        self.assertEqual(res.returncode, 3)
        self.assertIn("FAILED_TO_START", res.stdout)

    def test_log_never_created(self):
        res = self.launch("nolog", self.tmp / "missing-dir" / "x.log", 3, "sleep", "30")
        self.assertEqual(res.returncode, 3)
        self.assertIn("FAILED_TO_START", res.stdout)
        self.assertRegex(res.stdout, "exited at once|never created|not creatable|not alive")

    def test_log_never_grows_and_job_is_stopped(self):
        res = self.launch("quiet", self.tmp / "quiet.log", 1, "sleep", "300")
        self.assertEqual(res.returncode, 3)
        self.assertIn("did not grow", res.stdout)
        rec = json.loads((self.jobs / "quiet.json").read_text())
        import bg_job
        self.assertFalse(bg_job.pid_is_job(rec["pid"], rec["nonce"]), "launcher must stop the job it started")

    def test_argv_is_not_a_shell_string(self):
        sentinel = self.tmp / "injected"
        path = self.script("echoarg.sh", 'echo "$1"\nsleep 30\n')
        res = self.launch("argv", self.tmp / "argv.log", 10, "sh", path, "x; touch %s" % sentinel)
        self.assertEqual(res.returncode, 0, res.stdout)
        self.assertFalse(sentinel.exists())

    def test_bad_inputs(self):
        self.assertEqual(self.launch("../evil", self.tmp / "a.log", 3, "true").returncode, 64)
        self.assertEqual(run_bg("launch", "--name", "e", "--log", str(self.tmp / "e.log"), "--deadline", "3",
                                "--dir", str(self.jobs)).returncode, 64)
        self.assertEqual(self.launch("d", self.tmp / "d.log", 0, "true").returncode, 64)

    def test_second_launch_of_running_name_refused(self):
        path = self.script("twice.sh", "echo hi\nsleep 30\n")
        self.assertEqual(self.launch("twice", self.tmp / "t.log", 10, "sh", path).returncode, 0)
        res = self.launch("twice", self.tmp / "t2.log", 3, "sh", path)
        self.assertEqual(res.returncode, 3)
        self.assertIn("already running", res.stdout)


class RedTeamRegressions(Base):
    """Findings B1, B2, N3, N4 from the independent red-team pass."""

    def _alive_pid(self, name):
        import bg_job
        rec = json.loads((self.jobs / (name + ".json")).read_text())
        return bg_job.group_alive(rec["pid"])

    def test_term_ignoring_silent_job_is_killed_on_failed_to_start(self):
        path = self.script("deaf.sh", "trap '' TERM\nsleep 300\n")
        res = self.launch("deaf", self.tmp / "deaf.log", 1, "sh", path)
        self.assertEqual(res.returncode, 3, res.stdout)
        self.assertFalse(self._alive_pid("deaf"), "SIGTERM-ignoring job outlived FAILED_TO_START")

    def test_record_write_failure_does_not_orphan_job(self):
        self.jobs.mkdir()
        (self.jobs / "orph.json").mkdir()  # the record cannot be written
        path = self.script("orph.sh", "echo hi\nsleep 300\n")
        res = self.launch("orph", self.tmp / "orph.log", 5, "sh", path)
        self.assertEqual(res.returncode, 3, res.stdout)
        self.assertIn("FAILED_TO_START", res.stdout)
        time.sleep(0.5)
        import bg_job
        out = subprocess.run(["ps", "-ww", "-o", "command="], stdout=subprocess.PIPE, universal_newlines=True).stdout
        self.assertNotIn(str(self.tmp / "orph.sh"), out)

    def test_empty_or_bad_nonce_never_matches_a_stranger(self):
        import bg_job
        self.assertFalse(bg_job.pid_is_job(os.getpid(), ""))
        self.assertFalse(bg_job.pid_is_job(os.getpid(), 5))
        self.assertFalse(bg_job.pid_is_job(2 ** 40, "0" * 32))

    def test_tampered_record_is_unproven_not_job_failure(self):
        self.jobs.mkdir()
        for rec in ({"pid": 10 ** 12, "nonce": "0" * 32, "status": "s", "log": "l", "argv_sha256": "x"},
                    {"pid": 123, "nonce": 7, "status": "s", "log": "l", "argv_sha256": "x"},
                    {"pid": True, "nonce": "0" * 32, "status": "s", "log": "l", "argv_sha256": "x"}):
            (self.jobs / "t.json").write_text(json.dumps(rec))
            for cmd in ("wait", "status"):
                res = run_bg(cmd, "--name", "t", "--dir", str(self.jobs))
                self.assertEqual(res.returncode, 2, res.stdout)

    def test_non_finite_numbers_refused(self):
        self.assertEqual(self.launch("nan", self.tmp / "n.log", "nan", "true").returncode, 64)
        self.assertEqual(self.launch("inf", self.tmp / "i.log", "inf", "true").returncode, 64)
        self.assertEqual(run_bg("wait", "--name", "x", "--timeout", "nan", "--dir", str(self.jobs)).returncode, 64)


class Round2(Base):
    """Adversarial spec review findings B3, B4, N1, N3."""

    def test_stop_group_never_signals_a_stranger(self):
        import bg_job
        stranger = subprocess.Popen(["sleep", "300"], start_new_session=True)  # started here, so we may stop it
        try:
            bg_job.stop_group(stranger.pid, "0" * 32)  # own=False: identity is not proven, nothing is signalled
            time.sleep(0.3)
            self.assertIsNone(stranger.poll(), "stop_group signalled a process that is not the job")
            bg_job.stop_group(stranger.pid, "")
            time.sleep(0.2)
            self.assertIsNone(stranger.poll())
        finally:
            stranger.terminate()
            stranger.wait()

    def test_status_exit_codes_are_not_false_success(self):
        for name, body, want, word in (("sok", "echo go\nsleep 1\nexit 0\n", 0, "EXIT_STATUS=0"),
                                       ("sbad", "echo go\nsleep 1\nexit 3\n", 1, "EXIT_STATUS=3")):
            res = self.launch(name, self.tmp / (name + ".log"), 10, "sh", self.script(name + ".sh", body))
            self.assertEqual(res.returncode, 0, res.stdout)
            run_bg("wait", "--name", name, "--timeout", "20", "--dir", str(self.jobs))
            st = run_bg("status", "--name", name, "--dir", str(self.jobs))
            self.assertEqual(st.returncode, want, st.stdout)
            self.assertIn(word, st.stdout)
        res = self.launch("slost", self.tmp / "slost.log", 10, "sh", self.script("slost.sh", "echo go\nsleep 300\n"))
        rec = json.loads((self.jobs / "slost.json").read_text())
        os.killpg(rec["pid"], 9)
        time.sleep(0.5)
        st = run_bg("status", "--name", "slost", "--dir", str(self.jobs))
        self.assertEqual(st.returncode, 2, st.stdout)
        self.assertIn("LOST", st.stdout)

    def test_wait_after_failed_to_start_is_unproven_even_if_job_exited_zero(self):
        res = self.launch("f0", self.tmp / "f0.log", 5, sys.executable, "-c", "raise SystemExit(0)")
        self.assertEqual(res.returncode, 3, res.stdout)
        w = run_bg("wait", "--name", "f0", "--timeout", "3", "--dir", str(self.jobs))
        self.assertEqual(w.returncode, 2, w.stdout)
        self.assertIn("failed to start", w.stdout)

    def test_concurrent_launch_of_same_name_is_serialised(self):
        path = self.script("conc.sh", "echo hi\nsleep 30\n")
        self.started.append("conc")
        cmd = [sys.executable, str(BG_JOB), "launch", "--name", "conc", "--log", str(self.tmp / "conc.log"),
               "--deadline", "10", "--dir", str(self.jobs), "--", "sh", path]
        procs = [subprocess.Popen(cmd, stdout=subprocess.PIPE, universal_newlines=True) for _ in range(2)]
        outs = [p.communicate(timeout=60)[0] for p in procs]
        started = [o for o in outs if o.startswith("STARTED")]
        self.assertEqual(len(started), 1, outs)
        rec = json.loads((self.jobs / "conc.json").read_text())
        self.assertIn("pid=%d" % rec["pid"], started[0])  # the one recorded job is the one reported


class TransientPsRead(Base):
    """Flake found by the acceptance reviewer: a ps read between fork and exec must not fail a live launch."""

    def test_launch_survives_transient_pid_check_failures(self):
        import io
        import contextlib
        import bg_job
        real, calls = bg_job.pid_is_job, {"n": 0}

        def flaky(pid, nonce):
            calls["n"] += 1
            return False if calls["n"] <= 3 else real(pid, nonce)

        path = self.script("tr.sh", "echo hi\nsleep 30\n")
        self.started.append("tr")
        bg_job.pid_is_job = flaky
        out = io.StringIO()
        try:
            with contextlib.redirect_stdout(out):
                rc = bg_job.main(["launch", "--name", "tr", "--log", str(self.tmp / "tr.log"), "--deadline", "10",
                                  "--dir", str(self.jobs), "--", "sh", path])
        finally:
            bg_job.pid_is_job = real
        self.assertEqual(rc, 0, out.getvalue())
        self.assertGreater(calls["n"], 3)


class WaitFailsClosed(Base):
    def start(self, name, body):
        res = self.launch(name, self.tmp / (name + ".log"), 10, "sh", self.script(name + ".sh", body))
        self.assertEqual(res.returncode, 0, res.stdout)

    def wait(self, name, timeout="20"):
        return run_bg("wait", "--name", name, "--timeout", timeout, "--dir", str(self.jobs))

    def test_exit_zero(self):
        self.start("z", "echo go\nsleep 1\nexit 0\n")
        res = self.wait("z")
        self.assertEqual(res.returncode, 0, res.stdout)
        self.assertIn("EXIT_STATUS=0", res.stdout)

    def test_nonzero_exit_seen_by_wait(self):
        self.start("nz", "echo go\nsleep 1\nexit 9\n")
        res = self.wait("nz")
        self.assertEqual(res.returncode, 1, res.stdout)
        self.assertIn("EXIT_STATUS=9", res.stdout)

    def test_last_command_ls_does_not_mask_failure(self):
        self.start("ls", "echo go\nsleep 1\nfalse\nls /\nexit 4\n")
        self.assertEqual(self.wait("ls").returncode, 1)

    def test_missing_status_dead_pid_fails_closed(self):
        self.start("gone", "echo go\nsleep 1\nexit 0\n")
        self.assertEqual(self.wait("gone").returncode, 0)
        (self.jobs / "gone.status").unlink()  # wrapper's proof is gone, process is gone
        res = self.wait("gone")
        self.assertEqual(res.returncode, 2, res.stdout)
        self.assertIn("UNPROVEN", res.stdout)

    def test_killed_wrapper_leaves_no_status(self):
        self.start("kill", "echo go\nsleep 300\n")
        rec = json.loads((self.jobs / "kill.json").read_text())
        os.killpg(rec["pid"], 9)  # our own job's group
        time.sleep(0.5)
        res = self.wait("kill", "5")
        self.assertEqual(res.returncode, 2, res.stdout)

    def test_garbled_status(self):
        self.start("g", "echo go\nsleep 1\nexit 0\n")
        self.wait("g")
        (self.jobs / "g.status").write_text("{not json")
        self.assertEqual(self.wait("g").returncode, 2)
        (self.jobs / "g.status").write_text(json.dumps({"exit": "0", "nonce": "x"}))
        self.assertEqual(self.wait("g").returncode, 2)

    def test_status_of_other_job_rejected(self):
        self.start("o", "echo go\nsleep 1\nexit 0\n")
        self.wait("o")
        (self.jobs / "o.status").write_text(json.dumps({"exit": 0, "nonce": "someone-else"}))
        res = self.wait("o")
        self.assertEqual(res.returncode, 2, res.stdout)

    def test_exit_bool_or_negative_not_trusted_as_success(self):
        self.start("b", "echo go\nsleep 1\nexit 0\n")
        rec = json.loads((self.jobs / "b.json").read_text())
        self.wait("b")
        (self.jobs / "b.status").write_text(json.dumps({"exit": True, "nonce": rec["nonce"]}))
        self.assertEqual(self.wait("b").returncode, 2)

    def test_status_is_a_directory_or_fifo_does_not_hang(self):
        self.start("d", "echo go\nsleep 1\nexit 0\n")
        self.wait("d")
        (self.jobs / "d.status").unlink()
        (self.jobs / "d.status").mkdir()
        self.assertEqual(self.wait("d", "5").returncode, 2)

    def test_timeout_while_running(self):
        self.start("slow", "echo go\nsleep 300\n")
        res = self.wait("slow", "1")
        self.assertEqual(res.returncode, 3, res.stdout)
        self.assertIn("TIMEOUT", res.stdout)

    def test_no_record(self):
        self.assertEqual(self.wait("never-launched").returncode, 2)

    def test_pid_reused_after_exit(self):
        """A live, unrelated process now owns the job's PID: it must not be mistaken for the job."""
        self.start("reuse", "echo go\nsleep 1\nexit 0\n")
        self.wait("reuse")
        (self.jobs / "reuse.status").unlink()
        stranger = subprocess.Popen(["sleep", "300"])  # started by this test, so we may stop it
        try:
            rec = json.loads((self.jobs / "reuse.json").read_text())
            rec["pid"] = stranger.pid
            (self.jobs / "reuse.json").write_text(json.dumps(rec))
            res = self.wait("reuse", "3")
            self.assertEqual(res.returncode, 2, res.stdout)
            self.assertIn("UNPROVEN", res.stdout)
            import bg_job
            self.assertFalse(bg_job.pid_is_job(stranger.pid, rec["nonce"]))
        finally:
            stranger.terminate()
            stranger.wait()


class WaitFile(Base):
    """GoodQA #15565: a waiter must name the producer of its file, give up, and alert (one waited 12 h for nothing)."""

    def wait_file(self, target, producer, timeout="20", *extra):
        env = dict(os.environ, HOME=str(self.tmp))  # the ring alert lands in a throwaway home
        return subprocess.run([sys.executable, str(BG_JOB), "wait-file", "--file", str(target), "--producer", producer,
                               "--timeout", timeout, "--poll", "0.1", "--dir", str(self.jobs), *extra],
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True, timeout=60, env=env)

    def alerts(self):
        ring = self.tmp / ".agent-harness" / "state" / "alerts.jsonl"
        return ring.read_bytes() if ring.exists() else b""

    def test_a_producer_and_a_finite_timeout_are_required(self):
        target = self.tmp / "out.txt"
        for args in ((["wait-file", "--file", str(target), "--timeout", "5"]),
                     (["wait-file", "--file", str(target), "--producer", "someone", "--timeout", "5"]),
                     (["wait-file", "--file", str(target), "--producer", "pid:abc", "--timeout", "5"]),
                     (["wait-file", "--file", str(target), "--producer", "pid:%d" % os.getpid()]),
                     (["wait-file", "--file", str(target), "--producer", "pid:%d" % os.getpid(), "--timeout", "999999"])):
            res = run_bg(*args)
            self.assertNotEqual(res.returncode, 0, args)
            self.assertNotIn("FILE_READY", res.stdout)

    def test_a_producer_that_wrote_the_file_is_ready(self):
        target = self.tmp / "out.txt"
        script = self.script("producer.sh", "echo up; sleep 0.6; echo data > %s; sleep 5\n" % target)
        self.assertEqual(self.launch("prod1", self.tmp / "p1.log", 5, "sh", script).returncode, 0)
        res = self.wait_file(target, "job:prod1")
        self.assertEqual(res.returncode, 0, res.stdout)
        self.assertIn("FILE_READY", res.stdout)

    def test_a_producer_that_exits_without_the_file_ends_the_wait_and_alerts(self):
        target = self.tmp / "never.txt"
        script = self.script("quitter.sh", "echo working; sleep 0.8\n")
        self.assertEqual(self.launch("quit1", self.tmp / "q1.log", 5, "sh", script).returncode, 0)
        started = time.time()
        res = self.wait_file(target, "job:quit1", timeout="60")
        self.assertEqual(res.returncode, 4, res.stdout)
        self.assertIn("PRODUCER_GONE", res.stdout)
        self.assertLess(time.time() - started, 30)  # nowhere near the 60 s timeout
        self.assertIn(b"bgwait:never.txt:producer-gone", self.alerts())

    def test_a_live_producer_that_never_writes_times_out_and_alerts(self):
        target = self.tmp / "slow.txt"
        script = self.script("sleeper.sh", "echo up; sleep 60\n")
        self.assertEqual(self.launch("slow1", self.tmp / "s1.log", 5, "sh", script).returncode, 0)
        res = self.wait_file(target, "job:slow1", timeout="2")
        self.assertEqual(res.returncode, 3, res.stdout)
        self.assertIn("TIMEOUT", res.stdout)
        self.assertIn(b"bgwait:slow.txt:timeout", self.alerts())

    def test_poll_is_bounded_and_a_directory_is_not_a_ready_file(self):
        # red-team ad4294 W2 and W3
        target = self.tmp / "later.txt"
        for poll in ("0", "-1", "nan", "1e9", "61"):
            res = run_bg("wait-file", "--file", str(target), "--producer", "pid:%d" % os.getpid(), "--timeout", "5",
                         "--poll", poll)
            self.assertNotEqual(res.returncode, 0, poll)
            self.assertNotIn("FILE_READY", res.stdout, poll)
        started = time.time()
        res = self.wait_file(self.tmp, "pid:%d" % os.getpid(), timeout="2")  # a directory is not output
        self.assertEqual(res.returncode, 3, res.stdout)
        self.assertLess(time.time() - started, 6)
        slow = subprocess.run([sys.executable, str(BG_JOB), "wait-file", "--file", str(target), "--producer",
                               "pid:%d" % os.getpid(), "--timeout", "1", "--poll", "30", "--dir", str(self.jobs)],
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT, universal_newlines=True, timeout=20,
                              env=dict(os.environ, HOME=str(self.tmp)))
        self.assertEqual(slow.returncode, 3)  # the 30 s poll did not push the 1 s timeout out

    def test_a_dead_pid_or_unknown_job_is_not_a_producer(self):
        target = self.tmp / "x.txt"
        dead = subprocess.Popen([sys.executable, "-c", "pass"])
        dead.wait()
        res = self.wait_file(target, "pid:%d" % dead.pid, timeout="30")
        self.assertEqual(res.returncode, 4, res.stdout)
        res = self.wait_file(target, "job:nosuchjob", timeout="30")
        self.assertEqual(res.returncode, 4, res.stdout)

    def test_an_existing_file_is_ready_at_once_even_when_the_producer_is_gone(self):
        target = self.tmp / "done.txt"
        target.write_text("x")
        self.assertEqual(self.wait_file(target, "pid:1999999", timeout="5").returncode, 0)


class LintCorpora(unittest.TestCase):
    def test_positive_corpus(self):
        import bg_lint
        cases = json.loads((DATA / "bg_lint_positive.json").read_text())
        self.assertGreaterEqual(len(cases), 12)
        for case in cases:
            codes = [c for c, _ in bg_lint.lint(case["command"])]
            self.assertIn(case["expect"], codes, case["id"])
            for _, message in bg_lint.lint(case["command"]):
                self.assertIn("bg_job.py", message, case["id"])

    def test_negative_corpus(self):
        import bg_lint
        cases = json.loads((DATA / "bg_lint_negative.json").read_text())
        self.assertGreaterEqual(len(cases), 12)
        for case in cases:
            self.assertEqual(bg_lint.lint(case["command"]), [], case["id"])

    def test_every_warning_names_bg_job(self):
        import bg_lint
        for case in json.loads((DATA / "bg_lint_positive.json").read_text()):
            for code, message in bg_lint.lint(case["command"]):
                self.assertIn("bg_job.py", message, case["id"])


class LintBounded(unittest.TestCase):
    def test_unclosed_substitutions_are_linear(self):
        import bg_lint
        for text in ("x=$(" * 40000, "x=$(a|" * 30000, "x=`" * 60000, ("a=$(b|" * 100) + "PIPESTATUS" + "x=$(" * 30000):
            start = time.time()
            bg_lint.lint(text + " echo ${PIPESTATUS[@]}")
            self.assertLess(time.time() - start, 2.0, text[:12])


class LintHook(unittest.TestCase):
    def run_hook(self, payload):
        return subprocess.run([sys.executable, str(HOOKS / "bg_lint.py")], input=payload, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, universal_newlines=True, timeout=30)

    def test_warns_and_never_blocks(self):
        res = self.run_hook(json.dumps({"tool_name": "Bash", "tool_input": {"command": "a; nohup s & echo started"}}))
        self.assertEqual(res.returncode, 0)
        msg = json.loads(res.stdout)["hookSpecificOutput"]
        self.assertEqual(msg["hookEventName"], "PreToolUse")
        self.assertIn("bg_job.py", msg["additionalContext"])
        self.assertNotIn("permissionDecision", msg)

    def test_silent_on_clean_and_hostile_input(self):
        for payload in (json.dumps({"tool_name": "Bash", "tool_input": {"command": "a && echo ok"}}),
                        "not json", "{}", json.dumps({"tool_name": "Write", "tool_input": {"command": "a; echo ok"}}),
                        json.dumps({"tool_name": "Bash", "tool_input": {"command": 5}}), "[" * 5000, ""):
            res = self.run_hook(payload)
            self.assertEqual(res.returncode, 0, payload[:20])
            self.assertEqual(res.stdout, "", payload[:20])

    def test_huge_command_is_bounded(self):
        start = time.time()
        res = self.run_hook(json.dumps({"tool_name": "Bash", "tool_input": {"command": "a; " * 100000 + "echo ok"}}))
        self.assertEqual(res.returncode, 0)
        self.assertLess(time.time() - start, 20)


class Wiring(unittest.TestCase):
    def test_installer_ships_and_registers_lint_as_advisory(self):
        sys.path.insert(0, str(ROOT))
        import install
        self.assertIn("bg_job.py", install.HOOKS)
        self.assertIn("bg_lint.py", install.HOOKS)
        claude = Path("/nonexistent-claude-home/.claude")
        self.assertIn(str(claude / "hooks" / "bg_lint.py"), install.managed_scripts(claude))
        bash_groups = [g for g in install.managed_hooks(claude)["PreToolUse"] if g.get("matcher") == "Bash"]
        lints = [h for g in bash_groups for h in g["hooks"] if h.get("args", [""])[0].endswith("bg_lint.py")]
        self.assertEqual(len(lints), 1)
        self.assertNotEqual(lints[0].get("onFailure"), "block")  # advisory: a lint failure must not block
        self.assertTrue((HOOKS / "bg_job.py").is_file() and (HOOKS / "bg_lint.py").is_file())

    def test_codex_ships_helper(self):
        text = (ROOT / "install_codex.py").read_text()
        self.assertIn("'bg_job.py'", text)


class RulesEntry(unittest.TestCase):
    def test_rules_registry_entry(self):
        entry = json.loads((ROOT / "docs" / "rules" / "bg-launch.json").read_text())["rules"][0]
        self.assertEqual(entry["id"], "bg-launch")
        cls, meth = entry["test"].split(".")
        self.assertTrue(hasattr(globals()[cls], meth), entry["test"])
        self.assertEqual(entry["test_file"], "tests/test_bg_job.py")
        self.assertIn(entry["enforcement"], ("ENFORCED", "ALERT-ONLY", "NOT-ENFORCED"))


if __name__ == "__main__":
    unittest.main()
