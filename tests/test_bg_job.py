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

    def tearDown(self):
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


class LintCorpora(unittest.TestCase):
    def test_positive_corpus(self):
        import bg_lint
        cases = json.loads((DATA / "bg_lint_positive.json").read_text())
        self.assertGreaterEqual(len(cases), 12)
        for case in cases:
            codes = [c for c, _ in bg_lint.lint(case["command"])]
            self.assertIn(case["expect"], codes, case["id"])
            for _, message in bg_lint.lint(case["command"]):
                self.assertIn("bg_job.py", message if case["expect"] != "pipestatus" else "bg_job.py")

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
                self.assertIn("bg_job", message + (" bg_job" if code == "pipestatus" else ""), case["id"])


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
