"""Real subprocess controls for explicitly enrolled detached task recovery."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest

HELPER = Path(__file__).resolve().parents[1] / "harness/hooks/task_recovery.py"


class Recovery(unittest.TestCase):
    def test_timeout_does_not_release_a_surviving_writer(self):
        spec = importlib.util.spec_from_file_location("task_recovery_control", HELPER)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        writer = self.root / "orphan-wrote"
        program = (
            "import os,signal,time,pathlib; "
            "pid=os.fork(); "
            "signal.signal(signal.SIGTERM,signal.SIG_IGN) if pid==0 else None; "
            "time.sleep(1) if pid==0 else time.sleep(20); "
            "pathlib.Path(" + repr(str(writer)) + ").write_text('unsafe') if pid==0 else None"
        )
        result = module.execute([sys.executable, "-c", program], str(self.root),
                                self.root / "descendant.log", .2)
        self.assertEqual(result, 124)
        time.sleep(1.1)
        self.assertFalse(writer.exists(), "descendant wrote after the command was declared terminated")

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.prompt = self.root / "prompt"
        self.prompt.write_text("Continue the enrolled test task.")
        self.prompt.chmod(0o600)
        self.agent = self.root / "codex"
        self.agent.write_text("#!" + sys.executable + """
import pathlib,sys,time
root=pathlib.Path(sys.argv[1])
prompt=sys.stdin.read()
assert "Reconcile the existing checkout" in prompt
with (root/"calls").open("a") as f: f.write("call\\n")
time.sleep(float(sys.argv[2]))
if sys.argv[3]=="complete": (root/"done").write_text("verified")
""")
        self.agent.chmod(0o700)
        self.manifest = self.root / "input.json"
        self.task = self.root / "task"

    def enroll(self, delay="0", mode="complete", attempts=2, timeout=5):
        value = {"schema": "native-recovery-v1", "task_id": "test-recovery", "cwd": str(self.root),
                 "agent_argv": [str(self.agent), str(self.root), delay, mode],
                 "prompt_file": str(self.prompt),
                 "prompt_sha256": hashlib.sha256(self.prompt.read_bytes()).hexdigest(),
                 "verify_argv": [sys.executable, "-c",
                                 "from pathlib import Path; raise SystemExit(0 if Path('done').read_text()=='verified' else 1)"],
                 "max_attempts": attempts, "attempt_timeout": timeout, "task_timeout": 30}
        self.manifest.write_text(json.dumps(value))
        self.manifest.chmod(0o600)
        self.assertEqual(self.command("enroll", "--manifest", str(self.manifest)).returncode, 0)

    def command(self, cmd, *args):
        return subprocess.run([sys.executable, str(HELPER), cmd, "--task-dir", str(self.task), *args],
                              capture_output=True, timeout=15)

    def start(self):
        return subprocess.Popen([sys.executable, str(HELPER), "run", "--task-dir", str(self.task)],
                                start_new_session=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def wait_calls(self):
        for _ in range(100):
            if (self.root / "calls").exists():
                return
            time.sleep(.02)
        self.fail("native child did not start")

    def tearDown(self):
        self.temp.cleanup()

    def test_completion_is_verified_and_repeat_suppressed(self):
        self.enroll()
        self.assertEqual(self.command("run").returncode, 0)
        self.assertEqual(self.command("run").returncode, 0)
        self.assertEqual((self.root / "calls").read_text(), "call\n")
        self.assertEqual(json.loads((self.task / "state.json").read_text())["status"], "complete")

    def test_zero_agent_exit_does_not_establish_completion(self):
        self.enroll(mode="fail")
        self.assertEqual(self.command("run").returncode, 0)
        self.assertEqual((self.root / "calls").read_text(), "call\ncall\n")
        self.assertEqual(json.loads((self.task / "state.json").read_text())["status"], "attempts_exhausted")

    def test_supervisor_death_preserves_child_lock_and_recovers(self):
        self.enroll(delay="1.5")
        supervisor = self.start()
        self.wait_calls()
        supervisor.kill()
        supervisor.wait(timeout=3)
        self.assertEqual(self.command("run").returncode, 75)
        time.sleep(1.7)
        self.assertEqual(self.command("run").returncode, 0)
        self.assertEqual((self.root / "calls").read_text(), "call\n")
        self.assertEqual(json.loads((self.task / "state.json").read_text())["status"], "complete")

    def test_interrupted_agent_reconciles_in_fresh_attempt(self):
        self.enroll(delay="0", mode="fail")
        state = json.loads((self.task / "state.json").read_text())
        state["attempts"], state["status"] = 1, "running"
        (self.task / "state.json").write_text(json.dumps(state))
        self.assertEqual(self.command("run").returncode, 0)
        self.assertFalse((self.root / "calls").exists())
        self.assertEqual(json.loads((self.task / "state.json").read_text())["status"], "recovery_uncertain")

    def test_pause_prevents_dispatch_and_drift_refused(self):
        self.enroll()
        self.assertEqual(self.command("pause").returncode, 0)
        self.assertEqual(self.command("run").returncode, 0)
        self.assertFalse((self.root / "calls").exists())
        self.prompt.write_text("changed")
        self.assertEqual(self.command("run").returncode, 75)

    def test_timeout_is_bounded_and_services_are_generated(self):
        self.enroll(delay="10", mode="fail", attempts=1, timeout=1)
        start = time.monotonic()
        self.assertEqual(self.command("run").returncode, 0)
        self.assertLess(time.monotonic() - start, 5)
        receipt = json.loads((self.task / "attempt-1.json").read_text())
        self.assertEqual(receipt["exit"], 124)
        self.assertIn(b"Restart=on-failure", self.command("service", "--kind", "systemd").stdout)
        self.assertIn(b"SuccessfulExit", self.command("service", "--kind", "launchd").stdout)


if __name__ == "__main__":
    unittest.main()
