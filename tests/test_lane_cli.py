"""S1 (GoodQA goodqa#15946): caller stamps for `ah lane`, and the `ah.py lane` entry end to end without a stamp.

Covers AC-9, NEG-87, NEG-84 of software-factory/s1/spec.md.
Bounded: at most 3 short subprocesses (the real `ah.py lane` entry), a temp AH_HOME, no network.
"""
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

HOOKS = Path(__file__).resolve().parents[1] / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
from lane import auth  # noqa: E402
import caller_identity as ci  # noqa: E402

LANE = "lane_01ARZ3NDEKTSV4RRFFQ69G5FAV"
SESSION = "11111111-2222-4333-8444-555555555555"


class ParseTests(unittest.TestCase):
    def test_plain_commands_parse(self):
        self.assertEqual(auth.parse("python3 ~/.claude/hooks/ah.py lane start --lane %s" % LANE), ("start", LANE))
        self.assertEqual(auth.parse("python3 ah.py lane new --ticket 'GoodQA goodqa#5' --repo /r"),
                         ("new", "GoodQA goodqa#5"))

    def test_metacharacters_and_other_programs_are_not_stamped(self):
        for bad in ("python3 ah.py lane start --lane %s; rm x" % LANE, "echo `python3 ah.py lane start --lane %s`" % LANE,
                    "python3 other.py lane start --lane %s" % LANE, "python3 ah.py task start --lane %s" % LANE,
                    "python3 ah.py lane start --lane %s $(id)" % LANE, "python3 ah.py lane start"):
            with self.subTest(bad=bad):
                self.assertIsNone(auth.parse(bad))


class StampTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = Path(self.tmp.name)
        proj = self.home / ".claude" / "projects" / "p"
        proj.mkdir(parents=True)
        self.transcript = proj / (SESSION + ".jsonl")
        self.transcript.write_text("{}\n")

    def tearDown(self):
        self.tmp.cleanup()

    def payload(self, command, **extra):
        return dict({"tool_name": "Bash", "tool_input": {"command": command}, "session_id": SESSION,
                     "transcript_path": str(self.transcript), "tool_use_id": "toolu_" + "a" * 20}, **extra)

    def test_main_command_is_stamped_and_consumed_once(self):
        cmd = "python3 ah.py lane start --lane %s" % LANE
        self.assertEqual(auth.stamp_command(self.payload(cmd), home=self.home, claude_dir=self.home / ".claude"), "lane-main")
        self.assertIsNotNone(ci.take_stamp("lane-main", ["start", LANE], home=self.home))
        self.assertIsNone(ci.take_stamp("lane-main", ["start", LANE], home=self.home))

    def test_subagent_payload_never_gets_a_main_stamp(self):  # NEG-87
        cmd = "python3 ah.py lane start --lane %s" % LANE
        got = auth.stamp_command(self.payload(cmd, agent_id="A1", agent_type="task-owner"), home=self.home,
                                 claude_dir=self.home / ".claude")
        self.assertIsNone(got)
        self.assertFalse(auth.is_main("start", LANE, home=self.home))

    def test_environment_and_arguments_do_not_prove_main(self):  # NEG-87
        os.environ["LANE_MAIN"], os.environ["AI_AGENT"] = "1", "claude-code_main"
        try:
            self.assertFalse(auth.is_main("start", LANE, home=self.home))
        finally:
            os.environ.pop("LANE_MAIN", None)
            os.environ.pop("AI_AGENT", None)

    def test_stamp_is_for_that_command_and_lane_only(self):
        auth.stamp_command(self.payload("python3 ah.py lane start --lane %s" % LANE), home=self.home,
                           claude_dir=self.home / ".claude")
        self.assertFalse(auth.is_main("bind", LANE, home=self.home))
        self.assertFalse(auth.is_main("start", "lane_OTHER", home=self.home))
        self.assertTrue(auth.is_main("start", LANE, home=self.home))

    def test_holder_checkpoint_stamps_the_payload_agent_id(self):
        cmd = "python3 ah.py lane checkpoint --lane %s --kind plan --note x" % LANE
        self.assertEqual(auth.stamp_command(self.payload(cmd, agent_id="A1"), home=self.home), "lane-holder")
        self.assertEqual(auth.holder_identity(LANE, home=self.home), "A1")
        self.assertIsNone(auth.holder_identity(LANE, home=self.home))  # one-shot


class EntryTests(unittest.TestCase):
    def run_ah(self, home, *args):
        env = dict(os.environ, AH_HOME=str(home))
        return subprocess.run([sys.executable, str(HOOKS / "ah.py"), "lane"] + list(args), capture_output=True,
                              text=True, env=env, timeout=60)

    def test_main_only_command_without_a_stamp_is_refused_and_writes_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp) / "r"
            repo.mkdir()
            subprocess.run(["git", "init", "-q"], cwd=repo, check=True, capture_output=True, timeout=30)
            home = Path(tmp) / "home"
            home.mkdir()
            done = self.run_ah(home, "new", "--ticket", "GoodQA goodqa#1", "--repo", str(repo), "--dry-run")
            self.assertEqual(done.returncode, 3, done.stdout + done.stderr)
            self.assertIn("main-only", done.stdout)
            self.assertFalse((home / ".agent-harness").exists())

    def test_usage_error_exits_2(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(self.run_ah(Path(tmp), "start").returncode, 2)

    def test_status_of_an_unknown_lane_is_a_refusal_not_a_crash(self):
        with tempfile.TemporaryDirectory() as tmp:
            done = self.run_ah(Path(tmp), "status", "--lane", "lane_nope")
            self.assertNotEqual(done.returncode, 0)
            self.assertNotIn("Traceback", done.stderr)


class RealPortFailureTests(unittest.TestCase):
    def test_a_failing_real_port_is_a_message_and_exit_6_not_a_traceback(self):
        import subprocess as sp
        import ah_lane
        orig = ah_lane.run
        for exc in (sp.CalledProcessError(1, "git"), RuntimeError("registry down"), OSError("no route")):
            ah_lane.run = lambda a, p, s, exc=exc: (_ for _ in ()).throw(exc)
            try:
                with tempfile.TemporaryDirectory() as tmp:
                    os.environ["AH_HOME"] = tmp
                    os.environ["CLAUDE_CODE_SESSION_ID"] = SESSION
                    out = ah_lane.main(["status", "--lane", "lane_x"])
            finally:
                ah_lane.run = orig
                os.environ.pop("AH_HOME", None)
                os.environ.pop("CLAUDE_CODE_SESSION_ID", None)
            self.assertEqual(out, 6, repr(exc))

    def test_unknown_session_refuses_the_commands_that_need_one(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = {"PATH": os.environ.get("PATH", ""), "HOME": tmp, "AH_HOME": tmp}
            done = subprocess.run([sys.executable, str(HOOKS / "ah.py"), "lane", "start", "--lane", "lane_x"],
                                  capture_output=True, text=True, env=env, timeout=60)
            self.assertEqual(done.returncode, 4, done.stdout + done.stderr)
            self.assertIn("session unknown", done.stdout)


if __name__ == "__main__":
    unittest.main()
