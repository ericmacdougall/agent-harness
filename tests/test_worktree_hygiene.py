"""goodqa#14908 / rule S18: worktree_hygiene, vendored from Hawkeye's hawkeye-worktree-hygiene.py.

Two layers:
- Hawkeye's own 108-check scenario suite (tests/worktree_hygiene_scenarios.py), run as a child process with
  block_unpushed on, which is Hawkeye's semantics.
- The harness differences: unpushed commits are reported, not blocked, by default; harness owner worktrees
  under ~/.agent-harness/work are in scope; a pushed feature branch (the PR_READY state) is quiet; the commit
  suggestion goes through the commit policy.
Every test uses a temporary HOME with real git repositories and a bare origin. WTH_HOOK points the suite at
another implementation; the review packet's mutants use it to show the suite failing first.
"""

import json
import os
import re
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HOOK = Path(os.environ.get("WTH_HOOK") or ROOT / "harness/hooks/worktree_hygiene.py")
GIT_ENV = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid", "GIT_COMMITTER_NAME": "t",
           "GIT_COMMITTER_EMAIL": "t@example.invalid", "GIT_CONFIG_NOSYSTEM": "1"}


class HawkeyeScenarios(unittest.TestCase):
    def test_all_hawkeye_scenarios_pass(self):
        env = {k: v for k, v in os.environ.items() if not k.startswith(("HARNESS_WORKTREE", "HAWKEYE_"))}
        env["WTH_HOOK"] = str(HOOK)
        r = subprocess.run([sys.executable, str(ROOT / "tests/worktree_hygiene_scenarios.py")], env=env,
                           capture_output=True, text=True, timeout=900)
        m = re.search(r"^(\d+) passed, (\d+) failed$", r.stdout, re.M)
        fails = [ln for ln in r.stdout.splitlines() if ln.startswith("  FAIL")]
        self.assertTrue(m, r.stdout[-2000:] + r.stderr[-2000:])
        self.assertEqual((r.returncode, int(m.group(2)), fails), (0, 0, []), r.stdout[-3000:])
        self.assertGreaterEqual(int(m.group(1)), 100)  # not vacuous


class HarnessDefaults(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="wth-")
        self.tmp = Path(os.path.realpath(self._tmp.name))
        self.home = self.tmp / "home"
        self.home.mkdir()
        self.env = {"HOME": str(self.home), "PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LC_ALL": "C", **GIT_ENV}
        self.bare = self.tmp / "origin.git"
        self.git(self.tmp, "init", "-q", "--bare", "-b", "main", str(self.bare))
        seed = self.tmp / "seed"
        self.git(self.tmp, "init", "-q", "-b", "main", str(seed))
        (seed / "app.py").write_text("x = 1\n")
        self.git(seed, "add", "-A")
        self.git(seed, "commit", "-q", "-m", "seed")
        self.git(seed, "remote", "add", "origin", str(self.bare))
        self.git(seed, "push", "-q", "origin", "main")
        # A harness-style checkout and owner worktree, both under ~/.agent-harness/work/<session>/.
        self.session = self.home / ".agent-harness/work/sess"
        self.session.mkdir(parents=True)
        self.repo = self.session / "harness-delivery"
        self.git(self.tmp, "clone", "-q", str(self.bare), str(self.repo))
        self.wt = self.session / "agent-a1/feat-wt"
        self.git(self.repo, "worktree", "add", "-q", "-b", "feat/x", str(self.wt), "origin/main")
        self.transcript = self.home / ".claude/projects/p/sess.jsonl"
        self.transcript.parent.mkdir(parents=True)
        self.tool("Bash", {"command": "git -C %s worktree add -b feat/x %s origin/main" % (self.repo, self.wt)})

    def tearDown(self):
        self._tmp.cleanup()

    def git(self, cwd, *args):
        r = subprocess.run(["git"] + list(args), cwd=str(cwd), env=dict(os.environ, **GIT_ENV), capture_output=True,
                           text=True, timeout=120)
        if r.returncode:
            raise AssertionError("%s: %s" % (args[:2], r.stderr[-300:]))
        return r.stdout

    def tool(self, name, inp):
        rec = {"type": "assistant", "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S.000Z", time.gmtime()),
               "cwd": str(self.repo), "sessionId": "sess",
               "message": {"role": "assistant", "content": [{"type": "tool_use", "id": "t%d" % time.time_ns(),
                                                              "name": name, "input": inp}]}}
        with open(self.transcript, "a") as fh:
            fh.write(json.dumps(rec) + "\n")

    def hook(self, **env):
        ev = {"session_id": "sess", "transcript_path": str(self.transcript), "cwd": str(self.repo),
              "hook_event_name": "Stop", "stop_hook_active": False}
        return subprocess.run([sys.executable, str(HOOK)], input=json.dumps(ev), capture_output=True, text=True,
                              env=dict(self.env, **env), timeout=60, cwd=str(self.tmp))

    def commit_work(self, text="x = 2\n"):
        (self.wt / "app.py").write_text(text)
        self.tool("Edit", {"file_path": str(self.wt / "app.py"), "old_string": "1", "new_string": "2"})
        self.git(self.wt, "commit", "-q", "-am", "work")

    def sysmsg(self, r):
        return json.loads(r.stdout).get("systemMessage", "") if r.stdout.strip() else ""

    def test_uncommitted_work_in_harness_worktree_blocks_without_push_advice(self):
        (self.wt / "app.py").write_text("x = 3\n")
        self.tool("Edit", {"file_path": str(self.wt / "app.py"), "old_string": "1", "new_string": "3"})
        r = self.hook()
        self.assertEqual(r.returncode, 2, (r.stdout, r.stderr))
        self.assertIn("commit it before you stop", r.stderr)
        self.assertIn(str(self.wt), r.stderr)
        self.assertIn("commit_policy.py check-message", r.stderr)
        self.assertNotIn("push -u", r.stderr)
        self.assertNotIn("user.name=", r.stderr)
        self.assertEqual(self.hook().returncode, 0)  # bounded: once per state

    def test_unpushed_commits_are_reported_not_blocked_by_default(self):
        self.commit_work()
        r = self.hook()
        self.assertEqual(r.returncode, 0, r.stderr)
        msg = self.sysmsg(r)
        self.assertIn("UNPUSHED: %s" % self.wt, msg)
        self.assertIn("deliver.py prepare", msg)

    def test_block_unpushed_config_and_env_restore_hawkeye_semantics(self):
        self.commit_work()
        cfg = self.home / ".agent-harness/state/worktree-hygiene.json"
        cfg.parent.mkdir(parents=True, exist_ok=True)
        cfg.write_text(json.dumps({"block_unpushed": True}))
        r = self.hook()
        self.assertEqual(r.returncode, 2, r.stdout)
        self.assertIn("contained in no origin/* ref", r.stderr)
        self.assertIn("push -u origin feat/x", r.stderr)
        cfg.write_text("{}")
        self.commit_work("x = 4\n")  # a new state, so the once-per-state bound does not hide it
        self.assertEqual(self.hook(HARNESS_WORKTREE_HYGIENE_BLOCK_UNPUSHED="1").returncode, 2)

    def test_pushed_feature_branch_is_quiet(self):
        self.commit_work()
        self.git(self.wt, "push", "-q", "origin", "feat/x")
        r = self.hook()
        self.assertEqual((r.returncode, r.stderr), (0, ""))
        self.assertNotIn("UNPUSHED", self.sysmsg(r))

    def test_harness_opt_out(self):
        (self.wt / "app.py").write_text("x = 5\n")
        self.tool("Edit", {"file_path": str(self.wt / "app.py"), "old_string": "1", "new_string": "5"})
        r = self.hook(HARNESS_WORKTREE_GATE="off")
        self.assertEqual((r.returncode, r.stderr, r.stdout), (0, "", ""))

    def test_state_lives_under_agent_harness(self):
        (self.wt / "app.py").write_text("x = 6\n")
        self.tool("Edit", {"file_path": str(self.wt / "app.py"), "old_string": "1", "new_string": "6"})
        self.assertEqual(self.hook().returncode, 2)
        self.assertTrue(list((self.home / ".agent-harness/state/worktree-hygiene/asked").iterdir()))
        self.assertFalse((self.home / ".hawkeye").exists())


class Install(unittest.TestCase):
    def test_registered_on_stop_and_subagent_stop_fail_open(self):
        sys.path.insert(0, str(ROOT))
        import install
        claude = Path("/h/.claude")
        hooks = install.managed_hooks(claude)
        script = str(claude / "hooks" / "worktree_hygiene.py")
        for event in ("Stop", "SubagentStop"):
            handlers = [h for g in hooks[event] for h in g["hooks"] if script in (h.get("args") or [])]
            self.assertEqual(len(handlers), 1, event)
            self.assertNotIn("onFailure", handlers[0])
            self.assertGreaterEqual(handlers[0]["timeout"], 20)  # the hook's own budget is at most 15 s
        self.assertIn("worktree_hygiene.py", install.HOOKS)
        self.assertIn(script, install.managed_scripts(claude))


if __name__ == "__main__":
    unittest.main()
