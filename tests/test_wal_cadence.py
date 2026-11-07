"""goodqa#14908 / rule W04: wal_cadence, ported from Hawkeye's hawkeye-wal-cadence.py.

Every test builds its own temporary home (AH_HOME) with real git repositories and linked worktrees, and runs
the hook as a child process, the way Claude Code runs it. WC_HOOKS_DIR points the suite at another
implementation; the review packet's mutants use it to show the suite failing first.
"""

import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HOOKS = Path(os.environ.get("WC_HOOKS_DIR") or ROOT / "harness/hooks")
SCRIPT = HOOKS / "wal_cadence.py"
SID = "sess-wc"
AGENT = "a0123456789abcdef"
GIT_ENV = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@example.invalid", "GIT_COMMITTER_NAME": "t",
           "GIT_COMMITTER_EMAIL": "t@example.invalid", "GIT_CONFIG_NOSYSTEM": "1"}


def run(*args, cwd=None):
    r = subprocess.run(list(args), cwd=cwd, env=dict(os.environ, **GIT_ENV), capture_output=True, text=True)
    if r.returncode:
        raise AssertionError("%s: %s" % (args[:3], r.stderr[-300:]))
    return r.stdout


def stamp(seconds_ago=0):
    return datetime.fromtimestamp(time.time() - seconds_ago, timezone.utc).isoformat()


class Case(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="wc-")
        self.home = Path(os.path.realpath(self._tmp.name))
        self.primary = self.home / "repo"
        run("git", "init", "-q", "-b", "main", str(self.primary))
        (self.primary / "app.py").write_text("x = 1\n")
        run("git", "add", "-A", cwd=self.primary)
        run("git", "commit", "-q", "-m", "one", cwd=self.primary)
        self.wt = self.home / "wt"
        run("git", "worktree", "add", "-q", "-b", "feat", str(self.wt), cwd=self.primary)
        self.wals = self.home / ".claude/wals" / SID
        self.wals.mkdir(parents=True)

    def tearDown(self):
        self._tmp.cleanup()

    def hook(self, event="Stop", cwd=None, env=None, raw=None, **extra):
        payload = {"hook_event_name": event, "session_id": SID, "cwd": str(cwd or self.wt)}
        payload.update(extra)
        full_env = {"AH_HOME": str(self.home), "HOME": str(self.home), "PATH": os.environ.get("PATH", "/usr/bin:/bin")}
        full_env.update(env or {})
        return subprocess.run([sys.executable, "-I", str(SCRIPT)], input=raw if raw is not None else json.dumps(payload),
                              capture_output=True, text=True, env=full_env, cwd=str(self.home), timeout=60)

    def work(self, where=None, lines=50, name="feature.py"):
        path = Path(where or self.wt) / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("".join("line_%d = %d\n" % (i, i) for i in range(lines)))
        return path

    def note(self, wal="main.jsonl", seconds_ago=0, event="status", **extra):
        row = {"at": stamp(seconds_ago), "event": event, "note": "did a thing", "id": "w1"}
        row.update(extra)
        with open(self.wals / wal, "a") as fh:
            fh.write(json.dumps(row) + "\n")

    def assertNudged(self, r, *needles):
        self.assertEqual(r.returncode, 2, r.stderr)
        self.assertIn("NO DURABLE RECORD", r.stderr)
        for needle in needles:
            self.assertIn(needle, r.stderr)

    def assertQuiet(self, r):
        self.assertEqual((r.returncode, r.stderr), (0, ""), r.stderr)


class StopInWorktree(Case):
    def test_big_untracked_diff_without_wal_note_nudges_once(self):
        self.work()
        self.assertNudged(self.hook(), "feature.py", str(self.wals / "main.jsonl"), "wal_note.py")
        self.assertQuiet(self.hook())  # bounded: the same diff never blocks twice
        self.work(lines=60)
        self.assertNudged(self.hook())  # a new diff earns one new nudge

    def test_unwritable_state_never_blocks_and_success_still_suppresses_duplicates(self):
        # goodqa#15039 (Kimi revised R07): an unrecorded block would repeat on every stop
        self.work()
        state_dir = self.home / ".agent-harness/state/wal-cadence"
        state_dir.parent.mkdir(parents=True, exist_ok=True)
        state_dir.write_text("not a directory")  # a reliable OSError even when tests run as root
        self.assertQuiet(self.hook())
        self.assertQuiet(self.hook())
        state_dir.unlink()
        self.assertNudged(self.hook())
        self.assertQuiet(self.hook())  # durable state still bounds the nudge to once per diff

    def test_tracked_change_counts(self):
        (self.wt / "app.py").write_text("".join("y%d = 0\n" % i for i in range(45)))
        self.assertNudged(self.hook(), "app.py")

    def test_recent_human_note_satisfies_but_metadata_does_not(self):
        self.work()
        with open(self.wals / "main.jsonl", "a") as fh:
            fh.write(json.dumps({"at": stamp(), "event": "pretool", "tool": "Bash", "target_chars": 9}) + "\n")
            fh.write(json.dumps({"at": stamp(), "event": "status"}) + "\n")  # no note: not a human entry
        self.assertNudged(self.hook())
        self.work(lines=70)
        self.note()
        self.assertQuiet(self.hook())

    def test_stale_human_note_nudges(self):
        self.work()
        self.note(seconds_ago=30 * 60)
        self.assertNudged(self.hook(), "30 minutes old")

    def test_small_or_journal_only_diffs_are_quiet(self):
        self.work(lines=39)
        self.assertQuiet(self.hook())
        self.work(name="docs/notes.md", lines=200)
        self.work(name="plans/HANDOFF.md", lines=200)
        self.assertQuiet(self.hook())

    def test_primary_checkout_and_non_git_cwd_are_quiet(self):
        self.work(self.primary)
        self.assertQuiet(self.hook(cwd=self.primary))
        self.assertQuiet(self.hook(cwd=self.home))

    def test_opt_out_repeat_stop_and_garbage_are_quiet(self):
        self.work()
        self.assertQuiet(self.hook(env={"HARNESS_WAL_CADENCE": "off"}))
        self.assertQuiet(self.hook(stop_hook_active=True))
        self.assertQuiet(self.hook(raw="{nope"))
        self.assertQuiet(self.hook(event="PreToolUse"))
        self.assertQuiet(self.hook(session_id=""))


class SubagentStop(Case):
    def setUp(self):
        super().setUp()
        self.agent_dir = self.home / ".agent-harness/work" / SID / ("agent-" + AGENT)
        self.agent_dir.mkdir(parents=True)
        self.agent_wt = self.agent_dir / "wt"
        run("git", "worktree", "add", "-q", "-b", "agent", str(self.agent_wt), cwd=self.primary)

    def test_agent_worktree_checked_against_agent_wal(self):
        self.work(self.agent_wt)
        wal = self.wals / ("agent-%s.jsonl" % AGENT)
        self.note()  # a main-WAL note does not cover the agent
        self.assertNudged(self.hook("SubagentStop", cwd=self.home, agent_id=AGENT), str(wal), str(self.agent_wt))
        self.work(self.agent_wt, lines=80)
        self.note(wal.name)
        self.assertQuiet(self.hook("SubagentStop", cwd=self.home, agent_id=AGENT))

    def test_subagent_checks_only_its_own_worktrees_never_its_cwd(self):
        # native review F5 (goodqa#14908): a subagent that inherits main's cwd (or sits in another
        # owner's tree) must not be blocked for work it does not own
        self.work()  # in self.wt, not under this agent's work folder
        self.assertQuiet(self.hook("SubagentStop", agent_id=AGENT))
        self.assertQuiet(self.hook("SubagentStop", cwd=self.primary, agent_id=AGENT))
        self.assertNudged(self.hook("Stop"))  # the tree is still main's to account for
        self.work(self.agent_wt)
        self.assertNudged(self.hook("SubagentStop", agent_id=AGENT), str(self.agent_wt))

    def test_subagent_without_id_is_quiet(self):
        self.work(self.agent_wt)
        self.assertQuiet(self.hook("SubagentStop", cwd=self.home))


class Install(unittest.TestCase):
    def test_registered_on_stop_and_subagent_stop_fail_open(self):
        sys.path.insert(0, str(ROOT))
        import install
        claude = Path("/h/.claude")
        hooks = install.managed_hooks(claude)
        script = str(claude / "hooks" / "wal_cadence.py")
        for event in ("Stop", "SubagentStop"):
            handlers = [h for g in hooks[event] for h in g["hooks"] if script in (h.get("args") or [])]
            self.assertEqual(len(handlers), 1, event)
            self.assertNotIn("onFailure", handlers[0])
        self.assertIn("wal_cadence.py", install.HOOKS)
        self.assertIn(script, install.managed_scripts(claude))


if __name__ == "__main__":
    unittest.main()
