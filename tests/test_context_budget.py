"""Context budget (context-noise workstream, 2026-11-24): what wal.py and log_backup.py add to a session.

The owner's report: the WAL path, a triage reminder and 120-plus ops alerts arrived on every prompt, sometimes four
times in one turn, and a 273-hour-old log-backup alert repeated at every session start.
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
HOOKS = ROOT / "harness" / "hooks"
WAL = HOOKS / "wal.py"
LOG_BACKUP = HOOKS / "log_backup.py"
sys.path.insert(0, str(HOOKS))
import ops_watch  # noqa: E402

SESSION = "0f8fad5b-d9cb-469f-a165-70867728950e"
OTHER = "aaaabbbb-0000-4000-8000-000000000000"


def seed_alerts(home: Path, n: int = 133) -> None:
    """n active alerts shaped like the real ring: one critical disk alert on this machine, other sessions' silent
    owners, a few machine warnings."""
    host = ops_watch.default_host()
    ops_watch.emit({"host": host, "source": "ops-watch", "event": "raise", "severity": "critical",
                    "key": "disk:volume:/System/Volumes/Data", "message": "98% used, 9 GiB free"}, home=home)
    for i in range(n - 4):
        ops_watch.emit({"host": host, "source": "ops-watch", "event": "raise", "severity": "high",
                        "key": f"liveness:{OTHER[:8]}/agent-a{i:016x}", "message": "owner silent 2h",
                        "detail": {"session": OTHER[:8]}}, home=home)
    for key in ("mem:pressure", "procs:orphans", "runtime:stale"):
        ops_watch.emit({"host": host, "source": "ops-watch", "event": "raise", "severity": "warning",
                        "key": key, "message": "warning text"}, home=home)
    state = ops_watch.load_state(home)
    ops_watch.save_state(home, dict(state, last_run=time.time()))


class Base(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=ROOT / "tests")
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name).resolve()

    def env(self, **extra):
        env = {k: v for k, v in os.environ.items() if not k.startswith(("CLAUDE", "CODEX_"))}
        return {**env, "HOME": str(self.home), "HARNESS_PROVENANCE_OFFLINE": "1", **extra}

    def wal(self, event, data):
        done = subprocess.run([sys.executable, str(WAL), event], input=json.dumps(data), text=True,
                              capture_output=True, env=self.env(), timeout=30)
        self.assertEqual(done.returncode, 0, done.stderr)
        return done.stdout

    @staticmethod
    def context(stdout):
        return json.loads(stdout)["hookSpecificOutput"]["additionalContext"] if stdout.strip() else ""


class PromptBudget(Base):
    def test_second_prompt_emits_nothing_when_nothing_is_new(self):
        seed_alerts(self.home)
        self.wal("session", {"session_id": SESSION, "source": "startup"})
        first = self.wal("prompt", {"session_id": SESSION, "prompt": "first"})
        second = self.wal("prompt", {"session_id": SESSION, "prompt": "second"})
        self.assertEqual(first, "")
        self.assertEqual(second, "")
        # the WAL still records every prompt
        rows = [json.loads(x) for x in (self.home / ".claude/wals" / SESSION / "main.jsonl").read_text().splitlines()]
        self.assertEqual([r["event"] for r in rows], ["session", "prompt", "prompt"])

    def test_a_new_critical_alert_about_this_session_is_shown_once(self):
        seed_alerts(self.home)
        self.wal("session", {"session_id": SESSION, "source": "startup"})
        ops_watch.emit({"host": ops_watch.default_host(), "source": "ops-watch", "event": "raise",
                        "severity": "critical", "key": f"liveness:{SESSION[:8]}/agent-afeed", "message": "owner dropped",
                        "detail": {"session": SESSION[:8]}}, home=self.home)
        # another session's new critical alert is not this session's to act on
        ops_watch.emit({"host": ops_watch.default_host(), "source": "ops-watch", "event": "raise",
                        "severity": "critical", "key": f"liveness:{OTHER[:8]}/agent-bfeed", "message": "owner dropped",
                        "detail": {"session": OTHER[:8]}}, home=self.home)
        text = self.context(self.wal("prompt", {"session_id": SESSION, "prompt": "go"}))
        self.assertIn("agent-afeed", text)
        self.assertNotIn("agent-bfeed", text)
        self.assertLessEqual(len(text), 600)
        self.assertEqual(self.wal("prompt", {"session_id": SESSION, "prompt": "again"}), "")

    def test_no_triage_reminder_or_work_dir_per_prompt(self):
        self.wal("session", {"session_id": SESSION, "source": "startup"})
        out = self.wal("prompt", {"session_id": SESSION, "prompt": "x"})
        self.assertNotIn("triage", out)
        self.assertNotIn("Durable work dir", out)

    def test_a_session_that_missed_its_start_is_told_its_wal_once(self):
        text = self.context(self.wal("prompt", {"session_id": SESSION, "prompt": "x"}))
        self.assertIn("Session WAL:", text)
        self.assertEqual(self.wal("prompt", {"session_id": SESSION, "prompt": "y"}), "")


class SessionStartBudget(Base):
    def test_133_alerts_become_one_short_line(self):
        seed_alerts(self.home)
        text = self.context(self.wal("session", {"session_id": SESSION, "source": "startup"}))
        self.assertLessEqual(len(text), 600)
        ops = text[text.index("Ops alerts"):]
        self.assertIn("133 active (1 critical, 129 high, 3 warning)", ops)
        self.assertIn("ops_watch.py status", ops)
        self.assertIn("[critical] disk:volume", ops)
        self.assertLessEqual(ops.count("[critical]") + ops.count("[high]") + ops.count("[warning]"), 3)
        self.assertNotIn("liveness:", ops)  # other sessions' owners are counted, never listed
        # with a real home's shorter paths there is room for three, never more
        line, ids = ops_watch.session_summary(self.home, SESSION)
        self.assertEqual(len(ids), 133)
        self.assertEqual(line.count("[critical]") + line.count("[high]") + line.count("[warning]"), 3)
        self.assertLessEqual(len(line), 420)

    def test_wal_path_and_work_dir_once_per_start_and_after_compaction(self):
        for source in ("startup", "compact", "resume"):
            text = self.context(self.wal("session", {"session_id": SESSION, "source": source}))
            self.assertIn("Session WAL:", text, source)
            self.assertIn("Durable work dir:", text, source)


class Duplicates(Base):
    def test_duplicate_registrations_in_one_turn_emit_once(self):
        seed_alerts(self.home)
        self.assertTrue(self.wal("session", {"session_id": SESSION, "source": "startup"}))
        self.assertEqual(self.wal("session", {"session_id": SESSION, "source": "startup"}), "")
        ops_watch.emit({"host": ops_watch.default_host(), "source": "ops-watch", "event": "raise",
                        "severity": "critical", "key": f"liveness:{SESSION[:8]}/agent-afeed", "message": "owner dropped",
                        "detail": {"session": SESSION[:8]}}, home=self.home)
        payload = {"session_id": SESSION, "prompt": "same prompt"}
        outputs = [self.wal("prompt", payload) for _ in range(4)]
        self.assertEqual(sum(1 for o in outputs if o.strip()), 1, outputs)

    def test_parallel_registrations_emit_once(self):
        payload = json.dumps({"session_id": SESSION, "source": "startup"})
        procs = [subprocess.Popen([sys.executable, str(WAL), "session"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                  text=True, env=self.env()) for _ in range(4)]
        outs = [p.communicate(payload, timeout=30)[0] for p in procs]
        self.assertEqual(sum(1 for o in outs if o.strip()), 1, outs)


class SubAgents(Base):
    def test_subagent_gets_its_wal_path_once_and_no_alerts(self):
        seed_alerts(self.home)
        data = {"session_id": SESSION, "agent_id": "a1b2c3d4", "agent_type": "task-owner"}
        text = self.context(self.wal("subagent", data))
        self.assertIn("Your private WAL:", text)
        self.assertNotIn("Ops alerts", text)
        self.assertNotIn("OPS ALERTS", text)
        self.assertLessEqual(len(text), 600)
        self.assertEqual(self.wal("subagent", data), "")  # a second registration of the same start

    def test_subagent_prompt_payload_gets_nothing(self):
        seed_alerts(self.home)
        self.wal("session", {"session_id": SESSION, "source": "startup"})
        out = self.wal("prompt", {"session_id": SESSION, "agent_id": "a1b2c3d4", "agent_type": "Explore",
                                  "prompt": "x"})
        self.assertEqual(out, "")


def stamp(epoch):
    return datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class LogBackupAlert(Base):
    def setUp(self):
        super().setUp()
        logs = self.home / ".agent-harness" / "logs"
        logs.mkdir(parents=True)
        (logs / "log-backup.last-ok").write_text(stamp(time.time() - 273 * 3600) + " sources=6\n")
        (logs / "log-backup.bulk-last-ok").write_text(stamp(time.time()) + "\n")
        (logs / "log-backup.log").write_text(
            stamp(time.time() - 60) + " budget reached for .claude/projects (rclone exit 10); partial, last-ok withheld\n")

    def run_lb(self, *args, env=None):
        return subprocess.run([sys.executable, str(LOG_BACKUP), *args], input=b"{}", capture_output=True,
                              env=env or self.env(), timeout=30)

    def test_once_per_24_hours_per_machine(self):
        first = self.run_lb("session-start")
        self.assertEqual(first.returncode, 0)
        text = json.loads(first.stdout)["hookSpecificOutput"]["additionalContext"]
        self.assertIn("273h", text)
        self.assertIn("budget reached for .claude/projects", text)
        self.assertIn("log_backup.py ack", text)
        self.assertEqual(text.count("\n"), 0)
        self.assertLessEqual(len(text), 600)
        self.assertEqual(self.run_lb("session-start").stdout, b"")
        state = self.home / ".agent-harness" / "state" / "log-backup-alert.json"
        data = json.loads(state.read_text())
        data["last_shown"] = time.time() - 25 * 3600
        state.write_text(json.dumps(data))
        self.assertIn(b"LOG BACKUP", self.run_lb("session-start").stdout)

    def test_ack_silences_it(self):
        done = self.run_lb("ack", "--hours", "48", "--reason", "Dropbox throttled; fix tracked")
        self.assertEqual(done.returncode, 0, done.stderr)
        state = self.home / ".agent-harness" / "state" / "log-backup-alert.json"
        data = json.loads(state.read_text())
        self.assertGreater(data["ack_until"], time.time() + 47 * 3600)
        data["last_shown"] = 0
        state.write_text(json.dumps(data))
        self.assertEqual(self.run_lb("session-start").stdout, b"")

    def test_ack_from_an_ordinary_agent_shell_is_refused(self):
        env = self.env(CLAUDECODE="1", CLAUDE_CODE_SESSION_ID=SESSION)
        done = self.run_lb("ack", "--hours", "24", "--reason", "x", env=env)
        self.assertEqual(done.returncode, 3)
        self.assertIn(b"refused", done.stderr)

    def test_ack_from_a_supervisor_session_is_allowed(self):
        (self.home / ".agent-harness" / "roles.json").write_text(json.dumps(
            {"supervisors": {SESSION: {"projects": [], "by": "user", "set_at": "x"}}}))
        env = self.env(CLAUDECODE="1", CLAUDE_CODE_SESSION_ID=SESSION)
        done = self.run_lb("ack", "--hours", "24", "--reason", "known", env=env)
        self.assertEqual(done.returncode, 0, done.stderr)


class Measured(Base):
    """Bytes of context per prompt on the 133-alert fixture (the report quotes these numbers)."""

    def test_bytes_per_prompt(self):
        seed_alerts(self.home)
        start = self.wal("session", {"session_id": SESSION, "source": "startup"})
        prompts = [self.wal("prompt", {"session_id": SESSION, "prompt": f"p{i}"}) for i in range(5)]
        sizes = [len(p.encode()) for p in prompts]
        print(f"\n[measured] SessionStart {len(start.encode())} bytes; per prompt {sizes}", file=sys.stderr)
        self.assertLess(len(start.encode()), 900)
        self.assertEqual(sizes, [0] * 5)


if __name__ == "__main__":
    unittest.main()
