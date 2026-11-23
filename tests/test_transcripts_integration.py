"""Transcript archive checkpoints and enforcement (GoodQA #16650, spec AC-8, AC-9, AC-12, AC-14, NEG-9, NEG-10).

The core tool (harness/hooks/transcripts.py) is built separately; every test here drives a fake that follows its CLI
contract (tests/transcripts_fake.py) through TRANSCRIPTS_BIN, so nothing reaches GitHub, launchd or systemd.
"""
import argparse
import ast
import io
import json
import os
import plistlib
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stderr
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
HOOKS = ROOT / "harness" / "hooks"
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(HOOKS))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import transcripts_fake  # noqa: E402

FAST = 1.0  # seconds: AC-8, a hook returns in under 1 s (measured in process, without interpreter start-up)
WALL = 3.0  # seconds of subprocess wall time on a loaded host: still well under the fake sync's 5 s sleep


def iso(delta_hours, z=True):
    stamp = (datetime.now(timezone.utc) - timedelta(hours=delta_hours)).replace(microsecond=0)
    text = stamp.isoformat()
    return text.replace("+00:00", "Z") if z else text


class Base(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="transcripts-integ-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.home = self.root / "home"
        self.home.mkdir()
        self.fake = transcripts_fake.write_fake(self.root)
        self.log = self.root / "calls.jsonl"
        self.env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(self.home),
                    "TRANSCRIPTS_BIN": str(self.fake), "FAKE_TRANSCRIPTS_LOG": str(self.log),
                    "PYTHONDONTWRITEBYTECODE": "1"}

    def calls(self, count=1, timeout=5.0):
        return transcripts_fake.wait_for_log(self.log, count, timeout)

    def run_py(self, argv, stdin="", env=None, timeout=30):
        started = time.monotonic()
        done = subprocess.run([sys.executable] + [str(a) for a in argv], input=stdin, capture_output=True, text=True,
                              env={**self.env, **(env or {})}, timeout=timeout, cwd=str(self.root))
        return done, time.monotonic() - started


# ---------------------------------------------------------------- Claude SessionStart

class SessionStartHook(Base):
    HOOK = HOOKS / "transcripts_hook.py"

    def test_source_maps_to_checkpoint_and_returns_fast(self):
        cases = {"startup": "start", "resume": "recovery", "compact": "recovery", "clear": "recovery", "": "start"}
        for source, checkpoint in cases.items():
            with self.subTest(source=source):
                self.log.unlink(missing_ok=True)
                payload = json.dumps({"hook_event_name": "SessionStart", "session_id": "s1", "source": source})
                done, took = self.run_py([self.HOOK, "session-start"], payload, {"FAKE_SYNC_SLEEP": "5"})
                self.assertEqual(done.returncode, 0, done.stderr)
                self.assertLess(took, WALL, "the hook waited for the sync")
                self.assertEqual(done.stdout, "")
                self.assertEqual(self.calls()[-1], ["sync", "--checkpoint", checkpoint, "--background"])

    def test_missing_script_and_bad_input_never_fail_the_session(self):
        for env, stdin in (({"TRANSCRIPTS_BIN": str(self.root / "absent.py")}, '{"source": "startup"}'),
                           ({}, "not json"), ({}, "")):
            with self.subTest(env=env, stdin=stdin):
                done, took = self.run_py([self.HOOK, "session-start"], stdin, env)
                self.assertEqual(done.returncode, 0, done.stderr)
                self.assertLess(took, WALL)
                self.assertEqual(done.stdout, "")

    def test_hook_body_returns_in_under_a_second(self):
        import transcripts_hook  # noqa: PLC0415
        with mock.patch.dict(os.environ, {**self.env, "FAKE_SYNC_SLEEP": "5"}), \
                mock.patch.object(sys, "stdin", io.StringIO('{"source": "resume"}')):
            started = time.monotonic()
            self.assertEqual(transcripts_hook.main(["session-start"]), 0)
            self.assertLess(time.monotonic() - started, FAST)
        self.assertEqual(self.calls()[-1], ["sync", "--checkpoint", "recovery", "--background"])
        with mock.patch.dict(os.environ, {"TRANSCRIPTS_BIN": str(self.root / "absent.py")}):
            started = time.monotonic()
            self.assertFalse(transcripts_hook.spawn_sync("start"))
            self.assertLess(time.monotonic() - started, FAST)

    def test_installer_registers_the_hook(self):
        import install  # noqa: PLC0415
        claude = Path("/h/.claude")
        groups = install.managed_hooks(claude)["SessionStart"]
        found = [h for g in groups for h in g["hooks"]
                 if h.get("args") == [str(claude / "hooks" / "transcripts_hook.py"), "session-start"]]
        self.assertEqual(len(found), 1)
        self.assertLessEqual(found[0]["timeout"], 10)
        self.assertNotIn("onFailure", found[0])  # fails open: never blocks a session
        self.assertIn(str(claude / "hooks" / "transcripts_hook.py"), install.managed_scripts(claude))
        self.assertIn("transcripts_hook.py", install.HOOKS)
        # The core files ship from the core writer's branch; once they exist here the installer must list them
        # (listing an absent file breaks every install, so this guard switches on at merge).
        for name in ("transcripts.py", "transcript_redact.py"):
            if (HOOKS / name).exists():
                self.assertIn(name, install.HOOKS)

    def test_codex_install_ships_the_tool_beside_its_hooks(self):
        tree = ast.parse((ROOT / "install_codex.py").read_text())
        helpers = next(ast.literal_eval(n.value) for n in tree.body if isinstance(n, ast.Assign)
                       and any(getattr(t, "id", "") == "DELIVERY_HELPERS" for t in n.targets))
        for name in ("transcripts.py", "transcript_redact.py"):
            if (HOOKS / name).exists():
                self.assertIn(name, helpers)


# ---------------------------------------------------------------- ah transcripts

class AhPassthrough(Base):
    AH = HOOKS / "ah.py"

    def test_takeover_sync_and_exit_code_pass_through(self):
        done, _ = self.run_py([self.AH, "transcripts", "sync", "--checkpoint", "takeover"])
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertEqual(self.calls()[-1], ["sync", "--checkpoint", "takeover"])
        done, _ = self.run_py([self.AH, "transcripts", "find", "--session", "abc", "--json"], env={"FAKE_ARGV_RC": "7"})
        self.assertEqual(done.returncode, 7)
        self.assertEqual(self.calls(2)[-1], ["find", "--session", "abc", "--json"])
        self.assertIn("fake transcripts find --session abc --json", done.stdout)

    def test_help_documents_takeover_and_recovery(self):
        done, _ = self.run_py([self.AH, "--help"])
        self.assertIn("transcripts", done.stdout)
        done, _ = self.run_py([self.AH, "transcripts", "--help"])
        self.assertEqual(done.returncode, 0)
        self.assertIn("ah transcripts sync --checkpoint takeover", done.stdout)
        self.assertIn("recovery", done.stdout)
        self.assertEqual(transcripts_fake.read_log(self.log), [])  # help is ah's own, never the tool's

    def test_missing_tool_is_one_json_line(self):
        done, _ = self.run_py([self.AH, "transcripts", "status"], env={"TRANSCRIPTS_BIN": str(self.root / "no.py")})
        self.assertEqual(done.returncode, 4)
        self.assertEqual(json.loads(done.stdout)["code"], "missing")


# ---------------------------------------------------------------- wal_note.py --event deploy

class WalNoteDeploy(Base):
    NOTE = HOOKS / "wal_note.py"

    def wal(self):
        return self.home / ".claude" / "wals" / "sess-2" / "main.jsonl"

    def test_deploy_row_spawns_a_detached_sync(self):
        done, took = self.run_py([self.NOTE, "--wal", self.wal(), "--event", "deploy", "--note", "deployed abc1234f live"],
                                 env={"FAKE_SYNC_SLEEP": "5"})
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertLess(took, 3.0)  # interpreter start-up dominates; the sync itself sleeps 5 s
        self.assertEqual(json.loads(done.stdout)["status"], "WROTE")
        self.assertEqual(self.calls()[-1], ["sync", "--checkpoint", "deploy", "--background"])

    def test_other_events_and_failures_never_change_the_result(self):
        done, _ = self.run_py([self.NOTE, "--wal", self.wal(), "--event", "result", "--note", "focused check passed"])
        self.assertEqual(done.returncode, 0, done.stderr)
        time.sleep(0.3)
        self.assertEqual(transcripts_fake.read_log(self.log), [])
        done, _ = self.run_py([self.NOTE, "--wal", self.wal(), "--event", "deploy", "--note", "deployed abc1234f"],
                              env={"TRANSCRIPTS_BIN": str(self.root / "absent.py")})
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(sum(1 for _ in self.wal().read_text().splitlines()), 2)
        # a refused deploy row (no sha) writes nothing and spawns nothing
        done, _ = self.run_py([self.NOTE, "--wal", self.wal(), "--event", "deploy", "--note", "merged"])
        self.assertEqual(done.returncode, 2)
        time.sleep(0.3)
        self.assertEqual(transcripts_fake.read_log(self.log), [])


# ---------------------------------------------------------------- Codex wal.py SessionStart

class CodexSessionStart(Base):
    WAL = ROOT / "codex" / "hooks" / "wal.py"

    def hook(self, source, env=None):
        payload = {"hook_event_name": "SessionStart", "session_id": "codex-1"}
        if source is not None:
            payload["source"] = source
        return self.run_py([self.WAL, "hook"], json.dumps(payload), env)

    def test_source_maps_and_output_is_unchanged(self):
        baseline, _ = self.hook("startup", {"TRANSCRIPTS_BIN": str(self.root / "absent.py")})
        self.assertEqual(baseline.returncode, 0, baseline.stderr)
        for source, checkpoint in (("startup", "start"), ("resume", "recovery"), ("clear", "recovery"), (None, "start")):
            with self.subTest(source=source):
                before = len(transcripts_fake.read_log(self.log))
                done, took = self.hook(source, {"FAKE_SYNC_SLEEP": "5"})
                self.assertEqual(done.returncode, 0, done.stderr)
                self.assertLess(took, 3.0)
                self.assertEqual(done.stdout, baseline.stdout)  # the hook's own output, byte for byte
                self.assertEqual(self.calls(before + 1)[-1], ["sync", "--checkpoint", checkpoint, "--background"])

    def test_other_events_do_not_spawn(self):
        done, _ = self.run_py([self.WAL, "hook"], json.dumps({"hook_event_name": "UserPromptSubmit",
                                                               "session_id": "codex-1", "prompt": "hi"}))
        self.assertEqual(done.returncode, 0, done.stderr)
        time.sleep(0.3)
        self.assertEqual(transcripts_fake.read_log(self.log), [])


# ---------------------------------------------------------------- backfill scheduler

class BackfillScheduler(Base):
    def setUp(self):
        super().setUp()
        import transcripts_install  # noqa: PLC0415
        self.ti = transcripts_install

    def test_units_render(self):
        plist_bytes = dict((p.name, d) for p, d, _m, _u in self.ti.desired_files(self.home, "Darwin"))
        plist = plistlib.loads(plist_bytes[f"{self.ti.LABEL}.plist"])
        self.assertEqual(plist["StartInterval"], 1800)
        self.assertEqual(plist["Nice"], 10)
        args = plist["ProgramArguments"]
        self.assertEqual(args[-4:], [str(self.home / ".claude" / "hooks" / "transcripts.py"), "backfill",
                                     "--budget-seconds", "1500"])
        self.assertNotIn("@HOME@", plist_bytes[f"{self.ti.LABEL}.plist"].decode())
        units = dict((p.name, d.decode()) for p, d, _m, _u in self.ti.desired_files(self.home, "Linux"))
        service, timer = units["transcripts-backfill.service"], units["transcripts-backfill.timer"]
        self.assertIn("Nice=10", service)
        self.assertIn("transcripts.py backfill --budget-seconds 1500", service)
        self.assertRegex(service, r"TimeoutStartSec=(2[6-9]|[3-9]\d)min")  # above the 1500 s budget
        self.assertIn("OnUnitActiveSec=30min", timer)
        for text in [service, timer, plist_bytes[f"{self.ti.LABEL}.plist"].decode()]:
            self.assertNotIn("rcl" + "one", text)  # AC-12: split so a grep of the diff stays clean

    def test_status_is_opt_in_and_uses_the_injected_runner(self):
        calls = []
        runner = lambda argv: calls.append(argv) or 0  # noqa: E731
        out = self.ti.status(self.home, True, system="Linux", run=runner, uid=501, activate=True, enabled=False)
        self.assertIn("not installed", out)
        self.assertEqual(calls, [])
        out = self.ti.status(self.home, False, system="Linux", run=runner, uid=501, activate=True, enabled=True)
        self.assertIn("would", out)
        self.assertFalse((self.home / ".config" / "systemd" / "user" / "transcripts-backfill.timer").exists())
        out = self.ti.status(self.home, True, system="Linux", run=runner, uid=501, activate=True, enabled=True)
        self.assertTrue((self.home / ".config" / "systemd" / "user" / "transcripts-backfill.timer").exists(), out)
        self.assertIn(["systemctl", "--user", "enable", "--now", "transcripts-backfill.timer"], calls)
        calls.clear()
        out = self.ti.status(self.home, True, system="Linux", run=runner, uid=501, activate=True, enabled=True)
        self.assertEqual(calls, [], out)  # unchanged units: no reload
        out = self.ti.status(self.home, True, system="Darwin", run=runner, uid=501, activate=False, enabled=True)
        self.assertTrue((self.home / "Library" / "LaunchAgents" / f"{self.ti.LABEL}.plist").exists(), out)
        self.assertEqual(calls, [])  # non-default home: files only
        self.assertTrue(self.ti.component_installed(self.home))



if __name__ == "__main__":
    unittest.main()
