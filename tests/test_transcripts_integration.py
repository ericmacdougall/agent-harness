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


# ---------------------------------------------------------------- deliver.py prepare

class DeliverGate(Base):
    def setUp(self):
        super().setUp()
        patcher = mock.patch.dict(os.environ, self.env)
        patcher.start()
        self.addCleanup(patcher.stop)
        import deliver  # noqa: PLC0415
        self.deliver = deliver
        self.wal = self.home / ".claude" / "wals" / "sess-1" / "main.jsonl"

    def args(self, **kw):
        base = {"wal": None, "transcripts_waiver": None, "task": "fixture"}
        base.update(kw)
        return argparse.Namespace(**base)

    def check_json(self, status, last_ok_at, rc=0, **extra):
        os.environ["FAKE_CHECK_JSON"] = json.dumps({"status": status, "last_ok_at": last_ok_at, "age_min": None,
                                                    "reasons": [status], **extra})
        os.environ["FAKE_CHECK_RC"] = str(rc)

    def gate(self, args=None):
        err = io.StringIO()
        with redirect_stderr(err):
            result = self.deliver.transcripts_gate(args or self.args())
        return result, err.getvalue()

    def refused(self, args=None):
        err = io.StringIO()
        with redirect_stderr(err), self.assertRaises(self.deliver.DeliveryError) as caught:
            self.deliver.transcripts_gate(args or self.args())
        self.assertEqual((caught.exception.status, caught.exception.code), ("BLOCKED_POLICY", 2))
        self.assertEqual(caught.exception.facts.get("reason"), "TRANSCRIPTS_RECEIPT")
        return caught.exception, err.getvalue()

    def wal_rows(self):
        try:
            return [json.loads(x) for x in self.wal.read_text().splitlines()]
        except FileNotFoundError:
            return []

    def test_deliver_refuses_without_receipt(self):
        self.check_json("never-ok", None, rc=3)
        error, _ = self.refused()
        self.assertIn("transcript archive receipt", error.message)
        self.assertIn("ah transcripts sync --checkpoint pr", error.facts.get("hint", ""))
        self.assertEqual(self.calls(2)[:2], [["sync", "--checkpoint", "pr", "--budget-seconds", "90"],
                                             ["check", "--json"]])

    def test_refuses_when_last_ok_is_over_24h(self):
        self.check_json("stale", iso(25), rc=1)
        self.refused()

    def test_deliver_warns_on_stale(self):
        self.check_json("stale", iso(2), rc=1)
        result, err = self.gate(self.args(wal=self.wal))
        self.assertIn("stale", err)
        self.assertEqual(result["status"], "stale")
        risk = [r for r in self.wal_rows() if r.get("event") == "risk"]
        self.assertEqual(len(risk), 1)
        self.assertIn("transcript", risk[0]["note"])

    def test_warns_on_held_and_cap_and_passes_quietly_when_fresh(self):
        for status in ("held", "cap"):
            with self.subTest(status=status):
                self.check_json(status, iso(1), rc=2)
                _, err = self.gate()
                self.assertIn(status, err)
        # the core's own shape: held and omission caps come back as status failed with the reason listed
        os.environ["FAKE_CHECK_JSON"] = json.dumps({"status": "failed", "last_ok_at": iso(1), "age_min": 60.0,
                                                    "reasons": ["held=2", "omission-cap: 0.7%"], "exit": 2})
        _, err = self.gate()
        self.assertIn("held=2", err)
        self.assertIn("omission-cap", err)
        self.check_json("ok", iso(0.2, z=False), rc=0)
        _, err = self.gate()
        self.assertEqual([l for l in err.splitlines() if "TRANSCRIPTS_BIN is set" not in l], [])
        self.assertIn("TRANSCRIPTS_BIN is set", err)  # the override is never silent

    def test_network_failure_refuses_only_when_last_ok_is_also_old(self):
        os.environ["FAKE_SYNC_RC"] = "1"
        self.check_json("failed", iso(3), rc=2)
        _, err = self.gate()
        self.assertIn("sync", err)
        self.check_json("failed", iso(30), rc=2)
        self.refused()

    def test_unreadable_or_impossible_receipts_refuse(self):
        for status, last in (("ok", None), ("ok", "yesterday"), ("ok", iso(-3))):
            with self.subTest(last=last):
                self.check_json(status, last)
                self.refused()
        os.environ["FAKE_CHECK_JSON"] = "not json"
        self.refused()

    def test_missing_tool_refuses(self):
        os.environ["TRANSCRIPTS_BIN"] = str(self.root / "absent.py")
        error, _ = self.refused()
        self.assertIn("not installed", error.message)

    def test_sync_that_hangs_is_killed_at_the_timeout_and_treated_as_failed(self):
        os.environ["FAKE_SYNC_SLEEP"] = "60"
        self.check_json("ok", iso(0.5))
        started = time.monotonic()
        with mock.patch.object(self.deliver, "TRANSCRIPTS_SYNC_TIMEOUT", 1):
            result, err = self.gate()
        self.assertLess(time.monotonic() - started, 10)
        self.assertIn("sync", err)
        self.assertIn("timed out", err)
        self.assertTrue(result["sync_failed"])
        self.check_json("ok", iso(26))
        with mock.patch.object(self.deliver, "TRANSCRIPTS_SYNC_TIMEOUT", 1):
            self.refused()

    def test_check_that_hangs_is_killed_and_refuses(self):
        os.environ["FAKE_CHECK_SLEEP"] = "60"
        self.check_json("ok", iso(0.5))
        started = time.monotonic()
        with mock.patch.object(self.deliver, "TRANSCRIPTS_CHECK_TIMEOUT", 1):
            self.refused()
        self.assertLess(time.monotonic() - started, 10)

    def test_waiver_proceeds_and_is_recorded(self):
        self.check_json("never-ok", None, rc=3)
        reason = "GitHub archive repos not created on this host yet"
        result, err = self.gate(self.args(wal=self.wal, transcripts_waiver=reason))
        self.assertTrue(result["waived"])
        self.assertIn("waiver", err)
        rows = [r for r in self.wal_rows() if r.get("event") == "decision"]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["transcripts_waiver"]["reason"], reason)
        self.assertEqual(rows[0]["transcripts_waiver"]["status"], "never-ok")
        counted = (self.home / ".agent-harness" / "transcripts" / "waivers.jsonl").read_text().splitlines()
        self.assertEqual(len(counted), 1)  # `ah transcripts status` counts this file
        self.assertEqual(json.loads(counted[0])["wal_row"], rows[0]["id"])
        import ops_watch  # noqa: PLC0415
        ring = ops_watch.read_ring(ops_watch.ring_path(self.home))
        keys = [(e["key"], e["severity"], e["event"]) for e in ring]
        self.assertIn(("transcripts-waiver:fixture", "high", "raise"), keys)
        self.assertTrue(any(k.startswith("transcripts-waiver:") for k in ops_watch.defaults("h")["point_events"]["prefixes"]))

    def test_waiver_that_cannot_be_recorded_refuses(self):
        self.check_json("never-ok", None, rc=3)
        bad = self.root / "not-a-wal.jsonl"
        self.refused(self.args(wal=bad, transcripts_waiver="a perfectly long reason"))

    def test_waiver_flag_is_validated(self):
        base = ["deliver.py", "prepare", "--task", "t", "--original", "/x", "--original-branch", "main"]
        for extra in (["--transcripts-waiver", "too short", "--wal", str(self.wal)],
                      ["--transcripts-waiver", "long enough reason here"],
                      ["--transcripts-waiver", "token=" + "a" * 30, "--wal", str(self.wal)],
                      ["--transcripts-waiver", "bad\x07control chars", "--wal", str(self.wal)]):
            with self.subTest(extra=extra[:2]), mock.patch.object(sys, "argv", base + extra), \
                    redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                self.deliver.parse_args()
        with mock.patch.object(sys, "argv", base + ["--transcripts-waiver", "long enough reason here",
                                                    "--wal", str(self.wal)]):
            self.assertEqual(self.deliver.parse_args().transcripts_waiver, "long enough reason here")

    def test_waiver_refused_when_the_credential_scan_cannot_run(self):
        """Gate F3 (PR #316): no scanner, or a scanner error, refuses the waiver; it never writes it unscanned."""
        base = ["deliver.py", "prepare", "--task", "t", "--original", "/x", "--original-branch", "main",
                "--transcripts-waiver", "long enough reason here", "--wal", str(self.wal)]

        class Broken:
            @staticmethod
            def has_secret(_text):
                raise RuntimeError("scanner broke")

        for case, module in (("missing", None), ("raises", Broken)):
            with self.subTest(case=case), mock.patch.dict(sys.modules, {"redact": module}), \
                    mock.patch.object(sys, "argv", base), redirect_stderr(io.StringIO()) as err, \
                    self.assertRaises(SystemExit):
                self.deliver.parse_args()
            self.assertIn("credential scan", err.getvalue())
        with mock.patch.object(sys, "argv", base):  # the scanner is back: the same waiver passes
            self.assertEqual(self.deliver.parse_args().transcripts_waiver, "long enough reason here")

    def test_prepare_runs_the_gate_before_publishing_and_skips_local_only(self):
        class Gate(Exception):
            pass

        class Entered(Exception):
            pass

        args = argparse.Namespace(reconcile_only=False, original=None, original_branch=None, scan=None,
                                  local_only=False, pr_title="t", pr_body_file=Path("/b"), wal=None,
                                  transcripts_waiver=None, task="fixture")
        with mock.patch.object(self.deliver, "source_inputs", return_value=(Path("/s"), "b", "h", "o", "k")), \
                mock.patch.object(self.deliver, "checked_body", return_value=b"body"), \
                mock.patch.object(self.deliver, "valid_identity_text", return_value=True), \
                mock.patch.object(self.deliver, "matching_origins", return_value=("o/r", "url")), \
                mock.patch.object(self.deliver, "Workflow", side_effect=Entered), \
                mock.patch.object(self.deliver, "transcripts_gate", side_effect=Gate) as gate:
            with self.assertRaises(Gate):
                self.deliver.prepare(args)
            args.local_only = True
            with self.assertRaises(Entered):
                self.deliver.prepare(args)
            self.assertEqual(gate.call_count, 1)


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


# ---------------------------------------------------------------- AC-8: every checkpoint fires

class HookPointsFire(Base):
    def test_hook_points_fire(self):
        self.run_py([HOOKS / "transcripts_hook.py", "session-start"], '{"source": "startup"}')
        self.run_py([HOOKS / "transcripts_hook.py", "session-start"], '{"source": "resume"}')
        self.run_py([HOOKS / "ah.py", "transcripts", "sync", "--checkpoint", "takeover"])
        wal = self.home / ".claude" / "wals" / "sess-3" / "main.jsonl"
        self.run_py([HOOKS / "wal_note.py", "--wal", wal, "--event", "deploy", "--note", "released v1.2.3"])
        with mock.patch.dict(os.environ, {**self.env, "FAKE_CHECK_JSON": json.dumps({"status": "ok",
                                                                                     "last_ok_at": iso(0.1)})}):
            import deliver  # noqa: PLC0415
            deliver.transcripts_gate(argparse.Namespace(wal=None, transcripts_waiver=None, task="t"))
        rows = self.calls(6)
        fired = {r[r.index("--checkpoint") + 1] for r in rows if r and r[0] == "sync"}
        self.assertEqual(fired, {"start", "recovery", "takeover", "deploy", "pr"})


# ---------------------------------------------------------------- AC-14: WAL size alarm

class WalSizeAlarm(Base):
    def setUp(self):
        super().setUp()
        import ops_watch  # noqa: PLC0415
        self.ow = ops_watch
        self.cfg = ops_watch.load_config(self.home, host="testhost", overrides={})

    def sparse(self, path, mib):
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "wb") as handle:
            handle.truncate(mib * 1024 * 1024)
        return path

    def test_wal_size_alarm(self):
        big = self.sparse(self.home / ".claude" / "wals" / "s1" / "main.jsonl", 41)
        self.sparse(self.home / ".claude" / "wals" / "s1" / "agent-x.jsonl", 39)
        codex = self.sparse(self.home / ".agent-harness" / "codex-wals" / "c1" / "main.jsonl", 45)
        self.assertIn("wal_size", self.ow.DEFAULT_CHECKS)
        alerts = self.ow.DEFAULT_CHECKS["wal_size"](self.cfg, {}, None, time.time())
        self.assertEqual(len(alerts), 2)
        self.assertEqual({a["severity"] for a in alerts}, {"high"})
        text = " ".join(a["message"] for a in alerts)
        self.assertIn("s1/main.jsonl", text)
        self.assertIn("c1/main.jsonl", text)
        self.assertNotIn("agent-x", text)
        keys = {a["key"] for a in alerts}
        again = {a["key"] for a in self.ow.DEFAULT_CHECKS["wal_size"](self.cfg, {}, None, time.time())}
        self.assertEqual(keys, again)  # one stable key per file
        big.unlink()
        codex.unlink()
        self.assertEqual(self.ow.DEFAULT_CHECKS["wal_size"](self.cfg, {}, None, time.time()), [])

    def test_symlinks_are_not_followed_and_missing_roots_are_quiet(self):
        self.assertEqual(self.ow.DEFAULT_CHECKS["wal_size"](self.cfg, {}, None, time.time()), [])
        target = self.sparse(self.root / "elsewhere" / "huge.jsonl", 50)
        link = self.home / ".claude" / "wals" / "s2" / "main.jsonl"
        link.parent.mkdir(parents=True)
        link.symlink_to(target)
        (self.home / ".claude" / "wals" / "linked").symlink_to(target.parent, target_is_directory=True)
        self.assertEqual(self.ow.DEFAULT_CHECKS["wal_size"](self.cfg, {}, None, time.time()), [])


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


# ---------------------------------------------------------------- AC-9: rule text

class RuleText(unittest.TestCase):
    SOURCES = (ROOT / "HARNESS.md", ROOT / "codex" / "AGENTS.md", ROOT / "codex" / "skills" / "agent-harness" / "SKILL.md")

    def test_three_rule_sources_carry_the_rule(self):
        for path in self.SOURCES:
            text = path.read_text()
            with self.subTest(file=path.name):
                self.assertRegex(text, r"ah(?:\.py)? transcripts sync --checkpoint <?start\|takeover\|recovery\|pr\|deploy>?")
                self.assertIn("transcripts check", text)
                self.assertRegex(text, r"transcripts find`?/`?cat`?/`?recover")
                self.assertRegex(text, r"(?i)incomplete without a fresh sync receipt")
                self.assertRegex(text, r"(?i)byte-identical to the redacted archive")
                self.assertRegex(text, r"(?i)never treat it as secret-free")
                self.assertRegex(text, r"(?i)never edit or delete source transcripts")
                self.assertRegex(text, r"(?i)untrusted")


if __name__ == "__main__":
    unittest.main()
