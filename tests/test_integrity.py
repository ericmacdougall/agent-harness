"""harness/hooks/integrity.py: tamper evidence. ssh and gq.py are faked; the mirror program itself really runs (locally,
under a scratch directory). Nothing here reaches dev2, GoodQA or the real ~/.claude."""
import json
import os
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "harness" / "hooks"))
sys.path.insert(0, str(ROOT))
import doctor  # noqa: E402
import install  # noqa: E402
import integrity  # noqa: E402

REAL_RUN = subprocess.run


class FakeMirrors:
    """subprocess.run stand-in: `ssh ... host 'python3 -c PROG --local ...'` runs PROG locally (so the real mirror
    program is tested); gq.py comment/read calls hit an in-memory ticket. `down` makes every call fail."""

    def __init__(self):
        self.comments, self.calls, self.down = [], [], set()

    def __call__(self, argv, input=None, **kw):
        self.calls.append(argv)
        if argv[0] == "ssh":
            if "ssh" in self.down:
                return subprocess.CompletedProcess(argv, 255, "", "unreachable")
            assert "BatchMode=yes" in argv and argv[-2] != "--", argv
            words = shlex.split(argv[-1])
            assert words[:2] == ["python3", "-c"] and words[3] == "--local", words
            return REAL_RUN([sys.executable, "-I", "-S", "-c"] + words[2:], input=input, capture_output=True,
                            text=True, timeout=30)
        if len(argv) > 3 and argv[3] in ("comment_on_issue", "get_issue_comments"):
            if "goodqa" in self.down:
                return subprocess.CompletedProcess(argv, 1, "", "error")
            args = json.loads(argv[4])
            if argv[3] == "comment_on_issue":
                self.comments.append({"body": args["body"], "issueId": args["issueId"]})
                return subprocess.CompletedProcess(argv, 0, json.dumps({"comment": {"id": "c"}}), "")
            return subprocess.CompletedProcess(argv, 0, json.dumps({"comments": self.comments}), "")
        raise AssertionError(f"unexpected command {argv[:4]}")


class Base(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name).resolve()
        self.hooks = self.root / ".claude" / "hooks"
        shutil.copytree(ROOT / "harness" / "hooks", self.hooks, ignore=shutil.ignore_patterns("__pycache__"))
        self.settings = self.root / ".claude" / "settings.json"
        self.settings.write_text(json.dumps({"model": "x", "hooks": {"PreToolUse": [{"matcher": "Bash"}]}}))
        self.mirror_dir = str(self.root / "mirror")
        self.fake = FakeMirrors()
        patcher = mock.patch.object(integrity.subprocess, "run", self.fake)
        patcher.start()
        self.addCleanup(patcher.stop)

    def record(self, **kw):
        return integrity.record(self.hooks, self.settings, self.mirror_dir, host="testhost", **kw)

    def verify(self, **kw):
        return integrity.verify(self.hooks, self.settings, self.mirror_dir, host="testhost", **kw)


class Snapshot(Base):
    def test_snapshot_covers_hooks_holds_files_and_settings_hooks(self):
        files = integrity.snapshot(self.hooks, self.settings)
        for name in install.HOOKS:
            if name not in ("holds.json",):
                self.assertIn(f"hooks:{name}", files, name)
        for key in ("holds.json", "holds.state.json", "settings-hooks", "hooks:integrity.py", "hooks:holds_guard.py"):
            self.assertIn(key, files)
        self.assertIsNone(files["holds.state.json"])  # absent until a lift
        self.assertEqual(len(files["hooks:holds_guard.py"]), 64)

    def test_manifest_integrity_files_list_every_installed_hook_file(self):
        manifest = json.loads((ROOT / "harness" / "hooks" / "hooks_manifest.json").read_text())
        self.assertEqual(sorted(manifest["integrity_files"]), sorted(install.HOOKS))

    def test_settings_digest_ignores_non_hook_settings(self):
        before = integrity.settings_digest(self.settings)
        data = json.loads(self.settings.read_text())
        data["model"] = "other"
        self.settings.write_text(json.dumps(data))
        self.assertEqual(integrity.settings_digest(self.settings), before)
        data["hooks"]["PreToolUse"] = []
        self.settings.write_text(json.dumps(data))
        self.assertNotEqual(integrity.settings_digest(self.settings), before)


class RecordVerify(Base):
    def test_record_then_verify_matches_on_both_mirrors(self):
        rec, results = self.record()
        self.assertEqual(results, {"ssh:dev2": "ok", "goodqa": "ok"})
        line = (Path(self.mirror_dir) / "testhost.jsonl").read_text().strip().splitlines()
        self.assertEqual(json.loads(line[-1])["digest"], rec["digest"])
        self.assertEqual(stat.S_IMODE(os.stat(self.mirror_dir).st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(os.stat(Path(self.mirror_dir) / "testhost.jsonl").st_mode), 0o600)
        self.assertTrue(self.fake.comments[-1]["body"].startswith(integrity.COMMENT_TAG + "\n"))
        self.assertNotIn("key", json.loads(self.fake.comments[-1]["body"].split("\n", 1)[1]))
        result = self.verify()
        self.assertEqual(result["status"], "MATCH", result)

    def test_changed_hook_file_is_listed_with_expected_and_actual(self):
        rec, _ = self.record()
        (self.hooks / "holds_guard.py").write_text("# edited\n")
        result = self.verify()
        self.assertEqual(result["status"], "CHANGED")
        self.assertEqual([c["key"] for c in result["changed"]], ["hooks:holds_guard.py"])
        c = result["changed"][0]
        self.assertEqual(c["expected"], rec["files"]["hooks:holds_guard.py"])
        self.assertEqual(c["actual"], integrity.sha256_file(self.hooks / "holds_guard.py"))

    def test_deleted_file_settings_and_lift_state_changes_are_reported(self):
        self.record()
        (self.hooks / "wal_note.py").unlink()
        (self.hooks / "holds.state.json").write_text('{"lifted": {"yates": {}}}')
        data = json.loads(self.settings.read_text())
        data["hooks"] = {}
        self.settings.write_text(json.dumps(data))
        changed = {c["key"]: c for c in self.verify()["changed"]}
        self.assertEqual(set(changed), {"hooks:wal_note.py", "holds.state.json", "settings-hooks"})
        self.assertIsNone(changed["hooks:wal_note.py"]["actual"])
        self.assertIn("lifted-but-unrecorded", changed["holds.state.json"]["note"])

    def test_a_new_record_after_a_legitimate_change_matches_again(self):
        self.record()
        (self.hooks / "holds.json").write_text("{}")
        self.assertEqual(self.verify()["status"], "CHANGED")
        self.record()
        self.assertEqual(self.verify()["status"], "MATCH")

    def test_unreachable_mirrors_are_unverifiable_not_changed(self):
        self.record()
        self.fake.down = {"ssh", "goodqa"}
        result = self.verify()
        self.assertEqual(result["status"], "UNVERIFIABLE")
        self.assertIn("exit 255", result["reason"])

    def test_one_mirror_is_enough_and_the_newest_record_wins(self):
        self.record()
        (self.hooks / "holds.json").write_text("{}")
        self.fake.down = {"ssh"}
        _, results = self.record()  # only GoodQA got the new record
        self.assertTrue(results["ssh:dev2"].startswith("FAILED"))
        self.fake.down = set()
        result = self.verify()
        self.assertEqual((result["status"], result["mirror"]), ("MATCH", "goodqa"))

    def test_records_of_other_hosts_and_foreign_comments_are_ignored(self):
        self.fake.comments.append({"body": "plain comment"})
        integrity.record(self.hooks, self.settings, self.mirror_dir, host="otherhost")
        self.assertEqual(self.verify()["status"], "UNVERIFIABLE")

    def test_mirror_program_refuses_a_record_for_another_host_and_bad_hosts(self):
        rec = integrity.make_record({"x": "1"}, "a")
        r = REAL_RUN(integrity.local_argv("append", self.mirror_dir, "b"), input=json.dumps(rec), capture_output=True,
                     text=True, timeout=30)
        self.assertEqual(r.returncode, 65)
        for bad in ("../x", ".hidden", "a/b"):
            r = REAL_RUN(integrity.local_argv("append", self.mirror_dir, bad), input=json.dumps(rec),
                         capture_output=True, text=True, timeout=30)
            self.assertEqual(r.returncode, 64, bad)
        with self.assertRaises(integrity.MirrorError):
            integrity.ssh_argv("-oProxyCommand=x", "append", "/tmp", "h", 8)

    def test_ssh_call_shape_bounded_and_marked_local(self):
        argv = integrity.ssh_argv("dev2", "latest", "~/.agent-harness/integrity", "Mac-2", 8)
        self.assertEqual(argv[:6], ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", "--"])
        self.assertIn(" --local latest ", argv[-1])


class Cli(Base):
    def main(self, *args):
        argv = ["--hooks-dir", str(self.hooks), "--settings", str(self.settings), "--mirror-dir", self.mirror_dir,
                "--host-label", "testhost", *args]
        with mock.patch.object(integrity, "agent_home", lambda: self.root / "agent-harness"):
            return integrity.main(argv)

    def test_exit_code_contract(self):
        self.assertEqual(self.main("verify"), 0)  # no record yet: UNVERIFIABLE is a warning, exit 0
        self.assertEqual(self.main("record"), 0)
        self.assertEqual(self.main("verify", "--alert"), 0)
        (self.hooks / "holds.py").write_text("# edited\n")
        self.assertEqual(self.main("verify", "--alert"), 1)
        self.fake.down = {"ssh", "goodqa"}
        self.assertEqual(self.main("verify", "--alert"), 0)
        self.assertEqual(self.main("record"), 1)  # no mirror took the record

    def test_alert_delivery_failure_is_surfaced(self):
        self.main("record")
        (self.hooks / "holds.py").write_text("# edited\n")
        with mock.patch.object(integrity, "deliver", side_effect=OSError("ring full")):
            self.assertEqual(self.main("verify", "--alert"), 1)  # CHANGED stays 1 (the raise is retried next run)
        self.assertEqual(self.main("verify", "--alert"), 1)  # delivered now (reserve file)
        (self.hooks / "holds.py").write_text((ROOT / "harness" / "hooks" / "holds.py").read_text())
        with mock.patch.object(integrity, "deliver", side_effect=OSError("ring full")):
            self.assertEqual(self.main("verify", "--alert"), 3)  # MATCH, but the clear could not be delivered


class Alerts(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.home = Path(tmp.name).resolve() / "agent-harness"
        self.hooks = Path(tmp.name).resolve() / "hooks"
        self.hooks.mkdir()
        self.sent = []

    def changed(self, *keys, n=1):
        return {"status": "CHANGED", "host": "h1", "mirror": "dev2", "recorded_at": "t",
                "changed": [{"key": k, "expected": "a" * 64, "actual": "b" * 64} for k in keys] * n}

    def alert(self, result):
        return integrity.alert(result, self.hooks, self.home, self.sent.append)

    def test_schema_fields_and_stable_keys(self):
        self.alert(self.changed("hooks:holds_guard.py", "holds.json", "holds.state.json", "settings-hooks"))
        self.assertEqual([e["key"] for e in self.sent], ["hooks:holds_guard.py", "holds.json", "holds.state.json",
                                                         "settings-hooks"])
        for e in self.sent:
            self.assertEqual({"schema", "at", "host", "source", "event", "severity", "key", "message", "detail"}, set(e))
            self.assertEqual((e["schema"], e["source"], e["event"], e["severity"], e["host"]),
                             (1, "harness-integrity", "raise", "high", "h1"))
            self.assertTrue(e["at"].endswith("+00:00"))
            self.assertLessEqual(len(e["message"]), 512)
            self.assertLessEqual(len(json.dumps(e["detail"]).encode()), 4096)

    def test_transition_only_raise_then_clear(self):
        self.alert(self.changed("holds.json"))
        self.alert(self.changed("holds.json"))  # hourly repeat: nothing new
        self.assertEqual([(e["event"], e["key"]) for e in self.sent], [("raise", "holds.json")])
        self.alert({"status": "MATCH", "host": "h1", "mirror": "dev2", "changed": []})
        self.assertEqual(self.sent[-1]["event"], "clear")
        self.assertEqual((self.sent[-1]["severity"], self.sent[-1]["message"]), ("info", "cleared"))
        n = len(self.sent)
        self.alert({"status": "MATCH", "host": "h1", "mirror": "dev2", "changed": []})
        self.assertEqual(len(self.sent), n)

    def test_unverifiable_warns_once_and_rises_to_high(self):
        unv = {"status": "UNVERIFIABLE", "host": "h1", "reason": "ssh dev2 read exit 255", "changed": []}
        self.alert(unv)
        self.alert(unv)
        self.assertEqual([(e["key"], e["severity"]) for e in self.sent], [("mirror", "warning")])
        self.alert(self.changed("holds.json"))
        self.assertEqual([(e["event"], e["key"]) for e in self.sent[1:]], [("raise", "holds.json"), ("clear", "mirror")])

    def test_limits_and_safe_text(self):
        big = self.changed("hooks:x.py", n=200)
        ev = integrity.alert_event("raise", "high", "k", "line1\nline2\x1b[31m" + "m" * 900, {"changed": big["changed"]}, "h")
        self.assertLessEqual(len(ev["message"]), 512)
        self.assertNotRegex(ev["message"], r"[\x00-\x1f]")
        self.assertLessEqual(len(json.dumps(ev["detail"]).encode()), 4096)
        self.assertTrue(ev["detail"]["truncated"])

    def test_fallback_delivery_writes_the_reserve_file_privately(self):
        ev = integrity.alert_event("raise", "high", "holds.json", "m", {}, "h1")
        self.assertEqual(integrity.deliver(ev, self.hooks, self.home), "reserve")
        path = self.home / "reserve" / "alerts-in.jsonl"
        self.assertEqual(json.loads(path.read_text().splitlines()[-1])["key"], "holds.json")
        self.assertEqual(stat.S_IMODE(os.stat(path.parent).st_mode), 0o700)
        self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o600)
        self.assertFalse((self.home / "state" / "alerts.jsonl").exists())  # the ring is never written directly

    def test_ops_watch_writer_is_used_when_installed(self):
        (self.hooks / "ops_watch.py").write_text(
            "import json\nSENT = []\ndef emit(event, home=None):\n    SENT.append(event)\n    return 7\n")
        sys.modules.pop("ops_watch", None)
        self.addCleanup(sys.modules.pop, "ops_watch", None)
        self.addCleanup(lambda: str(self.hooks) in sys.path and sys.path.remove(str(self.hooks)))
        ev = integrity.alert_event("raise", "high", "holds.json", "m", {}, "h1")
        self.assertEqual(integrity.deliver(ev, self.hooks, self.home), "ops_watch")
        import ops_watch
        self.assertEqual(ops_watch.SENT, [ev])
        self.assertFalse((self.home / "reserve").exists())


class DoctorRow(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.hooks = Path(tmp.name)
        (self.hooks / "integrity.py").write_text("")
        self.manifest = json.loads(doctor.MANIFEST.read_text())

    def run_with(self, result):
        fake = lambda argv, **kw: subprocess.CompletedProcess(argv, 1 if result["status"] == "CHANGED" else 0,  # noqa: E731
                                                              json.dumps(result), "")
        return doctor.check_integrity(self.manifest, self.hooks, "/x/settings.json", run=fake)

    def test_changed_fails_unverifiable_warns_match_passes(self):
        changed = self.run_with({"status": "CHANGED", "changed": [{"key": "holds.json"}]})
        self.assertEqual((changed[0]["state"], doctor.verdict(changed)), ("CHANGED", 1))
        self.assertIn("holds.json", changed[0]["detail"])
        unv = self.run_with({"status": "UNVERIFIABLE", "reason": "ssh"})
        self.assertEqual((unv[0]["state"], doctor.verdict(unv)), ("UNVERIFIABLE", 0))
        ok = self.run_with({"status": "MATCH", "mirror": "dev2"})
        self.assertEqual((ok[0]["state"], doctor.verdict(ok)), (doctor.WIRED, 0))

    def test_garbage_output_is_unverifiable_and_missing_script_fails_where_b1_is_installed(self):
        bad = doctor.check_integrity(self.manifest, self.hooks, "/x", run=lambda argv, **kw: subprocess.CompletedProcess(argv, 0, "nope", ""))
        self.assertEqual(bad[0]["state"], "UNVERIFIABLE")
        (self.hooks / "integrity.py").unlink()
        self.assertEqual(doctor.verdict(doctor.check_integrity(self.manifest, self.hooks, "/x")), 0)
        (self.hooks / "holds_guard.py").write_text("")
        self.assertEqual(doctor.verdict(doctor.check_integrity(self.manifest, self.hooks, "/x")), 1)

    def test_doctor_runs_verify_isolated_with_the_hooks_dir(self):
        seen = []
        doctor.check_integrity(self.manifest, self.hooks, "/x/settings.json",
                               run=lambda argv, **kw: seen.append(argv) or subprocess.CompletedProcess(argv, 0, "{}", ""))
        self.assertEqual(seen[0][:3], ["python3", "-I", "-S"])
        self.assertIn("--hooks-dir", seen[0])
        self.assertEqual(seen[0][-2:], ["verify", "--json"])


class InstallerRecords(unittest.TestCase):
    def test_install_runs_record_and_a_failure_only_warns(self):
        home = install.real_home()  # injected runner only: nothing real runs
        seen = []
        ok = install.integrity_status(home, True, run=lambda argv, **kw: seen.append(argv) or
                                      subprocess.CompletedProcess(argv, 0, "RECORDED host=x", ""))
        self.assertIn("RECORDED", ok)
        self.assertEqual(seen[0][1:3], ["-I", "-S"])
        self.assertTrue(seen[0][3].endswith(".claude/hooks/integrity.py") and seen[0][4] == "record")
        bad = install.integrity_status(home, True, run=lambda argv, **kw: subprocess.CompletedProcess(argv, 1, "x", ""))
        self.assertIn("WARNING", bad)
        self.assertIn("would record", install.integrity_status(home, False))

    def test_a_trial_home_is_skipped(self):
        with tempfile.TemporaryDirectory() as d:
            seen = []
            out = install.integrity_status(Path(d), True, run=lambda argv, **kw: seen.append(argv))
        self.assertEqual(seen, [])
        self.assertIn("skipped", out)


if __name__ == "__main__":
    unittest.main()
