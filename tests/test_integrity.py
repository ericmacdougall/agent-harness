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
import time
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
        self.assertEqual(argv[:5], ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8"])
        self.assertIn("ServerAliveInterval=5", argv)
        self.assertEqual(argv[-3], "--")
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


class PagedGoodQA:
    """get_issue_comments as measured on the live API 2026-11-05: order=desc pages newest first, the comments inside a
    page run oldest to newest, nextCursor/hasMore page on. Without order=desc it serves oldest first."""

    def __init__(self, comments, page=20):
        self.comments, self.page, self.reads = comments, page, []

    def __call__(self, argv, input=None, **kw):
        if argv[0] == "ssh":
            return subprocess.CompletedProcess(argv, 255, "", "unreachable")
        args = json.loads(argv[4])
        self.reads.append(args)
        rows = list(reversed(self.comments)) if args.get("order") == "desc" else list(self.comments)
        size = min(args.get("limit", self.page), self.page)
        start = int(args.get("cursor") or 0)
        chunk, more = rows[start:start + size], start + size < len(rows)
        if args.get("order") == "desc":
            chunk = list(reversed(chunk))
        return subprocess.CompletedProcess(argv, 0, json.dumps(
            {"comments": chunk, "hasMore": more, "nextCursor": str(start + size) if more else None}), "")


class GoodQAPaging(Base):
    """Review item 2: after enough records the first page of the ticket is not where the newest record is."""

    def records(self, n, host="testhost", final=None):
        out = []
        for i in range(n):
            files = dict(final or {}) if i == n - 1 else {"holds.json": f"old{i}"}
            rec = {"schema": 1, "host": host, "at": f"2026-11-05T00:{i // 60:02d}:{i % 60:02d}+00:00", "digest": "d", "files": files}
            out.append({"id": f"c{i}", "createdAt": rec["at"], "archivedAt": None,
                        "body": f"{integrity.COMMENT_TAG}\n{json.dumps(rec)}"})
        return out

    def verify_with(self, fake):
        with mock.patch.object(integrity.subprocess, "run", fake):
            return self.verify()

    def current(self):
        return integrity.snapshot(self.hooks, self.settings)

    def test_thirty_one_records_over_twenty_per_page_with_ssh_down_match_the_newest(self):
        fake = PagedGoodQA(self.records(31, final=self.current()))
        result = self.verify_with(fake)
        self.assertEqual((result["status"], result["mirror"]), ("MATCH", "goodqa"), result)
        self.assertEqual(fake.reads[0]["order"], "desc")
        self.assertEqual(len(fake.reads), 1, "the newest page holds the newest record")

    def test_records_of_another_host_on_the_first_page_turn_the_page(self):
        mine = self.records(1, final=self.current())
        theirs = self.records(25, host="other")
        fake = PagedGoodQA(mine + theirs)
        result = self.verify_with(fake)
        self.assertEqual(result["status"], "MATCH", result)
        self.assertEqual([r.get("cursor") for r in fake.reads], [None, "20"])

    def test_an_archived_record_does_not_count(self):
        comments = self.records(2, final=self.current())
        comments[-1]["archivedAt"] = "2026-11-05T01:00:00Z"
        result = self.verify_with(PagedGoodQA(comments))
        self.assertEqual(result["status"], "CHANGED")

    def test_running_out_of_pages_or_a_bad_page_is_unverifiable_never_a_stale_change(self):
        with mock.patch.object(integrity, "GQ_MAX_PAGES", 1):
            result = self.verify_with(PagedGoodQA(self.records(1) + self.records(25, host="other")))
        self.assertEqual(result["status"], "UNVERIFIABLE", result)
        for stdout in ("not json", "[]", '{"comments": 3}', '{"comments": ["x"]}', "{}"):
            fake = lambda argv, input=None, stdout=stdout, **kw: (  # noqa: E731
                subprocess.CompletedProcess(argv, 255, "", "") if argv[0] == "ssh" else subprocess.CompletedProcess(argv, 0, stdout, ""))
            self.assertEqual(self.verify_with(fake)["status"], "UNVERIFIABLE", stdout)

    def test_comment_reply_must_be_json_with_a_comment_id(self):
        for stdout, ok in (('{"comment": {"id": "c1"}}', True), ('{"error": "the \\"comment\\" field"}', False),
                           ('"comment"', False), ("oops \"comment\"", False), ('{"comment": {}}', False), ('{"comment": 1}', False)):
            run = lambda argv, input=None, stdout=stdout, **kw: subprocess.CompletedProcess(argv, 0, stdout, "")  # noqa: E731
            goodqa = {"issue_id": "x", "gq": "/nonexistent"}
            if ok:
                self.assertEqual(integrity.goodqa_append(goodqa, {"host": "h"}, run), "ok")
            else:
                with self.assertRaises(integrity.MirrorError, msg=stdout):
                    integrity.goodqa_append(goodqa, {"host": "h"}, run)


class GoodQAReplySize(Base):
    def test_the_reply_limit_holds_a_reply_that_echoes_the_record(self):
        """Found on the live API: gq.py cuts its output at maxchars, and a cut reply is not JSON though the post worked."""
        rec = integrity.make_record(integrity.snapshot(self.hooks, self.settings), "h")

        def echo(argv, input=None, **kw):
            body = json.loads(argv[4])["body"]
            return subprocess.CompletedProcess(argv, 0, json.dumps({"comment": {"id": "c", "body": body}})[:int(argv[5])], "")
        self.assertEqual(integrity.goodqa_append({"issue_id": "x"}, rec, echo), "ok")


class OverallBudget(Base):
    """Review item 3: the deadman allows 60 s; ssh and GoodQA must not add up past it."""

    def clocked(self, fn):
        """A simulated clock: a hanging call costs its whole timeout. Returns (result, timeouts given)."""
        now, spent = [1000.0], []

        def hang(argv, input=None, timeout=None, **kw):
            spent.append(timeout)
            now[0] += timeout
            raise subprocess.TimeoutExpired(argv, timeout)
        with mock.patch.object(integrity.subprocess, "run", hang), mock.patch.object(integrity.time, "monotonic", lambda: now[0]):
            result = fn()
        return result, spent, now[0] - 1000.0

    def test_verify_with_everything_hanging_is_unverifiable_inside_the_budget(self):
        result, spent, elapsed = self.clocked(self.verify)
        self.assertEqual(result["status"], "UNVERIFIABLE")
        self.assertLessEqual(elapsed, integrity.BUDGET_S)
        self.assertLess(integrity.BUDGET_S, 50)
        self.assertEqual(len(spent), 2, "one ssh and one GoodQA call")

    def test_record_with_everything_hanging_stays_inside_the_budget(self):
        (rec, results), spent, elapsed = self.clocked(self.record)
        self.assertLessEqual(elapsed, integrity.BUDGET_S)
        self.assertTrue(all(v.startswith("FAILED") for v in results.values()), results)

    def test_dead_ssh_mirrors_leave_time_for_goodqa(self):
        policy = json.loads((self.hooks / "integrity_policy.json").read_text())
        policy["mirrors"] = [{"kind": "ssh", "host": f"m{i}", "dir": "d"} for i in range(4)]
        (self.hooks / "integrity_policy.json").write_text(json.dumps(policy))
        result, spent, elapsed = self.clocked(self.verify)
        self.assertLessEqual(elapsed, integrity.BUDGET_S)
        self.assertGreaterEqual(spent[-1], integrity.GQ_CALL_S, spent)

    def test_a_spent_budget_makes_no_further_call(self):
        calls = []
        budget = integrity.Budget(0)
        with self.assertRaises(integrity.MirrorError):
            integrity.goodqa_latest({"issue_id": "x"}, "h", lambda *a, **k: calls.append(a), budget)
        self.assertEqual(calls, [])

    def test_real_hanging_stubs_end_unverifiable_with_exit_zero(self):
        bin_dir = self.root / "bin"
        bin_dir.mkdir()
        (bin_dir / "ssh").write_text("#!/bin/sh\nexec sleep 30\n")
        (bin_dir / "ssh").chmod(0o755)
        gq = self.root / "gq.py"
        gq.write_text("import time\ntime.sleep(30)\n")
        policy = json.loads((self.hooks / "integrity_policy.json").read_text())
        policy["goodqa"]["gq"] = str(gq)
        (self.hooks / "integrity_policy.json").write_text(json.dumps(policy))
        env = {"PATH": f"{bin_dir}:{os.environ['PATH']}"}
        start = time.monotonic()
        with mock.patch.object(integrity.subprocess, "run", REAL_RUN), mock.patch.dict(os.environ, env), \
                mock.patch.object(integrity, "BUDGET_S", 2.0), mock.patch.object(integrity, "SSH_CALL_S", 1), \
                mock.patch.object(integrity, "GQ_CALL_S", 1), mock.patch.object(integrity, "GQ_RESERVE_S", 1), \
                mock.patch("sys.stdout"), mock.patch("sys.stderr"):
            rc = integrity.main(["--hooks-dir", str(self.hooks), "--settings", str(self.settings), "--host-label", "h", "verify"])
        self.assertEqual(rc, 0)
        self.assertLess(time.monotonic() - start, 5)


class StableHostId(Base):
    """Review item 9: the label must not follow the network, and old records keep verifying through an alias."""

    IOREG = '  "IOPlatformUUID" = "ABCDEF01-2345-6789-ABCD-EF0123456789"\n'

    def ioreg(self, argv, **kw):
        return subprocess.CompletedProcess(argv, 0, self.IOREG, "")

    def clean_env(self):
        return mock.patch.dict(os.environ, {k: v for k, v in os.environ.items() if k != "HARNESS_HOST_ID"}, clear=True)

    def test_id_does_not_change_with_the_host_name_and_hides_the_uuid(self):
        with self.clean_env(), mock.patch.object(integrity.sys, "platform", "darwin"):
            with mock.patch.object(integrity.socket, "gethostname", lambda: "Mac-2.local"):
                one = integrity.host_id(self.ioreg)
            with mock.patch.object(integrity.socket, "gethostname", lambda: "Erics-MacBook-Air"):
                two = integrity.host_id(self.ioreg)
        self.assertEqual(one, two)
        self.assertRegex(one, r"^mac-[0-9a-f]{16}$")
        self.assertNotIn("abcdef01", one.lower())
        self.assertRegex(one, integrity.HOST_RE)

    def test_linux_uses_machine_id_and_the_host_name_is_the_last_resort(self):
        with self.clean_env(), mock.patch.object(integrity.sys, "platform", "linux"), \
                mock.patch.object(integrity.Path, "read_text", lambda self: "abc123\n"):
            self.assertRegex(integrity.host_id(), r"^linux-[0-9a-f]{16}$")
        with self.clean_env(), mock.patch.object(integrity.sys, "platform", "linux"), \
                mock.patch.object(integrity.Path, "read_text", side_effect=OSError), \
                mock.patch.object(integrity.socket, "gethostname", lambda: "box.lan"):
            self.assertEqual(integrity.host_id(), "box")

        def broken(argv, **kw):
            raise OSError("no ioreg")
        with self.clean_env(), mock.patch.object(integrity.sys, "platform", "darwin"), \
                mock.patch.object(integrity.socket, "gethostname", lambda: "box.lan"):
            self.assertEqual(integrity.host_id(broken), "box")
        with mock.patch.dict(os.environ, {"HARNESS_HOST_ID": "fixed-label"}):
            self.assertEqual(integrity.host_id(broken), "fixed-label")

    def alias_policy(self, table):
        policy = json.loads((self.hooks / "integrity_policy.json").read_text())
        policy["host_aliases"] = table
        (self.hooks / "integrity_policy.json").write_text(json.dumps(policy))

    def test_a_record_under_an_old_name_verifies_through_a_documented_alias(self):
        self.alias_policy({"mac-1": ["Mac-2"]})  # the policy file is hashed too, so it is in place before the record
        integrity.record(self.hooks, self.settings, self.mirror_dir, host="Mac-2")
        with mock.patch.object(integrity, "host_id", lambda: "mac-1"):
            result = integrity.verify(self.hooks, self.settings, self.mirror_dir)
        self.assertEqual((result["status"], result["host"]), ("MATCH", "mac-1"), result)
        for down in ("ssh", "goodqa"):
            self.fake.down = {down}
            with mock.patch.object(integrity, "host_id", lambda: "mac-1"):
                self.assertEqual(integrity.verify(self.hooks, self.settings, self.mirror_dir)["status"], "MATCH", down)

    def test_no_alias_no_match_and_the_id_is_preferred_over_an_alias(self):
        integrity.record(self.hooks, self.settings, self.mirror_dir, host="Mac-2")
        self.alias_policy({"another-machine": ["Mac-2"]})
        with mock.patch.object(integrity, "host_id", lambda: "mac-1"):
            self.assertEqual(integrity.verify(self.hooks, self.settings, self.mirror_dir)["status"], "UNVERIFIABLE")
        self.alias_policy({"mac-1": ["Mac-2"]})
        with mock.patch.object(integrity, "host_id", lambda: "mac-1"):
            rec, _ = integrity.record(self.hooks, self.settings, self.mirror_dir)
            self.assertEqual(rec["host"], "mac-1")
            self.fake.down = {"goodqa"}
            calls_before = len(self.fake.calls)
            self.assertEqual(integrity.verify(self.hooks, self.settings, self.mirror_dir)["status"], "MATCH")
            self.assertEqual(len(self.fake.calls) - calls_before, 2, "one ssh read, one GoodQA attempt: no alias read")

    def test_shipped_policy_has_the_t2_example_and_only_real_mirrors_are_read(self):
        shipped = json.loads((ROOT / "harness" / "hooks" / "integrity_policy.json").read_text())
        self.assertEqual(shipped["mirrors_example"][0]["kind"], "ssh")
        self.assertNotIn("t2", [m["host"] for m in shipped["mirrors"]])
        self.assertNotIn("mirrors_example", integrity.load_policy(ROOT / "harness" / "hooks"))
        for names in shipped["host_aliases"].values():
            self.assertIn("Mac-2", names)


class DeliverFailures(Base):
    """Review R4, R5: emit's arguments, and an emit failure is exit 3, never exit 1 (CHANGED) or a traceback."""

    def setUp(self):
        super().setUp()
        sys.modules.pop("ops_watch", None)
        self.addCleanup(sys.modules.pop, "ops_watch", None)
        self.addCleanup(lambda: str(self.hooks) in sys.path and sys.path.remove(str(self.hooks)))
        self.base = self.root / "agent-harness-home" / ".agent-harness"

    def ops(self, body):
        (self.hooks / "ops_watch.py").write_text(body)

    def main(self, *args):
        with mock.patch("sys.stdout"), mock.patch("sys.stderr"), mock.patch.object(integrity, "agent_home", lambda: self.base):
            return integrity.main(["--hooks-dir", str(self.hooks), "--settings", str(self.settings), "--mirror-dir",
                                   self.mirror_dir, "--host-label", "testhost", *args])

    def test_emit_gets_home_by_keyword_as_the_user_home(self):
        seen = self.root / "seen.json"
        self.ops(f"""import json
def emit(event, path=None, home=None):
    open({str(seen)!r}, "w").write(json.dumps([path, str(home)]))
    return 1
""")
        integrity.deliver({"k": 1}, self.hooks, self.base)
        self.assertEqual(json.loads(seen.read_text()), [None, str(self.base.parent)])

    def test_emit_value_error_is_exit_three_on_a_clear_and_stays_one_on_changed(self):
        self.ops("def emit(event, path=None, home=None):\n    raise ValueError('bad event')\n")
        self.record()
        self.assertEqual(self.main("verify", "--alert"), 0)  # MATCH with nothing to deliver
        (self.hooks / "holds.json").write_text("{}")
        self.assertEqual(self.main("verify", "--alert"), 1)  # CHANGED, and delivery failed: still the CHANGED code
        self.record()
        state = self.base / "integrity" / "alert-state.json"
        state.parent.mkdir(parents=True, exist_ok=True)
        state.write_text(json.dumps({"active": {"holds.json": "high"}}))
        self.assertEqual(self.main("verify", "--alert"), 3)  # MATCH with a clear that could not be delivered

    def test_a_broken_module_is_not_a_change(self):
        for body in ("import nonexistent_module_x\n", "this is not python\n", "x = 1\n",
                     "def emit(event, path=None, home=None):\n    raise OSError('disk')\n"):
            sys.modules.pop("ops_watch", None)
            self.ops(body)
            with self.assertRaises(OSError, msg=body):
                integrity.deliver({"k": 1}, self.hooks, self.base)


if __name__ == "__main__":
    unittest.main()
