"""Native click provenance through a disposable tracker and native-shaped stores."""
import hashlib
import json
from pathlib import Path
import sqlite3
import subprocess
from types import SimpleNamespace
from unittest import mock

from test_spec_flow import ISSUE, SPEC, SpecFlowCase, git_repo, setUpModule, sf, tearDownModule  # noqa: F401

PARENT = "11111111-1111-4111-8111-111111111111"
TESTER = "22222222-2222-4222-8222-222222222222"
UNRELATED = "33333333-3333-4333-8333-333333333333"
ROLE = "harness_click_tester"
AGENT_PATH = "/root/fixture_click"
URL = "https://fixture.example.invalid/"
START = "2026-11-05T10:03:00Z"
END = "2026-11-05T10:06:00Z"
NOTE = "2026-11-05T10:07:00Z"
FINAL = "2026-11-05T10:08:00Z"


class NativeClick(SpecFlowCase):
    def setUp(self):
        super().setUp()
        self.attached()
        self.native_home = self.home.resolve()
        user_home = mock.patch("pwd.getpwuid", return_value=SimpleNamespace(pw_dir=str(self.native_home)))
        user_home.start()
        self.addCleanup(user_home.stop)
        self.native_dir = self.native_home / ".agent-harness/codex-wals" / PARENT
        self.native_dir.mkdir(parents=True, mode=0o700)
        self.main = self.native_dir / "main.jsonl"
        self.child = self.native_dir / f"agent-{TESTER}.jsonl"
        start = {"at": "2026-11-05T10:01:00Z", "event": "SubagentStart", "agent_id": TESTER, "agent_type": ROLE}
        for path in (self.main, self.child):
            self.wal(path, start)
            path.chmod(0o600)
        self.rollout = (self.native_home / ".codex/sessions/2026/11/05" /
                        f"rollout-2026-11-05T10-01-00-{TESTER}.jsonl")
        self.rollout.parent.mkdir(parents=True)
        self.wal(self.rollout, {"timestamp": "2026-11-05T10:01:02Z", "type": "session_meta", "payload": {
            "id": TESTER, "session_id": PARENT, "parent_thread_id": PARENT, "originator": "Codex Desktop",
            "thread_source": "subagent", "agent_role": ROLE, "agent_path": AGENT_PATH,
        }})
        self.rollout.chmod(0o600)
        self.db = sqlite3.connect(self.native_home / ".codex/state_5.sqlite")
        self.addCleanup(self.db.close)
        self.db.execute("CREATE TABLE threads (id TEXT PRIMARY KEY, source TEXT, thread_source TEXT, "
                        "originator TEXT, agent_path TEXT, agent_role TEXT, attached_thread_parent_id TEXT, "
                        "archived INTEGER, rollout_path TEXT)")
        self.db.execute("INSERT INTO threads VALUES(?,?,?,?,?,?,?,?,?)",
                        (PARENT, "vscode", "user", "Codex Desktop", None, None, None, 0, None))
        source = {"subagent": {"thread_spawn": {"parent_thread_id": PARENT, "depth": 1,
                  "agent_path": AGENT_PATH, "agent_role": ROLE}}}
        self.db.execute("INSERT INTO threads VALUES(?,?,?,?,?,?,?,?,?)",
                        (TESTER, json.dumps(source), "subagent", "Codex Desktop", AGENT_PATH, ROLE, None, 0,
                         str(self.rollout)))
        self.db.commit()
        self.repo = self.tmp / "fixture-repo"
        self.commits = git_repo(self.repo, "first", "deployed", "after")
        subprocess.run(["git", "-C", str(self.repo), "remote", "add", "origin",
                        "https://example.invalid/fixture/app.git"], check=True)
        self.report = self.tmp / "report.md"
        self.report.write_text("CLICK_TEST_RESULT: PASS\nsynthetic fixture walkthrough\n")
        self.log = self.tmp / "edge.log"
        self.log.write_text("synthetic fixture trace\n")

    def click(self, *extra, url=URL, commit=None, wal=None, tester=TESTER):
        return self.run_cli("click-test", "--ticket", "GoodQA harness#168", "--actor", "agent:owner1",
                            "--url", url, "--agent-id", tester, "--wal-dir", str(wal or self.native_dir),
                            "--repo", str(self.repo), "--deployed-commit", commit or self.commits[1],
                            "--result", "pass", "--started", START, "--ended", END, "--report", str(self.report),
                            "--log", str(self.log), *extra)

    def line(self):
        code, line, error = self.click("--print-native-witness")
        self.assertEqual(code, 0, error)
        self.assertTrue(line.startswith(sf.NATIVE_CLICK_PREFIX))
        return line.rstrip("\n")

    def message(self, line, *, role="assistant", phase="final_answer", timestamp=FINAL, file=None):
        self.wal(file or self.rollout, {"type": "response_item", "timestamp": timestamp, "payload": {
            "type": "message", "role": role, "phase": phase, "status": "completed",
            "content": [{"type": "output_text", "text": "synthetic tester result\n" + line}],
        }})

    def witness(self, **kwargs):
        line = self.line()
        self.wal(self.child, {"at": NOTE, "event": "check", "note": line})
        self.message(line, **kwargs)
        return line

    def no_write(self, *extra, **kwargs):
        before = (len(self.fake.comments[ISSUE]), len(self.fake.attachments))
        code, _, _ = self.click(*extra, **kwargs)
        self.assertNotEqual(code, 0)
        self.assertEqual((len(self.fake.comments[ISSUE]), len(self.fake.attachments)), before)

    def test_native_record_preflights_posts_and_revalidates_without_role_grant(self):
        line = self.witness()
        code, out, error = self.click("--verify-native-witness")
        self.assertEqual(code, 0, error)
        self.assertEqual(json.loads(out)["sha256"], hashlib.sha256(line.encode()).hexdigest())
        code, out, error = self.click()
        self.assertEqual(code, 0, error)
        self.assertEqual(json.loads(out)["status"], "RECORDED")
        self.assertFalse(any(m.startswith("click-test:") for m in self.evaluate()["missing"]))
        code, out, error = self.click()
        self.assertEqual(code, 0, error)
        self.assertEqual(json.loads(out)["status"], "ALREADY_RECORDED")
        code, _, _ = self.run_cli("signoff", "--ticket", "GoodQA harness#168", "--actor", "agent:owner1",
                                  "--kind", "agent", "--by", TESTER, "--source", "fixture")
        self.assertNotEqual(code, 0)

    def test_legacy_post_idempotency_does_not_read_native_history(self):
        self.witness()
        code, _, error = self.click()
        self.assertEqual(code, 0, error)
        self.wal(self.main_wal, {"event": "subagent", "agent_id": "legacy1", "agent_type": "click-tester",
                                 "at": START})
        args = ("click-test", "--ticket", "GoodQA harness#168", "--actor", "agent:owner1",
                "--url", URL, "--agent-id", "legacy1", "--wal-dir", str(self.wal_dir),
                "--repo", str(self.repo), "--deployed-commit", self.commits[1], "--result", "fail",
                "--log", str(self.log))
        with mock.patch.object(sf, "_native_click_record_proof", wraps=sf._native_click_record_proof) as probe:
            for status in ("RECORDED", "ALREADY_RECORDED"):
                code, out, error = self.run_cli(*args)
                self.assertEqual(code, 0, error)
                self.assertEqual(json.loads(out)["status"], status)
        probe.assert_not_called()

    def test_own_wal_without_native_voice_and_user_echo_are_denied(self):
        line = self.line()
        self.wal(self.child, {"at": NOTE, "event": "check", "note": line})
        self.no_write()
        self.message(line, role="user")
        self.message(line, phase="commentary")
        self.no_write()

    def test_native_voice_requires_own_wal_and_valid_time_order(self):
        line = self.line()
        self.message(line, timestamp="2026-11-05T10:05:39Z")
        self.no_write()
        self.wal(self.main, {"at": NOTE, "event": "check", "note": line})
        self.no_write()
        self.wal(self.child, {"at": NOTE, "event": "check", "note": line})
        self.no_write()

    def test_duplicates_and_wrong_child_metadata_fail(self):
        line = self.witness()
        self.message(line)
        self.no_write()
        self.db.execute("UPDATE threads SET agent_role='harness_owner' WHERE id=?", (TESTER,))
        self.db.commit()
        self.no_write("--print-native-witness")
        self.no_write("--print-native-witness", tester=UNRELATED)

    def test_archived_parent_cannot_authorize_a_native_click_witness(self):
        self.witness()
        self.db.execute("UPDATE threads SET archived=1 WHERE id=?", (PARENT,))
        self.db.commit()
        self.no_write("--verify-native-witness")

    def test_retained_archived_child_can_verify_under_an_active_parent(self):
        self.witness()
        archived = self.native_home / ".codex/archived_sessions" / self.rollout.name
        archived.parent.mkdir()
        self.rollout.rename(archived)
        self.db.execute("UPDATE threads SET archived=1, rollout_path=? WHERE id=?", (str(archived), TESTER))
        self.db.commit()
        code, _, error = self.click("--verify-native-witness")
        self.assertEqual(code, 0, error)

    def test_witness_binds_commit_url_and_attachment_bytes(self):
        self.witness()
        self.no_write(commit=self.commits[2])
        self.no_write(url="https://other.example.invalid/")
        self.no_write("--print-native-witness", url="https://fixture.example.invalid/private-path/")
        self.no_write("--print-native-witness", url="https://fixture.example.invalid:65536/")
        self.log.write_text("changed synthetic log\n")
        self.no_write()
        self.log.write_text("synthetic fixture trace\n")
        self.report.write_text("CLICK_TEST_RESULT: PASS\nchanged synthetic report\n")
        self.no_write()

    def test_missing_reachability_and_unsafe_native_paths_refuse(self):
        self.witness()
        code, _, error = self.run_cli("evidence", "--ticket", "GoodQA harness#168", "--actor", "agent:evidence",
                                     "--ac", "AC-1", "--commit", self.commits[2], "--repo", str(self.repo), "--log", str(self.log))
        self.assertEqual(code, 0, error)
        self.no_write()
        self.no_write(wal=self.wal_dir)

    def test_unsafe_rollout_and_marker_stripping_fail_closed(self):
        line = self.witness()
        wrong = self.rollout.with_name("wrong.jsonl")
        self.rollout.rename(wrong)
        self.rollout.symlink_to(wrong)
        self.no_write()
        self.rollout.unlink()
        wrong.rename(self.rollout)
        (self.native_dir / "second-link.jsonl").hardlink_to(self.child)
        self.no_write()
        self.assertTrue(line)
        downgraded = {"v": 1, "kind": "click_test", "tester": {"kind": "agent", "identity": TESTER},
                      "pass_source": "report+agent-wal-sha256", "attachments": [{"role": "report"}]}
        self.assertTrue(any("native click-test" in p for p in sf.kind_problems(downgraded)))
        downgraded["tester"]["kind"] = "human"
        self.assertTrue(any("native click-test" in p for p in sf.kind_problems(downgraded)))

    def test_current_spec_timestamp_bounds_submission_and_revalidation(self):
        self.witness()
        code, _, error = self.click()
        self.assertEqual(code, 0, error)
        self.fake.comments[ISSUE][0]["createdAt"] = "2026-11-06T07:00:00Z"
        self.no_write("--print-native-witness")
        self.assertIn("click-test: the latest native result does not verify for this ticket on this host",
                      self.evaluate()["missing"])

    def test_scope_change_and_absent_local_provenance_block_readiness(self):
        self.witness()
        code, _, error = self.click()
        self.assertEqual(code, 0, error)
        self.rollout.unlink()
        self.assertIn("click-test: the latest native result does not verify for this ticket on this host",
                      self.evaluate()["missing"])
        self.attached(SPEC.replace("An agent cannot", "A current agent cannot"))
        self.no_write()

    def test_unverifiable_new_result_blocks_an_older_pass(self):
        core = sf.core_sha(SPEC)
        spec = {"v": 1, "kind": "spec", "_comment": "s", "_at": "1", "spec_core_sha": core,
                "spec_file_sha": "spec", "ac": ["AC-1"], "author": "agent:owner",
                "attachments": [{"id": "s", "role": "spec", "sha256": "spec"},
                                {"id": "r", "role": "reviews", "sha256": "rev"}]}
        base = {"v": 1, "kind": "click_test", "_comment": "c", "_at": "2", "spec_core_sha": core,
                "tester": {"kind": "agent", "identity": "legacy"}, "url": URL, "result": "pass",
                "deployed_commit": {"sha": self.commits[1]}, "attachments": [{"id": "c", "role": "report", "sha256": "report"}]}
        current = {**base, "v": 2, "_comment": "new", "_at": "3", "tester": {"kind": "agent", "identity": TESTER}}
        index = {item["id"]: {"commentId": rec["_comment"], "completionState": "completed", "sha256": item["sha256"]}
                 for rec in (spec, base) for item in rec["attachments"]}
        self.assertFalse(any(m.startswith("click-test:") for m in sf.evaluate([spec, base], index, {})["missing"]))
        self.assertIn("click-test: the latest native result does not verify for this ticket on this host",
                      sf.evaluate([spec, base, current], index, {})["missing"])

    def test_malformed_current_native_record_remains_a_blocker(self):
        core = sf.core_sha(SPEC)
        raw = {"v": 2, "kind": "click_test", "spec_core_sha": core, "tester": ["incompatible"]}
        records, ignored = sf.ticket_records([{"body": sf.record_body("fixture", raw), "id": "invalid"}], 65536)
        self.assertTrue(ignored)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0]["spec_core_sha"], core)
        self.assertTrue(sf._native_click_claim(records[0]))


    def order_fixture(self, outcomes):
        spec = {"spec_core_sha": sf.core_sha(SPEC), "_at": "2026-11-04T04:00:00Z"}
        records, index = [], {}
        for n, (tester, end, result, posted) in enumerate(outcomes):
            tag = f"result-{n}"
            record = {"v": 2, "kind": "click_test", "ticket": "GoodQA harness#168",
                      "spec_core_sha": spec["spec_core_sha"], "_at": posted, "_comment": tag,
                      "tester": {"kind": "agent", "family": "codex", "agent_type": ROLE,
                                 "identity": tester, "parent": PARENT, "repo": "example.invalid/project/app",
                                 "report_sha256": "a" * 64, "started_at": START, "ended_at": end},
                      "pass_source": sf.NATIVE_CLICK_SOURCE, "covers_commits": [], "result": result, "url": URL,
                      "deployed_commit": {"sha": self.commits[1]},
                      "attachments": [{"id": tag, "role": "report", "name": "report.md", "sha256": "b" * 64}]}
            records.append(record)
            index[tag] = {"commentId": tag, "completionState": "completed", "sha256": "b" * 64}
        return records, index, spec

    def latest(self, records, index, spec):
        return sf._latest_click_result(records, index, spec, "GoodQA harness#168", [])

    def test_delayed_and_repeated_pass_cannot_supersede_newer_observed_failure(self):
        records, index, spec = self.order_fixture([
            (UNRELATED, "2026-11-05T10:09:00Z", "fail", "2026-11-05T10:10:00Z"),
            (TESTER, END, "pass", "2026-11-05T10:11:00Z"),
            (TESTER, END, "pass", "2026-11-05T10:12:00Z"),
        ])
        with mock.patch.object(sf, "_native_agent_source", return_value={"parent": PARENT}), \
             mock.patch.object(sf, "_native_click_proof") as proof:
            latest, _, problem = self.latest(records, index, spec)
        self.assertIsNone(problem)
        self.assertIs(latest, records[0])
        self.assertEqual(proof.call_count, 2, "the replay must reuse its already-verified witness")

    def test_conflicting_equal_observed_times_and_unverified_later_attempts_block(self):
        records, index, spec = self.order_fixture([
            (TESTER, END, "pass", "2026-11-05T10:10:00Z"),
            (UNRELATED, END, "fail", "2026-11-05T10:11:00Z"),
        ])
        with mock.patch.object(sf, "_native_click_record_proof"):
            _, _, problem = self.latest(records, index, spec)
            self.assertIn("conflict at the same end time", problem)
            index[records[1]["_comment"]]["sha256"] = "changed"
            _, _, problem = self.latest(records, index, spec)
            self.assertIn("does not verify", problem)

    def test_candidate_limit_stops_before_native_history_reads(self):
        records, index, spec = self.order_fixture(
            [(TESTER, END, "pass", FINAL)] * (sf.MAX_NATIVE_CLICK_CANDIDATES + 1))
        with mock.patch.object(sf, "_native_click_record_proof") as proof:
            _, _, problem = self.latest(records, index, spec)
        self.assertIn("too many current native records", problem)
        proof.assert_not_called()


    def test_legacy_failure_can_block_a_native_pass_but_legacy_pass_cannot_clear_native_failure(self):
        records, index, spec = self.order_fixture([(TESTER, END, "pass", "2026-11-05T10:07:00Z")])
        legacy = {**records[0], "v": 1, "tester": {"kind": "agent", "identity": "older-harness"},
                  "pass_source": None, "_at": FINAL, "_comment": "legacy",
                  "result": "fail", "attachments": [{"id": "legacy", "role": "log", "sha256": "c" * 64}]}
        records.append(legacy)
        index["legacy"] = {"commentId": "legacy", "completionState": "completed", "sha256": "c" * 64}
        with mock.patch.object(sf, "_native_click_record_proof"):
            _, _, problem = self.latest(records, index, spec)
            self.assertIn("newer legacy click-test failed", problem)
            legacy["tester"]["ended_at"] = "2026-11-05T10:04:00Z"
            latest, _, problem = self.latest(records, index, spec)
            self.assertIsNone(problem)
            self.assertIs(latest, records[0])
            legacy["result"] = "pass"
            records[0]["result"] = "fail"
            latest, _, problem = self.latest(records, index, spec)
            self.assertIsNone(problem)
            self.assertIs(latest, records[0])
