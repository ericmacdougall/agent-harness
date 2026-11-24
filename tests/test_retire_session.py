"""goodqa#17148: `ah task retire-session` retires every owner of a session that has verifiably ended with ONE sourced
decision, so about 100 stale SILENT/DROPPED alerts stop burying real ones, and the bulk-close guard stays whole.

The session is accepted only when no process names it, every transcript has been quiet for RETIRE_QUIET_S, no owner is
live and the owner view is complete. Anything that cannot be read is a refusal. Each owner reads as its own `retired`
disposition that cites the decision; a retired owner that shows new activity alerts again.

Failing-first: tests/mutants_retire_session.py runs this file against controlled broken variants of ah.py."""
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

HOOKS = Path(os.environ.get("RETIRE_HOOKS") or Path(__file__).resolve().parents[1] / "harness" / "hooks")
sys.path.insert(0, str(HOOKS))
import ah  # noqa: E402
import ahd  # noqa: E402
import idle_guard  # noqa: E402
import liveness  # noqa: E402
import ops_watch  # noqa: E402

NOW = 1_800_000_000.0
OLD = NOW - 10 * 3600  # an ended session: quiet for 10 h
SESSION = "11111111-aaaa-4bbb-8ccc-222222222222"
OTHER = "99999999-aaaa-4bbb-8ccc-222222222222"
SOURCE = "user:99999999/abcd \"retire the ended sessions\""


def iso(ts):
    return time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime(ts))


def jl(path, rows):
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "a") as fh:
        for r in rows:
            fh.write(json.dumps(r) + "\n")


def agent(i):
    return f"a{0xbeef0000 + i:016x}"


QUIET_TABLE = [(1, 0, 0, "/sbin/launchd"), (4242, 1, os.getuid(), "/usr/bin/some-editor")]


class Base(unittest.TestCase):
    N = 5

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)
        p = mock.patch.dict(os.environ, {"AH_HOME": str(self.home), "HOME": str(self.home)})
        p.start()
        self.addCleanup(p.stop)
        for k in ("CLAUDE_CODE_CHILD_SESSION", "AH_AGENT_ID", "AGENT_ID", "CLAUDE_CODE_SESSION_ID", "CLAUDE_SESSION_ID"):
            os.environ.pop(k, None)
        self.clock = NOW
        for target, value in ((ah, "server_now"),):
            c = mock.patch.object(target, value, side_effect=lambda: iso(self.clock))
            c.start()
            self.addCleanup(c.stop)
        t = mock.patch.object(ah.time, "time", side_effect=lambda: self.clock)
        t.start()
        self.addCleanup(t.stop)
        self.table = list(QUIET_TABLE)
        for name, fn in (("_retire_ps_rows", lambda: list(self.table)), ("_retire_env_of", lambda pid: None)):
            m = mock.patch.object(ah, name, side_effect=fn)
            m.start()
            self.addCleanup(m.stop)
        import provenance
        self.prov = mock.patch.object(provenance, "resolve", return_value={"ok": True, "problems": []})
        self.prov.start()
        self.addCleanup(self.prov.stop)
        self.w = self.home / ".claude" / "wals" / SESSION
        self.build(SESSION, self.N)
        jl(self.home / ".claude" / "wals" / OTHER / "main.jsonl", [{"at": iso(OLD), "event": "intent", "note": "the replacement"}])

    def build(self, session, n, transcript_at=OLD):
        w = self.home / ".claude" / "wals" / session
        rows = []
        for i in range(n):
            rows += [{"at": iso(OLD - 3000), "event": "subagent", "agent_id": agent(i), "agent_type": "task-owner"}]
            if i != 4:  # four stopped without a result (DROPPED), one silently gone (SILENT)
                rows += [{"at": iso(OLD - 1900), "event": "subagent_stop", "agent_id": agent(i), "agent_type": "task-owner"}]
        jl(w / "main.jsonl", rows or [{"at": iso(OLD), "event": "intent", "note": "x"}])
        for i in range(n):
            jl(w / f"agent-{agent(i)}.jsonl", [{"at": iso(OLD - 2000), "event": "intent", "note": f"slice {i} work"}])
        proj = self.home / ".claude" / "projects" / "-proj"
        main_t = proj / f"{session}.jsonl"
        main_t.parent.mkdir(parents=True, exist_ok=True)
        main_t.write_text("{}\n")
        os.utime(main_t, (transcript_at, transcript_at))
        for i in range(n):
            sub = proj / session / "subagents" / f"agent-{agent(i)}.jsonl"
            sub.parent.mkdir(parents=True, exist_ok=True)
            sub.write_text("{}\n")
            os.utime(sub, (transcript_at - 2500, transcript_at - 2500))  # before the stop, so the owner reads as DROPPED

    def retire(self, session=SESSION, **extra):
        a = {"session": session, "ended": iso(OLD), "at": iso(self.clock), "source": SOURCE, "dropped": True}
        a.update(extra)
        return ah.write(self.home, "task.retire_session", a, "", extra.pop("key", None))

    def refused(self, code, **extra):
        with self.assertRaises(ah.AhError) as cm:
            self.retire(**extra)
        self.assertEqual(cm.exception.code, code, str(cm.exception))
        self.assertFalse(self.applied(), "a refusal must write no decision")
        return cm.exception

    def ledger(self):
        return ah._ledger(self.home)

    def applied(self):
        return [r for r in self.ledger() if r.get("op") == "task.retire_session"]

    def owners(self):
        return ah.owners(self.home, SESSION, now=self.clock)

    def audit(self):
        p = ah.store_dir(self.home) / "audit.jsonl"
        return [json.loads(x) for x in p.read_text().splitlines()] if p.exists() else []

    def main_wal_lines(self):
        return [json.loads(x) for x in (self.w / "main.jsonl").read_text().splitlines()]


class Accepted(Base):
    def test_retire_covers_every_owner(self):
        before = self.owners()
        self.assertEqual(len(before["undisposed"]), self.N - 1)  # four DROPPED; the fifth is SILENT-HIGH (attention)
        self.assertEqual(len(before["attention"]), self.N - 4)
        out = self.retire()
        self.assertEqual(out["result"], "applied")
        self.assertEqual(sorted(out["retired"]), sorted(agent(i) for i in range(self.N)))
        rows = [r for r in self.ledger() if r.get("op") in ("task.retire_session", "task.dispose")]
        self.assertEqual([r["op"] for r in rows], ["task.retire_session"], "ONE decision, not one dispose per owner")
        after = self.owners()
        self.assertEqual(after["undisposed"], [])
        for r in after["owners"]:
            self.assertEqual(r["state"], "retired")
            self.assertIs(r["decision_required"], False)
            self.assertEqual(r["attention"], [])
            self.assertEqual(r["disposition"]["kind"], "retired")
            self.assertEqual(r["disposition"]["ref"], out["id"])
            self.assertIs(r["disposition"]["live"], True)
        decisions = [x for x in self.main_wal_lines() if x.get("kind") == "retired_session"]
        self.assertEqual(len(decisions), 1)
        self.assertEqual(decisions[0]["source"], SOURCE)

    def test_per_owner_audit(self):
        out = self.retire()
        lines = [a for a in self.audit() if a.get("kind") == "retired" and a.get("result") == "applied"]
        self.assertEqual(sorted(a["agent"] for a in lines), sorted(agent(i) for i in range(self.N)))
        self.assertTrue(all(a["decision"] == out["id"] for a in lines))

    def test_replaced_by_is_recorded(self):
        out = self.retire(dropped=None, replaced_by=OTHER)
        self.assertEqual(out["result"], "applied")
        self.assertIn(OTHER, [x for x in self.main_wal_lines() if x.get("kind") == "retired_session"][0]["note"])

    def test_dry_run_writes_nothing_and_lists_the_evidence(self):
        before = (list(self.ledger()), list(self.audit()), self.main_wal_lines())
        ev = ah.retire_dry_run(self.home, SESSION)
        self.assertEqual(ev["would_cover"], self.N)
        self.assertEqual(ev["live_pids"], [])
        self.assertEqual(ev["owner_count"], self.N)
        self.assertTrue(ev["transcript_main"] and ev["transcript_files"] == self.N + 1)
        self.assertEqual((list(self.ledger()), list(self.audit()), self.main_wal_lines()), before)
        self.assertFalse(list((ah.store_dir(self.home)).glob("ledger.jsonl")) and
                         any(r.get("state") == "intent" for r in ah._ledger(self.home, include_intents=True)))

    def test_a_retry_is_a_duplicate_not_a_second_decision(self):
        first = self.retire()
        self.clock += 30
        again = self.retire()
        self.assertEqual(again["result"], "duplicate")
        self.assertEqual(again["id"], first["id"])
        self.assertEqual(len(self.applied()), 1)
        self.assertEqual(len([x for x in self.main_wal_lines() if x.get("kind") == "retired_session"]), 1)

    def test_same_key_with_another_body_is_a_conflict(self):
        self.retire(key="retire-key-0001")
        with self.assertRaises(ah.AhError) as cm:
            ah.write(self.home, "task.retire_session", {"session": SESSION, "ended": iso(OLD - 7200), "at": iso(self.clock),
                                                         "source": SOURCE, "dropped": True}, "", "retire-key-0001")
        self.assertEqual(cm.exception.code, "key_conflict")

    def test_a_second_retire_of_retired_owners_finds_nothing_to_do(self):
        self.retire()
        self.clock += 60
        with self.assertRaises(ah.AhError) as cm:
            self.retire(source=SOURCE + " again")
        self.assertEqual(cm.exception.code, "retire_no_owners")


class Refused(Base):
    def test_running_session_by_command_line(self):
        self.table.append((777, 1, 0, f"claude --resume {SESSION}"))
        self.refused("retire_running")

    def test_running_session_by_environment(self):
        self.table.append((778, 1, os.getuid(), "/Applications/Claude.app/Contents/MacOS/claude"))
        with mock.patch.object(ah, "_retire_env_of", side_effect=lambda pid: SESSION if pid == 778 else None):
            self.refused("retire_running")

    def test_this_process_and_its_ancestors_are_not_the_session(self):
        me = os.getpid()
        self.table += [(me, 5000, os.getuid(), f"python3 ah.py task retire-session --session {SESSION}"),
                       (5000, 1, os.getuid(), f"zsh -c ah task retire-session --session {SESSION}")]
        self.assertEqual(self.retire()["result"], "applied")

    def test_recent_main_transcript(self):
        os.utime(self.home / ".claude" / "projects" / "-proj" / f"{SESSION}.jsonl", (NOW - 3600, NOW - 3600))
        self.refused("retire_recent")

    def test_recent_subagent_transcript(self):
        sub = self.home / ".claude" / "projects" / "-proj" / SESSION / "subagents" / f"agent-{agent(2)}.jsonl"
        os.utime(sub, (NOW - 600, NOW - 600))
        self.refused("retire_recent")

    def test_the_threshold_is_not_the_wal_mtime(self):
        # a harness write to a WAL (touching its file time) must not block a retire: activity is what the owners did
        os.utime(self.w / "main.jsonl", (NOW - 60, NOW - 60))
        os.utime(self.w / f"agent-{agent(1)}.jsonl", (NOW - 60, NOW - 60))
        self.assertEqual(self.retire()["result"], "applied")

    def test_recent_owner_wal_activity(self):
        jl(self.w / f"agent-{agent(0)}.jsonl", [{"at": iso(NOW - 5000), "event": "status", "note": "still going"}])
        self.refused("retire_recent")

    def test_unreadable_process_list(self):
        for rc, out in ((1, ""), (0, ""), (0, "garbage line\n")):
            with mock.patch.object(ah, "_retire_ps_rows", wraps=None, side_effect=None):
                pass
            self.setUp_real_ps()
            with mock.patch.object(ah.subprocess, "run", return_value=subprocess.CompletedProcess([], rc, out, "")):
                self.refused("retire_unreadable")

    def setUp_real_ps(self):
        mock.patch.stopall()
        c = mock.patch.object(ah, "server_now", side_effect=lambda: iso(self.clock))
        c.start()
        self.addCleanup(c.stop)
        t = mock.patch.object(ah.time, "time", side_effect=lambda: self.clock)
        t.start()
        self.addCleanup(t.stop)
        import provenance
        p = mock.patch.object(provenance, "resolve", return_value={"ok": True, "problems": []})
        p.start()
        self.addCleanup(p.stop)

    def test_the_real_parser_reads_a_negative_uid_and_an_empty_command(self):
        self.setUp_real_ps()
        table = "    1     0     0 /sbin/launchd\n  325     1    -2 /usr/sbin/distnoted agent\n  400     1   501\n"
        with mock.patch.object(ah.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, table, "")):
            self.assertEqual(ah._retire_ps_rows(), [(1, 0, 0, "/sbin/launchd"), (325, 1, -2, "/usr/sbin/distnoted agent"),
                                                    (400, 1, 501, "")])

    def test_ps_that_cannot_run(self):
        self.setUp_real_ps()
        with mock.patch.object(ah.subprocess, "run", side_effect=OSError("no ps")):
            self.refused("retire_unreadable")

    def test_env_probe_of_an_existing_process_that_fails(self):
        self.table.append((779, 1, os.getuid(), "/Applications/Claude.app/Contents/MacOS/claude"))
        with mock.patch.object(ah, "_retire_env_of", side_effect=ah.AhError("retire_unreadable", "x", 3)):
            self.refused("retire_unreadable")

    def test_missing_transcript(self):
        (self.home / ".claude" / "projects" / "-proj" / f"{SESSION}.jsonl").unlink()
        self.refused("retire_unreadable")

    def test_unlistable_transcript_folder(self):
        import shutil
        shutil.rmtree(self.home / ".claude" / "projects")
        self.refused("retire_unreadable")

    def test_unread_owner_sources(self):
        view = self.owners()
        view["read"] = dict(view["read"], unread_total=1, state="partial")
        with mock.patch.object(ah, "owners", return_value=view):
            self.refused("retire_unreadable")

    def test_live_owner(self):
        view = self.owners()
        view["owners"][0]["state"] = "live"
        with mock.patch.object(ah, "owners", return_value=view):
            self.refused("retire_live_owner")

    def test_live_wait_disposition(self):
        view = self.owners()
        view["owners"][1]["disposition"] = {"kind": "waiting", "live": True, "at": NOW, "until": NOW + 3600}
        with mock.patch.object(ah, "owners", return_value=view):
            self.refused("retire_live_owner")

    def test_missing_or_empty_source(self):
        for src in ("", "   "):
            with self.assertRaises(ah.AhError) as cm:
                self.retire(source=src)
            self.assertEqual(cm.exception.code, "bad_request")
        self.assertFalse(self.applied())

    def test_source_that_provenance_rejects(self):
        import provenance
        with mock.patch.object(provenance, "resolve", return_value={"ok": False, "problems": [{"code": "x", "message": "no"}]}):
            self.refused("provenance")

    def test_session_with_no_owners(self):
        self.build(OTHER, 0)
        self.refused("retire_no_owners", session=OTHER)

    def test_session_with_no_wal_or_transcript(self):
        self.refused("retire_unreadable", session="33333333-aaaa-4bbb-8ccc-222222222222")

    def test_replaced_by_the_same_session(self):
        self.refused("bad_request", dropped=None, replaced_by=SESSION)

    def test_replaced_by_an_unknown_session(self):
        self.refused("bad_request", dropped=None, replaced_by="44444444-aaaa-4bbb-8ccc-222222222222")

    def test_both_or_neither_of_replaced_by_and_dropped(self):
        self.refused("bad_request", replaced_by=OTHER)  # dropped is also set
        self.refused("bad_request", dropped=None)

    def test_ended_in_the_future_or_unparseable(self):
        self.refused("bad_request", ended=iso(NOW + 86400))
        self.refused("bad_request", ended="yesterday-ish")

    def test_a_session_cannot_retire_itself(self):
        with mock.patch.dict(os.environ, {"CLAUDE_CODE_SESSION_ID": SESSION}):
            with self.assertRaises(ah.AhError) as cm:
                ah.write(self.home, "task.retire_session", {"session": SESSION, "ended": iso(OLD), "at": iso(NOW),
                                                             "source": SOURCE, "dropped": True}, SESSION)
        self.assertEqual(cm.exception.code, "forbidden")

    def test_caller_cannot_inject_its_own_evidence(self):
        # a caller-supplied `retire` block (owners to cover) is dropped; ah's preflight is the only writer
        self.table.append((777, 1, 0, f"claude --resume {SESSION}"))
        with self.assertRaises(ah.AhError) as cm:
            self.retire(retire={"owners": ["a-forged"], "skipped": [], "owner_count": 1})
        self.assertEqual(cm.exception.code, "retire_running")

    def test_an_owner_of_the_session_cannot_retire_it(self):
        with mock.patch.dict(os.environ, {"AH_AGENT_ID": agent(0)}):
            self.refused("forbidden")

    def test_the_real_env_probe_refuses_an_unreadable_process_that_exists(self):
        self.setUp_real_ps()
        bad = subprocess.CompletedProcess([], 1, "", "")
        with mock.patch.object(ah.subprocess, "run", return_value=bad):
            with self.assertRaises(ah.AhError) as cm:
                ah._retire_env_of(os.getpid())
            self.assertEqual(cm.exception.code, "retire_unreadable")
            self.assertIsNone(ah._retire_env_of(2 ** 22 + 12345))  # no such process: gone, not unreadable

    def test_the_dry_run_through_the_cli_writes_nothing(self):
        args = ah.build_parser().parse_args(["task", "retire-session", "--session", SESSION, "--dry-run"])
        before = (self.ledger(), self.audit(), self.main_wal_lines())
        out = ah.run(args, self.home)
        self.assertEqual((out["result"], out["would_cover"]), ("dry-run", self.N))
        self.assertEqual((self.ledger(), self.audit(), self.main_wal_lines()), before)

    def test_the_cli_requires_a_full_session_id(self):
        with self.assertRaises(SystemExit):
            ah.build_parser().parse_args(["task", "retire-session", "--dropped"])


class PartialFailure(Base):
    def assert_nothing_effective(self):
        self.assertEqual(len(self.owners()["undisposed"]), self.N - 1)
        self.assertFalse(self.applied())

    def test_an_unwritable_wal_leaves_no_decision(self):
        with mock.patch.object(ah, "_wal_append", side_effect=ah.AhError("wal_unsafe", "WAL is not writable", 3)):
            with self.assertRaises(ah.AhError):
                self.retire()
        self.assert_nothing_effective()
        self.assertFalse([a for a in self.audit() if a.get("kind") == "retired" and a.get("result") == "applied"])
        self.assertEqual(self.retire()["result"], "applied")  # and the retry completes
        self.assertEqual(len([x for x in self.main_wal_lines() if x.get("kind") == "retired_session"]), 1)

    def test_a_crash_between_the_wal_line_and_the_ledger_row_resumes_without_duplicates(self):
        real = ah._append_line

        def crash(path, record):
            if path.name == "ledger.jsonl" and record.get("state") == "applied":
                raise OSError("disk went away")
            return real(path, record)
        with mock.patch.object(ah, "_append_line", side_effect=crash):
            with self.assertRaises(OSError):
                self.retire()
        self.assert_nothing_effective()
        self.clock += 90
        out = self.retire()
        self.assertEqual(out["result"], "applied")
        self.assertEqual(len([x for x in self.main_wal_lines() if x.get("kind") == "retired_session"]), 1)
        self.assertEqual(len(self.applied()), 1)
        self.assertEqual(self.owners()["undisposed"], [])


class AlertsAndReopening(Base):
    def test_alerts_skip_retired(self):
        view = self.owners()
        pol = ahd.load_policy()
        self.assertTrue(ahd.liveness_alerts({SESSION: view}, pol))  # the live situation: raised alerts exist
        self.retire()
        after = self.owners()
        self.assertEqual(ahd.liveness_alerts({SESSION: after}, pol), {})
        with mock.patch.object(ah, "owners", return_value=after):
            got = ops_watch._owner_alerts(Path("/nonexistent"), SESSION, type("T", (), {"quiet_h": lambda s, r: 0})(), NOW)
        self.assertEqual(got, [])
        self.assertEqual([r for r in after["owners"] if idle_guard.actionable(r)], [])
        for r in after["owners"]:
            self.assertTrue(liveness.row_disposed(r))

    def test_the_result_unacked_and_silent_paths_are_cleared_too(self):
        jl(self.w / f"agent-{agent(0)}.jsonl", [{"at": iso(OLD - 1000), "event": "handoff", "note": "handoff: all done, please take over"}])
        jl(self.w / "main.jsonl", [{"at": iso(OLD - 900), "event": "subagent_stop", "agent_id": agent(0), "agent_type": "task-owner"}])
        before = {r["agent_id"]: r for r in self.owners()["owners"]}[agent(0)]
        self.assertEqual((before["state"], before["attention"], before["decision_required"]), ("handoff", ["result-unacked"], True))
        self.retire()
        after = {r["agent_id"]: r for r in self.owners()["owners"]}[agent(0)]
        self.assertEqual((after["decision_required"], after["attention"]), (False, []))
        self.assertNotIn("handoff-unacked", after["flags"])
        silent = {r["agent_id"]: r for r in self.owners()["owners"]}[agent(4)]
        self.assertEqual((silent["state"], silent["attention"]), ("retired", []))

    def test_a_retired_session_that_shows_new_activity_alerts_again(self):
        self.retire()
        self.clock += 600
        jl(self.w / f"agent-{agent(3)}.jsonl", [{"at": iso(self.clock - 5), "event": "status", "note": "I am alive after all"}])
        view = self.owners()
        by = {r["agent_id"]: r for r in view["owners"]}
        self.assertIn("retired-reopened", by[agent(3)]["flags"])
        self.assertIs(by[agent(3)]["disposition"]["live"], False)
        self.assertNotEqual(by[agent(3)]["state"], "retired")
        self.assertEqual(by[agent(0)]["state"], "retired")  # the quiet ones stay retired

    def test_new_subagent_transcript_activity_reopens(self):
        self.retire()
        sub = self.home / ".claude" / "projects" / "-proj" / SESSION / "subagents" / f"agent-{agent(4)}.jsonl"
        os.utime(sub, (NOW + 500, NOW + 500))
        self.clock += 600
        by = {r["agent_id"]: r for r in self.owners()["owners"]}
        self.assertIn("retired-reopened", by[agent(4)]["flags"])

    def test_a_reopened_owner_can_be_retired_again(self):
        self.retire()
        self.clock += 600
        jl(self.w / f"agent-{agent(3)}.jsonl", [{"at": iso(self.clock - 5), "event": "status", "note": "back"}])
        os.utime(self.home / ".claude" / "projects" / "-proj" / f"{SESSION}.jsonl", (OLD, OLD))
        self.clock += 7 * 3600
        out = self.retire(source=SOURCE + " second")
        self.assertEqual(out["retired"], [agent(3)])

    def test_the_bulk_close_guard_is_unchanged(self):
        # retiring is not a bypass: closing owners one by one is still refused as a burst
        who = {"session": "", "agent_id": "unknown", "host": "h"}
        self.retire()
        for i in range(ah.CLOSE_BURST_MAX):
            ah._append_line(ah.store_dir(self.home) / "audit.jsonl", {"at": iso(self.clock), "op": "task.dispose", "kind": "closed",
                                                                      "agent": f"x{i}", "actor": who, "result": "rejected"})
        with self.assertRaises(ah.AhError) as cm:
            ah.write(self.home, "task.dispose", {"agent": "x9", "session": SESSION, "kind": "closed", "at": iso(self.clock),
                                                 "reason": "verified x9 shipped and was checked live on prod",
                                                 "deployed": "w00000000001", "live_test": "t1"}, "")
        self.assertEqual(cm.exception.code, "bulk_close")


class DroppedGate(unittest.TestCase):
    def test_a_sub_agent_cannot_run_it(self):
        import dropped_gate
        self.assertTrue(dropped_gate.acknowledges(f"python3 ~/.claude/hooks/ah.py task retire-session --session {SESSION} --dropped"))
        self.assertTrue(dropped_gate.acknowledges(f"ah task retire-session --session {SESSION} --dropped"))
        self.assertTrue(dropped_gate.acknowledges(f'bash -c "ah task retire-session --session {SESSION} --dropped"'))
        self.assertFalse(dropped_gate.acknowledges("ah task list"))


if __name__ == "__main__":
    unittest.main()
