"""goodqa#17148: `ah task retire-session` retires every owner of a session that has verifiably ended with ONE sourced
decision, so about 100 stale SILENT/DROPPED alerts stop burying real ones, and the bulk-close guard stays whole.

The session is accepted only when no process names it, every transcript has been quiet for RETIRE_QUIET_S, no owner is
live and the owner view is complete. Anything that cannot be read is a refusal. Each owner reads as its own `retired`
disposition that cites the decision; a retired owner that shows new activity alerts again.

Failing-first: tests/mutants_retire_session.py runs this file against controlled broken variants of ah.py."""
import calendar
import datetime as dt
import json
import shlex
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
import caller_identity  # noqa: E402
import dropped_gate  # noqa: E402
import ahd  # noqa: E402
import idle_guard  # noqa: E402
import liveness  # noqa: E402
import ops_watch  # noqa: E402

REAL_PS = ah._retire_ps_rows
REAL_PID_ALIVE = ah._retire_pid_alive
REAL_PROC_START = ah._retire_proc_start
REAL_HOME = Path.home()
NOW = 1_800_000_000.0
OLD = NOW - 10 * 3600  # an ended session: quiet for 10 h
SESSION = "11111111-aaaa-4bbb-8ccc-222222222222"
OTHER = "99999999-aaaa-4bbb-8ccc-222222222222"
OTHER_LIVE = "88888888-aaaa-4bbb-8ccc-222222222222"
SOURCE = "user:99999999/abcd \"retire the ended sessions\""
TICKET = "GoodQA goodqa#16999"  # the ticket that holds the dropped work (not the feature ticket)


def iso(ts):
    return time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime(ts))


def ended(ts):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


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

        class FakeDT(dt.datetime):  # the decision line and the audit are stamped by the same fake clock
            @classmethod
            def now(cls, tz=None):
                return dt.datetime.fromtimestamp(test.clock + 1, tz)  # a write is stamped just after the request's own time
        test = self
        d = mock.patch.object(ah.dt, "datetime", FakeDT)
        d.start()
        self.addCleanup(d.stop)
        self.table = list(QUIET_TABLE)
        self.alive = set()  # pids the fake kernel says exist
        self.starts = {}  # pid -> the start time ps prints
        for name, fn in (("_retire_ps_rows", lambda: list(self.table)), ("_retire_pid_alive", lambda pid: pid in self.alive),
                         ("_retire_proc_start", lambda pid: self.starts.get(pid))):
            m = mock.patch.object(ah, name, side_effect=fn)
            m.start()
            self.addCleanup(m.stop)
        m = mock.patch.object(ah, "_ticket_exists", return_value=True)
        m.start()
        self.addCleanup(m.stop)
        (self.home / ".claude" / "sessions").mkdir(parents=True)
        self.registry(OTHER_LIVE, 4242)  # another, live session: the registry is read and does not name SESSION
        import provenance
        self.prov = mock.patch.object(provenance, "resolve", return_value={"ok": True, "problems": []})
        self.prov.start()
        self.addCleanup(self.prov.stop)
        self.w = self.home / ".claude" / "wals" / SESSION
        self.build(SESSION, self.N)
        jl(self.home / ".claude" / "wals" / OTHER / "main.jsonl", [{"at": iso(OLD), "event": "intent", "note": "the replacement"}])

    START = 1_790_000_000  # a process start time (epoch)

    def registry(self, session, pid, start=START, alive=True, recorded=None, host=None, text=None):
        stamp = time.strftime("%a %b %d %H:%M:%S %Y", time.gmtime(recorded if recorded is not None else start))
        entry = {"pid": pid, "sessionId": session, "procStart": text or stamp, "pidDomain": "darwin"}
        if host:
            entry["hostSessionId"] = host
        (self.home / ".claude" / "sessions" / f"{pid}.json").write_text(json.dumps(entry))
        if alive:
            self.alive.add(pid)
        self.starts[pid] = float(start)

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

    def txn(self):
        p = self.home / "main-transcript.jsonl"
        if not p.exists():
            p.write_text('{"type":"user"}\n')
        return p

    def put_stamp(self, mode, fields, tool_use_id="toolu_test000001", bound=True):
        purpose = "retire-revoke" if mode == "revoke" else "retire-session"
        caller_identity.put_stamp(purpose, ah.retire_stamp_parts(fields, mode), session="main-session", home=self.home,
                                  tool_use_id=tool_use_id if bound else None, transcript=str(self.txn()))

    def args_for(self, session=SESSION, **extra):
        key = extra.pop("key", None)
        if extra.get("expect", None) is None:  # --expect is required: take it from a dry run like main does
            try:
                extra["expect"] = ah.retire_dry_run(self.home, session)["owners_sha"]
            except ah.AhError:
                extra["expect"] = "0" * 16  # the real call then meets its own refusal
        elif extra["expect"] is False:
            extra.pop("expect")
        a = {"session": session, "ended": ended(OLD), "at": iso(self.clock), "source": SOURCE, "dropped": True, "ticket": TICKET}
        a.update(extra)
        if "dropped" in extra and extra["dropped"] is None:  # a --replaced-by call carries no ticket
            a.pop("ticket", None)
        return {k: v for k, v in a.items() if v is not None}, key

    def stamp(self, session=SESSION, **extra):
        a, _key = self.args_for(session, **extra)
        self.put_stamp("retire", a)

    def retire(self, session=SESSION, stamp=True, caller="", **extra):
        a, key = self.args_for(session, **extra)
        if stamp:
            self.put_stamp("retire", a)
        return ah.write(self.home, "task.retire_session", a, caller, key)

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
        self.registry(OTHER, 5151)  # the replacement is live
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

    def test_a_path_that_holds_the_session_id_is_not_the_session(self):
        for cmd in (f"gpg-agent --homedir /Users/x/.agent-harness/work/{SESSION}/gnupg --daemon",
                    f"Google Chrome --user-data-dir=/tmp/profiles/{SESSION}", f"tail -f /w/{SESSION}/log"):
            self.table.append((801, 1, 0, cmd))
        self.assertEqual(self.retire()["result"], "applied")

    def test_an_argument_that_is_the_session_id_is_the_session(self):
        for cmd in (f"claude --resume {SESSION}", f"claude --session-id={SESSION} -p", f"x CLAUDE_CODE_SESSION_ID={SESSION}"):
            with self.subTest(cmd=cmd):
                self.table = list(QUIET_TABLE) + [(802, 1, 0, cmd)]
                self.refused("retire_running")

    def test_a_retry_is_a_duplicate_not_a_second_decision(self):
        sha = ah.retire_dry_run(self.home, SESSION)["owners_sha"]
        first = self.retire(expect=sha)
        self.clock += 30
        again = self.retire(expect=sha)
        self.assertEqual(again["result"], "duplicate")
        self.assertEqual(again["id"], first["id"])
        self.assertEqual(len(self.applied()), 1)
        self.assertEqual(len([x for x in self.main_wal_lines() if x.get("kind") == "retired_session"]), 1)

    def test_same_key_with_another_body_is_a_conflict(self):
        self.retire(key="retire-key-0001")
        with self.assertRaises(ah.AhError) as cm:
            ah.write(self.home, "task.retire_session", {"session": SESSION, "ended": ended(OLD - 7200), "at": iso(self.clock),
                                                         "source": SOURCE, "dropped": True, "ticket": TICKET, "expect": "0" * 16}, "", "retire-key-0001")
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
        m = mock.patch.object(ah, "_retire_ps_rows", REAL_PS)  # the real parser, the rest of the fixture unchanged
        m.start()
        self.addCleanup(m.stop)

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
        err = self.refused("bad_request", dropped=None, replaced_by="44444444-aaaa-4bbb-8ccc-222222222222")
        self.assertIn("no main WAL", str(err))

    def test_both_or_neither_of_replaced_by_and_dropped(self):
        self.registry(OTHER, 5153)  # a live replacement, so only the double answer can refuse
        err = self.refused("bad_request", replaced_by=OTHER)  # dropped is also set
        self.assertIn("exactly one", str(err))
        self.refused("bad_request", dropped=None)

    def test_ended_in_the_future_or_unparseable(self):
        self.refused("bad_request", ended=ended(NOW + 86400))
        self.refused("bad_request", ended="yesterday-ish")

    def test_a_session_cannot_retire_itself(self):
        with mock.patch.dict(os.environ, {"CLAUDE_CODE_SESSION_ID": SESSION}):
            self.stamp()  # even main's stamp does not let a session retire itself
            with self.assertRaises(ah.AhError) as cm:
                ah.write(self.home, "task.retire_session", {"session": SESSION, "ended": ended(OLD), "at": iso(NOW),
                                                             "source": SOURCE, "dropped": True, "ticket": TICKET, "expect": "0" * 16}, SESSION)
        self.assertEqual(cm.exception.code, "forbidden")
        self.assertIn("itself", str(cm.exception))

    def test_caller_cannot_inject_its_own_evidence(self):
        # a caller-supplied `retire` block (owners to cover) is dropped; ah's preflight is the only writer
        self.table.append((777, 1, 0, f"claude --resume {SESSION}"))
        with self.assertRaises(ah.AhError) as cm:
            self.retire(retire={"owners": ["a-forged"], "skipped": [], "owner_count": 1})
        self.assertEqual(cm.exception.code, "retire_running")

    def test_an_owner_of_the_session_cannot_retire_it(self):
        with mock.patch.dict(os.environ, {"AH_AGENT_ID": agent(0)}):
            self.refused("forbidden")

    def test_the_dry_run_through_the_cli_writes_nothing(self):
        args = ah.build_parser().parse_args(["task", "retire-session", "--session", SESSION, "--dry-run"])
        before = (self.ledger(), self.audit(), self.main_wal_lines())
        out = ah.run(args, self.home)
        self.assertEqual((out["result"], out["would_cover"]), ("dry-run", self.N))
        self.assertEqual((self.ledger(), self.audit(), self.main_wal_lines()), before)

    def test_the_cli_requires_a_full_session_id(self):
        with self.assertRaises(SystemExit):
            ah.build_parser().parse_args(["task", "retire-session", "--dropped"])


class Authority(Base):
    """R2: only main's stamped, ticketed, bounded call retires."""

    def test_no_stamp_no_retire(self):
        self.refused("forbidden", stamp=False)

    def test_a_stamp_is_one_shot(self):
        self.retire()
        self.clock += 5
        self.build(OTHER, 2)
        jl(self.home / ".claude" / "wals" / OTHER / "main.jsonl", [{"at": iso(OLD), "event": "intent", "note": "x"}])
        with self.assertRaises(ah.AhError) as cm:
            self.retire(session=OTHER, stamp=False)
        self.assertEqual(cm.exception.code, "forbidden")

    def test_a_stamp_for_another_session_does_not_count(self):
        self.stamp(OTHER)
        self.refused("forbidden", stamp=False)

    def test_a_refusal_does_not_burn_the_stamp(self):
        self.stamp()
        import provenance
        with mock.patch.object(provenance, "resolve", return_value={"ok": False, "problems": [{"code": "x", "message": "no"}]}):
            with self.assertRaises(ah.AhError) as cm:  # refused in the preflight, after the cheap checks, before the stamp
                self.retire(stamp=False)
        self.assertEqual(cm.exception.code, "provenance")
        self.assertEqual(self.retire(stamp=False)["result"], "applied")

    def command(self, *more, session=SESSION, expect="0123456789abcdef"):
        words = ["python3", "~/.claude/hooks/ah.py", "task", "retire-session", "--session", session, "--dropped", "--ticket", TICKET,
                 "--ended", ended(OLD), "--expect", expect, "--source", SOURCE, *more]
        return " ".join(shlex.quote(w) if w != "~/.claude/hooks/ah.py" else w for w in words)

    def test_main_hook_stamps_a_plain_command_and_only_that(self):
        cmd = self.command()
        calls = []
        payload = {"session_id": "m", "tool_use_id": "toolu_hook000001", "transcript_path": str(self.txn())}
        with mock.patch.object(caller_identity, "put_stamp", side_effect=lambda *a, **k: calls.append((a[:2], k))):
            dropped_gate._stamp_retire(cmd, payload)
            fields = {"session": SESSION, "ended": ended(OLD), "ticket": TICKET, "expect": "0123456789abcdef", "source": SOURCE,
                      "dropped": True}
            self.assertEqual([c[0] for c in calls], [("retire-session", ah.retire_stamp_parts(fields))])
            self.assertEqual(calls[0][1]["tool_use_id"], "toolu_hook000001")  # bound to main's tool call
            self.assertIs(calls[0][1]["require_bound"], True)
            calls.clear()
            for text in (cmd + " --dry-run", f"echo task retire-session --session {SESSION}", "ah task retire-session --help",
                         f'bash -c "{cmd}"', f"python3 -c \"{cmd}\""):
                dropped_gate._stamp_retire(text, payload)
            self.assertEqual(calls, [])

    def test_a_revoke_command_is_stamped_with_its_own_purpose(self):
        calls = []
        cmd = f"ah task retire-session --session {SESSION} --revoke ah0123456789 --source 'ticket:GoodQA goodqa#17148'"
        with mock.patch.object(caller_identity, "put_stamp", side_effect=lambda *a, **k: calls.append(a[:2])):
            dropped_gate._stamp_retire(cmd, {"session_id": "m", "tool_use_id": "toolu_hook000002", "transcript_path": str(self.txn())})
        self.assertEqual([c[0] for c in calls], ["retire-revoke"])

    def test_the_hook_and_write_agree_on_the_stamp_end_to_end(self):
        # the REAL stamp: minted by the hook from the command text, taken by write() from its own arguments
        sha = ah.retire_dry_run(self.home, SESSION)["owners_sha"]
        dropped_gate._stamp_retire(self.command(expect=sha), {"session_id": "main-session", "tool_use_id": "toolu_hook000003",
                                                              "transcript_path": str(self.txn())})
        self.assertEqual(self.retire(stamp=False, expect=sha)["result"], "applied")

    def test_a_stamp_that_is_not_bound_to_a_tool_call_is_refused(self):
        a, _k = self.args_for()
        self.put_stamp("retire", a, bound=False)
        self.refused("forbidden", stamp=False)

    def test_a_stamp_dies_with_main_s_call(self):
        a, _k = self.args_for()
        self.put_stamp("retire", a, tool_use_id="toolu_ended00001")
        with open(self.txn(), "a") as fh:  # the call's result was appended: it is over
            fh.write('{"type":"user","message":{"content":[{"type":"tool_result","tool_use_id":"toolu_ended00001"}]}}\n')
        self.refused("forbidden", stamp=False)

    def test_a_stamp_for_other_arguments_does_not_authorize_this_command(self):
        a, _k = self.args_for()
        self.put_stamp("retire", dict(a, ticket="GoodQA goodqa#16000"))
        self.refused("forbidden", stamp=False)
        self.put_stamp("retire", dict(a, ended=ended(OLD + 60)))
        self.refused("forbidden", stamp=False)
        self.put_stamp("retire", dict(a, expect="f" * 16))
        self.refused("forbidden", stamp=False)

    def test_a_revoke_stamp_does_not_authorize_a_retire_and_the_reverse(self):
        a, _k = self.args_for()
        self.put_stamp("revoke", {"session": SESSION, "decision": "ah0123456789", "source": SOURCE})
        self.refused("forbidden", stamp=False)
        out = self.retire()
        self.put_stamp("retire", a)
        with self.assertRaises(ah.AhError) as cm:
            ah.write(self.home, "task.retire_revoke", {"session": SESSION, "decision": out["id"], "at": iso(self.clock),
                                                        "source": SOURCE}, "")
        self.assertEqual(cm.exception.code, "forbidden")

    def test_the_feature_ticket_is_not_the_dropped_work(self):
        err = self.refused("bad_request", ticket="GoodQA goodqa#17148")
        self.assertIn("this feature", str(err))

    def test_a_cite_that_names_no_session_is_warned_about(self):
        out = self.retire()
        self.assertIn("names this session", out["warning"])
        self.build(OTHER, 1)
        jl(self.home / ".claude" / "wals" / OTHER / "main.jsonl", [])
        out = self.retire(session=OTHER, source=f"ticket:GoodQA goodqa#17148 for {OTHER[:8]}")
        self.assertNotIn("warning", out)

    def test_dropped_needs_a_ticket_that_exists(self):
        self.refused("bad_request", ticket=None)
        with mock.patch.object(ah, "_ticket_exists", return_value=False):
            self.refused("evidence")
        with mock.patch.object(ah, "_ticket_exists", return_value=None):
            self.refused("evidence_unverifiable")

    def test_a_loop_of_retires_is_refused_and_alerted(self):
        with mock.patch.object(ah, "RETIRE_BURST_MAX", 2):
            for i in range(3):
                s = f"7777777{i}-aaaa-4bbb-8ccc-222222222222"
                self.build(s, 1)
                if i < 2:
                    self.assertEqual(self.retire(session=s, caller="caller-session")["result"], "applied")
                else:
                    with self.assertRaises(ah.AhError) as cm:
                        self.retire(session=s, caller="caller-session")
                    self.assertEqual(cm.exception.code, "bulk_close")
        keys = [e.get("key") for e in ops_watch.read_ring(self.home / ".agent-harness" / "state" / "alerts.jsonl")]
        self.assertIn("bulk-retire:caller-s", keys)

    def test_the_owner_list_is_taken_under_the_lock(self):
        # main records a wait for an owner AFTER the preflight and BEFORE the apply: the retire must see it and refuse
        real = ah._retire_preflight

        def preflight_then_a_wait(home, args, now, caller):
            out = real(home, args, now, caller)
            ah.write(self.home, "task.dispose", {"agent": agent(1), "session": SESSION, "kind": "waiting", "ref": TICKET,
                                                  "until": iso(self.clock + 3600), "at": iso(self.clock)}, "")
            return out
        with mock.patch.object(ah, "_retire_preflight", side_effect=preflight_then_a_wait):
            self.refused("retire_live_wait")
        self.assertEqual({r["agent_id"]: r for r in self.owners()["owners"]}[agent(1)]["disposition"]["kind"], "waiting")

    def test_live_waits_and_resumes_are_never_overridden(self):
        for kind, extra in (("waiting", {"ref": TICKET, "until": iso(NOW + 3600)}), ("resumed", {})):
            with self.subTest(kind=kind):
                ah.write(self.home, "task.dispose", dict({"agent": agent(1), "session": SESSION, "kind": kind, "at": iso(self.clock)}, **extra), "")
                self.refused("retire_live_wait")

    def test_a_wait_on_an_open_user_ask_is_never_overridden(self):
        view = self.owners()
        view["owners"][2]["wait_on"] = "w0123456789a"
        with mock.patch.object(ah, "owners", return_value=view):
            self.refused("retire_live_wait")

    def test_unacked_handoffs_are_named_in_the_reply_and_the_wal(self):
        jl(self.w / f"agent-{agent(0)}.jsonl", [{"at": iso(OLD - 1000), "event": "handoff", "note": "handoff: all done, take over"}])
        jl(self.w / "main.jsonl", [{"at": iso(OLD - 900), "event": "subagent_stop", "agent_id": agent(0), "agent_type": "task-owner"}])
        out = self.retire()
        self.assertEqual(out["unacked_handoffs"], [agent(0)])
        self.assertEqual([x for x in self.main_wal_lines() if x.get("kind") == "retired_session"][0]["unacked_handoffs"], [agent(0)])


class EndedAndPreview(Base):
    def test_ended_needs_an_explicit_offset(self):
        naive = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(OLD))  # a valid instant, but no offset: ambiguous
        for bad in ("2026-11-24", "2026-11-24T10:00:00", "2026-11-24 10:00", "yesterday", naive):
            with self.subTest(bad=bad):
                self.refused("bad_request", ended=bad)

    def test_ended_earlier_than_the_last_transcript_write_is_refused(self):
        self.refused("bad_request", ended=ended(OLD - 7200))

    def test_an_offset_without_a_colon_is_accepted_or_refused_clearly(self):
        local = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(OLD + 3600)) + "+0100"
        self.retire(ended=local)
        self.assertEqual(self.applied()[0]["args"]["ended_utc"], ah.iso(OLD))

    def test_ended_is_stored_normalized_to_utc(self):
        local = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(OLD + 2 * 3600)) + "+02:00"
        self.retire(ended=local)
        self.assertEqual(self.applied()[0]["args"]["ended_utc"], ah.iso(OLD))
        self.assertEqual([r["disposition"]["ended"] for r in self.owners()["owners"]][0], ah.iso(OLD))

    def test_the_boundary_is_six_hours(self):
        main_t = self.home / ".claude" / "projects" / "-proj" / f"{SESSION}.jsonl"
        for age, code in ((6 * 3600 - 60, "retire_recent"), (6 * 3600 + 60, None)):
            with self.subTest(age=age):
                for p in (main_t, *main_t.parent.glob(f"{SESSION}/subagents/*.jsonl")):
                    os.utime(p, (NOW - age - 2500, NOW - age - 2500))
                os.utime(main_t, (NOW - age, NOW - age))
                if code:
                    self.refused(code, ended=ended(NOW - age))
                else:
                    self.assertEqual(self.retire(ended=ended(NOW - age))["result"], "applied")

    def test_expect_pins_the_apply_to_the_preview(self):
        sha = ah.retire_dry_run(self.home, SESSION)["owners_sha"]
        self.assertEqual(len(sha), 16)
        self.build(SESSION, self.N + 1)  # an owner appears after the preview
        self.refused("retire_stale", expect=sha)
        self.assertEqual(self.retire(expect=ah.retire_dry_run(self.home, SESSION)["owners_sha"])["result"], "applied")


class Revoke(Base):
    def revoke(self, decision, stamp=True, **extra):
        fields = dict({"session": SESSION, "decision": decision, "at": iso(self.clock), "source": SOURCE}, **extra)
        if stamp:
            self.put_stamp("revoke", fields)
        return ah.write(self.home, "task.retire_revoke", fields, "")

    def test_a_revoke_brings_the_alerts_back(self):
        pol = ahd.load_policy()
        before = ahd.liveness_alerts({SESSION: self.owners()}, pol)
        out = self.retire()
        self.assertEqual(ahd.liveness_alerts({SESSION: self.owners()}, pol), {})
        self.clock += 60
        self.revoke(out["id"])
        after = self.owners()
        self.assertEqual(ahd.liveness_alerts({SESSION: after}, pol).keys(), before.keys())
        self.assertEqual(len(after["undisposed"]), self.N - 1)
        self.assertTrue(all(r["disposition"] is None for r in after["owners"]))
        self.assertEqual(len([x for x in self.main_wal_lines() if x.get("kind") == "retire_revoked"]), 1)

    def test_a_revoke_needs_the_stamp_and_a_real_decision_once(self):
        out = self.retire()
        with self.assertRaises(ah.AhError) as cm:
            self.revoke(out["id"], stamp=False)
        self.assertEqual(cm.exception.code, "forbidden")
        with self.assertRaises(ah.AhError) as cm:
            self.revoke("ah0000000000")
        self.assertEqual(cm.exception.code, "bad_request")
        self.clock += 60
        self.revoke(out["id"])
        self.clock += 60
        with self.assertRaises(ah.AhError) as cm:
            self.revoke(out["id"], source=SOURCE + " again")
        self.assertEqual(cm.exception.code, "bad_request")

    def test_a_retired_session_can_be_retired_again_after_a_revoke(self):
        out = self.retire()
        self.clock += 60
        self.revoke(out["id"])
        self.clock += 60
        self.assertEqual(self.retire(source=SOURCE + " again")["result"], "applied")


class Registry(Base):
    """R1: Claude Code's own pid registry is the liveness signal for an idle session no command line names."""

    def test_an_idle_session_at_its_prompt_is_running_even_when_everything_else_is_quiet(self):
        self.registry(SESSION, 9001)  # alive, start time matches; no command line names it; transcripts are 10 h old
        self.refused("retire_running")

    def test_the_host_session_id_counts_too(self):
        self.registry(OTHER_LIVE, 9002, host=SESSION)
        self.refused("retire_running")

    def test_a_dead_pid_is_not_running(self):
        self.registry(SESSION, 9003, alive=False)
        self.assertEqual(self.retire()["result"], "applied")

    def test_a_reused_pid_is_not_the_session(self):
        self.registry(SESSION, 9004, recorded=self.START - 86400)  # the pid now runs something that started a day later
        self.assertEqual(self.retire()["result"], "applied")

    def test_a_start_time_that_cannot_be_compared_fails_closed(self):
        self.registry(SESSION, 9005)
        self.starts.pop(9005)  # ps cannot say when the process started
        self.refused("retire_running")

    def test_a_missing_registry_refuses(self):
        import shutil
        shutil.rmtree(self.home / ".claude" / "sessions")
        self.refused("retire_unreadable")

    def test_a_corrupt_entry_refuses_and_a_key_file_is_never_opened(self):
        (self.home / ".claude" / "sessions" / "123.json").write_text("{not json")
        self.refused("retire_unreadable")
        (self.home / ".claude" / "sessions" / "123.json").write_text("{}")
        (self.home / ".claude" / "sessions" / "123.abcdef.key").write_text("{not json at all")
        self.assertEqual(self.retire()["result"], "applied")

    def test_an_entry_that_names_the_session_with_no_pid_refuses(self):
        (self.home / ".claude" / "sessions" / "124.json").write_text(json.dumps({"sessionId": SESSION}))
        self.refused("retire_unreadable")

    def test_the_replacement_must_be_live_or_recent(self):
        self.refused("bad_request", dropped=None, replaced_by=OTHER)  # OTHER is 10 h old and has no process
        self.registry(OTHER, 5152)
        self.assertEqual(self.retire(dropped=None, replaced_by=OTHER)["result"], "applied")


class Reopen(Base):
    """R4: any new activity in the session reopens every retired owner, and the alert and the decision come back."""

    def reopened(self):
        view = self.owners()
        return view, {r["agent_id"]: r for r in view["owners"]}

    def assert_alerting(self, view):
        self.assertTrue(ahd.liveness_alerts({SESSION: view}, ahd.load_policy()))
        self.assertTrue([r for r in view["owners"] if idle_guard.actionable(r)])

    def test_main_transcript_activity_reopens_every_owner(self):
        self.retire()
        self.assertEqual(ahd.liveness_alerts({SESSION: self.owners()}, ahd.load_policy()), {})
        self.clock += 600
        main_t = self.home / ".claude" / "projects" / "-proj" / f"{SESSION}.jsonl"
        os.utime(main_t, (NOW + 300, NOW + 300))  # the user resumed the session; its owners never write again
        view, by = self.reopened()
        self.assertTrue(all("retired-reopened" in r["flags"] for r in by.values()))
        self.assertTrue(all(r["disposition"]["live"] is False for r in by.values()))
        self.assertEqual(len(view["undisposed"]), self.N - 1)
        self.assert_alerting(view)

    def test_main_wal_activity_reopens_but_ahs_own_decision_line_does_not(self):
        self.retire()
        self.clock += 600
        self.assertEqual(self.owners()["undisposed"], [])  # the decision line itself is on the main WAL
        jl(self.w / "main.jsonl", [{"at": iso(NOW + 300), "event": "status", "note": "main is back"}])
        view, by = self.reopened()
        self.assertTrue(all("retired-reopened" in r["flags"] for r in by.values()))
        self.assert_alerting(view)

    def test_a_reopened_silent_owner_gets_attention(self):
        self.retire()
        self.clock += 600
        jl(self.w / "main.jsonl", [{"at": iso(NOW + 300), "event": "status", "note": "main is back"}])
        _view, by = self.reopened()
        silent = by[agent(4)]
        self.assertTrue(silent["state"].startswith("SILENT"))
        self.assertEqual(silent["attention"], ["silent-undisposed"])
        self.assertTrue(idle_guard.actionable(silent))

    def test_a_revoked_decision_reopens_nothing_it_never_closed(self):
        out = self.retire()
        self.clock += 60
        self.put_stamp("revoke", {"session": SESSION, "decision": out["id"], "source": SOURCE})
        ah.write(self.home, "task.retire_revoke", {"session": SESSION, "decision": out["id"], "at": iso(self.clock), "source": SOURCE}, "")
        self.assert_alerting(self.owners())


class PlanReview(Base):
    """The plan review's F1 to F5: ah's own bookkeeping, a mandatory preview, old readers, revoke parity, unreadable."""

    def test_expect_is_required_for_a_real_retire(self):
        err = self.refused("bad_request", expect=False)
        self.assertIn("--expect", str(err))
        self.refused("bad_request", expect="not-a-sha")

    def test_the_predicate_counts_only_what_the_session_wrote(self):
        mine = [{"event": "status", "note": "x"}, {"event": "subagent", "agent_id": "a1"}, {"event": "ask", "id": "w1"},
                {"event": "intent", "note": "y"}, {"event": "subagent_stop", "agent_id": "a1"}]
        theirs = [{"event": "disposition", "kind": "closed"}, {"event": "deadline"}, {"event": "deadline_done"},
                  {"event": "pending_stop"}, {"event": "status", "by": "dropped_gate"}, {"event": "status", "by": "ah"},
                  {"event": "disposition", "kind": "retired_session"}, "not a dict", None]
        self.assertTrue(all(ah.is_session_activity(r) for r in mine))
        self.assertFalse(any(ah.is_session_activity(r) for r in theirs))

    def test_a_dispose_or_deadline_after_the_decision_does_not_reopen_the_others(self):
        self.retire()
        self.clock += 600
        ah.write(self.home, "task.deadline.add" if False else "deadline.add",
                 {"session": SESSION, "at": iso(self.clock + 7200), "ref": TICKET, "owner": agent(0), "note": "check back"}, "")
        ah.write(self.home, "task.dispose", {"agent": agent(1), "session": SESSION, "kind": "waiting", "ref": TICKET,
                                              "until": iso(self.clock + 3600), "at": iso(self.clock)}, "")
        by = {r["agent_id"]: r for r in self.owners()["owners"]}
        for who in (agent(0), agent(2), agent(3), agent(4)):
            self.assertEqual(by[who]["state"], "retired", who)
            self.assertNotIn("retired-reopened", by[who]["flags"])
        self.assertEqual(ahd.liveness_alerts({SESSION: self.owners()}, ahd.load_policy()).keys(),
                         {k for k in ahd.liveness_alerts({SESSION: self.owners()}, ahd.load_policy()) if agent(1) in k})

    def test_a_reader_ignores_an_op_it_does_not_know(self):
        # what an older ah does with the new rows: it sees an unknown op and ignores it, so the owners alert as before
        row = {"state": "applied", "seq": 99, "id": "ahffffffffff", "key": "k-future", "sha": "s", "op": "task.future_op",
               "args": {"session": SESSION, "agent": agent(0), "kind": "closed", "retire": {"owners": [agent(0)]}}}
        ah._append_line(ah.store_dir(self.home) / "ledger.jsonl", row)
        self.assertEqual(ah.dispositions(self.home, SESSION), {})
        self.assertEqual(len(self.owners()["undisposed"]), self.N - 1)

    def test_revoke_wraps_the_resolver_and_refuses_the_target_session(self):
        out = self.retire()
        import provenance
        self.stamp()
        with mock.patch.object(provenance, "resolve", side_effect=RuntimeError("boom")):
            with self.assertRaises(ah.AhError) as cm:
                ah.write(self.home, "task.retire_revoke", {"session": SESSION, "decision": out["id"], "at": iso(self.clock),
                                                            "source": SOURCE}, "")
        self.assertEqual(cm.exception.code, "provenance")
        with self.assertRaises(ah.AhError) as cm:
            ah.write(self.home, "task.retire_revoke", {"session": SESSION, "decision": out["id"], "at": iso(self.clock),
                                                        "source": SOURCE}, SESSION)
        self.assertEqual(cm.exception.code, "forbidden")

    def test_an_unreadable_replacement_transcript_is_retire_unreadable(self):
        (self.home / ".claude" / "projects" / "-proj" / f"{OTHER}.jsonl").write_text("{}\n")
        real = os.stat

        def deny(path, *a, **k):
            if str(path).endswith(f"{OTHER}.jsonl"):
                raise PermissionError(13, "denied")
            return real(path, *a, **k)
        with mock.patch.object(ah.os, "stat", side_effect=deny):
            self.refused("retire_unreadable", dropped=None, replaced_by=OTHER)


class RealSources(Base):
    """Tests that mock BOTH sides cannot see a format or zone difference between them (the delta red-team's N1): these
    read the real ps, a registry entry in Claude Code's own UTC format, and (when this host has one) the real registry."""

    def real(self):
        for name, fn in (("_retire_pid_alive", REAL_PID_ALIVE), ("_retire_proc_start", REAL_PROC_START)):
            m = mock.patch.object(ah, name, fn)
            m.start()
            self.addCleanup(m.stop)

    def own_start(self):
        r = subprocess.run(["ps", "-o", "lstart=", "-p", str(os.getpid())], capture_output=True, text=True,
                           env=dict(os.environ, LC_ALL="C", LANG="C", TZ="UTC"))
        return " ".join(r.stdout.split())

    def test_this_process_is_live_in_any_host_zone(self):
        self.real()
        text = self.own_start()
        self.assertTrue(text, "ps printed no start time")
        (self.home / ".claude" / "sessions" / f"{os.getpid()}.json").write_text(json.dumps(
            {"pid": os.getpid(), "sessionId": SESSION, "procStart": text}))
        for zone in ("America/Denver", "UTC", "Asia/Kolkata"):
            with self.subTest(zone=zone), mock.patch.dict(os.environ, {"TZ": zone}):
                self.assertEqual(ah._retire_registry_live(self.home, SESSION), [os.getpid()])

    def test_a_different_start_time_is_a_reused_pid_in_any_host_zone(self):
        self.real()
        started = ah._retire_parse_start(self.own_start())
        other = time.strftime("%a %b %d %H:%M:%S %Y", time.gmtime(started - 3 * 86400))
        (self.home / ".claude" / "sessions" / f"{os.getpid()}.json").write_text(json.dumps(
            {"pid": os.getpid(), "sessionId": SESSION, "procStart": other}))
        for zone in ("America/Denver", "UTC"):
            with self.subTest(zone=zone), mock.patch.dict(os.environ, {"TZ": zone}):
                self.assertEqual(ah._retire_registry_live(self.home, SESSION), [])

    def test_a_start_time_that_does_not_parse_fails_closed(self):
        self.real()
        for bad in ("", "garbage", "Tue Nov 24 2026", "2026-11-24T16:06:07Z"):
            (self.home / ".claude" / "sessions" / f"{os.getpid()}.json").write_text(json.dumps(
                {"pid": os.getpid(), "sessionId": SESSION, "procStart": bad}))
            with self.subTest(bad=bad):
                self.assertEqual(ah._retire_registry_live(self.home, SESSION), [os.getpid()])

    def test_the_real_ps_table_lists_this_process(self):
        rows = REAL_PS()
        self.assertIn(os.getpid(), [r[0] for r in rows])
        self.assertTrue(all(isinstance(r[3], str) for r in rows))

    def test_the_real_registry_format_parses_when_this_host_has_one(self):
        folder = REAL_HOME / ".claude" / "sessions"
        names = sorted(n for n in os.listdir(folder) if ah.REGISTRY_FILE_RE.match(n)) if folder.is_dir() else []
        if not names:
            self.skipTest("this host has no Claude Code session registry")
        for name in names:
            entry = json.loads((folder / name).read_text())
            self.assertIsInstance(entry.get("pid"), int, name)
            text = str(entry.get("procStart"))
            # macOS writes a UTC date string we compare; Linux writes /proc starttime ticks, which we do not compare: it
            # does not parse, so the entry counts as live while its pid exists (fail closed, documented)
            if text.isdigit():
                self.assertIsNone(ah._retire_parse_start(text), name)
            else:
                self.assertIsNotNone(ah._retire_parse_start(text), name)


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
