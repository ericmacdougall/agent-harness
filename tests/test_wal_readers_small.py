"""WAL segment-chain migration, part 1: the plain readers (goodqa#16751, spec docs/spec/wal-segments.md AC-8, AC-9).

Every reader here is run over a ROTATED fixture (three or more closed segments plus a live file, built with the real
writer `wal_segments.append_line`) and over a GAP fixture (a middle segment deleted). Each test is written so it fails
on the unmigrated reader, which only sees the live tail: the data it needs sits in an OLD segment. Synthetic data only.
"""
import importlib.util
import io
import json
import os
import re
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stderr
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
HOOKS = ROOT / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
import wal_segments as ws  # noqa: E402

SESSION = "11111111-2222-4333-8444-555555555555"
LIMIT = 4096
INFO = ("live_missing", "schema_newer", "marker_info")


def iso(seconds_ago=0.0):
    return (datetime.now(timezone.utc) - timedelta(seconds=seconds_ago)).isoformat()


def line(rec):
    return (json.dumps(rec, separators=(",", ":")) + "\n").encode()


class Fixture(unittest.TestCase):
    """A scratch HOME whose session directory holds WALs written by the real segment writer with a tiny limit."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name).resolve()
        self.dir = self.home / ".claude" / "wals" / SESSION
        self.dir.mkdir(parents=True)
        (self.home / ".agent-harness" / "state").mkdir(parents=True)
        (self.home / ".agent-harness" / "state" / "wal-rotation.on").write_text("")
        env = {"HOME": str(self.home), "AH_HOME": str(self.home), "HARNESS_TEST": "1",
               "HARNESS_WAL_SEGMENT_BYTES": str(LIMIT)}
        patcher = patch.dict(os.environ, env)
        patcher.start()
        self.addCleanup(patcher.stop)
        os.environ.pop("CLAUDE_CONFIG_DIR", None)

    # -- fixture builders
    def append(self, name, rec):
        fd = os.open(self.dir, os.O_RDONLY | os.O_DIRECTORY)
        try:
            ws.append_line(fd, name, line(rec))
        finally:
            os.close(fd)

    def fill(self, name, n=60, pad=300, event="pretool", **extra):
        for i in range(n):
            self.append(name, dict({"at": iso(), "event": event, "n": i, "pad": "x" * pad}, **extra))

    def stem(self, name):
        return name[:-len(".jsonl")]

    def closed(self, name="main.jsonl"):
        stem = self.stem(name)
        return sorted(p.name for p in self.dir.iterdir()
                      if ws.SEGMENT_RE.match(p.name) and ws.SEGMENT_RE.match(p.name).group("stem") == stem)

    def rotated(self, name="main.jsonl", at_least=3):
        self.assertGreaterEqual(len(self.closed(name)), at_least, "the fixture must have rotated")

    def make_gap(self, name="main.jsonl"):
        """Delete the middle segment (test fixture only) and prove the chain now reports a gap."""
        segments = self.closed(name)
        self.assertGreaterEqual(len(segments), 3)
        os.unlink(self.dir / segments[1])
        codes = [p["code"] for p in ws.chain(str(self.dir), self.stem(name)).problems]
        self.assertIn("gap", codes)

    def path(self, name="main.jsonl"):
        return self.dir / name

    def stderr(self, fn, *args, **kwargs):
        buf = io.StringIO()
        with redirect_stderr(buf):
            result = fn(*args, **kwargs)
        return result, buf.getvalue()


def load_script(path, name):
    spec = importlib.util.spec_from_file_location(name, str(path))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# ---------------------------------------------------------------------------------------------------------------
class WalNoteTests(Fixture):
    def test_ask_entry_and_open_ask_read_the_whole_chain(self):
        import wal_note
        self.append("main.jsonl", {"at": iso(), "event": "ask", "id": "wa5c00000001", "note": "need a decision"})
        self.fill("main.jsonl")
        self.rotated()
        self.assertEqual(wal_note.ask_entry(self.path(), "wa5c00000001")["note"], "need a decision")
        self.assertTrue(wal_note.open_ask_exists(self.path(), "wa5c00000001"))
        self.append("main.jsonl", {"at": iso(), "event": "ask_resolved", "ref": "wa5c00000001", "id": "wres00000001"})
        self.assertFalse(wal_note.open_ask_exists(self.path(), "wa5c00000001"))

    def test_a_gap_is_reported_on_stderr_and_never_silent(self):
        import wal_note
        self.append("main.jsonl", {"at": iso(), "event": "ask", "id": "wa5c00000002", "note": "need a decision"})
        self.fill("main.jsonl")
        self.make_gap()
        found, err = self.stderr(wal_note.open_ask_exists, self.path(), "wa5c00000002")
        self.assertTrue(found)  # the ask itself sits in the readable first segment
        self.assertIn("gap", err)
        problems = []
        wal_note.open_ask_exists(self.path(), "wa5c00000002", problems)
        self.assertIn("gap", [p["code"] for p in problems])

    def test_sibling_ask_wal_folds_segments_into_their_stem(self):
        import wal_note
        self.append("agent-x1.jsonl", {"at": iso(), "event": "ask", "id": "wa5c00000003", "note": "owner needs the user"})
        self.fill("agent-x1.jsonl")
        self.rotated("agent-x1.jsonl")
        self.append("main.jsonl", {"at": iso(), "event": "status", "note": "main"})
        # exactly one WAL holds the open ask: agent-x1 (never the closed segment agent-x1.0001 as a WAL of its own)
        self.assertEqual(wal_note.sibling_ask_wal(self.path(), "wa5c00000003"), "agent-x1")


class AgentGateTests(Fixture):
    def test_live_agents_see_a_start_record_in_a_closed_segment(self):
        import agent_gate
        now = time.time()
        self.append("main.jsonl", {"at": iso(), "event": "subagent", "agent_id": "a1"})
        self.fill("main.jsonl")
        self.append("main.jsonl", {"at": iso(), "event": "pretool", "agent_id": "a1"})
        self.rotated()
        self.assertEqual(agent_gate.live_agents(str(self.dir), now + 1), ["a1"])
        self.append("main.jsonl", {"at": iso(), "event": "subagent_stop", "agent_id": "a1"})
        self.assertEqual(agent_gate.live_agents(str(self.dir), now + 2), [])

    def test_a_gap_is_reported_by_the_gate_and_it_stays_fail_open(self):
        import agent_gate
        self.append("main.jsonl", {"at": iso(), "event": "subagent", "agent_id": "a1"})
        self.fill("main.jsonl")
        self.make_gap()
        result = agent_gate.decide(SESSION, now=time.time() + 1, wal_root=str(self.dir.parent),
                                   state_root=str(self.home / "state"))
        self.assertEqual(result["action"], "allow")  # documented fail-open gate
        self.assertIn("gap", [p["code"] for p in result["chain_problems"]])
        self.assertIn("Chain problem", result["message"])


class AhdTests(Fixture):
    def test_wal_asks_read_an_ask_from_a_closed_segment(self):
        import ahd
        self.append("main.jsonl", {"at": "2027-01-15T07:00:00+00:00", "event": "ask", "id": "w1", "note": "need a key"})
        self.fill("main.jsonl")
        self.rotated()
        self.assertEqual([a["id"] for a in ahd.wal_asks({}, [SESSION])], ["w1"])
        self.append("main.jsonl", {"event": "ask_resolved", "ref": "w1"})
        self.assertEqual(ahd.wal_asks({}, [SESSION]), [])

    def test_scan_sessions_use_the_chain_and_block_a_gap(self):
        import ahd
        self.append("main.jsonl", {"at": iso(), "event": "status", "note": "x"})
        self.fill("main.jsonl")
        self.rotated()
        usable, blocked = ahd.scan_sessions({}, time.time())
        self.assertEqual((usable, blocked), ([SESSION], {}))
        self.make_gap()
        usable, blocked = ahd.scan_sessions({}, time.time())
        self.assertEqual(usable, [])
        self.assertIn("gap", blocked[SESSION])

    def test_a_crashed_rotation_is_still_a_session(self):
        import ahd
        self.fill("main.jsonl")
        self.rotated()
        os.unlink(self.path())  # the crash window: closed segments, no live file yet
        usable, _blocked = ahd.scan_sessions({}, time.time())
        self.assertEqual(usable, [SESSION])


class AhdPeekTests(Fixture):
    def test_wal_tail_lines_cross_segments_and_report_a_gap(self):
        import ahd_peek
        self.fill("main.jsonl", n=80)
        self.rotated()
        lines, stats = ahd_peek.read_wal_tail_lines(str(self.path()), 1 << 20, 1 << 20)
        self.assertEqual(len([x for x in lines if x.strip()]), 80)  # the open markers are not rows
        self.assertEqual(stats["problems"], [])
        self.make_gap()
        _lines, stats = ahd_peek.read_wal_tail_lines(str(self.path()), 1 << 20, 1 << 20)
        self.assertIn("gap", [p["code"] for p in stats["problems"]])


class ReviewMapTests(Fixture):
    def test_find_wal_judges_a_chain_by_its_newest_write_and_reports_a_gap(self):
        import review_map
        self.append("main.jsonl", {"at": iso(), "event": "decision", "note": "chose the design for goodqa#1 here"})
        self.fill("main.jsonl")
        self.rotated()
        for name in self.closed():  # old segments carry old mtimes: the chain is as new as its live file
            os.utime(self.dir / name, (1, 1))
        rows = review_map.find_wal(["a" * 40], "feat/some-branch", ["GoodQA goodqa#1"], time.time() - 60, time.time())
        self.assertEqual([r["event"] for r in rows], ["decision"])
        self.make_gap()
        problems = []
        review_map.find_wal(["a" * 40], "feat/some-branch", ["GoodQA goodqa#1"], time.time() - 60, time.time(), problems)
        self.assertTrue(any("gap" in p for p in problems), problems)


class MissionCoverageTests(Fixture):
    def setUp(self):
        super().setUp()
        import mission_coverage
        self.mc = mission_coverage

    def test_find_wal_row_returns_the_logical_wal_and_reports_a_gap(self):
        self.append("main.jsonl", {"at": iso(), "event": "check", "id": "wabc00000001", "note": "REALLY_TESTED x ok"})
        self.fill("main.jsonl")
        self.rotated()
        name, rec = self.mc.find_wal_row(self.home, SESSION, "wabc00000001")
        self.assertEqual((name, rec["id"]), ("main.jsonl", "wabc00000001"))
        self.make_gap()
        problems = []
        self.assertEqual(self.mc.find_wal_row(self.home, SESSION, "w0000000dead", problems=problems), (None, None))
        self.assertTrue(any("gap" in p for p in problems), problems)

    def test_ask_states_read_the_chain(self):
        self.append("main.jsonl", {"at": iso(), "event": "ask", "id": "wa5c00000004", "note": "goal g1 needs the user"})
        self.fill("main.jsonl")
        self.rotated()
        states = self.mc.ask_states(self.home, SESSION)
        self.assertEqual(states["wa5c00000004"]["state"], "open")
        self.assertIn("goal g1", states["wa5c00000004"]["note"])
        self.append("main.jsonl", {"at": iso(), "event": "ask_resolved", "ref": "wa5c00000004"})
        self.assertEqual(self.mc.ask_states(self.home, SESSION)["wa5c00000004"]["state"], "resolved")
        self.make_gap()
        problems = []
        self.mc.ask_states(self.home, SESSION, problems)
        self.assertTrue(any("gap" in p for p in problems), problems)

    def test_owner_progress_finds_the_owners_last_own_row_in_an_old_segment(self):
        old = "2027-01-01T00:00:00+00:00"
        self.append("agent-own1.jsonl", {"at": old, "event": "status", "note": "my own entry"})
        self.fill("agent-own1.jsonl", pad=400)  # hook lifecycle rows only afterwards
        self.rotated("agent-own1.jsonl")
        self.assertEqual(self.mc.owner_progress(self.home, SESSION, "own1"), self.mc.parse_ts(old))


class AhExportTests(Fixture):
    def test_read_folds_segments_into_one_source_and_lists_a_gap_as_unread(self):
        import ah
        import ah_export
        for i in range(30):
            self.append("main.jsonl", {"at": iso(), "event": "status", "id": "w%011d" % i, "note": "n" * 500})
        self.rotated()
        rows, unread, skipped, agents = ah_export._read(ah, self.dir)
        self.assertEqual((agents, unread, skipped, len(rows)), (["main"], [], 0, 30))
        self.make_gap()
        _rows, unread, _skipped, agents = ah_export._read(ah, self.dir)
        self.assertEqual(agents, [])
        self.assertEqual([u["wal"] for u in unread], ["main.jsonl"])
        self.assertIn("gap", unread[0]["reason"])


class WalCadenceTests(Fixture):
    def test_last_human_entry_age_reaches_back_across_segments(self):
        import wal_cadence
        self.append("agent-own1.jsonl", {"at": iso(300), "event": "status", "note": "a human note"})
        self.fill("agent-own1.jsonl", pad=400)
        self.rotated("agent-own1.jsonl")
        age = wal_cadence.last_human_entry_age(self.path("agent-own1.jsonl"), time.time())
        self.assertIsNotNone(age)
        self.assertTrue(250 < age < 400, age)
        self.make_gap("agent-own1.jsonl")
        problems = []
        wal_cadence.last_human_entry_age(self.path("agent-own1.jsonl"), time.time(), problems)
        self.assertTrue(any("gap" in p for p in problems), problems)


class WorkdirTests(Fixture):
    def test_marked_done_reads_the_chain_and_fails_safe_on_a_gap(self):
        import workdir
        self.append("main.jsonl", {"at": iso(), "event": "status", "note": "WORKDIR_DONE all shipped"})
        self.fill("main.jsonl")  # only hook lifecycle rows afterwards
        self.rotated()
        self.assertTrue(workdir._marked_done(self.path()))

    def test_a_gap_never_marks_a_session_done(self):
        import workdir
        self.fill("main.jsonl", n=40)
        self.append("main.jsonl", {"at": iso(), "event": "status", "note": "WORKDIR_DONE tail"})
        self.rotated()
        self.assertTrue(workdir._marked_done(self.path()))
        self.make_gap()
        self.assertFalse(workdir._marked_done(self.path()))  # pruning never rests on a partial view

    def test_wal_mtime_counts_every_segment_and_a_missing_live_file(self):
        import workdir
        self.fill("main.jsonl")
        self.rotated()
        os.unlink(self.path())
        self.assertGreater(workdir._wal_mtime(self.path()), time.time() - 3600)


class DroppedGateTests(Fixture):
    def test_pending_work_sees_an_open_intent_in_a_closed_segment(self):
        import dropped_gate
        self.append("main.jsonl", {"at": iso(), "event": "status", "note": "main"})
        self.append("agent-own1.jsonl", {"at": iso(), "event": "intent", "note": "starting the work"})
        self.fill("agent-own1.jsonl")  # lifecycle rows afterwards: the last own entry is the intent
        self.rotated("agent-own1.jsonl")
        self.assertEqual(dropped_gate.pending_work(self.home, SESSION, "own1"), "last WAL entry is an open intent")

    def test_a_chain_problem_is_never_read_as_nothing_pending(self):
        import dropped_gate
        self.append("main.jsonl", {"at": iso(), "event": "status", "note": "main"})
        self.fill("agent-own1.jsonl")  # lifecycle rows only: nothing pending if the chain were whole
        self.make_gap("agent-own1.jsonl")
        why = dropped_gate.pending_work(self.home, SESSION, "own1")
        self.assertIsNotNone(why)
        self.assertIn("chain", why)


class GoalsViewTests(Fixture):
    def setUp(self):
        super().setUp()
        import goals_view
        import mission_coverage
        self.gv, self.mc = goals_view, mission_coverage

    def test_index_wals_resolves_an_attached_row_from_a_closed_segment(self):
        self.append("main.jsonl", {"at": iso(), "event": "check", "id": "wabc00000002", "note": "REALLY_TESTED t ok"})
        self.fill("main.jsonl")
        self.rotated()
        out = self.gv.index_wals(self.home, {(SESSION, "main.jsonl"): {"wabc00000002"}}, SESSION, [])
        self.assertIn((SESSION, "main.jsonl", "wabc00000002"), out["rows"])
        self.assertEqual(out["chain_problems"], [])

    def test_a_gap_is_reported_and_unresolved_rows_are_said_so(self):
        self.append("main.jsonl", {"at": iso(), "event": "check", "id": "wabc00000003", "note": "REALLY_TESTED t ok"})
        self.fill("main.jsonl")
        self.make_gap()
        out = self.gv.index_wals(self.home, {(SESSION, "main.jsonl"): {"w0000000beef"}}, SESSION, [])
        self.assertTrue(any("gap" in p for p in out["chain_problems"]), out["chain_problems"])
        self.assertEqual(out["chain_unresolved"], ["main.jsonl"])


class SkillScanTests(Fixture):
    def test_sessions_count_a_session_whose_main_wal_is_only_segments(self):
        scan = load_script(ROOT / "harness" / "skills" / "check-dropped-workstreams" / "scan.py", "scan_under_test")
        self.fill("main.jsonl")
        self.rotated()
        self.assertEqual(scan.sessions(self.home, 3600), [SESSION])
        os.unlink(self.path())  # crash window: no live file
        self.assertEqual(scan.sessions(self.home, 3600), [SESSION])


class BudgetTests(Fixture):
    """R2-4: a byte budget over a chain drops the OLDEST rows, never the newest, and says so (`truncated`)."""

    def test_agent_gate_window_keeps_the_newest_rows_and_reports_truncated(self):
        import agent_gate
        self.append("main.jsonl", {"at": iso(), "event": "subagent", "agent_id": "a-old"})
        self.fill("main.jsonl", n=30, pad=300)  # pushes the old start far beyond a small window
        self.append("main.jsonl", {"at": iso(), "event": "subagent", "agent_id": "a-new"})
        self.append("main.jsonl", {"at": iso(), "event": "pretool", "agent_id": "a-new"})
        self.rotated()
        problems = []
        with patch.object(agent_gate, "CHAIN_WINDOW_BYTES", 2000):
            live = agent_gate.live_agents(str(self.dir), time.time() + 1, problems=problems)
        self.assertEqual(live, ["a-new"])  # the newest start survives; the budget cut the oldest
        self.assertIn("truncated", [p["code"] for p in problems])

    def test_agent_gate_does_not_read_a_cold_owner_wal(self):
        import agent_gate
        self.append("main.jsonl", {"at": iso(), "event": "subagent", "agent_id": "a1"})
        self.append("main.jsonl", {"at": iso(), "event": "pretool", "agent_id": "a1"})
        self.append("agent-a1.jsonl", {"at": iso(), "event": "pretool", "agent_id": "a1"})
        os.utime(self.dir / "agent-a1.jsonl", (1, 1))  # idle far longer than the live window
        calls = []
        real = agent_gate.jsonl_records
        with patch.object(agent_gate, "jsonl_records", side_effect=lambda path, *a, **k: calls.append(path) or real(path, *a, **k)):
            self.assertEqual(agent_gate.live_agents(str(self.dir), time.time() + 1), ["a1"])
        self.assertEqual([os.path.basename(c) for c in calls], ["main.jsonl"])

    def test_the_real_hook_writes_subagent_start_and_stop_rows_to_main(self):
        """The cold-WAL skip in agent_gate rests on this: start and stop rows reach main.jsonl, not only the owner WAL."""
        import subprocess
        hook = HOOKS / "wal.py"
        env = dict(os.environ, HOME=str(self.home), HARNESS_PROVENANCE_OFFLINE="1")
        for event, payload in (("subagent", {"session_id": SESSION, "agent_id": "a1", "agent_type": "task-owner"}),
                               ("subagent_stop", {"session_id": SESSION, "agent_id": "a1", "agent_type": "task-owner"})):
            done = subprocess.run([sys.executable, str(hook), event], input=json.dumps(payload), text=True,
                                  capture_output=True, env=env)
            self.assertEqual(done.returncode, 0, done.stderr)
        events = [(r["event"], r.get("agent_id")) for r in self.records_of("main.jsonl")]
        self.assertIn(("subagent", "a1"), events)
        self.assertIn(("subagent_stop", "a1"), events)

    def records_of(self, name):
        return [json.loads(raw) for _s, _n, raw in ws.iter_lines(self.dir / name) if raw]

    def test_agent_gate_cold_is_judged_against_the_given_now(self):
        import agent_gate
        self.append("main.jsonl", {"at": iso(), "event": "subagent", "agent_id": "a1"})
        self.append("agent-a1.jsonl", {"at": iso(), "event": "pretool", "agent_id": "a1"})
        for now, expect in ((time.time() + 7200, ["main"]), (time.time() - 7200, ["agent-a1", "main"]),
                            (time.time() + 1, ["agent-a1", "main"])):
            calls = []
            real = agent_gate.jsonl_records
            with patch.object(agent_gate, "jsonl_records",
                              side_effect=lambda path, *a, **k: calls.append(os.path.basename(path)[:-6]) or real(path, *a, **k)):
                agent_gate.live_agents(str(self.dir), now)
            self.assertEqual(sorted(calls), expect, now - time.time())

    def test_ahd_wal_asks_window_keeps_the_newest_ask(self):
        import ahd
        self.append("main.jsonl", {"at": "2027-01-15T07:00:00+00:00", "event": "ask", "id": "wold", "note": "old ask"})
        self.fill("main.jsonl", n=30, pad=300)
        self.append("main.jsonl", {"at": "2027-01-15T08:00:00+00:00", "event": "ask", "id": "wnew", "note": "new ask"})
        self.rotated()
        got = ahd.wal_asks({"wal_asks_max_bytes": 3000}, [SESSION])
        self.assertEqual([a["id"] for a in got], ["wnew"])

    def test_review_map_keeps_the_newest_rows_over_the_cap_and_reports_it(self):
        import review_map
        self.append("main.jsonl", {"at": iso(), "event": "decision", "note": "OLD decision for goodqa#1"})
        self.fill("main.jsonl", n=30, pad=300)
        self.append("main.jsonl", {"at": iso(), "event": "decision", "note": "NEW decision for goodqa#1"})
        self.rotated()
        problems = []
        with patch.object(review_map, "MAX_WAL_BYTES", 3000):
            rows = review_map.find_wal(["a" * 40], "feat/some-branch", ["GoodQA goodqa#1"], time.time() - 60, time.time(), problems)
        self.assertEqual([r["note"] for r in rows], ["NEW decision for goodqa#1"])
        self.assertTrue(any("truncated" in p for p in problems), problems)

    def test_wal_cadence_window_keeps_the_newest_human_note(self):
        import wal_cadence
        self.append("agent-own1.jsonl", {"at": iso(900), "event": "status", "note": "older note"})
        self.fill("agent-own1.jsonl", n=30, pad=300)
        self.append("agent-own1.jsonl", {"at": iso(60), "event": "status", "note": "newest note"})
        self.rotated("agent-own1.jsonl")
        with patch.object(wal_cadence, "WAL_TAIL_BYTES", 2000):
            age = wal_cadence.last_human_entry_age(self.path("agent-own1.jsonl"), time.time())
        self.assertTrue(30 < age < 200, age)


# ---------------------------------------------------------------------------------------------------------------
class ListingRaceTests(Fixture):
    """Gate findings F2 to F4 of PR 329: the pre-scanned listing (chain=) must stay correct when the WAL grows or
    rotates between `list_wals` and the read, ah_export must bound each read, and one session costs one scan."""

    def rows(self, n, start=0, pad=500):
        for i in range(start, start + n):
            self.append("main.jsonl", {"at": iso(), "event": "status", "id": "w%011d" % i, "n": i, "note": "x" * pad})

    def after_listing(self, action):
        """list_wals that runs `action` once, right after the directory was listed (a rotation after the listing)."""
        real = ws.list_wals
        done = []

        def listing(directory):
            chains = real(directory)
            if not done:
                done.append(True)
                action()
            return chains
        return listing

    def test_ah_export_rotation_after_listing_loses_and_duplicates_nothing(self):
        import ah
        import ah_export
        self.rows(30)
        self.rotated()
        with patch.object(ws, "list_wals", self.after_listing(lambda: self.rows(12, start=30))):
            rows, unread, _skipped, agents = ah_export._read(ah, self.dir)
        self.assertEqual([r["n"] for _a, r in rows], list(range(42)))  # none lost, none twice, in order
        self.assertEqual((agents, unread), (["main"], []))

    def test_ah_export_a_gap_is_still_reported_when_the_chain_rotates_after_listing(self):
        import ah
        import ah_export
        self.rows(30)
        self.make_gap()
        with patch.object(ws, "list_wals", self.after_listing(lambda: self.rows(12, start=30))):
            _rows, unread, _skipped, _agents = ah_export._read(ah, self.dir)
        self.assertEqual([u["wal"] for u in unread], ["main.jsonl"])
        self.assertIn("gap", unread[0]["reason"])

    def test_ah_export_bounds_each_read_by_the_limits_and_lists_a_grown_wal_as_unread(self):
        import ah
        import ah_export
        self.rows(2, pad=100)  # small at listing time, under the limit
        with patch.object(ah_export, "TOTAL_LIMIT", 3000), \
                patch.object(ws, "list_wals", self.after_listing(lambda: self.rows(12, start=2, pad=500))):
            rows, unread, _skipped, agents = ah_export._read(ah, self.dir)
        self.assertEqual(agents, [])  # it grew past the limit after the listing: never exported in part
        self.assertEqual([u["wal"] for u in unread], ["main.jsonl"])
        self.assertIn("truncated", unread[0]["reason"])

    def test_agent_gate_rotation_after_listing_keeps_every_agent_and_a_gap_is_reported(self):
        import agent_gate
        self.append("main.jsonl", {"at": iso(), "event": "subagent", "agent_id": "a1"})
        self.fill("main.jsonl", n=45, pad=300, event="status")
        self.rotated()
        grow = lambda: [self.append("main.jsonl", {"at": iso(), "event": "pretool", "agent_id": "a1", "pad": "x" * 500})
                        for _ in range(12)]
        with patch.object(ws, "list_wals", self.after_listing(grow)):
            self.assertEqual(agent_gate.live_agents(str(self.dir), time.time() + 1), ["a1"])
        self.make_gap()
        problems = []
        with patch.object(ws, "list_wals", self.after_listing(grow)):
            agent_gate.live_agents(str(self.dir), time.time() + 1, problems=problems)
        self.assertIn("gap", [p["code"] for p in problems])

    def test_one_directory_scan_per_session(self):
        import ah
        import agent_gate
        import ah_export
        for i in range(6):
            self.append(f"agent-a{i}.jsonl", {"at": iso(), "event": "status", "id": "w%011d" % i, "n": i})
        self.append("main.jsonl", {"at": iso(), "event": "subagent", "agent_id": "a0"})
        for label, call in (("agent_gate", lambda: agent_gate.live_agents(str(self.dir), time.time() + 1)),
                            ("ah_export", lambda: ah_export._read(ah, self.dir))):
            scans = []
            real = ws._scan
            with patch.object(ws, "_scan", side_effect=lambda *a, **k: scans.append(a) or real(*a, **k)):
                call()
            self.assertEqual(len(scans), 1, f"{label} scanned the directory {len(scans)} times for 7 WALs")

    def test_opens_are_counted_through_both_open_paths_on_a_rotated_chain(self):
        import goals_view
        self.append("main.jsonl", {"at": iso(), "event": "check", "id": "wabc00000002", "note": "REALLY_TESTED t ok"})
        self.fill("main.jsonl")
        self.rotated()
        opened = []
        real_regular, real_at = ws._open_regular, ws._open_at
        patches = (patch.object(ws, "_open_regular", side_effect=lambda d, n, *a, **k: opened.append(n) or real_regular(d, n, *a, **k)),
                   patch.object(ws, "_open_at", side_effect=lambda dfd, d, n, *a, **k: opened.append(n) or real_at(dfd, d, n, *a, **k)))
        with patches[0], patches[1]:
            goals_view.index_wals(self.home, {(SESSION, "main.jsonl"): {"wabc00000002"}}, SESSION, ["goal-x"])
        members = sorted(self.closed()) + ["main.jsonl"]
        self.assertEqual(sorted(opened), members, "each member of the chain is opened exactly once per report")


MIGRATED = ("wal_note", "agent_gate", "ahd", "ahd_peek", "review_map", "mission_coverage", "ah_export", "wal_cadence",
            "workdir", "dropped_gate", "goals_view")
# modules of this set that name WAL files but read none (reviewed, with the reason)
ALLOWLIST = {
    "worktree_hygiene.py": "reads Claude Code transcripts (projects/*.jsonl), read-only sources the spec leaves out of scope",
}
OPEN_RE = re.compile(r"open\([^)\n]*(?:main|agent-[^)\n]*)\.jsonl")


class InventoryTests(unittest.TestCase):
    def test_every_migrated_module_names_the_chain_reader_and_opens_no_wal_directly(self):
        for module in MIGRATED:
            source = (HOOKS / f"{module}.py").read_text()
            with self.subTest(module=module):
                self.assertIn("wal_segments", source)
                self.assertIsNone(OPEN_RE.search(source), "a migrated reader must not open a WAL file by name")

    def test_the_scan_regex_has_a_negative_control(self):
        self.assertIsNotNone(OPEN_RE.search("with open(folder / 'main.jsonl') as fh:"))
        self.assertIsNotNone(OPEN_RE.search("open(wal_dir + '/agent-x.jsonl')"))

    def test_allowlisted_modules_read_no_wal(self):
        for name, reason in ALLOWLIST.items():
            with self.subTest(module=name):
                self.assertTrue(reason)
                self.assertIsNone(OPEN_RE.search((HOOKS / name).read_text()))

    def test_codex_hooks_have_no_wal_reader_of_their_own(self):
        source = (ROOT / "codex" / "hooks" / "wal.py").read_text()
        self.assertIn("wal_segments", source)  # the writer is the shared one; it reads only checkpoint state files
        self.assertNotIn("iter_jsonl_lines", source)


if __name__ == "__main__":
    unittest.main()
