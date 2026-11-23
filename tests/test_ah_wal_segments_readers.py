"""goodqa#16751: every WAL reader of ah.py reads the whole segment chain (docs/wal-segments.md).

Each test builds a rotated fixture (a WAL split over two or three segments, the live file starting with an open
marker) and compares the reader with the same records in one file, or builds a chain with a gap and asserts the gap
is said (an unread source, or an AhError for a caller with nowhere to say it) and never skipped. The fixtures are
written by hand (names and markers per the spec), so they do not depend on the writer or on the rotation switch.
"""
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

HOOKS = Path(__file__).resolve().parents[1] / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
os.environ["AGENT_HARNESS_POLICY_LOCAL"] = str(Path(__file__).resolve().parent / "data" / "policy_profile_fixture.json")
import ah  # noqa: E402

SID = "11111111-2222-3333-4444-555555555555"
NOW = 1_800_000_000.0


def iso(ts):
    return ah.iso(ts)


def marker(stem, seq):
    return json.dumps({"at": iso(NOW - 1), "event": "wal_segment_open", "by": "wal_segments", "schema": 1, "stem": stem,
                       "segment": seq, "prev": f"{stem}.{seq - 1:04d}.jsonl", "prev_bytes": 0, "prev_lines": 0,
                       "prev_sha256": "0" * 64, "limit": 52428800})


def put(directory, name, rows, mode="w"):
    directory.mkdir(parents=True, exist_ok=True)
    with open(directory / name, mode) as fh:
        for r in rows:
            fh.write((r if isinstance(r, str) else json.dumps(r)) + "\n")


def chain(directory, stem, parts):
    """The WAL `stem` as len(parts) segments: the closed ones S.0001.jsonl.., the last one live; every file after
    the first starts with its open marker, as a rotation writes it."""
    for i, recs in enumerate(parts, 1):
        name = f"{stem}.{i:04d}.jsonl" if i < len(parts) else f"{stem}.jsonl"
        put(directory, name, ([marker(stem, i)] if i >= 2 else []) + list(recs))


def flat(directory, stem, parts):
    put(directory, f"{stem}.jsonl", [r for part in parts for r in part])


def split3(recs):
    n = len(recs)
    a, b = max(1, n // 3), max(2, 2 * n // 3)
    return [recs[:a], recs[a:b], recs[b:]]


def spawn(agent, at):
    return {"at": iso(at), "event": "subagent", "agent_id": agent, "agent_type": "task-owner"}


MAIN = [spawn("ownera", NOW - 9000), spawn("ownerb", NOW - 8900),
        {"at": iso(NOW - 3000), "event": "subagent_stop", "agent_id": "ownerb", "agent_type": "task-owner"},
        {"at": iso(NOW - 2900), "event": "ask", "id": "w00000000a01", "owner": "ownera", "note": "may main push?",
         "reason": "r", "source": "inferred: fixture"},
        {"at": iso(NOW - 60), "event": "intent", "id": "wint00000001", "note": "keep going"}]
OWNERA = [{"at": iso(NOW - 5000), "event": "intent", "note": "build GoodQA goodqa#42 the parser"},
          {"at": iso(NOW - 4000), "event": "status", "note": "half way"},
          {"at": iso(NOW - 3500), "event": "decision", "note": "use the safe path"},
          {"at": iso(NOW - 100), "event": "result", "note": "all done"}]
OWNERB = [{"at": iso(NOW - 4500), "event": "intent", "note": "second stream"},
          {"at": iso(NOW - 3100), "event": "handoff", "note": "handed to main"}]


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name)
        p = mock.patch.dict(os.environ, {"AH_HOME": str(self.home), "HOME": str(self.home)})
        clock = mock.patch.object(ah, "server_now", side_effect=lambda: iso(NOW))
        clock.start()
        self.addCleanup(clock.stop)
        p.start()
        self.addCleanup(p.stop)
        for k in ("CLAUDE_CODE_CHILD_SESSION", "AH_AGENT_ID", "AGENT_ID"):
            os.environ.pop(k, None)
        self.w = self.home / ".claude" / "wals" / SID

    def other_home(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        return Path(tmp.name)

    def build(self, rotated, home=None):
        home = home or self.home
        w = home / ".claude" / "wals" / SID
        for stem, recs in (("main", MAIN), ("agent-ownera", OWNERA), ("agent-ownerb", OWNERB)):
            (chain if rotated else flat)(w, stem, split3(recs) if rotated else [recs])
        return home

    def owners(self, home=None):
        with mock.patch.dict(os.environ, {"AH_HOME": str(home or self.home), "HOME": str(home or self.home)}):
            return ah.owners(home or self.home, SID, now=NOW)

    @staticmethod
    def view(doc):
        keys = ("agent_id", "type", "task", "ticket", "state", "last_activity", "result_at", "owner", "idle_s")
        return sorted(({k: r.get(k) for k in keys} for r in doc["owners"]), key=lambda r: r["agent_id"])

    def unread_text(self, doc):
        return json.dumps(doc["read"]["unread"])


class OwnersOverChains(Base):
    def test_a_rotated_session_answers_like_one_file(self):
        flat_doc = self.owners(self.build(False, self.other_home()))
        rotated_doc = self.owners(self.build(True))
        self.assertEqual(sorted(r["agent_id"] for r in rotated_doc["owners"]), ["ownera", "ownerb"])
        self.assertEqual(self.view(rotated_doc), self.view(flat_doc))
        self.assertEqual(rotated_doc["read"]["state"], "ok", rotated_doc["read"])
        self.assertEqual(flat_doc["read"]["state"], "ok", flat_doc["read"])

    def test_a_segment_is_not_an_agent(self):
        self.build(True)
        found = ah.discover_agents(self.home, SID, self.w)
        self.assertEqual(sorted(found), ["ownera", "ownerb"])

    def test_a_gap_in_the_main_chain_makes_the_view_partial(self):
        w = self.w
        put(w, "main.0001.jsonl", MAIN[:2])
        put(w, "main.0003.jsonl", [marker("main", 3)] + MAIN[2:4])    # segment 2 is missing
        put(w, "main.jsonl", [marker("main", 4)] + MAIN[4:])
        doc = self.owners()
        self.assertNotEqual(doc["read"]["state"], "ok", doc["read"])
        self.assertIn("gap", self.unread_text(doc))

    def test_a_gap_in_an_agent_chain_makes_the_view_partial(self):
        self.build(False)
        w = self.w
        (w / "agent-ownera.jsonl").unlink()
        put(w, "agent-ownera.0001.jsonl", OWNERA[:1])
        put(w, "agent-ownera.0003.jsonl", [marker("agent-ownera", 3)] + OWNERA[1:3])
        put(w, "agent-ownera.jsonl", [marker("agent-ownera", 4)] + OWNERA[3:])
        doc = self.owners()
        self.assertNotEqual(doc["read"]["state"], "ok", doc["read"])
        self.assertIn("agent-ownera", self.unread_text(doc))
        self.assertIn("gap", self.unread_text(doc))
        row = {r["agent_id"]: r for r in doc["owners"]}["ownera"]
        self.assertEqual(row["result_at"], iso(NOW - 100))      # the newest record is still read

    def test_a_task_named_wal_is_read_across_its_segments(self):
        recs = [{"at": iso(NOW - 600), "event": "intent", "note": "task wal first GoodQA goodqa#7"},
                {"at": iso(NOW - 300), "event": "status", "note": "task wal middle"},
                {"at": iso(NOW - 50), "event": "result", "note": "task wal done"}]
        self.build(False)
        chain(self.w, "taskwal", split3(recs))
        for f in self.w.glob("taskwal*.jsonl"):
            os.utime(f, (NOW, NOW))      # inside the 48 h window the owners view keeps task WALs
        row = {r["agent_id"]: r for r in self.owners()["owners"]}["taskwal"]
        self.assertEqual((row["type"], row["ticket"]), ("task-wal", "GoodQA goodqa#7"))
        self.assertEqual(row["result_at"], iso(NOW - 50))


class SummaryAndItsCaches(Base):
    def summary(self, home, stem="agent-ownera"):
        return ah.summarize_agent_wal(home / ".claude" / "wals" / SID / f"{stem}.jsonl", ah.state_dir(home, "ah-index"))

    FIELDS = ("first", "last_at", "outcome", "outcome_at", "last_note", "tickets", "events", "skipped")

    def facts(self, s):
        return {k: s[k] for k in self.FIELDS}

    def test_the_summary_of_a_chain_equals_the_summary_of_one_file(self):
        flat_s = self.summary(self.build(False, self.other_home()))
        rot_s = self.summary(self.build(True))
        self.assertEqual(self.facts(rot_s), self.facts(flat_s))
        self.assertEqual(rot_s["events"], len(OWNERA))      # an open marker is never an event

    def test_the_offset_cache_survives_a_rotation_without_a_rescan(self):
        w = self.w
        put(w, "main.jsonl", MAIN)
        put(w, "agent-ownera.jsonl", OWNERA[:2])
        put(w, "agent-ownerb.jsonl", OWNERB)
        before = self.owners()
        row = {r["agent_id"]: r for r in before["owners"]}["ownera"]
        self.assertEqual(row["ticket"], "GoodQA goodqa#42")
        put(w, "agent-ownera.jsonl", OWNERA[2:3], mode="a")      # appended, then the file rotates under the reader
        os.rename(w / "agent-ownera.jsonl", w / "agent-ownera.0001.jsonl")
        put(w, "agent-ownera.jsonl", [marker("agent-ownera", 2)] + OWNERA[3:])
        calls = []
        real = ah.read_new_lines
        with mock.patch.object(ah, "read_new_lines", side_effect=lambda path, meta, **kw: (calls.append(dict(meta)), real(path, meta, **kw))[1]):
            after = self.owners()
        self.assertTrue(any(c.get("offset") for c in calls), calls)      # resumed in the renamed file, not rescanned
        cold = self.owners(self.build(False, self.other_home()))
        self.assertEqual(self.view(after), self.view(cold))
        s = self.summary(self.home)
        self.assertEqual((s["events"], s["first"]), (len(OWNERA), "build GoodQA goodqa#42 the parser"))

    def test_a_rotation_between_the_listing_and_the_open_is_not_missed(self):
        """owners lists the directory once and summarizes each live-only WAL from that listing: a rotation after the
        listing leaves another file under the name, which must never be read as the file that was listed."""
        w = self.w
        live = w / "agent-ownera.jsonl"
        put(w, "agent-ownera.jsonl", OWNERA[:2])
        listed = ah._wal_chain(live)
        self.assertEqual((listed.segments, listed.live.name), ([], "agent-ownera.jsonl"))
        os.rename(live, w / "agent-ownera.0001.jsonl")      # the rotation, after the listing
        put(w, "agent-ownera.jsonl", [marker("agent-ownera", 2)] + OWNERA[2:])
        self.assertIsNone(ah._live_only_snapshot(live, listed))      # a different file under the listed name
        ah._CHAIN_HINT[str(live)] = listed
        try:
            s = ah._summarize_agent_wal(live, ah.state_dir(self.home, "ah-index"))
        finally:
            ah._CHAIN_HINT.pop(str(live), None)
        self.assertEqual(s["events"], len(OWNERA))

    def test_a_replaced_closed_segment_is_rescanned(self):
        self.build(True)
        self.owners()
        w = self.w
        swapped = [{"at": iso(NOW - 5000), "event": "intent", "note": "a different first record"}]
        put(w, "swap.tmp", swapped)
        os.replace(w / "swap.tmp", w / "agent-ownera.0001.jsonl")      # a segment restored from a backup
        s = self.summary(self.home)
        self.assertEqual(s["first"], "a different first record")
        self.assertEqual(s["events"], 1 + len(split3(OWNERA)[1]) + len(split3(OWNERA)[2]))

    def test_a_closed_segment_rewritten_in_place_with_the_same_size_is_rescanned(self):
        self.build(True)
        self.owners()
        seg = self.w / "agent-ownera.0001.jsonl"
        before = (seg.stat().st_ino, seg.stat().st_size)
        text = seg.read_text()
        self.assertIn("the parser", text)
        with open(seg, "r+") as fh:      # the same inode and the same size: only the mtime tells
            fh.write(text.replace("the parser", "the lexers"))
        self.assertEqual((seg.stat().st_ino, seg.stat().st_size), before)
        self.assertEqual(self.summary(self.home)["first"], "build GoodQA goodqa#42 the lexers")

    def test_a_restored_middle_segment_is_read_when_it_comes_back(self):
        w = self.w
        put(w, "main.jsonl", MAIN)
        parts = split3(OWNERA)
        put(w, "agent-ownera.0001.jsonl", parts[0])
        put(w, "agent-ownera.0003.jsonl", [marker("agent-ownera", 3)] + parts[2])      # segment 2 missing
        put(w, "agent-ownera.jsonl", [marker("agent-ownera", 4)])
        gap = self.summary(self.home)
        self.assertEqual(gap["events"], len(parts[0]) + len(parts[2]))
        put(w, "agent-ownera.0002.jsonl", [marker("agent-ownera", 2)] + parts[1])      # restored
        whole = self.summary(self.home)
        self.assertEqual(whole["events"], len(OWNERA))

    def test_only_a_files_own_open_marker_is_dropped_as_wal_segments_does(self):
        """THE marker rule (wal_segments.Snapshot._drops_marker) in the incremental reader: a marker-shaped line 1 of
        another segment or stem is an ordinary record. Compared with the reader API on the same fixture."""
        w = self.w
        stray = marker("agent-ownera", 7)         # not this file's marker (the live file is segment 2)
        put(w, "agent-ownera.0001.jsonl", OWNERA[:1])
        put(w, "agent-ownera.jsonl", [stray] + OWNERA[1:])
        s = self.summary(self.home)
        api = [raw for _seg, _n, raw in ah._ws().iter_lines(w / "agent-ownera.jsonl")]
        self.assertEqual(len(api), len(OWNERA) + 1)      # the reader API keeps the stray line as a record
        self.assertEqual((s["events"], s["skipped"]), (len(OWNERA) + 1, 0))      # the stray line is a record, never dropped
        put(w, "agent-ownera.jsonl", [marker("agent-ownera", 2)] + OWNERA[1:])
        fresh = ah._summarize_agent_wal(w / "agent-ownera.jsonl", ah.state_dir(self.other_home(), "ah-index"))
        self.assertEqual((fresh["events"], fresh["skipped"]), (len(OWNERA), 0))

    def test_a_partial_last_line_in_a_closed_segment_is_a_lost_line(self):
        w = self.w
        put(w, "agent-ownera.0001.jsonl", [json.dumps(OWNERA[0])])
        with open(w / "agent-ownera.0001.jsonl", "a") as fh:
            fh.write('{"at":"x","event":"sta')      # no newline: a closed segment ends with one
        put(w, "agent-ownera.jsonl", [marker("agent-ownera", 2)] + OWNERA[1:])
        s = self.summary(self.home)
        self.assertEqual((s["skipped"], s["events"]), (1, len(OWNERA)))


class AskAndLookupHelpers(Base):
    def setUp(self):
        super().setUp()
        self.main = self.w / "main.jsonl"
        chain(self.w, "main", [[spawn("ownera", NOW - 9000),
                                {"at": iso(NOW - 8000), "event": "ask", "id": "w00000000a01", "owner": "ownerb",
                                 "note": "q?", "reason": "r", "source": "inferred: fixture"},
                                {"at": iso(NOW - 7000), "event": "ask", "id": "w00000000a02", "note": "q2?", "reason": "r",
                                 "source": "inferred: fixture"}],
                               [{"at": iso(NOW - 6000), "event": "ask_resolved", "id": "w00000000a03", "ref": "w00000000a02",
                                 "note": "yes"}],
                               []])

    def test_ask_state_owner_and_entries_come_from_every_segment(self):
        self.assertEqual(ah.ask_states(self.main), {"w00000000a01": "open", "w00000000a02": "resolved"})
        self.assertEqual(ah.ask_owners(self.main), {"w00000000a01": "ownerb"})
        self.assertTrue(ah._wal_has(self.main, "subagent", None, agent="ownera"))
        self.assertFalse(ah._wal_has(self.main, "subagent", None, agent="nobody"))
        with self.assertRaises(ah.AhError):      # the ask belongs to ownerb: a wait on it excuses only ownerb
            ah.narrow_wait(self.home, self.main, SID, "ownera", "w00000000a01")

    def test_a_gap_is_said_never_an_empty_or_partial_answer(self):
        os.unlink(self.w / "main.0001.jsonl")      # segments 2 and the live file remain: segment 1 is a gap
        for fn in (ah.ask_states, ah.ask_owners):
            with self.subTest(reader=fn.__name__):
                with self.assertRaises(ah.AhError) as c:
                    fn(self.main)
                self.assertEqual(c.exception.code, "wal_incomplete")
                tally = ah.ReadTally()
                fn(self.main, tally)
                self.assertTrue(any("gap" in u["reason"] for u in tally.unread), tally.unread)
        with self.assertRaises(ah.AhError):
            ah.narrow_wait(self.home, self.main, SID, "ownera", "w00000000a09")
        with self.assertRaises(ah.AhError):
            ah._wal_has(self.main, "subagent", None, agent="nobody")      # not found across a gap is unknown, not absent
        self.assertTrue(ah._wal_has(self.main, "ask_resolved", "w00000000a03"))      # found newest first stays found


class TailHelpers(Base):
    def test_pending_stop_marker_is_not_repeated_when_the_last_line_sits_in_the_previous_segment(self):
        put(self.w, "main.jsonl", MAIN)
        stop = {"at": iso(NOW - 500), "event": "pending_stop", "id": "wpend0000001", "by": "dropped_gate", "note": "stopped"}
        chain(self.w, "agent-dropowner", [[{"at": iso(NOW - 900), "event": "intent", "note": "work"}, stop], []])
        wal = self.w / "agent-dropowner.jsonl"
        self.assertTrue(ah._last_line_is(wal, "pending_stop"))      # live holds only the open marker
        ah.write(self.home, "task.pending", {"agent": "dropowner", "session": SID, "at": iso(NOW)}, SID, "pend-key-00-0000")
        logical = (self.w / "agent-dropowner.0001.jsonl").read_text() + (self.w / "agent-dropowner.jsonl").read_text()
        self.assertEqual(logical.count('"pending_stop"'), 1)

    def test_a_deadline_is_recorded_when_the_live_file_is_missing_but_segments_exist(self):
        chain(self.w, "main", [MAIN[:2], MAIN[2:]])
        os.unlink(self.w / "main.jsonl")      # a crashed rotation: no live file, closed segments only
        r = ah.write(self.home, "deadline.add", {"session": SID, "at": iso(NOW + 1800), "ref": "GoodQA goodqa#14791",
                                                 "owner": "ownera", "note": "check"}, SID, "dl-key-000001")
        self.assertTrue(r["deadline"].startswith("dl"))

    def test_nearest_source_reads_the_previous_segment(self):
        sourced = {"at": iso(NOW - 900), "event": "decision", "id": "wdec00000001", "note": "use safe path", "source": "file:x"}
        chain(self.w, "main", [[sourced], [{"at": iso(NOW - 10), "event": "status", "note": "later"}]])
        got = ah.nearest_source(self.w / "main.jsonl")
        self.assertEqual(got and got["id"], "wdec00000001")


class SessionDiscovery(Base):
    def test_session_dir_finds_a_session_whose_live_file_is_missing(self):
        codex = self.home / ".agent-harness" / "codex-wals" / SID
        put(codex, "main.0001.jsonl", MAIN[:2])
        self.assertEqual(ah.session_dir(self.home, SID), codex)

    def test_list_sessions_and_newest_session_count_a_segments_only_main(self):
        put(self.w, "main.0001.jsonl", MAIN[:2])
        self.assertEqual([s for s, _ in ah.list_sessions(self.home)], [SID])
        self.assertEqual(ah.newest_session(self.home), SID)


class EvidenceLookups(Base):
    def reg(self):
        return {"received_at": iso(NOW - 10000), "args": {"session": SID, "owner_agent": "ownerx", "task": "t1"}}

    def test_a_really_tested_entry_in_an_old_segment_counts(self):
        note = {"at": iso(NOW - 500), "event": "check", "id": "wq1", "note": "REALLY_TESTED t1: ran it live on https://app.example"}
        chain(self.w, "main", [[note], [{"at": iso(NOW - 10), "event": "status", "note": "later"}]])
        wal = (self.w / "main.jsonl").resolve()
        ah._evidence_ok(self.home, [{"really_tested": "t1", "wal": str(wal)}], {wal}, self.reg(), [])

    def test_not_found_across_a_gap_is_unverifiable_not_absent(self):
        put(self.w, "main.0001.jsonl", MAIN[:1])
        put(self.w, "main.0003.jsonl", [marker("main", 3)] + MAIN[1:2])
        put(self.w, "main.jsonl", [marker("main", 4)] + MAIN[2:])
        wal = (self.w / "main.jsonl").resolve()
        with self.assertRaises(ah.AhError) as c:
            ah._evidence_ok(self.home, [{"really_tested": "t1", "wal": str(wal)}], {wal}, self.reg(), [])
        self.assertEqual(c.exception.code, "evidence_unverifiable")

    def test_session_entries_read_every_segment_and_refuse_a_miss_across_a_gap(self):
        rec = {"at": iso(NOW - 500), "event": "deploy", "id": "wde00000000a", "note": "DEPLOYED app v1.0.0"}
        chain(self.w, "main", [[rec], [{"at": iso(NOW - 10), "event": "status", "note": "later"}]])
        found = ah._session_entries(self.home, SID, ah._by_id("wde00000000a"))
        self.assertEqual([r["id"] for r in found], ["wde00000000a"])
        os.unlink(self.w / "main.0001.jsonl")
        put(self.w, "main.0003.jsonl", [marker("main", 3)])
        with self.assertRaises(ah.AhError) as c:
            ah._session_entries(self.home, SID, ah._by_id("wde00000000a"))
        self.assertEqual(c.exception.code, "evidence_unverifiable")
        put(self.w, "main.0003.jsonl", [marker("main", 3), rec], mode="w")      # found beyond the gap: still found
        self.assertEqual(len(ah._session_entries(self.home, SID, ah._by_id("wde00000000a"))), 1)


class StatusOverChains(Base):
    def report(self):
        return ah.status_report(self.home, SID, ah.parse_since("12h"), now=NOW)

    def test_a_rotated_wal_is_one_logical_wal_and_a_gap_is_listed(self):
        tested = {"at": iso(NOW - 500), "event": "check", "id": "wq1", "note": "REALLY_TESTED PP-1: curl on prod, 200"}
        chain(self.w, "main", [[spawn("ownera", NOW - 900)], [{"at": iso(NOW - 400), "event": "status", "note": "x"}]])
        chain(self.w, "agent-ownera", [[tested], [{"at": iso(NOW - 300), "event": "status", "note": "y"}], []])
        r = self.report()
        self.assertEqual([(v["check"], v["agent"]) for v in r["verified"]], [("PP-1", "ownera")])      # one agent, not three
        self.assertEqual(r["unread"], [])
        os.unlink(self.w / "agent-ownera.0002.jsonl")      # a gap inside the owner's chain
        put(self.w, "agent-ownera.0003.jsonl", [marker("agent-ownera", 3)])
        os.unlink(self.w / "agent-ownera.jsonl")
        put(self.w, "agent-ownera.jsonl", [marker("agent-ownera", 4)])
        r = self.report()
        wal_entries = [u for u in r["unread"] if "wal" in u]
        self.assertEqual([u["wal"] for u in wal_entries], ["agent-ownera.jsonl"])
        self.assertIn("gap", wal_entries[0]["reason"])
        self.assertIn("owners view", [u["source"] for u in r["unread"]])      # and the owners view says it is partial
        self.assertEqual([v["check"] for v in r["verified"]], ["PP-1"])      # what is readable is still reported


class DoctorNamesALostSegment(Base):
    def test_a_lost_segment_is_a_failing_check_with_the_recover_command(self):
        chain(self.w, "main", split3(MAIN))
        with mock.patch.dict(os.environ, {"AH_EXPECT_AHD": "0"}):
            healthy = [c for c in ah.doctor()["checks"] if c["check"].startswith("wal chain")]
            os.unlink(self.w / "main.0001.jsonl")
            checks = [c for c in ah.doctor()["checks"] if c["check"].startswith("wal chain")]
            doc_ok = ah.doctor()["ok"]
        self.assertEqual(healthy, [])
        self.assertEqual(len(checks), 1)
        self.assertFalse(checks[0]["ok"])
        self.assertIn("gap", checks[0]["problem"])
        self.assertIn("wal_segments.py verify", checks[0]["recover"])
        self.assertIn("--allow-gaps", checks[0]["recover"])
        self.assertFalse(doc_ok)

    def test_the_refusal_points_at_doctor(self):
        chain(self.w, "main", split3(MAIN))
        os.unlink(self.w / "main.0001.jsonl")
        with self.assertRaises(ah.AhError) as c:
            ah.ask_states(self.w / "main.jsonl")
        self.assertIn("ah doctor", str(c.exception))


class NoDirectOpen(unittest.TestCase):
    READERS = ("owners", "discover_agents", "summarize_agent_wal", "_summarize_agent_wal", "_summarize_cached", "ask_owners",
               "narrow_wait", "ask_states", "_wal_has", "_last_line_is", "_evidence_ok", "_session_entries",
               "_owner_context", "status_report", "nearest_source", "note_cmd", "newest_session", "list_sessions",
               "session_dir", "requirements_view", "chain_new_lines", "_wal_lines", "_wal_exists", "_wal_mtime",
               "_wal_fingerprint", "_wal_chain")
    # The only functions of the WAL read path that open a file themselves, each with why (reviewer question 1).
    OPENERS = {
        "_segment_fd": "opens one CLOSED segment by the name wal_segments.chain listed, O_NOFOLLOW, accepted only when "
                       "its inode is the listed one",
        "_live_only_snapshot": "opens a WAL that the single list_wals listing showed as a live file only, accepted only "
                               "when its inode is the listed one (else wal_segments.open_chain is used): one directory "
                               "listing per agent made cold `ah owners` on 2,400 agents 8.0 s instead of 1.1 s",
        "read_new_lines": "shared with the transcript indexer: reads a path (a transcript) or a descriptor the caller "
                          "pinned (a WAL chain); never a WAL by name",
    }
    OPEN = r"(?<![\w])(?:os\.)?open\("

    def test_no_wal_reader_opens_or_globs_a_wal_by_name_except_the_reviewed_helpers(self):
        """A guard that can fail: the WAL read path reaches a WAL through the wal_segments reader API, except for
        the helpers in OPENERS. (ah._wal_append is the writer and keeps its own bounded plain-append fallback; the
        ledger, the audit log and the transcripts are not WALs.)"""
        import inspect
        import re
        opening, checked = set(), 0
        for name in self.READERS + tuple(self.OPENERS):
            fn = getattr(ah, name, None)
            self.assertIsNotNone(fn, f"{name} is gone: update the guard")
            checked += 1
            src = inspect.getsource(fn)
            if re.search(self.OPEN, src):
                opening.add(name)
            with self.subTest(reader=name):
                self.assertNotIn(".glob(", src)
                self.assertNotIn(".is_file()", src)
                self.assertNotIn("safe_input.read_tail", src)
                self.assertNotIn("_bounded(path", src)
        self.assertEqual(opening, set(self.OPENERS), "a WAL reader opens a file itself: use the reader API or review it here")
        self.assertGreaterEqual(checked, 28)

    def test_the_guard_can_fail(self):
        import inspect
        import re

        def planted(path):
            with open(path, "rb") as handle:   # what an unmigrated reader looks like
                return handle.read()

        def planted_low_level(path):
            return os.open(path, os.O_RDONLY)
        self.assertIsNotNone(re.search(self.OPEN, inspect.getsource(planted)))
        self.assertIsNotNone(re.search(self.OPEN, inspect.getsource(planted_low_level)))
        self.assertIsNone(re.search(self.OPEN, "x = _ws().open_chain(path)  # fdopen( and reopen( are not opens"))


if __name__ == "__main__":
    unittest.main()
