"""ops_watch reads WAL chains through wal_segments (goodqa#16751, docs/spec/wal-segments.md R3-3, AC-8, AC-9).

Every test builds a rotated fixture (at least 2 closed segments plus a live file) and most add a gap case. Sparse files
make the size cases cheap. Synthetic data only."""
import hashlib
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
import ops_watch as ow  # noqa: E402
import wal_segments as ws  # noqa: E402

MIB = 1024 * 1024
NOW = 1_800_000_000.0


def rec(at, event, note=""):
    return json.dumps({"at": ow.now_iso(at), "event": event, "note": note}) + "\n"


class Fx(unittest.TestCase):
    """HOME is a temp dir; sessions live under ~/.claude/wals/<session>."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name).resolve()
        self.wals = self.home / ".claude" / "wals"
        self.sess = self.wals / "sess-aaaa1111"
        self.sess.mkdir(parents=True)
        self.cfg = ow.load_config(self.home, host="testhost", overrides={})
        self.cfg["_home"] = str(self.home)
        self.cfg["liveness"] = dict(self.cfg["liveness"], wal_root=str(self.wals), gq=None)
        self.cfg["wal_size"] = dict(self.cfg["wal_size"], roots=[str(self.wals)])
        self.cfg["deploys"] = dict(self.cfg["deploys"], wal_root=str(self.wals), services=[])
        p = mock.patch.dict(os.environ, {"HOME": str(self.home)})
        p.start()
        self.addCleanup(p.stop)

    def switch(self, on):
        state = self.home / ".agent-harness" / "state"
        state.mkdir(parents=True, exist_ok=True)
        flag = state / "wal-rotation.on"
        if on:
            flag.write_text("")
        elif flag.exists():
            flag.unlink()

    def marker(self, stem, seq):
        prev = ws.segment_name(stem, seq - 1) if seq > 2 else ws.segment_name(stem, 1)
        return ws._marker(stem, seq, prev, 0, 0, "0" * 64).decode()

    def chain(self, stem, closed, live=None, gap=False, session=None, mtime=None):
        """closed: list of text bodies for segments 1..n (marker added from segment 2); live: body of the live file.
        gap=True drops segment 2 of a 3-closed chain (the files that remain keep their numbers)."""
        d = Path(session) if session else self.sess
        d.mkdir(parents=True, exist_ok=True)
        mtime = mtime or NOW - 60  # the fixture clock: real mtimes would sit outside every lookback window
        for i, body in enumerate(closed, 1):
            if gap and i == 2:
                continue
            text = (self.marker(stem, i) if i >= 2 else "") + body
            p = d / ws.segment_name(stem, i)
            p.write_text(text)
            if mtime:
                os.utime(p, (mtime, mtime))
        if live is not None:
            p = d / f"{stem}.jsonl"
            p.write_text(self.marker(stem, len(closed) + 1) + live)
            if mtime:
                os.utime(p, (mtime, mtime))
        return d

    def sparse(self, path, size):
        with open(path, "ab") as handle:
            handle.truncate(size)


def by_key(alerts):
    return {a["key"]: a for a in alerts}


class WalSizeTests(Fx):
    def test_closed_segments_are_not_wals_of_their_own(self):
        # AC-9: two 45 MiB closed segments must never raise a per-file size alert
        self.switch(True)
        d = self.chain("main", ["x\n", "y\n", "z\n"], live=rec(NOW, "status"))
        for n in (1, 2, 3):
            self.sparse(d / ws.segment_name("main", n), 45 * MIB)
        self.assertEqual([a for a in ow.check_wal_size(self.cfg, {}, None, NOW) if a["key"].startswith("wal:size:")], [])

    def test_live_file_over_limit_plus_slack_when_rotation_is_on(self):
        self.switch(True)
        d = self.chain("main", ["a\n", "b\n"], live=rec(NOW, "status"))
        self.sparse(d / "main.jsonl", 56 * MIB)  # over 50 MiB + 10%: rotation is not working
        got = [a for a in ow.check_wal_size(self.cfg, {}, None, NOW) if a["key"].startswith("wal:size:")]
        self.assertEqual(len(got), 1)
        self.assertEqual(got[0]["severity"], "high")
        self.assertEqual(got[0]["detail"]["live_bytes"], 56 * MIB)
        self.assertEqual(got[0]["detail"]["chain_bytes"], sum(s.size for s in ws.chain(d, "main").segments) + 56 * MIB)
        self.assertIn("rotation", got[0]["message"])

    def test_live_file_between_alarm_and_limit_is_quiet_when_rotation_is_on(self):
        self.switch(True)
        d = self.chain("main", ["a\n", "b\n"], live=rec(NOW, "status"))
        self.sparse(d / "main.jsonl", 45 * MIB)  # a healthy live file just before it rotates
        self.assertEqual([a for a in ow.check_wal_size(self.cfg, {}, None, NOW) if a["key"].startswith("wal:size:")], [])

    def test_unrotated_live_file_over_alarm_when_rotation_is_off(self):
        self.switch(False)
        (self.sess / "main.jsonl").write_text(rec(NOW, "status"))
        self.sparse(self.sess / "main.jsonl", 41 * MIB)
        got = [a for a in ow.check_wal_size(self.cfg, {}, None, NOW) if a["key"].startswith("wal:size:")]
        self.assertEqual(len(got), 1)
        self.assertEqual(got[0]["detail"]["live_bytes"], 41 * MIB)

    def test_chain_total_alert(self):
        self.switch(True)
        self.cfg["wal_size"]["chain_max_mib"] = 100
        d = self.chain("main", ["a\n", "b\n"], live=rec(NOW, "status"))
        self.sparse(d / ws.segment_name("main", 1), 60 * MIB)
        self.sparse(d / ws.segment_name("main", 2), 60 * MIB)
        got = [a for a in ow.check_wal_size(self.cfg, {}, None, NOW) if a["key"].startswith("wal:chain-size:")]
        self.assertEqual(len(got), 1)
        self.assertEqual(got[0]["severity"], "warning")
        self.assertGreaterEqual(got[0]["detail"]["chain_bytes"], 120 * MIB)
        # failing control: under the total there is no alert
        self.cfg["wal_size"]["chain_max_mib"] = 500
        self.assertEqual([a for a in ow.check_wal_size(self.cfg, {}, None, NOW) if a["key"].startswith("wal:chain-size:")], [])


class ChainProblemTests(Fx):
    def alerts(self):
        return [a for a in ow.check_wal_size(self.cfg, {}, None, NOW) if a["key"].startswith("wal:chain:")]

    def test_gap_is_an_alert(self):
        self.switch(True)
        self.chain("main", ["a\n", "b\n", "c\n"], live=rec(NOW, "status"), gap=True)
        got = self.alerts()
        self.assertEqual(len(got), 1)
        self.assertEqual(got[0]["severity"], "high")
        self.assertIn("gap", got[0]["detail"]["codes"])
        self.assertIn("segment 2 is missing", got[0]["message"])
        self.assertIn("never edit", got[0]["message"])

    def test_healthy_rotated_chain_is_quiet(self):
        self.switch(True)
        self.chain("main", ["a\n", "b\n"], live=rec(NOW, "status"))
        self.assertEqual(self.alerts(), [])

    def test_marker_mismatch_is_an_alert(self):
        self.switch(True)
        d = self.chain("main", ["a\n", "b\n"], live=rec(NOW, "status"))
        bad = json.loads(self.marker("main", 3))
        bad["prev"] = "main.0007.jsonl"
        (d / "main.jsonl").write_text(json.dumps(bad) + "\n" + rec(NOW, "status"))
        got = self.alerts()
        self.assertEqual(len(got), 1)
        self.assertIn("marker_mismatch", got[0]["detail"]["codes"])

    def test_marker_missing_is_an_alert(self):
        self.switch(True)
        d = self.chain("main", ["a\n", "b\n"], live=rec(NOW, "status"))
        (d / "main.jsonl").write_text(rec(NOW, "status"))  # an old writer's live file with closed predecessors
        got = self.alerts()
        self.assertEqual(len(got), 1)
        self.assertIn("marker_missing", got[0]["detail"]["codes"])

    def test_live_missing_alerts_only_after_ten_minutes_and_names_the_fix(self):
        self.switch(True)
        d = self.chain("main", ["a\n", "b\n"], live=None, mtime=NOW - 5 * 60)
        self.assertEqual(self.alerts(), [])  # a rotation in flight
        for p in d.glob("main.*.jsonl"):
            os.utime(p, (NOW - 11 * 60, NOW - 11 * 60))
        got = self.alerts()
        self.assertEqual(len(got), 1)
        self.assertIn("live_missing", got[0]["detail"]["codes"])
        self.assertIn(f"wal_segments.py recover --write {d} main", got[0]["message"])

    def test_info_codes_do_not_alert_and_ops_watch_never_writes(self):
        self.switch(True)
        d = self.chain("main", ["a\n", "b\n", "c\n"], live=rec(NOW, "status"), gap=True)
        before = {p.name: (p.stat().st_mtime_ns, p.stat().st_size) for p in d.iterdir()}
        ow.check_wal_size(self.cfg, {}, None, NOW)
        ow.check_liveness(self.cfg, {}, mock.Mock(), NOW)
        ow.check_deploys(self.cfg, {}, mock.Mock(), NOW)
        after = {p.name: (p.stat().st_mtime_ns, p.stat().st_size) for p in d.iterdir()}
        self.assertEqual(before, after)  # R3-3: the repair is the writer's or `recover --write`, never the watcher


class LivenessChainTests(Fx):
    def test_segments_are_not_task_wals(self):
        # AC-9: owner.0001.jsonl is part of the owner WAL, not a task named "owner.0001"
        old = NOW - 3 * 3600
        self.chain("owner", [rec(old - 60, "scope", "Ticket: GoodQA goodqa#14500"), rec(old, "status", "x")],
                   live=rec(NOW - 120, "check", "tests run"), mtime=None)
        os.utime(self.sess / "owner.0001.jsonl", (old, old))
        os.utime(self.sess / "owner.0002.jsonl", (old, old))
        os.utime(self.sess / "owner.jsonl", (NOW - 120, NOW - 120))
        self.assertEqual(ow.check_liveness(self.cfg, {}, mock.Mock(), NOW), [])

    def test_terminal_event_in_a_closed_segment_retires_the_task(self):
        old = NOW - 3 * 3600
        self.chain("solve", [rec(old - 600, "status", "working"), rec(old, "handoff", "PR_READY")],
                   live=rec(old + 30, "status", "late note"))
        for p in self.sess.glob("solve*.jsonl"):
            os.utime(p, (old, old))
        self.assertEqual(ow.check_liveness(self.cfg, {}, mock.Mock(), NOW), [])

    def test_silent_rotated_task_alerts_once_with_its_stem(self):
        old = NOW - 3 * 3600
        self.chain("stuck", [rec(old - 600, "scope", "Ticket: GoodQA goodqa#14501"), rec(old - 300, "status", "a")],
                   live=rec(old, "blocker", "tests fail"))
        for p in self.sess.glob("stuck*.jsonl"):
            os.utime(p, (old, old))
        a = by_key(ow.check_liveness(self.cfg, {}, mock.Mock(), NOW))
        self.assertEqual(sorted(a), ["liveness:sess-aaa/stuck"])
        self.assertEqual(a["liveness:sess-aaa/stuck"]["detail"]["ticket"], "goodqa#14501")  # ticket named in segment 1

    def test_gap_is_named_in_the_alert(self):
        self.switch(True)
        old = NOW - 3 * 3600
        self.chain("stuck", [rec(old - 900, "status", "a"), rec(old - 800, "status", "b"), rec(old - 700, "status", "c")],
                   live=rec(old, "blocker", "tests fail"), gap=True)
        for p in self.sess.glob("stuck*.jsonl"):
            os.utime(p, (old, old))
        a = by_key(ow.check_liveness(self.cfg, {}, mock.Mock(), NOW))
        self.assertEqual(sorted(a), ["liveness:sess-aaa/stuck"])
        self.assertIn("gap", a["liveness:sess-aaa/stuck"]["detail"]["wal_problems"])
        self.assertIn("WAL chain incomplete", a["liveness:sess-aaa/stuck"]["message"])

    def test_main_with_only_segments_still_counts_as_main(self):
        # a crashed rotation (live missing) is still the session: the owner view must run
        self.chain("main", [rec(NOW - 600, "prompt"), rec(NOW - 500, "prompt")], live=None, mtime=NOW - 60)
        with mock.patch.object(ow, "_owner_alerts", return_value=[]) as owner_view:
            ow.check_liveness(self.cfg, {}, mock.Mock(), NOW)
        owner_view.assert_called_once()


class IdleGuardChainTests(Fx):
    def run_check(self, assess_result):
        import idle_guard
        self.cfg["idle_guard"] = dict(self.cfg["idle_guard"], wal_root=str(self.wals))
        with mock.patch.object(idle_guard, "assess", return_value=assess_result) as assess:
            return ow.check_idle_guard(self.cfg, {}, mock.Mock(), NOW), assess

    IDLE = {"idle": True, "idle_s": 3600, "streams": [{"agent": "a1", "next": "review"}]}

    def test_crashed_rotation_main_is_still_assessed(self):
        self.chain("main", [rec(NOW - 900, "prompt"), rec(NOW - 800, "prompt")], live=None, mtime=NOW - 60)
        out, assess = self.run_check(self.IDLE)
        assess.assert_called_once()
        self.assertEqual([a["key"] for a in out], ["idle-guard:sess-aaa"])

    def test_old_chain_is_history(self):
        old = NOW - 20 * 3600
        self.chain("main", [rec(old, "prompt"), rec(old, "prompt")], live=rec(old, "prompt"), mtime=old)
        out, assess = self.run_check(self.IDLE)
        assess.assert_not_called()
        self.assertEqual(out, [])

    def test_gap_is_named_in_the_alert(self):
        self.chain("main", [rec(NOW - 900, "prompt"), rec(NOW - 800, "prompt"), rec(NOW - 700, "prompt")],
                   live=rec(NOW - 60, "prompt"), gap=True, mtime=NOW - 60)
        out, _ = self.run_check(self.IDLE)
        self.assertEqual(len(out), 1)
        self.assertIn("gap", out[0]["detail"]["wal_problems"])


class DeploysChainTests(Fx):
    def pending(self, session):
        return [a for a in ow.check_deploys(self.cfg, {}, mock.Mock(), NOW) if a["key"].endswith(session[:8])]

    def test_pending_in_a_closed_segment_older_than_lookback_stays_open(self):
        # the live file is fresh, so the chain is fresh: an open PENDING_REAL_TEST from 80 h ago must not be dropped
        old = NOW - 80 * 3600
        self.chain("main", [rec(old, "check", "PENDING_REAL_TEST T1: live click"), rec(old + 60, "status", "x")],
                   live=rec(NOW - 60, "status", "later"))
        os.utime(self.sess / "main.0001.jsonl", (old, old))
        os.utime(self.sess / "main.0002.jsonl", (old, old))
        got = by_key(self.pending(self.sess.name))
        self.assertEqual(sorted(got), ["pending-open:sess-aaa"])
        self.assertIn("T1", got["pending-open:sess-aaa"]["message"])

    def test_tested_in_the_live_file_closes_a_pending_in_a_segment(self):
        old = NOW - 8 * 3600
        self.chain("main", [rec(old, "check", "PENDING_REAL_TEST T1: live click"), rec(old + 60, "status", "x")],
                   live=rec(NOW - 60, "check", "REALLY_TESTED T1: ran it, ok"))
        self.assertEqual(self.pending(self.sess.name), [])

    def test_gap_reports_the_chain_as_not_scanned(self):
        old = NOW - 8 * 3600
        self.chain("main", [rec(old, "check", "PENDING_REAL_TEST T1: x"), rec(old, "status", "y"), rec(old, "status", "z")],
                   live=rec(NOW - 60, "status", "later"), gap=True)
        got = by_key(self.pending(self.sess.name))
        self.assertIn("pending-unscanned:sess-aaa", got)
        self.assertIn("gap", got["pending-unscanned:sess-aaa"]["detail"]["problems"])

    def test_over_cap_chain_is_not_cut(self):
        # a chain over the cap is reported as not scanned, never read from its oldest bytes only
        self.cfg["deploys"]["max_chain_mib"] = 1
        self.chain("main", [rec(NOW - 9 * 3600, "check", "PENDING_REAL_TEST T1: x"), "y\n"], live=rec(NOW - 60, "status", "n"))
        self.sparse(self.sess / "main.0002.jsonl", 3 * MIB)
        got = by_key(self.pending(self.sess.name))
        self.assertIn("pending-unscanned:sess-aaa", got)
        self.assertNotIn("pending-open:sess-aaa", got)

    def test_segment_shaped_file_without_a_chain_is_ignored_as_a_wal(self):
        # AC-9: an index or a stray file never becomes a log
        (self.sess / "main.segments.json").write_text("{}")
        self.assertEqual(self.pending(self.sess.name), [])


if __name__ == "__main__":
    unittest.main()
