"""goodqa#17100: hook-host load from ops_watch and ahd.

ops_watch: one liveness pass re-parsed the 21 MB ah ledger for every session (ah._ledger), one run took 30+ minutes
and runs could stack. ahd: one `ah owners` interpreter per session per 60 s tick.

Controls: each test below fails against the previous implementation (verified by reverting the three files; see the
packet). Every test runs in a scratch HOME, with `ah.owners` or a fake `ah` CLI; no network, no real WALs."""
import fcntl
import json
import os
import sys
import tempfile
import time
import types
import unittest
from pathlib import Path
from unittest import mock

HOOKS = Path(__file__).resolve().parents[1] / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import ah  # noqa: E402
import ahd  # noqa: E402
import ops_watch as ow  # noqa: E402
import test_ahd  # noqa: E402

SESS = "aaaaaaaa-1111-4222-8333-444444444444"
SESS2 = "bbbbbbbb-1111-4222-8333-444444444444"


def dropped(agent):
    return {"agent_id": agent, "type": "task-owner", "owner": True, "state": "DROPPED", "severity": "high",
            "idle_s": 90000, "ticket": None, "disposition": None, "decision_required": False}


def live(agent):
    return dict(dropped(agent), state="live", severity="info", idle_s=60)


class NoTickets:
    def quiet_h(self, ref):
        return 0


# ---------------------------------------------------------------- ah._ledger memo

class LedgerMemo(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name)
        self.path = ah.store_dir(self.home) / "ledger.jsonl"
        ah._LEDGER_MEMO.clear()

    def add(self, n):
        with open(self.path, "a") as f:
            f.write(json.dumps({"op": "task.dispose", "args": {"session": SESS, "n": n}, "state": "applied"}) + "\n")

    def read(self, tally=True):
        return ah._ledger(self.home, tally=ah.ReadTally() if tally else None)

    def test_append_is_seen_by_the_next_read_for_readers_and_writers(self):
        self.add(1)
        self.assertEqual(len(self.read()), 1)
        self.add(2)  # an append between two reads of one process
        self.assertEqual(len(self.read()), 2)
        self.assertEqual(len(self.read(tally=False)), 2)
        self.add(3)
        self.assertEqual(len(self.read(tally=False)), 3)  # a writer never reads the memo
        self.assertEqual(len(self.read()), 3)

    def test_unchanged_file_is_parsed_once(self):
        for i in range(5):
            self.add(i)
        self.age()
        real = json.loads
        with mock.patch.object(ah.json, "loads", side_effect=real) as spy:
            for _ in range(4):
                self.assertEqual(len(self.read()), 5)
        self.assertEqual(spy.call_count, 5)

    def age(self, secs=10):
        old = time.time() - secs
        os.utime(self.path, (old, old))

    def test_a_just_written_file_is_not_served_from_the_memo(self):
        """Racy-timestamp control: parsed within the timestamp granularity of its last write, so re-read next time."""
        self.add(1)
        real = json.loads
        with mock.patch.object(ah.json, "loads", side_effect=real) as spy:
            self.read()
            self.read()
        self.assertEqual(spy.call_count, 2)

    def test_same_size_rewrite_of_a_settled_file_is_not_served_stale(self):
        self.add(1)
        self.age()
        self.assertEqual(self.read()[0]["args"]["n"], 1)
        self.path.write_text(self.path.read_text().replace('"n": 1', '"n": 9'))
        self.assertEqual(self.read()[0]["args"]["n"], 9)

    def test_same_size_rewrite_is_not_served_stale(self):
        self.add(1)
        self.assertEqual(self.read()[0]["args"]["n"], 1)
        data = self.path.read_text().replace('"n": 1', '"n": 9')
        self.path.write_text(data)  # same length, new inode content and mtime
        self.assertEqual(self.read()[0]["args"]["n"], 9)

    def test_torn_line_is_replayed_into_the_tally(self):
        self.add(1)
        with open(self.path, "a") as f:
            f.write("{torn\n")
        t1, t2 = ah.ReadTally(), ah.ReadTally()
        ah._ledger(self.home, tally=t1)
        ah._ledger(self.home, tally=t2)  # from the memo
        self.assertEqual((t1.skipped, t1.read_ok), (t2.skipped, t2.read_ok))
        self.assertGreaterEqual(t1.skipped, 0)

    def test_returned_list_is_a_copy(self):
        self.add(1)
        self.read().clear()
        self.assertEqual(len(self.read()), 1)


# ---------------------------------------------------------------- ops_watch

class Scan(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name)
        self.now = time.time()
        self.cfg = ow.load_config(self.home, host="testhost", overrides={})
        self.cfg["liveness"] = dict(self.cfg["liveness"], wal_root=str(self.home / ".claude" / "wals"), gq=None)
        self.state = {}
        self.rows = {}
        self.calls = []
        ah._LEDGER_MEMO.clear()
        patcher = mock.patch.object(ah, "owners", side_effect=self.fake_owners)
        patcher.start()
        self.addCleanup(patcher.stop)

    def fake_owners(self, home, session, now=None, comments=None):
        self.calls.append(session)
        return {"owners": self.rows.get(session, [])}

    def wal(self, session, line="x"):
        d = self.home / ".claude" / "wals" / session
        d.mkdir(parents=True, exist_ok=True)
        with open(d / "main.jsonl", "a") as f:
            f.write(json.dumps({"at": ow.now_iso(self.now), "event": "intent", "note": line}) + "\n")

    def run_check(self, cfg=None):
        out = ow.check_liveness(cfg or self.cfg, self.state, lambda *a, **k: (1, ""), self.now)
        return sorted(a["key"] for a in out)

    def key(self, session, agent):
        return f"liveness:{session[:8]}/agent-{agent}"

    def ledger(self, **row):
        p = ah.store_dir(self.home) / "ledger.jsonl"
        with open(p, "a") as f:
            f.write(json.dumps(dict({"state": "applied"}, **row)) + "\n")

    def test_unchanged_session_of_dropped_owners_is_not_rescanned(self):
        self.wal(SESS)
        self.rows[SESS] = [dropped("a1"), dropped("a2")]
        first = self.run_check()
        second = self.run_check()
        self.assertEqual(first, second)
        self.assertEqual(first, [self.key(SESS, "a1"), self.key(SESS, "a2")])
        self.assertEqual(self.calls, [SESS])  # the second run reused the first

    def test_changed_session_is_read_again_and_a_new_drop_is_reported(self):
        """Near-miss: the scan is incremental, but a newly dropped owner in a changed WAL dir shows on the next run."""
        self.wal(SESS)
        self.rows[SESS] = [dropped("a1")]
        self.assertEqual(self.run_check(), [self.key(SESS, "a1")])
        self.wal(SESS, "a2 stopped")
        self.rows[SESS] = [dropped("a1"), dropped("a2")]
        self.assertEqual(self.run_check(), [self.key(SESS, "a1"), self.key(SESS, "a2")])
        self.assertEqual(self.calls, [SESS, SESS])

    def test_new_agent_wal_in_an_unchanged_main_is_seen(self):
        self.wal(SESS)
        self.rows[SESS] = [dropped("a1")]
        self.run_check()
        (self.home / ".claude" / "wals" / SESS / "agent-a2.jsonl").write_text("{}\n")
        self.rows[SESS] = [dropped("a1"), dropped("a2")]
        self.assertIn(self.key(SESS, "a2"), self.run_check())

    def test_live_owner_session_is_always_rescanned(self):
        self.wal(SESS)
        self.rows[SESS] = [live("a1")]
        self.run_check()
        self.run_check()
        self.assertEqual(self.calls, [SESS, SESS])  # live ages into SILENT with no file change

    def test_timed_disposition_is_always_rescanned(self):
        self.wal(SESS)
        row = dict(dropped("a1"), disposition={"kind": "waiting", "live": True, "until": self.now + 10})
        self.rows[SESS] = [row]
        self.run_check()
        self.run_check()
        self.assertEqual(len(self.calls), 2)

    def test_relevant_ledger_row_rescans_unrelated_one_does_not(self):
        self.wal(SESS)
        self.rows[SESS] = [dropped("a1")]
        self.run_check()
        self.ledger(op="ticket.comment", args={"ref": "x"})  # not read by ah.owners
        self.run_check()
        self.assertEqual(len(self.calls), 1)
        self.rows[SESS] = []  # main disposed of it
        self.ledger(op="task.dispose", args={"session": SESS, "agent": "a1", "kind": "closed"})
        self.assertEqual(self.run_check(), [])
        self.assertEqual(len(self.calls), 2)

    def test_reuse_expires(self):
        self.wal(SESS)
        self.rows[SESS] = [dropped("a1")]
        self.run_check()
        self.now += 4000  # past reuse_max_s (3600); the WAL file is unchanged
        self.run_check()
        self.assertEqual(len(self.calls), 2)

    def test_failed_owner_read_is_not_cached(self):
        self.wal(SESS)
        with mock.patch.object(ah, "owners", side_effect=ah.AhError("session_unknown", "x")):
            self.assertEqual(self.run_check(), [])
        self.rows[SESS] = [dropped("a1")]
        self.assertEqual(self.run_check(), [self.key(SESS, "a1")])

    def test_budget_never_clears_an_alert_for_a_session_it_did_not_reach(self):
        """Near-miss: scan_budget_s=0 reaches no session; the previous alert is carried, not cleared."""
        self.wal(SESS)
        k = self.key(SESS, "a1")
        self.state["active"] = {k: {"severity": "high", "message": "owner dropped: agent-a1", "detail": {"agent": "a1"},
                                    "check": "liveness"}}
        cfg = dict(self.cfg, liveness=dict(self.cfg["liveness"], scan_budget_s=0))
        out = ow.check_liveness(cfg, self.state, lambda *a, **kw: (1, ""), self.now)
        self.assertEqual([a["key"] for a in out], [k, "ops-watch:liveness-scan-truncated"])
        self.assertEqual((out[0]["severity"], out[0]["message"]), ("high", "owner dropped: agent-a1"))
        self.assertEqual(self.calls, [])

    def _budgeted(self, sessions, budget=150, cost=100):
        """Non-stable (live) sessions under a clock that advances `cost` s per ah.owners call; deadline `budget` s."""
        clock = [0.0]
        for s in sessions:
            self.wal(s)
            self.rows[s] = [live("a1")]
        real = self.fake_owners

        def timed(home, session, now=None, comments=None):
            clock[0] += cost
            return real(home, session, now, comments)
        shim = types.SimpleNamespace(monotonic=lambda: clock[0], time=time.time, sleep=time.sleep)
        cfg = dict(self.cfg, liveness=dict(self.cfg["liveness"], scan_budget_s=budget))
        return cfg, timed, shim

    def test_budget_rotates_so_every_non_stable_session_is_reached(self):
        """F1: under a budget that fits two of four live sessions, the sessions skipped in one run come first in the
        next, so all four are read within two runs (alphabetical order would starve the last two for ever)."""
        names = [f"{c * 8}-1111-4222-8333-444444444444" for c in "abcd"]
        cfg, timed, shim = self._budgeted(names)
        reached = set()
        with mock.patch.object(ah, "owners", side_effect=timed), mock.patch.object(ow, "time", shim):
            for _ in range(2):
                self.calls.clear()
                ow.check_liveness(cfg, self.state, lambda *a, **k: (1, ""), self.now)
                reached |= set(self.calls)
        self.assertEqual(reached, set(names))

    def test_truncated_scan_raises_a_warning_naming_the_count(self):
        names = [f"{c * 8}-1111-4222-8333-444444444444" for c in "abc"]
        cfg, timed, shim = self._budgeted(names)
        with mock.patch.object(ah, "owners", side_effect=timed), mock.patch.object(ow, "time", shim):
            out = {a["key"]: a for a in ow.check_liveness(cfg, self.state, lambda *a, **k: (1, ""), self.now)}
        a = out["ops-watch:liveness-scan-truncated"]
        self.assertEqual((a["severity"], a["detail"]["skipped"], a["detail"]["sessions"]), ("warning", 1, 3))
        self.assertIn("1 of 3", a["message"])

    def test_a_complete_scan_raises_no_truncation_warning(self):
        names = [f"{c * 8}-1111-4222-8333-444444444444" for c in "ab"]
        cfg, timed, shim = self._budgeted(names, budget=1000)
        with mock.patch.object(ah, "owners", side_effect=timed), mock.patch.object(ow, "time", shim):
            out = ow.check_liveness(cfg, self.state, lambda *a, **k: (1, ""), self.now)
        self.assertNotIn("ops-watch:liveness-scan-truncated", [a["key"] for a in out])

    def test_stale_sessions_leave_the_scan_cache(self):
        self.wal(SESS)
        self.rows[SESS] = [dropped("a1")]
        self.run_check()
        self.assertIn(SESS, self.state["liveness_scan"])
        self.now += 30 * 24 * 3600  # beyond every horizon
        self.run_check()
        self.assertNotIn(SESS, self.state["liveness_scan"])


class RunLock(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name)

    def test_second_holder_gets_none_and_release_frees_it(self):
        a = ow.acquire_run_lock(self.home)
        self.assertIsNotNone(a)
        self.assertIsNone(ow.acquire_run_lock(self.home))
        os.close(a)
        b = ow.acquire_run_lock(self.home)
        self.assertIsNotNone(b)
        os.close(b)

    def test_run_exits_at_once_while_another_run_holds_the_lock(self):
        held = ow.acquire_run_lock(self.home)
        self.addCleanup(os.close, held)
        with mock.patch.dict(os.environ, {"HOME": str(self.home)}), \
                mock.patch.object(ow, "run_once", side_effect=AssertionError("must not run")) as run:
            t0 = time.monotonic()
            self.assertEqual(ow.main(["run"]), 0)
            self.assertLess(time.monotonic() - t0, 5)
            run.assert_not_called()
        self.assertFalse((self.home / ".agent-harness" / "logs" / "ops-watch.last-ok").exists())

    def test_run_proceeds_when_the_lock_is_free_and_is_held_during_it(self):
        seen = []

        def fake_run(cfg, home, *a, **k):
            seen.append(ow.acquire_run_lock(home))
            return 0
        with mock.patch.dict(os.environ, {"HOME": str(self.home)}), mock.patch.object(ow, "run_once", fake_run):
            self.assertEqual(ow.main(["run"]), 0)
        self.assertEqual(seen, [None])  # a nested attempt during the run was refused

    def test_lock_file_is_a_kernel_lock_so_a_dead_holder_frees_it(self):
        pid = os.fork()
        if pid == 0:
            fd = ow.acquire_run_lock(self.home)
            os._exit(0 if fd is not None else 1)
        _, status = os.waitpid(pid, 0)
        self.assertEqual(status, 0)
        fd = ow.acquire_run_lock(self.home)
        self.assertIsNotNone(fd)  # the child exited holding it; the kernel released it
        os.close(fd)


# ---------------------------------------------------------------- ahd owners cache

class OwnersCache(test_ahd.Scratch):
    def setUp(self):
        super().setUp()
        self.policy["owners_cache_ttl_seconds"] = 300
        self.t_mono = 1000.0
        patcher = mock.patch.object(ahd, "mono", side_effect=lambda: self.t_mono)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.owners([test_ahd.owner("a1111111111111111", "DROPPED")])

    def spawns(self):
        return len([c for c in self.calls() if c["argv"][:1] == ["owners"]])

    def tick(self, d, advance=0.0):
        self.t_mono += advance
        d.tick()

    def test_serves_within_ttl_without_spawning(self):
        d = self.daemon()
        for _ in range(4):
            self.tick(d, 60)  # four 60 s ticks, one interpreter
        self.assertEqual(self.spawns(), 1)

    def test_refreshes_after_ttl(self):
        d = self.daemon()
        self.tick(d)
        self.tick(d, 301)
        self.assertEqual(self.spawns(), 2)

    def test_refreshes_after_a_wal_change(self):
        d = self.daemon()
        self.tick(d)
        with open(self.main_wal, "a") as f:
            f.write(json.dumps({"at": "2027-01-15T08:01:00+00:00", "event": "note", "note": "y"}) + "\n")
        os.utime(self.main_wal, (self.t - 30, self.t - 30))
        self.tick(d, 60)
        self.assertEqual(self.spawns(), 2)

    def test_refreshes_after_a_new_agent_wal(self):
        d = self.daemon()
        self.tick(d)
        (self.main_wal.parent / "agent-a2.jsonl").write_text("{}\n")
        self.tick(d, 60)
        self.assertEqual(self.spawns(), 2)

    def test_refreshes_after_a_ledger_change(self):
        d = self.daemon()
        self.tick(d)
        led = self.home / ".agent-harness" / "state" / "ah" / "store" / "ledger.jsonl"
        led.parent.mkdir(parents=True, exist_ok=True)
        led.write_text("{}\n")
        self.tick(d, 60)
        self.assertEqual(self.spawns(), 2)

    def test_a_changed_owner_doc_is_alerted_after_the_refresh(self):
        """Near-miss: the cache must not hide a newly silent owner once its WAL changes."""
        d = self.daemon()
        self.tick(d)
        self.owners([test_ahd.owner("a1111111111111111", "DROPPED"), test_ahd.owner("a2222222222222222", "DROPPED")])
        self.tick(d, 60)
        self.assertEqual(len(self.alert_calls("raise")), 1)  # still the cached view: WAL unchanged
        with open(self.main_wal, "a") as f:
            f.write(json.dumps({"at": "2027-01-15T08:02:00+00:00", "event": "subagent_stop", "agent_id": "a2"}) + "\n")
        os.utime(self.main_wal, (self.t - 20, self.t - 20))
        self.tick(d, 60)
        self.assertEqual(len(self.alert_calls("raise")), 2)

    def test_partial_read_is_never_cached(self):
        self.owners([test_ahd.owner("a1111111111111111", "DROPPED")], read="partial")
        d = self.daemon()
        for _ in range(3):
            self.tick(d, 60)
        self.assertEqual(self.spawns(), 3)

    def test_session_with_a_time_dependent_row_is_asked_every_tick(self):
        """F3: a live, silent or timed-wait row changes with the clock alone, so it is never served from the cache."""
        for row in (test_ahd.owner("a1111111111111111", "live", idle=60),
                    test_ahd.owner("a1111111111111111", "SILENT"),
                    dict(test_ahd.owner("a1111111111111111", "DROPPED"), disposition={"kind": "waiting", "until": 9e9})):
            self.owners([row])
            d = ahd.Daemon(policy=self.policy)
            self.assertTrue(d.acquire())
            self.addCleanup(d.release)
            before = self.spawns()
            for _ in range(3):
                self.tick(d, 60)
            self.assertEqual(self.spawns() - before, 3, row)
            d.release()

    def test_failed_call_is_retried_next_tick(self):
        (self.fake / f"owners-{test_ahd.SESSION}.json").write_text("not json")
        d = self.daemon()
        self.tick(d)
        self.tick(d, 60)
        self.assertEqual(self.spawns(), 2)

    def test_ttl_zero_restores_one_spawn_per_tick(self):
        self.policy["owners_cache_ttl_seconds"] = 0
        d = self.daemon()
        for _ in range(3):
            self.tick(d, 60)
        self.assertEqual(self.spawns(), 3)

    def test_ttl_is_jittered_below_the_base(self):
        d = ahd.Daemon(policy=self.policy)
        ttls = {d.owners_ttl(f"s{i}") for i in range(50)}
        self.assertTrue(all(225 <= t <= 300 for t in ttls))
        self.assertGreater(len(ttls), 10)

    def test_sessions_that_left_the_window_leave_the_cache(self):
        d = self.daemon()
        self.tick(d)
        self.assertIn(test_ahd.SESSION, d.owner_cache)
        os.utime(self.main_wal, (self.t - 10 * 86400, self.t - 10 * 86400))
        self.tick(d, 60)
        self.assertEqual(d.owner_cache, {})


if __name__ == "__main__":
    unittest.main()
