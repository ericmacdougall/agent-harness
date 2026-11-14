"""S1 (GoodQA goodqa#15946): lane store layout, atomic writes, lock, index, journal chain, op records.

Covers AC-4 (store part), NEG-4, NEG-14, NEG-21, NEG-84 of software-factory/s1/spec.md.
Bounded probes: at most 2 short-lived processes (lock contention), one temp directory, 60 s timeout.
Fails on main c82ad2af: module `lane.store` does not exist.
"""
import json
import multiprocessing
import os
import stat
import sys
import tempfile
import time
import unittest
from pathlib import Path

HOOKS = Path(__file__).resolve().parents[1] / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
from lane import store as st  # noqa: E402

NOW = "2026-11-13T00:00:00Z"


def hold_lock(root, ready, release):
    s = st.Store(root)
    with s.lock():
        ready.set()
        release.wait(30)


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(os.path.realpath(self.tmp.name)) / "lanes"
        self.store = st.Store(self.root)

    def tearDown(self):
        self.tmp.cleanup()

    def lane(self, name="lane_A"):
        self.store.ensure_root()
        d = self.store.lane_dir(name)
        d.mkdir(parents=True, exist_ok=True)
        return d


class LayoutTests(Base):
    def test_root_and_files_have_private_permissions(self):
        self.store.ensure_root()
        self.assertEqual(stat.S_IMODE(os.stat(self.root).st_mode), 0o700)
        f = self.root / "x.json"
        st.atomic_write(f, b"{}")
        self.assertEqual(stat.S_IMODE(os.stat(f).st_mode), 0o600)

    def test_atomic_write_leaves_no_temp_files_and_replaces(self):
        self.store.ensure_root()
        f = self.root / "a.json"
        st.atomic_write(f, b"one")
        st.atomic_write(f, b"two")
        self.assertEqual(f.read_bytes(), b"two")
        self.assertEqual(sorted(p.name for p in self.root.iterdir()), ["a.json"])

    def test_root_that_is_a_symlink_is_refused(self):  # NEG-84
        real = Path(self.tmp.name) / "real"
        real.mkdir()
        link = Path(self.tmp.name) / "link"
        link.symlink_to(real)
        with self.assertRaises(st.RefusedInput):
            st.Store(link).ensure_root()
        self.assertEqual(list(real.iterdir()), [])

    def test_root_loose_permissions_are_refused(self):  # NEG-84 (other users could write)
        self.root.mkdir(mode=0o755, parents=True)
        os.chmod(self.root, 0o755)
        with self.assertRaises(st.RefusedInput):
            st.Store(self.root).ensure_root()


class ReadInputTests(Base):
    def test_regular_file_is_read(self):
        f = self.root.parent / "ok.json"
        f.write_text("{}")
        self.assertEqual(st.read_input(f), b"{}")

    def test_symlink_fifo_oversize_and_directory_are_refused(self):  # NEG-4
        base = self.root.parent
        real = base / "real.json"
        real.write_text("{}")
        link = base / "link.json"
        link.symlink_to(real)
        fifo = base / "fifo.json"
        os.mkfifo(fifo)
        big = base / "big.json"
        big.write_bytes(b"x" * (st.MAX_FILE + 1))
        for bad in (link, fifo, big, base):
            with self.subTest(bad=bad.name):
                with self.assertRaises(st.RefusedInput):
                    st.read_input(bad)

    def test_exactly_at_the_cap_is_accepted(self):  # positive control for the size check
        f = self.root.parent / "cap.json"
        f.write_bytes(b"x" * st.MAX_FILE)
        self.assertEqual(len(st.read_input(f)), st.MAX_FILE)


class LockTests(Base):
    def test_lock_timeout_gives_conflict_and_is_logged_not_a_hang(self):
        ctx = multiprocessing.get_context("fork")
        ready, release = ctx.Event(), ctx.Event()
        self.store.ensure_root()
        proc = ctx.Process(target=hold_lock, args=(str(self.root), ready, release))
        proc.start()
        try:
            self.assertTrue(ready.wait(20))
            started = time.monotonic()
            with self.assertRaises(st.LockTimeout) as caught:
                with self.store.lock(timeout=0.5):
                    self.fail("lock must not be granted")
            self.assertLess(time.monotonic() - started, 5)
            self.assertEqual(caught.exception.exit_code, 5)
            rows = [json.loads(x) for x in (self.root / "store.log.jsonl").read_text().splitlines()]
            self.assertEqual(rows[-1]["event"], "lock_timeout")
        finally:
            release.set()
            proc.join(20)
        with self.store.lock(timeout=2):  # positive control: free once the holder exits
            pass

    def test_lock_is_reentrant_in_one_process(self):
        with self.store.lock():
            with self.store.lock(timeout=0.2):
                pass


class IndexTests(Base):
    def test_claim_is_idempotent_and_one_lane_per_key(self):
        with self.store.lock():
            self.assertEqual(self.store.claim_key("T|r", "lane_1"), "lane_1")
            self.assertEqual(self.store.claim_key("T|r", "lane_2"), "lane_1")
            self.assertEqual(self.store.claim_key("U|r", "lane_2"), "lane_2")
        self.assertEqual(self.store.load_index()["lanes"], {"T|r": "lane_1", "U|r": "lane_2"})

    def test_corrupt_or_symlinked_index_is_refused_and_preserved(self):  # NEG-4
        self.store.ensure_root()
        (self.root / "index.json").write_text("{not json")
        with self.assertRaises(st.RefusedInput):
            self.store.load_index()
        self.assertEqual((self.root / "index.json").read_text(), "{not json")

    def test_missing_index_is_empty(self):
        self.assertEqual(self.store.load_index()["lanes"], {})


class JournalTests(Base):
    def append(self, d, kind="created", idem="k1", **kw):
        return self.store.journal_append(d, kind=kind, lane="lane_A", generation=0, writer={"id": "main", "session": "s"},
                                         idem=idem, source="inferred: test", data=kw.get("data", {}), ts=NOW)

    def test_rows_chain_and_head_matches(self):
        d = self.lane()
        r1 = self.append(d, idem="a")
        r2 = self.append(d, kind="queued", idem="b")
        self.assertEqual((r1["seq"], r2["seq"]), (1, 2))
        self.assertEqual(r2["prev"], r1["hash"])
        self.assertEqual((d / "head").read_text().strip(), r2["hash"])
        self.assertEqual(self.store.verify_journal(d), (True, None, None))

    def test_unknown_kind_is_refused_and_nothing_written(self):
        d = self.lane()
        with self.assertRaises(st.RefusedInput):
            self.append(d, kind="made_up")
        self.assertFalse((d / "journal.jsonl").exists())

    def test_idempotent_replay_returns_first_row(self):
        d = self.lane()
        first = self.append(d, idem="same", data={"x": 1})
        again = self.append(d, idem="same", data={"x": 1})
        self.assertEqual(first, again)
        self.assertEqual(len((d / "journal.jsonl").read_text().splitlines()), 1)

    def test_same_key_with_different_content_is_a_conflict(self):  # NEG-21 / NEG-14
        d = self.lane()
        self.append(d, idem="same", data={"x": 1})
        with self.assertRaises(st.KeyConflict) as caught:
            self.append(d, idem="same", data={"x": 2})
        self.assertEqual(caught.exception.exit_code, 5)
        self.assertEqual(len((d / "journal.jsonl").read_text().splitlines()), 1)

    def test_editing_a_middle_row_reports_the_first_broken_seq(self):  # AC-4 chain
        d = self.lane()
        for i in range(4):
            self.append(d, kind="queued", idem="k%d" % i, data={"n": i})
        self.assertEqual(self.store.verify_journal(d)[0], True)  # positive control
        lines = (d / "journal.jsonl").read_text().splitlines()
        row = json.loads(lines[1])
        row["data"] = {"n": 99}
        lines[1] = json.dumps(row, sort_keys=True)
        (d / "journal.jsonl").write_text("\n".join(lines) + "\n")
        ok, seq, _ = self.store.verify_journal(d)
        self.assertFalse(ok)
        self.assertEqual(seq, 2)

    def test_truncated_head_or_dropped_last_row_is_detected(self):
        d = self.lane()
        for i in range(3):
            self.append(d, kind="queued", idem="k%d" % i)
        lines = (d / "journal.jsonl").read_text().splitlines()
        (d / "journal.jsonl").write_text("\n".join(lines[:-1]) + "\n")
        ok, seq, reason = self.store.verify_journal(d)
        self.assertFalse(ok)
        self.assertIn("head", reason)

    def test_symlinked_journal_is_refused(self):  # NEG-4
        d = self.lane()
        real = d / "elsewhere"
        real.write_text("")
        (d / "journal.jsonl").symlink_to(real)
        with self.assertRaises(st.RefusedInput):
            self.append(d)


class OpRecordTests(Base):
    def test_retry_completes_only_missing_effects(self):
        d = self.lane()
        op = self.store.begin_op(d, op="op1", kind="checkpoint", lane="lane_A", key="k", content={"n": 1},
                                 effects=["note", "comment", "kit", "journal"], ts=NOW)
        self.store.set_effect(d, "op1", "note", "done", ref="row1", ts=NOW)
        again = self.store.begin_op(d, op="op1", kind="checkpoint", lane="lane_A", key="k", content={"n": 1},
                                    effects=["note", "comment", "kit", "journal"], ts=NOW)
        self.assertEqual([e["name"] for e in self.store.pending_effects(again)], ["comment", "kit", "journal"])
        self.assertEqual(op["content_sha256"], again["content_sha256"])

    def test_same_key_different_content_is_refused(self):  # NEG-21
        d = self.lane()
        self.store.begin_op(d, op="op1", kind="checkpoint", lane="lane_A", key="k", content={"n": 1},
                            effects=["a"], ts=NOW)
        with self.assertRaises(st.KeyConflict):
            self.store.begin_op(d, op="op1", kind="checkpoint", lane="lane_A", key="k", content={"n": 2},
                                effects=["a"], ts=NOW)

    def test_bad_effect_state_or_name_is_refused(self):
        d = self.lane()
        self.store.begin_op(d, op="op1", kind="checkpoint", lane="lane_A", key="k", content={}, effects=["a"], ts=NOW)
        with self.assertRaises(st.RefusedInput):
            self.store.set_effect(d, "op1", "a", "weird", ts=NOW)
        with self.assertRaises(st.RefusedInput):
            self.store.set_effect(d, "op1", "nope", "done", ts=NOW)

    def test_op_id_cannot_escape_the_ops_directory(self):  # scope-pinning
        d = self.lane()
        for bad in ("../x", "a/b", "", ".hidden", "x" * 200):
            with self.subTest(bad=bad):
                with self.assertRaises(st.RefusedInput):
                    self.store.begin_op(d, op=bad, kind="checkpoint", lane="l", key="k", content={}, effects=["a"], ts=NOW)


class SnapshotTests(Base):
    def test_snapshot_round_trip_and_interrupted_write_keeps_previous(self):  # NEG-23
        d = self.lane()
        self.store.write_snapshot(d, {"v": 1, "lane": "lane_A", "taken_at": NOW, "sources": {}, "gates": {},
                                      "flags": [], "totals": {}})
        before = (d / "snapshot.json").read_bytes()
        orig = os.replace

        def boom(*a, **k):
            raise OSError("interrupted")
        os.replace = boom
        try:
            with self.assertRaises(OSError):
                self.store.write_snapshot(d, {"v": 1, "lane": "lane_A", "taken_at": "later", "sources": {}, "gates": {},
                                              "flags": [], "totals": {}})
        finally:
            os.replace = orig
        self.assertEqual((d / "snapshot.json").read_bytes(), before)
        self.assertEqual(self.store.read_snapshot(d)["taken_at"], NOW)
        self.assertEqual([p.name for p in d.iterdir()], ["snapshot.json"])


if __name__ == "__main__":
    unittest.main()
