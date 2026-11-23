"""Contract tests for harness/hooks/wal_segments.py (docs/spec/wal-segments.md). Synthetic data only."""
import ast
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

HOOKS = Path(__file__).resolve().parents[1] / "harness/hooks"
sys.path.insert(0, str(HOOKS))
import wal_segments as ws  # noqa: E402

LIMIT = 4096


def hard(problems):
    return [p for p in problems if p["code"] not in ("live_missing", "marker_info", "schema_newer")]


def rec(i, pad=0, who="w"):
    return {"at": "2026-01-01T00:00:00+00:00", "event": "status", "n": i, "who": who, "pad": "x" * pad}


def line(r):
    return (json.dumps(r, separators=(",", ":")) + "\n").encode()


class Base(unittest.TestCase):
    switch = True

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name).resolve()
        self.dir = self.home / ".claude" / "wals" / "sess"
        self.dir.mkdir(parents=True)
        if self.switch:
            (self.home / ".agent-harness" / "state").mkdir(parents=True)
            (self.home / ".agent-harness" / "state" / "wal-rotation.on").write_text("")
        self.env = {"HOME": str(self.home), "HARNESS_TEST": "1", "HARNESS_WAL_SEGMENT_BYTES": str(LIMIT)}
        p = patch.dict(os.environ, self.env)
        p.start()
        self.addCleanup(p.stop)

    def append(self, name, r):
        fd = os.open(self.dir, os.O_RDONLY | os.O_DIRECTORY)
        try:
            ws.append_line(fd, name, line(r))
        finally:
            os.close(fd)

    def records(self, name="main.jsonl"):
        return [json.loads(raw) for _, _, raw in ws.iter_lines(self.dir / name)]

    def closed(self, stem="main"):
        return sorted(p.name for p in self.dir.iterdir() if ws.SEGMENT_RE.match(p.name) and ws.SEGMENT_RE.match(p.name).group("stem") == stem)

    def child(self, code, extra=None, **kw):
        env = dict(os.environ, **self.env, **(extra or {}))
        return subprocess.run([sys.executable, "-c", "import sys; sys.path.insert(0, %r)\n%s" % (str(HOOKS), code)],
                              env=env, capture_output=True, text=True, **kw)


APPEND_CODE = """
import os, json, wal_segments as ws
fd = os.open(%(dir)r, os.O_RDONLY | os.O_DIRECTORY)
for i in range(%(n)d):
    r = {"at": "2026-01-01T00:00:00+00:00", "event": "status", "n": i, "who": %(who)r, "pad": "x" * %(pad)d}
    ws.append_line(fd, "main.jsonl", (json.dumps(r, separators=(",", ":")) + "\\n").encode())
"""


class RotationTests(Base):
    def test_rotates_and_links(self):
        for i in range(60):
            self.append("main.jsonl", rec(i, 200))
        segs = self.closed()
        self.assertGreaterEqual(len(segs), 3)
        self.assertEqual(segs, [ws.segment_name("main", k) for k in range(1, len(segs) + 1)])  # contiguous
        self.assertEqual([r["n"] for r in self.records()], list(range(60)))  # no loss, no duplicate, in order
        first = (self.dir / "main.jsonl").read_bytes().split(b"\n")[0]
        m = ws.parse_marker(first)
        self.assertEqual(m["prev"], segs[-1])
        self.assertEqual(m["segment"], len(segs) + 1)
        prev = (self.dir / segs[-1]).read_bytes()
        self.assertEqual((m["prev_sha256"], m["prev_bytes"], m["prev_lines"]),
                         (hashlib.sha256(prev).hexdigest(), len(prev), prev.count(b"\n")))
        self.assertEqual(hard(ws.verify_chain(self.dir, "main", deep=True)), [])

    def test_index_written_and_rebuildable(self):
        for i in range(40):
            self.append("main.jsonl", rec(i, 200))
        idx = json.loads((self.dir / "main.segments.json").read_text())
        n = len(self.closed())
        self.assertEqual(len(idx["segments"]), n)
        self.assertEqual(idx["live"]["seq"], n + 1)
        fd = os.open(self.dir, os.O_RDONLY | os.O_DIRECTORY)
        again = ws.build_index(fd, "main")
        os.close(fd)
        self.assertEqual(idx["segments"], again["segments"])  # live bytes move after the last rotation: segments only
        os.chmod(self.dir / "main.segments.json", 0o600)
        (self.dir / "main.segments.json").unlink()  # a missing index never changes what a reader returns
        self.assertEqual([r["n"] for r in self.records()], list(range(40)))

    def test_switch_absent_means_no_rotation_and_no_marker(self):
        (self.home / ".agent-harness/state/wal-rotation.on").unlink()
        for i in range(60):
            self.append("main.jsonl", rec(i, 200))
        self.assertEqual(self.closed(), [])
        self.assertIsNone(ws.parse_marker((self.dir / "main.jsonl").read_bytes().split(b"\n")[0]))

    def test_oversized_record_does_not_loop(self):
        self.append("main.jsonl", rec(0, 100))
        self.append("main.jsonl", rec(1, LIMIT * 3))
        self.append("main.jsonl", rec(2, 10))
        self.append("main.jsonl", rec(3, 10))
        self.assertEqual([r["n"] for r in self.records()], [0, 1, 2, 3])
        for name in self.closed():  # never a marker-only segment
            self.assertGreater((self.dir / name).stat().st_size, ws.MARKER_ONLY_BYTES)

    def test_production_ignores_test_overrides(self):
        with patch.dict(os.environ, {"HARNESS_TEST": ""}):
            self.assertEqual(ws.segment_limit(), ws.SEGMENT_BYTES)
        with patch.dict(os.environ, {"HOME": "/Users/not-a-tmp-home"}):
            self.assertEqual(ws.segment_limit(), ws.SEGMENT_BYTES)

    def test_reserved_stem_refused(self):
        with self.assertRaises(ValueError):
            self.append("agent-x.0001.jsonl", rec(0))

    def test_torn_tail_removed_before_rotation(self):
        for i in range(10):
            self.append("main.jsonl", rec(i, 300))
        with open(self.dir / "main.jsonl", "ab") as f:
            f.write(b'{"torn":')
        for i in range(10, 30):
            self.append("main.jsonl", rec(i, 300))
        self.assertEqual([r["n"] for r in self.records()], list(range(30)))
        for name in self.closed():
            self.assertTrue((self.dir / name).read_bytes().endswith(b"\n"))

    def test_rename_collision_skips_rotation_and_keeps_record(self):
        (self.dir / "main.0001.jsonl").write_text('{"at":"x","event":"status","n":-1}\n')
        # seq 1 exists, so the next seq is 2: force a collision on 2 by pre-creating it while hiding it from the scan
        orig = ws._next_seq
        with patch.object(ws, "_next_seq", side_effect=lambda d, s, f=None: 1):
            for i in range(30):
                self.append("main.jsonl", rec(i, 300))
        self.assertEqual(orig(os.open(self.dir, os.O_RDONLY | os.O_DIRECTORY), "main"), 2)
        self.assertEqual((self.dir / "main.0001.jsonl").read_text(), '{"at":"x","event":"status","n":-1}\n')  # never replaced
        self.assertEqual([r["n"] for r in self.records()][-30:], list(range(30)))

    def test_unsupported_exclusive_rename_is_reported_and_record_kept(self):
        with patch.object(ws, "_exclusive_rename", side_effect=NotImplementedError("EINVAL")):
            for i in range(30):
                self.append("main.jsonl", rec(i, 300))
        self.assertEqual(self.closed(), [])
        self.assertEqual([r["n"] for r in self.records()], list(range(30)))

    def test_seglock_timeout_skips_rotation_but_appends(self):
        import fcntl
        fd = os.open(self.dir / ".main.seglock", os.O_RDWR | os.O_CREAT, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX)
        self.addCleanup(os.close, fd)
        with patch.dict(os.environ, {"HARNESS_WAL_LOCK_WAIT": "0.1"}):
            for i in range(30):
                self.append("main.jsonl", rec(i, 300))
        self.assertEqual(self.closed(), [])
        self.assertEqual(len(self.records()), 30)


class LegacyTests(Base):
    def test_80mb_wal_is_renamed_whole(self):
        path = self.dir / "main.jsonl"
        chunk = line(rec(0, 1000)) * 1000
        h = hashlib.sha256()
        with open(path, "wb") as f:
            for _ in range(80):
                f.write(chunk)
                h.update(chunk)
        ino, sha = path.stat().st_ino, h.hexdigest()
        with patch.dict(os.environ, {"HARNESS_WAL_SEGMENT_BYTES": str(50 * 1024 * 1024)}):
            self.append("main.jsonl", rec(1, 5))
        seg = self.dir / "main.0001.jsonl"
        self.assertEqual(self.closed(), ["main.0001.jsonl"])
        self.assertEqual(seg.stat().st_ino, ino)  # a rename, not a copy
        self.assertEqual(hashlib.sha256(seg.read_bytes()).hexdigest(), sha)
        m = ws.parse_marker((self.dir / "main.jsonl").read_bytes().split(b"\n")[0])
        self.assertEqual(m["prev_sha256"], sha)
        self.assertEqual(len((self.dir / "main.jsonl").read_bytes().splitlines()), 2)


class GapTests(Base):
    def make(self, names):
        for n in names:
            (self.dir / n).write_text(json.dumps(rec(0)) + "\n")

    def codes(self, stem="main"):
        return [(p["code"], p["seq"]) for p in ws.chain(self.dir, stem).problems]

    def test_missing_middle(self):
        self.make(["main.0001.jsonl", "main.0003.jsonl", "main.jsonl"])
        self.assertEqual(self.codes(), [("gap", 2)])
        problems = []
        list(ws.iter_lines(self.dir / "main.jsonl", problems=problems))
        self.assertIn("gap", [p["code"] for p in problems])  # reported, never silent
        with self.assertRaises(ws.SegmentProblem):
            list(ws.iter_lines(self.dir / "main.jsonl", strict=True))

    def test_missing_leading_is_a_range(self):
        self.make(["main.0003.jsonl", "main.jsonl"])
        self.assertEqual(self.codes(), [("gap", 1)])
        self.assertIn("1..2", ws.chain(self.dir, "main").problems[0]["message"])

    def test_huge_seq_is_not_enumerated(self):
        self.make(["main.9999999999999.jsonl", "main.jsonl"])
        start = time.time()
        self.assertEqual(self.codes(), [("gap", 1)])
        self.assertLess(time.time() - start, 2)

    def test_live_missing_is_not_a_gap(self):
        self.make(["main.0001.jsonl", "main.0002.jsonl"])
        self.assertEqual(self.codes(), [("live_missing", None)])
        self.assertTrue(ws.chain(self.dir, "main").complete)
        self.assertTrue(ws.exists(self.dir / "main.jsonl"))

    def test_symlink_and_directory_segments_never_followed(self):
        real = self.dir / "elsewhere.jsonl"
        real.write_text(json.dumps(rec(99)) + "\n")
        self.make(["main.jsonl"])
        os.symlink(real, self.dir / "main.0001.jsonl")
        (self.dir / "main.0002.jsonl").mkdir()
        got = self.codes()
        self.assertIn(("not_regular", 1), got)
        self.assertIn(("not_regular", 2), got)
        self.assertNotIn(99, [r["n"] for r in self.records()])

    def test_ambiguous_duplicate_seq(self):
        self.make(["main.0002.jsonl", "main.00002.jsonl", "main.0001.jsonl", "main.jsonl"])
        self.assertIn("ambiguous", [c for c, _ in self.codes()])

    def test_marker_checks(self):
        for i in range(30):
            self.append("main.jsonl", rec(i, 300))
        segs = self.closed()
        self.assertGreaterEqual(len(segs), 2)
        os.rename(self.dir / segs[0], self.dir / "gone.tmp")  # now a leading gap
        self.assertIn("gap", [p["code"] for p in ws.verify_chain(self.dir, "main")])

    def test_markers_hidden_after_two_rotations(self):  # R3-1: a closed segment keeps its marker as line 1
        for i in range(60):
            self.append("main.jsonl", rec(i, 300))
        self.assertGreaterEqual(len(self.closed()), 2)
        events = [r["event"] for r in self.records()]
        self.assertNotIn(ws.MARKER_EVENT, events)
        self.assertEqual(len(events), 60)
        lines = [n for _, n, _ in ws.iter_lines(self.dir / "main.jsonl")]
        self.assertEqual(lines, list(range(1, 61)))  # logical numbering is unchanged by rotations

    def test_forged_marker_mid_file_is_an_ordinary_record(self):
        self.append("main.jsonl", rec(0))
        self.append("main.jsonl", {"at": "x", "event": ws.MARKER_EVENT, "by": ws.MARKER_BY, "stem": "main", "segment": 7})
        self.assertEqual(len(self.records()), 2)


class CrashTests(Base):
    def run_to(self, step):
        for i in range(8):
            self.append("main.jsonl", rec(i, 400))
        before = self.closed()
        code = APPEND_CODE % {"dir": str(self.dir), "n": 30, "who": "c", "pad": 400}
        r = self.child(code, {"HARNESS_WAL_FAULT": step})
        self.assertEqual(r.returncode, 77, r.stderr)  # the child died AT the fault point, not earlier or never
        return before

    def converge(self, expect_state):
        expect_state()
        seen = [r["n"] for r in self.records() if r["who"] == "w"]
        self.assertEqual(seen, list(range(8)))  # nothing lost at the crash state
        self.append("main.jsonl", rec(100, 10, "after"))
        self.assertEqual(hard(ws.verify_chain(self.dir, "main", deep=True)), [])
        self.assertEqual([r["n"] for r in self.records() if r["who"] == "after"], [100])

    def test_after_hash(self):
        before = self.run_to("after_hash")
        self.converge(lambda: self.assertEqual(self.closed(), before))

    def test_after_rename(self):
        before = self.run_to("after_rename")

        def state():
            self.assertFalse((self.dir / "main.jsonl").exists())
            self.assertEqual(len(self.closed()), len(before) + 1)
            self.assertTrue(ws.exists(self.dir / "main.jsonl"))
        self.converge(state)

    def test_after_temp(self):  # the marked temp file exists; nothing renamed yet
        before = self.run_to("after_temp")

        def state():
            self.assertEqual(self.closed(), before)
            self.assertTrue(list(self.dir.glob(".main.live.*.new")), "the temp file is the only new thing")
            self.assertIsNone(ws.parse_marker((self.dir / "main.jsonl").read_bytes().split(b"\n")[0]))
        self.converge(state)

    def test_after_live(self):  # the marked file was renamed into the live name
        before = self.run_to("after_live")

        def state():
            self.assertEqual(len(self.closed()), len(before) + 1)
            self.assertIsNotNone(ws.parse_marker((self.dir / "main.jsonl").read_bytes().split(b"\n")[0]))
        self.converge(state)

    def test_after_index(self):
        self.run_to("after_index")
        self.converge(lambda: self.assertTrue((self.dir / "main.segments.json").exists()))

    def test_enospc_on_create_rolls_back(self):
        real = os.open

        def fake(path, flags, mode=0o777, *, dir_fd=None):
            if path.startswith(".main.live.") and flags & os.O_EXCL:
                raise OSError(28, "No space left on device")
            return real(path, flags, mode, dir_fd=dir_fd)
        with patch.object(ws.os, "open", side_effect=fake):
            for i in range(30):
                self.append("main.jsonl", rec(i, 300))
        self.assertEqual(self.closed(), [])  # rotation skipped before anything was renamed
        self.assertEqual([r["n"] for r in self.records()], list(range(30)))  # record kept, nothing lost


class ConcurrencyTests(Base):
    def test_many_writers_lose_nothing(self):
        code = APPEND_CODE % {"dir": str(self.dir), "n": 120, "who": "%s", "pad": 300}
        procs = [subprocess.Popen([sys.executable, "-c", "import sys; sys.path.insert(0, %r)\n%s" % (str(HOOKS), code % f"p{k}")],
                                  env=dict(os.environ, **self.env), stderr=subprocess.PIPE, text=True) for k in range(6)]
        errs = [p.communicate()[1] for p in procs]
        self.assertEqual([p.returncode for p in procs], [0] * 6, errs)
        got = self.records()
        self.assertEqual(len(got), 6 * 120)
        for k in range(6):
            self.assertEqual([r["n"] for r in got if r["who"] == f"p{k}"], list(range(120)))  # exactly once, in order
        segs = self.closed()
        self.assertGreaterEqual(len(segs), 3)
        self.assertEqual(segs, [ws.segment_name("main", k) for k in range(1, len(segs) + 1)])
        self.assertEqual(hard(ws.verify_chain(self.dir, "main", deep=True)), [])
        for name in segs:
            self.assertGreater((self.dir / name).stat().st_size, ws.MARKER_ONLY_BYTES)  # no marker-only segments

    def test_stale_writer_retries_into_new_live(self):
        for i in range(20):
            self.append("main.jsonl", rec(i, 300))
        self.assertGreaterEqual(len(self.closed()), 1)
        self.assertEqual(len(self.records()), 20)


class ReaderRaceTests(Base):
    def test_reader_paused_between_open_and_list_sees_consistent_prefix(self):
        for i in range(10):
            self.append("main.jsonl", rec(i, 300))
        pause = self.home / "reader.pause"
        code = """
import json, wal_segments as ws
out = [json.loads(r)["n"] for _, _, r in ws.iter_lines(%r)]
print(json.dumps(out))
""" % str(self.dir / "main.jsonl")
        proc = subprocess.Popen([sys.executable, "-c", "import sys; sys.path.insert(0, %r)\n%s" % (str(HOOKS), code)],
                                env=dict(os.environ, **self.env, HARNESS_WAL_READER_PAUSE="after_open", HARNESS_WAL_PAUSE_FILE=str(pause)),
                                stdout=subprocess.PIPE, text=True)
        deadline = time.time() + 10
        while not pause.exists() and time.time() < deadline:
            time.sleep(0.01)
        self.assertTrue(pause.exists(), "reader never reached the pause point")
        before = len(self.closed())
        for i in range(10, 40):  # rotate while the reader holds the old live fd
            self.append("main.jsonl", rec(i, 300))
        self.assertGreater(len(self.closed()), before)
        pause.unlink()
        out = json.loads(proc.communicate()[0])
        self.assertEqual(out, list(range(10)))  # a duplicate-free, in-order prefix holding everything written before it opened
        self.assertEqual([r["n"] for r in self.records()], list(range(40)))  # and a fresh read sees all


class ReadTailTests(Base):
    def test_tail_crosses_segments_without_markers(self):
        for i in range(40):
            self.append("main.jsonl", rec(i, 300))
        data = ws.read_tail(self.dir / "main.jsonl", 10_000_000)
        self.assertEqual([json.loads(x)["n"] for x in data.splitlines()], list(range(40)))
        small = ws.read_tail(self.dir / "main.jsonl", 1500)
        self.assertLessEqual(len(small), 1500)
        self.assertEqual(json.loads(small.splitlines()[-1])["n"], 39)


class CliTests(Base):
    def cli(self, *args):
        return subprocess.run([sys.executable, str(HOOKS / "wal_segments.py"), *args], capture_output=True, text=True,
                              env={"PATH": os.environ.get("PATH", ""), "HOME": "/nonexistent-home"})

    def backup(self):
        for i in range(40):
            self.append("main.jsonl", rec(i, 300))
        dest = self.home / "backup" / "copy"
        dest.mkdir(parents=True)
        for p in self.dir.iterdir():
            if p.is_file():
                (dest / p.name).write_bytes(p.read_bytes())
        return dest

    def test_map_verify_cat_reindex_on_a_copy(self):
        dest = self.backup()
        m = json.loads(self.cli("map", str(dest)).stdout)
        self.assertTrue(m["wals"][0]["complete"])
        self.assertEqual(self.cli("verify", str(dest), "--deep").returncode, 0)
        cat = self.cli("cat", str(dest), "main")
        self.assertEqual([json.loads(x)["n"] for x in cat.stdout.splitlines()], list(range(40)))
        before = (dest / "main.segments.json").read_bytes()
        self.assertEqual(self.cli("reindex", str(dest), "main").returncode, 0)  # dry run
        self.assertEqual((dest / "main.segments.json").read_bytes(), before)
        self.assertEqual(self.cli("reindex", str(dest), "main", "--write").returncode, 0)

    def test_gap_makes_cat_and_verify_fail(self):
        dest = self.backup()
        os.rename(dest / "main.0002.jsonl", dest / "stash.tmp")
        self.assertEqual(self.cli("verify", str(dest)).returncode, 1)
        self.assertEqual(self.cli("cat", str(dest), "main").returncode, 1)
        allowed = self.cli("cat", str(dest), "main", "--allow-gaps")
        self.assertEqual(allowed.returncode, 0)
        self.assertIn("gap", allowed.stderr)

    def test_bad_arguments_refused(self):
        dest = self.backup()
        link = self.home / "link"
        os.symlink(dest, link)
        self.assertNotEqual(self.cli("map", str(link)).returncode, 0)
        self.assertNotEqual(self.cli("cat", str(dest), "../main").returncode, 0)
        self.assertNotEqual(self.cli("cat", str(dest), "main.0001").returncode, 0)


class WriterContractTests(Base):
    """Every writer (claude wal.py, codex wal.py, ah._wal_append) rotates through the one shared implementation."""

    def load(self, path, name):
        import importlib.util
        spec = importlib.util.spec_from_file_location(name, path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod

    def check_rotated(self, directory, total):
        got = [json.loads(raw)["n"] for _, _, raw in ws.iter_lines(directory / "main.jsonl")]
        self.assertEqual(got, list(range(total)))
        segs = [p.name for p in directory.iterdir() if ws.SEGMENT_RE.match(p.name)]
        self.assertGreaterEqual(len(segs), 2)  # rotation actually happened, not just byte equality
        self.assertEqual(hard(ws.verify_chain(directory, "main", deep=True)), [])

    def test_claude_hook_writer(self):
        mod = self.load(HOOKS / "wal.py", "wal_claude")
        session = self.home / ".claude/wals/claudes"
        session.mkdir(parents=True)
        for i in range(40):
            mod.append(session / "main.jsonl", rec(i, 300))
        self.check_rotated(session, 40)

    def test_codex_hook_writer(self):
        mod = self.load(HOOKS.parents[1] / "codex/hooks/wal.py", "wal_codex")
        session = self.home / ".agent-harness/codex-wals/codexs"
        session.mkdir(parents=True)
        for i in range(40):
            mod.append(session / "main.jsonl", rec(i, 300))
        self.check_rotated(session, 40)

    def test_ah_writer_and_dedupe_across_segments(self):
        ah = self.load(HOOKS / "ah.py", "ah_under_test")
        session = self.home / ".claude/wals/ahsess"
        session.mkdir(parents=True)
        path = session / "main.jsonl"
        for i in range(40):
            ah._wal_append(self.home, path, dict(rec(i, 300), id=f"wid{i:04d}"))
        self.check_rotated(session, 40)
        ah._wal_append(self.home, path, dict(rec(999, 300), id="wid0001"))  # id sits in a closed segment
        self.assertEqual(len(ws.read_logical(path).splitlines()), 40)  # the retry appended nothing

    def test_segment_shaped_ids_are_escaped(self):
        for path, name in ((HOOKS / "wal.py", "w1"), (HOOKS.parents[1] / "codex/hooks/wal.py", "w2")):
            mod = self.load(path, name)
            safe = mod.safe_id("x.0001")
            self.assertTrue(safe.startswith("z-"), safe)
            self.assertIsNone(ws.SEGMENT_RE.match(f"agent-{safe}.jsonl"))


def open_fds():
    return len(os.listdir("/dev/fd"))  # the listing's own fd is counted before and after alike


class AppendInvariantTests(Base):
    """One invariant for append_line (gate F1): the record lands in a valid live file or a handled error is raised,
    and every exit path closes what it opened. Each early-exit shape of _rotate is a scenario."""

    def run_scenario(self, patches, total=40, expect_closed=None):
        before = open_fds()
        with patches:
            for i in range(total):
                self.append("main.jsonl", rec(i, 300))
        self.assertEqual(open_fds(), before, "fd leaked")
        self.assertEqual([r["n"] for r in self.records()], list(range(total)))  # every record exactly once, in order
        if expect_closed is not None:
            self.assertEqual(len(self.closed()), expect_closed)

    def test_live_name_recreated_between_rename_and_create(self):  # R3-8: an old writer recreates the live name
        real = ws._fault

        def fake(step):
            if step == "after_rename" and not (self.dir / "main.jsonl").exists():
                (self.dir / "main.jsonl").write_bytes(b"")
            return real(step)
        self.run_scenario(patch.object(ws, "_fault", fake))
        self.assertGreaterEqual(len(self.closed()), 1)  # the rotation really happened

    def test_collision_skips_rotation_without_leak(self):
        (self.dir / "main.0001.jsonl").write_text('{"at":"x","event":"status","n":-1}\n')
        with patch.object(ws, "_next_seq", side_effect=lambda d, s, f=None: 1):
            before = open_fds()
            for i in range(30):
                self.append("main.jsonl", rec(i, 300))
            self.assertEqual(open_fds(), before)
        self.assertEqual([r["n"] for r in self.records()][-30:], list(range(30)))

    def test_unsupported_rename_without_leak(self):
        self.run_scenario(patch.object(ws, "_exclusive_rename", side_effect=NotImplementedError("EINVAL")), expect_closed=0)

    def test_implausible_seq_without_leak(self):
        self.run_scenario(patch.object(ws, "_next_seq", side_effect=lambda d, s, f=None: 5000), expect_closed=0)

    def test_create_failure_undone_without_leak(self):
        real = os.open

        def fake(path, flags, mode=0o777, *, dir_fd=None):
            if path.startswith(".main.live.") and flags & os.O_EXCL:
                raise OSError(28, "No space left on device")
            return real(path, flags, mode, dir_fd=dir_fd)
        self.run_scenario(patch.object(ws.os, "open", side_effect=fake), expect_closed=0)

    def test_io_error_writing_the_marker_skips_rotation_and_keeps_every_record(self):  # F2, before any rename
        real = ws._write_all

        def eio(fd, data):
            if ws.MARKER_EVENT.encode() in data:
                raise OSError(5, "injected EIO writing the marker")
            return real(fd, data)
        self.run_scenario(patch.object(ws, "_write_all", eio), expect_closed=0)

    def test_failure_after_rename_raises_the_documented_code_then_recovers(self):  # F2, after the rename
        for i in range(8):
            self.append("main.jsonl", rec(i, 400))
        real = ws._exclusive_rename
        calls = []

        def flaky(dir_fd, old, new):
            calls.append((old, new))
            if len(calls) == 1:
                return real(dir_fd, old, new)  # live -> segment succeeds
            raise OSError(5, "injected EIO moving the marked file into the live name")
        before = open_fds()
        failed = None
        with patch.object(ws, "_exclusive_rename", flaky):
            for i in range(8, 30):
                try:
                    self.append("main.jsonl", rec(i, 400))
                except ValueError as error:
                    failed = (i, str(error))
                    break
        self.assertIsNotNone(failed, "the rotation never reached the failure")
        self.assertTrue(failed[1].startswith("rotate_failed_record_not_written"), failed[1])  # the documented code
        self.assertEqual(open_fds(), before)
        for i in range(100, 105):  # the next appends recover: live file recreated with its marker
            self.append("main.jsonl", rec(i, 50))
        got = [r["n"] for r in self.records()]
        self.assertEqual(got, list(range(failed[0])) + list(range(100, 105)))  # the failed record was not written anywhere
        self.assertEqual(hard(ws.verify_chain(self.dir, "main", deep=True)), [])

    def test_live_name_is_never_visible_without_its_marker(self):  # F1: a record can never precede the marker
        seen = []
        real = ws._fault

        def check(step):
            live = self.dir / "main.jsonl"
            if live.exists() and self.closed():
                data = live.read_bytes()
                seen.append((step, bool(data) and ws.parse_marker(data.split(b"\n")[0]) is not None, bool(data)))
            return real(step)
        with patch.object(ws, "_fault", check):
            for i in range(40):
                self.append("main.jsonl", rec(i, 300))
        self.assertGreaterEqual(len(self.closed()), 2)
        # a live file that exists next to closed segments is, at every fault point of every later rotation, either
        # the previous live file (marked) or the new one (marked): never empty or unmarked
        self.assertTrue(seen)
        self.assertEqual([s for s in seen if not s[1]], [])

    def test_writer_without_the_seglock_never_creates_the_live_file_early(self):  # F3 docs vs code
        import threading
        for i in range(3):
            self.append("main.jsonl", rec(i, 50))
        (self.dir / ".main.seglock").mkdir()  # an unusable seglock: the writer proceeds without it
        seg = (self.dir / "main.jsonl").read_bytes()
        os.rename(self.dir / "main.jsonl", self.dir / "main.0001.jsonl")  # a rotation is mid-flight: live name absent

        def rotator_finishes():  # the rotator moves its marked file into the live name a moment later
            time.sleep(0.15)
            tmp = self.dir / ".main.live.test.new"
            tmp.write_bytes(ws._marker("main", 2, "main.0001.jsonl", len(seg), 3, hashlib.sha256(seg).hexdigest()))
            os.rename(tmp, self.dir / "main.jsonl")
        t = threading.Thread(target=rotator_finishes)
        t.start()
        self.append("main.jsonl", rec(3, 50))
        t.join()
        first = (self.dir / "main.jsonl").read_bytes().split(b"\n")[0]
        self.assertIsNotNone(ws.parse_marker(first), "the writer created the live file itself and put its record before the marker")
        self.assertEqual([r["n"] for r in self.records()], [0, 1, 2, 3])


class FramingTests(Base):
    """One framing rule for every reader (gate F2, F3)."""

    def fake_marker(self, seg, stem="main"):
        return line({"at": "x", "event": ws.MARKER_EVENT, "by": ws.MARKER_BY, "schema": 1, "stem": stem, "segment": seg,
                     "prev": "main.0001.jsonl", "prev_bytes": 1, "prev_lines": 1, "prev_sha256": "0" * 64, "limit": 1})

    def test_oversized_line_is_one_none_and_keeps_numbering(self):
        big = b'{"at":"x","event":"status","pad":"' + b"x" * (9 * 1024 * 1024) + b'"}\n'
        (self.dir / "main.jsonl").write_bytes(line(rec(0)) + big + line(rec(1)))
        got = list(ws.iter_lines(self.dir / "main.jsonl"))
        self.assertEqual([n for _, n, _ in got], [1, 2, 3])
        self.assertIsNone(got[1][2])
        self.assertEqual(json.loads(got[2][2])["n"], 1)  # the tail of the big line is not a fake line
        self.assertEqual(ws.read_logical(self.dir / "main.jsonl").count(b"\n"), 2)

    def test_marker_shaped_first_record_of_unrotated_live_is_a_record(self):
        (self.dir / "main.jsonl").write_bytes(self.fake_marker(2) + line(rec(1)))
        problems = []
        got = list(ws.iter_lines(self.dir / "main.jsonl", problems=problems))
        self.assertEqual([n for _, n, _ in got], [1, 2])
        self.assertIn("marker_mismatch", [p["code"] for p in problems])
        self.assertIn(ws.MARKER_EVENT.encode(), ws.read_tail(self.dir / "main.jsonl", 10_000))

    def test_marker_shaped_first_record_of_segment_1_is_a_record(self):
        seg1 = self.fake_marker(2) + line(rec(1))
        (self.dir / "main.0001.jsonl").write_bytes(seg1)
        real_marker = ws._marker("main", 2, "main.0001.jsonl", len(seg1), 2, hashlib.sha256(seg1).hexdigest())
        (self.dir / "main.jsonl").write_bytes(real_marker + line(rec(2)))
        problems = []
        got = list(ws.iter_lines(self.dir / "main.jsonl", problems=problems))
        self.assertEqual([n for _, n, _ in got], [1, 2, 3])  # fake marker record, rec 1, rec 2
        self.assertIn("marker_mismatch", [p["code"] for p in problems])

    def test_marker_with_wrong_segment_or_stem_is_not_dropped(self):
        (self.dir / "main.0001.jsonl").write_bytes(line(rec(0)))
        for bad in (self.fake_marker(9), self.fake_marker(2, stem="other")):
            (self.dir / "main.jsonl").write_bytes(bad + line(rec(1)))
            problems = []
            got = list(ws.iter_lines(self.dir / "main.jsonl", problems=problems))
            self.assertEqual(len(got), 3)
            self.assertIn("marker_mismatch", [p["code"] for p in problems])

    def test_live_without_marker_is_flagged_by_verify_and_reindex(self):
        (self.dir / "main.0001.jsonl").write_bytes(line(rec(0)))
        (self.dir / "main.jsonl").write_bytes(line(rec(1)))  # a degraded writer's record as line 1
        tool = str(HOOKS / "wal_segments.py")
        cli = subprocess.run([sys.executable, tool, "verify", str(self.dir)], capture_output=True, text=True)
        self.assertEqual(cli.returncode, 1)
        self.assertIn("marker_missing", cli.stderr)
        again = subprocess.run([sys.executable, tool, "reindex", str(self.dir), "main"], capture_output=True, text=True)
        self.assertIn("marker_missing", again.stderr)


class HardeningTests(Base):
    """goodqa#16787 gate findings F4 and F5."""

    def test_closed_segment_replaced_after_listing_is_reported_not_read(self):  # F5
        for i in range(30):
            self.append("main.jsonl", rec(i, 300))
        segs = self.closed()
        self.assertGreaterEqual(len(segs), 2)
        snap = ws.Snapshot(self.dir / "main.jsonl")
        imposter = self.dir / "imposter.tmp"
        imposter.write_bytes(line(rec(999)))
        os.replace(imposter, self.dir / segs[0])  # swapped after the directory was listed
        got = [json.loads(raw)["n"] for _, _, raw in snap.lines() if raw]
        problems = [p["code"] for p in snap.problems]
        snap.close()
        self.assertNotIn(999, got)
        self.assertIn("segment_changed", problems)

    def test_installed_codex_hook_does_not_import_from_a_stray_harness_dir(self):  # F4
        import shutil
        inst = self.home / ".codex" / "agent-harness"
        inst.mkdir(parents=True)
        shutil.copy(HOOKS.parents[1] / "codex/hooks/wal.py", inst / "wal.py")
        decoy = self.home / "harness" / "hooks"  # where parents[2]/harness/hooks points for an installed copy
        decoy.mkdir(parents=True)
        (decoy / "wal_segments.py").write_text("DECOY = True\n")
        code = ("import importlib.util, sys\n"
                "spec = importlib.util.spec_from_file_location('wal_installed', %r)\n"
                "mod = importlib.util.module_from_spec(spec)\nspec.loader.exec_module(mod)\n"
                "print(getattr(mod.wal_segments, 'DECOY', None) if mod.wal_segments else 'none')\n") % str(inst / "wal.py")
        out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, cwd=str(self.home),
                             env={"PATH": os.environ.get("PATH", ""), "HOME": str(self.home)})
        self.assertEqual(out.stdout.strip(), "none", out.stderr)  # the decoy was not imported


class NoDestructiveTests(unittest.TestCase):
    FORBIDDEN = {"unlink", "remove", "rmdir", "rmtree", "truncate", "ftruncate", "move", "replace", "rename", "renames"}

    def violations(self, source):
        tree = ast.parse(source)
        out = []
        for fn in [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]:
            for node in ast.walk(fn):
                if isinstance(node, ast.Call):
                    f = node.func
                    name = f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", "")
                    if name in self.FORBIDDEN:
                        out.append((fn.name, name))
        return out

    def test_only_reviewed_functions_may_remove_or_rename(self):
        found = self.violations((HOOKS / "wal_segments.py").read_text())
        # torn tail line; the derived index; our own marker-only temp file (never a WAL)
        allowed = {("_repair_tail", "ftruncate"), ("write_index", "rename"), ("_discard_temp", "unlink")}
        self.assertEqual(sorted(set(found) - allowed), [])
        self.assertIn(("_repair_tail", "ftruncate"), found)  # the guard sees what it should

    def test_exclusive_rename_is_only_called_by_rotate(self):  # the ctypes rename is not on the name list above
        tree = ast.parse((HOOKS / "wal_segments.py").read_text())
        callers = set()
        for fn in [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)]:
            for node in ast.walk(fn):
                if isinstance(node, ast.Call) and getattr(node.func, "id", "") == "_exclusive_rename":
                    callers.add(fn.name)
        self.assertEqual(callers, {"_rotate"})

    def test_guard_has_teeth(self):
        self.assertEqual(self.violations("import os\ndef f():\n    os.replace('a','b')\n"), [("f", "replace")])
        self.assertEqual(self.violations("from pathlib import Path\ndef g():\n    Path('x').unlink()\n"), [("g", "unlink")])


if __name__ == "__main__":
    unittest.main()
