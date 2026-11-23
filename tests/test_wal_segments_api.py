"""Contract tests for the reader-facing API additions of wal_segments.py (PR stacked on #327): a pre-scanned listing,
the public sources/marker API, the recover CLI, and the fail-closed check when the module is missing."""
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from tests.test_wal_segments import Base, HOOKS, hard, line, rec, ws  # noqa: F401  (Base is a TestCase with no tests)

CODEX_WAL = HOOKS.parents[1] / "codex/hooks/wal.py"
CLAUDE_WAL = HOOKS / "wal.py"


class PrescannedListingTests(Base):
    def fill(self, n=30):
        for i in range(n):
            self.append("main.jsonl", rec(i, 300))

    def plain(self, name="main.jsonl"):
        return [(seg, num, raw) for seg, num, raw in ws.iter_lines(self.dir / name)]

    def test_iter_lines_read_tail_open_chain_and_read_logical_accept_a_listing(self):
        self.fill()
        listing = ws.list_wals(self.dir)["main"]
        self.assertGreaterEqual(len(listing.segments), 2)
        path = self.dir / "main.jsonl"
        self.assertEqual(list(ws.iter_lines(path, chain=listing)), self.plain())
        self.assertEqual(ws.read_tail(path, 10_000_000, chain=listing), ws.read_tail(path, 10_000_000))
        self.assertEqual(ws.read_logical(path, chain=listing), ws.read_logical(path))
        with ws.open_chain(path, chain=listing) as snap:
            self.assertEqual([r for _, _, r in snap.lines()], [r for _, _, r in self.plain()])

    def test_a_listing_means_no_directory_scan_per_call(self):
        self.fill()
        listing = ws.list_wals(self.dir)["main"]
        calls = []
        real = os.scandir

        def counting(*a, **k):
            calls.append(a)
            return real(*a, **k)
        with patch.object(ws.os, "scandir", counting):
            for _ in range(20):
                list(ws.iter_lines(self.dir / "main.jsonl", chain=listing))
        self.assertEqual(calls, [], "a valid pre-scanned listing must not trigger a scandir")

    def test_a_stale_listing_is_detected_and_rescanned(self):
        self.fill(20)
        listing = ws.list_wals(self.dir)["main"]
        before = len(listing.segments)
        for i in range(20, 70):  # more rotations after the listing was taken
            self.append("main.jsonl", rec(i, 300))
        self.assertGreater(len(self.closed()), before)
        got = [json.loads(r)["n"] for _, _, r in ws.iter_lines(self.dir / "main.jsonl", chain=listing)]
        self.assertEqual(got, list(range(70)))  # nothing lost, nothing twice, despite the stale listing
        tail = ws.read_tail(self.dir / "main.jsonl", 10_000_000, chain=listing)
        self.assertEqual([json.loads(x)["n"] for x in tail.splitlines()], list(range(70)))

    def test_a_listing_of_another_wal_or_directory_is_ignored(self):
        self.fill(20)
        for i in range(5):
            self.append("agent-x.jsonl", rec(i, 50))
        other = ws.list_wals(self.dir)["agent-x"]
        got = [json.loads(r)["n"] for _, _, r in ws.iter_lines(self.dir / "main.jsonl", chain=other)]
        self.assertEqual(got, list(range(20)))

    def test_a_listing_naming_a_missing_segment_reports_a_problem_not_an_exception(self):
        self.fill(30)
        listing = ws.list_wals(self.dir)["main"]
        os.rename(self.dir / listing.segments[0].name, self.dir / "gone.tmp")
        problems = []
        list(ws.iter_lines(self.dir / "main.jsonl", chain=listing, problems=problems))
        self.assertTrue([p for p in problems if p["code"] in ("unreadable", "gap", "segment_changed")], problems)


class SourcesApiTests(Base):
    def test_sources_and_marker_rule_are_public(self):
        for i in range(30):
            self.append("main.jsonl", rec(i, 300))
        with ws.open_chain(self.dir / "main.jsonl") as snap:
            sources = snap.sources()
            self.assertEqual([s.seq for s in sources], list(range(1, len(sources) + 1)))
            self.assertEqual([s.name for s in sources][-1], "main.jsonl")
            first = (self.dir / sources[1].name).read_bytes().split(b"\n")[0]
        self.assertIsNotNone(ws.valid_marker(first, "main", 2))
        self.assertIsNone(ws.valid_marker(first, "main", 1))  # seq 1 never has a marker
        self.assertIsNone(ws.valid_marker(first, "other", 2))  # wrong stem
        self.assertIsNone(ws.valid_marker(first, "main", 3))  # wrong segment
        self.assertIsNone(ws.valid_marker(b'{"event":"status"}', "main", 2))

    def test_closed_digests_come_from_the_markers_and_match_the_files(self):
        for i in range(40):
            self.append("main.jsonl", rec(i, 300))
        digests = ws.closed_digests(self.dir, "main")
        segs = self.closed()
        self.assertEqual(sorted(digests), list(range(1, len(segs) + 1)))
        for seq, d in digests.items():
            data = (self.dir / d["name"]).read_bytes()
            self.assertEqual((d["bytes"], d["lines"], d["sha256"]), (len(data), data.count(b"\n"), hashlib.sha256(data).hexdigest()))

    def test_closed_digests_reuse_a_listing(self):
        for i in range(40):
            self.append("main.jsonl", rec(i, 300))
        listing = ws.list_wals(self.dir)["main"]
        calls = []
        real = os.scandir
        with patch.object(ws.os, "scandir", lambda *a, **k: (calls.append(a), real(*a, **k))[1]):
            ws.closed_digests(self.dir, "main", chain=listing)
        self.assertEqual(calls, [])


class LatencyTests(Base):
    """2,300 WALs in one directory (the shape that made ah_export._read take 6.97 s and cold `ah owners` 8.0 s)."""

    N = 2300

    def test_prescanned_listing_keeps_the_cost_near_a_plain_read(self):
        d = self.dir
        for i in range(self.N):
            (d / f"agent-{i:05d}.jsonl").write_bytes(line(rec(i, 40)) * 3)
        for i in range(0, self.N, 10):  # every 10th WAL has two closed segments
            stem = f"agent-{i:05d}"
            body = line(rec(i, 40)) * 3
            (d / f"{stem}.0001.jsonl").write_bytes(body)
            m2 = ws._marker(stem, 2, f"{stem}.0001.jsonl", len(body), 3, hashlib.sha256(body).hexdigest())
            (d / f"{stem}.0002.jsonl").write_bytes(m2 + body)
            m3 = ws._marker(stem, 3, f"{stem}.0002.jsonl", len(m2 + body), 4, hashlib.sha256(m2 + body).hexdigest())
            (d / f"{stem}.jsonl").write_bytes(m3 + body)
        paths = sorted(p for p in d.glob("agent-*.jsonl") if not ws.SEGMENT_RE.match(p.name))
        self.assertEqual(len(paths), self.N)

        t = time.perf_counter()
        for p in paths:
            with open(p, "rb") as f:
                f.read()
        t_plain = time.perf_counter() - t

        sample = paths[:150]
        t = time.perf_counter()
        for p in sample:
            list(ws.iter_lines(p))  # a private scan of the whole directory per WAL
        per_naive = (time.perf_counter() - t) / len(sample)

        calls = []
        real = os.scandir
        t = time.perf_counter()
        with patch.object(ws.os, "scandir", lambda *a, **k: (calls.append(a), real(*a, **k))[1]):
            listing = ws.list_wals(d)  # ONE scan of the directory
            total = 0
            for p in paths:
                total += sum(1 for _ in ws.iter_lines(p, chain=listing[p.stem]))
        t_listing = time.perf_counter() - t
        per_listing = t_listing / len(paths)

        print(f"\nlatency {self.N} WALs: plain read {t_plain:.3f}s, private scan per WAL {per_naive * self.N:.2f}s "
              f"(extrapolated), pre-scanned listing {t_listing:.3f}s", file=sys.stderr)
        self.assertEqual(len(calls), 1, "one scandir for the whole directory, none per WAL")
        self.assertEqual(total, self.N * 3 + (self.N // 10) * 6)  # every record, segments included
        self.assertLess(per_listing * 5, per_naive, "the listing must be at least 5x cheaper per WAL than a private scan")
        self.assertLess(t_listing, 5 * t_plain + 2.5, "the pre-scanned read must stay near a plain read")


class RecoverCliTests(Base):
    def cli(self, *args, home=None):
        return subprocess.run([sys.executable, str(HOOKS / "wal_segments.py"), *args], capture_output=True, text=True,
                              env={"PATH": os.environ.get("PATH", ""), "HOME": str(home or self.home), "HARNESS_TEST": "1"})

    def crashed(self, d):
        d.mkdir(parents=True, exist_ok=True)
        seg1 = line(rec(0)) + line(rec(1))
        (d / "main.0001.jsonl").write_bytes(seg1)
        m2 = ws._marker("main", 2, "main.0001.jsonl", len(seg1), 2, hashlib.sha256(seg1).hexdigest())
        (d / "main.0002.jsonl").write_bytes(m2 + line(rec(2)))  # live missing: a rotation crashed after the rename

    def test_recover_write_recreates_the_live_file_with_its_marker(self):
        d = self.home / ".claude/wals/crashed"
        self.crashed(d)
        dry = self.cli("recover", str(d), "main")
        self.assertEqual(dry.returncode, 0, dry.stderr)
        self.assertFalse((d / "main.jsonl").exists(), "no --write: nothing changes")
        done = self.cli("recover", str(d), "main", "--write")
        self.assertEqual(done.returncode, 0, done.stderr)
        first = (d / "main.jsonl").read_bytes().split(b"\n")[0]
        m = ws.parse_marker(first)
        self.assertIsNotNone(m)
        self.assertEqual((m["segment"], m["prev"]), (3, "main.0002.jsonl"))
        again = self.cli("recover", str(d), "main", "--write")
        self.assertEqual(again.returncode, 0)
        self.assertIn("nothing to do", again.stdout)
        self.assertEqual(self.cli("verify", str(d)).returncode, 0)

    def test_recover_finishes_an_empty_live_file(self):
        d = self.home / ".claude/wals/emptylive"
        self.crashed(d)
        (d / "main.jsonl").write_bytes(b"")
        self.assertEqual(self.cli("recover", str(d), "main", "--write").returncode, 0)
        self.assertIsNotNone(ws.parse_marker((d / "main.jsonl").read_bytes().split(b"\n")[0]))

    def test_recover_refuses_a_backup_path(self):
        d = self.home / "backup" / "copy"
        self.crashed(d)
        out = self.cli("recover", str(d), "main", "--write")
        self.assertNotEqual(out.returncode, 0)
        self.assertFalse((d / "main.jsonl").exists())
        self.assertIn("wals", out.stderr)

    def test_recover_never_edits_a_live_file_that_holds_records(self):
        d = self.home / ".claude/wals/hasrecords"
        self.crashed(d)
        (d / "main.jsonl").write_bytes(line(rec(9)))  # a degraded writer's record as line 1
        before = (d / "main.jsonl").read_bytes()
        out = self.cli("recover", str(d), "main", "--write")
        self.assertEqual((d / "main.jsonl").read_bytes(), before)
        self.assertNotEqual(out.returncode, 0)
        self.assertIn("marker_missing", out.stderr)

    def test_recover_refuses_a_symlinked_directory(self):
        d = self.home / ".claude/wals/real"
        self.crashed(d)
        link = self.home / ".claude/wals/link"
        os.symlink(d, link)
        self.assertNotEqual(self.cli("recover", str(link), "main", "--write").returncode, 0)


class MissingModuleTests(unittest.TestCase):
    """Gate-side fail-closed check: wal.py (and the codex copy) refuse to append without wal_segments.py when
    rotation is on or segment files exist, instead of silently writing only a live tail."""

    def setUp(self):
        import tempfile
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name).resolve()
        self.bin = self.home / "bin"
        self.bin.mkdir()

    def run_append(self, src, root_rel, switch=False, segment_file=False):
        shutil.copy(src, self.bin / "wal.py")  # the installed hook WITHOUT wal_segments.py beside it
        session = self.home / root_rel / "s1"
        session.mkdir(parents=True)
        if segment_file:
            (session / "main.0001.jsonl").write_text("{}\n")
        if switch:
            (self.home / ".agent-harness/state").mkdir(parents=True)
            (self.home / ".agent-harness/state/wal-rotation.on").write_text("")
        code = ("import sys\nsys.path.insert(0, %r)\nimport wal\nfrom pathlib import Path\n"
                "wal.append(Path(%r) / 'main.jsonl', {'event': 'status', 'n': 1})\nprint('appended')\n") % (str(self.bin), str(session))
        out = subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True, cwd=str(self.home),
                             env={"PATH": os.environ.get("PATH", ""), "HOME": str(self.home)})
        return out, session

    def test_claude_hook_fails_closed_when_rotation_is_on(self):
        out, session = self.run_append(CLAUDE_WAL, ".claude/wals", switch=True)
        self.assertNotEqual(out.returncode, 0)
        self.assertIn("wal_segments.py is missing", out.stderr)
        self.assertFalse((session / "main.jsonl").exists(), "nothing was appended")

    def test_claude_hook_fails_closed_when_segment_files_exist(self):
        out, session = self.run_append(CLAUDE_WAL, ".claude/wals", segment_file=True)
        self.assertNotEqual(out.returncode, 0)
        self.assertIn("wal_segments.py is missing", out.stderr)

    def test_claude_hook_still_appends_plainly_when_nothing_needs_the_module(self):
        out, session = self.run_append(CLAUDE_WAL, ".claude/wals")
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(len((session / "main.jsonl").read_text().splitlines()), 1)

    def test_codex_hook_fails_closed_when_rotation_is_on(self):
        out, session = self.run_append(CODEX_WAL, ".agent-harness/codex-wals", switch=True)
        self.assertNotEqual(out.returncode, 0)
        self.assertIn("wal_segments.py is missing", out.stderr)

    def test_the_gate_helper_is_public_for_readers_and_gates(self):
        sys.path.insert(0, str(HOOKS))
        import importlib
        wal = importlib.import_module("wal")
        self.assertTrue(callable(wal.require_segments))
        self.assertIsNone(wal.require_segments(self.home))  # the module is present here: no refusal


if __name__ == "__main__":
    unittest.main()
