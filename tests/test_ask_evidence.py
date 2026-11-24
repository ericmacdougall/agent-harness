"""#170 round 2 F2 (class 4): ask_evidence.jsonl_records lists EVERY record it does not return in `unread`. Each early stop
has a test with small patched limits: a refused file (symlink, FIFO, directory, too large, missing), the time budget, the
byte budget (the file grew while it was read), a skipped over-long line and a line that does not parse. The CLI-level
consequence (the listing exits 2 and --apply refuses) is in test_ask_sweep.Incomplete.

Run: python3 -m unittest tests.test_ask_evidence
"""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "harness" / "hooks"))
import ask_evidence as ae  # noqa: E402
import provenance  # noqa: E402


def rec(n):
    return json.dumps({"event": "status", "id": "w%011x" % n, "note": "row %d" % n}) + "\n"


class Reader(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)

    def file(self, name, data):
        path = self.dir / name
        path.write_bytes(data.encode() if isinstance(data, str) else data)
        return path

    def read(self, path, **kw):
        unread = []
        return ae.jsonl_records(path, unread, **kw), unread

    def test_a_clean_file_is_read_in_full_with_nothing_unread(self):
        rows, unread = self.read(self.file("a.jsonl", "".join(rec(n) for n in range(5)) + "\n"))
        self.assertEqual((len(rows), unread), (5, []))  # a blank line holds no record and is not a gap

    def test_refused_files_are_named_and_never_read(self):
        target = self.file("real.jsonl", rec(1))
        (self.dir / "link.jsonl").symlink_to(target)
        os.mkfifo(self.dir / "pipe.jsonl")
        (self.dir / "folder.jsonl").mkdir()
        for name, reason in (("link.jsonl", "file-symlink"), ("pipe.jsonl", "file-not-regular"),
                             ("folder.jsonl", "file-not-regular"), ("missing.jsonl", "FileNotFoundError")):
            with self.subTest(name=name):
                rows, unread = self.read(self.dir / name)
                self.assertEqual((rows, [u["reason"] for u in unread]), ([], [reason]))

    def test_a_file_over_the_size_cap_is_refused_up_front(self):
        path = self.file("big.jsonl", "".join(rec(n) for n in range(10)))
        rows, unread = self.read(path, max_file=100)
        self.assertEqual((rows, unread), ([], [{"source": str(path), "reason": "file-too-large"}]))

    def test_the_time_budget_stop_is_listed_with_the_line_it_stopped_at(self):
        path = self.file("slow.jsonl", "".join(rec(n) for n in range(10)))
        ticks = iter(range(1000))
        with mock.patch.object(ae, "MAX_SECONDS", 3.5), mock.patch.object(ae, "_clock", lambda: next(ticks)):
            rows, unread = self.read(path)
        # deadline 0 + 3.5: the clock reads 1, 2, 3 before lines 1 to 3 and 4 before line 4, so three rows are read
        self.assertEqual(len(rows), 3)
        self.assertEqual(unread, [{"source": str(path), "reason": "time-budget", "line": 4}])

    def test_a_file_that_grows_past_the_cap_while_it_is_read_stops_at_the_byte_budget(self):
        path = self.file("grow.jsonl", "".join(rec(n) for n in range(3)))
        size = path.stat().st_size
        grown = []

        def clock():  # deterministic: the writer appends once, after the size check and before the first line
            if not grown:
                grown.append(1)
                with open(path, "a") as fh:
                    fh.write("".join(rec(n) for n in range(3, 9)))
            return 0.0
        with mock.patch.object(ae, "_clock", clock):
            rows, unread = self.read(path, max_file=size + 10)
        self.assertLess(len(rows), 9)
        self.assertEqual([u["reason"] for u in unread], ["byte-budget"])

    def test_every_skipped_over_long_line_is_listed_and_reading_goes_on(self):
        long = json.dumps({"event": "status", "note": "x" * 300}) + "\n"
        path = self.file("long.jsonl", rec(1) + long + rec(3) + long + rec(5))
        with mock.patch.object(ae, "MAX_LINE", 120):
            rows, unread = self.read(path)
            with_needle, unread_needle = self.read(path, needle=b"never-there")
        self.assertEqual(len(rows), 3)
        self.assertEqual(unread, [{"source": str(path), "reason": "line-too-long", "lines": [2, 4], "count": 2}])
        # a needle cannot be checked in a line that was not read, so the long lines are still listed
        self.assertEqual((with_needle, [u["lines"] for u in unread_needle]), ([], [[2, 4]]))

    def test_lines_that_do_not_parse_are_listed_and_a_torn_last_line_is_named_in_progress(self):
        path = self.file("bad.jsonl", rec(1) + "not json\n" + b"\xff\xfe{}\n".decode("latin-1") + "[1, 2]\n" + rec(5)
                         + '{"event": "ask", "id": "w0')
        rows, unread = self.read(path)
        self.assertEqual(len(rows), 2)
        self.assertEqual(sorted((u["reason"], tuple(u["lines"])) for u in unread),
                         [("line-incomplete", (6,)), ("line-malformed", (2, 3, 4))])

    def test_invalid_utf8_is_a_decode_error_listed_as_malformed(self):
        path = self.file("utf.jsonl", rec(1).encode() + b'{"note": "\xff\xfe"}\n')
        rows, unread = self.read(path)
        self.assertEqual((len(rows), [(u["reason"], u["lines"]) for u in unread]), (1, [("line-malformed", [2])]))

    def test_a_line_without_the_needle_is_skipped_without_a_listing(self):
        path = self.file("n.jsonl", rec(1) + "not json and no needle\n" + json.dumps({"toolUseResult": 1}) + "\n")
        rows, unread = self.read(path, needle=b"toolUseResult")
        self.assertEqual((rows, unread), ([{"toolUseResult": 1}], []))

    def test_the_listed_line_numbers_are_bounded_and_the_count_is_exact(self):
        path = self.file("many.jsonl", "bad\n" * 50)
        rows, unread = self.read(path)
        self.assertEqual((rows, len(unread[0]["lines"]), unread[0]["count"]), ([], ae.LISTED_LINES, 50))

    def test_the_line_cap_is_provenances_so_a_line_provenance_verifies_is_never_unread(self):
        self.assertEqual(ae.MAX_LINE, provenance.MAX_LINE)
        self.assertEqual(ae.MAX_DEPTH, provenance.MAX_JSON_DEPTH)


class ReadAsks(unittest.TestCase):
    def test_read_asks_folds_open_and_resolved_through_the_bounded_reader(self):
        with tempfile.TemporaryDirectory() as tmp:
            wal = Path(tmp) / "s1" / "main.jsonl"
            wal.parent.mkdir()
            wal.write_text("".join(json.dumps(r) + "\n" for r in (
                {"event": "ask", "id": "w00000000001", "at": "2026-11-23T10:00:00+00:00", "note": "a"},
                {"event": "ask", "id": "w00000000002", "at": "2026-11-23T10:00:00+00:00", "note": "b"},
                {"event": "ask_resolved", "id": "w00000000009", "ref": "w00000000002", "source": "ticket:GoodQA x#1"})))
            unread = []
            got = ae.read_asks(wal, lambda v: 1.0, unread)
            self.assertEqual(([a["id"] for a in got["open"]], sorted(got["resolved"]), unread),
                             (["w00000000001"], ["w00000000002"], []))
            link = Path(tmp) / "s2" / "main.jsonl"
            link.parent.mkdir()
            link.symlink_to(wal)
            unread = []
            self.assertEqual(ae.read_asks(link, lambda v: 1.0, unread), {"open": [], "resolved": {}})
            self.assertEqual([u["reason"] for u in unread], ["file-symlink"])


if __name__ == "__main__":
    unittest.main()
