"""MC consumer controls only; synthetic cursors are not real producer compatibility evidence."""

import json
import os
import shlex
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "harness/hooks"))
sys.path.insert(0, str(REPO / "harness/mission_control"))
import collectors as col
import events as ev
import safeio

FIRST = "fx1:fixture_cursor-1"
NEXT = "fx1:fixture_cursor-2"


def event(eid="fixture:history", historic=True):
    return ev.make("owner", "fixture", "synthetic owner activity", eid=eid, historic=historic)


def batch(events=(), cursor=NEXT):
    return "\n".join(json.dumps(row) for row in [*events, {"cursor": cursor}]) + "\n"


class ExportDouble:
    """Validate the real MC SSH-command shape, without connecting to any host or producer."""
    def __init__(self):
        self.real = safeio.Runner(python="/usr/bin/python3", ah="/h/ah.py", fabric_bin="/fixture/fab-live")
        self.calls = []
        self.output = None
        self.code = 0

    def run(self, kind, *args, **kwargs):
        argv = self.real.argv(kind, *args)
        words = shlex.split(argv[-1])
        cursor = words[words.index("--since") + 1] if "--since" in words else ""
        self.calls.append((args, kwargs, words))
        if cursor not in ("", FIRST, NEXT):
            return 64, ""  # specifically catches MC substituting literal0 for the empty initial cursor
        if self.output is not None:
            return self.code, self.output
        return 0, batch([event()] if cursor == "" else [event("fixture:live", False)], FIRST if cursor == "" else NEXT)


class ConsumerContract(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="mc-consumer-")
        self.addCleanup(self.tmp.cleanup)
        self.drop = Path(self.tmp.name) / "sources"
        self.drop.mkdir()
        self.hub = ev.Hub(max_rate=1000)
        self.health = col.Health(self.hub)
        self.runner = ExportDouble()
        self.remote = col.Remote(self.hub, self.health, self.runner, fabric=True, drop_dir=self.drop)

    def data(self):
        path = self.drop / "fabric.jsonl"
        return path.read_bytes() if path.exists() else b""

    def test_initial_command_keeps_empty_cursor(self):
        words = shlex.split(self.runner.real.argv("fabric-export", "")[-1])
        cursor = words[words.index("--since") + 1] if "--since" in words else ""
        self.assertEqual(cursor, "")

    def test_initial_resume_and_filedrop_keep_history_and_live_distinct(self):
        self.remote.fabric_export()
        self.assertEqual(self.remote.cursor, FIRST)
        self.remote.fabric_export()
        self.assertEqual(self.remote.cursor, NEXT)
        self.assertEqual([call[0] for call in self.runner.calls], [("",), (FIRST,)])
        self.assertTrue(all(call[1] == {"timeout": 15, "limit": 1024 * 1024} for call in self.runner.calls))
        drop = col.FileDrop(self.hub, self.health, safeio.Reader([self.drop]), self.drop)
        drop.tick(0)
        rows = {row["id"]: row for row in self.hub.recent()}
        self.assertTrue(rows["fixture:history"]["historic"])
        self.assertFalse(rows["fixture:live"].get("historic", False))

    def test_valid_resume_cursor_is_preserved_exactly(self):
        self.remote.cursor = FIRST
        self.runner.output = batch()
        self.remote.fabric_export()
        self.assertEqual(self.runner.calls[0][0], (FIRST,))
        self.assertEqual(self.remote.cursor, NEXT)

    def test_history_survives_normalization(self):
        normalized = ev.normalize_external(event(), "fabric")
        self.assertTrue(normalized.get("historic"))

    def test_history_survives_filedrop(self):
        (self.drop / "fabric.jsonl").write_text(batch([event()]).splitlines()[0] + "\n")
        drop = col.FileDrop(self.hub, self.health, safeio.Reader([self.drop]), self.drop)
        drop.tick(0)
        self.assertTrue(self.hub.recent()[0].get("historic"))

    def test_non_boolean_historic_is_refused(self):
        for value in ("false", 1, None):
            with self.subTest(value=value):
                self.assertEqual(ev.validate(dict(event(), historic=value)), "bad historic")

    def test_outgoing_cursor_requires_exact_safe_string(self):
        for cursor in ("x" * 129, "fx1:ok\n", "fx1:bad space", "fx1:bad;echo", "fx1:$(echo)", "a/b", "é", 0, None):
            with self.subTest(cursor=cursor):
                with self.assertRaises(safeio.Refused):
                    self.runner.real.argv("fabric-export", cursor)
        boundary = "fx1:" + "x" * 124
        self.assertIn(boundary, self.runner.real.argv("fabric-export", boundary)[-1])

    def test_failed_exit_preserves_cursor_and_drop(self):
        self.remote.cursor = FIRST
        self.runner.output, self.runner.code = batch([event()]), 1
        with self.assertRaises(RuntimeError):
            self.remote.fabric_export()
        self.assertEqual(self.remote.cursor, FIRST)
        self.assertEqual(self.data(), b"")

    def test_transport_exception_preserves_cursor_and_drop(self):
        self.remote.cursor = FIRST
        with mock.patch.object(self.runner, "run", side_effect=OSError("synthetic transport failure")):
            with self.assertRaises(OSError):
                self.remote.fabric_export()
        self.assertEqual(self.remote.cursor, FIRST)
        self.assertEqual(self.data(), b"")

    def test_invalid_returned_cursor_does_not_publish_or_advance(self):
        for index, cursor in enumerate(("x" * 129, "fx1:bad\n", "fx1:bad space", "fx1:bad;echo", 7)):
            with self.subTest(cursor=cursor):
                self.drop = Path(self.tmp.name) / ("case-" + str(index))
                self.drop.mkdir()
                self.remote.drop_dir = self.drop
                self.remote.cursor = FIRST
                self.runner.output = batch([event()], cursor)
                try:
                    self.remote.fabric_export()
                except (ValueError, RuntimeError, safeio.Refused):
                    pass
                self.assertEqual(self.remote.cursor, FIRST)
                self.assertEqual(self.data(), b"")

    def test_missing_footer_does_not_publish_partial_batch(self):
        self.remote.cursor = FIRST
        self.runner.output = json.dumps(event()) + "\n"
        try:
            self.remote.fabric_export()
        except (ValueError, RuntimeError):
            pass
        self.assertEqual(self.remote.cursor, FIRST)
        self.assertEqual(self.data(), b"")

    def test_append_failure_does_not_advance_cursor(self):
        self.remote.cursor = FIRST
        self.runner.output = batch([event()])
        with mock.patch.object(col.os, "open", side_effect=OSError("synthetic append failure")):
            with self.assertRaises(OSError):
                self.remote.fabric_export()
        self.assertEqual(self.remote.cursor, FIRST)

    def test_missing_sink_does_not_acknowledge_events(self):
        self.remote.cursor, self.remote.drop_dir = FIRST, None
        self.runner.output = batch([event()])
        try:
            self.remote.fabric_export()
        except (ValueError, RuntimeError):
            pass
        self.assertEqual(self.remote.cursor, FIRST)

    def test_oversize_line_does_not_skip_and_acknowledge(self):
        self.remote.cursor = FIRST
        self.runner.output = batch([dict(event(), padding="x" * 9000)])
        try:
            self.remote.fabric_export()
        except (ValueError, RuntimeError):
            pass
        self.assertEqual(self.remote.cursor, FIRST)
        self.assertEqual(self.data(), b"")

    def test_partial_bytes_interleaved_read_and_retry_lose_no_events(self):
        prior = event("fixture:prior")
        (self.drop / "fabric.jsonl").write_text(json.dumps(prior) + "\n")
        reader = col.FileDrop(self.hub, self.health, safeio.Reader([self.drop]), self.drop)
        reader.tick(0)
        records = [event("fixture:first", False)]
        self.remote.cursor, self.runner.output = FIRST, batch(records)
        payload = "".join(json.dumps(row) + "\n" for row in records).encode()
        cut = len(payload) // 2
        written = bytearray()
        snapshots = []
        original_write, original_fdopen = os.write, os.fdopen

        def is_data(fd):
            path = self.drop / "fabric.jsonl"
            return path.exists() and os.fstat(fd).st_ino == path.stat().st_ino

        def inject(data, write, flush):
            raw = data.encode() if isinstance(data, str) else bytes(data)
            remaining = cut - len(written)
            if len(raw) <= remaining:
                result = write(data)
                flush()
                written.extend(raw)
                return result
            fragment = raw[:remaining]
            write(fragment.decode() if isinstance(data, str) else fragment)
            flush()
            written.extend(fragment)
            snapshots.append(self.data())  # actual bytes ending midway through the new NDJSON line
            reader.tick(1)  # same reader interleaves before the writer reports failure
            raise OSError("synthetic mid-line append failure")

        class FileProxy:
            def __init__(self, handle):
                self.handle = handle
            def __enter__(self):
                self.handle.__enter__()
                return self
            def __exit__(self, *args):
                return self.handle.__exit__(*args)
            def __getattr__(self, name):
                return getattr(self.handle, name)
            def write(self, data):
                return inject(data, self.handle.write, self.handle.flush)

        def fdopen(fd, *args, **kwargs):
            handle = original_fdopen(fd, *args, **kwargs)
            return FileProxy(handle) if is_data(fd) else handle

        def write(fd, data):
            return inject(data, lambda part: original_write(fd, part), lambda: None) if is_data(fd) else original_write(fd, data)

        with mock.patch.object(col.os, "fdopen", side_effect=fdopen), mock.patch.object(col.os, "write", side_effect=write):
            with self.assertRaises(OSError):
                self.remote.fabric_export()
        cursor_after_failure = self.remote.cursor
        self.assertEqual(bytes(written), payload[:cut])
        self.assertTrue(snapshots[0].endswith(payload[:cut]))
        self.assertFalse(snapshots[0].endswith(b"\n"))
        reader.tick(2)  # after the failed writer releases its lock, torn bytes must still be hidden
        restarted_hub = ev.Hub(max_rate=1000)
        restarted = col.FileDrop(restarted_hub, col.Health(restarted_hub), safeio.Reader([self.drop]), self.drop)
        restarted.tick(0)
        with self.subTest(check="fresh reader obeys durable accepted prefix"):
            self.assertEqual(restarted.files[str(self.drop / "fabric.jsonl")].offset,
                             len((json.dumps(prior) + "\n").encode()))
        self.remote.fabric_export()
        for tick in range(3, 6):
            reader.tick(tick)
        ids = [row["id"] for row in self.hub.recent()]
        with self.subTest(check="no event loss or duplicate on retry"):
            self.assertEqual(ids, ["fixture:prior", "fixture:first"])
        with self.subTest(check="failed write retained cursor"):
            self.assertEqual(cursor_after_failure, FIRST)
        self.assertEqual(self.remote.cursor, NEXT)
        raw_ids = [json.loads(line)["id"] for line in self.data().splitlines()]
        self.assertEqual(raw_ids, ids)

    def test_200_character_ids_remain_distinct_through_filedrop(self):
        ids = ["fixture:" + "x" * 191 + suffix for suffix in ("a", "b")]
        self.assertEqual(len(ids[0]), 200)
        records = [dict(event(), id=eid) for eid in ids]
        (self.drop / "fabric.jsonl").write_text("".join(json.dumps(row) + "\n" for row in records))
        reader = col.FileDrop(self.hub, self.health, safeio.Reader([self.drop]), self.drop)
        reader.tick(0)
        self.assertEqual([row["id"] for row in self.hub.recent()], ids)

    def test_id_validation_refuses_trailing_newline(self):
        self.assertEqual(ev.validate(dict(event(), id="fixture:bad\n")), "bad id")

    def test_over_budget_batch_is_refused_without_acknowledgment(self):
        self.remote.cursor = FIRST
        records = [{"schema": ev.SCHEMA, "id": "fixture:" + str(i), "kind": "owner", "ts": "2026-11-10T00:00:00Z"}
                   for i in range(5001)]
        self.runner.output = batch(records)
        self.assertLess(len(self.runner.output.encode()), 1024 * 1024)
        with self.assertRaises((ValueError, RuntimeError)):
            self.remote.fabric_export()
        self.assertEqual(self.remote.cursor, FIRST)
        self.assertEqual(self.data(), b"")

    def test_invalid_event_or_malformed_footer_refuses_the_whole_batch(self):
        for index, output in enumerate((batch([dict(event(), schema="unknown")]), batch([event()])[:-4], "")):
            with self.subTest(index=index):
                self.remote.cursor = FIRST
                self.runner.output = output
                with self.assertRaises((ValueError, RuntimeError)):
                    self.remote.fabric_export()
                self.assertEqual(self.remote.cursor, FIRST)
                self.assertEqual(self.data(), b"")

    def test_checkpoint_publication_failure_hides_complete_unaccepted_batch(self):
        self.runner.output = batch([event("fixture:prior")], FIRST)
        self.remote.fabric_export()
        self.runner.output = batch([event("fixture:new", False)], NEXT)
        with mock.patch.object(col.os, "replace", side_effect=OSError("synthetic checkpoint publication failure")):
            with self.assertRaises(OSError):
                self.remote.fabric_export()
        self.assertIn(b"fixture:new", self.data())  # full bytes exist, but are not acknowledged
        self.assertEqual(self.remote.cursor, FIRST)
        reader = col.FileDrop(self.hub, self.health, safeio.Reader([self.drop]), self.drop)
        reader.tick(0)
        self.assertEqual([row["id"] for row in self.hub.recent()], ["fixture:prior"])
        self.remote.fabric_export()
        reader.tick(1)
        self.assertEqual([row["id"] for row in self.hub.recent()], ["fixture:prior", "fixture:new"])
        self.assertEqual([json.loads(line)["id"] for line in self.data().splitlines()], ["fixture:prior", "fixture:new"])

    def test_checkpoint_offset_must_end_on_line_boundary(self):
        self.remote.fabric_export()
        before = self.data()
        checkpoint = self.drop / ".fabric-commit.json"
        value = json.loads(checkpoint.read_text())
        value["offset"] -= 1
        checkpoint.write_text(json.dumps(value))
        self.runner.output = batch([event("fixture:new", False)], NEXT)
        with self.assertRaises(safeio.Refused):
            self.remote.fabric_export()
        self.assertEqual(self.data(), before)
        self.assertEqual(self.remote.cursor, FIRST)
        reader = col.FileDrop(self.hub, self.health, safeio.Reader([self.drop]), self.drop)
        reader.tick(0)
        self.assertEqual(reader.skipped, 1)
        self.assertEqual(self.hub.recent(), [])

    def test_legacy_torn_tail_is_refused_without_rewriting_existing_data(self):
        before = b'{"schema":"mc.event/1","id":"unfinished'
        (self.drop / "fabric.jsonl").write_bytes(before)
        self.remote.cursor, self.runner.output = FIRST, batch([event()])
        with self.assertRaises(safeio.Refused):
            self.remote.fabric_export()
        self.assertEqual(self.data(), before)
        self.assertEqual(self.remote.cursor, FIRST)

    def test_real_runner_refuses_overflow_instead_of_accepting_truncated_footer(self):
        cap = 1024 * 1024
        footer = batch((), NEXT).encode()
        # The first cap bytes look complete, but the real subprocess emits extra bytes after the footer.
        script = ("import sys; footer=" + repr(footer) + "; sys.stdout.buffer.write(b'\\n' * ("
                  + str(cap) + "-len(footer)) + footer + b'x')")
        runner = safeio.Runner(python=sys.executable, ah="/fixture/ah.py", fabric_bin="/fixture/export")
        self.remote.runner, self.remote.cursor = runner, FIRST
        with mock.patch.object(runner, "argv", return_value=[sys.executable, "-c", script]):
            with self.assertRaises(RuntimeError):
                self.remote.fabric_export()
        self.assertEqual(self.remote.cursor, FIRST)
        self.assertEqual(self.data(), b"")

    def test_real_runner_accepts_complete_output_within_budget(self):
        footer = batch((), NEXT)
        runner = safeio.Runner(python=sys.executable, ah="/fixture/ah.py", fabric_bin="/fixture/export")
        self.remote.runner, self.remote.cursor = runner, FIRST
        with mock.patch.object(runner, "argv", return_value=[sys.executable, "-c", "print(" + repr(footer) + ",end='')"]):
            self.remote.fabric_export()
        self.assertEqual(self.remote.cursor, NEXT)

    def test_real_runner_timeout_returns_no_partial_output(self):
        runner = safeio.Runner(python=sys.executable, ah="/fixture/ah.py", fabric_bin="/fixture/export")
        script = "import sys,time;sys.stdout.write('{');sys.stdout.flush();time.sleep(1)"
        with mock.patch.object(runner, "argv", return_value=[sys.executable, "-c", script]):
            code, output = runner.run("fabric-export", FIRST, timeout=0.05, limit=1024)
        self.assertEqual((code, output), (124, ""))

    def test_unicode_separator_inside_json_is_not_an_ndjson_boundary(self):
        self.remote.cursor = FIRST
        records = [dict(event(), summary="one\u2028two"), {"cursor": NEXT}]
        self.runner.output = "\n".join(json.dumps(row, ensure_ascii=False) for row in records) + "\n"
        self.remote.fabric_export()
        reader = col.FileDrop(self.hub, self.health, safeio.Reader([self.drop]), self.drop)
        reader.tick(0)
        self.assertEqual(self.hub.recent()[0]["id"], "fixture:history")
        self.assertEqual(self.remote.cursor, NEXT)

    def test_selector_setup_failure_does_not_spawn_an_unowned_export(self):
        runner = safeio.Runner(python=sys.executable, ah="/fixture/ah.py", fabric_bin="/fixture/export")
        with mock.patch.object(safeio.selectors, "DefaultSelector", side_effect=OSError("synthetic selector failure")):
            with mock.patch.object(safeio.subprocess, "Popen") as spawn:
                code, _ = runner.run("fabric-export", FIRST, timeout=1, limit=1024)
        self.assertEqual(code, 127)
        spawn.assert_not_called()


if __name__ == "__main__":
    unittest.main()
