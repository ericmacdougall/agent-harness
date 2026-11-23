"""WAL segment-chain migration, part 2: the gates (command_guard, escalation, spec_flow native proofs) (goodqa#16751).

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
class CommandGuardTests(Fixture):
    def test_hook_wal_predates_reads_the_chain_head_and_fails_closed(self):
        import command_guard
        old = datetime.now(timezone.utc) - timedelta(hours=2)
        self.append("main.jsonl", {"at": old.isoformat(), "event": "pretool", "tool_use_id": "t1"})
        self.fill("main.jsonl", event="status")
        self.rotated()
        self.assertTrue(command_guard._hook_wal_predates(str(self.path()), time.time() - 3600))
        self.assertFalse(command_guard._hook_wal_predates(str(self.path()), old.timestamp() - 10))
        self.make_gap()
        self.assertFalse(command_guard._hook_wal_predates(str(self.path()), time.time() - 3600))

    def test_a_chain_problem_refuses_even_when_the_live_file_alone_would_approve(self):
        import command_guard
        old = datetime.now(timezone.utc) - timedelta(hours=2)
        self.fill("main.jsonl", event="status")
        self.append("main.jsonl", {"at": old.isoformat(), "event": "pretool", "tool_use_id": "t9"})
        self.rotated()
        self.assertTrue(command_guard._hook_wal_predates(str(self.path()), time.time() - 3600))
        self.make_gap()
        self.assertFalse(command_guard._hook_wal_predates(str(self.path()), time.time() - 3600))

    def test_scan_paths_scan_the_closed_segments_of_a_named_wal_and_report_a_gap(self):
        import command_guard
        self.append("main.jsonl", {"at": iso(), "event": "status", "note": "key AKIAIOSFODNN7EXAMPLE leaked"})
        self.fill("main.jsonl", event="status")
        self.rotated()
        report = command_guard.scan_paths([str(self.path())])
        self.assertTrue([r for r in report if r[0].endswith("main.0001.jsonl") and r[2]], report)  # the secret shape in segment 1
        self.make_gap()
        report = command_guard.scan_paths([str(self.path())])
        self.assertTrue(any(any(k.startswith("wal-chain-gap") for k in r[2]) for r in report), report)


class SpecFlowTests(Fixture):
    def setUp(self):
        super().setUp()
        import spec_flow
        self.sf = spec_flow

    def test_wal_entries_return_every_row_and_refuse_a_gap(self):
        for i in range(30):
            self.append("main.jsonl", {"at": iso(), "event": "check", "n": i, "pad": "y" * 500})
        self.rotated()
        entries = self.sf.wal_entries(self.path())
        self.assertEqual([e["n"] for e in entries], list(range(30)))  # no marker, no loss, in order
        self.make_gap()
        with self.assertRaises(self.sf.SpecError) as raised:
            self.sf.wal_entries(self.path())
        self.assertIn("gap", str(raised.exception))

    def test_native_wal_read_is_the_bound_chain_and_fails_closed(self):
        for i in range(30):
            self.append("main.jsonl", {"at": iso(), "event": "check", "n": i, "pad": "z" * 500})
        self.rotated()
        identity = {"home": self.home, "uid": os.getuid()}
        data = self.sf._native_read_wal(self.path(), identity, 4_000_000)
        self.assertEqual([json.loads(x)["n"] for x in data.splitlines()], list(range(30)))
        binding = tuple(b for _m, b in self.sf._native_wal_members(self.path(), os.getuid(), 4_000_000))
        self.assertEqual(self.sf._native_read_wal(self.path(), identity, 4_000_000, binding=binding), data)
        self.fill("main.jsonl", n=12, pad=500)  # a rotation: a new segment and a new live inode
        with self.assertRaises(ValueError):  # the bound chain changed while the proof was being made
            self.sf._native_read_wal(self.path(), identity, 4_000_000, binding=binding)
        self.make_gap()
        with self.assertRaises(ValueError):
            self.sf._native_read_wal(self.path(), identity, 4_000_000)


class EscalationTests(Fixture):
    def _approval(self, resolved_late=True):
        self.append("main.jsonl", {"at": iso(), "id": "w1", "event": "ask", "note": "top for [task:k]",
                                   "source": 'user:s/u "yes"'})
        self.fill("main.jsonl", n=40)
        self.append("main.jsonl", {"at": iso(), "id": "w2", "event": "ask_resolved", "ref": "w1", "decision": "approved"})

    def test_verify_ask_pair_reads_an_ask_from_a_closed_segment(self):
        import escalation as esc
        self._approval()
        self.rotated()
        with patch.dict(os.environ, {"AGENT_HARNESS_WALS_DIR": str(self.dir.parent)}):
            self.assertEqual(esc.verify_ask_pair(self.path(), "w1", "k", allow_env_root=True)["source"][:5], "user:")

    def test_verify_ask_pair_fails_closed_on_a_gap(self):
        import escalation as esc
        self._approval()
        self.make_gap()
        with patch.dict(os.environ, {"AGENT_HARNESS_WALS_DIR": str(self.dir.parent)}):
            with self.assertRaises(esc.LedgerError) as raised:
                esc.verify_ask_pair(self.path(), "w1", "k", allow_env_root=True)
        self.assertIn("chain problem", str(raised.exception))


# ---------------------------------------------------------------------------------------------------------------
MIGRATED = ("command_guard", "escalation", "spec_flow")
# the two process-safety guards read no WAL, so their decisions cannot change (reviewed, with the reason)
UNCHANGED_GUARDS = {
    "kill_guard.py": "only judges the SHAPE of a codex WAL path inside a command it analyses; it opens no WAL",
    "ah_kill.py": "writes through wal.append and reads asks through provenance.ledger (another writer's module)",
}
OPEN_RE = re.compile(r"open\([^)\n]*(?:main|agent-[^)\n]*)\.jsonl")


class InventoryTests(unittest.TestCase):
    def test_every_migrated_gate_names_the_chain_reader_and_opens_no_wal_directly(self):
        for module in MIGRATED:
            source = (HOOKS / f"{module}.py").read_text()
            with self.subTest(module=module):
                self.assertIn("wal_segments", source)
                self.assertIsNone(OPEN_RE.search(source), "a migrated reader must not open a WAL file by name")

    def test_the_scan_regex_has_a_negative_control(self):
        self.assertIsNotNone(OPEN_RE.search("with open(folder / 'main.jsonl') as fh:"))

    def test_the_unchanged_guards_read_no_wal(self):
        for name, reason in UNCHANGED_GUARDS.items():
            with self.subTest(module=name):
                self.assertTrue(reason)
                source = (HOOKS / name).read_text()
                self.assertIsNone(OPEN_RE.search(source))
                self.assertNotIn("wal_segments", source)  # no reader to migrate: decisions identical by construction


if __name__ == "__main__":
    unittest.main()
