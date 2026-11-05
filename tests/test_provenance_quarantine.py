"""S3a (GoodQA goodqa#14791): sourced ask_resolved (G5), unsourced-entry quarantine with a bounded stop lint (P11), and
`ah note --source auto --dry-run`. Fail on d0c6351: ask_resolved took any token with no source, unsourced
scope/decision rows carried no quarantine flag and nothing surfaced them, and `ah note` did not exist.
"""
import datetime as dt
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

HOOKS = Path(__file__).resolve().parents[1] / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
import provenance_hooks as ph  # noqa: E402

SESSION = "sess-quar-0001"


def iso(ts):
    return dt.datetime.fromtimestamp(ts, dt.timezone.utc).isoformat()


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = Path(self.tmp.name)
        self.addCleanup(self.tmp.cleanup)
        self.env = dict(os.environ, HOME=str(self.home), AH_HOME=str(self.home))
        p = mock.patch.dict(os.environ, {"HOME": str(self.home), "AH_HOME": str(self.home)})
        p.start()
        self.addCleanup(p.stop)
        self.wal = self.home / ".claude" / "wals" / SESSION / "main.jsonl"
        self.wal.parent.mkdir(parents=True)
        self.wal.write_text("")

    def note(self, *args):
        p = subprocess.run([sys.executable, str(HOOKS / "wal_note.py"), "--wal", str(self.wal), *args],
                           capture_output=True, text=True, env=self.env, timeout=60)
        out = (p.stdout.strip().splitlines() or [""])[-1]
        err = (p.stderr.strip().splitlines() or [""])[-1]
        try:
            doc = json.loads(out) if out.startswith("{") else json.loads(err)
        except ValueError:
            doc = {"raw": out + err}
        return p.returncode, doc

    def rows(self):
        return [json.loads(l) for l in self.wal.read_text().splitlines() if l.strip()]

    def ah(self, *args):
        p = subprocess.run([sys.executable, "-I", str(HOOKS / "ah.py"), *args], capture_output=True, text=True, env=self.env, timeout=60)
        try:
            return p.returncode, json.loads(p.stdout)
        except ValueError:
            return p.returncode, {"raw": p.stdout + p.stderr}


sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_provenance as base  # noqa: E402  (grounded user: sources backed by a fixture transcript)


class AskResolvedSourcing(base.Env):
    """G5: a resolution names an open ask of this WAL and cites the answer; any token no longer resolves anything."""

    def note(self, *args):
        env = dict(os.environ, HOME=str(self.home))
        p = subprocess.run([sys.executable, str(HOOKS / "wal_note.py"), "--wal", str(self.wals / "main.jsonl"), *args],
                           capture_output=True, text=True, env=env, timeout=60)
        out = (p.stdout.strip().splitlines() or [""])[-1]
        err = (p.stderr.strip().splitlines() or [""])[-1]
        try:
            doc = json.loads(out) if out.startswith("{") else json.loads(err)
        except ValueError:
            doc = {"raw": out + err}
        return p.returncode, doc

    def test_resolution_needs_an_open_ask_and_a_source(self):
        src = self.user(base.HUMAN, base.QUOTE)
        rc, ask = self.note("--event", "ask", "--note", "which key?", "--reason", "release needs the staging key", "--source", src)
        self.assertEqual(rc, 0, ask)
        rc, doc = self.note("--event", "ask_resolved", "--ref", "wdoesnotexist", "--note", "done", "--source", src)
        self.assertEqual(rc, 2, doc)
        self.assertIn("no open ask", doc.get("problem", ""))
        rc, doc = self.note("--event", "ask_resolved", "--ref", ask["id"], "--note", "user said go")
        self.assertEqual(rc, 2, doc)
        self.assertIn("--source", doc.get("problem", ""))
        rc, doc = self.note("--event", "ask_resolved", "--ref", ask["id"], "--note", "user said go", "--source", "whatever I say")
        self.assertEqual(rc, 2, doc)  # M1: a garbage source is refused, not stored
        rc, doc = self.note("--event", "ask_resolved", "--ref", ask["id"], "--note", "user said go", "--source", src)
        self.assertEqual(rc, 0, doc)
        rows = [json.loads(l) for l in (self.wals / "main.jsonl").read_text().splitlines()]
        self.assertEqual(rows[-1]["event"], "ask_resolved")
        self.assertEqual(rows[-1]["source"], src)  # M1: stored
        rc, doc = self.note("--event", "ask_resolved", "--ref", ask["id"], "--note", "again", "--source", src)
        self.assertEqual(rc, 2, doc)  # already resolved: not open


class Quarantine(Base):
    def test_unsourced_decision_is_written_and_flagged_not_dropped(self):
        rc, doc = self.note("--event", "decision", "--note", "we go with python")
        self.assertEqual(rc, 0, doc)
        self.assertEqual(doc["status"], "WROTE")
        row = self.rows()[-1]
        self.assertTrue(row.get("unsourced"))
        self.assertEqual(row["note"], "we go with python")

    def test_stop_lint_blocks_after_the_grace_bounded_and_names_the_fix(self):
        now = time.time()
        old = {"at": iso(now - 11 * 60), "event": "decision", "id": "wquar0000001", "note": "old unsourced", "unsourced": True}
        fresh = {"at": iso(now - 2 * 60), "event": "scope", "id": "wquar0000002", "note": "fresh unsourced", "unsourced": True}
        sourced = {"at": iso(now - 20 * 60), "event": "decision", "id": "wquar0000003", "note": "cited", "source": "ticket:GoodQA goodqa#14791"}
        with open(self.wal, "a") as fh:
            for r in (sourced, fresh):
                fh.write(json.dumps(r) + "\n")
        payload = {"session_id": SESSION, "hook_event_name": "Stop", "stop_hook_active": False}
        self.assertEqual(ph.quarantine_block(SESSION, payload, now=now), {})  # within the grace: nothing
        with open(self.wal, "a") as fh:
            fh.write(json.dumps(old) + "\n")
        out = ph.quarantine_block(SESSION, payload, now=now)
        self.assertEqual(out.get("decision"), "block")
        self.assertIn("wquar0000001", out["reason"])
        self.assertIn("note --source auto --dry-run", out["reason"])
        self.assertNotIn("wquar0000002", out["reason"])  # the fresh one is not nagged yet
        blocks = 1 + sum(1 for _ in range(5) if ph.quarantine_block(SESSION, payload, now=now).get("decision") == "block")
        self.assertEqual(blocks, ph.QUARANTINE_MAX_BLOCKS)
        later = ph.quarantine_block(SESSION, payload, now=now)
        self.assertNotIn("decision", later)
        self.assertIn("wquar0000001", later.get("systemMessage", ""))  # still named, never silent
        active = dict(payload, stop_hook_active=True)
        self.assertNotIn("decision", ph.quarantine_block(SESSION, active, now=now))
        with mock.patch.dict(os.environ, {"CLAUDE_CODE_ENTRYPOINT": "sdk-cli"}):
            self.assertEqual(ph.quarantine_block(SESSION, payload, now=now), {})  # headless sessions are not gated
        # M3: a tool-written row (by set) is never quarantined
        with open(self.wal, "a") as fh:
            fh.write(json.dumps({"at": iso(now - 3600), "event": "decision", "id": "wquar0000009", "note": "LADDER tool row",
                                 "unsourced": True, "by": "escalation"}) + "\n")
        self.assertNotIn("wquar0000009", [r["id"] for r in ph.quarantined_entries(SESSION, now, 600)])


class NoteSourceAuto(base.Env):
    """`ah note --source auto` over a WAL whose ancestor is grounded in a real human turn (the fixture transcript)."""

    def setUp(self):
        super().setUp()
        self.wal = self.wals / "main.jsonl"
        self.wal.write_text("")
        self.env = dict(os.environ, HOME=str(self.home), AH_HOME=str(self.home))

    def rows(self):
        return [json.loads(l) for l in self.wal.read_text().splitlines() if l.strip()]

    def ah(self, *args):
        p = subprocess.run([sys.executable, "-I", str(HOOKS / "ah.py"), *args], capture_output=True, text=True, env=self.env, timeout=60)
        try:
            return p.returncode, json.loads(p.stdout)
        except ValueError:
            return p.returncode, {"raw": p.stdout + p.stderr}

    def test_dry_run_picks_the_nearest_sourced_ancestor_and_writes_nothing(self):
        now = time.time()
        with open(self.wal, "a") as fh:
            fh.write(json.dumps({"at": iso(now - 600), "event": "scope", "id": "wsrc00000001", "note": "user asked for X",
                                 "source": self.user(base.HUMAN, base.QUOTE)}) + "\n")
            fh.write(json.dumps({"at": iso(now - 300), "event": "decision", "id": "wab5c0000001", "note": "we pick Y", "unsourced": True}) + "\n")
        before = len(self.rows())
        rc, plan = self.ah("note", "--wal", str(self.wal), "--source", "auto", "--dry-run", "--note", "we pick Y")
        self.assertEqual(rc, 0, plan)
        self.assertTrue(plan["dry_run"])
        self.assertEqual(plan["source"], f"inferred: from wal:{self.wal}#wsrc00000001 -- auto-picked nearest sourced ancestor")  # M4
        self.assertEqual(plan["ancestor"]["id"], "wsrc00000001")
        self.assertEqual(len(self.rows()), before)
        rc, plan = self.ah("note", "--wal", str(self.wal), "--source", "auto", "--dry-run", "--id", "wab5c0000001")
        self.assertEqual(rc, 0, plan)
        self.assertEqual(plan["ancestor"]["id"], "wsrc00000001")  # ancestor search stops before the re-cited entry
        self.assertIn("[re-cites wab5c0000001]", plan["note"])
        rc, done = self.ah("note", "--wal", str(self.wal), "--source", "auto", "--id", "wab5c0000001")
        self.assertEqual(rc, 0, done)
        self.assertTrue(done["ok"], done)
        last = self.rows()[-1]
        self.assertEqual(last["event"], "decision")
        self.assertIn("wsrc00000001", last.get("source", ""))
        self.assertTrue(last.get("assumption"))  # M4: auto is an assumption, labelled
        self.assertEqual(last.get("recites"), "wab5c0000001")
        self.assertFalse(last.get("unsourced"))
        # B1: the sanctioned fix clears the quarantine; the lint must not block again
        payload = {"session_id": SESSION, "hook_event_name": "Stop", "stop_hook_active": False}
        self.assertEqual(ph.quarantined_entries(SESSION, now + 3600, 0), [])
        self.assertEqual(ph.quarantine_block(SESSION, payload, now=now + 3600), {})

    def test_no_ancestor_is_refused_not_guessed(self):
        rc, plan = self.ah("note", "--wal", str(self.wal), "--source", "auto", "--dry-run", "--note", "orphan decision")
        self.assertEqual(rc, 2, plan)
        self.assertEqual(plan.get("code"), "no_source")


if __name__ == "__main__":
    unittest.main()
