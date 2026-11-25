"""S3a (GoodQA goodqa#14791): sourced ask_resolved (G5), unsourced entries flagged and written (P11), and
`ah note --source auto --dry-run`. The quarantine stop lint that blocked on unsourced rows was removed in the harness
redesign (2026-11-24): an unsourced row is recorded, labelled and usable, and nothing blocks on it
(tests/test_provenance_loose.py).
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
        rc, doc = self.note("--event", "ask_resolved", "--ref", ask["id"], "--note", "I assume yes",
                            "--source", "inferred: from ticket:GoodQA goodqa#14791 -- my guess")
        self.assertEqual(rc, 2, doc)  # M3: an ask is never closed on the agent's own assumption
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

    def test_untraced_source_is_written_and_labelled_unsourced(self):
        """2026-11-24 (inverts the 2026-11-06 refusal): a source that does not trace is kept as given, the row is
        written with unsourced=True and the warning names the cause; nothing is refused for a source's form."""
        for src in ("inferred: from af794b88 ledger read ; QAC journal whens -- free text inputs are not sources",
                    "whatever I say", "ticket:not-a-ticket"):
            with self.subTest(src):
                before = len(self.rows())
                rc, doc = self.note("--event", "decision", "--note", "we go with python", "--source", src)
                self.assertEqual(rc, 0, doc)
                self.assertEqual(doc.get("status"), "WROTE")
                self.assertEqual(len(self.rows()), before + 1)
                self.assertTrue(self.rows()[-1].get("unsourced"))
                self.assertEqual(self.rows()[-1]["source"], src)  # kept as given
        # a missing source still writes, flagged
        rc, doc = self.note("--event", "decision", "--note", "no source at all")
        self.assertEqual(rc, 0, doc)
        self.assertTrue(self.rows()[-1].get("unsourced"))

    def test_only_caller_error_codes_are_refused_transient_codes_still_quarantine(self):
        """Review finding (2026-11-06): a resolver that times out or hits a malformed transcript is not the caller's
        mistake; those rejections keep the warn-mode quarantine path instead of dropping the note."""
        import wal_note
        for code in ("bad-syntax", "ticket-missing", "transcript-missing", "inferred-nested", "excerpt-not-found"):
            self.assertTrue(wal_note.caller_error(f"source rejected ({code}): x"), code)
        for code in ("scan-timeout", "transcript-malformed", "wal-missing", "wal-malformed", "file-unreadable",
                     "file-too-large", "internal", "rejected"):
            self.assertFalse(wal_note.caller_error(f"source rejected ({code}): x"), code)
        self.assertFalse(wal_note.caller_error("decision has no --source"))
        self.assertFalse(wal_note.caller_error("provenance check failed (TypeError)"))
        self.assertFalse(wal_note.caller_error(None))

    def test_inferred_free_text_input_names_the_input_not_the_source(self):
        """The rejection of `inferred: from <free text> -- why` must say which input is not a source; the old message
        said the Source must start with inferred: although it did (main WAL w8d5f765ea4c)."""
        import provenance
        r = provenance.resolve("inferred: from af794b88 ledger read 22:10Z ; ticket:GoodQA goodqa#14902 -- the when collides")
        self.assertFalse(r["ok"])
        msg = r["problems"][0]["message"]
        self.assertIn("af794b88 ledger read", msg)
        self.assertIn("inferred input", msg)
        self.assertNotIn("Source must start with", msg)


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

    def test_by_is_an_allowlist(self):
        env = dict(os.environ, HOME=str(self.home))
        p = subprocess.run([sys.executable, str(HOOKS / "wal_note.py"), "--wal", str(self.wal), "--event", "decision", "--note", "x", "--by", "me"],
                           capture_output=True, text=True, env=env, timeout=60)
        self.assertEqual(p.returncode, 2)
        self.assertIn("allowlist", p.stderr)

    def test_note_with_an_unbackable_source_is_written_unsourced(self):
        """M2: when the chosen source cannot be backed here, `ah note` must not say ok. Since 2026-11-24 the row is
        written labelled unsourced (it was refused and dropped from 2026-11-06)."""
        now = time.time()
        with open(self.wal, "a") as fh:
            fh.write(json.dumps({"at": iso(now - 600), "event": "scope", "id": "wsrc00000002", "note": "unbackable ancestor",
                                 "source": 'user:12345678-1234-1234-1234-123456789abc/12345678-1234-1234-1234-123456789abd "gone"'}) + "\n")
        before = len(self.rows())
        rc, done = self.ah("note", "--wal", str(self.wal), "--source", "auto", "--note", "follow-up")
        self.assertFalse(done["ok"])
        self.assertFalse(done.get("refused"), done)
        self.assertEqual(len(self.rows()), before + 1)
        self.assertTrue(self.rows()[-1].get("unsourced"))

    def test_no_ancestor_is_refused_not_guessed(self):
        rc, plan = self.ah("note", "--wal", str(self.wal), "--source", "auto", "--dry-run", "--note", "orphan decision")
        self.assertEqual(rc, 2, plan)
        self.assertEqual(plan.get("code"), "no_source")


if __name__ == "__main__":
    unittest.main()
