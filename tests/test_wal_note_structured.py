"""Structured evidence (GoodQA goodqa#15754, P1-5): wal_note --goal/--ticket/--result/--live and a deploy event;
`ah status` keeps FAIL rows out of VERIFIED and takes LIVE from deploy records only.

Evidence: 14 of 296 VERIFIED rows in 96 h were FAIL, FALSIFIED or "code only, NOT installed" (s5b2-live-controls,
pa-email-signin, df1-merged); LIVE was a prose regex, so a "review ... BLOCK" note sat in LIVE; no WAL row was a deploy
event. On main 4f9f4a39 wal_note rejects --goal and `--event deploy`, and `ah status` lists "REALLY_TESTED x: FAIL rc=1"
under verified, so these tests fail there.
"""
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
import ah  # noqa: E402
import goals_view as gv  # noqa: E402

NOW = 1_800_000_000.0
SESSION = "sess-structured-01"


def iso(ts):
    return time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime(ts))


class WalNote(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name)
        self.wal = self.home / ".claude" / "wals" / SESSION / "agent-aowner.jsonl"
        self.wal.parent.mkdir(parents=True)

    def note(self, *args):
        env = dict(os.environ, HOME=str(self.home))
        return subprocess.run([sys.executable, str(HOOKS / "wal_note.py"), "--wal", str(self.wal), *args],
                              capture_output=True, text=True, env=env, timeout=60)

    def rows(self):
        return [json.loads(x) for x in self.wal.read_text().splitlines()]

    def test_structured_fields_land_and_goals_view_reads_them(self):
        r = self.note("--event", "check", "--note", "REALLY_TESTED pp-live: sign-in on prod abc1234", "--goal",
                      "parentproof", "--ticket", "goodqa#615", "--result", "PASS", "--live")
        self.assertEqual(r.returncode, 0, r.stderr)
        row = self.rows()[-1]
        self.assertEqual((row["goal"], row["ticket"], row["result"], row["live"]),
                         ("parentproof", "goodqa#615", "PASS", True))
        self.assertEqual(gv.verdict(row), "PASS")

    def test_deploy_event_needs_a_sha_or_version(self):
        self.assertNotEqual(self.note("--event", "deploy", "--note", "deployed to prod").returncode, 0)
        r = self.note("--event", "deploy", "--note", "deployed def5678 to prod", "--goal", "parentproof")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(gv.verdict(self.rows()[-1]), "DEPLOY")

    def test_bad_values_are_refused(self):
        self.assertNotEqual(self.note("--event", "check", "--note", "REALLY_TESTED x: ok", "--goal", "Bad Goal!")
                            .returncode, 0)
        self.assertNotEqual(self.note("--event", "status", "--note", "all good", "--result", "PASS").returncode, 0)
        self.assertNotEqual(self.note("--event", "status", "--note", "all good", "--live").returncode, 0)
        self.assertNotEqual(self.note("--event", "check", "--note", "REALLY_TESTED x: ok", "--ticket", "nope")
                            .returncode, 0)


class Status(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name)
        p = mock.patch.dict(os.environ, {"AH_HOME": str(self.home), "HOME": str(self.home)})
        p.start()
        self.addCleanup(p.stop)
        w = self.home / ".claude" / "wals" / SESSION
        w.mkdir(parents=True)
        (w / "main.jsonl").write_text("")
        rows = [
            {"at": iso(NOW - 900), "event": "check", "note": "REALLY_TESTED s5b2-live-controls: FAIL rc=1"},
            {"at": iso(NOW - 800), "event": "check", "note": "REALLY_TESTED df1-merged: code only, NOT installed"},
            {"at": iso(NOW - 700), "event": "check", "note": "REALLY_TESTED pp-615 PASS: device flow on prod a67ab74f"},
            {"at": iso(NOW - 600), "event": "check", "note": "REALLY_TESTED legacy-ok: 12 passed on a67ab74f"},
            {"at": iso(NOW - 500), "event": "deploy", "note": "deployed a67ab74f to prod"},
            {"at": iso(NOW - 400), "event": "status", "note": "blog worker ae83610c deployed to prod"},
            {"at": iso(NOW - 300), "event": "status", "note": "review of ae83610c: BLOCK; LIVE gate not met"}]
        (w / "agent-aowner.jsonl").write_text("\n".join(json.dumps(r) for r in rows) + "\n")

    def test_fail_rows_leave_verified_and_live_comes_from_deploy_records(self):
        r = ah.status_report(self.home, SESSION, 3600, now=NOW)
        self.assertEqual([v["check"] for v in r["verified"]], ["pp-615", "legacy-ok"])
        self.assertEqual([v["verdict"] for v in r["verified"]], ["PASS", "UNSTATED"])  # legacy kept, labelled
        self.assertEqual([f["check"] for f in r["failed"]], ["s5b2-live-controls", "df1-merged"])
        self.assertEqual([(e["note"][:8], e["label"]) for e in r["live"]], [("deployed", "DONE_LIVE")])
        legacy = [e["note"] for e in r["live_legacy"]]
        self.assertIn("blog worker ae83610c deployed to prod", legacy)  # prose: never LIVE
        self.assertTrue(all(e["label"].startswith("LEGACY_") for e in r["live_legacy"]))
        self.assertIn("FAILED", ah.status_text(r))


if __name__ == "__main__":
    unittest.main()
