"""GoodQA #15565 (never-drop slice 3): merged-not-deployed and open-PENDING alarms in ops_watch."""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

HOOKS = Path(__file__).resolve().parents[1] / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
import ops_watch as ow  # noqa: E402

NOW = 1_800_000_000.0
HEAD, OLD = "74ea04c1" + "0" * 32, "7ce758b8" + "0" * 32


def iso(ts):
    return ow.now_iso(ts)


class Case(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name)
        (self.home / "repo").mkdir()
        self.cfg = dict(ow.load_config(self.home), _home=str(self.home))
        self.cfg["deploys"] = dict(self.cfg["deploys"], services=[
            {"name": "solver", "repo": "~/repo", "ref": "origin/main", "deployed_file": "~/deployed.json"}])
        self.commits = [NOW - 5 * 3600, NOW - 3 * 3600, NOW - 600]  # oldest first: three merged since the deploy
        self.deployed_ahead = False
        self.head_ok = True

    def runner(self, argv, timeout, env=None):
        if "rev-parse" in argv:
            return (0, HEAD + "\n") if self.head_ok else (128, "")
        if "log" in argv:
            return 0, "\n".join(str(int(t)) for t in self.commits) + "\n"
        if "merge-base" in argv:
            return (0 if self.deployed_ahead else 1), ""
        return 1, ""

    def deployed(self, sha=OLD):
        (self.home / "deployed.json").write_text(json.dumps({"sha": sha}))

    def run_check(self):
        return ow.check_deploys(self.cfg, {}, self.runner, NOW)

    def wal(self, session, rows):
        d = self.home / ".claude" / "wals" / session
        d.mkdir(parents=True, exist_ok=True)
        with open(d / "main.jsonl", "a") as handle:
            for row in rows:
                handle.write(json.dumps(row) + "\n")
        os.utime(d / "main.jsonl", (NOW, NOW))  # the check runs on the fixture clock


class MergedNotDeployed(Case):
    def test_commits_merged_but_not_deployed_for_over_two_hours_alarm(self):
        self.deployed()
        got = self.run_check()
        self.assertEqual([a["key"] for a in got], ["deploy-drift:solver"])
        self.assertIn("3 merged commit(s) not deployed, oldest 5h old", got[0]["message"])
        self.assertIn("7ce758b8", got[0]["message"])

    def test_a_deploy_at_head_or_a_young_merge_is_quiet(self):
        self.deployed(HEAD)
        self.assertEqual(self.run_check(), [])
        self.deployed()
        self.commits = [NOW - 600]
        self.assertEqual(self.run_check(), [])

    def test_no_deploy_record_or_a_foreign_sha_is_reported_not_trusted(self):
        got = self.run_check()
        self.assertIn("no readable deploy record", got[0]["message"])
        (self.home / "deployed.json").write_text("not json")
        self.assertIn("no readable deploy record", self.run_check()[0]["message"])
        self.deployed()
        self.commits = []  # git finds nothing between the shas: not an ancestor
        self.assertIn("have diverged", self.run_check()[0]["message"])
        self.deployed_ahead = True  # a hotfix deployed ahead of the ref is not merged-not-deployed
        self.assertEqual(self.run_check(), [])
        self.deployed_ahead = False
        self.head_ok = False
        self.assertIn("cannot resolve", self.run_check()[0]["message"])

    def test_the_check_is_registered_and_can_be_switched_off(self):
        self.assertIn("deploys", ow.DEFAULT_CHECKS)
        self.cfg["deploys"]["enabled"] = False
        self.assertEqual(ow.DEFAULT_CHECKS["deploys"](self.cfg, {}, self.runner, NOW), [])


class OpenPending(Case):
    def setUp(self):
        super().setUp()
        self.cfg["deploys"] = dict(self.cfg["deploys"], services=[])  # only the pending rule is under test here

    def test_a_pending_id_older_than_six_hours_with_no_test_alarms_per_session(self):
        self.wal("sess-aaaa-1111", [
            {"at": iso(NOW - 7 * 3600), "event": "check", "note": "PENDING_REAL_TEST solve-live-screen: live call works"},
            {"at": iso(NOW - 8 * 3600), "event": "check", "note": "PENDING_REAL_TEST done-one: x"},
            {"at": iso(NOW - 3600), "event": "check", "note": "REALLY_TESTED done-one: ran it live, ok"},
            {"at": iso(NOW - 3600), "event": "check", "note": "PENDING_REAL_TEST too-young: y"}])
        got = self.run_check()
        self.assertEqual([a["key"] for a in got], ["pending-open:sess-aaa"])
        self.assertIn("solve-live-screen", got[0]["message"])
        self.assertNotIn("done-one", got[0]["message"])
        self.assertNotIn("too-young", got[0]["message"])

    def test_a_pending_raised_again_after_a_test_is_open_again(self):
        # red-team a5 A1: a behavior change invalidates the earlier live test
        self.wal("sess-dddd-4444", [
            {"at": iso(NOW - 20 * 3600), "event": "check", "note": "PENDING_REAL_TEST t1: x"},
            {"at": iso(NOW - 19 * 3600), "event": "check", "note": "REALLY_TESTED t1: live ok"},
            {"at": iso(NOW - 10 * 3600), "event": "check", "note": "PENDING_REAL_TEST t1: behavior changed, retest"}])
        self.assertEqual([a["key"] for a in self.run_check()], ["pending-open:sess-ddd"])
        self.wal("sess-dddd-4444", [{"at": iso(NOW - 1 * 3600), "event": "check", "note": "REALLY_TESTED t1: retested"}])
        self.assertEqual(self.run_check(), [])

    def test_restating_a_pending_in_a_recap_does_not_restart_its_clock(self):
        # red-team ad4294 N1: an id open for 20 h and mentioned again 1 h ago is still open for 20 h
        self.wal("sess-ffff-6666", [
            {"at": iso(NOW - 20 * 3600), "event": "check", "note": "PENDING_REAL_TEST t1: x"},
            {"at": iso(NOW - 1 * 3600), "event": "status", "note": "PENDING_REAL_TEST t1: x (restated in the recap)"}])
        self.assertEqual([a["key"] for a in self.run_check()], ["pending-open:sess-fff"])
        self.wal("sess-ffff-6666", [{"at": iso(NOW - 30 * 60), "event": "check", "note": "REALLY_TESTED t1: ok"},
                                    {"at": iso(NOW - 10 * 60), "event": "check", "note": "PENDING_REAL_TEST t1: changed"}])
        self.assertEqual(self.run_check(), [])  # re-opened after a test: young again

    def test_an_unreadable_wal_is_reported_not_skipped_so_a_real_alarm_cannot_clear(self):
        # red-team a5 A2 and A3: oversize, FIFO and symlinked logs
        self.wal("sess-eeee-5555", [{"at": iso(NOW - 9 * 3600), "event": "check", "note": "PENDING_REAL_TEST t9: y"}])
        d = self.home / ".claude" / "wals" / "sess-eeee-5555"
        self.assertEqual([a["key"] for a in self.run_check()], ["pending-open:sess-eee"])
        with mock.patch.object(ow, "MAX_DEPLOY_WAL_BYTES", 10):  # now every log is "over the cap"
            keys = [a["key"] for a in self.run_check()]
        self.assertEqual(keys, ["pending-unscanned:sess-eee"])
        os.mkfifo(d / "fifo.jsonl")
        os.symlink("/dev/zero", d / "zero.jsonl")
        for name in ("main.jsonl", "fifo.jsonl", "zero.jsonl"):
            os.utime(d / name, (NOW, NOW), follow_symlinks=False)  # inside the lookback on the fixture clock
        got = self.run_check()  # returns at once: neither the FIFO nor /dev/zero is read
        keys = sorted(a["key"] for a in got)
        self.assertEqual(keys, ["pending-open:sess-eee", "pending-unscanned:sess-eee"])

    def test_a_tested_id_in_another_session_does_not_close_it_and_a_clean_session_is_quiet(self):
        self.wal("sess-bbbb-2222", [{"at": iso(NOW - 9 * 3600), "event": "check", "note": "PENDING_REAL_TEST t1: z"}])
        self.wal("sess-cccc-3333", [{"at": iso(NOW - 2 * 3600), "event": "check", "note": "REALLY_TESTED t1: unrelated"}])
        self.assertEqual([a["key"] for a in self.run_check()], ["pending-open:sess-bbb"])


if __name__ == "__main__":
    unittest.main()
