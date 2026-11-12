"""`ah goals` (GoodQA goodqa#15754, status-truth P0-1): per-goal status from the mission ledger, evidence of any age.

Evidence: on 2026-11-12 main answered "whats left" from `ah status --since 24h`; the live proofs of prod move
(w16dc0f5dd6b, 11-10), leads (w53ff16565a1, 11-09) and self-update (wa6c1d52d985, 11-09) were older than the window, so
main said those goals were not done. The user replied "seems incorrect". On main 4f9f4a39 there is no `ah goals`, no
goals_view.py and no `attach`, so every test here fails there (ImportError / unknown command).
"""
import contextlib
import io
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
HOOKS = ROOT / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
import ah  # noqa: E402
import goals_view as gv  # noqa: E402
import mission_coverage as mc  # noqa: E402

NOW = time.time()
SESSION = "11111111-2222-4333-8444-555555555555"
DAY = 86400


def iso(ts):
    return time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime(ts))


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name)
        env = mock.patch.dict(os.environ, {"AH_HOME": str(self.home), "HOME": str(self.home),
                                           "CLAUDE_CONFIG_DIR": str(self.home / ".claude")})
        env.start()
        self.addCleanup(env.stop)
        for k in ("CLAUDE_CODE_SESSION_ID", "CLAUDE_SESSION_ID"):
            os.environ.pop(k, None)
        self.wal = self.home / ".claude" / "wals" / SESSION
        self.wal.mkdir(parents=True)
        self.jl("main.jsonl", [{"at": iso(NOW - 60), "event": "prompt", "prompt_chars": 10}])
        # the prod-move owner's proof is 4 days old; the leads owner's WAL names its ticket
        self.jl("agent-a2bba6cd11ecec416.jsonl", [
            {"at": iso(NOW - 4 * DAY - 60), "event": "intent", "note": "dev2 retirement, goodqa#14518"},
            {"at": iso(NOW - 4 * DAY), "event": "check", "id": "w16dc0f5dd6b",
             "note": "REALLY_TESTED dev2-powered-off: qm status 100 stopped; t2 services healthy"}])
        self.jl("agent-a6d28999ce9ba1787.jsonl", [
            {"at": iso(NOW - 3 * DAY - 60), "event": "intent", "note": "leads stream goodqa#15533"},
            {"at": iso(NOW - 3 * DAY), "event": "result", "id": "w53ff16565a1",
             "note": "REALLY_TESTED crm-count-and-provenance: people total 1416; saved view 1415; desktop-browser 22"},
            {"at": iso(NOW - 3 * DAY + 60), "event": "result", "id": "wfa11ed00001",
             "note": "REALLY_TESTED leads-batch-5: FAILED, tab_not_found on 3 of 5"},
            {"at": iso(NOW - 3 * DAY + 90), "event": "status", "id": "wstatus00001", "note": "leads batch done"}])
        self.jl("agent-aunrelated000000001.jsonl", [
            {"at": iso(NOW - 3600), "event": "check", "id": "w0000000beef",
             "note": "REALLY_TESTED something-else: unrelated stream goodqa#99999"}])

    def jl(self, name, rows):
        with open(self.wal / name, "a") as fh:
            for r in rows:
                fh.write(json.dumps(r) + "\n")

    def as_main(self, argv):
        import caller_identity  # noqa: PLC0415
        """main's PreToolUse hook stamps exactly this argv; the next mc.main(argv) claims it."""
        caller_identity.put_stamp("mission-main", [argv[0], mc.argv_key(argv)], session=SESSION, home=self.home)
        self.addCleanup(mc._PROOF.clear)

    def cli(self, mod, argv):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
            try:
                rc = mod.main(list(argv))
            except SystemExit as stop:
                rc = stop.code if isinstance(stop.code, int) else 2
        return rc, out.getvalue()

    def seed(self):
        for gid, title, ticket in (("prod-move", "Prod move", "goodqa#14518"), ("leads", "1000 leads", "goodqa#15533"),
                                   ("self-update", "Self update", ""), ("user-tokens", "User tokens", "goodqa#15638"),
                                   ("harness-asks", "All the harness asks", ""), ("parentproof", "ParentProof", "")):
            mc.add_goal(self.home, gid, title, ticket)


class AhGoals(Base):
    def test_old_proof_is_invisible_to_status_24h_and_visible_to_goals(self):
        """The failing-first case: the only proof is 4 days old."""
        self.seed()
        status = ah.status_report(self.home, SESSION, ah.parse_since("24h"), now=NOW)
        self.assertNotIn("dev2-powered-off", [v["check"] for v in status["verified"]])
        argv = ["attach", "--goal", "prod-move", "--evidence", "w16dc0f5dd6b", "--kind", "live_test",
                "--session", SESSION]
        self.as_main(argv)
        self.assertEqual(self.cli(mc, argv)[0], 0)
        doc = gv.goals_report(self.home, now=NOW, session=SESSION, owner_rows=[])
        g = {x["id"]: x for x in doc["goals"]}
        self.assertEqual(g["prod-move"]["state"], "DONE_LIVE")
        self.assertEqual(g["prod-move"]["evidence"][0]["id"], "w16dc0f5dd6b")
        self.assertIn("w16dc0f5dd6b", gv.goals_text(doc))

    def test_no_evidence_is_unknown_never_not_started(self):
        self.seed()
        doc = gv.goals_report(self.home, now=NOW, session=SESSION, owner_rows=[])
        states = {x["id"]: x["state"] for x in doc["goals"]}
        self.assertEqual(set(states.values()), {"UNKNOWN"})
        self.assertNotIn("not started", gv.goals_text(doc).lower().replace("never 'not started'", ""))

    def test_live_owner_without_proof_is_in_progress(self):
        self.seed()
        rows = [{"agent_id": "a6d28999ce9ba1787", "type": "task-owner", "ticket": "GoodQA #15533", "state": "live",
                 "owner": True}]
        doc = gv.goals_report(self.home, now=NOW, session=SESSION, owner_rows=rows)
        self.assertEqual({x["id"]: x["state"] for x in doc["goals"]}["leads"], "IN_PROGRESS")

    def test_attached_fail_row_never_counts(self):
        self.seed()
        for wid, kind in (("w53ff16565a1", "live_test"), ("wfa11ed00001", "live_test")):
            self.assertEqual(self.cli(mc, ["attach", "--goal", "leads", "--evidence", wid, "--kind", kind,
                                           "--session", SESSION])[0], 0)  # the leads WAL names goodqa#15533
        doc = gv.goals_report(self.home, now=NOW, session=SESSION, owner_rows=[])
        leads = {x["id"]: x for x in doc["goals"]}["leads"]
        self.assertEqual(leads["state"], "FAILING")  # the newest test failed: not done
        self.assertEqual([e["verdict"] for e in leads["evidence"]], ["FAIL", "UNSTATED"])

    def test_owner_cannot_attach_from_a_wal_that_does_not_name_the_goal(self):
        self.seed()
        rc, out = self.cli(mc, ["attach", "--goal", "leads", "--evidence", "w0000000beef", "--session", SESSION])
        self.assertEqual(rc, 2)
        self.assertIn("never names goal leads", out)
        rc, out = self.cli(mc, ["attach", "--goal", "leads", "--evidence", "wstatus00001", "--session", SESSION])
        self.assertEqual(rc, 2)  # a narrative status row is not evidence
        rc, out = self.cli(mc, ["attach", "--goal", "leads", "--evidence", "w999999999ab", "--session", SESSION])
        self.assertEqual(rc, 2)  # an id that does not exist
        rc, out = self.cli(mc, ["attach", "--goal", "leads", "--evidence", "w53ff16565a1", "--remove",
                                "--session", SESSION])
        self.assertEqual(rc, 2)  # detaching is main-only

    def test_tagged_row_counts_without_attach(self):
        self.seed()
        self.jl("agent-aunrelated000000001.jsonl", [
            {"at": iso(NOW - 5 * DAY), "event": "check", "id": "w5e1f0000001", "goal": "self-update", "live": True,
             "result": "PASS", "note": "REALLY_TESTED mini-self-update: app updated itself to 0.2.57"}])
        doc = gv.goals_report(self.home, now=NOW, session=SESSION, owner_rows=[])
        g = {x["id"]: x for x in doc["goals"]}["self-update"]
        self.assertEqual((g["state"], g["evidence"][0]["id"], g["evidence"][0]["by"]),
                         ("DONE_LIVE", "w5e1f0000001", "tag"))

    def test_deploy_after_live_test_is_live_untested(self):
        self.seed()
        self.jl("agent-aunrelated000000001.jsonl", [
            {"at": iso(NOW - 2 * DAY), "event": "check", "id": "w5e1f0000002", "goal": "parentproof", "live": True,
             "result": "PASS", "note": "REALLY_TESTED pp-live: sign-in works on prod abc1234"},
            {"at": iso(NOW - DAY), "event": "deploy", "id": "wde9104000001", "goal": "parentproof",
             "note": "deployed def5678 to prod"}])
        doc = gv.goals_report(self.home, now=NOW, session=SESSION, owner_rows=[])
        self.assertEqual({x["id"]: x["state"] for x in doc["goals"]}["parentproof"], "LIVE_UNTESTED")

    def test_main_may_attach_from_any_wal(self):
        self.seed()
        argv = ["attach", "--goal", "leads", "--evidence", "w0000000beef", "--session", SESSION]
        self.as_main(argv)
        rc, out = self.cli(mc, argv)
        self.assertEqual(rc, 0, out)
        ev = {x["id"]: x for x in mc.load_goals(self.home)["goals"]}["leads"]["evidence"]
        self.assertEqual((ev[0]["id"], ev[0]["by"], ev[0]["kind"]), ("w0000000beef", "main", "test"))

    def test_as_of_hides_later_evidence(self):
        self.seed()
        argv = ["attach", "--goal", "prod-move", "--evidence", "w16dc0f5dd6b", "--kind", "live_test",
                "--session", SESSION]
        self.as_main(argv)
        self.cli(mc, argv)
        doc = gv.goals_report(self.home, now=NOW, as_of=NOW - 5 * DAY, session=SESSION, owner_rows=[])
        self.assertEqual({x["id"]: x["state"] for x in doc["goals"]}["prod-move"], "UNKNOWN")

    def test_missing_or_tampered_ledger_exits_nonzero(self):
        rc, out = self.cli(ah, ["goals", "--session", SESSION])
        self.assertEqual(rc, 2)
        self.assertIn("GOALS UNAVAILABLE (absent)", out)
        self.seed()
        self.assertEqual(self.cli(ah, ["goals", "--session", SESSION])[0], 0)
        path = mc.goals_path(self.home)
        doc = json.loads(path.read_text())
        doc["goals"][0]["status"] = "retired"
        path.write_text(json.dumps(doc))
        rc, out = self.cli(ah, ["goals", "--session", SESSION])
        self.assertEqual(rc, 2)
        self.assertIn("tampered", out)

    def test_text_is_capped_at_4kb(self):
        self.seed()
        for i in range(40):
            mc.add_goal(self.home, f"extra-{i}", "x" * 290, "")
            self.jl("agent-aunrelated000000001.jsonl", [
                {"at": iso(NOW - i * 60), "event": "check", "id": f"w{i:011x}", "goal": f"extra-{i}",
                 "note": "REALLY_TESTED t: " + "y" * 3000}])
        text = gv.goals_text(gv.goals_report(self.home, now=NOW, session=SESSION, owner_rows=[]))
        self.assertLessEqual(len(text.encode()), 4096)

    def test_verify_ok_with_six_goals(self):
        self.seed()
        self.assertTrue(mc.verify_audit(self.home)["ok"])
        self.assertEqual(len(mc.load_goals(self.home)["goals"]), 6)


class Target(Base):
    def test_target_needs_main_and_a_user_source(self):
        self.seed()
        rc, out = self.cli(mc, ["set", "--goal", "leads", "--target", "1000 leads", "--target-source", "user:x/y \"z\""])
        self.assertEqual(rc, 2)
        self.assertIn("main-only", out)
        argv = ["set", "--goal", "leads", "--target", "50 leads", "--target-source", "inferred: owner judgement"]
        self.as_main(argv)
        rc, out = self.cli(mc, argv)
        self.assertEqual(rc, 2)
        self.assertIn("user's own words", out)
        with mock.patch.object(mc, "verify_user_source", return_value=True):
            argv = ["set", "--goal", "leads", "--target", "1000 leads in the CRM view", "--target-source",
                    "user:" + SESSION + "/aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee \"1000 leads\"", "--alias", "leads",
                    "--alias", "crm"]
            self.as_main(argv)
            rc, out = self.cli(mc, argv)
        self.assertEqual(rc, 0, out)
        g = {x["id"]: x for x in mc.load_goals(self.home)["goals"]}["leads"]
        self.assertEqual((g["target"]["text"], g["aliases"]), ("1000 leads in the CRM view", ["leads", "crm"]))

    def test_aliases_are_main_only(self):
        self.seed()
        rc, out = self.cli(mc, ["set", "--goal", "leads", "--alias", "zzz"])
        self.assertEqual(rc, 2)


class Verdicts(unittest.TestCase):
    def test_verdicts(self):
        self.assertEqual(gv.verdict({"event": "check", "note": "REALLY_TESTED x PASS: ok"}), "PASS")
        self.assertEqual(gv.verdict({"event": "check", "note": "REALLY_TESTED x: FAIL rc=1"}), "FAIL")
        self.assertEqual(gv.verdict({"event": "check", "note": "REALLY_TESTED x: ok", "result": "FAIL"}), "FAIL")
        self.assertEqual(gv.verdict({"event": "check", "note": "REALLY_TESTED x: code only, NOT installed"}), "FAIL")
        self.assertEqual(gv.verdict({"event": "check", "note": "REALLY_TESTED x: FALSIFIED by y"}), "FAIL")
        self.assertEqual(gv.verdict({"event": "check", "note": "REALLY_TESTED x: 12 passed, 0 failed"}), "UNSTATED")
        self.assertEqual(gv.verdict({"event": "deploy", "note": "deployed"}), "DEPLOY")
        self.assertEqual(gv.verdict({"event": "status", "note": "deployed to prod, done"}), "")


if __name__ == "__main__":
    unittest.main()
