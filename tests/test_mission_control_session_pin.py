"""goodqa#15961: Mission Control follows the main Claude session on purpose, never the newest WAL or a Codex session.
Plan: work dir agent-a6e0ddd4ba7a7e425/plans/plan-15961-session-pin.md (Revision 1 + 2)."""
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "tests"))
sys.path.insert(0, str(REPO / "harness" / "hooks"))
sys.path.insert(0, str(REPO / "harness" / "mission_control"))
os.environ.setdefault("MC_HOOKS", str(REPO / "harness" / "hooks"))

import collectors as col  # noqa: E402
import events as ev  # noqa: E402
import session_pin as sp  # noqa: E402

MAIN = "baab765b-d85c-46b4-b7b9-588eb912c770"
OTHER = "d48ace33-0000-4000-8000-000000000001"     # a newer Claude session
CODEX = "01a1d873-d7c9-7752-83a9-b10a1cb85371"     # a Codex session (codex-wals only)


class Home:
    """A disposable HOME with both WAL roots; mtimes set so the Codex WAL is newest, then OTHER, then MAIN."""

    def __init__(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="mc-pin-")
        self.home = Path(self.tmp.name)
        self.claude = self.home / ".claude" / "wals"
        self.codex = self.home / ".agent-harness" / "codex-wals"
        now = time.time()
        for root, sid, age in ((self.claude, MAIN, 300), (self.claude, OTHER, 60), (self.codex, CODEX, 1)):
            (root / sid).mkdir(parents=True)
            main = root / sid / "main.jsonl"
            main.write_text("{}\n")
            os.utime(main, (now - age, now - age))


class Resolve(unittest.TestCase):
    def setUp(self):
        self.h = Home()
        self.addCleanup(self.h.tmp.cleanup)

    def test_old_rule_picks_codex_new_rule_picks_the_ledger_session(self):  # AC-1, AC-2, R9 (not vacuous)
        import ah  # the repo copy's newest_session: the behaviour this replaces
        self.assertEqual(ah.newest_session(self.h.home), CODEX)
        pin = sp.resolve(config_pin=None, ledger={"state": "ok", "mission_session": MAIN}, wals_root=self.h.claude)
        self.assertEqual((pin["display"], pin["write"], pin["source"]), (MAIN, MAIN, "ledger"))

    def test_no_ledger_never_guesses_the_newest_claude_session(self):  # R1 / F1
        pin = sp.resolve(config_pin=None, ledger=None, wals_root=self.h.claude)
        self.assertEqual((pin["display"], pin["write"], pin["write_error"]), ("", "", "unpinned"))

    def test_config_pin_wins_and_writes_when_it_agrees_or_stands_alone(self):  # AC-3
        alone = sp.resolve(config_pin=OTHER, ledger={"state": "error"}, wals_root=self.h.claude)
        self.assertEqual((alone["display"], alone["write"]), (OTHER, OTHER))
        agree = sp.resolve(config_pin=MAIN, ledger={"state": "ok", "mission_session": MAIN}, wals_root=self.h.claude)
        self.assertEqual((agree["write"], agree["warnings"]), (MAIN, []))

    def test_config_pin_that_differs_from_an_ok_ledger_refuses_writes(self):  # NEG-8 (D2)
        pin = sp.resolve(config_pin=OTHER, ledger={"state": "ok", "mission_session": MAIN}, wals_root=self.h.claude)
        self.assertEqual((pin["display"], pin["write"], pin["write_error"]), (OTHER, "", "pin_mismatch"))
        self.assertTrue(pin["warnings"])

    def test_codex_or_malformed_pins_are_refused(self):  # NEG-2, R4, R5/NEG-6
        for bad in (CODEX, "../etc", "BAAB765B-D85C-46B4-B7B9-588EB912C770", "x" * 36, 5):
            with self.subTest(bad=bad):
                pin = sp.resolve(config_pin=bad, ledger=None, wals_root=self.h.claude)
                self.assertEqual(pin["display"], "")
        ledger_codex = sp.resolve(config_pin=None, ledger={"state": "ok", "mission_session": CODEX},
                                  wals_root=self.h.claude)
        self.assertEqual(ledger_codex["display"], "")
        self.assertTrue(any("not a Claude session" in w for w in ledger_codex["warnings"]))

    def test_a_codex_session_with_a_claude_wal_dir_is_refused(self):  # review A-4: seen twice on the real Mac
        (self.h.claude / CODEX).mkdir()
        (self.h.claude / CODEX / "main.jsonl").write_text("{}\n")
        self.assertFalse(sp.claude_session_ok(CODEX, self.h.claude))
        pin = sp.resolve(config_pin=None, ledger={"state": "ok", "mission_session": CODEX}, wals_root=self.h.claude)
        self.assertEqual((pin["display"], pin["write"]), ("", ""))
        self.assertTrue(sp.claude_session_ok(MAIN, self.h.claude))

    def test_symlinked_session_or_main_wal_is_refused(self):  # NEG-1
        target = self.h.home / "elsewhere"
        target.mkdir()
        (target / "main.jsonl").write_text("{}\n")
        link = "aaaaaaaa-0000-4000-8000-000000000002"
        os.symlink(target, self.h.claude / link)
        self.assertFalse(sp.claude_session_ok(link, self.h.claude))
        real = "aaaaaaaa-0000-4000-8000-000000000003"
        (self.h.claude / real).mkdir()
        os.symlink(target / "main.jsonl", self.h.claude / real / "main.jsonl")
        self.assertFalse(sp.claude_session_ok(real, self.h.claude))

    def test_tampered_or_failed_ledger_keeps_the_last_pin_for_display_only(self):  # NEG-4, R2, D1
        for state in ("tampered", "error", "absent"):
            with self.subTest(state=state):
                pin = sp.resolve(config_pin=None, ledger={"state": state, "mission_session": MAIN},
                                 wals_root=self.h.claude, last_good=MAIN)
                self.assertEqual((pin["display"], pin["write"], pin["source"]), (MAIN, "", "kept"))

    def test_write_check_needs_a_writable_pin_and_the_session_the_page_showed(self):  # R6 / NEG-7
        ok = {"display": MAIN, "write": MAIN}
        self.assertIsNone(sp.write_check(ok, MAIN))
        self.assertEqual(sp.write_check(ok, OTHER)[1]["error"], "session_changed")   # pin moved since render
        self.assertEqual(sp.write_check(ok, None)[1]["error"], "session_changed")    # an old page sends none
        self.assertEqual(sp.write_check({"display": MAIN, "write": "", "write_error": "unpinned"}, MAIN)[0], 409)


class Wiring(unittest.TestCase):
    """The server uses the pin: `ah owners --session <pin>`, the ledger's mission_session, no fallback."""

    def setUp(self):
        self.h = Home()
        self.addCleanup(self.h.tmp.cleanup)
        patcher = mock.patch.dict(os.environ, {"MC_HOME": str(self.h.home / "mc")})
        patcher.start()
        self.addCleanup(patcher.stop)

    def app(self, goals, session=None):
        import server as mcs
        from test_mission_control import FakeRunner
        calls = []

        def owners(*args):
            calls.append(args)
            return 0, json.dumps({"session": args[0] if args else CODEX, "owners": []})
        runner = FakeRunner({"ah-goals": (0, json.dumps(goals)), "ah-owners": owners})
        (self.h.home / "mc").mkdir(exist_ok=True)
        app = mcs.App(port=47999, root=self.h.home / "mc", initiatives=None, remote=False, fabric_bin=None,
                      runner=runner, wal_roots=[(self.h.home / "nowals", "claude")], start_threads=False,
                      session=session, wals_root=self.h.claude)
        return app, calls

    def test_owners_reads_the_ledger_session_even_when_codex_wrote_last(self):  # AC-4
        app, calls = self.app({"state": "ok", "mission_session": MAIN, "goals": []})
        app.owners.run(time.time())
        self.assertEqual(app.health.rows["owners"]["status"], "error", "unpinned before the ledger is read")
        self.assertEqual(calls, [])
        app.ledger.run(time.time())
        app.owners.run(time.time())
        self.assertEqual(calls, [(MAIN,)])
        self.assertEqual(app.owners.session, MAIN)
        state = app.state()
        self.assertEqual((state["pin"]["display"], state["pin"]["source"], state["pin"]["writable"]),
                         (MAIN, "ledger", True))   # AC-5

    def test_a_failed_goals_read_drops_write_rights(self):  # D1
        app, _ = self.app({"state": "ok", "mission_session": MAIN, "goals": []})
        app.ledger.run(time.time())
        self.assertTrue(app.pin()["write"])
        app.runner.outputs["ah-goals"] = (1, "")
        app.ledger.run(time.time())
        pin = app.pin()
        self.assertEqual((pin["display"], pin["write"], pin["source"]), (MAIN, "", "kept"))

    def test_flag_pin_is_used_and_a_mismatch_is_flagged(self):  # AC-3, NEG-8
        app, calls = self.app({"state": "ok", "mission_session": MAIN, "goals": []}, session=OTHER)
        app.ledger.run(time.time())
        app.owners.run(time.time())
        self.assertEqual(calls, [(OTHER,)])
        self.assertEqual(app.pin()["write_error"], "pin_mismatch")
        self.assertEqual(app.health.rows["session-pin"]["status"], "error")


    # review A-1 (red-team of 85fe28f2): the requirement list must be the pinned session's, never a lagging read's
    def _reqs(self, app):
        app.runner.outputs["ah-requirements"] = lambda s: (0, json.dumps({"requirements": [
            {"id": "w" + s[:11].replace("-", "0"), "session": s, "text": "req of " + s, "at": "2026-11-13T00:00:00Z"}]}))
        app.runner.outputs["ah-status"] = (0, "{}")

    def _archive(self, app, item, shown):
        return app.post_requirement({"req_id": item["id"], "action": "archive", "reason": "done",
                                     "digest": item["digest"], "client_key": "k" * 12, "session": shown})

    def test_the_ledger_rereads_for_the_new_pin_in_the_same_tick(self):
        goals = {"state": "ok", "mission_session": MAIN, "goals": []}
        app, _ = self.app(goals)
        self._reqs(app)
        app.ledger.run(time.time())
        self.assertEqual(app.ledger.parts["requirements"]["items"][0]["session"], MAIN)
        app.runner.outputs["ah-goals"] = (0, json.dumps(dict(goals, mission_session=OTHER)))
        app.ledger.next_at = 0
        app.ledger.run(time.time())      # the owners collector has not ticked: owners.session is still MAIN or empty
        item = app.ledger.parts["requirements"]["items"][0]
        self.assertEqual((app.pin()["write"], item["session"], app.ledger.read_session), (OTHER, OTHER, OTHER))
        status, _ = self._archive(app, item, OTHER)
        self.assertEqual(status, 201)
        self.assertEqual(app.actions.all()[-1]["session"], OTHER)

    def test_a_failed_read_for_the_new_pin_never_keeps_the_old_sessions_list(self):
        goals = {"state": "ok", "mission_session": MAIN, "goals": []}
        app, _ = self.app(goals)
        self._reqs(app)
        app.ledger.run(time.time())
        old = app.ledger.parts["requirements"]["items"][0]
        app.runner.outputs["ah-goals"] = (0, json.dumps(dict(goals, mission_session=OTHER)))
        app.runner.outputs["ah-requirements"] = (1, "")
        app.ledger.next_at = 0
        try:
            app.ledger.run(time.time())
        except RuntimeError:
            pass
        self.assertEqual(app.ledger.parts["requirements"]["items"], [])
        status, body = self._archive(app, old, OTHER)
        self.assertEqual((status, body["error"]), (409, "unknown-requirement"))
        self.assertEqual(app.actions.all(), [])

    def test_a_list_read_for_another_session_is_refused(self):
        goals = {"state": "ok", "mission_session": MAIN, "goals": []}
        app, _ = self.app(goals)
        self._reqs(app)
        app.ledger.run(time.time())
        item = app.ledger.parts["requirements"]["items"][0]
        app.runner.outputs["ah-goals"] = (0, json.dumps(dict(goals, mission_session=OTHER)))
        app.ledger._read("goals", "ah goals", "ah-goals", (), app.ledger._goals, time.time())  # pin moves, list not yet
        app.ledger.mission = {"state": "ok", "mission_session": OTHER}
        self.assertEqual((app.pin()["write"], app.ledger.read_session), (OTHER, MAIN))
        status, body = self._archive(app, item, OTHER)
        self.assertEqual((status, body["error"]), (409, "session_changed"))
        self.assertEqual(app.actions.all(), [])

if __name__ == "__main__":
    unittest.main()
