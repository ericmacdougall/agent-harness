"""Archive and restore of requirements (GoodQA goodqa#15920 AC-12, NEG-12..NEG-16): a signed, audited, reversible,
non-deleting write path behind an explicit click, with every unsourced or malformed request refused."""
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "tests"))
sys.path.insert(0, str(REPO / "harness" / "hooks"))
sys.path.insert(0, str(REPO / "harness" / "mission_control"))
os.environ.setdefault("MC_HOOKS", str(REPO / "harness" / "hooks"))

import archive  # noqa: E402
import mc_chat  # noqa: E402
import req_actions  # noqa: E402
from test_mission_control import ServerHarness  # noqa: E402
from test_mission_control_ledger import GOALS, REQS, STATUS, iso, SID  # noqa: E402

KEY = b"k" * 32


def acts(tmp):
    return req_actions.ReqActions(Path(tmp), KEY)


def rec(a, **kw):
    args = dict(session=SID, req="wr1", action="archive", reason="no longer wanted", digest="d" * 16, client_key="click-key-0001")
    args.update(kw)
    return a.record(**args)


class Log(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.a = acts(self.tmp.name)

    def test_a_click_is_one_signed_row_with_who_when_rule_why_and_source(self):
        row, created = rec(self.a)
        self.assertTrue(created)
        self.assertTrue(mc_chat.verified(row, KEY))
        self.assertEqual((row["origin"], row["rule"], row["action"], row["req"], row["session"]), ("dashboard", "manual", "archive", "wr1", SID))
        self.assertTrue(row["source"].startswith("mc:" + SID) and row["at"].endswith("Z") and row["reason"] == "no longer wanted")
        self.assertNotIn("user:", row["source"])  # a dashboard click is never the user's own words
        self.assertEqual(self.a.latest()["wr1"]["id"], row["id"])
        self.assertEqual(oct(os.stat(self.a.path).st_mode & 0o777), "0o600")

    def test_the_same_click_is_idempotent_and_a_reused_key_with_other_content_conflicts(self):
        first, _ = rec(self.a)
        again, created = rec(self.a)
        self.assertEqual((again["id"], created), (first["id"], False))
        self.assertEqual(len(self.a.all()), 1)
        with self.assertRaises(req_actions.ActionError) as ctx:
            rec(self.a, reason="something else")
        self.assertEqual(ctx.exception.code, "key-conflict")

    def test_unsourced_or_malformed_requests_are_refused_and_write_nothing(self):
        bad = [dict(reason=""), dict(reason="   "), dict(reason="x" * 301), dict(reason=None), dict(reason="a\x00b"),
               dict(client_key="short"), dict(client_key=None), dict(client_key="bad key with spaces!"),
               dict(action="delete"), dict(action=None), dict(req="../etc"), dict(req=""), dict(req=None), dict(session=""),
               dict(session="nope")]
        for kw in bad:
            with self.subTest(kw), self.assertRaises(req_actions.ActionError):
                rec(self.a, **kw)
        self.assertEqual(self.a.all(), [])

    def test_forged_rows_are_ignored(self):
        row, _ = rec(self.a)
        tampered = dict(row, reason="edited later", id="ra-forged")
        unsigned = {k: v for k, v in row.items() if k != "sig"}
        wrong_source = mc_chat.sign({**{k: v for k, v in row.items() if k != "sig"}, "id": "ra-x", "req": "wr9", "source": 'user:s/u "yes"'}, KEY)
        other_key = mc_chat.sign({**{k: v for k, v in row.items() if k != "sig"}, "id": "ra-y", "req": "wr8"}, b"z" * 32)
        with open(self.a.path, "a") as handle:
            for line in (tampered, unsigned, wrong_source, other_key):
                handle.write(json.dumps(line) + "\n")
            handle.write("not json\n{\n")
        self.a._cache = None
        self.assertEqual(list(self.a.latest()), ["wr1"])
        self.assertEqual(self.a.latest()["wr1"]["reason"], "no longer wanted")

    def test_latest_row_wins_and_the_log_only_grows(self):
        rec(self.a)
        size = os.stat(self.a.path).st_size
        rec(self.a, action="restore", reason="still needed", client_key="click-key-0002")
        self.assertEqual(self.a.latest()["wr1"]["action"], "restore")
        self.assertGreater(os.stat(self.a.path).st_size, size)
        self.assertEqual([r["action"] for r in self.a.all()], ["archive", "restore"])  # the audit trail keeps both

    def test_secrets_in_a_reason_are_redacted_before_they_are_stored(self):
        row, _ = rec(self.a, reason="because token=abcdef1234567890abcdef was leaked")
        self.assertNotIn("abcdef1234567890abcdef", json.dumps(row))

    def test_a_torn_last_line_does_not_swallow_the_next_click(self):
        rec(self.a)
        with open(self.a.path, "a") as handle:
            handle.write('{"v": 1, "id": "ra-torn", "act')  # a crash or a full disk cut the last write short
        self.a._cache = None
        row, created = rec(self.a, req="wr2", client_key="click-key-0002")
        self.assertTrue(created)
        self.a._cache = None
        self.assertEqual(self.a.latest()["wr2"]["id"], row["id"])
        self.assertIn("wr1", self.a.latest())
        again, created = rec(self.a, req="wr2", client_key="click-key-0002")
        self.assertEqual((again["id"], created), (row["id"], False))
        self.assertEqual(len(self.a.all()), 2)

    def test_f3_every_accepted_action_stays_readable_at_the_size_cap_and_a_full_log_refuses_cleanly(self):
        probe = acts(tempfile.mkdtemp())
        one_row, _ = rec(probe, req="w000", client_key="cap-key-0000")
        width = os.stat(probe.path).st_size
        old = req_actions.MAX_BYTES
        self.addCleanup(setattr, req_actions, "MAX_BYTES", old)
        req_actions.MAX_BYTES = 3 * width + 5  # three rows fit, a fourth would cross the cap
        accepted = []
        for i in range(6):
            try:
                row, _ = rec(self.a, req=f"w{i:03d}", client_key=f"cap-key-{i:04d}")
                accepted.append(row)
            except req_actions.ActionError as exc:
                self.assertEqual((exc.code, exc.status), ("log-full", 507))
                break
        self.assertEqual(len(accepted), 3)
        size = os.stat(self.a.path).st_size
        self.assertLessEqual(size, req_actions.MAX_BYTES)
        self.a._cache = None
        self.assertEqual([r["id"] for r in self.a.all()], [r["id"] for r in accepted])  # every success is readable
        self.assertEqual(sorted(self.a.latest()), ["w000", "w001", "w002"])
        with self.assertRaises(req_actions.ActionError):
            rec(self.a, req="w009", client_key="cap-key-0009")
        self.assertEqual(os.stat(self.a.path).st_size, size, "a refused action writes nothing")
        again, created = rec(self.a, req="w001", client_key="cap-key-0001")  # idempotent even when the log is full
        self.assertEqual((again["id"], created), (accepted[1]["id"], False))

    def test_f3_the_torn_line_newline_counts_toward_the_cap(self):
        probe = acts(tempfile.mkdtemp())
        rec(probe, req="w000", client_key="cap-key-0000")
        width = os.stat(probe.path).st_size
        old = req_actions.MAX_BYTES
        self.addCleanup(setattr, req_actions, "MAX_BYTES", old)
        rec(self.a, req="w000", client_key="cap-key-0000")
        with open(self.a.path, "a") as handle:
            handle.write("torn")
        size = os.stat(self.a.path).st_size
        req_actions.MAX_BYTES = size + width  # a row fits only if the extra newline is ignored
        with self.assertRaises(req_actions.ActionError) as ctx:
            rec(self.a, req="w001", client_key="cap-key-0001")
        self.assertEqual(ctx.exception.code, "log-full")
        self.assertEqual(os.stat(self.a.path).st_size, size)
        req_actions.MAX_BYTES = size + width + 1
        row, created = rec(self.a, req="w001", client_key="cap-key-0001")
        self.assertTrue(created)
        self.a._cache = None
        self.assertIn("w001", self.a.latest())
        self.assertLessEqual(os.stat(self.a.path).st_size, req_actions.MAX_BYTES)

    def test_a_symlinked_log_is_refused(self):
        self.a._ensure()
        os.symlink("/etc/hosts", self.a.path)
        with self.assertRaises(OSError):
            rec(self.a)


class Route(ServerHarness):
    def setUp(self):
        super().setUp()
        self.app.runner.outputs.update({"ah-goals": (0, json.dumps(GOALS)), "ah-requirements": lambda *_a: (0, json.dumps(REQS)),
                                        "ah-status": lambda *_a: (0, json.dumps(STATUS))})
        self.app.owners.session = SID
        self.app.ledger.run(time.time())
        self.cookie, self.csrf = self.login()

    def req(self, rid="wr1"):
        return next(r for r in self.app.ledger.parts["requirements"]["items"] if r["id"] == rid)

    def post(self, body, headers=None):
        hdrs = {"Cookie": self.cookie, "X-MC-CSRF": self.csrf, "Origin": self.origin, "Content-Type": "application/json"}
        hdrs.update(headers or {})
        hdrs = {k: v for k, v in hdrs.items() if v is not None}
        resp, data = self.request("POST", "/api/requirements/archive", hdrs, json.dumps(body).encode())
        try:
            return resp.status, json.loads(data)
        except ValueError:
            return resp.status, {}

    def click(self, action="archive", rid="wr1", key="click-key-0001", reason="not wanted any more", **kw):
        return self.post({"req_id": rid, "action": action, "reason": reason, "client_key": key, "digest": kw.pop("digest", self.req(rid)["digest"]), **kw})

    def test_archive_then_restore_moves_the_row_and_keeps_both_records(self):
        status, value = self.click()
        self.assertEqual((status, value["created"]), (201, True))
        row = self.req()
        self.assertEqual((row["bucket"], row["rule"]), ("archived", "M"))
        self.assertIn("not wanted any more", row["reason"])
        self.assertEqual(self.app.ledger.snapshot()["requirements"]["summary"]["archived"], 2)  # wr3 (done) plus this one
        status, value = self.click("restore", key="click-key-0002", reason="needed after all")
        self.assertEqual(status, 201)
        self.assertEqual(self.req()["bucket"], "live")
        self.assertEqual([r["action"] for r in self.app.actions.all()], ["archive", "restore"])

    def test_a_restore_keeps_an_automatically_archived_row_live_across_the_next_ledger_read(self):
        self.assertEqual(self.req("wr3")["rule"], "R1")
        self.assertEqual(self.click("restore", rid="wr3", key="click-key-0003", reason="not really done")[0], 201)
        self.app.ledger.run(time.time() + 61)  # a fresh `ah` read re-applies the user's override
        self.assertEqual((self.req("wr3")["bucket"], self.req("wr3")["manual"]["action"]), ("live", "restore"))

    def test_the_click_survives_a_restart_of_the_collector(self):
        self.click()
        self.app.ledger.run(time.time() + 61)
        self.assertEqual(self.req()["rule"], "M")

    def test_unsourced_and_malformed_clicks_are_refused(self):
        digest = self.req()["digest"]
        base = {"req_id": "wr1", "action": "archive", "reason": "ok", "client_key": "click-key-0009", "digest": digest}
        cases = [({"reason": ""}, 400), ({"reason": "x" * 400}, 400), ({"client_key": "x"}, 400), ({"action": "delete"}, 400),
                 ({"req_id": "nope-not-there"}, 409), ({"req_id": 5}, 409), ({"digest": "0" * 16}, 409), ({"digest": None}, 409)]
        for change, status in cases:
            with self.subTest(change):
                self.assertEqual(self.post({**base, **change})[0], status)
        self.assertEqual(self.post([1, 2])[0], 400)
        self.assertEqual(self.app.actions.all(), [])

    def test_archiving_an_archived_row_or_restoring_a_live_one_is_refused(self):
        self.assertEqual(self.click(rid="wr3", key="click-key-0004")[1]["error"], "already-archived")
        self.assertEqual(self.click("restore", rid="wr1", key="click-key-0005")[1]["error"], "not-archived")

    def test_no_session_no_csrf_no_origin_no_cookie_each_refuse_and_write_nothing(self):
        body = {"req_id": "wr1", "action": "archive", "reason": "x", "client_key": "click-key-0006", "digest": self.req()["digest"]}
        self.assertEqual(self.post(body, {"X-MC-CSRF": "wrong"})[0], 403)
        self.assertEqual(self.post(body, {"X-MC-CSRF": None})[0], 403)
        self.assertEqual(self.post(body, {"Origin": "http://evil.example"})[0], 403)
        self.assertEqual(self.post(body, {"Cookie": None})[0], 401)
        self.assertEqual(self.post(body, {"Content-Type": "text/plain"})[0], 415)
        self.app.owners.session = ""
        self.assertEqual(self.post(body)[1].get("error"), "no-main")
        self.assertEqual(self.app.actions.all(), [])

    def test_an_unattended_client_with_a_launch_link_archives_a_user_sourced_requirement(self):
        """NEG-20: a process that holds a launch link looks like the user to the server. The result must never be
        attributed to the user, must be flagged as a user-sourced requirement archived from the dashboard, and must be
        restorable."""
        self.assertTrue(self.req("wr1")["source"].startswith("user:"))
        status, value = self.click()
        self.assertEqual(status, 201)
        row = self.req("wr1")
        self.assertEqual((row["bucket"], row["rule"], row["user_sourced"]), ("archived", "M", True))
        short = SID[:8]
        self.assertIn(f"dashboard session {short}", row["reason"])
        self.assertIn(f"dashboard session {short}", row["manual"]["by"])
        shown = json.dumps(row).lower() + " ".join(e["summary"] for e in self.app.hub.recent(limit=5)).lower()
        for phrase in ("by you", "you archived", "you restored", "archived by you"):
            self.assertNotIn(phrase, shown)
        logged = self.app.actions.all()[-1]
        self.assertEqual((logged["origin"], logged["session"]), ("dashboard", SID))
        self.assertTrue(logged["source"].startswith("mc:") and "user:" not in logged["source"])
        summary = self.app.ledger.snapshot()["requirements"]["summary"]
        self.assertEqual(summary["manual_user"], 1)
        self.assertEqual(self.click("restore", key="click-key-0007", reason="restored by a person")[0], 201)
        self.assertEqual(self.req("wr1")["bucket"], "live")
        self.assertEqual(self.app.ledger.snapshot()["requirements"]["summary"]["manual_user"], 0)

    def test_every_user_source_kind_gets_the_badge_and_the_count(self):
        """NEG-20 for queue: and uuid: sources (the user's own words in provenance), not only user: and answer:."""
        sources = {"wr1": 'queue:baab765b-d85c-46b4-b7b9-588eb912c770/2026-11-13T17:33:02.321Z#3a69eba31644 "x"',
                   "wr2": 'uuid:baab765b-d85c-46b4-b7b9-588eb912c770/1b0a0685-cc50-4b90-9b63-c9cd33a7750f "x"'}
        reqs = dict(REQS, requirements=[dict(r, source=sources.get(r["id"], r["source"])) for r in REQS["requirements"]])
        self.app.runner.outputs["ah-requirements"] = lambda *_a: (0, json.dumps(reqs))
        self.app.ledger.run(time.time() + 61)
        for i, rid in enumerate(("wr1", "wr2")):
            self.assertTrue(self.req(rid)["user_sourced"], rid)
            self.assertEqual(self.click(rid=rid, key=f"click-key-10{i}")[0], 201)
            self.assertEqual((self.req(rid)["rule"], self.req(rid)["user_sourced"]), ("M", True))
        self.assertEqual(self.app.ledger.snapshot()["requirements"]["summary"]["manual_user"], 2)

    def test_a_same_key_retry_after_the_row_changed_state_is_answered_with_the_same_row(self):
        status, first = self.click(key="click-key-0200")
        self.assertEqual(status, 201)
        status, again = self.click(key="click-key-0200", digest=self.req()["digest"])
        self.assertEqual((status, again["id"], again["created"]), (200, first["id"], False))

    def test_the_write_routes_in_the_server_match_the_coverage_map(self):
        import re
        server = (REPO / "harness" / "mission_control" / "server.py").read_text()
        routes = set(re.findall(r'"(/api/[a-z/]+)"', re.search(r"if route not in \(([^)]*)\)", server).group(1)))
        mapped = {k.split(" ", 1)[1] for k in json.loads((REPO / "harness" / "mission_control" / "web" / "coverage.json").read_text())["routes"] if k.startswith("POST ")}
        self.assertEqual(routes, mapped)

    def test_the_ledger_and_state_need_a_session_and_the_right_host(self):
        resp, _ = self.request("GET", "/api/state", {"Sec-Fetch-Site": "same-origin"})
        self.assertEqual(resp.status, 401)
        resp, _ = self.request("GET", "/api/state", {"Cookie": self.cookie, "Sec-Fetch-Site": "same-origin"}, host="evil.example")
        self.assertEqual(resp.status, 403)
        resp, data = self.request("GET", "/api/state", {"Cookie": self.cookie, "Sec-Fetch-Site": "same-origin"})
        self.assertIn("ledger", json.loads(data))
        self.assertIn("default-src 'self'", resp.getheader("Content-Security-Policy"))
        self.assertNotIn("unsafe-inline", resp.getheader("Content-Security-Policy"))
        self.assertNotIn("Access-Control-Allow-Origin", dict(resp.getheaders()))


if __name__ == "__main__":
    unittest.main()
