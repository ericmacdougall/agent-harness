"""Focused tests for coordd (goodqa#16043): ledger, routing, restart recovery, auth. No network, no model."""
import json
import os
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "harness" / "coordinator"))
import coordd  # noqa: E402


class CoorddTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        os.environ["COORD_HOME"] = self.tmp.name
        self._home = os.environ.get("HOME")
        os.environ["HOME"] = self.tmp.name  # event drops and lane probes stay inside the temp dir
        self.root = coordd.ensure_home()
        self.con = coordd.db(self.root)

    def tearDown(self):
        os.environ["HOME"] = self._home
        self.tmp.cleanup()

    def test_same_key_is_one_task(self):
        a = coordd.submit(self.con, "status", "x", None, "t", "key-0001")
        b = coordd.submit(self.con, "status", "x", None, "t", "key-0001")
        self.assertEqual(a["id"], b["id"])
        self.assertTrue(b["deduplicated"])
        self.assertEqual(self.con.execute("SELECT COUNT(*) FROM tasks").fetchone()[0], 1)

    def test_bad_input_refused(self):
        for kind, text, ticket in (("deploy", "x", None), ("agent", "", None), ("agent", "x", "../etc#1"),
                                   ("agent", "y" * 9000, None)):
            with self.assertRaises(ValueError):
                coordd.submit(self.con, kind, text, ticket, "t", None)

    def test_no_lane_fails_loudly_not_dropped(self):
        os.environ["COORD_CODEX_POOL"] = ""
        t = coordd.submit(self.con, "agent", "do a thing", None, "t", None)
        self.assertTrue(coordd.run_one(self.con, self.root, chat_only=False))
        row = self.con.execute("SELECT state, error FROM tasks WHERE id=?", (t["id"],)).fetchone()
        self.assertEqual(row["state"], "failed")
        self.assertIn("no worker lane", row["error"])

    def test_restart_requeues_once_then_fails_and_never_reruns_done(self):
        t = coordd.submit(self.con, "agent", "x", None, "t", None)
        d = coordd.submit(self.con, "status", "x", None, "t", None)
        u = coordd.submit(self.con, "agent", "y", None, "t", None)
        self.con.execute("UPDATE tasks SET state='running', attempts=1, lane='codex-pool-build' WHERE id=?", (t["id"],))
        self.con.execute("UPDATE tasks SET state='running', attempts=1, lane='some-writing-lane' WHERE id=?", (u["id"],))
        self.con.execute("UPDATE tasks SET state='done', result='r', attempts=1 WHERE id=?", (d["id"],))
        coordd.recover(self.con)
        get = lambda i: self.con.execute("SELECT state FROM tasks WHERE id=?", (i,)).fetchone()[0]  # noqa: E731
        self.assertEqual(get(t["id"]), "queued")
        self.assertEqual(get(d["id"]), "done")
        self.assertEqual(get(u["id"]), "outcome-unknown")  # not replay-safe: never rerun, never called failed
        self.con.execute("UPDATE tasks SET state='running', attempts=2 WHERE id=?", (t["id"],))
        coordd.recover(self.con)
        self.assertEqual(get(t["id"]), "outcome-unknown")

    def test_task_needing_commands_is_blocked_not_dispatched(self):
        os.environ["COORD_CODEX_POOL"] = __file__
        orig = coordd.lane_codex_pool
        coordd.lane_codex_pool = lambda task, root: self.fail("dispatched a task no lane can serve")
        try:
            t = coordd.submit(self.con, "agent", "run ls", None, "t", None, "run-commands")
            coordd.run_one(self.con, self.root, chat_only=False)
        finally:
            coordd.lane_codex_pool = orig
            os.environ["COORD_CODEX_POOL"] = ""
        row = self.con.execute("SELECT state, error FROM tasks WHERE id=?", (t["id"],)).fetchone()
        self.assertEqual(row["state"], "blocked")
        self.assertIn("run-commands", row["error"])
        with self.assertRaises(ValueError):
            coordd.submit(self.con, "agent", "x", None, "t", None, "root-shell")

    def test_chat_commands_and_freeform_without_subscription(self):
        t = coordd.submit(self.con, "chat", "run check the build ticket:goodqa#1", None, "chat", None)
        coordd.run_one(self.con, self.root, chat_only=True)
        row = self.con.execute("SELECT state, result FROM tasks WHERE id=?", (t["id"],)).fetchone()
        self.assertEqual(row["state"], "done")
        q = self.con.execute("SELECT text, ticket, state FROM tasks WHERE kind='agent'").fetchone()
        self.assertEqual((q["text"], q["ticket"], q["state"]), ("check the build", "goodqa#1", "queued"))
        self.con.execute("UPDATE tasks SET state='queued' WHERE id=?", (t["id"],))  # replay after a restart
        coordd.run_one(self.con, self.root, chat_only=True)
        self.assertEqual(self.con.execute("SELECT COUNT(*) FROM tasks WHERE kind='agent'").fetchone()[0], 1)
        orig = coordd.subscription_cli
        coordd.subscription_cli = lambda: None
        try:
            f = coordd.submit(self.con, "chat", "how are things?", None, "chat", None)
            coordd.run_one(self.con, self.root, chat_only=True)
        finally:
            coordd.subscription_cli = orig
        row = self.con.execute("SELECT state, error FROM tasks WHERE id=?", (f["id"],)).fetchone()
        self.assertEqual(row["state"], "failed")
        self.assertIn("unavailable", row["error"])

    def test_worker_result_must_claim_ok(self):
        self.assertEqual(coordd.typed_result("did it\nCOORD_RESULT: ok"), (True, "did it"))
        for out in ("I could not read the file: sandbox failed", "x\nCOORD_RESULT: blocked: sandbox failed",
                    "COORD_RESULT: ok\ntrailing text", ""):
            self.assertFalse(coordd.typed_result(out)[0], out)

    def test_transient_worker_failure_retries_once(self):
        os.environ["COORD_CODEX_POOL"] = __file__  # any existing file: the lane itself is stubbed below
        calls = []
        orig = coordd.lane_codex_pool
        coordd.lane_codex_pool = lambda task, root: (calls.append(1), (False, "worker exit 4: ERROR: Quota exceeded."))[1]
        try:
            t = coordd.submit(self.con, "agent", "x", None, "t", None)
            coordd.run_one(self.con, self.root, chat_only=False)
            self.assertEqual(self.con.execute("SELECT state FROM tasks WHERE id=?", (t["id"],)).fetchone()[0], "queued")
            coordd.run_one(self.con, self.root, chat_only=False)
            coordd.run_one(self.con, self.root, chat_only=False)
        finally:
            coordd.lane_codex_pool = orig
            os.environ["COORD_CODEX_POOL"] = ""
        self.assertEqual(self.con.execute("SELECT state FROM tasks WHERE id=?", (t["id"],)).fetchone()[0], "failed")
        self.assertEqual(len(calls), 2)

    def test_device_login_rules(self):
        c, t0 = self.con, 1_000_000.0
        a = coordd.login_start(c, "browser A", now=t0)
        b = coordd.login_start(c, "browser B", now=t0)
        self.assertRegex(a["code"], coordd.CODE_RE)
        self.assertEqual(coordd.login_poll(c, a["poll"], now=t0 + 1), ("pending", None))
        for bad in ("", "AAAA-AAA", a["code"].replace("-", ""), "0O1I-LU00", "ZZZZ-ZZZZ"):
            with self.assertRaises(ValueError):  # malformed, look-alike characters, or simply not issued
                coordd.login_approve(c, bad, "t", now=t0 + 2)
        self.assertEqual(coordd.login_approve(c, a["code"].lower(), "t", now=t0 + 2)["client"], "browser A")
        with self.assertRaises(ValueError):  # a code is approved once
            coordd.login_approve(c, a["code"], "t", now=t0 + 3)
        # Only the browser that started the login holds its poll secret: B's poll and a guess get nothing.
        self.assertEqual(coordd.login_poll(c, b["poll"], now=t0 + 3), ("pending", None))
        self.assertEqual(coordd.login_poll(c, "guess", now=t0 + 3), ("gone", None))
        state, sid = coordd.login_poll(c, a["poll"], now=t0 + 4)
        self.assertEqual(state, "approved")
        self.assertTrue(coordd.session_ok(c, sid, now=t0 + 5))
        self.assertEqual(coordd.login_poll(c, a["poll"], now=t0 + 6), ("gone", None))  # consumed: second poll gets nothing
        self.assertFalse(coordd.session_ok(c, sid, now=t0 + coordd.SESSION_TTL_S + 10))
        self.assertFalse(coordd.session_ok(c, "", now=t0))
        self.assertNotIn(sid, [r[0] for r in c.execute("SELECT sid_hash FROM sessions")])  # stored hashed
        with self.assertRaises(ValueError):  # B's code expired before anyone approved it
            coordd.login_approve(c, b["code"], "t", now=t0 + coordd.LOGIN_TTL_S + 1)
        self.assertEqual(coordd.login_poll(c, b["poll"], now=t0 + coordd.LOGIN_TTL_S + 1), ("gone", None))

    def test_device_login_limit_is_per_client(self):
        t0 = 2_000_000.0
        for i in range(coordd.LOGIN_PER_CLIENT_PENDING):
            coordd.login_start(self.con, "x", now=t0 + i, addr="10.0.0.1")
        with self.assertRaises(PermissionError):
            coordd.login_start(self.con, "x", now=t0 + 10, addr="10.0.0.1")
        coordd.login_start(self.con, "y", now=t0 + 10, addr="10.0.0.2")  # one noisy client locks out nobody else

    def test_requester_text_cannot_carry_control_characters(self):
        r = coordd.login_start(self.con, "evil\x1b[2J\nAPPROVED user", now=3_000_000.0, addr="a")
        shown = coordd.login_pending(self.con, now=3_000_000.0)[0]["client"]
        self.assertEqual(shown, "evil?[2J?APPROVED user")
        self.assertTrue(r["code"])

    def test_browser_session_reaches_no_worker_and_no_ticket(self):
        W = coordd.WEB_ORIGIN
        for kind, ticket in (("agent", None), ("status", None), ("chat", "goodqa#1")):
            with self.assertRaises(PermissionError):
                coordd.submit(self.con, kind, "x", ticket, W, None)
        for text in ("run print ../../token", "please read the token file"):
            t = coordd.submit(self.con, "chat", text, None, W, None)
            coordd.run_one(self.con, self.root, chat_only=True)
            row = self.con.execute("SELECT state, error FROM tasks WHERE id=?", (t["id"],)).fetchone()
            self.assertEqual(row["state"], "blocked")
        self.assertEqual(self.con.execute("SELECT COUNT(*) FROM tasks WHERE kind='agent'").fetchone()[0], 0)
        t = coordd.submit(self.con, "chat", "help", None, W, None)
        coordd.run_one(self.con, self.root, chat_only=True)
        self.assertEqual(self.con.execute("SELECT state FROM tasks WHERE id=?", (t["id"],)).fetchone()[0], "done")

    def test_ticket_project_allowlist_and_typed_fields(self):
        with self.assertRaises(ValueError):
            coordd.submit(self.con, "agent", "x", "otherproj#5", "cli:t", None)
        with self.assertRaises(ValueError):
            coordd.submit(self.con, "agent", "x", None, "cli:t", ["not", "text"])
        self.assertEqual(coordd.submit(self.con, "agent", "x", "goodqa#5", "cli:t", None)["ticket"], "goodqa#5")

    def test_short_or_empty_token_is_never_authority(self):
        (self.root / "token").write_text("")
        with self.assertRaises(SystemExit):
            coordd.read_token(self.root)
        coordd.Handler.root, coordd.Handler.token = self.root, ""
        coordd.Handler.hosts = {"127.0.0.1", "localhost"}
        httpd = ThreadingHTTPServer(("127.0.0.1", 0), coordd.Handler)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        try:
            req = urllib.request.Request(f"http://127.0.0.1:{httpd.server_address[1]}/api/tasks",
                                         headers={"Authorization": "Bearer "})
            with self.assertRaises(urllib.error.HTTPError) as ctx:
                urllib.request.urlopen(req, timeout=5)
            self.assertEqual(ctx.exception.code, 401)
        finally:
            httpd.shutdown()

    def test_http_browser_session(self):
        coordd.Handler.root, coordd.Handler.token = self.root, (self.root / "token").read_text().strip()
        coordd.Handler.hosts = {"127.0.0.1", "localhost"}
        httpd = ThreadingHTTPServer(("127.0.0.1", 0), coordd.Handler)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        base = f"http://127.0.0.1:{httpd.server_address[1]}"

        def call(path, body=None, cookie=None, token=None, origin=None):
            h = {"Content-Type": "application/json"}
            if cookie:
                h["Cookie"] = cookie
            if token:
                h["Authorization"] = "Bearer " + token
            if origin:
                h["Origin"] = origin
            req = urllib.request.Request(base + path, headers=h, data=json.dumps(body).encode() if body is not None else None)
            try:
                with urllib.request.urlopen(req, timeout=5) as r:
                    return r.status, json.loads(r.read()), r.headers.get("Set-Cookie")
            except urllib.error.HTTPError as e:
                return e.code, json.loads(e.read() or b"{}"), None
        try:
            _, login, _ = call("/api/login/start", {})
            self.assertEqual(call("/api/login/poll", {"poll": login["poll"]})[1], {"state": "pending"})
            self.assertEqual(call("/api/login/approve", {"code": login["code"]})[0], 401)  # nobody signed in
            self.assertEqual(call("/api/login/approve", {"code": login["code"]}, token=coordd.Handler.token)[0], 200)
            code, body, setc = call("/api/login/poll", {"poll": login["poll"]})
            self.assertEqual(body, {"state": "approved"})
            self.assertIn("HttpOnly", setc)
            self.assertIn("SameSite=Strict", setc)
            cookie = setc.split(";")[0]
            self.assertEqual(call("/api/status", cookie=cookie)[0], 200)
            self.assertEqual(call("/api/chat", {"text": "help"}, cookie=cookie, origin=base)[0], 200)
            self.assertEqual(call("/api/chat", {"text": "help"}, cookie=cookie, origin="https://evil.example")[0], 401)
            self.assertEqual(call("/api/chat", {"text": "help"}, cookie=cookie, origin="http://127.0.0.1:1")[0], 401)  # other port
            # The session cannot queue a worker task, and a forged origin field in the body changes nothing.
            self.assertEqual(call("/api/tasks", {"kind": "agent", "text": "x", "origin": "cli"}, cookie=cookie)[0], 403)
            self.assertEqual(call("/api/tasks", {"kind": "agent", "text": "x", "key": {"a": 1}}, token=coordd.Handler.token)[0], 400)
            st, made, _ = call("/api/tasks", {"kind": "status", "text": "x", "origin": "web-session"}, token=coordd.Handler.token)
            self.assertEqual((st, made["origin"]), (200, "cli:web-session"))
            # A browser session cannot approve other sign-ins or list them: that stays a host action.
            _, second, _ = call("/api/login/start", {})
            self.assertEqual(call("/api/login/approve", {"code": second["code"]}, cookie=cookie)[0], 403)
            self.assertEqual(call("/api/logins", cookie=cookie)[0], 403)
            self.assertEqual(call("/api/logout-all", {"all": True}, token=coordd.Handler.token)[0], 200)
            self.assertEqual(call("/api/status", cookie=cookie)[0], 401)
        finally:
            httpd.shutdown()

    def test_http_needs_token_and_loopback_host(self):
        coordd.Handler.root, coordd.Handler.token = self.root, (self.root / "token").read_text().strip()
        coordd.Handler.hosts = {"127.0.0.1", "localhost"}
        httpd = ThreadingHTTPServer(("127.0.0.1", 0), coordd.Handler)
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        base = f"http://127.0.0.1:{httpd.server_address[1]}"

        def call(path, token=None, host=None, body=None):
            h = {"Content-Type": "application/json"}
            if token:
                h["Authorization"] = "Bearer " + token
            if host:
                h["Host"] = host
            req = urllib.request.Request(base + path, headers=h, data=json.dumps(body).encode() if body else None)
            try:
                with urllib.request.urlopen(req, timeout=5) as r:
                    return r.status
            except urllib.error.HTTPError as e:
                return e.code
        try:
            self.assertEqual(call("/api/tasks"), 401)
            self.assertEqual(call("/api/tasks", token="wrong"), 401)
            self.assertEqual(call("/api/chat", body={"text": "status"}), 401)
            self.assertEqual(call("/api/tasks", token=coordd.Handler.token, host="evil.example"), 403)
            self.assertEqual(call("/api/tasks", token=coordd.Handler.token), 200)
            self.assertEqual(call("/healthz"), 200)
        finally:
            httpd.shutdown()


if __name__ == "__main__":
    unittest.main()
