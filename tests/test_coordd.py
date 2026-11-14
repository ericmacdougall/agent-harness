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

    def test_http_needs_token_and_loopback_host(self):
        coordd.Handler.root, coordd.Handler.token = self.root, (self.root / "token").read_text().strip()
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
