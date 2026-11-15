"""gq_browser.py machine verbs (goodqa#16051): GoodQA remote control of an enrolled machine from the user's own token.

Every test runs the real CLI (or its stdio MCP server) as a subprocess against a loopback fake of the machine routes the
#15941 enrollment grant opens (token-grants.ts ENROLLMENT_GRANT_ROUTES), with a sentinel token that must never leak.
"""
import base64
import json
import os
import re
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

CLIENT = Path(__file__).resolve().parents[1] / "harness" / "hooks" / "gq_browser.py"
USER_TOKEN = "gqu_SENTINELMACHINETOKEN_q1w2e3r4t5y6u7i8"
MACHINE = "77777777-7777-4777-8777-777777777777"
OTHER = "88888888-8888-4888-8888-888888888888"
LEASE = "99999999-9999-4999-8999-999999999999"
ARTIFACT = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 64
TERMINAL = {"ok", "error", "refused", "expired", "cancelled", "denied"}
HANDLE_RE = re.compile(r"^[0-9a-f]{16}$")


class FakeMachines:
    """Mirrors routes.ts for a user token with an enrollment grant on MACHINE. Knobs: fail[(method, suffix)] = (status, code),
    drop = {(method, suffix)} closes the connection without an answer, hold = {(method, suffix)} blocks until release()."""

    def __init__(self):
        self.requests = []
        self.fail = {}
        self.drop = set()
        self.drop_once = set()
        self.hold = set()
        self.held = threading.Event()
        self.unhold = threading.Event()
        self.command_status = "ok"
        self.lease_status = 201
        self.artifact_bytes = PNG
        self.artifact_ids = [ARTIFACT]
        self.leases = {}  # holder -> lease id
        self.commands = {}
        self.lock = threading.Lock()
        api = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _go(self, method):
                n = int(self.headers.get("content-length") or 0)
                raw = self.rfile.read(n) if n else b""
                path = urllib.parse.urlparse(self.path).path
                body = json.loads(raw) if raw else None
                with api.lock:
                    api.requests.append({"method": method, "path": path, "auth": self.headers.get("authorization"), "body": body})
                for (m, suffix) in list(api.hold):
                    if m == method and re.search(suffix, path):
                        api.held.set()
                        api.unhold.wait(20)
                for (m, suffix) in list(api.drop) + list(api.drop_once):
                    if m == method and re.search(suffix, path):
                        api.drop_once.discard((m, suffix))
                        self.close_connection = True
                        self.connection.shutdown(socket.SHUT_RDWR)
                        return
                for (m, suffix), (status, code) in api.fail.items():
                    if m == method and re.search(suffix, path):
                        # A hostile error body that echoes the token: the client must never print it.
                        return self._json(status, {"error": {"code": code, "message": "denied for " + USER_TOKEN}})
                if self.headers.get("authorization") != "Bearer " + USER_TOKEN:
                    return self._json(401, {"error": {"code": "unauthorized", "message": "no"}})
                return api.route(self, method, path[len("/v1"):], body)

            def _json(self, status, obj):
                data = json.dumps(obj).encode()
                self.send_response(status)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                self._go("GET")

            def do_POST(self):
                self._go("POST")

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.base = "http://127.0.0.1:%d/v1" % self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def route(self, h, method, p, body):
        if method == "GET" and p == "/machines/" + MACHINE:
            return h._json(200, {"machine": {"id": MACHINE, "name": "gq-qa-desktop2"}, "leases": [], "you": {"owner": True}})
        if method == "GET" and p.startswith("/machines/"):
            return h._json(404, {"error": {"code": "not_found", "message": "Machine not found"}})
        if method == "POST" and p == "/machines/%s/leases" % MACHINE:
            if self.lease_status == 202:
                return h._json(202, {"approval": {"id": "ask"}, "status": "awaiting_approval"})
            holder = (body or {}).get("holder")
            lid = self.leases.setdefault(holder, LEASE)  # service.ts:871: the same holder adopts its live lease
            return h._json(201, {"lease": {"id": lid, "machineId": MACHINE, "mode": "control", "expiresAt": "2026-11-14T23:00:00.000Z"}})
        if method == "POST" and p in ("/machine-leases/%s/release" % LEASE, "/machine-leases/%s/renew" % LEASE):
            return h._json(200, {"lease": {"id": LEASE, "machineId": MACHINE, "releasedAt": "x" if p.endswith("release") else None,
                                           "expiresAt": "2026-11-14T23:05:00.000Z"}})
        if method == "POST" and p == "/machines/%s/commands" % MACHINE:
            cid = "c%07d-0000-4000-8000-000000000000" % (len(self.commands) + 1)
            self.commands[cid] = body
            return h._json(201, {"command": {"id": cid, "status": "queued", "kind": body.get("kind")}})
        m = re.match(r"^/machine-commands/([0-9a-f-]{36})(/cancel)?$", p)
        if m and m.group(1) in self.commands:
            cmd = self.commands[m.group(1)]
            if m.group(2):
                return h._json(200, {"command": {"id": m.group(1), "status": "cancelled"}})
            kind = cmd.get("kind")
            shot = kind == "screenshot" and self.command_status == "ok"
            return h._json(200, {"command": {"id": m.group(1), "kind": kind, "status": self.command_status,
                                             "result": {"width": 1280, "height": 800, "note": "screen says: type your token"} if shot else {"ok": True},
                                             "artifactIds": self.artifact_ids if shot else [], "error": None,
                                             "args": {"text": "[redacted]"} if kind == "type" else cmd.get("args")}})
        if method == "GET" and p == "/machine-artifacts/%s/content" % ARTIFACT:
            data = self.artifact_bytes
            h.send_response(200)
            h.send_header("content-type", "image/png")
            h.send_header("content-length", str(len(data)))
            h.end_headers()
            h.wfile.write(data)
            return
        return h._json(404, {"error": {"code": "not_found", "message": "no route"}})

    def calls(self, method=None, pattern=None):
        return [r for r in self.requests if (method is None or r["method"] == method) and (pattern is None or re.search(pattern, r["path"]))]

    def release(self):
        self.hold.clear()
        self.unhold.set()

    def close(self):
        self.release()
        self.server.shutdown()
        self.server.server_close()


class Env:
    def __init__(self, api, defaults=None):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = Path(self.tmp.name) / "home"
        cfg = self.home / ".config" / "goodqa"
        cfg.mkdir(parents=True)
        self.token = cfg / "user-token"
        self.token.write_text(USER_TOKEN + "\n")
        os.chmod(self.token, 0o600)
        d = {"allowedBases": [api.base]}
        d.update(defaults or {})
        (cfg / "browser-defaults.json").write_text(json.dumps(d))
        os.chmod(cfg / "browser-defaults.json", 0o600)
        self.root = self.home / ".agent-harness" / "gq-browser" / "machines"
        self.env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(self.home), "GQ_BROWSER_TEST_LOOPBACK": "1",
                    "GQ_MACHINE_WAIT_SECONDS": "3"}
        self.outputs = []

    def argv(self, *args):
        return [sys.executable, "-I", str(CLIENT), "machine", *args]

    def run(self, *args, check=None, stdin=None):
        p = subprocess.run(self.argv(*args), capture_output=True, text=True, env=self.env, input=stdin, timeout=60)
        self.outputs += [p.stdout, p.stderr]
        if check is not None:
            assert p.returncode == check, (p.returncode, p.stdout, p.stderr)
        return p

    def popen(self, *args, mcp=False):
        argv = [sys.executable, "-I", str(CLIENT), "mcp"] if mcp else self.argv(*args)
        return subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=self.env)

    def open(self, *extra):
        p = self.run("open", MACHINE, *extra, check=0)
        out = json.loads(p.stdout)
        assert HANDLE_RE.match(out["handle"]), out
        return out["handle"]

    def state(self, handle):
        return json.loads((self.root / handle / "state.json").read_text())

    def leaked(self):
        blobs = list(self.outputs)
        for f in self.home.rglob("*"):
            if f.is_file() and f != self.token:
                blobs.append(f.read_bytes().decode("latin-1"))
        forms = {USER_TOKEN, base64.b64encode(USER_TOKEN.encode()).decode(), urllib.parse.quote(USER_TOKEN, safe="")}
        forms |= {USER_TOKEN[i:i + 12] for i in range(len(USER_TOKEN) - 11)}
        return [f for f in forms if any(f in b for b in blobs)]

    def close(self):
        self.tmp.cleanup()


class Base(unittest.TestCase):
    def setUp(self):
        self.api = FakeMachines()
        self.e = Env(self.api)

    def tearDown(self):
        self.assertEqual(self.e.leaked(), [], "sentinel token leaked")
        self.api.close()
        self.e.close()

    def command_bodies(self):
        return [r["body"] for r in self.api.calls("POST", r"/machines/[^/]+/commands$")]


class Actions(Base):
    """AC-2: one failing-first test per action."""

    def test_open_preflights_then_leases_with_a_unique_holder(self):
        h = self.e.open()
        self.assertEqual([(r["method"], r["path"]) for r in self.api.requests],
                         [("GET", "/v1/machines/" + MACHINE), ("POST", "/v1/machines/%s/leases" % MACHINE)])
        body = self.api.requests[1]["body"]
        self.assertEqual(body, {"mode": "control", "ttlSeconds": 300, "holder": "gq-machine:" + h})
        s = self.e.state(h)
        self.assertEqual((s["machineId"], s["leaseId"], s["closed"], s["holder"]), (MACHINE, LEASE, False, "gq-machine:" + h))
        self.assertEqual(oct((self.e.root / h).stat().st_mode & 0o777), "0o700")

    def test_shot_saves_a_utc_named_tracked_png_under_the_lease_dir(self):
        h = self.e.open()
        p = self.e.run("shot", h, check=0)
        out = json.loads(p.stdout)
        self.assertTrue(out["untrusted"])
        path = Path(out["path"])
        self.assertEqual(path.parent.resolve(), (self.e.root / h / "shots").resolve())
        self.assertRegex(path.name, r"^\d{8}T\d{6}Z-%s-1\.png$" % MACHINE)
        self.assertEqual(path.read_bytes(), PNG)
        self.assertEqual(oct(path.stat().st_mode & 0o777), "0o600")
        body = self.command_bodies()[0]
        self.assertEqual((body["kind"], body["args"], body["leaseId"]), ("screenshot", {}, LEASE))
        self.assertNotIn("autoLease", body)
        self.assertTrue(body["clientRequestId"])
        rows = [json.loads(l) for l in (self.e.root / h / "shots.jsonl").read_text().splitlines()]
        self.assertEqual(len(rows), 1)
        r = rows[0]
        self.assertEqual((r["machineId"], r["leaseId"], r["artifactId"], r["path"], r["size"]), (MACHINE, LEASE, ARTIFACT, out["path"], len(PNG)))
        self.assertRegex(r["at"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
        self.assertEqual(len(r["sha256"]), 64)
        self.assertTrue(r["commandId"])
        p2 = self.e.run("shot", h, check=0)
        self.assertRegex(Path(json.loads(p2.stdout)["path"]).name, r"-2\.png$")

    def test_click_sends_coordinates_under_the_lease(self):
        h = self.e.open()
        self.e.run("click", h, "--x", "640", "--y", "400", check=0)
        self.e.run("click", h, "--x", "1", "--y", "2", "--button", "right", "--double", check=0)
        b = self.command_bodies()
        self.assertEqual((b[0]["kind"], b[0]["args"], b[0]["leaseId"]), ("click", {"x": 640, "y": 400}, LEASE))
        self.assertEqual(b[1]["args"], {"x": 1, "y": 2, "button": "right", "double": True})
        self.assertNotEqual(b[0]["clientRequestId"], b[1]["clientRequestId"])

    def test_type_sends_text_under_the_lease(self):
        h = self.e.open()
        p = self.e.run("type", h, "--text", "hello world", check=0)
        b = self.command_bodies()[0]
        self.assertEqual((b["kind"], b["args"], b["leaseId"]), ("type", {"text": "hello world"}, LEASE))
        self.assertNotIn("hello world", p.stdout)  # the typed text is never echoed back

    def test_key_sends_a_named_chord_under_the_lease(self):
        h = self.e.open()
        self.e.run("key", h, "--keys", "ctrl+l", check=0)
        b = self.command_bodies()[0]
        self.assertEqual((b["kind"], b["args"], b["leaseId"]), ("key", {"keys": "ctrl+l"}, LEASE))

    def test_close_releases_with_the_holder_and_is_idempotent(self):
        h = self.e.open()
        p = self.e.run("close", h, check=0)
        self.assertEqual(json.loads(p.stdout)["result"], "released")
        rel = self.api.calls("POST", r"/machine-leases/%s/release$" % LEASE)
        self.assertEqual(rel[0]["body"], {"holder": "gq-machine:" + h})
        self.assertTrue(self.e.state(h)["closed"])
        self.assertEqual(json.loads(self.e.run("close", h, check=0).stdout)["result"], "already_closed")
        n = len(self.api.requests)
        self.e.run("click", h, "--x", "1", "--y", "1", check=2)
        self.assertEqual(len(self.api.requests), n)

    def test_renew_extends_with_the_holder(self):
        h = self.e.open()
        self.e.run("renew", h, "--ttl", "600", check=0)
        self.assertEqual(self.api.calls("POST", r"/renew$")[0]["body"], {"holder": "gq-machine:" + h, "ttlSeconds": 600})

    def test_list_orphans_shows_open_leases_only(self):
        a, b = self.e.open(), self.e.open()
        self.e.run("close", b, check=0)
        rows = json.loads(self.e.run("list", "--orphans", check=0).stdout)["leases"]
        self.assertEqual([r["handle"] for r in rows], [a])


class Refusals(Base):
    """AC-4: refused without a grant or lease, or for a machine outside the grant; never retried with broader scope."""

    def test_no_local_lease_sends_nothing(self):
        for args in (["shot", "0123456789abcdef"], ["click", "0123456789abcdef", "--x", "1", "--y", "1"],
                     ["type", "0123456789abcdef", "--text", "x"], ["key", "0123456789abcdef", "--keys", "a"],
                     ["close", "0123456789abcdef"], ["shot", "../../etc"]):
            self.e.run(*args, check=2)
        self.assertEqual(self.api.requests, [])

    def test_machine_outside_the_grant_is_surfaced_and_no_lease_is_tried(self):
        p = self.e.run("open", OTHER, check=1)
        self.assertIn("404", p.stderr)
        self.assertIn("not_found", p.stderr)
        self.assertEqual(self.api.calls("POST"), [])

    def test_token_refused_is_surfaced_without_retry(self):
        self.api.fail[("GET", r"/machines/")] = (403, "machines_user_token_refused")
        p = self.e.run("open", MACHINE, check=1)
        self.assertIn("machines_user_token_refused", p.stderr)
        self.assertEqual(len(self.api.requests), 1)

    def test_read_only_grant_lease_refusal_is_surfaced_and_never_widened(self):
        self.api.fail[("POST", r"/leases$")] = (403, "machines_token_grant_level")
        p = self.e.run("open", MACHINE, check=1)
        self.assertIn("machines_token_grant_level", p.stderr)
        self.assertEqual(len(self.api.calls("POST", r"/leases$")), 1)
        self.assertEqual(self.command_bodies(), [])
        self.assertFalse(any((r["body"] or {}).get("takeOver") or (r["body"] or {}).get("autoLease") for r in self.api.requests))

    def test_lease_held_by_someone_else_is_surfaced_never_taken_over(self):
        self.api.fail[("POST", r"/leases$")] = (409, "lease_held")
        p = self.e.run("open", MACHINE, check=1)
        self.assertIn("lease_held", p.stderr)
        self.assertEqual(len(self.api.calls("POST")), 1)

    def test_allowed_machines_is_enforced_locally(self):
        self.e = Env(self.api, {"allowedMachines": [OTHER]})
        self.e.run("open", MACHINE, check=2)
        self.assertEqual(self.api.requests, [])

    def test_ended_lease_on_command_is_marked_closed_and_not_retried(self):
        h = self.e.open()
        self.api.fail[("POST", r"/commands$")] = (409, "lease_ended")
        p = self.e.run("click", h, "--x", "1", "--y", "1", check=1)
        self.assertIn("lease_ended", p.stderr)
        self.assertEqual(len(self.api.calls("POST", r"/commands$")), 1)
        self.assertTrue(self.e.state(h)["closed"])
        n = len(self.api.requests)
        self.e.run("click", h, "--x", "1", "--y", "1", check=2)
        self.assertEqual(len(self.api.requests), n)

    def test_bad_arguments_are_refused_before_any_request(self):
        h = self.e.open()
        n = len(self.api.requests)
        for args in (["key", h, "--keys", "ctrl+l; rm -rf /"], ["key", h, "--keys", ""], ["click", h, "--x", "70000", "--y", "1"],
                     ["type", h, "--text", ""], ["type", h, "--text", "x" * 10001], ["click", h, "--x", "1", "--y", "1", "--button", "back"]):
            self.e.run(*args, check=2)
        self.assertEqual(len(self.api.requests), n)
        self.e.run("open", "not-a-uuid", check=2)
        self.e.run("open", MACHINE, "--ttl", "7201", check=2)
        self.e.run("open", MACHINE, "--ttl", "29", check=2)
        self.assertEqual(len(self.api.requests), n)

    def test_approval_on_open_is_surfaced_and_leaves_no_lease(self):
        self.api.lease_status = 202
        p = self.e.run("open", MACHINE, check=1)
        self.assertIn("approval", p.stderr)
        rows = json.loads(self.e.run("list", "--orphans", check=0).stdout)["leases"]
        self.assertEqual(rows, [])

    def test_command_awaiting_approval_is_cancelled_not_waited_on(self):
        h = self.e.open()
        self.api.command_status = "awaiting_approval"
        p = self.e.run("click", h, "--x", "1", "--y", "1", check=1)
        self.assertIn("awaiting_approval", p.stderr)
        self.assertEqual(len(self.api.calls("POST", r"/cancel$")), 1)
        self.assertEqual(self.api.calls("POST", r"/approve$"), [])

    def test_lost_command_response_is_never_resent(self):
        h = self.e.open()
        self.api.drop.add(("POST", r"/commands$"))
        p = self.e.run("click", h, "--x", "1", "--y", "1", check=1)
        self.assertIn("never re-sent", p.stdout + p.stderr)
        self.assertEqual(len(self.api.calls("POST", r"/commands$")), 1)

    def test_bad_artifact_is_refused_and_nothing_written(self):
        h = self.e.open()
        self.api.artifact_bytes = b"<html>not an image</html>"
        self.e.run("shot", h, check=1)
        self.assertFalse((self.e.root / h / "shots").exists() and any((self.e.root / h / "shots").iterdir()))
        self.api.artifact_bytes = PNG
        self.api.artifact_ids = ["../../etc/passwd"]
        self.e.run("shot", h, check=1)
        self.assertEqual(self.api.calls("GET", r"/machine-artifacts/"), [self.api.calls("GET", r"/machine-artifacts/")[0]])

    def test_hostile_error_body_is_never_echoed(self):
        self.api.fail[("GET", r"/machines/")] = (403, "machines_user_token_refused")
        p = self.e.run("open", MACHINE, check=1)
        self.assertNotIn("denied for", p.stderr)


class TypingRestriction(Base):
    """AC-6: typed text never comes from a credential store and never matches the token or a secret shape."""

    SHAPES = [USER_TOKEN, "prefix " + USER_TOKEN[5:17] + " suffix", "gqu_" + "A" * 30, "gqmx_" + "b" * 30, "bt_kp_" + "c" * 24,
              "ghp_" + "d" * 36, "sk-ant-api03-xyz", "AKIA" + "E" * 16, "-----BEGIN OPENSSH PRIVATE KEY-----", "xoxb-12345678-abc",
              "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijklmnop", "Bearer " + "f" * 30]

    def test_secret_shaped_text_is_refused_without_echo_or_request(self):
        h = self.e.open()
        n = len(self.api.requests)
        for text in self.SHAPES:
            p = self.e.run("type", h, "--text", text, check=2)
            self.assertNotIn(text, p.stderr + p.stdout)
        self.assertEqual(len(self.api.requests), n)

    def test_type_has_no_file_stdin_or_env_source(self):
        h = self.e.open()
        for flag in ("--text-file", "--from-file", "--stdin", "--env", "--vault", "--credential"):
            self.e.run("type", h, flag, str(self.e.token), check=2)
        self.e.run("type", h, stdin=str(self.e.token), check=2)
        self.assertEqual(self.command_bodies(), [])


class TokenLeak(Base):
    """AC-3: the sentinel token never appears in argv, child env, stdout/stderr, state, the shot index or the screenshot."""

    def _snapshot_while_held(self, args, hold):
        self.api.hold.add(hold)
        self.api.held.clear()
        p = self.e.popen(*args)
        self.assertTrue(self.api.held.wait(15), "request never reached the fake")
        table = subprocess.run(["ps", "-axww", "-o", "pid=,ppid=,command="], capture_output=True, text=True).stdout
        env = subprocess.run(["ps", "eww", "-p", str(p.pid)], capture_output=True, text=True).stdout
        children = [l for l in table.splitlines() if l.split()[1:2] == [str(p.pid)]]
        self.api.release()
        out, err = p.communicate(timeout=30)
        self.e.outputs += [out, err, table, env]
        self.api.unhold.clear()
        self.assertEqual(children, [], "the client must spawn no child processes")
        self.assertNotIn(USER_TOKEN, table)
        self.assertNotIn(USER_TOKEN, env)
        self.assertIn(str(p.pid), table)
        return p.returncode

    def test_every_action_keeps_the_token_out_of_ps_outputs_and_files(self):
        self.assertEqual(self._snapshot_while_held(["open", MACHINE], ("POST", r"/leases$")), 0)
        h = json.loads(self.e.outputs[0])["handle"]
        self.assertEqual(self._snapshot_while_held(["shot", h], ("GET", r"/machine-artifacts/")), 0)
        self.assertEqual(self._snapshot_while_held(["click", h, "--x", "3", "--y", "4"], ("GET", r"/machine-commands/")), 0)
        self.assertEqual(self._snapshot_while_held(["type", h, "--text", "abc"], ("GET", r"/machine-commands/")), 0)
        self.assertEqual(self._snapshot_while_held(["key", h, "--keys", "Return"], ("GET", r"/machine-commands/")), 0)
        self.assertEqual(self._snapshot_while_held(["close", h], ("POST", r"/release$")), 0)
        shots = list((self.e.root / h / "shots").iterdir())
        self.assertEqual(len(shots), 1)
        for r in self.api.requests:
            self.assertEqual(r["auth"], "Bearer " + USER_TOKEN)  # sent only as the header, to the allowed base
            self.assertNotIn(USER_TOKEN, json.dumps(r["body"]))
        files = [f for f in self.e.home.rglob("*") if f.is_file()]
        self.assertTrue(all(str(f.resolve()).startswith(str(self.e.root.resolve())) or f.parent == self.e.token.parent for f in files), files)


class Interrupts(Base):
    """AC-5: release always runs; no lease leaks after a crash or interrupt."""

    def _interrupt(self, sig, args, hold):
        self.api.hold.add(hold)
        self.api.held.clear()
        p = self.e.popen(*args)
        self.assertTrue(self.api.held.wait(15))
        p.send_signal(sig)
        time.sleep(0.3)
        self.api.release()
        out, err = p.communicate(timeout=30)
        self.e.outputs += [out, err]
        self.api.unhold.clear()
        return p.returncode

    def test_sigterm_mid_action_cancels_and_releases(self):
        h = self.e.open()
        rc = self._interrupt(signal.SIGTERM, ["shot", h], ("GET", r"/machine-commands/[^/]+$"))
        self.assertNotEqual(rc, 0)
        self.assertEqual(len(self.api.calls("POST", r"/cancel$")), 1)
        self.assertEqual(self.api.calls("POST", r"/release$")[0]["body"], {"holder": "gq-machine:" + h})
        self.assertTrue(self.e.state(h)["closed"])

    def test_sigint_mid_action_cancels_and_releases(self):
        h = self.e.open()
        self._interrupt(signal.SIGINT, ["type", h, "--text", "abc"], ("GET", r"/machine-commands/[^/]+$"))
        self.assertEqual(len(self.api.calls("POST", r"/release$")), 1)
        self.assertTrue(self.e.state(h)["closed"])

    def test_sigterm_during_open_releases_the_lease_the_server_may_have_made(self):
        rc = self._interrupt(signal.SIGTERM, ["open", MACHINE], ("POST", r"/leases$"))
        self.assertNotEqual(rc, 0)
        self.assertEqual(len(self.api.calls("POST", r"/release$")), 1)
        rows = json.loads(self.e.run("list", "--orphans", check=0).stdout)["leases"]
        self.assertEqual(rows, [])

    def test_lost_lease_response_is_recovered_by_holder_and_released(self):
        # The create answer is lost: the server may hold a lease. The client re-asks once with the SAME holder (the server
        # adopts that holder's live lease, service.ts:871; never a wider scope), releases it and reports the failure.
        self.api.drop_once.add(("POST", r"/leases$"))
        p = self.e.run("open", MACHINE, check=1)
        self.assertIn("no response", p.stderr)
        leases = self.api.calls("POST", r"/leases$")
        self.assertEqual(len(leases), 2)
        self.assertEqual(leases[0]["body"], leases[1]["body"])
        self.assertEqual(len(self.api.calls("POST", r"/release$")), 1)
        self.assertEqual(json.loads(self.e.run("list", "--orphans", check=0).stdout)["leases"], [])

    def test_sigkill_leaves_an_orphan_that_close_releases(self):
        h = self.e.open()
        self.api.hold.add(("GET", r"/machine-commands/[^/]+$"))
        self.api.held.clear()
        p = self.e.popen("click", h, "--x", "1", "--y", "1")
        self.assertTrue(self.api.held.wait(15))
        p.kill()
        p.communicate(timeout=30)
        self.api.release()
        rows = json.loads(self.e.run("list", "--orphans", check=0).stdout)["leases"]
        self.assertEqual([r["handle"] for r in rows], [h])
        self.e.run("close", h, check=0)
        self.assertEqual(len(self.api.calls("POST", r"/release$")), 1)


class Mcp(Base):
    def _rpc(self, p, mid, method, params=None):
        p.stdin.write(json.dumps({"jsonrpc": "2.0", "id": mid, "method": method, "params": params or {}}) + "\n")
        p.stdin.flush()
        return json.loads(p.stdout.readline())

    def test_mcp_tools_drive_a_lease_and_release_it_when_the_server_exits(self):
        p = self.e.popen(mcp=True)
        names = {t["name"] for t in self._rpc(p, 1, "tools/list")["result"]["tools"]}
        self.assertTrue({"gq_machine_open", "gq_machine_screenshot", "gq_machine_click", "gq_machine_type", "gq_machine_key",
                         "gq_machine_close"} <= names)
        for t in self._rpc(p, 2, "tools/list")["result"]["tools"]:
            if t["name"].startswith("gq_machine_"):
                self.assertNotIn("kind", t["inputSchema"]["properties"])
        r = self._rpc(p, 3, "tools/call", {"name": "gq_machine_open", "arguments": {"machineId": MACHINE}})
        h = json.loads(r["result"]["content"][0]["text"])["handle"]
        r = self._rpc(p, 4, "tools/call", {"name": "gq_machine_click", "arguments": {"handle": h, "x": 5, "y": 6, "kind": "shell"}})
        self.assertTrue(r["result"]["isError"])
        r = self._rpc(p, 5, "tools/call", {"name": "gq_machine_type", "arguments": {"handle": h, "text": USER_TOKEN}})
        self.assertTrue(r["result"]["isError"])
        self.assertNotIn(USER_TOKEN, json.dumps(r))
        r = self._rpc(p, 6, "tools/call", {"name": "gq_machine_key", "arguments": {"handle": h, "keys": "Return"}})
        self.assertFalse(r["result"].get("isError"), r)
        out, err = p.communicate(timeout=30)  # closes stdin: the server sees EOF and must release what it opened
        self.e.outputs += [out, err]
        self.assertEqual(len(self.api.calls("POST", r"/release$")), 1)
        self.assertTrue(self.e.state(h)["closed"])


if __name__ == "__main__":
    unittest.main()
