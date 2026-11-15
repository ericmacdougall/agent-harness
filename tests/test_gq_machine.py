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


RELEASED_AT = "2026-11-14T22:00:00.000Z"


def lease_id(n):
    """The n-th lease the fake makes: LEASE first, then other strict uuids."""
    return LEASE if n == 0 else "%08x-9999-4999-8999-999999999999" % (0x99999999 - n)


class FakeMachines:
    """Mirrors routes.ts for a user token with an enrollment grant on MACHINE. Knobs: fail[(method, suffix)] = (status, code),
    drop = {(method, suffix)} closes the connection without an answer, hold = {(method, suffix)} blocks until release(),
    mutate(method, path, status, body) -> (status, body) rewrites every JSON answer (the hostile-server tests).

    Leases follow service.ts (bugtracker dbb83448): the same holder adopts its live lease (acquireLease); release checks the
    holder first (requireLeaseHolder: 409 lease_holder_mismatch), then answers 200 with releasedAt, also for a lease that
    had already ended (releaseLease returns row ?? lease); renew of an ended lease is 409 lease_ended (renewLease)."""

    def __init__(self, token=USER_TOKEN):
        self.token = token
        self.mutate = None
        self.requests = []
        self.fail = {}
        self.drop = set()
        self.drop_once = set()
        self.hold = set()
        self.hold_after = set()  # {(method, suffix)}: the route runs (the server applied it), then the answer waits
        self.held = threading.Event()
        self.unhold = threading.Event()
        self.command_status = "ok"
        self.lease_status = 201
        self.lease_reason = None
        self.lease_expires = "2026-11-14T23:00:00.000Z"
        self.artifact_bytes = PNG
        self.artifact_ids = [ARTIFACT]
        self.leases = {}  # holder -> live lease id
        self.lease_rows = {}  # lease id -> {"holder": h, "released": bool}
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
                        return self._json(status, {"error": {"code": code, "message": "denied for " + api.token}})
                if self.headers.get("authorization") != "Bearer " + api.token:
                    return self._json(401, {"error": {"code": "unauthorized", "message": "no"}})
                return api.route(self, method, path[len("/v1"):], body)

            def _json(self, status, obj):
                for (m, suffix) in list(api.hold_after):
                    if m == self.command and re.search(suffix, urllib.parse.urlparse(self.path).path):
                        api.held.set()
                        api.unhold.wait(20)
                if api.mutate:
                    status, obj = api.mutate(self.command, urllib.parse.urlparse(self.path).path, status, obj)
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
                body202 = {"approval": {"askId": "ask", "status": "pending"}}
                if self.lease_reason:
                    body202["reason"] = self.lease_reason
                return h._json(202, body202)
            holder = (body or {}).get("holder")
            with self.lock:
                lid = self.leases.get(holder)
                if lid is None or self.lease_rows[lid]["released"]:  # service.ts:871: the same holder adopts its live lease
                    lid = lease_id(len(self.lease_rows))
                    self.leases[holder] = lid
                    self.lease_rows[lid] = {"holder": holder, "released": False}
            return h._json(201, {"lease": {"id": lid, "machineId": MACHINE, "mode": "control", "expiresAt": self.lease_expires,
                                           "releasedAt": None}})
        m = re.match(r"^/machine-leases/([0-9a-f-]{36})/(release|renew)$", p)
        if method == "POST" and m:
            row = self.lease_rows.get(m.group(1))
            if row is None:
                return h._json(404, {"error": {"code": "not_found", "message": "Lease not found"}})
            if m.group(2) == "renew" and row["released"]:
                return h._json(409, {"error": {"code": "lease_ended", "message": "This lease was released"}})
            if (body or {}).get("holder") != row["holder"]:
                return h._json(409, {"error": {"code": "lease_holder_mismatch", "message": "send its matching holder"}})
            if m.group(2) == "release":
                row["released"] = True
            return h._json(200, {"lease": {"id": m.group(1), "machineId": MACHINE, "mode": "control",
                                           "releasedAt": RELEASED_AT if row["released"] else None, "expiresAt": self.lease_expires}})
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

    def seed(self, holder, lid=LEASE):
        """Register a live lease made outside the fake's create route (the tests that write state.json directly)."""
        with self.lock:
            self.leases[holder] = lid
            self.lease_rows[lid] = {"holder": holder, "released": False}

    def calls(self, method=None, pattern=None):
        return [r for r in self.requests if (method is None or r["method"] == method) and (pattern is None or re.search(pattern, r["path"]))]

    def release(self):
        self.hold.clear()
        self.hold_after.clear()
        self.unhold.set()

    def close(self):
        self.release()
        self.server.shutdown()
        self.server.server_close()


class Env:
    def __init__(self, api, defaults=None, allow=True):
        self.tmp = tempfile.TemporaryDirectory()
        self.home = Path(self.tmp.name) / "home"
        cfg = self.home / ".config" / "goodqa"
        cfg.mkdir(parents=True)
        self.token = cfg / "user-token"
        self.token_value = api.token
        self.token.write_text(api.token + "\n")
        os.chmod(self.token, 0o600)
        d = {"allowedBases": [api.base]}
        if allow:
            d["allowedMachines"] = [MACHINE]
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
        t = self.token_value
        forms = {t, base64.b64encode(t.encode()).decode(), urllib.parse.quote(t, safe="")}
        forms |= {t[i:i + 12] for i in range(len(t) - 11)}
        return [f for f in forms if any(f in b for b in blobs)]

    def seed(self, api, lease=LEASE):
        """A local open lease without a request: the state op_machine_open writes after a 201 (hostile-server tests)."""
        handle = os.urandom(8).hex()
        self.root.mkdir(parents=True, exist_ok=True)
        for p in (self.root.parent, self.root):
            os.chmod(p, 0o700)
        d = self.root / handle
        d.mkdir(mode=0o700)
        holder = "gq-machine:" + handle
        state = {"kind": "machine", "handle": handle, "machineId": MACHINE, "base": api.base, "holder": holder, "ttl": 300,
                 "leaseId": lease, "leaseRequested": True, "closed": False, "createdAt": "2026-11-14T21:00:00.000Z",
                 "expiresAt": "2026-11-14T23:00:00.000Z"}
        (d / "state.json").write_text(json.dumps(state))
        api.seed(holder, lease)
        return handle

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
        self.e = Env(self.api, {"allowedMachines": [MACHINE, OTHER]})  # allowed locally, refused by the server's grant
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

    def test_lease_not_yours_on_command_or_renew_does_not_close_the_lease(self):
        # rescue r3 class B: lease_not_yours (service.ts createCommand) is no termination signal.
        h = self.e.open()
        for args, route in ((["click", h, "--x", "1", "--y", "1"], ("POST", r"/commands$")), (["renew", h], ("POST", r"/renew$"))):
            self.api.fail[route] = (409, "lease_not_yours")
            self.e.run(*args, check=1)
            del self.api.fail[route]
            self.assertFalse(self.e.state(h)["closed"], args[0])
        self.assertEqual([r["handle"] for r in json.loads(self.e.run("list", "--orphans", check=0).stdout)["leases"]], [h])

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

    def test_no_allowed_machines_list_fails_closed(self):
        # red-team r1 F3: without allowedMachines any machine the token's grants reach (the user's own Mac) could be driven.
        self.e = Env(self.api, allow=False)
        p = self.e.run("open", MACHINE, check=2)
        self.assertIn("allowedMachines", p.stderr)
        self.assertEqual(self.api.requests, [])

    def test_forged_state_fields_are_refused_before_any_request(self):
        # red-team r1 F4: leaseId, holder and ttl from state.json must never steer an authenticated request.
        h = self.e.open()
        good = self.e.state(h)
        n = len(self.api.requests)
        for field, value in (("leaseId", "../../api-keys/%s/revoke" % LEASE), ("holder", "gq-machine:0000000000000000"),
                             ("ttl", 999999), ("leaseId", 7), ("machineId", OTHER)):
            bad = dict(good)
            bad[field] = value
            (self.e.root / h / "state.json").write_text(json.dumps(bad))
            for args in (["click", h, "--x", "1", "--y", "1"], ["renew", h], ["close", h]):
                self.e.run(*args, check=2)
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
        # NEG-8 (red-team r1 F6): the lease is released too
        self.assertEqual(len(self.api.calls("POST", r"/release$")), 1)
        self.assertTrue(self.e.state(h)["closed"])

    def test_error_code_holding_the_token_is_never_printed(self):
        # red-team r1 F5: a hostile error.code is not a safe code; tearDown's leak scan fails if it reaches stderr.
        self.api.fail[("GET", r"/machines/")] = (403, USER_TOKEN)
        self.e.run("open", MACHINE, check=1)

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

    def test_unlisted_error_codes_print_as_unrecognized(self):
        # PR 250 receipt F2: only allow-listed server codes are printed; a lowercase token or any fragment is not.
        low = USER_TOKEN.lower()
        for code in (low, low[5:17], low[5:13], low[5:9], "GqU_MiXeD", "q1w2e3r4t5y6", "not_found_" + low[5:12]):
            self.api.fail[("GET", r"/machines/")] = (403, code)
            p = self.e.run("open", MACHINE, check=1)
            self.assertIn("unrecognized_error", p.stderr)
            self.assertNotIn(code, p.stderr)
            self.assertNotIn(code.lower(), p.stderr.lower().replace("unrecognized_error", ""))

    def test_echoed_lease_expiry_never_reaches_output_or_state(self):
        # red-team r3 B1: expiresAt is a server value; only an ISO-8601 UTC timestamp is kept. tearDown scans for the token.
        self.api.lease_expires = "echo " + USER_TOKEN
        h = self.e.open()
        self.assertIsNone(self.e.state(h)["expiresAt"])
        self.e.run("renew", h, check=0)
        self.e.run("list", check=0)
        self.api.lease_expires = "2026-11-14T23:00:00.123Z"
        h2 = self.e.open()
        self.assertEqual(self.e.state(h2)["expiresAt"], "2026-11-14T23:00:00.123Z")

    def test_auth_gate_codes_print(self):
        # red-team r3 M1: an expired token is the likeliest real failure; its code must be readable.
        for code in ("user_token_expired", "user_token_rate_limited", "payload_too_large"):
            self.api.fail[("GET", r"/machines/")] = (401, code)
            self.assertIn(code, self.e.run("open", MACHINE, check=1).stderr)

    def test_every_allow_listed_code_still_prints(self):
        import importlib.util
        spec = importlib.util.spec_from_file_location("gqb_under_test", str(CLIENT))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        self.assertGreater(len(mod.KNOWN_CODES), 20)
        api = mod.Api(self.api.base, USER_TOKEN)
        for code in sorted(mod.KNOWN_CODES):
            self.api.fail[("GET", r"/machines/")] = (403, code)
            with self.assertRaises(mod.ApiError) as cm:
                api.call("GET", "/machines/" + MACHINE, USER_TOKEN)
            self.assertEqual(cm.exception.code, code)
            self.assertIn(code, str(cm.exception))

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

    def test_key_refuses_the_token_and_secret_shapes(self):
        # red-team r1 F2: key args are stored server-side like type text.
        h = self.e.open()
        n = len(self.api.requests)
        for keys in (USER_TOKEN, "gqu_" + "A" * 30, "x " + USER_TOKEN[3:15]):
            p = self.e.run("key", h, "--keys", keys, check=2)
            self.assertNotIn(keys, p.stderr + p.stdout)
        self.assertEqual(len(self.api.requests), n)

    def test_more_secret_shapes_are_refused(self):
        # red-team r1 F10
        h = self.e.open()
        n = len(self.api.requests)
        for text in ("sk-proj-" + "a" * 24, "dop_v1_" + "b" * 40, "glpat-" + "c" * 20, "whsec_" + "d" * 24, "ya29." + "e" * 30,
                     "npm_" + "f" * 36, "xapp-1-" + "g" * 20):
            self.e.run("type", h, "--text", text, check=2)
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

    def test_lease_answer_lost_twice_stays_an_orphan_that_close_recovers(self):
        # red-team r1 F1: with both the create and the recovery answer lost, a server lease may exist: never mark it closed.
        self.api.drop.add(("POST", r"/leases$"))
        self.e.run("open", MACHINE, check=1)
        self.assertEqual(self.api.calls("POST", r"/release$"), [])
        rows = json.loads(self.e.run("list", "--orphans", check=0).stdout)["leases"]
        self.assertEqual(len(rows), 1)
        self.api.drop.clear()
        p = self.e.run("close", rows[0]["handle"], check=0)
        self.assertEqual(json.loads(p.stdout)["result"], "released")
        self.assertEqual(len(self.api.calls("POST", r"/release$")), 1)

    def test_recovery_refusal_other_than_absent_keeps_the_lease_listed(self):
        # PR 250 receipt F1 and rescue r3 class B: after a lost create, a re-ask answer proves there is no lease of ours
        # only when it is a 202 with reason access_mode (service.ts acquireLease asks only when this principal holds no
        # live control lease). A 404 may be the machines switch or the grant (routes.ts machineFor), lease_held may be our
        # own holderless lease, lease_not_yours is never sent by acquireLease: all of them keep the lease listed.
        for status, code in ((500, "internal_error"), (429, "rate_limited"), (403, "forbidden"), (409, "lease_held"),
                             (404, "not_found"), (409, "lease_not_yours"), (409, "conflict"), (409, "zz_new_code"), (401, "unauthorized")):
            before = len(json.loads(self.e.run("list", "--orphans", check=0).stdout)["leases"])
            self.api.drop_once.add(("POST", r"/leases$"))
            self.api.fail[("POST", r"/leases$")] = (status, code)
            p = self.e.run("open", MACHINE, check=1)
            self.assertIn("lease kept open", p.stderr, (status, code))
            del self.api.fail[("POST", r"/leases$")]
            rows = json.loads(self.e.run("list", "--orphans", check=0).stdout)["leases"]
            self.assertEqual(len(rows), before + 1, (status, code))

    def test_recovery_approval_ask_proves_absence_only_for_access_mode(self):
        for reason, listed in (("access_mode", 0), ("machine_paused", 1), (None, 1)):
            before = len(json.loads(self.e.run("list", "--orphans", check=0).stdout)["leases"])
            self.api.drop_once.add(("POST", r"/leases$"))
            self.api.lease_status, self.api.lease_reason = 202, reason
            self.e.run("open", MACHINE, check=1)
            self.api.lease_status, self.api.lease_reason = 201, None
            rows = json.loads(self.e.run("list", "--orphans", check=0).stdout)["leases"]
            self.assertEqual(len(rows), before + listed, reason)

    def test_create_redirect_is_treated_like_a_lost_answer(self):
        # A 3xx is no refusal: the create may have run before a proxy redirected it, so cleanup re-asks with the holder.
        self.api.fail[("POST", r"/leases$")] = (303, "bad_request")
        self.e.run("open", MACHINE, check=1)
        self.assertEqual(len(self.api.calls("POST", r"/leases$")), 2)
        self.assertEqual(len(json.loads(self.e.run("list", "--orphans", check=0).stdout)["leases"]), 1)

    def test_create_5xx_is_treated_like_a_lost_answer(self):
        # A 5xx on create does not prove the server made no lease: recover with the same holder and release.
        self.api.fail[("POST", r"/leases$")] = (502, "internal_error")
        self.e.run("open", MACHINE, check=1)
        self.assertEqual(len(self.api.calls("POST", r"/leases$")), 2)
        self.assertEqual(len(json.loads(self.e.run("list", "--orphans", check=0).stdout)["leases"]), 1)

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


DRIVER = r'''
"""Test driver: load gq_browser from argv[1], pause at one point (GQ_TEST_PAUSE=kind:arg), then run its main()."""
import importlib.util, json, os, re, sys, time
spec = importlib.util.spec_from_file_location("gq_browser_under_test", sys.argv[1])
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
marker = os.environ.get("GQ_TEST_MARKER")


def pause():
    open(marker, "w").close()
    for _ in range(400):  # a signal raises out of sleep; inside a release shield it is deferred, so stop waiting
        if getattr(mod, "_PENDING", None):
            return
        time.sleep(0.05)


kind, _, arg = (os.environ.get("GQ_TEST_PAUSE") or "none:").partition(":")
if kind == "send":  # before the first request whose "METHOD path" matches arg is sent
    orig_call = mod.Api.call

    def call(self, method, path, *a, **k):
        if re.search(arg, method + " " + path) and not os.path.exists(marker):
            pause()
        return orig_call(self, method, path, *a, **k)
    mod.Api.call = call
elif kind == "save":  # inside the arg-th state write, after the temp file is written and before the rename
    orig_save, count = mod.save_state, [0]

    def save_state(d, state):
        count[0] += 1
        if count[0] != int(arg):
            return orig_save(d, state)
        tmp = os.path.join(d, ".state.test.tmp")
        mod.write_new(tmp, json.dumps(state, sort_keys=True).encode())
        pause()
        os.replace(tmp, os.path.join(d, "state.json"))
    mod.save_state = save_state
elif kind == "write":  # before writing a file whose name ends with arg
    orig_write = mod.write_new

    def write_new(path, data, *a, **k):
        if path.endswith(arg):
            pause()
        return orig_write(path, data, *a, **k)
    mod.write_new = write_new
sys.exit(mod.main(sys.argv[2:]))
'''

CMD = r"/machines/[^/]+/commands$"
POINTS = {
    "open": [("send", r"^POST .*/leases$"), ("hold", ("POST", r"/leases$")), ("hold_after", ("POST", r"/leases$")), ("save", "3")],
    "renew": [("send", r"^POST .*/renew$"), ("hold", ("POST", r"/renew$")), ("hold_after", ("POST", r"/renew$")), ("save", "1")],
    "click": [("send", r"^POST .*/commands$"), ("hold", ("POST", CMD)), ("hold_after", ("POST", CMD)), ("hold", ("GET", r"/machine-commands/[^/]+$"))],
    "type": [("send", r"^POST .*/commands$"), ("hold", ("POST", CMD)), ("hold_after", ("POST", CMD)), ("hold", ("GET", r"/machine-commands/[^/]+$"))],
    "key": [("send", r"^POST .*/commands$"), ("hold", ("POST", CMD)), ("hold_after", ("POST", CMD)), ("hold", ("GET", r"/machine-commands/[^/]+$"))],
    "shot": [("send", r"^POST .*/commands$"), ("hold_after", ("POST", CMD)), ("hold", ("GET", r"/machine-artifacts/")), ("write", ".png")],
    "close": [("send", r"^POST .*/release$"), ("hold", ("POST", r"/release$")), ("hold_after", ("POST", r"/release$"))],
}
ARGV = {"open": lambda h: ["open", MACHINE], "renew": lambda h: ["renew", h], "click": lambda h: ["click", h, "--x", "1", "--y", "2"],
        "type": lambda h: ["type", h, "--text", "hello"], "key": lambda h: ["key", h, "--keys", "Return"], "shot": lambda h: ["shot", h],
        "close": lambda h: ["close", h]}
SIGS = {signal.SIGINT: "SIGINT", signal.SIGTERM: "SIGTERM"}


class InterruptTable(Base):
    """PR 250 v3 receipt F1, as a class: verb x interrupt point x signal x release outcome. Every cell must end in a
    confirmed release or an open lease listed by list --orphans, and the message must state that outcome. Ground truth
    is the fake's lease row, not the client's words."""

    def setUp(self):
        super().setUp()
        self.driver = Path(self.e.tmp.name) / "driver.py"
        self.driver.write_text(DRIVER)

    def live(self, h):
        return any(r["holder"] == "gq-machine:" + h and not r["released"] for r in self.api.lease_rows.values())

    def orphans(self):
        return [r["handle"] for r in json.loads(self.e.run("list", "--orphans", check=0).stdout)["leases"]]

    def run_cell(self, argv, point, sig, outcome, n):
        api = self.api
        api.fail.clear()
        api.held.clear()
        api.unhold.clear()
        env = dict(self.e.env)
        marker = Path(self.e.tmp.name) / ("marker-%d" % n)
        kind, arg = point
        if outcome == "fail":
            api.fail[("POST", r"/release$")] = (500, "internal_error")
        if kind in ("send", "save", "write"):
            env["GQ_TEST_PAUSE"], env["GQ_TEST_MARKER"] = "%s:%s" % (kind, arg), str(marker)
        elif kind == "hold":
            api.hold.add(arg)
        else:
            api.hold_after.add(arg)
        proc = subprocess.Popen([sys.executable, "-I", str(self.driver), str(CLIENT), "machine", *argv], stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True, env=env)
        deadline, reached = time.time() + 15, False
        while time.time() < deadline and not reached:
            reached = marker.exists() if kind in ("send", "save", "write") else api.held.is_set()
            time.sleep(0.02)
        if reached:
            proc.send_signal(sig)
            time.sleep(0.2)
        api.release()
        out, err = proc.communicate(timeout=60)
        api.unhold.clear()
        api.fail.clear()
        self.e.outputs += [out, err]
        return reached, proc.returncode, out, err

    def check(self, verb, h, reached, rc, err, sig, cmds_before, cancels_before, command_done=False):
        problems = []
        if not reached:
            return ["pause point never reached"]
        if rc != 128 + sig:
            problems.append("rc %s" % rc)
        if "interrupted (%s)" % SIGS[sig] not in err:
            problems.append("no interrupt message")
        closed = self.e.state(h)["closed"]
        if closed != (not self.live(h)):
            problems.append("local closed=%s but server live=%s" % (closed, self.live(h)))
        if closed and "NOT released" in err:
            problems.append("closed yet reported NOT released")
        if closed and not re.search(r"released \(|already closed|nothing_to_release", err):
            problems.append("closed without a stated release")
        if not closed and ("NOT released" not in err or h not in self.orphans()):
            problems.append("open lease not reported or not listed")
        queued = len(self.api.commands) > cmds_before
        cancelled = len(self.api.calls("POST", r"/cancel$")) > cancels_before
        if queued and not command_done and not cancelled and "may still run" not in err:
            problems.append("a queued command was neither cancelled nor reported")
        if not closed:  # the orphan must still be releasable
            p = self.e.run("close", h)
            if p.returncode != 0 or self.live(h):
                problems.append("retry close did not release (%s)" % p.returncode)
        return problems

    def test_every_verb_point_signal_and_release_outcome(self):
        failures, n = [], 0
        for verb, points in POINTS.items():
            for point in points:
                for sig in SIGS:
                    for outcome in ("ok", "fail"):
                        n += 1
                        h = None if verb == "open" else self.e.seed(self.api)
                        before = set(os.listdir(self.e.root)) if self.e.root.exists() else set()
                        cmds, cancels = len(self.api.commands), len(self.api.calls("POST", r"/cancel$"))
                        reached, rc, out, err = self.run_cell(ARGV[verb](h), point, sig, outcome, n)
                        if h is None:
                            new = set(os.listdir(self.e.root)) - before
                            if len(new) != 1:
                                failures.append("%s %s %s %s: %d new handles" % (verb, point, SIGS[sig], outcome, len(new)))
                                continue
                            h = new.pop()
                        # shot's artifact fetch and file write come after the command reached a terminal state
                        done = verb == "shot" and point[0] in ("write",) or point == ("hold", ("GET", r"/machine-artifacts/"))
                        problems = self.check(verb, h, reached, rc, err, sig, cmds, cancels, command_done=done)
                        if problems:
                            failures.append("%s %s %s %s: %s | %s" % (verb, point[0], SIGS[sig], outcome, "; ".join(problems), err.strip()[-160:]))
        self.assertEqual(n, 108)
        self.assertEqual(failures, [], "%d of %d cells failed:\n%s" % (len(failures), n, "\n".join(failures)))

    def test_mcp_renew_on_a_handle_it_did_not_open(self):
        for sig in SIGS:
            for outcome in ("ok", "fail"):
                h = self.e.seed(self.api)
                self.api.held.clear()
                if outcome == "fail":
                    self.api.fail[("POST", r"/release$")] = (500, "internal_error")
                self.api.hold_after.add(("POST", r"/renew$"))
                proc = self.e.popen(mcp=True)
                proc.stdin.write(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                                             "params": {"name": "gq_machine_renew", "arguments": {"handle": h}}}) + "\n")
                proc.stdin.flush()
                self.assertTrue(self.api.held.wait(15))
                proc.send_signal(sig)
                time.sleep(0.2)
                self.api.release()
                out, err = proc.communicate(timeout=60)
                self.api.unhold.clear()
                self.api.fail.clear()
                self.e.outputs += [out, err]
                problems = self.check("renew", h, True, proc.returncode, err, sig, len(self.api.commands), len(self.api.calls("POST", r"/cancel$")))
                self.assertEqual(problems, [], (SIGS[sig], outcome, err))

    def test_unexpected_local_error_after_a_renew_reports_the_lease_still_open(self):
        h = self.e.seed(self.api)
        d = self.e.root / h
        os.chmod(d, 0o500)  # the server applies the renew; the state write then fails
        try:
            p = self.e.run("renew", h)
        finally:
            os.chmod(d, 0o700)
        self.assertEqual(p.returncode, 1, p.stderr)
        self.assertIn("is still open", p.stderr)
        self.assertFalse(self.e.state(h)["closed"])
        self.assertTrue(self.live(h))
        self.assertIn(h, self.orphans())
        self.e.run("close", h, check=0)
        self.assertFalse(self.live(h))


class Mcp(Base):
    def _rpc(self, p, mid, method, params=None):
        p.stdin.write(json.dumps({"jsonrpc": "2.0", "id": mid, "method": method, "params": params or {}}) + "\n")
        p.stdin.flush()
        line = p.stdout.readline()
        self.e.outputs.append(line)  # every MCP answer is scanned by tearDown too
        return json.loads(line)

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


class ReleaseUncertainty(Base):
    """Rescue r3 class B: only a positive end signal closes a lease. Anything else keeps it open, listed, retryable, and
    the verb reports failure. Server contract: bugtracker dbb83448 machines/routes.ts release (leaseFor, machineFor) and
    service.ts releaseLease / requireLeaseHolder / leaseEndedError; openapi.ts documents 200 {lease} and 409
    lease_holder_mismatch for release."""

    def orphans(self):
        return [r["handle"] for r in json.loads(self.e.run("list", "--orphans", check=0).stdout)["leases"]]

    def assert_open_then_retry_releases(self, h):
        self.assertFalse(self.e.state(h)["closed"])
        self.assertIn(h, self.orphans())
        self.api.fail.clear()
        self.api.drop.clear()
        self.api.mutate = None
        p = self.e.run("close", h, check=0)
        self.assertEqual(json.loads(p.stdout)["result"], "released")
        self.assertTrue(self.e.state(h)["closed"])
        self.assertNotIn(h, self.orphans())

    def test_unrelated_409_on_release_keeps_the_lease_then_retry_releases(self):
        # v2 receipt F2: a lease_holder_mismatch 409 says the lease is live under another holder, not that it ended.
        h = self.e.open()
        self.api.fail[("POST", r"/release$")] = (409, "lease_holder_mismatch")
        p = self.e.run("close", h, check=1)
        self.assertIn("release_failed (HTTP 409 lease_holder_mismatch)", p.stderr)
        self.assertIn("lease kept open", p.stderr)
        self.assert_open_then_retry_releases(h)

    def test_unrecognized_409_code_on_release_keeps_the_lease(self):
        for code in ("conflict", "zz_brand_new_code", "already_released", "lease_held"):
            h = self.e.open()
            self.api.fail[("POST", r"/release$")] = (409, code)
            self.e.run("close", h, check=1)
            self.assert_open_then_retry_releases(h)

    def _sigterm_mid_click(self, h):
        self.api.hold.add(("GET", r"/machine-commands/[^/]+$"))
        self.api.held.clear()
        proc = self.e.popen("click", h, "--x", "1", "--y", "1")
        reached = self.api.held.wait(5)
        if reached:
            proc.send_signal(signal.SIGTERM)
            time.sleep(0.3)
        self.api.release()
        out, err = proc.communicate(timeout=30)
        self.e.outputs += [out, err]
        self.api.unhold.clear()
        return proc.returncode, err

    def test_release_errors_at_every_entry_point_keep_the_lease_open(self):
        # 5xx, 429, 403, 404 (machineFor and leaseFor share it), 401 and a lost answer, through close, the cleanup of a
        # failed open, the awaiting-approval cleanup, SIGTERM mid-action and the MCP server's exit.
        failures = [(500, "internal_error"), (503, "database_busy"), (429, "rate_limited"), (403, "forbidden"),
                    (404, "not_found"), (401, "user_token_expired"), "lost"]

        def arm(f):
            if f == "lost":
                self.api.drop.add(("POST", r"/release$"))
            else:
                self.api.fail[("POST", r"/release$")] = f

        for f in failures:
            with self.subTest(entry="close", failure=f):
                h = self.e.open()
                arm(f)
                self.e.run("close", h, check=1)
                self.assert_open_then_retry_releases(h)
            with self.subTest(entry="open cleanup", failure=f):
                before = set(self.orphans())
                self.api.drop_once.add(("POST", r"/leases$"))
                arm(f)
                p = self.e.run("open", MACHINE, check=1)
                self.assertIn("lease_recovered", p.stderr)
                new = set(self.orphans()) - before
                self.assertEqual(len(new), 1)
                self.assert_open_then_retry_releases(new.pop())
            with self.subTest(entry="awaiting approval", failure=f):
                h = self.e.open()
                self.api.command_status = "awaiting_approval"
                arm(f)
                self.e.run("click", h, "--x", "1", "--y", "1", check=1)
                self.api.command_status = "ok"
                self.assert_open_then_retry_releases(h)
            with self.subTest(entry="sigterm", failure=f):
                h = self.e.open()
                arm(f)
                rc, _ = self._sigterm_mid_click(h)
                self.assertNotEqual(rc, 0)
                self.assert_open_then_retry_releases(h)
            with self.subTest(entry="mcp exit", failure=f):
                proc = self.e.popen(mcp=True)
                proc.stdin.write(json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                                             "params": {"name": "gq_machine_open", "arguments": {"machineId": MACHINE}}}) + "\n")
                proc.stdin.flush()
                line = proc.stdout.readline()
                self.e.outputs.append(line)
                h = json.loads(json.loads(line)["result"]["content"][0]["text"])["handle"]
                arm(f)
                out, err = proc.communicate(timeout=30)
                self.e.outputs += [out, err]
                self.assert_open_then_retry_releases(h)

    def test_a_2xx_release_that_does_not_name_the_lease_released_is_no_proof(self):
        # service.ts releaseLease returns `row ?? lease`: a stale row can come back with releasedAt null.
        bodies = [{}, {"lease": {"id": LEASE, "releasedAt": None}}, {"lease": {"id": OTHER, "releasedAt": RELEASED_AT}},
                  {"lease": {"id": LEASE, "releasedAt": "yes"}}, {"ok": True}]
        for b in bodies:
            h = self.e.open()

            def mutate(method, path, status, body, b=b):
                return (200, b) if path.endswith("/release") else (status, body)
            self.api.mutate = mutate
            p = self.e.run("close", h, check=1)
            self.assertIn("release_unconfirmed", p.stderr, b)
            self.assert_open_then_retry_releases(h)

    def test_lease_ended_on_release_closes(self):
        # The contract's ended code (service.ts leaseEndedError) is the one 409 that proves the end.
        h = self.e.open()
        self.api.fail[("POST", r"/release$")] = (409, "lease_ended")
        p = self.e.run("close", h, check=0)
        self.assertIn("already_ended (lease_ended)", p.stdout)
        self.assertTrue(self.e.state(h)["closed"])
        self.assertNotIn(h, self.orphans())

    def test_orphan_without_a_lease_id_refuses_actions_and_an_interrupt_never_hides_it(self):
        # _mrelease(recover=False) with leaseRequested and no leaseId used to fall through to closed.
        self.api.drop.add(("POST", r"/leases$"))
        self.e.run("open", MACHINE, check=1)
        self.api.drop.clear()
        (h,) = self.orphans()
        self.assertIsNone(self.e.state(h)["leaseId"])
        n = len(self.api.requests)
        rc, err = self._sigterm_mid_click(h)
        self.assertEqual(rc, 2, err)  # refused locally: there is no confirmed lease to name
        self.assertEqual(len(self.api.requests), n)
        self.e.run("renew", h, check=2)
        self.e.run("shot", h, check=2)
        self.assertEqual(len(self.api.requests), n)
        self.assertEqual(self.orphans(), [h])
        p = self.e.run("close", h, check=0)  # close re-asks with the same holder and releases
        self.assertEqual(json.loads(p.stdout)["result"], "released")


# ------------------------------------------------------------------ hostile server (rescue r3 class A)

HOSTILE_TOKEN = "gqu_sentinelhostiletoken_q1w2e3r4t5y6u7i8"  # lowercase, so no letter case can save a leak
FRAG = HOSTILE_TOKEN[5:17]
CANARY = "zq9canarymarker"  # no credential: only a closed output schema keeps it out (the backstop cannot see it)
KINDS = {"token": HOSTILE_TOKEN, "frag": FRAG, "canary": CANARY,
         "nest": {"v": CANARY, "t": HOSTILE_TOKEN, "l": [FRAG, {"d": [CANARY, HOSTILE_TOKEN]}]}}
NORM = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")


def route_of(method, path):
    return "%s %s" % (method, NORM.sub(":id", path))


def leaf_paths(obj, prefix=()):
    if isinstance(obj, dict):
        if not obj:
            yield prefix
        for k, v in obj.items():
            yield from leaf_paths(v, prefix + (k,))
    elif isinstance(obj, list):
        if not obj:
            yield prefix
        for i, v in enumerate(obj):
            yield from leaf_paths(v, prefix + (i,))
    else:
        yield prefix


def set_leaf(obj, path, value):
    obj = json.loads(json.dumps(obj))
    if not path:
        return value
    cur = obj
    for k in path[:-1]:
        cur = cur[k]
    cur[path[-1]] = value
    return obj


def add_extras(obj):
    if isinstance(obj, dict):
        out = {k: add_extras(v) for k, v in obj.items()}
        out["zz_extra"] = KINDS["nest"]
        out["message"] = HOSTILE_TOKEN
        return out
    if isinstance(obj, list):
        return [add_extras(v) for v in obj] + [KINDS["nest"]]
    return obj


def leaks(text):
    low = text.lower()
    found = [f for f in {HOSTILE_TOKEN, CANARY} | {HOSTILE_TOKEN[i:i + 12] for i in range(len(HOSTILE_TOKEN) - 11)} if f in low]
    for form in (base64.b64encode(HOSTILE_TOKEN.encode()).decode(), urllib.parse.quote(HOSTILE_TOKEN, safe=""),
                 base64.b64encode(CANARY.encode()).decode()):
        if form in text:
            found.append(form)
    return found


class HostileServer(unittest.TestCase):
    """Every JSON answer field of every machine verb carries the lowercase token, a 12-character piece of it, a
    non-credential canary or a nested mix of them (plus extra keys at every level and hostile error bodies). Neither the
    token, any piece of it, nor the canary may reach CLI stdout or stderr, MCP output or any state file."""

    VERBS = {
        "open": lambda h: ["open", MACHINE],
        "shot": lambda h: ["shot", h],
        "click": lambda h: ["click", h, "--x", "1", "--y", "2"],
        "type": lambda h: ["type", h, "--text", "hello"],
        "key": lambda h: ["key", h, "--keys", "ctrl+l"],
        "renew": lambda h: ["renew", h],
        "close": lambda h: ["close", h],
    }
    MCP = {
        "open": lambda h: ("gq_machine_open", {"machineId": MACHINE}),
        "shot": lambda h: ("gq_machine_screenshot", {"handle": h}),
        "click": lambda h: ("gq_machine_click", {"handle": h, "x": 1, "y": 2}),
        "type": lambda h: ("gq_machine_type", {"handle": h, "text": "hello"}),
        "key": lambda h: ("gq_machine_key", {"handle": h, "keys": "ctrl+l"}),
        "renew": lambda h: ("gq_machine_renew", {"handle": h}),
        "close": lambda h: ("gq_machine_close", {"handle": h}),
    }

    def setUp(self):
        self.api = FakeMachines(token=HOSTILE_TOKEN)
        self.e = Env(self.api)
        self.e.env["GQ_MACHINE_WAIT_SECONDS"] = "1"

    def tearDown(self):
        self.api.close()
        self.e.close()

    def record(self, verb):
        """The JSON answers a clean run of the verb gets: {route: (status, body)}."""
        seen = {}

        def rec(method, path, status, body):
            seen.setdefault(route_of(method, path), (status, body))
            return status, body
        self.api.mutate = rec
        self.e.run(*self.VERBS[verb](self.e.seed(self.api)), check=0)
        self.api.mutate = None
        self.assertTrue(seen, verb)
        return seen

    def cases(self, verb):
        for route, (status, body) in sorted(self.record(verb).items()):
            for path in sorted(set(leaf_paths(body)), key=repr):
                for kind, value in KINDS.items():
                    yield "%s %s=%s" % (route, "/".join(map(str, path)), kind), route, (lambda b, p=path, v=value, st=status: (st, set_leaf(b, p, v)))
            yield "%s +extras" % route, route, (lambda b, st=status: (st, add_extras(b)))
            for est in (409, 500, 429):
                err = {"error": {"code": HOSTILE_TOKEN, "message": CANARY, "details": KINDS["nest"]}, "lease": add_extras(body)}
                yield "%s error %d" % (route, est), route, (lambda b, est=est, err=err: (est, err))
            yield "%s error frag" % route, route, (lambda b: (409, {"error": {"code": FRAG, "message": FRAG}}))

    def arm(self, route, fn):
        def mutate(method, path, status, body):
            return fn(body) if route_of(method, path) == route else (status, body)
        self.api.mutate = mutate

    def state_leaks(self):
        """Leaks in any state file (screenshots excluded: they are image bytes the fake never alters). Each leaking file
        version is reported once, not again by every later case."""
        bad = []
        seen = self.__dict__.setdefault("_reported", set())
        for f in self.e.root.rglob("*"):
            if f.is_file() and not f.name.endswith((".png", ".jpg")):
                data = f.read_bytes()
                found = leaks(data.decode("latin-1"))
                if found and (str(f), data) not in seen:
                    seen.add((str(f), data))
                    bad += ["%s:%s" % (f.name, x) for x in found]
        return bad

    def test_cli_never_prints_or_stores_server_text(self):
        failures, n = [], 0
        for verb in self.VERBS:
            for name, route, fn in self.cases(verb):
                h = self.e.seed(self.api)
                self.arm(route, fn)
                p = subprocess.run(self.e.argv(*self.VERBS[verb](h)), capture_output=True, text=True, env=self.e.env, timeout=60)
                self.api.mutate = None
                n += 1
                found = leaks(p.stdout + p.stderr) + self.state_leaks()
                if found:
                    failures.append("%s %s: %s" % (verb, name, sorted(set(found))[:3]))
        p = self.e.run("list")  # every handle the cases left behind, open or closed
        self.assertGreater(len(json.loads(p.stdout)["leases"]), 200)
        if leaks(p.stdout + p.stderr):
            failures.append("list: %s" % leaks(p.stdout + p.stderr))
        self.assertGreater(n, 200)
        self.assertEqual(failures, [], "%d of %d hostile cases leaked:\n%s" % (len(failures), n, "\n".join(failures[:40])))

    def test_mcp_never_returns_server_text(self):
        cases = []
        for verb in self.MCP:
            cases += [(verb, name, route, fn) for name, route, fn in self.cases(verb)]
        proc = self.e.popen(mcp=True)
        failures = []
        try:
            for i, (verb, name, route, fn) in enumerate(cases):
                h = self.e.seed(self.api)
                tool, args = self.MCP[verb](h)
                self.arm(route, fn)
                proc.stdin.write(json.dumps({"jsonrpc": "2.0", "id": i + 1, "method": "tools/call",
                                             "params": {"name": tool, "arguments": args}}) + "\n")
                proc.stdin.flush()
                line = proc.stdout.readline()
                self.api.mutate = None
                self.assertEqual(json.loads(line)["id"], i + 1, (verb, name))  # an answer, never an empty or lost line
                found = leaks(line) + self.state_leaks()
                if found:
                    failures.append("%s %s: %s" % (verb, name, sorted(set(found))[:3]))
        finally:
            out, err = proc.communicate(timeout=60)
        if leaks(out + err):
            failures.append("mcp exit: %s" % leaks(out + err))
        self.assertGreater(len(cases), 200)
        self.assertEqual(failures, [], "%d of %d hostile cases leaked:\n%s" % (len(failures), len(cases), "\n".join(failures[:40])))

    def test_screenshot_bytes_holding_the_token_are_never_stored(self):
        # The one server body written under HOME: a PNG that carries the token (a tEXt chunk, say) is refused unsaved.
        for blob in (HOSTILE_TOKEN.encode(), HOSTILE_TOKEN.upper()[4:20].encode(), base64.b64encode(HOSTILE_TOKEN.encode())):
            h = self.e.seed(self.api)
            self.api.artifact_bytes = PNG + b"tEXt" + blob
            p = self.e.run("shot", h, check=1)
            self.assertIn("credential_in_response", p.stderr)
            self.assertEqual(leaks(p.stdout + p.stderr), [])
            shots = self.e.root / h / "shots"
            self.assertEqual(list(shots.iterdir()) if shots.exists() else [], [])
            self.assertFalse((self.e.root / h / "shots.jsonl").exists())

    def test_successful_command_result_is_never_echoed(self):
        # v2 receipt F1 as a direct case: an ok click or key whose result carries the token and nested copies of it.
        h = self.e.seed(self.api)

        def mutate(method, path, status, body):
            if "/machine-commands/" in path and isinstance(body.get("command"), dict):
                body = json.loads(json.dumps(body))
                body["command"]["result"] = {"note": HOSTILE_TOKEN, "nested": {"x": [HOSTILE_TOKEN, CANARY]}}
            return status, body
        self.api.mutate = mutate
        for args in (["click", h, "--x", "1", "--y", "2"], ["key", h, "--keys", "Return"]):
            p = self.e.run(*args)
            self.assertEqual(leaks(p.stdout + p.stderr), [], args)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertEqual(json.loads(p.stdout)["state"], "ok")


if __name__ == "__main__":
    unittest.main()
