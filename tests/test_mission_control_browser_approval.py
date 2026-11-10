"""Cookie-bound local browser approval; generated values never printed."""
import contextlib
import http.client
import io
import json
import os
import threading
import unittest
from types import SimpleNamespace
from unittest import mock
from urllib.parse import urlencode

from tests import test_mission_control as fixtures

mcs = fixtures.mcs
KEY = b"disposable-browser-approval-key" * 2
NEXT = b"disposable-browser-rotated-key" * 2


class BrowserBinding(unittest.TestCase):
    def setUp(self):
        self.current = {"key": KEY}
        self.auth = mcs.Auth(lambda: self.current["key"], 49999)

    def begin(self, now=1000):
        self.assertTrue(callable(getattr(self.auth, "browser_begin", None)), "browser request contract absent")
        value = self.auth.browser_begin(now=now)
        self.assertTrue(bool(value), "request not created")
        return value

    def approve(self, rid, now=1000):
        issued = int(now)
        mac = mcs.browser_approval_mac(self.current["key"], rid, self.auth.port, issued)
        return self.auth.browser_approve(rid, issued, mac, now=now)

    def test_public_id_never_claims_without_original_browser(self):
        rid, nonce = self.begin()
        self.assertTrue(self.approve(rid))
        for invalid in (None, "", "x" * 43):
            self.assertEqual(self.auth.browser_claim(rid, invalid, now=1001)[0], "invalid")
        self.assertFalse(self.auth.sessions)
        status, sid = self.auth.browser_claim(rid, nonce, now=1001)
        self.assertEqual(status, "ok")
        self.assertTrue(bool(sid))
        self.assertEqual(self.auth.browser_claim(rid, nonce, now=1002)[0], "invalid")

    def test_pending_claim_rate_and_repeated_begin_preserve_binding(self):
        rid, nonce = self.begin()
        same = self.auth.browser_begin(nonce, now=1000)
        self.assertTrue(same[0] == rid and same[1] == nonce)
        self.assertEqual(self.auth.browser_claim(rid, nonce, now=1000)[0], "pending")
        self.assertTrue(self.approve(rid))
        self.assertEqual(self.auth.browser_claim(rid, nonce, now=1000.5)[0], "pending")
        self.assertEqual(self.auth.browser_claim(rid, nonce, now=1001)[0], "ok")

    def test_approval_is_exact_one_use_generation_origin_time(self):
        rid, nonce = self.begin()
        for issued, port, key in ((1001, 49999, KEY), (969, 49999, KEY), (1000, 49998, KEY), (1000, 49999, NEXT)):
            mac = mcs.browser_approval_mac(key, rid, port, issued)
            self.assertFalse(self.auth.browser_approve(rid, issued, mac, now=1000))
        self.assertFalse(self.auth.browser_approve(rid, True, "0" * 64, now=1000))
        self.assertTrue(self.approve(rid))
        self.assertFalse(self.approve(rid))
        self.assertEqual(self.auth.browser_claim(rid, nonce, now=1121)[0], "invalid")

    def test_revoke_rotation_missing_key_and_restart_invalidate_pending(self):
        for kind in ("revoke", "rotate", "missing", "restart"):
            with self.subTest(kind=kind):
                self.current["key"] = KEY
                self.auth = mcs.Auth(lambda: self.current["key"], 49999)
                rid, nonce = self.begin()
                self.assertTrue(self.approve(rid))
                if kind == "revoke":
                    self.auth.revoke_all()
                elif kind == "rotate":
                    self.current["key"] = NEXT
                elif kind == "missing":
                    self.auth.key_loader = lambda: (_ for _ in ()).throw(OSError("fixture"))
                else:
                    self.auth = mcs.Auth(lambda: KEY, 49999)
                self.assertEqual(self.auth.browser_claim(rid, nonce, now=1001)[0], "invalid")
                self.assertFalse(self.auth.pending_browsers)

    def test_pending_cap_and_double_claim_are_bounded(self):
        first = self.begin()
        for _ in range(15):
            self.assertTrue(bool(self.auth.browser_begin(now=1000)))
        self.assertFalse(bool(self.auth.browser_begin(now=1000)))
        self.assertEqual(len(self.auth.pending_browsers), 16)
        self.assertTrue(self.approve(first[0]))
        results = []
        barrier = threading.Barrier(3)

        def claim():
            barrier.wait()
            results.append(self.auth.browser_claim(*first, now=1001)[0])

        threads = [threading.Thread(target=claim) for _ in range(2)]
        for t in threads:
            t.start()
        barrier.wait()
        for t in threads:
            t.join(2)
            self.assertFalse(t.is_alive())
        self.assertEqual(results.count("ok"), 1)
        self.assertEqual(len(results), 2)
        self.assertEqual(len(self.auth.sessions), 1)

    def test_rotation_between_mac_verification_and_approval_refuses(self):
        rid, nonce = self.begin()
        expected = mcs.browser_approval_mac(KEY, rid, self.auth.port, 1000)

        def rotate_after_mac(*args):
            result = expected
            self.current["key"] = NEXT
            return result

        with mock.patch.object(mcs, "browser_approval_mac", side_effect=rotate_after_mac):
            self.assertFalse(self.auth.browser_approve(rid, 1000, expected, now=1000))
        self.assertFalse(self.auth.pending_browsers)
        self.assertFalse(self.auth.sessions)

    def test_rotation_after_cookie_proof_cannot_mint_a_new_key_session(self):
        rid, nonce = self.begin()
        self.assertTrue(self.approve(rid))
        compare = mcs.hmac.compare_digest

        def rotate_after_cookie(*args):
            result = compare(*args)
            self.current["key"] = NEXT
            return result

        with mock.patch.object(mcs.hmac, "compare_digest", side_effect=rotate_after_cookie):
            self.assertEqual(self.auth.browser_claim(rid, nonce, now=1001)[0], "invalid")
        self.assertFalse(self.auth.sessions)


class BrowserHTTP(fixtures.ServerHarness):
    def form(self, path, values, cookie="", **headers):
        hdrs = {"Origin": self.origin, "Sec-Fetch-Site": "same-origin",
                "Content-Type": "application/x-www-form-urlencoded", "Cookie": cookie}
        hdrs.update(headers)
        return self.request("POST", path, hdrs, urlencode(values))

    def begin(self):
        response, body = self.form("/auth/browser/request", {"action": "begin"})
        self.assertEqual(response.status, 201, "public request route unavailable")
        cookie = response.getheader("Set-Cookie").split(";")[0]
        rid = next(iter(self.app.auth.pending_browsers))
        self.assertTrue(rid.encode() in body)
        nonce = cookie.partition("=")[2]
        self.assertFalse(nonce.encode() in body, "binding nonce leaked to page")
        return rid, cookie

    def test_only_public_form_documents_keep_same_origin_referrer_policy(self):
        def policy(response, expected):
            self.assertEqual([value for key, value in response.getheaders()
                              if key.lower() == "referrer-policy"], [expected])

        page, _ = self.request("GET", "/auth/browser", {"Sec-Fetch-Site": "none"})
        self.assertEqual(page.status, 200)
        policy(page, "same-origin")
        self.assertIn("form-action 'self'", page.getheader("Content-Security-Policy"))
        start, _ = self.form("/auth/browser/request", {"action": "begin"})
        self.assertEqual(start.status, 201)
        policy(start, "same-origin")
        rid = next(iter(self.app.auth.pending_browsers))
        cookie = start.getheader("Set-Cookie").split(";")[0]
        pending, _ = self.form("/auth/browser/claim", {"request_id": rid}, cookie)
        self.assertEqual(pending.status, 202)
        policy(pending, "same-origin")
        rejected, _ = self.form("/auth/browser/request", {"action": "begin"}, Origin="null")
        self.assertEqual(rejected.status, 403)
        policy(rejected, "no-referrer")
        for path in ("/", "/auth/browser?unexpected=1", "/launch?c=invalid", "/api/state"):
            response, _ = self.request("GET", path, {"Sec-Fetch-Site": "none"})
            policy(response, "no-referrer")
        issued = int(mcs.time.time())
        approved, _ = self.request("POST", "/auth/browser/approve", {"Content-Type": "application/json"},
            json.dumps({"request_id": rid, "issued": issued,
                        "mac": mcs.browser_approval_mac(fixtures.mc_chat.secret(), rid, self.port, issued)}))
        self.assertEqual(approved.status, 200)
        policy(approved, "no-referrer")

    def test_actual_http_cookie_jar_approval_and_private_session_delivery(self):
        page, body = self.request("GET", "/auth/browser", {"Sec-Fetch-Site": "none"})
        self.assertEqual(page.status, 200)
        self.assertNotIn(b"csrf", body)
        rid, cookie = self.begin()
        issued = int(mcs.time.time())
        mac = mcs.browser_approval_mac(fixtures.mc_chat.secret(), rid, self.port, issued)
        output = io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            rc = mcs.approve_browser(SimpleNamespace(request_id=rid, port=self.port))
        self.assertEqual(rc, 0)
        self.assertFalse(mac in output.getvalue() or cookie in output.getvalue())
        wrong, _ = self.form("/auth/browser/claim", {"request_id": rid})
        self.assertEqual(wrong.status, 403)
        good, body = self.form("/auth/browser/claim", {"request_id": rid}, cookie)
        self.assertEqual(good.status, 303)
        self.assertEqual(good.getheader("Referrer-Policy"), "no-referrer")
        sid_cookie = good.getheader("Set-Cookie").split(";")[0]
        self.assertTrue(sid_cookie.startswith("mc_sid="))
        self.assertFalse(sid_cookie.partition("=")[2].encode() in body)
        state, _ = self.request("GET", "/api/state", {"Cookie": sid_cookie, "Sec-Fetch-Site": "same-origin"})
        self.assertEqual(state.status, 200)
        replay, _ = self.form("/auth/browser/claim", {"request_id": rid}, cookie)
        self.assertEqual(replay.status, 403)
        log = (self.root / "log" / "server.log")
        self.assertTrue(log.is_file())
        raw = log.read_bytes()
        self.assertFalse(mac.encode() in raw or cookie.encode() in raw or sid_cookie.encode() in raw)

    def test_start_and_claim_require_host_origin_fetch_and_literal_body(self):
        for changes in ({"Origin": "http://evil.invalid"}, {"Origin": ""},
                        {"Sec-Fetch-Site": "cross-site"}, {"Sec-Fetch-Site": ""},
                        {"Content-Type": "application/json"}):
            response, _ = self.form("/auth/browser/request", {"action": "begin"}, **changes)
            self.assertIn(response.status, (403, 415))
        response, _ = self.request("POST", "/auth/browser/request", {"Origin": self.origin,
            "Sec-Fetch-Site": "same-origin", "Content-Type": "application/x-www-form-urlencoded"},
            "action=begin&action=begin")
        self.assertEqual(response.status, 400)
        response, _ = self.form("/auth/browser/request", {"unknown": "begin"})
        self.assertEqual(response.status, 400)
        self.assertFalse(getattr(self.app.auth, "pending_browsers", {}))

    def test_unsigned_approval_duplicate_envelopes_and_cookie_aliases_refuse(self):
        rid, cookie = self.begin()
        body = json.dumps({"request_id": rid, "issued": int(mcs.time.time()), "mac": "0" * 64})
        response, _ = self.request("POST", "/auth/browser/approve", {"Content-Type": "application/json"}, body)
        self.assertEqual(response.status, 403)
        response, _ = self.request("POST", "/auth/browser/approve", {"Content-Type": "application/json",
            "Origin": self.origin, "Sec-Fetch-Site": "same-origin"}, body)
        self.assertEqual(response.status, 403)
        response, _ = self.request("POST", "/auth/browser/approve", {"Content-Type": "application/json"},
                                   '{"request_id":"x","request_id":"y","issued":1,"mac":"z"}')
        self.assertEqual(response.status, 400)
        response, _ = self.request("POST", "/auth/browser/approve", {"Content-Type": "application/json"}, "x" * 1025)
        self.assertEqual(response.status, 413)
        response, _ = self.form("/auth/browser/claim", {"request_id": rid}, cookie + "; " + cookie)
        self.assertEqual(response.status, 400)
        self.assertFalse(self.app.auth.sessions)

    def test_wrong_host_alias_and_nonloopback_have_no_device_authority(self):
        response, _ = self.request("GET", "/auth/browser", {"Sec-Fetch-Site": "none"}, host="evil.invalid")
        self.assertEqual(response.status, 403)
        response, _ = self.request("GET", "/auth/browser", {"Sec-Fetch-Site": "none"},
                                   host=f"localhost:{self.port}")
        self.assertEqual(response.status, 404)
        fake = SimpleNamespace(app=self.app, client_address=("192.0.2.10", 1), headers={})
        self.assertFalse(mcs.Handler.browser_available(fake))

    def test_existing_valid_session_is_not_replaced_and_demo_is_disabled(self):
        cookie, _ = self.login()
        response, _ = self.form("/auth/browser/request", {"action": "begin"}, cookie)
        self.assertEqual(response.status, 303)
        self.assertIsNone(response.getheader("Set-Cookie"))
        self.app.demo = True
        response, _ = self.form("/auth/browser/request", {"action": "begin"})
        self.assertEqual(response.status, 404)


class LocalApprovalTransport(unittest.TestCase):
    def test_proxy_environment_and_redirect_never_change_destination_or_expose_mac(self):
        self.assertTrue(callable(getattr(mcs, "approve_browser", None)), "local approval transport absent")
        rid = "a" * 32 + "." + "b" * 32
        for status in (200, 302):
            with self.subTest(status=status):
                conn = mock.Mock()
                conn.getresponse.return_value = SimpleNamespace(status=status, read=lambda n: b'{"status":"approved"}')
                out = io.StringIO()
                with mock.patch.dict(os.environ, {k: "http://proxy.invalid:8999" for k in
                     ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY")}), \
                     mock.patch.object(mcs.mc_chat, "secret", return_value=KEY), \
                     mock.patch.object(mcs.http.client, "HTTPConnection", return_value=conn) as make, \
                     contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
                    rc = mcs.approve_browser(SimpleNamespace(request_id=rid, port=47616))
                make.assert_called_once_with("127.0.0.1", 47616, timeout=3)
                self.assertEqual(conn.request.call_count, 1)
                self.assertEqual(rc, 0 if status == 200 else 2)
                payload = json.loads(conn.request.call_args.kwargs["body"])
                self.assertFalse(payload["mac"] in out.getvalue())
                self.assertNotIn("proxy.invalid", out.getvalue())
                conn.close.assert_called_once()

    def test_malformed_oversized_or_reflected_transport_errors_do_not_escape(self):
        rid = "a" * 32 + "." + "b" * 32
        for raw in (b"x" * 1025, b"[]", b'{"status":"bad","status":"approved"}', b'{"status":"fixture-private"}'):
            conn = mock.Mock()
            conn.getresponse.return_value = SimpleNamespace(status=200, read=lambda n, data=raw: data)
            output = io.StringIO()
            with mock.patch.object(mcs.mc_chat, "secret", return_value=KEY), \
                 mock.patch.object(mcs.http.client, "HTTPConnection", return_value=conn), \
                 contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
                self.assertEqual(mcs.approve_browser(SimpleNamespace(request_id=rid, port=47616)), 2)
            self.assertNotIn("fixture-private", output.getvalue())
            conn.close.assert_called_once()

    def test_bad_cli_inputs_or_private_transport_error_do_not_leak_or_launch_elsewhere(self):
        output = io.StringIO()
        with mock.patch.object(mcs.http.client, "HTTPConnection") as connect, contextlib.redirect_stdout(output):
            for rid, port in (("invalid", 47616), ("a" * 32 + "." + "b" * 32, True),
                              ("a" * 32 + "." + "b" * 32, 0)):
                self.assertEqual(mcs.approve_browser(SimpleNamespace(request_id=rid, port=port)), 2)
            connect.assert_not_called()
        connection = mock.Mock()
        connection.request.side_effect = OSError("fixture-private-transport-detail")
        output = io.StringIO()
        with mock.patch.object(mcs.mc_chat, "secret", return_value=KEY), \
             mock.patch.object(mcs.http.client, "HTTPConnection", return_value=connection), \
             contextlib.redirect_stdout(output), contextlib.redirect_stderr(output):
            self.assertEqual(mcs.approve_browser(SimpleNamespace(request_id="a" * 32 + "." + "b" * 32,
                                                                port=47616)), 2)
        self.assertNotIn("fixture-private", output.getvalue())


if __name__ == "__main__":
    unittest.main()
