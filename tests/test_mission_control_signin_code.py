"""Sign-in codes for a browser that cannot be handed a launch link (GoodQA #16047). Disposable secrets only.

The page shows a short code bound to that browser's pending cookie; the host approves the code with a proof minted
from the install secret (`server.py approve CODE`). Nothing secret is typed into or shown by the browser, and the
code alone grants nothing. Test names map to the spec: AC-1..AC-5, NEG-1..NEG-10."""
import json
import re
import time
import unittest
from unittest import mock

from tests import test_mission_control as fixtures

mcs = fixtures.mcs
mc_chat = fixtures.mc_chat
KEY = b"fixture-signin-code-key-a" * 2
NEXT_KEY = b"fixture-signin-code-key-b" * 2
CODE_RE = re.compile(rb"\b([A-HJKMNP-Z2-9]{4}-[A-HJKMNP-Z2-9]{4})\b")


def cookie_value(resp, name):
    for header in resp.headers.get_all("Set-Cookie") or []:
        first = header.split(";")[0]
        if first.startswith(name + "="):
            return first, header
    return None, None


class AuthUnit(unittest.TestCase):
    """The Auth object alone, with a fixed clock."""

    def setUp(self):
        self.auth = mcs.Auth(lambda: KEY, 49999)

    def test_start_reuse_and_claim_once(self):  # AC-1, AC-3, NEG-5
        pid, code = self.auth.signin_start(None, now=1000)
        self.assertRegex(code, r"^[A-HJKMNP-Z2-9]{4}-[A-HJKMNP-Z2-9]{4}$")
        self.assertGreaterEqual(len(pid), 40)
        self.assertEqual(self.auth.signin_start(pid, now=1010), (pid, code), "a live pending cookie must reuse its entry")
        self.assertIsNone(self.auth.signin_claim(pid, now=1011), "unapproved entry claimed a session")
        self.assertEqual(self.auth.signin_approve(mcs.mint_code(KEY, now=1020, purpose="approve"), code, now=1020), "approved")
        sid = self.auth.signin_claim(pid, now=1021)
        self.assertTrue(sid)
        self.assertIsNotNone(self.auth.session("mc_sid=" + sid, now=1022)[0])
        self.assertIsNone(self.auth.signin_claim(pid, now=1022), "an approved entry was claimed twice")

    def test_code_alone_grants_nothing(self):  # NEG-1
        pid, code = self.auth.signin_start(None, now=1000)
        self.auth.signin_approve(mcs.mint_code(KEY, now=1001, purpose="approve"), code, now=1001)
        other, _ = self.auth.signin_start(None, now=1002)
        self.assertIsNone(self.auth.signin_claim(other, now=1003), "another browser's cookie claimed the approval")
        self.assertIsNone(self.auth.signin_claim("attacker-chosen", now=1003))
        self.assertIsNone(self.auth.signin_claim(None, now=1003))
        self.assertTrue(self.auth.signin_claim(pid, now=1004))

    def test_expiry_before_and_after_approval(self):  # NEG-2
        pid, code = self.auth.signin_start(None, now=1000)
        late = 1000 + mcs.SIGNIN_TTL_S + 1
        self.assertEqual(self.auth.signin_approve(mcs.mint_code(KEY, now=late, purpose="approve"), code, now=late), "unknown-code")
        pid, code = self.auth.signin_start(None, now=2000)
        self.assertEqual(self.auth.signin_approve(mcs.mint_code(KEY, now=2001, purpose="approve"), code, now=2001), "approved")
        late = 2000 + mcs.SIGNIN_TTL_S + 1
        self.assertIsNone(self.auth.signin_claim(pid, now=late), "an approved entry outlived its window")
        new_pid, _ = self.auth.signin_start(pid, now=late)
        self.assertNotEqual(new_pid, pid, "an expired pending cookie was reused")

    def test_wrong_and_look_alike_codes_are_refused_not_coerced(self):  # NEG-3
        _, code = self.auth.signin_start(None, now=1000)
        swap = code.replace(code[0], "O" if code[0] != "O" else "0", 1)
        malformed = [code.replace("-", ""), code + "A", code[:-1], "", "x" * 400, None, 12345678, swap,
                     code.replace("-", "_"), "0OOO-1III", code[:8] + "0", "IL10-OOOO", " " + code[1:], code[:4] + "\u2010" + code[5:], "\u017f" + code[1:]]
        for n, guess in enumerate(malformed):
            proof = mcs.mint_code(KEY, now=1001 + n, purpose="approve")
            self.assertEqual(self.auth.signin_approve(proof, guess, now=1001 + n), "bad-code", repr(guess)[:40])
        self.assertFalse(next(iter(self.auth.pending.values()))["approved"], "a malformed code approved the entry")
        # Lower case is the same code (only case is folded), checked on its own fresh entry.
        fresh = mcs.Auth(lambda: KEY, 49999)
        pid, code2 = fresh.signin_start(None, now=2000)
        self.assertEqual(fresh.signin_approve(mcs.mint_code(KEY, now=2001, purpose="approve"), code2.lower(), now=2001), "approved")
        self.assertTrue(fresh.signin_claim(pid, now=2002))

    def test_retry_after_claim_still_reports_already_approved(self):  # NEG-6 (lost CLI response, then retry)
        pid, code = self.auth.signin_start(None, now=1000)
        self.assertEqual(self.auth.signin_approve(mcs.mint_code(KEY, now=1001, purpose="approve"), code, now=1001), "approved")
        self.assertTrue(self.auth.signin_claim(pid, now=1002))
        self.assertEqual(self.auth.signin_approve(mcs.mint_code(KEY, now=1003, purpose="approve"), code, now=1003), "already-approved")
        late = 1000 + mcs.SIGNIN_TTL_S + 1
        self.assertEqual(self.auth.signin_approve(mcs.mint_code(KEY, now=late, purpose="approve"), code, now=late), "unknown-code",
                         "completion metadata must expire with the entry window")
        for n in range(mcs.MAX_PENDING * 3):  # completion metadata stays bounded
            p2, c2 = self.auth.signin_start(None, now=2000 + n)
            self.auth.signin_approve(mcs.mint_code(KEY, now=2000 + n, purpose="approve"), c2, now=2000 + n)
            self.auth.signin_claim(p2, now=2000 + n)
        self.assertLessEqual(len(self.auth.claimed), mcs.MAX_PENDING * 2)

    def test_approval_needs_a_fresh_single_use_approve_proof(self):  # NEG-4, NEG-6
        _, code = self.auth.signin_start(None, now=1000)
        self.assertEqual(self.auth.signin_approve(mcs.mint_code(b"k" * 32, now=1001, purpose="approve"), code, now=1001), "bad-proof")
        self.assertEqual(self.auth.signin_approve(mcs.mint_code(KEY, now=900, purpose="approve"), code, now=1001), "bad-proof")
        self.assertEqual(self.auth.signin_approve(mcs.mint_code(KEY, now=1001), code, now=1001), "bad-proof",
                         "a launch link worked as an approval proof")
        self.assertEqual(self.auth.signin_approve("malformed", code, now=1001), "bad-proof")
        proof = mcs.mint_code(KEY, now=1002, purpose="approve")
        self.assertIsNone(self.auth.redeem(proof, now=1002), "an approval proof worked as a launch link")
        self.assertEqual(self.auth.signin_approve(proof, code, now=1002), "approved")
        _, code2 = self.auth.signin_start(None, now=1003)
        self.assertEqual(self.auth.signin_approve(proof, code2, now=1003), "bad-proof", "an approval proof was reused")

    def test_second_approval_of_the_same_code_is_refused(self):  # NEG-5
        _, code = self.auth.signin_start(None, now=1000)
        self.assertEqual(self.auth.signin_approve(mcs.mint_code(KEY, now=1001, purpose="approve"), code, now=1001), "approved")
        self.assertEqual(self.auth.signin_approve(mcs.mint_code(KEY, now=1002, purpose="approve"), code, now=1002), "already-approved")

    def test_secret_rotation_voids_pending_and_approved_entries(self):  # NEG-7
        current = {"key": KEY}
        auth = mcs.Auth(lambda: current["key"], 49999)
        pid, code = auth.signin_start(None, now=1000)
        auth.signin_approve(mcs.mint_code(KEY, now=1001, purpose="approve"), code, now=1001)
        current["key"] = NEXT_KEY
        self.assertIsNone(auth.signin_claim(pid, now=1002), "an approval survived a secret rotation")
        pid2, code2 = auth.signin_start(None, now=1003)
        auth.revoke_all()
        self.assertEqual(auth.signin_approve(mcs.mint_code(NEXT_KEY, now=1004, purpose="approve"), code2, now=1004), "unknown-code")

    def test_pending_entries_are_capped(self):  # NEG-8
        pids = [self.auth.signin_start(None, now=1000 + n)[0] for n in range(mcs.MAX_PENDING + 5)]
        self.assertLessEqual(len(self.auth.pending), mcs.MAX_PENDING)
        self.assertIsNone(self.auth.signin_claim(pids[0], now=1100))
        self.assertIn(mcs.Auth._hash(pids[-1]), self.auth.pending)

    def test_codes_are_unique_among_live_entries(self):  # NEG-3
        with mock.patch.object(mcs.secrets, "choice", side_effect=list("AAAAAAAA" * 2 + "BBBBBBBB")):
            _, first = self.auth.signin_start(None, now=1000)
            _, second = self.auth.signin_start(None, now=1001)
        self.assertNotEqual(first, second)


class Http(fixtures.ServerHarness):
    """The real server on an ephemeral loopback port."""

    def page(self, cookie=None, site="none", host=None):
        headers = {"Sec-Fetch-Site": site}
        if cookie:
            headers["Cookie"] = cookie
        return self.request("GET", "/", headers, host=host)

    def approve(self, code, proof=None, headers=None):
        proof = proof or mcs.mint_code(mc_chat.secret(), purpose="approve")
        body = json.dumps({"proof": proof, "code": code}).encode()
        hdrs = {"Content-Type": "application/json"}
        hdrs.update(headers or {})
        return self.request("POST", "/signin/approve", hdrs, body)

    def test_page_shows_code_sets_pending_cookie_and_has_no_secret(self):  # AC-1, AC-4
        resp, body = self.page()
        self.assertEqual(resp.status, 401)
        pending, header = cookie_value(resp, "mc_pending")
        self.assertIsNotNone(pending)
        for flag in ("HttpOnly", "SameSite=Strict", "Path=/", f"Max-Age={mcs.SIGNIN_TTL_S}"):
            self.assertIn(flag, header)
        match = CODE_RE.search(body)
        self.assertIsNotNone(match, body)
        self.assertIn(b"server.py approve", body)
        self.assertIn(b"server.py open", body)  # the launch-link route still works and is still named
        self.assertNotIn(pending.split("=", 1)[1].encode(), body, "the pending id leaked into the page")
        self.assertNotIn(b"<script", body.lower())
        self.assertIn(b'http-equiv="refresh"', body)
        again, body2 = self.page(cookie=pending, site="same-origin")
        self.assertEqual(CODE_RE.search(body2).group(1), match.group(1), "a reload minted a new code")
        self.assertIsNone(cookie_value(again, "mc_sid")[0])

    def test_host_approval_signs_in_only_the_requesting_browser(self):  # AC-2, AC-3, NEG-1
        resp, body = self.page()
        pending, _ = cookie_value(resp, "mc_pending")
        code = CODE_RE.search(body).group(1).decode()
        other, _ = cookie_value(self.page()[0], "mc_pending")
        ok, data = self.approve(code)
        self.assertEqual((ok.status, json.loads(data)), (200, {"approved": True}))
        stranger, _ = self.page(cookie=other, site="same-origin")
        self.assertEqual(stranger.status, 401)
        self.assertIsNone(cookie_value(stranger, "mc_sid")[0], "another browser got the session")
        signed, _ = self.page(cookie=pending, site="same-origin")
        self.assertEqual(signed.status, 303)
        self.assertEqual(signed.getheader("Location"), "/")
        sid, header = cookie_value(signed, "mc_sid")
        for flag in ("HttpOnly", "SameSite=Strict", "Path=/"):
            self.assertIn(flag, header)
        cleared, cleared_header = cookie_value(signed, "mc_pending")
        self.assertIn("Max-Age=0", cleared_header)
        state, _ = self.request("GET", "/api/state", {"Cookie": sid, "Sec-Fetch-Site": "same-origin"})
        self.assertEqual(state.status, 200)
        replay, _ = self.page(cookie=pending, site="same-origin")
        self.assertIsNone(cookie_value(replay, "mc_sid")[0], "the pending cookie was claimed twice")

    def test_approve_endpoint_refuses_browsers_and_bad_requests(self):  # NEG-4, NEG-9
        resp, body = self.page()
        code = CODE_RE.search(body).group(1).decode()
        self.assertEqual(self.approve(code, headers={"Origin": self.origin})[0].status, 403, "a page could call approve")
        self.assertEqual(self.approve(code, headers={"Sec-Fetch-Site": "same-origin"})[0].status, 403)
        self.assertEqual(self.approve(code, headers={"Sec-Fetch-Mode": "cors"})[0].status, 403)
        self.assertEqual(self.approve(code, headers={"Cookie": "mc_pending=x"})[0].status, 403)
        self.assertEqual(self.approve(code, proof=mcs.mint_code(b"k" * 32, purpose="approve"))[0].status, 401)
        self.assertEqual(self.approve(code, headers={"Content-Type": "text/plain"})[0].status, 415)
        self.assertEqual(self.request("POST", "/signin/approve", {"Content-Type": "application/json"}, b"{")[0].status, 400)
        self.assertEqual(self.approve("ZZZZ-ZZZZ")[0].status, 404)
        evil = self.request("POST", "/signin/approve", {"Content-Type": "application/json", "Host": "evil.com"},
                            json.dumps({"proof": "x", "code": code}).encode())[0]
        self.assertEqual(evil.status, 403)

    def test_cross_site_navigation_gets_no_pending_entry(self):  # NEG-9
        resp, _ = self.page(site="cross-site")
        self.assertEqual(resp.status, 403)
        self.assertIsNone(cookie_value(resp, "mc_pending")[0])
        self.assertEqual(self.app.auth.pending, {})

    def test_non_loopback_host_never_offers_a_code(self):  # NEG-10
        self.app.auth.hosts.add("demo.example:443")
        resp, body = self.page(host="demo.example:443")
        self.assertEqual(resp.status, 401)
        self.assertIsNone(cookie_value(resp, "mc_pending")[0])
        self.assertIsNone(CODE_RE.search(body))
        self.assertEqual(self.app.auth.pending, {})

    def test_proxied_requests_never_get_a_code(self):  # NEG-10 (a proxy that keeps a loopback Host)
        for header in ({"X-Forwarded-For": "198.51.100.7"}, {"Forwarded": "for=198.51.100.7"},
                       {"X-Forwarded-Host": "demo.example"}, {"Tailscale-Funnel-Request": "?1"}):
            resp, body = self.request("GET", "/", dict(header, **{"Sec-Fetch-Site": "none"}))
            self.assertEqual(resp.status, 401, header)
            self.assertIsNone(cookie_value(resp, "mc_pending")[0], header)
            self.assertIsNone(CODE_RE.search(body), header)
        self.assertEqual(self.app.auth.pending, {})

    def test_log_holds_neither_code_nor_proof_nor_pending_id(self):  # AC-4
        resp, body = self.page()
        pending, _ = cookie_value(resp, "mc_pending")
        code = CODE_RE.search(body).group(1).decode()
        proof = mcs.mint_code(mc_chat.secret(), purpose="approve")
        self.approve(code, proof=proof)
        self.page(cookie=pending, site="same-origin")
        for handler in mcs.make_logger(self.root).handlers:
            handler.flush()
        log = (self.root / "log" / "server.log").read_text()
        self.assertIn("/signin/approve", log)
        self.assertIn("signin approved", log)
        self.assertIn("signin claimed", log)
        for value in (code, proof, pending.split("=", 1)[1]):
            self.assertNotIn(value, log)


class Cli(fixtures.ServerHarness):
    def test_approve_command_approves_the_shown_code(self):  # AC-5
        resp, body = self.request("GET", "/", {"Sec-Fetch-Site": "none"})
        code = CODE_RE.search(body).group(1).decode()
        with mock.patch("builtins.print") as out:
            rc = mcs.main(["approve", code, "--port", str(self.port)])
        self.assertEqual(rc, 0, out.call_args_list)
        with mock.patch("builtins.print"):
            self.assertEqual(mcs.main(["approve", code, "--port", str(self.port)]), 1, "approved twice")
            self.assertEqual(mcs.main(["approve", "ZZZZ-ZZZZ", "--port", str(self.port)]), 1)


if __name__ == "__main__":
    unittest.main()
