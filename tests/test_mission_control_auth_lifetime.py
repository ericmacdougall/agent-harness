"""Auth generation and long-lived SSE boundaries; disposable credentials only."""
import http.client
import io
import threading
import unittest
from types import SimpleNamespace
from unittest import mock

from tests import test_mission_control as fixtures

mcs = fixtures.mcs
KEY = b"fixture-auth-generation-a" * 2
NEXT_KEY = b"fixture-auth-generation-b" * 2


class GenerationBoundary(unittest.TestCase):
    def test_old_verified_code_cannot_mint_under_a_new_generation(self):
        calls = []

        def loader():
            calls.append(None)
            return KEY if len(calls) <= 2 else NEXT_KEY

        auth = mcs.Auth(loader, 49999)
        self.assertFalse(bool(auth.redeem(mcs.mint_code(KEY, auth.launch_generation, now=1000), now=1000)), "old code minted a session")
        self.assertFalse(auth.sessions)

    def test_rotation_after_signature_verification_refuses_mint(self):
        current = {"key": KEY}
        auth = mcs.Auth(lambda: current["key"], 49999)
        original = auth._signed_payload

        def verify_then_rotate(*args):
            result = original(*args)
            current["key"] = NEXT_KEY
            return result

        with mock.patch.object(auth, "_signed_payload", side_effect=verify_then_rotate):
            self.assertFalse(bool(auth.redeem(mcs.mint_code(KEY, auth.launch_generation, now=1000), now=1000)), "rotation allowed mint")
        self.assertFalse(auth.sessions)

    def test_signature_verification_is_inside_auth_lock(self):
        auth = mcs.Auth(lambda: KEY, 49999)
        original = auth._signed_payload

        def verify(*args):
            self.assertTrue(auth.lock.locked())
            return original(*args)

        with mock.patch.object(auth, "_signed_payload", side_effect=verify):
            self.assertTrue(auth.redeem(mcs.mint_code(KEY, auth.launch_generation, now=1000), now=1000))

    def test_stable_generation_preserves_single_use_expiry_and_invalid_refusal(self):
        auth = mcs.Auth(lambda: KEY, 49999)
        code = mcs.mint_code(KEY, auth.launch_generation, now=1000)
        self.assertTrue(auth.redeem(code, now=1000))
        self.assertFalse(bool(auth.redeem(code, now=1000)))
        self.assertFalse(bool(auth.redeem(mcs.mint_code(KEY, auth.launch_generation, now=900), now=1000)))
        self.assertFalse(bool(auth.redeem("malformed", now=1000)))


class StreamBoundary(unittest.TestCase):
    def setUp(self):
        self.now = [1000.0]
        self.clock = mock.patch.object(mcs.time, "time", side_effect=lambda: self.now[0])
        self.clock.start()
        self.addCleanup(self.clock.stop)
        self.reset_auth()

    def reset_auth(self):
        self.now[0] = 1000.0
        self.current = {"key": KEY}
        self.auth = mcs.Auth(lambda: self.current["key"], 49999)
        self.sid = self.auth.redeem(mcs.mint_code(KEY, self.auth.launch_generation))
        self.assertTrue(self.sid)

    def invalidate(self, kind):
        if kind == "revoke":
            self.auth.revoke_all()
        elif kind == "rotate":
            self.current["key"] = NEXT_KEY
        elif kind == "missing":
            self.auth.key_loader = lambda: (_ for _ in ()).throw(FileNotFoundError("fixture"))
        elif kind == "idle":
            self.auth.sessions[self.auth._hash(self.sid)]["last"] = self.now[0] - mcs.SESSION_TTL_S - 1
        elif kind == "absolute":
            self.now[0] += mcs.SESSION_TTL_S + 1
            self.auth.sessions[self.auth._hash(self.sid)]["last"] = self.now[0]

    def handler(self, action=lambda: None, frames=None, replay=False):
        stop = threading.Event()
        detached, statuses = [], []
        auth = self.auth

        class Sink(io.BytesIO):
            def write(inner, value):
                self.assertFalse(auth.lock.locked(), "network write holds the global auth lock")
                return super().write(value)

        def take(timeout):
            self.assertFalse(auth.lock.locked(), "queue wait holds the global auth lock")
            action()
            stop.set()
            return frames if frames is not None else [b"data: fixture-private-event\n\n"]

        client = SimpleNamespace(take=take)

        def recent(**kwargs):
            if replay:
                action()
                return [{"fixture": True}]
            return []

        hub = SimpleNamespace(attach=lambda: client, detach=lambda c: detached.append(c), recent=recent,
                              frame=lambda *args: b"data: fixture-private-replay\n\n")
        h = SimpleNamespace(app=SimpleNamespace(auth=auth, hub=hub, stop=stop),
                            headers={"Last-Event-ID": "1" if replay else "0"},
                            connection=SimpleNamespace(settimeout=lambda value: None), wfile=Sink(),
                            send_response=lambda status: statuses.append(status), send_header=lambda *args: None,
                            end_headers=lambda: None, deny=lambda status, reason: statuses.append(status),
                            close_connection=False)
        return h, detached, statuses

    def test_expiry_revocation_rotation_and_missing_key_block_queued_events(self):
        for kind in ["revoke", "rotate", "missing", "idle", "absolute"]:
            with self.subTest(kind=kind):
                self.reset_auth()
                h, detached, _ = self.handler(lambda: self.invalidate(kind))
                mcs.Handler.stream(h, self.sid)
                self.assertNotIn(b"fixture-private-event", h.wfile.getvalue())
                self.assertEqual(len(detached), 1)
                self.assertTrue(h.close_connection)

    def test_revoked_session_cannot_emit_heartbeat_or_initial_replay(self):
        for replay in [False, True]:
            with self.subTest(replay=replay):
                self.reset_auth()
                h, detached, _ = self.handler(self.auth.revoke_all, frames=[], replay=replay)
                mcs.Handler.stream(h, self.sid)
                self.assertNotIn(b"fixture-private-replay", h.wfile.getvalue())
                self.assertNotIn(b": keepalive", h.wfile.getvalue())
                self.assertEqual(len(detached), 1)

    def test_invalid_at_stream_entry_is_refused(self):
        self.auth.revoke_all()
        h, detached, statuses = self.handler()
        mcs.Handler.stream(h, self.sid)
        self.assertIn(401, statuses)
        self.assertNotIn(b"fixture-private", h.wfile.getvalue())

    def test_stream_remains_pinned_despite_another_valid_header(self):
        other = self.auth.redeem(mcs.mint_code(KEY, self.auth.launch_generation))

        def revoke_only_original():
            with self.auth.lock:
                self.auth.sessions.pop(self.auth._hash(self.sid))

        h, _, _ = self.handler(revoke_only_original)
        h.headers["Cookie"] = "mc_sid=" + other
        mcs.Handler.stream(h, self.sid)
        self.assertNotIn(b"fixture-private", h.wfile.getvalue())

    def test_valid_stream_delivers_without_refreshing_activity_or_holding_lock(self):
        before = dict(self.auth.sessions[self.auth._hash(self.sid)])
        h, detached, _ = self.handler(lambda: self.now.__setitem__(0, 1010.0))
        mcs.Handler.stream(h, self.sid)
        self.assertIn(b"fixture-private-event", h.wfile.getvalue())
        self.assertEqual(self.auth.sessions[self.auth._hash(self.sid)], before)
        self.assertEqual(len(detached), 1)


class NonTouchSession(unittest.TestCase):
    def test_non_touching_validation_and_default_http_activity(self):
        auth = mcs.Auth(lambda: KEY, 49999)
        sid = auth.redeem(mcs.mint_code(KEY, auth.launch_generation, now=1000), now=1000)
        cookie = "mc_sid=" + sid
        self.assertTrue(auth.session(cookie, now=1010, touch=False)[0])
        self.assertEqual(auth.sessions[auth._hash(sid)]["last"], 1000)
        self.assertTrue(auth.session(cookie, now=1020)[0])
        self.assertEqual(auth.sessions[auth._hash(sid)]["last"], 1020)


class SocketLifetime(fixtures.ServerHarness):
    def test_real_stream_closes_before_event_after_revocation(self):
        cookie, _ = self.login()
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=2)
        self.addCleanup(conn.close)
        conn.request("GET", "/api/events", headers={"Host": f"127.0.0.1:{self.port}", "Cookie": cookie,
                                                    "Sec-Fetch-Site": "same-origin"})
        response = conn.getresponse()
        self.assertEqual(response.status, 200)
        self.assertEqual(response.fp.readline(), b"retry: 3000\n")
        self.assertEqual(response.fp.readline(), b"\n")
        self.app.auth.revoke_all()
        self.app.hub.publish(fixtures.ev.make("wal", "fixture", "fixture-event", eid="fixture:revoked"))
        self.assertEqual(response.fp.read(1), b"", "revoked SSE stream stayed open or emitted an event")


if __name__ == "__main__":
    unittest.main()
