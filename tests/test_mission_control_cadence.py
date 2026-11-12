"""Collector cadence (GoodQA #15585 performance pass): the costly subprocess sources run less often when no page
is attached, the asks ledger runs when a WAL says an ask changed (not every minute), and static files are served
compressed and revalidated."""
import gzip
import json
import os
import sys
import time
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "tests"))
sys.path.insert(0, str(REPO / "harness" / "hooks"))
sys.path.insert(0, str(REPO / "harness" / "mission_control"))

import collectors as col  # noqa: E402
import events as ev  # noqa: E402
import needs_sweep  # noqa: E402
from test_mission_control import ServerHarness  # noqa: E402

SID = "baab765b-d85c-46b4-b7b9-588eb912c770"


class Runner:
    def __init__(self):
        self.calls = []

    def run(self, kind, *args, timeout=20.0, limit=0):
        self.calls.append(kind)
        return 0, json.dumps({"items": [], "resolved": [], "owners": []})


class Cadence(unittest.TestCase):
    def setUp(self):
        self.hub = ev.Hub()
        self.health = col.Health(self.hub)

    def test_asks_ledger_runs_on_an_ask_event_or_at_the_sweep_interval_only(self):
        runner = Runner()
        asks = col.Asks(self.hub, self.health, runner, lambda: SID)
        asks.run(1000.0)
        self.assertEqual(asks.interval, needs_sweep.SWEEP_EVERY_S)
        self.assertFalse(asks.due(1000.0 + 120), "no ask changed: the 5 CPU-second ledger read is not repeated")
        asks.mark_dirty()
        self.assertFalse(asks.due(1000.0 + 2), "a burst of ask lines is debounced")
        self.assertTrue(asks.due(1000.0 + 121))
        asks.run(1000.0 + 121)
        self.assertFalse(asks.due(1000.0 + 200))
        self.assertTrue(asks.due(1000.0 + 121 + needs_sweep.SWEEP_EVERY_S))
        self.assertEqual(runner.calls.count("provenance-asks"), 2)

    def test_the_wal_tailer_marks_asks_dirty_on_ask_lines_only(self):
        seen = []
        tailer = col.WalTailer(self.hub, self.health, None, [])
        tailer.on_ask = lambda: seen.append(1)
        tail = col._Tail(1, 0, "claude", SID, "main")
        for event in ("ask", "result", "ask_resolved", "pretool"):
            tailer._emit(tail, {"event": event, "note": "n", "at": "2026-11-11T10:00:00+00:00"}, event)
        self.assertEqual(len(seen), 2)

    def test_costly_sources_slow_down_with_no_page_attached_and_wake_with_one(self):
        owners = col.Owners(self.hub, self.health, Runner(), None)
        self.assertGreaterEqual(owners.idle_interval, 5 * owners.interval)
        owners.run(1000.0)
        self.assertFalse(owners.due(1000.0 + owners.interval + 1), "nobody is looking: `ah owners` waits")
        self.assertTrue(owners.due(1000.0 + owners.idle_interval + 1))
        client = self.hub.attach()
        owners.wake(1000.0 + owners.interval + 1)
        self.assertTrue(owners.due(1000.0 + owners.interval + 1), "a page attached: refresh at once")
        owners.run(1000.0 + owners.interval + 1)
        self.assertTrue(owners.due(1000.0 + 2 * owners.interval + 2), "and keep the normal cadence while it watches")
        self.hub.detach(client)
        fresh = col.Owners(self.hub, self.health, Runner(), None)
        fresh.run(5000.0)
        fresh.wake(5010.0)
        self.assertFalse(fresh.due(5010.0), "a wake never makes a source run faster than its interval")


class Static(ServerHarness):
    def setUp(self):
        super().setUp()
        self.cookie, _ = self.login()

    def get(self, path, headers=None):
        hdrs = {"Cookie": self.cookie, "Sec-Fetch-Site": "same-origin"}
        hdrs.update(headers or {})
        return self.request("GET", path, hdrs)

    def test_text_assets_are_gzipped_when_asked_and_identical_when_not(self):
        big = "console.log('x');\n" * 400
        (self.base / "web" / "js" / "main.js").write_text(big)
        self.server.static_files = self.server._index(self.base / "web")
        plain, body = self.get("/js/main.js")
        self.assertIsNone(plain.getheader("Content-Encoding"))
        self.assertEqual(body.decode(), big)
        packed, data = self.get("/js/main.js", {"Accept-Encoding": "gzip, br"})
        self.assertEqual(packed.getheader("Content-Encoding"), "gzip")
        self.assertIn("Accept-Encoding", packed.getheader("Vary"))
        self.assertEqual(gzip.decompress(data).decode(), big)
        self.assertLess(len(data), len(big) // 5)

    def test_unchanged_assets_revalidate_with_304_and_changed_ones_do_not(self):
        first, _ = self.get("/js/main.js")
        tag = first.getheader("ETag")
        self.assertTrue(tag)
        self.assertEqual(first.getheader("Cache-Control"), "no-cache, private")
        again, body = self.get("/js/main.js", {"If-None-Match": tag})
        self.assertEqual((again.status, body), (304, b""))
        (self.base / "web" / "js" / "main.js").write_text("console.log(2)")
        changed, body = self.get("/js/main.js", {"If-None-Match": tag})
        self.assertEqual((changed.status, body), (200, b"console.log(2)"))

    def test_api_and_page_shell_are_never_cached_and_a_304_needs_the_session(self):
        state, _ = self.get("/api/state")
        self.assertEqual(state.getheader("Cache-Control"), "no-store")
        page, _ = self.get("/", {"Sec-Fetch-Site": "none"})
        self.assertEqual(page.getheader("Cache-Control"), "no-store")
        tag = self.get("/js/main.js")[0].getheader("ETag")
        anonymous, _ = self.request("GET", "/js/main.js", {"Sec-Fetch-Site": "same-origin", "If-None-Match": tag})
        self.assertEqual(anonymous.status, 401)


if __name__ == "__main__":
    unittest.main()
