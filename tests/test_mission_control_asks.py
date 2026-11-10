"""The "Needs you" list (GoodQA #15585 hotfix): open asks are read-only data, shown as text, answered via chat."""
import json
import os
import re
import sys
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "harness" / "hooks"))
sys.path.insert(0, str(REPO / "harness" / "mission_control"))
os.environ.setdefault("MC_HOOKS", str(REPO / "harness" / "hooks"))

import collectors as col  # noqa: E402
import demo  # noqa: E402
import events as ev  # noqa: E402
from safeio import Refused, Runner  # noqa: E402

WEB = REPO / "harness" / "mission_control" / "web" / "js"
SID = "baab765b-d85c-46b4-b7b9-588eb912c770"


class FakeRunner:
    def __init__(self, code, payload):
        self.code, self.payload, self.calls = code, payload, []

    def run(self, kind, *args, timeout=20.0, limit=0):
        self.calls.append((kind, args))
        return self.code, self.payload if isinstance(self.payload, str) else json.dumps(self.payload)


def collector(runner, session=SID):
    hub = ev.Hub()
    health = col.Health(hub)
    return col.Asks(hub, health, runner, lambda: session), hub, health


class AsksCollector(unittest.TestCase):
    def test_runner_shape_is_fixed_and_validates_the_session(self):
        runner = Runner(python="/usr/bin/python3", ah="/h/hooks/ah.py")
        self.assertEqual(runner.argv("provenance-asks", SID),
                         ["/usr/bin/python3", "-I", "/h/hooks/provenance.py", "asks", "--session", SID, "--json", "--items"])
        for bad in ("--json", "a;rm -rf ~", "../../etc", "short", "x" * 80, f"{SID} --other"):
            with self.subTest(bad=bad), self.assertRaises(Refused):
                runner.argv("provenance-asks", bad)
        with self.assertRaises(Refused):
            runner.argv("provenance-asks")

    def test_items_are_bounded_redacted_and_keep_markup_as_plain_text(self):
        items = [{"id": "wgood0000001", "kind": "traced", "at": "2026-11-09T01:00:00Z",
                  "note": "<img src=x onerror=alert(1)> ship it? (goodqa#15585) token=abcdef1234567890abcdef",
                  "reason": "why", "owner": "main"},
                 {"id": "bad id; drop", "note": "dropped"}, "not a dict",
                 *[{"id": f"wbulk{i:07d}", "note": f"n{i}"} for i in range(150)]]
        asks, hub, health = collector(FakeRunner(0, {"counts": {}, "items": items}))
        asks.run(1000.0)
        self.assertEqual(health.rows["asks"]["status"], "ok", health.rows)
        self.assertEqual(len(asks.items), 98)  # only the first 100 are read; the bad id and the non-dict are dropped
        first = asks.items[0]
        self.assertEqual(first["ticket"], "goodqa#15585")
        self.assertIn("<img src=x onerror=alert(1)>", first["text"])  # data stays data; the page sets textContent
        self.assertNotIn("abcdef1234567890abcdef", json.dumps(asks.snapshot()))  # harness redaction applied
        self.assertEqual(first["session"], SID)
        self.assertEqual(hub.snapshots["asks"], asks.snapshot())

    def test_a_secret_past_the_display_limit_is_redacted_before_clipping(self):
        note = "x" * 390 + " token=abcdef1234567890abcdef1234"
        asks, _hub, _health = collector(FakeRunner(0, {"items": [{"id": "wlong0000001", "note": note}]}))
        asks.run(0.0)
        self.assertNotIn("abcdef12", json.dumps(asks.snapshot()))

    def test_a_failing_ledger_keeps_the_last_list_and_shows_an_error(self):
        runner = FakeRunner(0, {"items": [{"id": "wkeep0000001", "note": "keep me"}]})
        asks, _hub, health = collector(runner)
        asks.run(0.0)
        runner.code, runner.payload = 1, "Traceback: boom"
        asks.run(200.0)
        self.assertEqual(health.rows["asks"]["status"], "error")
        self.assertEqual([a["id"] for a in asks.items], ["wkeep0000001"])

    def test_no_session_runs_nothing(self):
        runner = FakeRunner(0, {"items": []})
        asks, _hub, health = collector(runner, session="")
        asks.run(0.0)
        self.assertEqual(runner.calls, [])
        self.assertLessEqual(asks.next_at, 10.0)  # retried soon, not after the full interval

    def test_demo_fixture_flows_through_without_a_process(self):
        runner = demo.DemoRunner()
        asks, _hub, _health = collector(runner)
        asks.run(0.0)
        self.assertEqual(len(asks.items), len(demo.ASKS))
        self.assertTrue(any("<script>" in a["why"] for a in asks.items))  # the hostile fixture survives as text


class Page(unittest.TestCase):
    def test_needs_panel_never_builds_markup_from_ask_text(self):
        source = (WEB / "needs.js").read_text()
        for sink in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function"):
            self.assertNotIn(sink, source, sink)
        self.assertIn("parts.text.textContent = ask.text", source)

    def test_escape_closes_dialogs_without_relying_on_native_cancel(self):  # click-test F1 (af566316)
        main = (WEB / "main.js").read_text()
        self.assertIn("if (event.key !== 'Escape') return;", main)
        self.assertIn("document.querySelectorAll('dialog[open]')", main)

    def test_a_reply_is_an_ordinary_tagged_chat_message_to_main(self):
        store = (WEB / "store.js").read_text()
        body = re.search(r"export function sendAskReply[\s\S]*?\n}\n", store).group(0)
        self.assertIn("const body = `[ask:${ask?.id}] ${clean}`;", body)
        self.assertIn("to: 'claude'", body)
        self.assertIn("askReplyAccess(ask).disabled", body)  # the chat channel's own gate, nothing new
        self.assertIn("deliver(item)", body)  # same transport (POST /api/chat with CSRF) as the composer


if __name__ == "__main__":
    unittest.main()
