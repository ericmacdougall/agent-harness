"""GoodQA #15565: an ask alert for a resolved ask is not active, even before the daemon clears it (own session, sourced row)."""
import json
import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "harness" / "hooks"))
import ops_watch as ow  # noqa: E402
from test_ops_watch import Base  # noqa: E402

SESS = "abcd1234-0000-4000-8000-000000000001"
OTHER = "ffff9999-0000-4000-8000-000000000002"
SRC = 'answer:abcd1234-0000-4000-8000-000000000001/u "a long enough answer"'


def resolved(ask_id, source=SRC, event="ask_resolved"):
    return {"event": event, "ref": ask_id, "source": source}


class ResolvedAskAlerts(Base):
    def raise_ask(self, ask_id, session="abcd1234"):
        ow.emit({"host": "testhost", "source": "ahd", "event": "raise", "severity": "high", "key": f"ask:{ask_id}:due",
                 "message": "ask awaits the user", "check": "ask", "detail": {"session": session}}, home=self.home)

    def main_log(self, session, rows, raw=None):
        path = self.home / ".claude" / "wals" / session / "main.jsonl"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(raw if raw is not None else "".join(json.dumps(r) + "\n" for r in rows))
        return path

    def keys(self):
        return {a["key"] for a in ow.active_alerts(self.home)}

    def test_a_resolved_ask_drops_out_and_an_open_one_stays(self):
        self.raise_ask("w00000000001")
        self.raise_ask("w00000000002")
        self.main_log(SESS, [resolved("w00000000001")])
        self.assertEqual(self.keys(), {"ask:w00000000002:due"})

    def test_other_alerts_and_non_due_ask_keys_are_untouched(self):
        ow.emit({"host": "testhost", "source": "ahd", "event": "raise", "severity": "high", "key": "ask:w00000000003:unowned",
                 "message": "m", "check": "ask"}, home=self.home)
        ow.emit({"host": "testhost", "source": "ahd", "event": "raise", "severity": "high", "key": "disk:x",
                 "message": "m", "check": "disk"}, home=self.home)
        self.main_log(SESS, [resolved("w00000000003")])
        self.assertEqual(self.keys(), {"ask:w00000000003:unowned", "disk:x"})

    def test_only_the_alerts_own_session_and_only_a_sourced_ask_resolved_row_hide_it(self):
        self.raise_ask("w00000000004")
        self.main_log(OTHER, [resolved("w00000000004")])  # another session's log
        self.assertEqual(self.keys(), {"ask:w00000000004:due"})
        self.main_log(SESS, [resolved("w00000000004", source="")])  # no source
        self.assertEqual(self.keys(), {"ask:w00000000004:due"})
        self.main_log(SESS, [resolved("w00000000004", event="decision")])  # not an ask_resolved row
        self.assertEqual(self.keys(), {"ask:w00000000004:due"})
        self.main_log(SESS, [resolved("w00000000004")])
        self.assertEqual(self.keys(), set())

    def test_agent_logs_are_not_read(self):
        self.raise_ask("w00000000005")
        self.main_log(SESS, [])
        (self.home / ".claude" / "wals" / SESS / "agent-x.jsonl").write_text(json.dumps(resolved("w00000000005")) + "\n")
        self.assertEqual(self.keys(), {"ask:w00000000005:due"})

    def test_a_symlinked_log_is_not_followed_and_an_oversized_one_is_skipped(self):
        self.raise_ask("w00000000006")
        real = self.main_log("real-" + SESS, [resolved("w00000000006")])
        link = self.home / ".claude" / "wals" / SESS / "main.jsonl"
        link.parent.mkdir(parents=True, exist_ok=True)
        os.symlink(real, link)  # a live symlink to a file that does contain the row
        self.assertEqual(self.keys(), {"ask:w00000000006:due"})
        link.unlink()
        self.main_log(SESS, [resolved("w00000000006")])
        old = ow.RESOLVED_SCAN_MAX_BYTES
        ow.RESOLVED_SCAN_MAX_BYTES = 5
        self.addCleanup(setattr, ow, "RESOLVED_SCAN_MAX_BYTES", old)
        self.assertEqual(self.keys(), {"ask:w00000000006:due"})

    def test_a_malformed_row_is_skipped(self):
        self.raise_ask("w00000000007")
        self.main_log(SESS, [], raw='{"event": "ask_resolved" broken\n' + json.dumps(resolved("w00000000007")) + "\n")
        self.assertEqual(self.keys(), set())

    def test_an_alert_without_a_session_is_never_hidden(self):
        self.raise_ask("w00000000008", session="")
        self.main_log(SESS, [resolved("w00000000008")])
        self.assertEqual(self.keys(), {"ask:w00000000008:due"})


if __name__ == "__main__":
    unittest.main()
