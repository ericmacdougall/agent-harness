"""GoodQA #15565: an ask alert for a resolved ask is not active, even before the daemon clears it."""
import json
import os
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "harness" / "hooks"))
import ops_watch as ow  # noqa: E402
from test_ops_watch import Base  # noqa: E402


class ResolvedAskAlerts(Base):
    def raise_ask(self, ask_id):
        ow.emit({"host": "testhost", "source": "ahd", "event": "raise", "severity": "high", "key": f"ask:{ask_id}:due",
                 "message": "ask awaits the user", "check": "ask"}, home=self.home)

    def main_log(self, session, rows):
        path = self.home / ".claude" / "wals" / session / "main.jsonl"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("".join(json.dumps(r) + "\n" for r in rows))
        return path

    def keys(self):
        return {a["key"] for a in ow.active_alerts(self.home)}

    def test_a_resolved_ask_drops_out_and_an_open_one_stays(self):
        self.raise_ask("w00000000001")
        self.raise_ask("w00000000002")
        self.main_log("s1", [{"event": "ask", "id": "w00000000001"}, {"event": "ask", "id": "w00000000002"},
                             {"event": "ask_resolved", "ref": "w00000000001", "outcome": "obsolete"}])
        self.assertEqual(self.keys(), {"ask:w00000000002:due"})

    def test_other_alerts_and_non_due_ask_keys_are_untouched(self):
        ow.emit({"host": "testhost", "source": "ahd", "event": "raise", "severity": "high", "key": "ask:w00000000003:unowned",
                 "message": "m", "check": "ask"}, home=self.home)
        ow.emit({"host": "testhost", "source": "ahd", "event": "raise", "severity": "high", "key": "disk:x",
                 "message": "m", "check": "disk"}, home=self.home)
        self.main_log("s1", [{"event": "ask_resolved", "ref": "w00000000003"}])
        self.assertEqual(self.keys(), {"ask:w00000000003:unowned", "disk:x"})

    def test_resolution_in_a_symlinked_or_oversized_log_is_ignored(self):
        self.raise_ask("w00000000004")
        real = self.main_log("real", [{"event": "ask_resolved", "ref": "w00000000004"}])
        link = self.home / ".claude" / "wals" / "linked" / "main.jsonl"
        link.parent.mkdir(parents=True)
        os.symlink(real, link)
        real.unlink()
        self.assertEqual(self.keys(), {"ask:w00000000004:due"})  # the only resolution is behind a dangling symlink
        self.main_log("big", [{"event": "ask_resolved", "ref": "w00000000004"}])
        old = ow.RESOLVED_SCAN_MAX_BYTES
        ow.RESOLVED_SCAN_MAX_BYTES = 5
        self.addCleanup(setattr, ow, "RESOLVED_SCAN_MAX_BYTES", old)
        self.assertEqual(self.keys(), {"ask:w00000000004:due"})

    def test_a_malformed_row_is_skipped(self):
        self.raise_ask("w00000000005")
        path = self.main_log("s2", [])
        path.write_text('{"event": "ask_resolved" broken\n' + json.dumps({"event": "ask_resolved", "ref": "w00000000005"}) + "\n")
        self.assertEqual(self.keys(), set())


if __name__ == "__main__":
    unittest.main()
