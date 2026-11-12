"""goodqa#15827 (B3 of goodqa#15805): a critical raise or clear that a foreign source (fabd-health, a script) wrote to the local
ring with `ops_watch.py emit` must reach the GoodQA digest and the deadman mail, like ops-watch's own critical transitions.
Stdlib only, no network; the sinks are fakes that record what they were asked to deliver."""
import os
import sys
import time
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "harness" / "hooks"))
import ops_watch as ow  # noqa: E402
from test_ops_watch import Base, FakeRunner  # noqa: E402

KEY = "fabric:live-down:fabd"


class Forwarding(Base):
    def setUp(self):
        super().setUp()
        self.posted, self.dead = [], []
        self.cfg["sinks"] = {"comment_min_interval_s": 0, "comment": {"mode": "cmd", "argv": ["fake-comment"]},
                             "deadman": [["fake-deadman", "{SUBJECT}"]]}
        self.runner = FakeRunner({("fake-comment",): self._comment, ("fake-deadman",): self._deadman})

    def _comment(self, argv, timeout, stdin):
        self.posted.append(stdin)
        return (0, "")

    def _deadman(self, argv, timeout, stdin):
        self.dead.append(argv)
        return (0, "")

    def emit(self, event="raise", severity="critical", key=KEY, source="fabd-health", **extra):
        row = {"host": "testhost", "source": source, "event": event, "severity": severity, "key": key,
               "message": f"{event} {key}", "detail": {}}
        row.update(extra)
        return ow.emit(row, home=self.home)

    def run_once(self, checks=None):
        return ow.run_once(self.cfg, self.home, runner=self.runner, checks=checks if checks is not None else {}, now=time.time())

    def delivered(self, text):
        return sum(body.count(text) for body in self.posted)

    # AC-1
    def test_an_emitted_critical_reaches_the_digest_and_the_deadman_queue(self):
        self.run_once()  # a first run: nothing is standing yet
        self.emit()
        self.assertEqual(self.run_once(), 0)
        self.assertEqual(self.delivered(f"`{KEY}`"), 1)
        self.assertEqual(len(self.dead), 1)
        self.assertIn(KEY, self.dead[0][1])

    # AC-2
    def test_a_rerun_does_not_deliver_it_twice_even_across_a_fresh_state_load(self):
        self.run_once()
        self.emit()
        for _ in range(3):
            self.run_once()
        self.assertEqual(self.delivered(f"`{KEY}`"), 1)
        self.assertEqual(len(self.dead), 1)
        self.assertGreaterEqual(ow.load_state(self.home).get("fwd_seq", 0), 1)  # durable, not an in-memory counter

    # AC-3
    def test_a_clear_is_forwarded_to_the_digest_not_to_the_deadman(self):
        self.run_once()
        self.emit()
        self.run_once()
        self.emit(event="clear", severity="info")
        self.run_once()
        self.assertEqual(self.delivered("CLEAR"), 1)
        self.assertEqual(len(self.dead), 1)  # only the raise mailed
        self.run_once()
        self.assertEqual(self.delivered("CLEAR"), 1)

    # AC-4
    def test_a_non_critical_event_and_an_ops_watch_source_event_are_not_forwarded(self):
        self.run_once()
        self.emit(severity="high", key="fabric:other")
        self.emit(severity="warning", key="fabric:warn")
        self.run_once()
        self.assertEqual(self.delivered("`fabric:other`"), 0)
        self.assertEqual(self.delivered("`fabric:warn`"), 0)
        self.assertEqual(self.dead, [])

    def test_a_row_with_the_ops_watch_source_is_left_to_the_ops_watch_path(self):
        self.run_once()
        self.emit(source="ops-watch", severity="critical", key="ops-watch:fake")
        state = {"fwd_seq": 0, "fwd_active": {}}
        self.assertEqual(ow.forward_foreign(self.cfg, self.home, state, ow.ring_path(self.home), time.time()), [])
        self.assertEqual(state["fwd_seq"], 1)

    def test_a_clear_for_a_raise_that_was_never_forwarded_is_not_forwarded(self):
        self.run_once()
        self.emit(event="clear", severity="critical", key="fabric:never-raised")
        self.run_once()
        self.assertEqual(self.delivered("`fabric:never-raised`"), 0)

    def test_a_text_refresh_row_is_not_forwarded_again(self):
        self.run_once()
        self.emit()
        self.run_once()
        self.emit(detail={"updated": True})
        self.emit(detail={"reasserted": True})
        self.run_once()
        self.assertEqual(self.delivered(f"`{KEY}`"), 1)
        self.assertEqual(len(self.dead), 1)

    # AC-5
    def test_the_first_run_forwards_only_what_is_standing_not_the_ring_history(self):
        self.emit(key="fabric:old")
        self.emit(event="clear", severity="info", key="fabric:old")
        self.emit(key="fabric:standing")
        self.run_once()
        self.assertEqual(self.delivered("`fabric:old`"), 0)
        self.assertEqual(self.delivered("`fabric:standing`"), 1)
        self.assertEqual(len(self.dead), 1)

    def test_a_new_raise_after_a_clear_is_forwarded_as_a_new_alert(self):
        self.run_once()
        self.emit()
        self.run_once()
        self.emit(event="clear", severity="info")
        self.run_once()
        self.emit()
        self.run_once()
        self.assertEqual(self.delivered(f"RAISE [critical] testhost `{KEY}`"), 2)

    def test_a_ring_that_restarted_its_sequence_is_not_silenced(self):
        self.run_once()
        for index in range(3):
            self.emit(key=f"fabric:filler{index}", severity="info")
        self.emit()
        self.run_once()
        self.assertEqual(self.delivered(f"`{KEY}`"), 1)
        ow.ring_path(self.home).unlink()  # a recreated ring: seq starts again below the stored one
        self.emit(event="clear", severity="info")
        self.emit(key="fabric:second")
        self.run_once()
        self.assertEqual(self.delivered("`fabric:second`"), 1)
        self.assertEqual(self.delivered("CLEAR"), 1)

    def test_a_foreign_row_with_a_malformed_detail_does_not_stop_the_alert_path(self):
        self.run_once()
        for index, detail in enumerate(("oops", ["a"], 7)):
            self.emit(key=f"fabric:odd{index}", detail=detail)
        self.emit()  # a well formed critical after the odd rows
        self.run_once()  # four mails queued, three sent per run by design: rc may be 2 here
        self.assertEqual(self.delivered(f"`{KEY}`"), 1)
        for index in range(3):
            self.assertEqual(self.delivered(f"`fabric:odd{index}`"), 1)  # forwarded with an empty detail, not dropped
        self.assertEqual(self.run_once(), 0)  # the fourth mail goes out and nothing is stuck
        self.assertEqual(self.delivered(f"`{KEY}`"), 1)  # and the seq advanced past them
        self.assertEqual(len(self.dead), 4)

    # receipt r1 F1 and F2: a failed or empty ring read is "unknown", never a reset
    def standing_then(self):
        self.run_once()
        self.emit()
        self.emit(key="fabric:second")
        self.run_once()
        self.assertEqual(self.delivered(f"`{KEY}`"), 1)
        return ow.ring_path(self.home)

    def test_an_unreadable_ring_after_a_forward_does_not_resend_the_history(self):
        ring = self.standing_then()
        saved = ring.with_name("alerts.saved")
        ring.rename(saved)
        ring.mkdir()  # the ring path is briefly not a regular file: read_ring returns []
        self.run_once()
        ring.rmdir()
        saved.rename(ring)
        self.run_once()
        self.assertEqual(self.delivered(f"`{KEY}`"), 1)
        self.assertEqual(self.delivered("`fabric:second`"), 1)
        self.assertEqual(len(self.dead), 2)
        self.assertGreaterEqual(ow.load_state(self.home).get("fwd_seq", 0), 2)  # the position was never lowered

    def test_an_empty_ring_read_after_a_forward_does_not_resend_the_history(self):
        ring = self.standing_then()
        data = ring.read_bytes()
        ring.write_bytes(b"")  # a truncated or not yet written ring
        self.run_once()
        ring.write_bytes(data)
        self.run_once()
        self.assertEqual(self.delivered(f"`{KEY}`"), 1)
        self.assertEqual(self.delivered("`fabric:second`"), 1)
        self.assertEqual(len(self.dead), 2)

    def test_one_torn_newest_slot_is_not_a_reset(self):
        ring = self.standing_then()
        top = max(e["seq"] for e in ow.read_ring(ring))
        offset = (top % ow.RING_SLOTS) * ow.SLOT_BYTES
        fd = os.open(str(ring), os.O_RDWR)
        try:
            good = os.pread(fd, ow.SLOT_BYTES, offset)
            os.pwrite(fd, b"x" * ow.SLOT_BYTES, offset)  # the newest slot cannot be parsed: the visible top drops by one
            self.run_once()
            os.pwrite(fd, good, offset)
        finally:
            os.close(fd)
        self.run_once()
        self.assertEqual(self.delivered(f"`{KEY}`"), 1)
        self.assertEqual(self.delivered("`fabric:second`"), 1)
        self.assertEqual(len(self.dead), 2)

    def test_a_clear_made_while_the_ring_was_unreadable_is_still_forwarded_afterwards(self):
        ring = self.standing_then()
        saved = ring.with_name("alerts.saved")
        ring.rename(saved)
        ring.mkdir()
        self.run_once()
        ring.rmdir()
        saved.rename(ring)
        self.emit(event="clear", severity="info")
        self.run_once()
        self.assertEqual(self.delivered("CLEAR"), 1)

    # receipt r1 F3: an expiry clear carries updated=true and must still close a forwarded raise
    def test_a_clear_row_marked_updated_still_clears_a_forwarded_raise(self):
        self.run_once()
        self.emit()
        self.run_once()
        self.emit(event="clear", severity="info", detail={"updated": True})
        self.run_once()
        self.assertEqual(self.delivered("CLEAR"), 1)

    # receipt r1 F4: a row whose key is not a string must not stop run_once
    def test_a_ring_row_with_an_unhashable_key_does_not_stop_the_alert_path(self):
        self.run_once()
        ring = ow.ring_path(self.home)
        self.emit(key="fabric:before", severity="info")
        seq = max(e["seq"] for e in ow.read_ring(ring)) + 1
        row = {"schema": 1, "at": "2026-11-12T00:00:00Z", "host": "testhost", "source": "x", "event": "raise",
               "severity": "critical", "key": ["a"], "message": "bad", "detail": {}, "seq": seq}
        fd = os.open(str(ring), os.O_RDWR)
        try:
            os.pwrite(fd, ow.encode_slot(row), (seq % ow.RING_SLOTS) * ow.SLOT_BYTES)
        finally:
            os.close(fd)
        self.emit()
        self.assertEqual(self.run_once(), 0)
        self.assertEqual(self.delivered(f"`{KEY}`"), 1)

    def test_emit_refuses_a_non_string_key_source_or_host(self):
        for field in ("key", "source", "host"):
            row = {"host": "testhost", "source": "x", "event": "raise", "severity": "info", "key": "k", "message": "m"}
            row[field] = ["no"]
            with self.assertRaises(ValueError):
                ow.emit(row, home=self.home)

    def test_no_deadman_configured_still_feeds_the_digest(self):
        self.cfg["sinks"] = dict(self.cfg["sinks"], deadman=[])
        self.run_once()
        self.emit()
        self.run_once()
        self.assertEqual(self.delivered(f"`{KEY}`"), 1)
        self.assertEqual(self.dead, [])


if __name__ == "__main__":
    unittest.main()
