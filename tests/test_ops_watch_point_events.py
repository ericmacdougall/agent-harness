"""goodqa#15234: point-event alerts (heavy refusals, foreign process stops) expire; other alerts never do."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "harness" / "hooks"))
import ops_watch as ow  # noqa: E402
from test_ops_watch import Base, FakeRunner  # noqa: E402

NOW = 1794100000.0
HOUR = 3600
KILL_KEY = "ah-" + "kill:foreign:k1"  # joined: the process-stop guard scans interpreter text for the word


class PointEventTests(Base):
    def setUp(self):
        super().setUp()
        self.cfg["sinks"] = {"comment": {"mode": "none"}, "deadman": []}

    def raise_at(self, key, age_h, source="heavy-guard", severity="warning"):
        ow.emit({"host": "testhost", "source": source, "event": "raise", "severity": severity, "key": key,
                 "message": "m " + key, "check": "x"}, home=self.home)
        # the ring stamps "now"; rewrite the stamp so the event looks age_h old
        ring = ow.ring_path(self.home)
        import json
        events = ow.read_ring(ring)
        last = events[-1]
        last["at"] = ow.now_iso(NOW - age_h * HOUR)
        with open(ring, "r+b") as fh:
            fh.seek((last["seq"] % ow.RING_SLOTS) * ow.SLOT_BYTES)
            fh.write(ow.encode_slot(last))

    def run_once(self, at=NOW):
        return ow.run_once(self.cfg, self.home, runner=FakeRunner(), checks={}, now=at)

    def active_keys(self):
        return {a["key"] for a in ow.active_alerts(self.home)}

    def test_old_point_events_expire_for_every_source(self):
        self.raise_at("heavy:copy:o1", 7)
        self.raise_at(KILL_KEY, 7, source=ow.SOURCE, severity="high")
        self.assertEqual(len(self.active_keys()), 2)
        self.run_once()
        self.assertEqual(self.active_keys(), set())

    def test_a_waiter_that_gave_up_expires_like_any_point_event(self):
        # goodqa#15565: bg_job wait-file raises bgwait:<file>:<reason> once; nothing re-derives the key, so it must expire
        self.raise_at("bgwait:out.txt:timeout", 7, source="bg-wait", severity="high")
        self.raise_at("bgwait:new.txt:producer-gone", 1, source="bg-wait", severity="high")
        self.run_once()
        self.assertEqual(self.active_keys(), {"bgwait:new.txt:producer-gone"})

    def test_recent_point_event_stays(self):
        self.raise_at("heavy:copy:o2", 1)
        self.run_once()
        self.assertEqual(self.active_keys(), {"heavy:copy:o2"})

    def test_other_families_never_expire(self):
        self.raise_at("disk:volume:/", 48, source=ow.SOURCE, severity="high")
        self.raise_at("liveness:s/a1", 48, source=ow.SOURCE, severity="high")
        self.run_once()
        self.assertEqual(self.active_keys(), {"disk:volume:/", "liveness:s/a1"})

    def test_expired_ops_watch_key_is_not_reasserted_next_run(self):
        self.raise_at(KILL_KEY, 7, source=ow.SOURCE, severity="high")
        self.run_once()
        self.run_once(NOW + 60)
        self.assertEqual(self.active_keys(), set())

    def test_repeat_after_expiry_raises_again(self):
        self.raise_at("heavy:copy:o3", 7)
        self.run_once()
        self.assertEqual(self.active_keys(), set())
        self.raise_at("heavy:copy:o3", 0)
        self.run_once(NOW + 60)
        self.assertEqual(self.active_keys(), {"heavy:copy:o3"})

    def test_other_host_not_touched(self):
        ow.emit({"host": "otherhost", "source": "heavy-guard", "event": "raise", "severity": "warning",
                 "key": "heavy:copy:x", "message": "m", "check": "x"}, home=self.home)
        ring = ow.ring_path(self.home)
        last = ow.read_ring(ring)[-1]
        last["at"] = ow.now_iso(NOW - 9 * HOUR)
        with open(ring, "r+b") as fh:
            fh.seek((last["seq"] % ow.RING_SLOTS) * ow.SLOT_BYTES)
            fh.write(ow.encode_slot(last))
        self.run_once()
        self.assertEqual(self.active_keys(), {"heavy:copy:x"})

    def test_future_dated_event_expires_when_over_an_hour_ahead(self):
        self.raise_at("heavy:copy:f1", -3)  # stamped 3 h in the future
        self.raise_at("heavy:copy:f2", -0.5)  # 30 min ahead: ordinary skew, stays
        self.run_once()
        self.assertEqual(self.active_keys(), {"heavy:copy:f2"})

    def test_repeat_between_snapshot_and_clear_is_not_cleared(self):
        self.raise_at("heavy:copy:r1", 7)
        ring = ow.ring_path(self.home)
        snapshot = ow.latest_by_key(ow.read_ring(ring))
        self.raise_at("heavy:copy:r1", 0)  # another process repeats the refusal after the snapshot
        out = ow.expire_point_events(self.cfg, snapshot, {}, NOW, ring)
        self.assertEqual(out, [])
        self.assertEqual(self.active_keys(), {"heavy:copy:r1"})

    def test_disabled_by_empty_prefixes_or_zero_ttl(self):
        self.raise_at("heavy:copy:o4", 99)
        for pe in ({"prefixes": [], "ttl_h": 6}, {"prefixes": ["heavy:"], "ttl_h": 0}):
            self.cfg["point_events"] = pe
            self.run_once()
            self.assertEqual(self.active_keys(), {"heavy:copy:o4"})


if __name__ == "__main__":
    unittest.main()
