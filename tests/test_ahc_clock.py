"""ahc_clock (goodqa#16049 slice 1 (b) AC-10): effective wall never goes backwards, elapsed comes from the boot
clock and survives a restart on the same boot, and a new or unreadable boot id takes each direction's conservative
action."""
import sqlite3
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "harness" / "hooks"))
import ahc_clock as clock  # noqa: E402

SCHEMA = """CREATE TABLE contract_meta (k TEXT PRIMARY KEY, v TEXT NOT NULL);
CREATE TABLE timers (owner TEXT NOT NULL, name TEXT NOT NULL, deadline_wall REAL NOT NULL, duration REAL NOT NULL,
  boot TEXT, anchor REAL, PRIMARY KEY (owner, name));"""


class Fake:
    def __init__(self, wall=1000.0, boot=50.0):
        self.wall, self.boot = wall, boot


class ClockTests(unittest.TestCase):
    def setUp(self):
        self.db = sqlite3.connect(":memory:", isolation_level=None)
        self.db.executescript(SCHEMA)
        self.t = Fake()

    def svc(self, boot_id="b1"):
        return clock.Clock(self.db, wall=lambda: self.t.wall, boot=lambda: self.t.boot, boot_id=boot_id)

    def test_effective_wall_never_goes_backwards_across_restarts(self):
        self.assertEqual(self.svc().effective_wall(), 1000.0)
        self.t.wall = 400.0                     # the wall clock steps back; a new service (a restart) reads the mark
        self.assertEqual(self.svc().effective_wall(), 1000.0)
        self.assertEqual(self.svc().utc_day(), int(1000.0 // 86400))

    def test_hwm_reset_needs_a_proof(self):
        with self.assertRaises(ValueError):
            self.svc().reset_hwm(10.0, "")
        self.svc().reset_hwm(10.0, "proof-1")
        self.t.wall = 20.0
        self.assertEqual(self.svc().effective_wall(), 20.0)

    def test_elapsed_comes_from_the_boot_clock_not_the_wall(self):
        c = self.svc()
        c.start("op1", "B42", 600)
        self.t.wall += 10 ** 6                  # a wall jump forward alone does not make elapsed large
        self.assertEqual(self.svc().elapsed("op1", "B42"), 0.0)
        self.t.boot += 30
        self.assertEqual(self.svc().elapsed("op1", "B42"), 30.0, "a restart on the same boot keeps the anchor")

    def test_escalation_fires_on_either_clock_and_on_a_new_boot(self):
        self.svc().start("op1", "B42", 600)
        self.assertFalse(self.svc().due("op1", "B42"))
        self.t.boot += 600
        self.assertTrue(self.svc().due("op1", "B42"), "elapsed alone fires an escalation")
        self.t.boot -= 600
        self.t.wall += 600
        self.assertTrue(self.svc().due("op1", "B42"), "wall alone fires an escalation")
        self.t.wall -= 600
        self.assertTrue(self.svc(boot_id="b2").due("op1", "B42"), "a new boot fires an escalation at once")

    def test_unreadable_boot_id_is_unknown_elapsed(self):
        self.svc().start("g", "B47", 60)
        c = self.svc()
        c.boot_id = None
        self.assertIsNone(c.elapsed("g", "B47"))
        self.assertTrue(c.due("g", "B47"), "an expiry with unknown elapsed is expired")

    def test_wait_needs_both_clocks_and_restarts_on_a_new_boot(self):
        self.svc().start("op1", "E13", 100)
        self.t.wall += 100
        self.assertFalse(self.svc().due("op1", "E13"), "wall alone never ends a wait")
        self.t.boot += 100
        self.assertTrue(self.svc().due("op1", "E13"))
        self.assertFalse(self.svc(boot_id="b2").due("op1", "E13"), "a new boot restarts the wait")
        self.t.wall += 100
        self.assertFalse(self.svc(boot_id="b2").due("op1", "E13"), "the re-anchored wait needs its full elapsed")
        self.t.boot += 100
        self.assertTrue(self.svc(boot_id="b2").due("op1", "E13"))

    def test_missing_row_is_conservative(self):
        self.assertTrue(self.svc().due("x", "B42"))
        self.assertTrue(self.svc().due("x", "OBS"))
        self.assertFalse(self.svc().due("x", "B48"))
        self.assertFalse(self.svc().due("x", "LATE_WATCH"))

    def test_every_timer_has_a_direction_and_unknown_names_refuse(self):
        self.assertTrue(set(clock.TIMERS.values()) <= set(clock.DIRECTIONS))
        with self.assertRaises(ValueError):
            self.svc().start("x", "NOPE", 1)


if __name__ == "__main__":
    unittest.main()


class BootIdTests(unittest.TestCase):
    """Main's ruling 4 (slice 1 (b)): once AC-13's sysctl form landed, the production boot id is the host's, not
    per-process, so a restart on the same boot keeps every timer's elapsed known."""

    def test_default_boot_id_is_the_host_s_and_stable_across_processes(self):
        import subprocess  # noqa: PLC0415
        if not (sys.platform == "darwin" or Path("/proc/sys/kernel/random/boot_id").exists()):
            self.skipTest("no host boot id on this platform")
        mine = clock.Clock(sqlite3.connect(":memory:")).boot_id
        self.assertTrue(mine.startswith(("macos:", "linux:")), mine)
        hooks = str(Path(__file__).resolve().parents[1] / "harness" / "hooks")
        other = subprocess.run([sys.executable, "-I", "-c", "import sys, sqlite3; sys.path.insert(0, sys.argv[1]); "
                                "import ahc_clock; print(ahc_clock.Clock(sqlite3.connect(':memory:')).boot_id)", hooks],
                               capture_output=True, text=True, timeout=60)
        self.assertEqual(other.stdout.strip(), mine, other.stderr)
