"""ahc clock service (goodqa#16049 slice 1 (b), AC-10; goodqa#16193).

Every timer reads this service, which has two parts:
- effective wall time: the maximum of the wall clock and a persisted high-water mark, so it never goes backwards
  across restarts. It guards wall deadlines and CAP1's UTC day; it never stands in for elapsed time;
- elapsed time: CLOCK_BOOTTIME where the platform has it, CLOCK_MONOTONIC otherwise, never derived from wall
  timestamps.

Each timer row (table `timers`) persists its wall deadline (effective wall at start plus the duration), the duration,
the boot id at start and the boot-clock reading at start (the anchor). On the same boot, elapsed is the boot clock now
minus the anchor, so a restart never resets it. On a new boot id, or when the boot id cannot be read, elapsed is
unknown and the timer takes its direction's conservative action at once (see DIRECTIONS).
"""
import time
from pathlib import Path

# A timer's direction decides how the two clocks combine and what an unknown elapsed (a new boot) means.
ESCALATION = "escalation"      # fires when either clock says the deadline passed; unknown elapsed fires at once
MONITOR = "monitor"            # ends only when both clocks agree; on a new boot it re-anchors with the full duration
EXPIRY = "expiry"              # authority expiry: expired when either clock says so; unknown elapsed is expired
WAIT = "wait"                  # a wait before acting: expires only when both agree; a new boot restarts the wait
RETENTION = "retention"        # deletes only when both agree; a new boot re-anchors with the full duration
DIRECTIONS = (ESCALATION, MONITOR, EXPIRY, WAIT, RETENTION)

# Every timer, with its direction (AC-10). CAP1's day is not a timer: it reads effective_wall() (never backwards).
TIMERS = {
    "B42": ESCALATION,            # unknown-effect age that raises an incident (escalate_at)
    "E12": ESCALATION,            # the PR-mark window after a dispatch
    "W23": ESCALATION,            # 10 min for W21's read-back before the lost-update escalation
    "FENCED": ESCALATION,         # a fenced op escalates 4 h after entry
    "LATE_WATCH": MONITOR,        # 30-day late-apply watch of an abandoned operation
    "B47": EXPIRY,                # grant expiry
    "OBS": EXPIRY,                # observation freshness (T2, 120 s)
    "E13": WAIT,                  # E13's first read gap and second read gap
    "B55": WAIT,                  # dispatch to unknown
    "B37": WAIT,                  # the next readback probe
    "B48": RETENTION,             # tombstoning after settlement
}


def read_boot_id(run=None):
    """This boot's id, or None when it cannot be read: Linux's kernel boot id, macOS's kern.bootsessionuuid (the
    one sysctl form AC-13 allows). None makes every timer's elapsed unknown, which is the conservative case."""
    try:
        value = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        if value:
            return "linux:" + value
    except OSError:
        pass
    if run is not None:
        try:
            proc = run(["/usr/sbin/sysctl", "-n", "kern.bootsessionuuid"], 10)
            value = proc.stdout.strip() if proc.returncode == 0 else ""
            if value:
                return "macos:" + value
        except Exception:  # noqa: BLE001 - an unreadable boot id is the conservative case, never an error
            return None
    return None


def boot_clock():
    """Seconds on CLOCK_BOOTTIME (counts suspend) where the platform has it, else CLOCK_MONOTONIC."""
    clock = getattr(time, "CLOCK_BOOTTIME", None)
    if clock is not None:
        try:
            return time.clock_gettime(clock)
        except OSError:
            pass
    return time.monotonic()


class Clock:
    """The clock service over one ledger connection. `wall`, `boot` (the boot clock) and `boot_id` are injectable
    for tests; production uses time.time, boot_clock and read_boot_id."""

    HWM_KEY = "wall_hwm"

    def __init__(self, db, wall=None, boot=None, boot_id=None):
        self.db = db
        self._wall = wall or time.time
        self._boot = boot or boot_clock
        self.boot_id = boot_id if boot_id is not None else read_boot_id()

    # ------------------------------------------------------------ wall half

    def _hwm(self):
        row = self.db.execute("SELECT v FROM contract_meta WHERE k=?", (self.HWM_KEY,)).fetchone()
        try:
            return float(row[0]) if row else 0.0
        except (TypeError, ValueError):
            return 0.0

    def effective_wall(self):
        """max(wall clock, high-water mark); the mark is raised as a side effect (in the caller's transaction when
        there is one), so effective wall never goes backwards across restarts."""
        now = float(self._wall())
        hwm = self._hwm()
        if now > hwm:
            self.db.execute("INSERT OR REPLACE INTO contract_meta(k, v) VALUES (?, ?)", (self.HWM_KEY, repr(now)))
            return now
        return hwm

    def reset_hwm(self, value, proof_id):
        """Main resets a wrong high-water mark only through a stamped CLI command whose proof is recorded."""
        if not isinstance(proof_id, str) or not proof_id:
            raise ValueError("a high-water mark reset needs a verified stamp proof id")
        self.db.execute("INSERT OR REPLACE INTO contract_meta(k, v) VALUES (?, ?)", (self.HWM_KEY, repr(float(value))))
        self.db.execute("INSERT OR REPLACE INTO contract_meta(k, v) VALUES ('wall_hwm_reset', ?)",
                        ("%s:%r" % (proof_id, float(value)),))

    def utc_day(self):
        """CAP1 counts against a UTC day that never goes backwards."""
        return int(self.effective_wall() // 86400)

    # ------------------------------------------------------------ timers

    def start(self, owner, name, duration):
        """Start (or restart) a timer: deadline_wall = effective wall + duration, with this boot's id and anchor."""
        if name not in TIMERS:
            raise ValueError("unknown timer %r (AC-10 lists every timer)" % name)
        deadline = self.effective_wall() + float(duration)
        self.db.execute("INSERT OR REPLACE INTO timers(owner, name, deadline_wall, duration, boot, anchor) "
                        "VALUES (?,?,?,?,?,?)", (owner, name, deadline, float(duration), self.boot_id,
                                                 float(self._boot())))
        return deadline

    def stop(self, owner, name):
        self.db.execute("DELETE FROM timers WHERE owner=? AND name=?", (owner, name))

    def _row(self, owner, name):
        return self.db.execute("SELECT deadline_wall, duration, boot, anchor FROM timers WHERE owner=? AND name=?",
                               (owner, name)).fetchone()

    def elapsed(self, owner, name):
        """Seconds since the anchor on the same boot; None when unknown (no row, another boot, an unread boot id,
        or no anchor, as for an operations row migrated with NULL wait columns)."""
        row = self._row(owner, name)
        if row is None:
            return None
        _deadline, _duration, boot, anchor = row
        if boot is None or anchor is None or self.boot_id is None or boot != self.boot_id:
            return None
        return max(0.0, float(self._boot()) - float(anchor))

    def due(self, owner, name):
        """Whether the timer's deadline counts as passed, by its direction (AC-10). A missing row counts as its
        conservative case: due for escalation and expiry, not due for a monitor, wait or retention (which then
        start a fresh full window)."""
        direction = TIMERS[name]
        row = self._row(owner, name)
        if row is None:
            return direction in (ESCALATION, EXPIRY)
        deadline, duration, _boot, _anchor = row
        wall_passed = self.effective_wall() >= float(deadline)
        elapsed = self.elapsed(owner, name)
        if direction in (ESCALATION, EXPIRY):
            return elapsed is None or wall_passed or elapsed >= float(duration)
        if elapsed is None:
            # a new boot: a wait restarts its full wait; a monitor or retention keeps running with a new anchor
            # and its remaining elapsed set to the full duration (deadline_wall keeps the later of the two)
            self.db.execute("UPDATE timers SET boot=?, anchor=?, deadline_wall=MAX(deadline_wall, ?) WHERE owner=? "
                            "AND name=?", (self.boot_id, float(self._boot()),
                                           self.effective_wall() + float(duration), owner, name))
            return False
        return wall_passed and elapsed >= float(duration)
