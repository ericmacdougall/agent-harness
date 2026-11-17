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
import os
import time
import sys
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
    "GH_BACKOFF": WAIT,           # AC-1: a gh 403/429 backs the producer off before it reads again
    "B48": RETENTION,             # tombstoning after settlement
}


def process_boot_id():
    """The fallback when no boot id can be read: an id for this process. Elapsed is then known within the process
    and unknown to any other process, which takes the conservative action (never a wait that cannot end)."""
    return "process:%d:%s" % (os.getpid(), os.urandom(8).hex())


def read_boot_id(run=None):
    """This boot's id, or None when it cannot be read: Linux's kernel boot id, macOS's kern.bootsessionuuid (the
    one sysctl form AC-13 allows, through the caller's launcher `run(argv, timeout)`). None makes every timer's
    elapsed unknown, which is the conservative case."""
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
        if boot_id is None:
            # main's ruling 4: macOS reads kern.bootsessionuuid once AC-13 (the sysctl form) has landed
            import ahc_guard  # noqa: PLC0415
            boot_id = read_boot_id(run=ahc_guard.sysctl_run if sys.platform == "darwin" else None) or \
                process_boot_id()
        self.boot_id = boot_id

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

    def due(self, owner, name, duration=None):
        """Whether the timer's deadline counts as passed, by its direction (AC-10). A missing row (a row written
        before v5, or a lost one) counts as its conservative case: due for an escalation or an expiry; for a
        monitor, wait or retention a fresh full window starts now (when `duration` is given) and it is not due."""
        direction = TIMERS[name]
        row = self._row(owner, name)
        if row is None:
            if direction in (ESCALATION, EXPIRY):
                return True
            if duration is not None:
                self.start(owner, name, duration)
            return False
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

    # ------------------------------------------------------------ canary age

    def canary_age(self, canary, github_date=None):
        """E9's canary_age: from the recorded (boot, mono) canary result on this boot, or from GitHub's server Date
        (the canary's recorded server Date and a fresh one), never from the local wall clock. A canary from an
        earlier boot with no Date pair is stale: None."""
        if not isinstance(canary, dict):
            return None
        mono = canary.get("mono")
        if canary.get("boot") == self.boot_id and self.boot_id is not None and isinstance(mono, (int, float)) \
                and not isinstance(mono, bool):
            return max(0.0, float(self._boot()) - float(mono))
        then = canary.get("github_date")
        if isinstance(then, (int, float)) and isinstance(github_date, (int, float)) \
                and not isinstance(then, bool) and not isinstance(github_date, bool):
            return max(0.0, float(github_date) - float(then))
        return None


# Every wall-clock read in the ahc modules outside this service (AC-10's static inventory): (module, function) ->
# (count, use). A use is "timer:<name>" when the read feeds a timer (each such timer also has a clock-service row)
# or "stamp:<why>" for a log stamp or a recorded fact that never decides a deadline.
NOW_INVENTORY = {
    ('ahc_clone', '_quarantine', 'time.time_ns'): (1,
        'stamp:a unique quarantine directory name'),
    ('ahc_contracts', 'Contracts._a0', 'self.now'): (1,
        "stamp:the transition audit row's time"),
    ('ahc_contracts', 'Contracts._attribute', 'self.now'): (1,
        'stamp:the recorded time of an activity attribution'),
    ('ahc_contracts', 'Contracts._grant_move', 'self.now'): (1,
        "stamp:the grant row's updated time"),
    ('ahc_contracts', 'Contracts._op_move', 'self.now'): (2,
        'stamp:updated and settled_at (the B48/LATE_WATCH wall record; their clock rows start in TIMERS_ON_ENTRY)'),
    ('ahc_contracts', 'Contracts._wi_effects', 'self.now'): (2,
        "stamp:the W23 lost send row's and the W16-resolved send row's updated time"),
    ('ahc_contracts', 'Contracts._w21_record', 'self.now'): (1,
        "stamp:the W21 send row's created and updated time (AC-7)"),
    ('ahc_contracts', 'Contracts._w21_move', 'self.now'): (1,
        "stamp:the W21 send row's updated time; W23's 10 min runs on the clock row started at attempted"),
    ('ahc_contracts', 'Contracts.w21_attempt', 'self.now'): (1,
        "stamp:the attempted time stamp, a record that attempted committed (cancel needs it absent)"),
    ('ahc_contracts', 'Contracts._wi_notice', 'self.now'): (1,
        "stamp:the notice row's time"),
    ('ahc_contracts', 'Contracts.admit_item', 'self.now'): (1,
        'stamp:admission time (lineage order, not a deadline)'),
    ('ahc_contracts', 'Contracts.dispatch', 'self.now'): (1,
        'timer:B55 and E12 wall record (dispatched_at, probe_at); clock rows start on entry'),
    ('ahc_contracts', 'Contracts.expire_grants', 'self.now'): (1,
        'timer:B47 wall half; the clock row decides too'),
    ('ahc_contracts', 'Contracts.fence', 'self.now'): (1,
        'timer:FENCED escalate_at wall record; the clock row starts on entry'),
    ('ahc_contracts', 'Contracts.fence_held', 'self.now'): (1,
        'timer:FENCED escalate_at wall record; the clock row starts on entry'),
    ('ahc_contracts', 'Contracts.intend', 'self.now'): (1,
        'stamp:created and updated'),
    ('ahc_contracts', 'Contracts.issue_grant', 'self.now'): (1,
        'timer:B47 expires_at wall record; the clock row starts here'),
    ('ahc_contracts', 'Contracts.readback_missed', 'self.now'): (2,
        'timer:B37 probe_at wall record and the updated stamp; the clock row restarts here'),
    ('ahc_contracts', 'Contracts.record_w16_proof', 'self.now'): (1,
        "stamp:the W16 proof row's created time"),
    ('ahc_contracts', 'Contracts.require_review', 'self.now'): (1,
        "stamp:the review row's created time"),
    ('ahc_contracts', 'Contracts.reserve_grant', 'self.now'): (1,
        'timer:B47 wall half; the clock row decides too'),
    ('ahc_contracts', 'Contracts.retain', 'self.now'): (1,
        'timer:B48 wall half; the clock row decides too'),
    ('ahc_contracts', 'Contracts.review', 'self.now'): (1,
        "stamp:the review row's updated time"),
    ('ahc_contracts', 'Contracts.set_merging.write', 'self.now'): (1,
        "stamp:the merging mark's time"),
    ('ahc_contracts', 'Contracts.stamp', 'self.now'): (1,
        "stamp:an observation's wall stamp for the log; T2 age uses its (boot, mono) stamp"),
    ('ahc_contracts', 'Contracts.unknown', 'self.now'): (1,
        'timer:B37 and B42 wall record (probe_at, escalate_at); clock rows start on entry'),
    ('ahc_contracts', 'Contracts.wi_move', 'self.now'): (1,
        "stamp:the work item's updated time"),
    ('ahc_core', 'submit', 'time.time'): (1,
        "stamp:the queued item's submitted time"),
    ('ahc_install', 'install', 'time.time'): (1,
        "stamp:the install record's time"),
    ('ahc_runner', 'Journal.append', 'time.time'): (1,
        "stamp:the journal entry's time"),
    ('ahc_runner', 'Ledger.backup', 'time.time_ns'): (1,
        'stamp:a unique backup file name'),
    ('ahc_runner', 'Ledger.restore', 'time.time_ns'): (1,
        'stamp:a unique moved-aside file name'),
    ('ahc_runner', 'LiveDeps.clock', 'time.time'): (1,
        "gate1:the Gate 1 runner's injectable wall clock (Worker.now); its timers are listed below"),
    ('ahc_runner', 'Worker._effect_done', 'self.now'): (1,
        "stamp:the effect row's done time"),
    ('ahc_runner', 'Worker.conclude', 'self.now'): (3,
        'stamp:conclusion and digest times'),
    ('ahc_runner', 'Worker.dispatch_effects', 'self.now'): (1,
        'stamp:the effect dispatch time'),
    ('ahc_runner', 'Worker.email_route', 'self.now'): (1,
        "stamp:the email route row's time"),
    ('ahc_runner', 'Worker.escalate', 'self.now'): (1,
        "stamp:the escalation row's time"),
    ('ahc_runner', 'Worker.escalate_overdue', 'self.now'): (1,
        "gate1:D20 overdue escalation, wall only (slice 1(a) runner; not in AC-10's list; follow-up)"),
    ('ahc_runner', 'Worker.fail', 'self.now'): (1,
        'stamp:the failure time'),
    ('ahc_runner', 'Worker.head_readback', 'self.now'): (1,
        'stamp:the readback time'),
    ('ahc_runner', 'Worker.lease', 'self.now'): (1,
        "gate1:the item lease expiry, wall only (slice 1(a) runner; not in AC-10's list; follow-up)"),
    ('ahc_runner', 'Worker.process', 'self.now'): (3,
        'stamp:step times in the journal and rows'),
    ('ahc_runner', 'Worker.prune_packets', 'self.now'): (1,
        "gate1:packet pruning age, wall only (slice 1(a) runner; not in AC-10's list; follow-up)"),
    ('ahc_runner', 'Worker.recheck_pass', 'self.now'): (1,
        'stamp:the recheck time'),
    ('ahc_runner', 'Worker.review', 'self.now'): (2,
        'stamp:review start and end times'),
    ('ahc_runner', 'Worker.settle', 'self.now'): (1,
        'stamp:the settle time'),
    ('ahc_runner', '_quarantine', 'time.time_ns'): (1,
        'stamp:a unique quarantine name'),
    ('ahc_runner', '_quarantine_report_dir', 'time.time_ns'): (1,
        'stamp:a unique report directory name'),
    ('ahc_runner', 'ack', 'time.time'): (1,
        "stamp:the ack record's time"),
    ('ahc_runner', 'admit', 'time.time'): (1,
        "stamp:the admit record's time"),
}
