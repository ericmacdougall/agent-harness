"""Owner liveness rule, shared by `ah owners` and ops-watch (one definition, never forked).

An owner is a sub-agent task. Inputs are timestamps (epoch seconds) taken from its task WAL and
transcript, and whether the harness recorded it as stopped.

  live      WAL activity within LIVE_WAL_S, or transcript mtime within LIVE_TRANSCRIPT_S
  quiet     no activity for more than the live window but under SILENT_S
  SILENT    running (never stopped) and no activity for SILENT_S or more
  SILENT-HIGH  same, past HIGH_S (alert severity high)
  done / handoff / waiting-on-<x> / DROPPED / returned  stopped owners, by their last recorded outcome
"""
from __future__ import annotations

import hashlib
import re

LIVE_WAL_S = 20 * 60
LIVE_TRANSCRIPT_S = 10 * 60
SILENT_S = 30 * 60
HIGH_S = 60 * 60
FINISH_GRACE_S = 30 * 60  # a just-stopped owner may be between turns or writing its handoff: not a drop yet

# An active alert's ring entry is what agents read, so its text must follow the condition, but a live counter must not
# fill the ring. Changed words refresh quickly; a change in numbers alone ("silent 31m") refreshes hourly.
ALERT_REFRESH_S = 3600
ALERT_REFRESH_MIN_S = 300
_NUMBER = re.compile(r"\d+")

_WAITING = re.compile(r"\bwaiting\s+(?:on|for)\s+((?:GoodQA\s+)?[A-Za-z0-9_.:#\-]{1,60})", re.I)


# Types that are owners only when main names them as one (a WAL scope/intent/decision note carrying the id).
NAMEABLE_TYPES = ("general-purpose", "claude")


_WAIT_TARGET = re.compile(r"^(w[0-9a-f]{11}|(GoodQA\s+)?([a-z0-9][a-z0-9-]*)?#\d{1,10}|a[0-9a-f]{6,32}|main)$", re.I)


def alert_text_stale(written: str, current: str, written_at: float, now: float) -> bool:
    """Should an active alert whose ring entry says `written` (written at `written_at`) be rewritten to `current`?"""
    written, current = str(written or ""), str(current or "")
    if written == current:
        return False
    words_changed = _NUMBER.sub("#", written) != _NUMBER.sub("#", current)
    return now - (written_at or 0) >= (ALERT_REFRESH_MIN_S if words_changed else ALERT_REFRESH_S)


def alert_marks(message) -> dict:
    """Hashes of an alert's text before the ring redacts or cuts it, for a writer that keeps no state of its own."""
    text = str(message or "")
    return {"text_sha": hashlib.sha256(text.encode()).hexdigest()[:16],
            "text_shape": hashlib.sha256(_NUMBER.sub("#", text).encode()).hexdigest()[:16]}


def ring_text_stale(detail, ring_message, current, written_at, now) -> bool:
    """alert_text_stale for a writer that can only read the ring back. The ring's text may be redacted or cut, so its
    marks decide. An overflowed slot has lost them and can't be compared, so it refreshes at most hourly."""
    detail = detail if isinstance(detail, dict) else {}
    age = now - (written_at or 0)
    if detail.get("text_sha"):
        marks = alert_marks(current)
        if marks["text_sha"] == detail["text_sha"]:
            return False
        return age >= (ALERT_REFRESH_S if marks["text_shape"] == detail.get("text_shape") else ALERT_REFRESH_MIN_S)
    if detail.get("truncated"):
        return age >= ALERT_REFRESH_S
    return alert_text_stale(ring_message, current, written_at, now)


def waiting_on(note: str):
    """The named thing an owner waits on: an ask id, a ticket or an agent. Anything else is not a wait
    (goodqa#14791 review H3: "waiting on <anything>" used to park an owner forever)."""
    match = _WAITING.search(note or "")
    target = match.group(1) if match else None
    return target if target and _WAIT_TARGET.match(target) else None


# Only owner tasks must leave a handoff/result in their WAL. Helpers (fixer, click-tester, red-team, reviewer,
# Explore, Plan) return their result to the parent as the final message, so stopping without a WAL outcome
# is "returned", not DROPPED. A helper explicitly registered as a task owner (ah task register) is an owner.
OWNER_TYPES = ("task-owner",)


DISPOSITIONS = ("resumed", "reassigned", "waiting", "closed", "legacy", "superseded", "wontdo")
CLOSING = ("closed", "superseded", "wontdo")  # end an owner; only "closed" means done (deployed live and tested)
RESUMED_GRACE_S = 30 * 60  # a "resumed" disposition must be followed by activity within this window


def disposition_live(disp: dict | None, now: float, last_activity: float = 0.0, replacement_live: bool = False) -> bool:
    """Whether a recorded disposition still excuses a DROPPED owner (goodqa#14791, invariant I1).

    resumed     live only while activity follows it: within RESUMED_GRACE_S of its time, or any activity after it
    reassigned  live while the replacement agent is live (the caller resolves that)
    waiting     live until its `until` time (epoch seconds); it must cite an ask id or a ticket (checked at write)
    closed      permanent: done, deployed to live and tested (ah checks both records at write)
    superseded  permanent, not done: the scope moved elsewhere; cites a ticket
    wontdo      permanent, not done: nobody will do it; cites a ticket
    legacy      permanent, not done: quiet before the gate was installed and unverified; `ah owners` keeps listing it
    """
    if not isinstance(disp, dict) or disp.get("kind") not in DISPOSITIONS:
        return False
    at = float(disp.get("at") or 0.0)
    kind = disp["kind"]
    if kind in ("closed", "legacy", "superseded", "wontdo"):
        return True
    if kind == "waiting":
        return now < float(disp.get("until") or 0.0)
    if kind == "reassigned":
        return bool(replacement_live)
    return (last_activity > at) or (now - at < RESUMED_GRACE_S)


ENDING_DISPOSITIONS = frozenset(("reassigned", "closed", "superseded", "wontdo", "legacy"))


def row_disposed(row: dict) -> bool:
    """goodqa#15322: an `ah owners` row whose owner main already disposed of (the work moved, ended or was written off)
    raises no liveness alert, whether or not the replacement is live right now. A time-boxed wait or resume only excuses
    the row while it is live (disposition.live), and a row `ah` still marks decision_required always alerts."""
    disp = row.get("disposition")
    if not isinstance(disp, dict) or row.get("decision_required") is True:
        return False
    return disp.get("kind") in ENDING_DISPOSITIONS or disp.get("live") is True


NOTE_WAIT_MAX_S = 24 * 3600  # a "waiting on <x>" WAL note holds at most this long after it was written (round 5,
# MJ-1). liveness cannot confirm a ticket exists, so every note wait gets the unconfirmed cap; a longer wait is an
# `ah task dispose --kind waiting`, which checks the ask or ticket and allows up to 7 days.


# wal.py metadata rows, not an owner's own words (as dropped_gate.LIFECYCLE_EVENTS)
HOOK_EVENTS = frozenset(("pretool", "subagent", "subagent_stop", "pending_stop", "session", "prompt"))
WAIT_SUPERSEDE_S = 60  # ambiguous owner activity this long after a wait means the owner moved on from it (goodqa#15949)
WAIT_TAIL_S = 300  # an in-turn wait's closing tail (tool rows, final report, stop row) ends within this, or it is work
STOP_SLACK_S = 10  # as ah's is_stopped: writes this close to a recorded stop row belong to the turn that stopped


def _whole(ts) -> float:
    """Whole seconds: ledger times (server_now) carry no fraction, so a WAL time is floored to compare like with like."""
    return float(int(float(ts or 0.0)))


def wait_current(wait_at: float, activity: dict | None = None) -> bool:
    """The one rule for whether a wait (a waiting disposition or a `waiting on <x>` WAL note) still holds (goodqa#15949,
    receipts r1-r5b). It reads only RECORDED, append-only times and fixed offsets from the wait itself, never a
    boundary inferred or recomputed from later state (r4: joined activity bursts; r5b F2: a synthetic stop from
    transcript metadata). Every input only grows and every threshold is fixed by `wait_at`, so once a wait is
    superseded it stays superseded. Where the rule cannot tell a closing tail from resumed work it says superseded:
    a false "needs a decision" is accepted, a false excuse is not.

    `activity` (epoch seconds, each optional):
      replaced_at  a newer wait or disposition for the same owner: the newest wait wins
      intent_at    the owner's latest own `intent` row
      starts       the owner's recorded turn starts (wal.py `subagent` rows: written on spawn and on every resume)
      stops        the owner's recorded stops (wal.py `subagent_stop` rows; never a synthetic stop)
      work_at      the owner's latest own WAL row that is not hook metadata (check, status, result, commit, ...)
      active_at    the owner's latest activity of any kind (any own WAL row, or a transcript write)

    The wait is superseded by:
      1. a newer wait;
      2. unambiguous new work strictly after the wait, with no slack (whole seconds): an own intent or a turn start;
      3. an own non-metadata row more than WAIT_SUPERSEDE_S after the wait;
      4. activity of any kind past a limit. The limit is wait + WAIT_SUPERSEDE_S, unless the recorded rows show the
         owner in a turn at the wait (its latest start at or before the wait is later than its latest recorded stop
         at or before it). Then the turn's closing tail is allowed until the earlier of wait + WAIT_TAIL_S and its
         first recorded stop after the wait + STOP_SLACK_S (never less than wait + WAIT_SUPERSEDE_S). Owners with no
         recorded starts (task WALs, unhooked agents) always get the strict limit."""
    act = activity or {}
    wait_at = float(wait_at or 0.0)
    if float(act.get("replaced_at") or 0.0) > wait_at:
        return False
    starts = [float(s) for s in (act.get("starts") or ()) if s]
    stops = [float(s) for s in (act.get("stops") or ()) if s]
    if _whole(act.get("intent_at")) > _whole(wait_at) or any(_whole(s) > _whole(wait_at) for s in starts):
        return False
    if float(act.get("work_at") or 0.0) > wait_at + WAIT_SUPERSEDE_S:
        return False
    limit = wait_at + WAIT_SUPERSEDE_S
    began = max((s for s in starts if s <= wait_at), default=0.0)
    if began and began > max((s for s in stops if s <= wait_at), default=0.0):
        tail = wait_at + WAIT_TAIL_S
        after = [s for s in stops if s > wait_at]
        if after:
            tail = min(tail, min(after) + STOP_SLACK_S)
        limit = max(limit, tail)
    return float(act.get("active_at") or 0.0) <= limit


def ack_bound(ack_at: float, activity: dict | None = None) -> bool:
    """A main-acknowledged (--ack-handoff) wait takes the owner's result (goodqa#15949 r5b F1). It binds to that result:
    it stays whole only while the owner's latest outcome (handoff or result) is still one recorded at or before the
    ack. A new intent clears the outcome and a newer result replaces it; then the ack is a plain wait under
    wait_current(). No outcome at all: nothing to bind, so the plain (strict) rule."""
    outcome_at = (activity or {}).get("outcome_at") or 0.0
    return bool(outcome_at) and _whole(outcome_at) <= float(ack_at or 0.0)


def note_wait(note: str, note_at: float, now: float, activity: dict | None = None):
    """waiting_on(note) while the note is younger than NOTE_WAIT_MAX_S (counted from the note's own time) and
    wait_current(note_at, activity) holds; None otherwise."""
    if not note_at or now - note_at >= NOTE_WAIT_MAX_S or not wait_current(note_at, activity):
        return None
    return waiting_on(note)


TASK_ABANDON_S = 6 * 3600  # a task-named WAL (no process behind it) silent this long without a terminal note is DROPPED


def classify_task_wal(now: float, last_at: float, outcome: str | None, last_note: str = "",
                      note_at: float | None = None, activity: dict | None = None) -> dict:
    """The one rule for task-named WALs (goodqa#14791 I8): shared by `ah owners`, ops-watch and the dropped scan.
    `note_at` is the time of the record that wrote `last_note` (default: last_at); `activity` goes to wait_current."""
    idle = max(0.0, now - last_at) if last_at else float("inf")
    if outcome in ("result", "done", "delivered"):
        return {"state": "done", "idle_s": idle, "severity": "info"}
    if outcome == "handoff":
        return {"state": "handoff", "idle_s": idle, "severity": "info"}
    wait = note_wait(last_note, last_at if note_at is None else note_at, now, activity)
    if wait:
        return {"state": f"waiting-on-{wait}", "idle_s": idle, "severity": "info"}
    if idle >= TASK_ABANDON_S:
        return {"state": "DROPPED", "idle_s": idle, "severity": "high"}
    if idle >= HIGH_S:
        return {"state": "SILENT-HIGH", "idle_s": idle, "severity": "high"}
    if idle >= SILENT_S:
        return {"state": "SILENT", "idle_s": idle, "severity": "warning"}
    return {"state": "live" if idle <= LIVE_WAL_S else "quiet", "idle_s": idle, "severity": "info"}


def classify(now: float, last_wal: float, transcript_mtime: float, stopped: bool, outcome: str | None,
             last_note: str = "", agent_type: str | None = None, registered: bool = False,
             owner: bool | None = None, finish_grace: float | None = None, note_at: float | None = None,
             activity: dict | None = None) -> dict:
    """Return {"state", "idle_s", "severity"}; `outcome` is the last done/handoff/result kind or None. A stopped
    owner's `last_note` names a wait only while note_wait() holds: `note_at` is that note's own time (default:
    last_wal) and `activity` goes to wait_current."""
    last = max(last_wal or 0.0, transcript_mtime or 0.0)
    idle = max(0.0, now - last) if last else float("inf")
    if stopped:
        if outcome == "result":
            state = "done"
        elif outcome == "handoff":
            state = "handoff"
        else:
            wait = note_wait(last_note, last_wal if note_at is None else note_at, now, activity)
            if wait:
                state = f"waiting-on-{wait}"
            else:
                is_owner = owner if owner is not None else (registered or (agent_type or "task-owner") in OWNER_TYPES)
                state = "returned"
                if is_owner:
                    grace = FINISH_GRACE_S if finish_grace is None else finish_grace
                    state = "finishing" if idle < grace else "DROPPED"
        return {"state": state, "idle_s": idle, "severity": "high" if state == "DROPPED" else "info"}
    wal_idle = now - last_wal if last_wal else float("inf")
    tr_idle = now - transcript_mtime if transcript_mtime else float("inf")
    if wal_idle <= LIVE_WAL_S or tr_idle <= LIVE_TRANSCRIPT_S:
        return {"state": "live", "idle_s": idle, "severity": "info"}
    if owner is False:  # a helper nobody named as owner: idle is expected, never an alert
        return {"state": "idle-helper", "idle_s": idle, "severity": "info"}
    if idle < SILENT_S:
        return {"state": "quiet", "idle_s": idle, "severity": "info"}
    if idle >= HIGH_S:
        return {"state": "SILENT-HIGH", "idle_s": idle, "severity": "high"}
    return {"state": "SILENT", "idle_s": idle, "severity": "warning"}
