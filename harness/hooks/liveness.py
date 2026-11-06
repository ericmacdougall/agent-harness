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


DISPOSITIONS = ("resumed", "reassigned", "waiting", "closed")
RESUMED_GRACE_S = 30 * 60  # a "resumed" disposition must be followed by activity within this window


def disposition_live(disp: dict | None, now: float, last_activity: float = 0.0, replacement_live: bool = False) -> bool:
    """Whether a recorded disposition still excuses a DROPPED owner (goodqa#14791, invariant I1).

    resumed     live only while activity follows it: within RESUMED_GRACE_S of its time, or any activity after it
    reassigned  live while the replacement agent is live (the caller resolves that)
    waiting     live until its `until` time (epoch seconds); it must cite an ask id or a ticket (checked at write)
    closed      permanent
    """
    if not isinstance(disp, dict) or disp.get("kind") not in DISPOSITIONS:
        return False
    at = float(disp.get("at") or 0.0)
    kind = disp["kind"]
    if kind == "closed":
        return True
    if kind == "waiting":
        return now < float(disp.get("until") or 0.0)
    if kind == "reassigned":
        return bool(replacement_live)
    return (last_activity > at) or (now - at < RESUMED_GRACE_S)


TASK_ABANDON_S = 6 * 3600  # a task-named WAL (no process behind it) silent this long without a terminal note is DROPPED


def classify_task_wal(now: float, last_at: float, outcome: str | None, last_note: str = "") -> dict:
    """The one rule for task-named WALs (goodqa#14791 I8): shared by `ah owners`, ops-watch and the dropped scan."""
    idle = max(0.0, now - last_at) if last_at else float("inf")
    if outcome in ("result", "done", "delivered"):
        return {"state": "done", "idle_s": idle, "severity": "info"}
    if outcome == "handoff":
        return {"state": "handoff", "idle_s": idle, "severity": "info"}
    wait = waiting_on(last_note)
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
             owner: bool | None = None, finish_grace: float | None = None) -> dict:
    """Return {"state", "idle_s", "severity"}; `outcome` is the last done/handoff/result kind or None."""
    last = max(last_wal or 0.0, transcript_mtime or 0.0)
    idle = max(0.0, now - last) if last else float("inf")
    if stopped:
        if outcome == "result":
            state = "done"
        elif outcome == "handoff":
            state = "handoff"
        else:
            wait = waiting_on(last_note)
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
