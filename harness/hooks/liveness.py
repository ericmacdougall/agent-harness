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

import re

LIVE_WAL_S = 20 * 60
LIVE_TRANSCRIPT_S = 10 * 60
SILENT_S = 30 * 60
HIGH_S = 60 * 60
FINISH_GRACE_S = 30 * 60  # a just-stopped owner may be between turns or writing its handoff: not a drop yet

_WAITING = re.compile(r"\bwaiting\s+(?:on|for)\s+([A-Za-z0-9_.:#\-]{1,60})", re.I)


# Types that are owners only when main names them as one (a WAL scope/intent/decision note carrying the id).
NAMEABLE_TYPES = ("general-purpose", "claude")


def waiting_on(note: str):
    match = _WAITING.search(note or "")
    return match.group(1) if match else None


# Only owner tasks must leave a handoff/result in their WAL. Helpers (fixer, click-tester, red-team, reviewer,
# Explore, Plan) return their result to the parent as the final message, so stopping without a WAL outcome
# is "returned", not DROPPED. A helper explicitly registered as a task owner (ah task register) is an owner.
OWNER_TYPES = ("task-owner",)


def classify(now: float, last_wal: float, transcript_mtime: float, stopped: bool, outcome: str | None,
             last_note: str = "", agent_type: str | None = None, registered: bool = False,
             owner: bool | None = None) -> dict:
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
                    state = "finishing" if idle < FINISH_GRACE_S else "DROPPED"
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
