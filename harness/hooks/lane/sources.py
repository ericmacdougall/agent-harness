"""Pure source readers for the lane commands (S1).

Every reader returns ``(value, complete, error, read_at)``-shaped data and never an empty value for a failed read.
Nothing here writes, resets or appends: the ledger peek reads the escalation state file directly because the
escalation ledger's own reader replaces a corrupt file with a fresh state and a reset record.
"""
from __future__ import annotations

import hashlib
import json
import os
import stat
import time
from pathlib import Path

MAX_STATE = 1 << 20


def held_agent_ids(rows, policy) -> list:
    """Agent ids of owner rows that hold a slot, by the spawn hook's own predicate (tier_gate helpers are called, not
    copied, so the two cannot drift; the parity test also runs tier_gate.live_owner_ids against the same rows)."""
    import tier_gate as tg  # noqa: PLC0415
    held = []
    for r in rows or []:
        state = str(r.get("state") or "")
        if not tg.counts_as_owner(r.get("type"), policy, r.get("owner")):
            continue
        if not (state.startswith(tg.RUNNING_STATES) or tg._counts_while_idle(r)):
            continue
        if state.startswith(("live", "working", "quiet")) or tg._counts_while_idle(r) or not tg._slot_freed(r):
            held.append(r["agent_id"])
    return sorted(held)


def read_owner_rows(home, session_id):
    """``(rows, complete, error, read_at)`` from ``ah.owners``; incomplete or failed reads are never an empty list."""
    read_at = time.time()
    try:
        import ah  # noqa: PLC0415
        data = ah.owners(Path(home), str(session_id))
    except Exception as error:  # noqa: BLE001 - any failure means capacity is not known
        return [], False, "owner read failed (%s)" % type(error).__name__, read_at
    rows = data.get("owners")
    if not isinstance(rows, list):
        return [], False, "owner read returned no list", read_at
    unread = data.get("unread")
    if unread:
        return rows, False, "owner read incomplete (%s unread)" % (len(unread) if hasattr(unread, "__len__") else unread), read_at
    return rows, True, None, read_at


def session_cap(policy):
    """The configured owner cap, or None when unreadable."""
    try:
        cap = int(policy["caps"]["session_owner_agents"])
    except (KeyError, TypeError, ValueError):
        return None
    return cap if cap > 0 else None


def _read_small(path):
    fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_STATE:
            raise ValueError("not a regular file within the size bound")
        return os.read(fd, MAX_STATE + 1), info.st_mtime
    finally:
        os.close(fd)


def ledger_peek(task, root, policy, prior_activity=False):
    """Pure peek at one stream's escalation state.

    Returns ``{"status": "ok"|"new"|"unreadable", "rung": str|None, "wiping_resets": [reset...], "mtime": float|None,
    "error": str|None}``. ``new`` (no file, no prior activity) is the lowest rung; a missing file after prior activity
    or an unreadable or corrupt one is ``unreadable`` (rung not known). A reset counts as wiping only when it names a
    prior state hash and is not a pending record.
    """
    import escalation as esc  # noqa: PLC0415
    path = Path(root) / (task + ".json")
    if not os.path.lexists(str(path)):
        if prior_activity:
            return {"status": "unreadable", "rung": None, "wiping_resets": [], "mtime": None,
                    "error": "ledger file missing after prior activity"}
        return {"status": "new", "rung": policy["lowest_rung"], "wiping_resets": [], "mtime": None, "error": None}
    try:
        raw, mtime = _read_small(path)
        state = json.loads(raw)
        if (not isinstance(state, dict) or state.get("schema") != esc.SCHEMA or state.get("task") != task
                or not isinstance(state.get("events"), list)):
            raise ValueError("schema")
    except (OSError, ValueError, UnicodeError) as error:
        return {"status": "unreadable", "rung": None, "wiping_resets": [], "mtime": None,
                "error": "ledger unreadable (%s)" % type(error).__name__}
    wiping = [r for r in state.get("resets") or []
              if isinstance(r, dict) and r.get("prior_state_sha256") and not r.get("pending")]
    return {"status": "ok", "rung": esc.rung_of(state["events"], policy)["rung"], "wiping_resets": wiping,
            "mtime": mtime, "error": None}


def preserved_rung(reset, root, policy):
    """The rung shown by a reset's preserved copy when that copy is readable, else None."""
    import escalation as esc  # noqa: PLC0415
    copy = (reset or {}).get("preserved_copy")
    if not copy:
        return None
    try:
        raw, _ = _read_small(copy)
        state = json.loads(raw)
        return esc.rung_of(state["events"], policy)["rung"]
    except (OSError, ValueError, UnicodeError, KeyError, TypeError):
        return None
