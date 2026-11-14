"""Read-only helpers for the hooks that watch lanes (S1): the ops-watch alerts and the spawn-hook advisory.

Both are fail-safe by construction: the advisory reads nothing at all, and the alert reader reads snapshots only,
through the bounded no-follow reader, and returns no alerts (never raises) when the store is missing, malformed,
symlinked or unreadable. Neither writes, neither opens a network connection, neither starts a process.
"""
from __future__ import annotations

import json
import os
import re
import stat
from pathlib import Path

LANE_TASK_KEY = re.compile(r"^stream-[0-9a-f]{12}$")
ALERT_FLAGS = {"reservation-stale": "warning", "push-late": "warning", "record-lagging": "warning",
               "source-unknown": "warning", "drift": "warning", "ledger-reset": "high", "journal-full": "high"}
MAX_SNAPSHOT = 1 << 20
MAX_LANES = 200


def advisory_text(task_key, subagent_type, policy):
    """Advisory for an owner-type spawn whose task key is not a lane's stream key, else None. Reads nothing."""
    try:
        import tier_gate as tg  # noqa: PLC0415
        if not tg.counts_as_owner(subagent_type, policy):
            return None
        if isinstance(task_key, str) and LANE_TASK_KEY.match(task_key):
            return None
        return "no lane: run `ah lane new` for this ticket so the work has a lane, a stream key and a kit (advisory only)"
    except Exception:  # noqa: BLE001 - an advisory must never affect a spawn
        return None


def _read_snapshot(path):
    fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_SNAPSHOT:
            return None
        return json.loads(os.read(fd, MAX_SNAPSHOT + 1))
    finally:
        os.close(fd)


def lane_alerts(store_root):
    """``[(key, severity, message)]`` from the lanes' snapshots; empty on any store problem."""
    root = Path(store_root)
    try:
        if root.is_symlink() or not root.is_dir():
            return []
        out = []
        for lane in sorted(root.glob("lane_*"))[:MAX_LANES]:
            if lane.is_symlink() or not lane.is_dir():
                continue
            try:
                snap = _read_snapshot(lane / "snapshot.json")
            except (OSError, ValueError):
                continue
            if not isinstance(snap, dict):
                continue
            for flag in snap.get("flags") or []:
                if flag in ALERT_FLAGS:
                    out.append(("lane:%s:%s" % (lane.name, flag), ALERT_FLAGS[flag],
                                "lane %s: %s (see `ah lane status --lane %s`)" % (lane.name, flag, lane.name)))
        return out
    except OSError:
        return []
