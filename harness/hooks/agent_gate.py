#!/usr/bin/env python3
"""PreToolUse(Agent|Task) concurrency gate: cap live subagents per session.

Counts live agents from the session WAL (plus slot reservations for spawns whose start record has not landed yet,
taken under flock so a burst of parallel spawns cannot all see zero live): an agent is live when it has a `subagent`
record, no `subagent_stop`, and its WAL showed activity inside LIVE_WINDOW_S (the stop
hook does not fire for every agent, so recent activity is the liveness signal).
Default ceiling is 8 concurrent agents per session, configurable with
HARNESS_MAX_AGENTS or {"max_agents": N} in resource_limits.json beside this file.
The denial tells the caller to queue the work or move it to dev2 (where heavy jobs
belong). Fails OPEN on any error; register WITHOUT onFailure=block. Only acts on macOS
(HARNESS_HEAVY_GUARD_FORCE=1 overrides for tests). Stdlib only, Python 3.9 compatible.
"""
from __future__ import annotations

import json
import os
import sys
import uuid
from datetime import datetime, timezone

DEFAULT_MAX_AGENTS = 8
LIVE_WINDOW_S = 600
RESERVE_TTL_S = 120  # a spawn is reserved here until its `subagent` start record appears (burst safety)


def limits():
    value = DEFAULT_MAX_AGENTS
    try:
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "resource_limits.json")
        if os.path.exists(path):
            value = int(json.load(open(path)).get("max_agents", value))
    except (OSError, ValueError, TypeError):
        pass
    env = os.environ.get("HARNESS_MAX_AGENTS", "")
    return int(env) if env.isdigit() and int(env) > 0 else value


def _ts(text):
    return datetime.fromisoformat(text).timestamp()


def live_agents(wal_dir: str, now: float, window: float = LIVE_WINDOW_S):
    """Ids of agents started, not stopped, and active within `window` seconds before `now`."""
    started, stopped, last = {}, set(), {}
    for name in os.listdir(wal_dir):
        path = os.path.join(wal_dir, name)
        if name == "main.jsonl" or (name.startswith("agent-") and name.endswith(".jsonl")):
            with open(path, "r", errors="replace") as handle:
                for line in handle:
                    try:
                        record = json.loads(line)
                        at = _ts(record["at"])
                    except (ValueError, KeyError, TypeError):
                        continue
                    if at > now:
                        break
                    agent = record.get("agent_id")
                    if not agent:
                        continue
                    if record.get("event") == "subagent":
                        started.setdefault(agent, at)
                    elif record.get("event") == "subagent_stop":
                        stopped.add(agent)
                    last[agent] = max(last.get(agent, 0), at)
    return sorted(a for a, t in started.items() if a not in stopped and now - last.get(a, t) <= window)


def recent_starts(wal_dir: str, now: float, window: float):
    count = 0
    path = os.path.join(wal_dir, "main.jsonl")
    try:
        with open(path, "r", errors="replace") as handle:
            for line in handle:
                try:
                    record = json.loads(line)
                    if record.get("event") == "subagent" and now - window <= _ts(record["at"]) <= now:
                        count += 1
                except (ValueError, KeyError, TypeError):
                    continue
    except OSError:
        pass
    return count


def reserve(session_id: str, now: float, state_root: str, wal_dir: str, live: int, ceiling: int):
    """Atomically count + reserve a slot (flock), so a burst of parallel spawns cannot all see 'zero live'.
    Reservations not yet matched by a start record count as live; the same applies to agent types that never
    write start records (general-purpose, Explore, Plan) for RESERVE_TTL_S after spawn."""
    import fcntl
    slot_dir = os.path.join(state_root, "agent-slots", os.path.basename(session_id))
    os.makedirs(slot_dir, mode=0o700, exist_ok=True)
    with open(os.path.join(slot_dir, ".lock"), "w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        slots = []
        for name in os.listdir(slot_dir):
            if name.startswith("slot-"):
                path = os.path.join(slot_dir, name)
                try:
                    age = now - os.stat(path).st_mtime
                except OSError:
                    continue
                if age > RESERVE_TTL_S:
                    try:
                        os.unlink(path)
                    except OSError:
                        pass
                else:
                    slots.append(path)
        unmatched = max(0, len(slots) - recent_starts(wal_dir, now, RESERVE_TTL_S))
        total = live + unmatched
        if total >= ceiling:
            return total
        fd = os.open(os.path.join(slot_dir, f"slot-{int(now * 1000)}-{os.getpid()}-{uuid.uuid4().hex[:8]}"), os.O_CREAT | os.O_WRONLY, 0o600)
        os.close(fd)
        return total


def decide(session_id: str, now: float = None, wal_root: str = None, max_agents: int = None, state_root: str = None):
    now = now if now is not None else datetime.now(timezone.utc).timestamp()
    root = wal_root or os.path.join(os.path.expanduser("~"), ".claude", "wals")
    wal_dir = os.path.join(root, os.path.basename(session_id))
    ceiling = max_agents or limits()
    live_ids = live_agents(wal_dir, now) if os.path.isdir(wal_dir) else []
    state = state_root or os.path.join(os.path.expanduser("~"), ".agent-harness", "state")
    try:
        total = reserve(session_id, now, state, wal_dir, len(live_ids), ceiling)
    except OSError:
        total = len(live_ids)  # cannot reserve: fall back to the plain count (still fails open on errors)
    live = list(range(total))
    if total >= ceiling:
        return {"action": "deny", "live": total, "max": ceiling,
                "message": (f"Agent gate: {total} agents are already live in this session (limit {ceiling}). Queue this work "
                            "until one finishes, resume an existing owner with SendMessage instead of spawning, or move heavy "
                            "work to dev2. The Mac is the fragile host: unbounded fan-out reset it on 2026-11-04.")}
    return {"action": "allow", "live": total}


def main() -> int:
    if sys.platform != "darwin" and os.environ.get("HARNESS_HEAVY_GUARD_FORCE") != "1":
        return 0
    try:
        raw = sys.stdin.read(4 * 1024 * 1024 + 1)
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from heavy_job_guard import json_depth_ok
        if not json_depth_ok(raw):
            return 0
        payload = json.loads(raw)
        if not isinstance(payload, dict) or payload.get("tool_name") not in ("Agent", "Task", "Workflow"):
            return 0
        session = payload.get("session_id")
        if not isinstance(session, str) or not session:
            return 0
        result = decide(session)
        if result["action"] == "deny":
            sys.stderr.write(result["message"] + "\n")
            return 2
        return 0
    except Exception as error:  # fail open
        sys.stderr.write(f"agent_gate: warning: {type(error).__name__}; failing open\n")
        return 0


if __name__ == "__main__":
    sys.exit(main())
