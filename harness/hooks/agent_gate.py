#!/usr/bin/env python3
"""PreToolUse(Agent|Task) concurrency gate: cap live subagents per session.

Counts live agents from the session WAL (plus slot reservations for spawns whose start record has not landed yet,
taken under flock so a burst of parallel spawns cannot all see zero live): an agent is live when it has a `subagent`
record, no `subagent_stop`, and its WAL showed activity inside LIVE_WINDOW_S (the stop
hook does not fire for every agent, so recent activity is the liveness signal).
Thresholds live in resource_limits.json beside this file: warn at {"warn_agents": 12} concurrent agents
(advisory context, the spawn proceeds) and deny at {"max_agents": 20}. HARNESS_MAX_AGENTS overrides the deny limit.
The denial tells the caller to queue the work or move it to dev2 (where heavy jobs
belong). Fails OPEN on any error; register WITHOUT onFailure=block. Only acts on macOS
(HARNESS_HEAVY_GUARD_FORCE=1 overrides for tests). Stdlib only, Python 3.9 compatible.
"""
from __future__ import annotations

import json
import os
import re
import sys
import uuid
from datetime import datetime, timezone

DEFAULT_MAX_AGENTS = 20  # deny; the replay of a real session showed 8 would block legitimate parallel owners
DEFAULT_WARN_AGENTS = 12
LIVE_WINDOW_S = 600
RESERVE_TTL_S = 120  # a spawn is reserved here until its `subagent` start record appears (burst safety)


def load_json_file(path):
    import safe_input
    return safe_input.safe_json_loads(safe_input.read_bounded(path, 64 * 1024), max_depth=20, max_bytes=64 * 1024)


def jsonl_records(path):
    """Parsed WAL records, bounded per line; non-regular files and oversize lines are skipped (fail open)."""
    import safe_input
    try:
        for _number, line in safe_input.iter_jsonl_lines(path, max_line=1024 * 1024, max_total_bytes=64 * 1024 * 1024,
                                                         max_seconds=5):
            if line is None:
                continue
            try:
                yield safe_input.safe_json_loads(line, max_depth=20, max_bytes=1024 * 1024)
            except ValueError:
                continue
    except safe_input.InputRejected:
        return


def limits():
    """(warn, deny) thresholds from resource_limits.json; the file wins over code defaults."""
    warn_at, deny_at = DEFAULT_WARN_AGENTS, DEFAULT_MAX_AGENTS
    try:
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "resource_limits.json")
        if os.path.exists(path):
            data = load_json_file(path)
            deny_at = int(data.get("max_agents", deny_at))
            warn_at = int(data.get("warn_agents", warn_at))
    except Exception:  # incl. safe_input.InputRejected (FIFO, device, oversize): keep defaults
        pass
    env = os.environ.get("HARNESS_MAX_AGENTS", "")
    if re.fullmatch(r"[0-9]{1,6}", env) and int(env) > 0:  # ASCII digits only: "²" must not raise
        deny_at = int(env)
    return min(warn_at, deny_at), deny_at


def _ts(text):
    return datetime.fromisoformat(text).timestamp()


def live_agents(wal_dir: str, now: float, window: float = LIVE_WINDOW_S):
    """Ids of agents started, not stopped, and active within `window` seconds before `now`."""
    started, stopped, last = {}, set(), {}
    for name in os.listdir(wal_dir):
        path = os.path.join(wal_dir, name)
        if name == "main.jsonl" or (name.startswith("agent-") and name.endswith(".jsonl")):
            for record in jsonl_records(path):
                try:
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
        for record in jsonl_records(path):
            try:
                if record.get("event") == "subagent" and now - window <= _ts(record["at"]) <= now:
                    count += 1
            except (ValueError, KeyError, TypeError, AttributeError):
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


def decide(session_id: str, now: float = None, wal_root: str = None, max_agents: int = None, state_root: str = None,
           warn_agents: int = None):
    now = now if now is not None else datetime.now(timezone.utc).timestamp()
    root = wal_root or os.path.join(os.path.expanduser("~"), ".claude", "wals")
    wal_dir = os.path.join(root, os.path.basename(session_id))
    warn_at, ceiling = limits()
    ceiling = max_agents or ceiling
    warn_at = warn_agents if warn_agents is not None else min(warn_at, ceiling)
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
    if total >= warn_at:
        return {"action": "warn", "live": total, "max": ceiling,
                "message": (f"Agent gate (warning): {total} agents are live in this session (deny at {ceiling}). Prefer resuming an "
                            "existing owner with SendMessage, queue independent work, and run heavy jobs on dev2.")}
    return {"action": "allow", "live": total}


def main() -> int:
    if sys.platform != "darwin" and os.environ.get("HARNESS_HEAVY_GUARD_FORCE") != "1":
        return 0
    try:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        import safe_input
        try:
            payload = safe_input.safe_json_loads(safe_input.read_stdin_bounded(8 * 1024 * 1024), max_depth=100,
                                                 max_bytes=8 * 1024 * 1024)
        except (safe_input.InputRejected, ValueError):
            return 0  # fail open
        if not isinstance(payload, dict) or payload.get("tool_name") not in ("Agent", "Task", "Workflow"):
            return 0
        session = payload.get("session_id")
        if not isinstance(session, str) or not session:
            return 0
        result = decide(session)
        if result["action"] == "deny":
            sys.stderr.write(result["message"] + "\n")
            return 2
        if result["action"] == "warn":
            print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "additionalContext": result["message"]}}))
        return 0
    except Exception as error:  # fail open
        sys.stderr.write(f"agent_gate: warning: {type(error).__name__}; failing open\n")
        return 0


if __name__ == "__main__":
    sys.exit(main())
