#!/usr/bin/env python3
"""PreToolUse(Agent|Task|Workflow): the one owner cap per session.

The number is resource_budget.owner_cap() (resource_limits.json `max_live_owners`, default 16; `ah limits show`).
Only owners count: a spawn of a helper type (reviewers, click-testers, fixers, Explore, Plan, ... from
model_tiers.json caps.helper_types) is never counted and never warned about. Live owners come from the session WAL:
a `subagent` record of an owner type, no `subagent_stop`, and WAL activity inside LIVE_WINDOW_S; owner spawns whose
start record has not landed yet hold a slot reservation (taken under flock, so a burst of parallel spawns cannot all
see zero live).

At the cap: a short advisory naming the count, and the spawn proceeds. With `"enforce": true` the spawn is denied.
Fails OPEN on any error; register WITHOUT onFailure=block. Only acts on macOS (HARNESS_HEAVY_GUARD_FORCE=1 overrides
for tests). Stdlib only, Python 3.9 compatible.
"""
from __future__ import annotations

import json
import os
import sys
import uuid
from datetime import datetime, timezone

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

LIVE_WINDOW_S = 600
RESERVE_TTL_S = 120  # an owner spawn is reserved here until its `subagent` start record appears (burst safety)
HELPER_TYPES_DEFAULT = ("red-team", "click-tester", "reviewer", "fixer", "Explore", "Plan", "claude-code-guide",
                        "statusline-setup")


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


def cap():
    """(max live owners, enforce) from resource_budget.owner_cap(), the one owner cap."""
    try:
        import resource_budget
        found = resource_budget.owner_cap()
        return int(found["max"]), bool(found["enforce"])
    except Exception:  # noqa: BLE001 - a partial install: the shipped default, advisory only
        return 16, False


def helper_types():
    try:
        data = load_json_file(os.path.join(os.path.dirname(os.path.abspath(__file__)), "model_tiers.json"))
        found = (data.get("caps") or {}).get("helper_types")
        if isinstance(found, list) and all(isinstance(t, str) for t in found):
            return tuple(found)
    except Exception:  # noqa: BLE001
        pass
    return HELPER_TYPES_DEFAULT


def is_helper(agent_type, helpers=None) -> bool:
    """A known helper type. The WAL stores types through wal.safe_id, which writes "Explore" as "z-explore-<hash>"."""
    value = str(agent_type or "")
    for helper in helpers or helper_types():
        if value == helper or value.startswith("z-" + helper.lower() + "-"):
            return True
    return False


def _ts(text):
    return datetime.fromisoformat(text).timestamp()


def live_owners(wal_dir: str, now: float, window: float = LIVE_WINDOW_S, helpers=None):
    """Ids of owner-type agents started, not stopped, and active within `window` seconds before `now`."""
    started, stopped, last = {}, set(), {}
    helpers = helpers or helper_types()
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
                if record.get("event") == "subagent" and not is_helper(record.get("agent_type"), helpers):
                    started.setdefault(agent, at)
                elif record.get("event") == "subagent_stop":
                    stopped.add(agent)
                last[agent] = max(last.get(agent, 0), at)
    return sorted(a for a, t in started.items() if a not in stopped and now - last.get(a, t) <= window)


live_agents = live_owners  # old name, kept for callers and tests


def recent_owner_starts(wal_dir: str, now: float, window: float, helpers=None):
    count = 0
    helpers = helpers or helper_types()
    try:
        for record in jsonl_records(os.path.join(wal_dir, "main.jsonl")):
            try:
                if record.get("event") == "subagent" and not is_helper(record.get("agent_type"), helpers) \
                        and now - window <= _ts(record["at"]) <= now:
                    count += 1
            except (ValueError, KeyError, TypeError, AttributeError):
                continue
    except OSError:
        pass
    return count


def reserve(session_id: str, now: float, state_root: str, wal_dir: str, live: int, ceiling: int, take: bool = True):
    """Count live owners plus unmatched reservations under flock, and reserve a slot for this spawn when `take` and
    there is room. Returns the count before this spawn."""
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
        unmatched = max(0, len(slots) - recent_owner_starts(wal_dir, now, RESERVE_TTL_S))
        total = live + unmatched
        if take and total < ceiling:
            fd = os.open(os.path.join(slot_dir, f"slot-{int(now * 1000)}-{os.getpid()}-{uuid.uuid4().hex[:8]}"),
                         os.O_CREAT | os.O_WRONLY, 0o600)
            os.close(fd)
        return total


def decide(session_id: str, now: float = None, wal_root: str = None, max_owners: int = None, state_root: str = None,
           subagent_type: str = "", enforce: bool = None):
    """{"action": allow|warn|deny, "live": n, "max": cap, "message"?}. warn is the advisory at the cap; deny only
    with enforce. A helper spawn is always a silent allow."""
    if is_helper(subagent_type):
        return {"action": "allow", "live": None, "helper": True}
    now = now if now is not None else datetime.now(timezone.utc).timestamp()
    root = wal_root or os.path.join(os.path.expanduser("~"), ".claude", "wals")
    wal_dir = os.path.join(root, os.path.basename(session_id))
    ceiling, enforcing = cap()
    ceiling = max_owners or ceiling
    enforcing = enforcing if enforce is None else enforce
    live = len(live_owners(wal_dir, now)) if os.path.isdir(wal_dir) else 0
    state = state_root or os.path.join(os.path.expanduser("~"), ".agent-harness", "state")
    try:
        total = reserve(session_id, now, state, wal_dir, live, ceiling)
    except OSError:
        total = live  # cannot reserve: the plain count (still fails open on errors)
    if total < ceiling:
        return {"action": "allow", "live": total, "max": ceiling}
    if enforcing:
        return {"action": "deny", "live": total, "max": ceiling,
                "message": (f"Owner cap: {total} live owners in this session (cap {ceiling}, enforced). Route this work to "
                            "the owner that holds its stream (SendMessage), or queue it on a ticket.")}
    return {"action": "warn", "live": total, "max": ceiling,
            "message": f"Owner cap: {total} live owners in this session (cap {ceiling}); this spawn proceeds."}


def main() -> int:
    if sys.platform != "darwin" and os.environ.get("HARNESS_HEAVY_GUARD_FORCE") != "1":
        return 0
    try:
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
        tool_input = payload.get("tool_input") if isinstance(payload.get("tool_input"), dict) else {}
        result = decide(session, subagent_type=str(tool_input.get("subagent_type") or ""))
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
