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
import time
import uuid
from datetime import datetime, timezone

DEFAULT_MAX_AGENTS = 20  # deny; the replay of a real session showed 8 would block legitimate parallel owners
DEFAULT_WARN_AGENTS = 12
LIVE_WINDOW_S = 600
RESERVE_TTL_S = 120  # a spawn is reserved here until its `subagent` start record appears (burst safety)


def load_json_file(path):
    import safe_input
    return safe_input.safe_json_loads(safe_input.read_bounded(path, 64 * 1024), max_depth=20, max_bytes=64 * 1024)


INFO_CODES = ("live_missing", "schema_newer", "marker_info")
CHAIN_WINDOW_BYTES = 64 * 1024 * 1024  # the newest bytes of each WAL chain that are counted (a test may lower it)


def jsonl_records(path, problems=None, deadline_s=5.0, chain=None):
    """Parsed WAL records of the whole segment chain of `path`, NEWEST first, bounded per line. Only the newest 64 MiB
    of the chain is read, so a budget or the deadline drops the OLDEST records, never the newest (R2-4). A gap, an
    unreadable segment, the 64 MiB window or the deadline is appended to `problems` (never silent); a path that is
    not a WAL is skipped (fail open)."""
    import safe_input
    import wal_segments as ws
    probs = []
    window = CHAIN_WINDOW_BYTES
    try:
        with ws.open_chain(path, chain=chain) as snap:  # one directory scan: the snapshot lists the chain once
            data = snap.read_tail(window)
            total = sum(seg.size for seg in snap.chain.segments) + (snap.chain.live.size if snap.chain.live else 0)
            probs.extend(snap.problems)
        if total > window:  # the window did not reach the start of a longer chain: older rows were not read
            probs.append({"code": "truncated", "message": "only the newest %d of %d bytes were read" % (window, total), "seq": None})
    except (OSError, ws.SegmentProblem):
        data = b""
    if problems is not None:
        problems.extend(p for p in probs if p.get("code") not in INFO_CODES)
    deadline = None if deadline_s is None else time.monotonic() + deadline_s
    for number, line in enumerate(reversed(data.split(b"\n"))):
        if not line.strip():
            continue
        if len(line) > 1024 * 1024:
            continue
        if deadline is not None and number % 256 == 0 and time.monotonic() > deadline:
            if problems is not None:
                problems.append({"code": "truncated", "message": "read deadline reached; older records skipped", "seq": None})
            return
        try:
            yield safe_input.safe_json_loads(line, max_depth=20, max_bytes=1024 * 1024)
        except ValueError:
            continue


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


def _newest_mtime(wal_dir, chain):
    """Newest mtime over a chain's live file and closed segments (lstat); now (never cold) when it cannot be told."""
    names = [seg.name for seg in chain.segments] + ([chain.live.name] if chain.live else [])
    try:
        return max(os.lstat(os.path.join(wal_dir, name)).st_mtime for name in names)
    except (OSError, ValueError):
        return time.time()


def live_agents(wal_dir: str, now: float, window: float = LIVE_WINDOW_S, problems=None):
    """Ids of agents started, not stopped, and active within `window` seconds before `now`. Reads the whole segment
    chain of main and every agent WAL (a closed segment is never an agent of its own)."""
    import wal_segments as ws
    started, stopped, last = {}, set(), {}
    chains = ws.list_wals(wal_dir)  # ONE directory scan; each chain read below scans again, so cold WALs are skipped
    cold_before = time.time() - max(window, LIVE_WINDOW_S) - 60
    for stem in sorted(chains):
        if not (stem == "main" or stem.startswith("agent-")):
            continue
        if stem != "main" and _newest_mtime(wal_dir, chains[stem]) < cold_before:
            # An owner WAL idle for longer than the live window holds no activity inside it, and a start or stop row is
            # also written to main (recent_starts reads them there): it cannot change the count, so it is not read.
            # (Measured: with 2,300 owner WALs each read costs a directory scan; skipping cold ones keeps the hook fast.)
            continue
        path = os.path.join(wal_dir, stem + ".jsonl")
        for record in jsonl_records(path, problems, chain=chains[stem]):  # newest first
            if not isinstance(record, dict):
                continue
            try:
                at = _ts(record["at"])
            except (ValueError, KeyError, TypeError):
                continue
            if at > now:
                continue
            agent = record.get("agent_id")
            if not agent:
                continue
            if record.get("event") == "subagent":
                started[agent] = min(started.get(agent, at), at)  # the earliest start of the agent
            elif record.get("event") == "subagent_stop":
                stopped.add(agent)
            last[agent] = max(last.get(agent, 0), at)
    return sorted(a for a, t in started.items() if a not in stopped and now - last.get(a, t) <= window)


def recent_starts(wal_dir: str, now: float, window: float, problems=None):
    count = 0
    path = os.path.join(wal_dir, "main.jsonl")
    try:
        for record in jsonl_records(path, problems):
            try:
                if record.get("event") == "subagent" and now - window <= _ts(record["at"]) <= now:
                    count += 1
            except (ValueError, KeyError, TypeError, AttributeError):
                continue
    except OSError:
        pass
    return count


def reserve(session_id: str, now: float, state_root: str, wal_dir: str, live: int, ceiling: int, problems=None):
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
        unmatched = max(0, len(slots) - recent_starts(wal_dir, now, RESERVE_TTL_S, problems))
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
    problems = []
    live_ids = live_agents(wal_dir, now, problems=problems) if os.path.isdir(wal_dir) else []
    state = state_root or os.path.join(os.path.expanduser("~"), ".agent-harness", "state")
    try:
        total = reserve(session_id, now, state, wal_dir, len(live_ids), ceiling, problems)
    except OSError:
        total = len(live_ids)  # cannot reserve: fall back to the plain count (still fails open on errors)
    note = ""
    if problems:  # documented fail-open gate, but a chain problem is reported, never skipped silently
        note = ("Chain problem while counting live agents (%s); the live count may be low (the gate stays fail-open)."
                % "; ".join(sorted({"%s %s" % (p.get("code"), str(p.get("message"))[:60]) for p in problems})[:3]))
    if total >= ceiling:
        return {"action": "deny", "live": total, "max": ceiling, "chain_problems": problems,
                "message": (f"Agent gate: {total} agents are already live in this session (limit {ceiling}). Queue this work "
                            "until one finishes, resume an existing owner with SendMessage instead of spawning, or move heavy "
                            "work to dev2. The Mac is the fragile host: unbounded fan-out reset it on 2026-11-04.")}
    if total >= warn_at:
        return {"action": "warn", "live": total, "max": ceiling, "chain_problems": problems,
                "message": (f"Agent gate (warning): {total} agents are live in this session (deny at {ceiling}). Prefer resuming an "
                            "existing owner with SendMessage, queue independent work, and run heavy jobs on dev2.")
                + (" " + note if note else "")}
    if problems:
        return {"action": "allow", "live": total, "chain_problems": problems, "message": "Agent gate: " + note}
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
        if result["action"] == "warn" or result.get("chain_problems"):
            if result.get("chain_problems"):
                sys.stderr.write("agent_gate: warning: WAL chain problem: " + result["message"] + "\n")
            print(json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "additionalContext": result["message"]}}))
        return 0
    except Exception as error:  # fail open
        sys.stderr.write(f"agent_gate: warning: {type(error).__name__}; failing open\n")
        return 0


if __name__ == "__main__":
    sys.exit(main())
