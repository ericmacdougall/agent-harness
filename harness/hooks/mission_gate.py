#!/usr/bin/env python3
"""Mission gate: a Stop hook that blocks the main agent's turn from ending while any active mission goal is UNCOVERED
(GoodQA goodqa#15565; the rule lives in mission_coverage.py).

Evidence: 2026-11-10 the leads goal (goodqa#15095) had no owner all night; the user had to ask "whats moving the
slowest" and then "why doesnt the dashboard and harness deal with this?". The dropped-owner gate only sees owners that
existed; this gate sees goals.

Scope and safety:
  - main only (caller_identity.is_main: proven by its own transcript path); sub-agents and Codex are never gated;
  - a host or session with no goals file never blocks (no mission configured there);
  - an unreadable, hostile or tampered goals file blocks safe-loud with one clear line;
  - bounded: at most MAX_STOP_BLOCKS blocks per problem signature (the sorted uncovered goal ids), then the turn may
    end, the message still names the goals, and a high `mission:gate-valve` alert goes to the ops ring;
    a repeated Stop (`stop_hook_active`) is never blocked again in the same turn;
  - its own errors and an unavailable owner list fail open with a message, never a silent pass or a trapped turn.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

MAX_STOP_BLOCKS = 25
OWNER_SCAN_BUDGET_S = 9  # the hook has 15 s; `ah owners` took ~24 s on a 2,089-owner session (2026-11-10)
VALVE_KEY = "mission:gate-valve"


def home_dir() -> Path:
    return Path(os.environ.get("AH_HOME") or Path.home())


def state_path(home: Path, session: str) -> Path:
    return home / ".agent-harness" / "state" / "mission-gate" / f"{session}.json"


def load_state(home: Path, session: str) -> dict:
    try:
        import safe_input  # noqa: PLC0415
        data = safe_input.safe_json_loads(safe_input.read_bounded(state_path(home, session), 65536), max_depth=8)
        return data if isinstance(data, dict) else {}
    except Exception:  # noqa: BLE001 - a damaged counter only loses the bound, never the decision
        return {}


def save_state(home: Path, session: str, state: dict) -> None:
    path = state_path(home, session)
    try:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        tmp = path.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(state, fh)
        os.replace(tmp, path)
    except OSError:
        pass


def ring(home: Path, event: str, message: str, detail: dict) -> None:
    """Raise (or clear) the valve alert in the shared ops ring, once per change. Best effort."""
    try:
        import ops_watch  # noqa: PLC0415
        path = ops_watch.ring_path(home)
        latest = None
        for e in ops_watch.read_ring(path):
            if e.get("source") == "mission-gate" and e.get("key") == VALVE_KEY:
                latest = e
        if (latest or {}).get("event", "clear") == event:
            return
        ops_watch.emit({"host": ops_watch.default_host(), "source": "mission-gate", "event": event,
                        "severity": "high", "key": VALVE_KEY, "message": message, "detail": detail}, path=path)
    except Exception:  # noqa: BLE001
        pass


def cmd_stop(payload: dict, now: float | None = None) -> dict:
    import caller_identity  # noqa: PLC0415
    if not caller_identity.is_main(payload):
        return {}
    session = str(payload.get("session_id") or "")
    home = home_dir()
    import mission_coverage as mc  # noqa: PLC0415
    if not os.path.lexists(mc.goals_path(home)):
        return {}  # no mission configured on this host
    a = mc.assess(home, session, now, deadline_s=OWNER_SCAN_BUDGET_S)
    if a["state"] == "absent":
        return {}
    if a["state"] == "owners-unavailable":
        return {"systemMessage": f"mission gate failed open: the owner list is unavailable ({a.get('error')}); "
                                 f"run `{mc.SCRIPT} report`"}
    if a["state"] in ("error", "tampered"):
        problem = a.get("error") or "goals file unreadable"
        if a["state"] == "error" and not problem.startswith("goals file unreadable"):
            problem = "goals file unreadable: " + problem
        sig_src = "file:" + a["state"]
        text = (f"Mission coverage (goodqa#15565) cannot check the mission goals: {problem}.\n"
                f"  Inspect: {mc.SCRIPT} verify ; restore ~/.agent-harness/mission/goals.json from the audit trail, or "
                f"record a deliberate change with `{mc.SCRIPT} reseal --reason <what changed and why>`.")
        names = [problem]
    else:
        uncovered = [r for r in a["results"] if r["state"] == "UNCOVERED"]
        if not uncovered:
            ring(home, "clear", "mission gate: every goal is covered again", {})
            return {}
        text = mc.gate_message(a["results"], a.get("advice") or "") + ("\n" + a["owners_note"] if a.get("owners_note") else "")
        names = [f"{r['id']} ({r['ticket'] or 'no ticket'})" for r in uncovered]
        sig_src = ",".join(sorted(r["id"] for r in uncovered))
    sig = hashlib.sha256(sig_src.encode()).hexdigest()[:16]
    state = load_state(home, session)
    count = int((state.get("blocks") or {}).get(sig, 0))
    if payload.get("stop_hook_active") or count >= MAX_STOP_BLOCKS:
        if count >= MAX_STOP_BLOCKS:
            ring(home, "raise", f"mission gate valve open after {count} blocks: uncovered {', '.join(names)}"[:300],
                 {"session": session[:8], "goals": names[:20], "blocks": count, "stop_block": True})
        return {"systemMessage": f"mission gate: still uncovered after {count} block(s): {', '.join(names)}. " + text}
    state.setdefault("blocks", {})[sig] = count + 1
    state["last"] = now or time.time()
    save_state(home, session, state)
    return {"decision": "block", "reason": text}


def main(argv=None) -> int:
    try:
        import safe_input  # noqa: PLC0415
        payload = safe_input.safe_json_loads(safe_input.read_stdin_bounded(1 << 20).decode("utf-8", "replace"))
    except Exception:  # noqa: BLE001 - oversized or malformed hook input: gate nothing
        payload = {}
    try:
        out = cmd_stop(payload if isinstance(payload, dict) else {})
    except Exception as exc:  # noqa: BLE001 - a gate crash must not trap the turn silently
        out = {"systemMessage": f"mission gate failed open ({type(exc).__name__})"}
    if out:
        sys.stdout.write(json.dumps(out) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
