"""Dropped-owner gate: a Stop hook that blocks the main agent's turn from ending, once per set of owners, while a
DROPPED owner of the session (one that stopped without a handoff) has no live disposition (GoodQA goodqa#14791,
NEVER-LOSE.md invariant I1). Since 2026-11-24 this is the one blocking Stop case the context budget keeps: a missed
deadline or an unacknowledged handoff gets one advisory line instead, and a set already blocked once stays silent.
Release 1001 registers only this Stop side (and Codex's Stop through codex/hooks/wal.py): the SubagentStop advisory and
the PreToolUse(Bash) check that read `ah task dispose` commands are deleted, because no hook reads a shell command.

Evidence: on 2026-11-05 21:10Z `ah owners` listed 12 DROPPED owners and the main agent wrote "0 dropped"; the
half-hourly prompt only advised. This hook is deterministic: it reads `ah.owners` (the shared liveness rule and the
dispositions recorded through `ah task dispose`) and blocks with the exact lines to run. The block count is bounded
per problem signature (the sorted set of undisposed agent ids) by MAX_STOP_BLOCKS, so a session cannot be trapped;
after the bound, and on a repeated Stop (`stop_hook_active`), it lets the turn end silently.
"""
from __future__ import annotations

import contextlib
import hashlib
import json
import os
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

MAX_STOP_BLOCKS = 1  # the one Stop block the context budget keeps (2026-11-24): once per set of dead owners
CONTEXT_CAP = 600


def state_path(session: str) -> Path:
    return Path(os.environ.get("AH_HOME") or Path.home()) / ".agent-harness" / "state" / "dropped-gate" / f"{session}.json"


def load_state(session: str) -> dict:
    try:
        import safe_input  # noqa: PLC0415
        data = safe_input.safe_json_loads(safe_input.read_bounded(state_path(session), 65536).decode("utf-8", "replace"))
        return data if isinstance(data, dict) else {}
    except Exception:  # noqa: BLE001 - a damaged counter file only loses the bound, never the decision
        return {}


def save_state(session: str, state: dict) -> None:
    path = state_path(session)
    try:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        tmp = path.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(state, fh)
        os.replace(tmp, path)
    except OSError:
        pass  # the gate still decides; only the bound counter is lost


def _age(r: dict) -> str:
    idle = r.get("idle_s")
    return f"{int(idle // 3600)}h{int(idle % 3600 // 60):02d}m" if isinstance(idle, (int, float)) else "?"


def is_dead(agent: str, r: dict) -> bool:
    """An owner that stopped without a handoff (DROPPED), as opposed to a missed deadline or a handoff nobody took."""
    return not (agent.startswith("dl") and not r) and "handoff-unacked" not in (r.get("flags") or [])


def message(undisposed: list, rows: dict) -> str:
    """At most CONTEXT_CAP characters: one line per kind of subject, each with the command that settles it. A
    finished owner takes a free-text reason, nothing else (release 1001: no deploy evidence, no ticket grammar)."""
    deadlines = [a for a in undisposed if a.startswith("dl") and not rows.get(a)]
    handoffs = [a for a in undisposed if a not in deadlines and "handoff-unacked" in ((rows.get(a) or {}).get("flags") or [])]
    dropped = [a for a in undisposed if a not in deadlines and a not in handoffs]
    lines = ["Owner(s) with no recorded decision (detail: ah owners):"]
    if deadlines:
        lines.append(f"deadline {', '.join(deadlines[:3])} missed: `ah deadline done --id {deadlines[0]}` once it is met")
    for agent in handoffs[:3]:
        lines.append(f"{agent} handed off {_age(rows.get(agent) or {})} ago, unacknowledged: `ah task dispose --agent "
                     f"{agent} --kind resumed` (you took it) or --kind reassigned --ref NEW_ID")
    if dropped:
        shown = ", ".join(f"{a} ({_age(rows.get(a) or {})})" for a in dropped[:4])
        more = f" +{len(dropped) - 4} more" if len(dropped) > 4 else ""
        lines.append(f"DROPPED {shown}{more}: `ah task dispose --agent ID --kind finished --reason 'WHY'`, or --kind "
                     "resumed, reassigned --ref NEW_ID, waiting --ref 'WHAT' --until ISO, superseded|wontdo --reason 'WHY'")
    text = "\n  - ".join(lines)
    return text if len(text) <= CONTEXT_CAP else text[:CONTEXT_CAP - 3] + "..."


GRANDFATHER_MAX = 50  # legacy rows one Stop may write


def grandfather(session: str, data: dict, now=None) -> list:
    """One-time grandfather (main's request, goodqa#14791): an undisposed owner whose last activity predates this
    host's gate install time is recorded as `legacy` through ah, which re-checks the epoch and writes the audit row.
    Owners that went quiet after the install are never touched. Returns the ids recorded."""
    try:
        import ah  # noqa: PLC0415
        home = Path(os.environ.get("AH_HOME") or Path.home())
        epoch = ah.gate_epoch(home)
    except Exception:  # noqa: BLE001
        return []
    if not epoch:
        return []
    rows = {r["agent_id"]: r for r in data.get("owners") or []}
    done = []
    scope = getattr(ah, "owner_view_scope", None)  # a half-updated install falls back to one view per owner
    with (scope(home, session, data) if scope else contextlib.nullcontext()):  # ah re-checks each owner, view read once
        for agent in list(data.get("undisposed") or [])[:GRANDFATHER_MAX]:
            last = ah.parse_ts((rows.get(agent) or {}).get("last_activity"))
            if not last or last >= epoch:
                continue
            try:
                ah.write(home, "task.dispose", {"agent": agent, "session": session, "kind": "legacy"}, session)
                done.append(agent)
            except Exception:  # noqa: BLE001 - a refused legacy row leaves the owner gated, which is the safe side
                continue
    return done


def cmd_stop(payload: dict, now: float | None = None) -> dict:
    session = str(payload.get("session_id") or "")
    if not session or "/" in session or session in (".", ".."):
        return {}
    if os.environ.get("CLAUDE_CODE_ENTRYPOINT", "").startswith("sdk") or payload.get("agent_id"):
        return {}  # headless or sub-agent sessions are owners themselves; only the interactive main is gated (review M1)
    try:
        import ah  # noqa: PLC0415 - installed beside this hook
        data = ah.owners(Path(os.environ.get("AH_HOME") or Path.home()), session, now=now)
    except Exception:  # noqa: BLE001 - no WAL, a partial install or an ah bug: fail open, never trap the turn
        return {}
    undisposed = list(data.get("undisposed") or [])
    legacy = grandfather(session, data, now)
    if legacy:
        try:
            data = ah.owners(Path(os.environ.get("AH_HOME") or Path.home()), session, now=now)
        except Exception:  # noqa: BLE001
            return {}
        undisposed = list(data.get("undisposed") or [])
    note = (f"dropped-owner gate: {len(legacy)} owner(s) quiet since before the gate was installed were recorded as "
            "unverified-legacy (each has an audit row; `ah owners` lists them until someone follows up): "
            + ", ".join(legacy)) if legacy else ""
    if not undisposed:
        return {"systemMessage": note} if note else {}
    rows = {r["agent_id"]: r for r in data.get("owners") or []}
    text = message(undisposed, rows)
    sig = hashlib.sha256(",".join(undisposed).encode()).hexdigest()[:16]
    state = load_state(session)
    count = int((state.get("blocks") or {}).get(sig, 0))
    if payload.get("stop_hook_active") or count >= MAX_STOP_BLOCKS:
        return {"systemMessage": note} if note else {}  # said once for this set of owners; silent until it changes
    state.setdefault("blocks", {})[sig] = count + 1
    state["last"] = now or time.time()
    save_state(session, state)
    if not any(is_dead(agent, rows.get(agent) or {}) for agent in undisposed):
        # a missed deadline or an unacknowledged handoff is reported, never a block
        return {"systemMessage": "dropped-owner gate: " + text}
    # Kept as the one blocking Stop case: the session holds an owner that died silently.
    return {"decision": "block", "reason": text}


def main(argv=None) -> int:
    mode = (argv or sys.argv[1:] or ["stop"])[0]
    if mode != "stop":
        return 0  # `pretool` and `subagent-stop` were removed in release 1001; a stale registration does nothing
    try:
        import safe_input  # noqa: PLC0415
        payload = safe_input.safe_json_loads(safe_input.read_stdin_bounded(1 << 20).decode("utf-8", "replace"))
    except Exception:  # noqa: BLE001 - oversized or malformed hook input: gate nothing, never block on garbage
        payload = {}
    try:
        payload = payload if isinstance(payload, dict) else {}
        out = cmd_stop(payload)
    except Exception as exc:  # noqa: BLE001 - a gate crash must not block the turn silently
        out = {"systemMessage": f"dropped-owner gate failed open ({type(exc).__name__})"}
    if out:
        sys.stdout.write(json.dumps(out) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
