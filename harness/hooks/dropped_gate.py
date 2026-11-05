"""Dropped-owner gate: a Stop hook that blocks the main agent's turn from ending while any DROPPED owner of the
session has no live disposition (GoodQA goodqa#14791, NEVER-LOSE.md invariant I1).

Evidence: on 2026-11-05 21:10Z `ah owners` listed 12 DROPPED owners and the main agent wrote "0 dropped"; the
half-hourly prompt only advised. This hook is deterministic: it reads `ah.owners` (the shared liveness rule and the
dispositions recorded through `ah task dispose`) and blocks with the exact lines to run. The block count is bounded
per problem signature (the sorted set of undisposed agent ids) by MAX_STOP_BLOCKS, so a session cannot be trapped;
after the bound, and on a repeated Stop (`stop_hook_active`), it lets the turn end but still names the owners.
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

MAX_STOP_BLOCKS = 3


def state_path(session: str) -> Path:
    return Path(os.environ.get("AH_HOME") or Path.home()) / ".agent-harness" / "state" / "dropped-gate" / f"{session}.json"


def load_state(session: str) -> dict:
    try:
        data = json.loads(state_path(session).read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
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


def message(undisposed: list, rows: dict) -> str:
    lines = []
    for agent in undisposed:
        r = rows.get(agent) or {}
        idle = r.get("idle_s")
        age = f"{int(idle // 3600)}h{int(idle % 3600 // 60):02d}m" if isinstance(idle, (int, float)) else "?"
        lines.append(f"  - {agent} DROPPED {age} ticket {r.get('ticket') or 'none'}: run one of\n"
                     f"      ah task dispose --agent {agent} --kind resumed   (after you resume or re-spawn it)\n"
                     f"      ah task dispose --agent {agent} --kind reassigned --ref <new agent id>\n"
                     f"      ah task dispose --agent {agent} --kind waiting --ref <ask id or GoodQA ticket> --until <ISO>\n"
                     f"      ah task dispose --agent {agent} --kind closed --reason <why> --evidence <ticket|WAL id|sha>")
    return ("Dropped owners need a decision before this turn ends (goodqa#14791):\n" + "\n".join(lines) +
            "\nA dropped owner is a defect: resume it, reassign it, name what it waits on, or close it with evidence.")


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
    if not undisposed:
        return {}
    rows = {r["agent_id"]: r for r in data.get("owners") or []}
    text = message(undisposed, rows)
    sig = hashlib.sha256(",".join(undisposed).encode()).hexdigest()[:16]
    state = load_state(session)
    count = int((state.get("blocks") or {}).get(sig, 0))
    if payload.get("stop_hook_active") or count >= MAX_STOP_BLOCKS:
        return {"systemMessage": f"dropped-owner gate: {len(undisposed)} owner(s) still undisposed after {count} block(s): "
                                 + ", ".join(undisposed) + ". " + text}
    state.setdefault("blocks", {})[sig] = count + 1
    state["last"] = now or time.time()
    save_state(session, state)
    return {"decision": "block", "reason": text}


def main(argv=None) -> int:
    try:
        payload = json.load(sys.stdin)
    except ValueError:
        payload = {}
    try:
        out = cmd_stop(payload if isinstance(payload, dict) else {})
    except Exception as exc:  # noqa: BLE001 - a gate crash must not block the turn silently
        out = {"systemMessage": f"dropped-owner gate failed open ({type(exc).__name__})"}
    if out:
        sys.stdout.write(json.dumps(out) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
