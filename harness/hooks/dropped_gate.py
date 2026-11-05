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


PENDING_EVENTS = ("intent", "scope", "status", "check", "risk", "decision", "commit", "blocker")
LIFECYCLE_EVENTS = ("pretool", "subagent", "subagent_stop", "prompt", "session", "pending_stop")  # wal.py metadata (review Part 3 #8)


def pending_work(home: Path, session: str, agent: str) -> str | None:
    """Why the agent's own WAL says its work is unfinished, or None (handoff/result/named wait/empty)."""
    import ah  # noqa: PLC0415
    import liveness  # noqa: PLC0415
    path = home / ".claude" / "wals" / session / f"agent-{agent}.jsonl"
    if not path.is_file():
        return None
    last = None
    with open(path, "rb") as fh:
        for raw in fh:
            try:
                rec = json.loads(raw)
            except ValueError:
                continue
            if (isinstance(rec, dict) and rec.get("event") and not rec.get("by")
                    and rec.get("event") not in LIFECYCLE_EVENTS):  # hook metadata rows are not the owner's own entries
                last = rec
    if not last:
        return None
    event, note = str(last.get("event")), str(last.get("note") or "")
    if event in ("handoff", "result") or liveness.waiting_on(note):
        return None
    if event in PENDING_EVENTS:
        return f"last WAL entry is an open {event}"
    return None


def armed_waiter(agent: str, home: Path | None = None) -> bool:
    """A live ah-run job attributed to the agent counts as an armed waiter: its completion record will notify.
    Read from the launcher's ledger directory (~/.agent-harness/reserve/ledger/<run>.json, one row per run, `agent`
    attribution, `end` set when the run finished; docs/observer.md). No ledger dir, or no live row: not armed."""
    import safe_input  # noqa: PLC0415
    home = home or Path(os.environ.get("AH_HOME") or Path.home())
    ledger = home / ".agent-harness" / "reserve" / "ledger"
    try:
        entries = sorted(os.scandir(ledger), key=lambda e: e.name)[-500:]
    except OSError:
        return False
    for entry in entries:
        if not entry.name.endswith(".json") or not entry.is_file(follow_symlinks=False):
            continue
        try:
            row = safe_input.safe_json_loads(safe_input.read_bounded(Path(entry.path), 65536).decode("utf-8", "replace"))
        except Exception:  # noqa: BLE001 - a torn row is not a waiter
            continue
        if isinstance(row, dict) and row.get("agent") == agent and not row.get("end"):
            return True
    return False


def cmd_subagent_stop(payload: dict, now: float | None = None) -> dict:
    session = str(payload.get("session_id") or "")
    agent = str(payload.get("agent_id") or "")
    if not session or not agent or "/" in session or "/" in agent:
        return {}
    home = Path(os.environ.get("AH_HOME") or Path.home())
    try:
        why = pending_work(home, session, agent)
    except Exception:  # noqa: BLE001
        return {}
    if not why or armed_waiter(agent, home):
        return {}
    state = load_state(session)
    seen = state.setdefault("subagent_blocks", {})
    text = (f"Sub-agent {agent} is ending its turn with pending work ({why}) and no armed waiter (goodqa#14791 I7). "
            f"Before stopping: write a handoff or result WAL entry, or name the wait with `ah task dispose --agent {agent} "
            f"--kind waiting --ref <ask id or GoodQA ticket> --until <ISO>`, or arm a waiter with `ah job wait`.")
    if not payload.get("stop_hook_active") and not seen.get(agent):
        seen[agent] = (now or time.time())
        save_state(session, state)
        return {"decision": "block", "reason": text}
    try:  # second stop: let it end, but the owner is DROPPED now, not after the finishing grace
        import ah  # noqa: PLC0415
        import datetime as dt  # noqa: PLC0415
        ts = dt.datetime.fromtimestamp(now or time.time(), dt.timezone.utc).isoformat()  # microseconds, like wal.py
        ah.write(home, "task.pending", {"agent": agent, "session": session, "at": ts}, session,
                 f"pending:{session[:16]}:{agent}:{int((now or time.time()) // 600)}")
    except Exception:  # noqa: BLE001 - the marker is best effort; the message still says what happened
        pass
    return {"systemMessage": "dropped-owner gate: " + text + " It is now DROPPED and needs a disposition."}


def main(argv=None) -> int:
    try:
        import safe_input  # noqa: PLC0415
        payload = safe_input.safe_json_loads(safe_input.read_stdin_bounded(1 << 20).decode("utf-8", "replace"))
    except Exception:  # noqa: BLE001 - oversized or malformed hook input: gate nothing, never block on garbage
        payload = {}
    mode = (argv or sys.argv[1:] or ["stop"])[0]
    try:
        payload = payload if isinstance(payload, dict) else {}
        out = cmd_subagent_stop(payload) if mode == "subagent-stop" else cmd_stop(payload)
    except Exception as exc:  # noqa: BLE001 - a gate crash must not block the turn silently
        out = {"systemMessage": f"dropped-owner gate failed open ({type(exc).__name__})"}
    if out:
        sys.stdout.write(json.dumps(out) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
