#!/usr/bin/env python3
"""One place that answers: is the harness off, who is calling, and what may they do.

Every guard and gate asks here instead of keeping its own idea of roles.

  harness_off()            True while ~/.agent-harness/OFF exists (the user's off switch; see ah_hook.py).
  caller_model(payload)    model id of the agent whose tool call the hook is judging ('' when unknown).
  is_top_rung(payload)     that model is Fable or Astra.
  is_supervisor(payload)   the calling session is recorded as a supervisor in ~/.agent-harness/roles.json.
  supervised_roots(payload) the project directories that supervisor covers.
  may_delete(payload, path) (allowed, reason): the delete rule the user set on 2026-11-24.
  may_handle_secrets(payload) Fable and Astra may; nobody else.
  may_edit_harness(payload) a Fable or Astra session marked as supervisor may change the harness itself.

Rules (the user, 2026-11-24):
  * Fable and Astra may delete files and folders anywhere, and may handle secrets.
  * A supervisor may clean up repositories and code of the projects it supervises.
  * Any agent may clean up its own code: its session work directory, its scratch directory, and checkouts or
    worktrees it made (callers pass those as `own_roots`).

Threat model, as everywhere in the harness: careless or hurried agents, not one that edits this file or roles.json.
Standard library only; never raises on bad input (unknown means the least privilege).
"""
from __future__ import annotations

import json
import os
import re
import sys
import time
from pathlib import Path

OFF_NAME = "OFF"
ROLES_NAME = "roles.json"
TOP_RUNG = (re.compile(r"^claude-fable-"), re.compile(r"^gpt-[0-9.]+-astra$"), re.compile(r"^(fable|astra)$"))
SESSION_ID = re.compile(r"^[0-9a-fA-F-]{8,64}$")
AGENT_ID = re.compile(r"^[A-Za-z0-9_-]{4,64}$")
TAIL_BYTES = 512 * 1024


def state_dir(home=None) -> Path:
    return Path(home or Path.home()) / ".agent-harness"


def off_path(home=None) -> Path:
    return state_dir(home) / OFF_NAME


def harness_off(home=None) -> bool:
    """True while the off switch is set. Any error reading it counts as on."""
    try:
        return off_path(home).exists()
    except OSError:
        return False


# ---- who is calling -------------------------------------------------------------------------------------------

def _transcript(payload) -> Path | None:
    """The calling agent's own transcript: the sub-agent's file when the payload names an agent, else the session's."""
    path = payload.get("agent_transcript_path") or payload.get("transcript_path")
    if not isinstance(path, str) or not path or "\x00" in path:
        return None
    main = Path(path)
    agent = payload.get("agent_id")
    if isinstance(agent, str) and AGENT_ID.match(agent) and not payload.get("agent_transcript_path"):
        name = agent if agent.startswith("agent-") else "agent-" + agent
        candidate = main.with_suffix("") / "subagents" / (name + ".jsonl")
        if candidate.is_file():
            return candidate
        return None  # a sub-agent whose transcript cannot be found is unknown, never taken for its parent
    return main if main.is_file() else None


def _last_model(path: Path) -> str:
    try:
        with path.open("rb") as handle:
            handle.seek(0, os.SEEK_END)
            size = handle.tell()
            handle.seek(max(0, size - TAIL_BYTES))
            tail = handle.read()
    except OSError:
        return ""
    for raw in reversed(tail.split(b"\n")):
        if b'"model"' not in raw:
            continue
        try:
            record = json.loads(raw)
        except ValueError:
            continue
        if not isinstance(record, dict):
            continue
        message = record.get("message")
        if record.get("type") == "assistant" and isinstance(message, dict):
            model = message.get("model")
            if isinstance(model, str) and model and not model.startswith("<"):
                return model
        payload = record.get("payload")  # Codex rollout: turn_context carries the model
        if isinstance(payload, dict) and isinstance(payload.get("model"), str) and payload["model"]:
            return payload["model"]
    return ""


def caller_model(payload) -> str:
    """Model id of the calling agent. The payload's own `model` wins (Codex); else the last assistant record of the
    caller's transcript. '' when it cannot be told."""
    if not isinstance(payload, dict):
        return ""
    for key in ("model", "agent_model"):
        value = payload.get(key)
        if isinstance(value, str) and value:
            return value
    path = _transcript(payload)
    return _last_model(path) if path else ""


def is_top_rung(payload) -> bool:
    model = caller_model(payload).strip().lower()
    return bool(model) and any(pattern.search(model) for pattern in TOP_RUNG)


# ---- roles file -----------------------------------------------------------------------------------------------

def load_roles(home=None) -> dict:
    """{"supervisors": {session_id: {"projects": [absolute dirs], "set_at": iso, "by": text}}}"""
    try:
        data = json.loads((state_dir(home) / ROLES_NAME).read_text())
    except (OSError, ValueError):
        return {"supervisors": {}}
    if not isinstance(data, dict) or not isinstance(data.get("supervisors"), dict):
        return {"supervisors": {}}
    return data


def save_roles(data: dict, home=None) -> None:
    directory = state_dir(home)
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = directory / f".{ROLES_NAME}.{os.getpid()}"
    temporary.write_text(json.dumps(data, indent=1, sort_keys=True) + "\n")
    os.chmod(temporary, 0o600)
    os.replace(temporary, directory / ROLES_NAME)


def set_supervisor(session: str, projects, by: str = "user", home=None) -> dict:
    if not isinstance(session, str) or not SESSION_ID.match(session):
        raise ValueError("session must be a session id")
    roots = sorted({str(Path(p).expanduser().resolve()) for p in projects or []})
    data = load_roles(home)
    data["supervisors"][session] = {"projects": roots, "by": by,
                                    "set_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    save_roles(data, home)
    return data["supervisors"][session]


def clear_supervisor(session: str, home=None) -> bool:
    data = load_roles(home)
    found = data["supervisors"].pop(session, None) is not None
    if found:
        save_roles(data, home)
    return found


def _session(payload) -> str:
    value = payload.get("session_id") if isinstance(payload, dict) else None
    return value if isinstance(value, str) else ""


def is_supervisor(payload, home=None) -> bool:
    """The calling session is a recorded supervisor. Its sub-agents are not (they act as ordinary agents)."""
    if not isinstance(payload, dict) or payload.get("agent_id") or payload.get("agent_type"):
        return False
    return _session(payload) in load_roles(home)["supervisors"]


def supervised_roots(payload, home=None) -> list[Path]:
    if not is_supervisor(payload, home):
        return []
    entry = load_roles(home)["supervisors"].get(_session(payload)) or {}
    return [Path(p) for p in entry.get("projects") or [] if isinstance(p, str)]


# ---- what the caller may do -----------------------------------------------------------------------------------

def _inside(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def own_roots(payload, home=None) -> list[Path]:
    """Directories every agent may clean without asking: its session's durable work directory and scratch."""
    session = _session(payload)
    if not session or not SESSION_ID.match(session):
        return []
    base = state_dir(home)
    roots = [base / "work" / session]
    scratch = base / "scratch"
    try:
        roots += [p for p in scratch.glob(f"*/*/{session}") if p.is_dir()]
    except OSError:
        pass
    return roots


def may_delete(payload, path, extra_own_roots=(), home=None) -> tuple[bool, str]:
    """(allowed, reason). `extra_own_roots`: checkouts and worktrees the caller made (the guard knows them).
    A False answer means "not by role"; the guard's other rules (verified backup, approval) still apply."""
    try:
        target = Path(os.path.realpath(os.path.expanduser(str(path))))
    except (OSError, ValueError):
        return False, "unreadable path"
    if is_top_rung(payload):
        return True, "top rung (Fable/Astra) may delete"
    for root in [*own_roots(payload, home), *(Path(os.path.realpath(str(r))) for r in extra_own_roots)]:
        if target != root.parent and _inside(target, root):
            return True, f"caller's own directory {root}"
    for root in supervised_roots(payload, home):
        if _inside(target, Path(os.path.realpath(str(root)))):
            return True, f"supervisor of {root}"
    return False, "not the caller's own code, not a supervised project, not top rung"


def may_handle_secrets(payload) -> bool:
    return is_top_rung(payload)


def may_edit_harness(payload, home=None) -> bool:
    """A Fable or Astra session the user marked as a supervisor is a harness maintainer (the user, 2026-11-24): it
    may change the harness machinery itself (hook scripts, guard policies, the instruction block, hook wiring) and
    weaken a guard to fit reality, with the user's approval recorded in `ah approvals` (kind `harness`). No guard
    refuses it for working on the harness."""
    return is_top_rung(payload) and is_supervisor(payload, home)


# ---- a command-line caller (no hook payload) -------------------------------------------------------------------
# Added for `log_backup.py ack` (context-noise workstream): a CLI run from an agent's shell has no hook payload, so
# its session comes from the runtime's environment and its transcript from the session's project file.

def cli_payload(environ=None, home=None) -> dict:
    """A payload-shaped dict for a CLI run inside a Claude Code shell: session_id from CLAUDE_CODE_SESSION_ID and the
    session's transcript when one is found. {} when the environment names no session."""
    environ = os.environ if environ is None else environ
    session = environ.get("CLAUDE_CODE_SESSION_ID") or ""
    if not SESSION_ID.match(session):
        return {}
    payload = {"session_id": session}
    try:
        for path in (Path(home or Path.home()) / ".claude" / "projects").glob(f"*/{session}.jsonl"):
            if path.is_file():
                payload["transcript_path"] = str(path)
                break
    except OSError:
        pass
    return payload


def describe(payload, home=None) -> dict:
    return {"off": harness_off(home), "model": caller_model(payload), "top_rung": is_top_rung(payload),
            "supervisor": is_supervisor(payload, home), "harness_maintainer": may_edit_harness(payload, home),
            "supervised": [str(p) for p in supervised_roots(payload, home)],
            "own": [str(p) for p in own_roots(payload, home)]}


if __name__ == "__main__":  # debugging aid: pipe a hook payload in, get the caller's facts out
    try:
        incoming = json.load(sys.stdin)
    except ValueError:
        incoming = {}
    print(json.dumps(describe(incoming), indent=1))
