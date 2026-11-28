#!/usr/bin/env python3
"""One place that answers: is the harness off, who is calling, and what may they do.

The role comes from how the session was launched, never from the model name or from anything the agent says
(docs/roles.md; docs/direction.md "Decisions taken"):

  1. AH_ROLE in the environment, put there by the launch: the generated `--settings` file's `env` block
     (ah_sandbox.claude_settings), the managed drop-in's `env` block, or Codex's
     `shell_environment_policy.set.AH_ROLE` (ah_sandbox.codex_launch_args). AH_ROLE_SOURCE names the file.
     Only `worker`, `reviewer` and `supervisor` are launch roles; any other value (`owner` included) is a worker.
  2. No AH_ROLE, no agent marker (AGENT_MARKERS) and no hook payload: `owner`, a person in a terminal.
  3. No AH_ROLE inside an agent: `supervisor` when the owner recorded this session with `ah supervisor set`
     (roles.json), else `worker` (least privilege).

The operating system backs this: a worker's sandbox cannot write approvals.jsonl or roles.json, so a worker that
exports a false AH_ROLE=supervisor still cannot record an approval.

  harness_off()             True while ~/.agent-harness/OFF exists (the user's off switch; see ah_hook.py).
  launch_role()             "owner" | "supervisor" | "worker" | "reviewer", as above.
  caller_model(payload)     model id of the calling agent, for display and reviewer selection only; no authority reads it.
  is_top_rung(payload)      deprecated alias of "owner or supervisor"; no model is read.
  is_supervisor(payload)    the role is supervisor and the payload is not a sub-agent's.
  supervised_roots(payload) the supervisor's projects: its own roles.json entry, else the role default entry.
  may_delete(payload, path) (allowed, reason): owner anywhere; supervisor its own roots and supervised projects;
                            worker and reviewer their own roots only.
  may_handle_secrets(payload) owner or supervisor; workers use `ah secret exec`.
  may_edit_harness(payload) a supervisor whose roles.json entry has "harness": true, with an `ah approve harness`
                            record from the owner.
  caller_transcript(payload) the calling agent's own transcript (for the checkouts it made).

Payload arguments are kept so callers need no edit. They give the session (for roles.json) and tell a sub-agent's or a
hook's call apart; they never carry identity. Threat model, as everywhere in the harness: careless or misled agents, not
one that edits this file; the boundary that holds against more is the sandbox. Standard library only; never raises on
bad input (unknown means the least privilege).
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
ROLES = ("owner", "supervisor", "worker", "reviewer")
LAUNCH_ROLES = ("worker", "reviewer", "supervisor")  # the values a launch may put in AH_ROLE
DEFAULT_KEY = "supervisor"  # roles.json: the role default entry, {"supervisor": {"projects": [...]}}
# Environment markers of a command run inside an agent. ah_approvals.AGENT_MARKERS is the documented list; it is
# repeated here so this module imports nothing at load (guards import it).
AGENT_MARKERS = ("CLAUDECODE", "CODEX_THREAD_ID", "CODEX_TOOL_CALL_ID", "CODEX_SANDBOX", "AI_AGENT")
SESSION_VARS = ("CLAUDE_CODE_SESSION_ID", "CLAUDE_SESSION_ID", "CODEX_THREAD_ID")
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


# ---- the calling agent's transcript and model (display only) ---------------------------------------------------

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
    """Model id of the calling agent, for display and reviewer selection only: no permission reads it. The payload's
    own `model` wins (Codex); else the last assistant record of the caller's transcript. '' when it cannot be told."""
    if not isinstance(payload, dict):
        return ""
    for key in ("model", "agent_model"):
        value = payload.get(key)
        if isinstance(value, str) and value:
            return value
    path = _transcript(payload)
    return _last_model(path) if path else ""


# ---- roles file -----------------------------------------------------------------------------------------------

def _entry(value) -> dict:
    """A roles.json entry with a clean project list; {} for anything that is not one."""
    if not isinstance(value, dict):
        return {}
    projects = value.get("projects")
    return dict(value, projects=[p for p in projects if isinstance(p, str)] if isinstance(projects, list) else [])


def load_roles(home=None) -> dict:
    """{"supervisors": {session_id: {"projects": [absolute dirs], "set_at": iso, "by": text, "harness"?: true}},
        "supervisor": {"projects": [...], ...}}   <- the role default entry, present only when set"""
    try:
        data = json.loads((state_dir(home) / ROLES_NAME).read_text())
    except (OSError, ValueError):
        data = {}
    if not isinstance(data, dict):
        data = {}
    sessions = data.get("supervisors")
    data["supervisors"] = ({k: _entry(v) for k, v in sessions.items() if isinstance(v, dict)}
                           if isinstance(sessions, dict) else {})
    default = _entry(data.get(DEFAULT_KEY))
    if default:
        data[DEFAULT_KEY] = default
    else:
        data.pop(DEFAULT_KEY, None)
    return data


def save_roles(data: dict, home=None) -> None:
    directory = state_dir(home)
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = directory / f".{ROLES_NAME}.{os.getpid()}"
    temporary.write_text(json.dumps(data, indent=1, sort_keys=True) + "\n")
    os.chmod(temporary, 0o600)
    os.replace(temporary, directory / ROLES_NAME)


def _stamp() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _roots(projects) -> list:
    return sorted({str(Path(p).expanduser().resolve()) for p in projects or []})


def set_supervisor(session: str, projects, by: str = "user", home=None) -> dict:
    if not isinstance(session, str) or not SESSION_ID.match(session):
        raise ValueError("session must be a session id")
    data = load_roles(home)
    data["supervisors"][session] = {"projects": _roots(projects), "by": by, "set_at": _stamp()}
    save_roles(data, home)
    return data["supervisors"][session]


def clear_supervisor(session: str, home=None) -> bool:
    data = load_roles(home)
    found = data["supervisors"].pop(session, None) is not None
    if found:
        save_roles(data, home)
    return found


def set_role_default(projects, by: str = "user", harness: bool = False, home=None) -> dict:
    """The entry a session launched as supervisor (AH_ROLE=supervisor) uses when roles.json has none of its own
    (`ah supervisor set --role-default --project DIR`)."""
    data = load_roles(home)
    entry = {"projects": _roots(projects), "by": by, "set_at": _stamp()}
    if harness:
        entry["harness"] = True
    data[DEFAULT_KEY] = entry
    save_roles(data, home)
    return entry


def clear_role_default(home=None) -> bool:
    data = load_roles(home)
    found = data.pop(DEFAULT_KEY, None) is not None
    if found:
        save_roles(data, home)
    return found


def supervisor_entry(session, home=None) -> dict:
    """The roles.json entry that governs a supervisor session: its own when recorded, else the role default; {}."""
    data = load_roles(home)
    own = data["supervisors"].get(session) if isinstance(session, str) and session else None
    return own if own else data.get(DEFAULT_KEY) or {}


# ---- the role, from the launch ---------------------------------------------------------------------------------

def _session(payload) -> str:
    value = payload.get("session_id") if isinstance(payload, dict) else None
    return value if isinstance(value, str) else ""


def _env_session(environ) -> str:
    for name in SESSION_VARS:
        value = environ.get(name)
        if isinstance(value, str) and value:
            return value
    return ""


def _in_agent(environ) -> bool:
    """An agent marker, or a session id only an agent runtime exports to its children."""
    return any(environ.get(name) for name in AGENT_MARKERS + SESSION_VARS)


def _resolve(environ, home=None, session="", hooked=False) -> tuple:
    """(role, source). `session`: the payload's session when a payload names one, else the environment's. `hooked`:
    the call is a hook payload, which is always an agent's call whatever the hook process's environment holds."""
    if "AH_ROLE" in environ:
        declared = str(environ.get("AH_ROLE") or "").strip().lower()
        if declared in LAUNCH_ROLES:
            return declared, str(environ.get("AH_ROLE_SOURCE") or "").strip()[:200] or "AH_ROLE (no AH_ROLE_SOURCE)"
        return "worker", "unknown AH_ROLE value, least privilege"
    if not hooked and not _in_agent(environ):
        return "owner", "no AH_ROLE and no agent marker: a person in a terminal"
    session = session or _env_session(environ)
    if session and session in load_roles(home)["supervisors"]:
        return "supervisor", "roles.json"
    return "worker", "an agent without AH_ROLE, least privilege"


def role_and_source(environ=None, home=None) -> tuple:
    """(launch_role(), where it came from): the AH_ROLE_SOURCE file, "roles.json", or why it defaulted. Never raises."""
    try:
        return _resolve(os.environ if environ is None else environ, home)
    except Exception:  # noqa: BLE001 - unknown is the least privilege
        return "worker", "error, least privilege"


def launch_role(environ=None, home=None) -> str:
    """"owner" | "supervisor" | "worker" | "reviewer" for this process (module docstring). Never raises."""
    return role_and_source(environ, home)[0]


def _is_subagent(payload) -> bool:
    return isinstance(payload, dict) and bool(payload.get("agent_id") or payload.get("agent_type"))


def _caller_role(payload, home=None, environ=None) -> tuple:
    """(role, source) of the caller a payload describes, in this process's environment. A supervisor's sub-agent acts
    as a worker, and a payload that names a hook event, a tool call or a sub-agent is never the owner's. Never
    raises."""
    try:
        payload = payload if isinstance(payload, dict) else {}
        hooked = bool(payload.get("hook_event_name") or payload.get("tool_name")) or _is_subagent(payload)
        role, source = _resolve(os.environ if environ is None else environ, home, _session(payload), hooked)
    except Exception:  # noqa: BLE001
        return "worker", "error, least privilege"
    if role == "supervisor" and _is_subagent(payload):
        return "worker", "a supervisor's sub-agent"
    return role, source


def is_top_rung(payload) -> bool:
    """Deprecated alias: the owner or a supervisor. No model is read."""
    return _caller_role(payload)[0] in ("owner", "supervisor")


def is_supervisor(payload, home=None) -> bool:
    """The caller was launched (or recorded) as a supervisor. Its sub-agents are not (they act as workers)."""
    return _caller_role(payload, home)[0] == "supervisor"


def _caller_session(payload) -> str:
    return _session(payload) or _env_session(os.environ)


def supervised_roots(payload, home=None) -> list[Path]:
    if not is_supervisor(payload, home):
        return []
    return [Path(p) for p in supervisor_entry(_caller_session(payload), home).get("projects") or []]


# ---- what the caller may do -----------------------------------------------------------------------------------

def _inside(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


def own_roots(payload, home=None) -> list[Path]:
    """Directories every agent may clean without asking: its session's durable work directory, its temp directory
    (the TMPDIR session_env.py gives it: tmp/<session_env.tmp_key of its folder name>) and scratch."""
    session = _session(payload)
    if not session or not SESSION_ID.match(session):
        return []
    base = state_dir(home)
    roots = [base / "work" / session]
    try:   # the one name of a session's temp directory (docs/lifecycle.md); unknown means no temp root
        import session_env  # noqa: PLC0415
        roots.append(base / "tmp" / session_env.tmp_key(session_env.workdir.safe_name(session)))
    except Exception:  # noqa: BLE001
        pass
    scratch = base / "scratch"
    try:
        roots += [p for p in scratch.glob(f"*/*/{session}") if p.is_dir()]
    except OSError:
        pass
    return roots


def may_delete(payload, path, extra_own_roots=(), home=None) -> tuple[bool, str]:
    """(allowed, reason). `extra_own_roots`: checkouts and worktrees the caller made (the tool knows them).
    Owner: anywhere. Supervisor: its own roots and its supervised projects. Worker and reviewer: own roots only.
    A False answer means "not by role"; the tool's other rules (verified backup, approval) still apply."""
    try:
        target = Path(os.path.realpath(os.path.expanduser(str(path))))
    except (OSError, ValueError):
        return False, "unreadable path"
    role = _caller_role(payload, home)[0]
    if role == "owner":
        return True, "the owner may delete"
    for root in [*own_roots(payload, home), *(Path(os.path.realpath(str(r))) for r in extra_own_roots)]:
        if target != root.parent and _inside(target, root):
            return True, f"caller's own directory {root}"
    for root in supervised_roots(payload, home):
        if _inside(target, Path(os.path.realpath(str(root)))):
            return True, f"supervisor of {root}"
    return False, f"not the caller's own code and not a supervised project (role {role})"


def may_handle_secrets(payload) -> bool:
    """The owner or a supervisor. Workers and reviewers store and use secrets through `ah secret put|exec`."""
    return _caller_role(payload)[0] in ("owner", "supervisor")


def may_edit_harness(payload, home=None) -> bool:
    """A harness maintainer: a supervisor whose roles.json entry (its own, else the role default) has "harness": true,
    with a live `harness` approval from the owner (`ah approve harness [--what ...]`; whether it covers one change is
    `ah approvals check harness --what ...`). No model is read."""
    if not is_supervisor(payload, home):
        return False
    if supervisor_entry(_caller_session(payload), home).get("harness") is not True:
        return False
    try:
        sys.path.insert(0, str(Path(__file__).resolve().parent))
        import ah_approvals  # noqa: PLC0415 - sibling module
        return bool(ah_approvals.list_approvals(kind="harness", home=home))
    except Exception:  # noqa: BLE001 - an unreadable store is "no approval"
        return False


# ---- a command-line caller (no hook payload) -------------------------------------------------------------------
# Added for `log_backup.py ack` (context-noise workstream): a CLI run from an agent's shell has no hook payload, so
# its session comes from the runtime's environment and its transcript from the session's project file.

SESSION_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")  # a session id the caller passed (ah's --session)


def cli_payload(environ=None, home=None, session=None, agent="") -> dict:
    """A payload-shaped dict for a CLI run inside a Claude Code shell: session_id (from `session`, else
    CLAUDE_CODE_SESSION_ID), agent_id when given, and the session's transcript when one is found. {} when nothing names
    a session or an agent. Unknown stays unknown, which is the least privilege. The one implementation: ah, ah_kill and
    log_backup call it."""
    environ = os.environ if environ is None else environ
    if session is None:
        session = environ.get("CLAUDE_CODE_SESSION_ID") or ""
        valid = bool(SESSION_ID.match(session))
    else:
        session = str(session or "")
        valid = bool(SESSION_NAME.match(session)) and ".." not in session
    payload = {}
    if valid:
        payload["session_id"] = session
        try:
            found = sorted((Path(home or Path.home()) / ".claude" / "projects").glob(f"*/{session}.jsonl"))
            found = [path for path in found if path.is_file()]
            if found:
                payload["transcript_path"] = str(found[0])
        except OSError:
            pass
    if agent:
        payload["agent_id"] = str(agent)
    return payload


def caller_transcript(payload) -> Path | None:
    """The calling agent's own transcript file (the sub-agent's when the payload names one), or None. Tools read it to
    find the checkouts and worktrees the caller made (its `extra_own_roots`)."""
    return _transcript(payload) if isinstance(payload, dict) else None


def describe(payload, home=None) -> dict:
    role, source = _caller_role(payload, home)
    return {"off": harness_off(home), "role": role, "role_source": source, "model": caller_model(payload),
            "top_rung": role in ("owner", "supervisor"), "supervisor": role == "supervisor",
            "harness_maintainer": may_edit_harness(payload, home),
            "supervised": [str(p) for p in supervised_roots(payload, home)],
            "own": [str(p) for p in own_roots(payload, home)]}


if __name__ == "__main__":  # debugging aid: pipe a hook payload in, get the caller's facts out
    try:
        incoming = json.load(sys.stdin)
    except ValueError:
        incoming = {}
    print(json.dumps(describe(incoming), indent=1))
