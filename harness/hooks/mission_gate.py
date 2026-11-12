#!/usr/bin/env python3
"""Mission gate: a Stop hook that blocks the main agent's turn from ending while any active mission goal is UNCOVERED
(GoodQA goodqa#15565; the rule lives in mission_coverage.py), and the PreToolUse(Bash) hook that stamps main's own
main-only mission commands (`mission_gate.py pretool`): one stamp per command that runs mission_coverage.py at shell
command position, keyed by its exact argument list; echoed, quoted, grepped or here-document text is never stamped.
The command line is split by a quote-aware tokenizer (shell_tokens): quoted or escaped punctuation is a word
character, never a separator (r14 F1), and a line whose words only the shell knows gets no stamp at all.

Evidence: 2026-11-10 the leads goal (goodqa#15095) had no owner all night; the user had to ask "whats moving the
slowest" and then "why doesnt the dashboard and harness deal with this?". The dropped-owner gate only sees owners that
existed; this gate sees goals.

Scope and safety:
  - main only (caller_identity.is_main: proven by its own transcript path), and only the main session that owns the
    mission (goals.json mission_session, sealed in the audit chain); sub-agents, Codex and other sessions never block;
  - a host with no goals file never blocks (no mission configured there);
  - owners come from ops-watch's signed snapshot when fresh, else a live scan within OWNER_SCAN_BUDGET_S; a missing,
    forged or overrun owner list never counts as coverage: the turn may end with "owner list unavailable" and a high
    `mission:scan:unavailable` alert;
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
import re
import sys
import time
import uuid
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

MAX_STOP_BLOCKS = 25
OWNER_SCAN_BUDGET_S = 9  # the hook has 15 s; `ah owners` took ~24 s on a 2,089-owner session (2026-11-10)
VALVE_KEY = "mission:gate-valve"
SCAN_KEY = "mission:scan:unavailable"
STAMP_PURPOSE = "mission-main"
MAIN_ONLY = ("set", "defer", "import-initiatives", "reseal", "activate", "set-session", "bind", "retire",
             "attach")


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
    """Atomic write that never follows a planted symlink: a fresh pid-unique temp file (O_EXCL|O_NOFOLLOW), then a
    rename over the target (which replaces a symlink rather than writing through it)."""
    path = state_path(home, session)
    try:
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if os.path.islink(path.parent):
            return
        tmp = path.with_name(f".{path.name}.{os.getpid()}.{uuid.uuid4().hex[:8]}.tmp")
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(state, fh)
        os.replace(tmp, path)
    except OSError:
        pass


def ring(home: Path, event: str, message: str, detail: dict, key: str = VALVE_KEY) -> None:
    """Raise (or clear) a gate alert in the shared ops ring, once per change. Best effort."""
    try:
        import ops_watch  # noqa: PLC0415
        path = ops_watch.ring_path(home)
        latest = None
        for e in ops_watch.read_ring(path):
            if e.get("source") == "mission-gate" and e.get("key") == key:
                latest = e
        if (latest or {}).get("event", "clear") == event:
            return
        ops_watch.emit({"host": ops_watch.default_host(), "source": "mission-gate", "event": event,
                        "severity": "high", "key": key, "message": message[:300], "detail": detail}, path=path)
    except Exception:  # noqa: BLE001
        pass


PYTHON = re.compile(r"^python(?:\d+(?:\.\d+)*)?$")
ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
# The quote-aware tokenizer lives in shellwords.py (shared with dropped_gate.py); the names stay importable here.
from shellwords import (HEREDOCS, OPERATOR_START, OPERATORS, REDIRECTS, SEPARATORS, Unparsed, Word,  # noqa: E402,F401
                        shell_tokens, simple_commands)


def mission_argv(words: list):
    """The argv after the script when this simple command runs mission_coverage.py itself (`[VAR=x ...] [python3
    [-flags]] .../mission_coverage.py SUB ...`); None when the script name is only an argument (echo, grep, cat)."""
    i = 0
    while i < len(words) and ASSIGN.match(words[i]):
        i += 1
    if i < len(words) and PYTHON.match(os.path.basename(words[i])):
        i += 1
        while i < len(words) and re.match(r"^-[A-Za-z]+$", words[i]) and words[i] not in ("-c", "-m"):
            i += 1
    if i < len(words) and os.path.basename(words[i]) == "mission_coverage.py":
        return words[i + 1:]
    return None


def stamps_for(cmd: str) -> list:
    """[(subcommand, argv key)] for each main-only mission_coverage.py command this Bash line runs. The key is
    mission_coverage.argv_key of the exact argument list, so the stamp covers that command and nothing else."""
    import mission_coverage as mc  # noqa: PLC0415
    out = []
    for words in simple_commands(cmd):
        argv = mission_argv(words)
        if not argv or argv[0] not in MAIN_ONLY:
            continue
        if any(getattr(w, "computed", False) for w in argv):
            continue  # the process would see what the shell computed, not these words
        flags = {x.split("=", 1)[0] for x in argv[1:] if x.startswith("--")}
        if argv[0] == "set" and not flags & {"--ticket", "--repo", "--target", "--target-source", "--alias"}:
            continue
        if argv[0] == "defer" and not flags & {"--user-source", "--ticket"}:
            continue
        # bash expands an unquoted leading ~ (`import-initiatives ~/x.json`); the process sees the expanded path
        argv = [os.path.expanduser(w) if getattr(w, "tilde", False) and (w == "~" or w.startswith("~/")) else str(w)
                for w in argv]
        out.append((argv[0], mc.argv_key(argv)))
    return out


def cmd_pretool(payload: dict) -> dict:
    """PreToolUse(Bash): when main (proven by caller_identity.is_main) runs a main-only mission command, record a
    one-shot stamp for exactly that argument list. Never denies anything; a sub-agent gets no stamp."""
    if payload.get("tool_name") != "Bash":
        return {}
    tool_input = payload.get("tool_input")
    cmd = str((tool_input if isinstance(tool_input, dict) else {}).get("command") or "")
    if "mission_coverage" not in cmd:
        return {}
    import caller_identity  # noqa: PLC0415
    if not caller_identity.is_main(payload):
        return {}
    session = str(payload.get("session_id") or "")
    for sub, key in stamps_for(cmd)[:10]:
        caller_identity.put_stamp(STAMP_PURPOSE, [sub, key], session=session, home=home_dir())
    return {}


def cmd_stop(payload: dict, now: float | None = None) -> dict:
    import caller_identity  # noqa: PLC0415
    if not caller_identity.is_main(payload):
        return {}
    session = str(payload.get("session_id") or "").lower()
    home = home_dir()
    import mission_coverage as mc  # noqa: PLC0415
    if not os.path.lexists(mc.goals_path(home)) and not mc.audit_segments(home):
        return {}  # no mission configured on this host
    mission = mc.mission_session_of(home)
    if not mission or mission != session:
        return {}  # only the main that owns the mission is held to it (set-session / import)
    a = mc.assess(home, session, now, deadline_s=OWNER_SCAN_BUDGET_S, prefer_snapshot=True)
    if a["state"] == "absent":
        return {}
    if a["state"] == "owners-unavailable":
        why = mc.clean(a.get("error"), 160)
        ring(home, "raise", f"mission gate: owner list unavailable, coverage not checked: {why}",
             {"session": session[:8], "stop_block": False}, key=SCAN_KEY)
        return {"systemMessage": f"mission gate: owner list unavailable ({why}); coverage was NOT checked this turn. "
                                 f"Run `{mc.SCRIPT} report` (ops-watch refreshes the signed owner list every 10 min)."}
    ring(home, "clear", "mission gate: owner list available again", {}, key=SCAN_KEY)
    if a["state"] in ("error", "tampered"):
        problem = mc.clean(a.get("error") or "goals file unreadable", 200)
        sig_src = "file:" + a["state"]
        text = (f"Mission coverage (goodqa#15565) cannot check the mission goals: {problem}.\n"
                f"  Inspect: {mc.SCRIPT} verify ; restore ~/.agent-harness/mission/goals.json from the audit trail, or "
                f"(main) record a deliberate change with `{mc.SCRIPT} reseal --reason <what changed and why>`.")
        names = [problem]
    else:
        uncovered = [r for r in a["results"] if r["state"] == "UNCOVERED"]
        if not uncovered:
            ring(home, "clear", "mission gate: every goal is covered again", {})
            state = load_state(home, session)
            if state.get("blocks"):
                state["blocks"] = {}
                save_state(home, session, state)
            return {}
        text = mc.gate_message(a["results"], a.get("advice") or "")
        if a.get("owners_note") and len(text) + len(a["owners_note"]) < mc.GATE_MAX_CHARS:
            text += "\n" + mc.clean(a["owners_note"], 120)
        names = [f"{r['id']} ({r['ticket'] or 'no ticket'})" for r in mc.sort_report(uncovered)]
        sig_src = ",".join(sorted(r["id"] for r in uncovered))
    sig = hashlib.sha256(sig_src.encode()).hexdigest()[:16]
    state = load_state(home, session)
    count = int((state.get("blocks") or {}).get(sig, 0)) if isinstance(state.get("blocks"), dict) else 0
    shown = ", ".join(names[:5]) + (f" and {len(names) - 5} more" if len(names) > 5 else "")
    if payload.get("stop_hook_active") or count >= MAX_STOP_BLOCKS:
        if count >= MAX_STOP_BLOCKS:
            ring(home, "raise", f"mission gate valve open after {count} blocks: uncovered {shown}",
                 {"session": session[:8], "goals": names[:20], "blocks": count, "stop_block": True})
        return {"systemMessage": f"mission gate: still uncovered after {count} block(s): {shown}. " + text}
    state["blocks"] = {sig: count + 1}  # a signature that cleared starts again from zero
    state["last"] = now or time.time()
    save_state(home, session, state)
    return {"decision": "block", "reason": text}


def main(argv=None) -> int:
    try:
        import safe_input  # noqa: PLC0415
        payload = safe_input.safe_json_loads(safe_input.read_stdin_bounded(1 << 20).decode("utf-8", "replace"))
    except Exception:  # noqa: BLE001 - oversized or malformed hook input: gate nothing
        payload = {}
    payload = payload if isinstance(payload, dict) else {}
    mode = (argv if argv is not None else sys.argv[1:])[:1]
    try:
        out = cmd_pretool(payload) if mode == ["pretool"] else cmd_stop(payload)
    except Exception as exc:  # noqa: BLE001 - a gate crash must not trap the turn silently
        out = {"systemMessage": f"mission gate failed open ({type(exc).__name__})"}
    if out:
        sys.stdout.write(json.dumps(out) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
