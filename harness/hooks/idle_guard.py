#!/usr/bin/env python3
"""Main-idle guard (GoodQA goodqa#15943).

Evidence: 2026-11-13 21:50Z to 2026-11-14 01:50Z main froze every stream after the user rejected one AskUserQuestion,
ran only the 30-minute checkpoint and reported "holding". dropped_gate stayed clear (every owner had a `waiting`
disposition) and nothing noticed that main was idle while non-user next steps existed.

assess() answers one question from the WALs and the owner view: has nothing progressed for N minutes while some stream
holds a next step that does not need the user? Modes (argv[1]):
  stop    Stop hook: block with the named streams (idle), or when every owner waits on a user ask while another owner
          holds a returned result nobody took (no idle time needed), or when this turn holds a user rejection and
          independent work exists. Bounded per problem signature; main only; fails open on any error.
  reject  PostToolUseFailure / PermissionDenied / UserPromptSubmit: one context line after a user rejection.
ops_watch.check_idle_guard raises the high `idle-guard:<session8>` alert from the same assess().

Progress is: main commit/check/intent/subagent/result/handoff rows, main Agent/Write/Edit pretool rows (a Bash-only
pretool row is not: a checkpoint script is Bash), and any owner activity (its WAL rows or transcript writes).
Not seen: SendMessage (not hooked). Next steps come from WAL and ledger state only; unreviewed PRs and specs are not
looked up over the network (disclosed limitation).
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

IDLE_MIN_DEFAULT = 30
RETURNED_WINDOW_S = 24 * 3600
MAX_STOP_BLOCKS = 2
TAIL_BYTES = 1 << 20
REMINDER = "A rejected question pauses only that question; keep every independent stream moving."
MAIN_PROGRESS = {"commit", "check", "intent", "subagent", "subagent_stop", "result", "handoff", "deploy"}
MAIN_PROGRESS_TOOLS = {"Agent", "Write", "Edit", "NotebookEdit"}
RETURNED_STATES = ("done", "handoff", "returned")
REJECT_RE = re.compile(r"doesn't want to proceed with this tool use|user-rejected|User rejected tool use", re.I)


def idle_min() -> float:
    try:
        return max(1.0, float(os.environ.get("AH_IDLE_GUARD_MIN") or IDLE_MIN_DEFAULT))
    except ValueError:
        return float(IDLE_MIN_DEFAULT)


def _tail_lines(path: Path):
    try:
        size = path.stat().st_size
        with open(path, "rb") as fh:
            fh.seek(max(0, size - TAIL_BYTES))
            data = fh.read()
    except OSError:
        return []
    return data.splitlines()[1:] if size > TAIL_BYTES else data.splitlines()


def main_progress(wal_dir: Path) -> float:
    import ah  # noqa: PLC0415
    best = 0.0
    for raw in _tail_lines(wal_dir / "main.jsonl"):
        try:
            rec = json.loads(raw)
        except ValueError:
            continue  # a torn or hostile line is skipped, never the whole scan
        if not isinstance(rec, dict) or rec.get("by"):
            continue
        ev = rec.get("event")
        if ev in MAIN_PROGRESS or (ev == "pretool" and rec.get("tool") in MAIN_PROGRESS_TOOLS):
            best = max(best, ah.parse_ts(rec.get("at")) or 0.0)
    return best


def assess(home: Path, session: str, now: float | None = None, idle_minutes: float | None = None) -> dict:
    """{idle, idle_s, last_progress, streams: [{agent, ticket, why, next}], returned, all_waiting_on_user}."""
    import ah  # noqa: PLC0415
    import liveness  # noqa: PLC0415
    now = time.time() if now is None else now
    limit = (idle_min() if idle_minutes is None else idle_minutes) * 60
    data = ah.owners(home, session, now=now)
    rows = data.get("owners") or []
    dirs = ah.subagent_dirs(home, session)
    progress = main_progress(ah.session_dir(home, session))
    streams, returned, user_waiters, active = [], [], 0, 0
    for r in rows:
        if not r.get("owner"):
            continue
        agent, state = r["agent_id"], str(r.get("state") or "")
        last = ah.parse_ts(r.get("last_activity")) or 0.0
        progress = max(progress, last, ah.transcript_mtime(home, session, agent, dirs) if r.get("type") != "task-wal" else 0.0)
        d = r.get("disposition") if isinstance(r.get("disposition"), dict) else None
        live = bool(d and d.get("live"))
        ref = str((d or {}).get("ref") or "")
        if live and d.get("kind") == "waiting":
            if ah.ASK_ID_RE.match(ref):
                user_waiters += 1
                continue
            streams.append({"agent": agent, "ticket": r.get("ticket"), "why": f"waiting on {ref or 'a ticket'}, not a user ask",
                            "next": f"work {ref or 'the ticket'} now, or record the real user ask it needs"})
            continue
        if state.startswith(("live", "working")):
            active += 1
        elif state in RETURNED_STATES and now - last <= RETURNED_WINDOW_S and not (d and (live or d.get("kind") in liveness.ENDING_DISPOSITIONS)):
            item = {"agent": agent, "ticket": r.get("ticket"), "why": f"returned a {state} nobody took",
                    "next": "review its result, then merge, resume or close it"}
            streams.append(item)
            returned.append(item)
    idle_s = now - progress if progress else None
    return {"idle": bool(streams) and idle_s is not None and idle_s >= limit, "idle_s": idle_s, "last_progress": progress,
            "streams": streams, "returned": returned, "user_waiters": user_waiters,
            "all_waiting_on_user": bool(user_waiters and not active and returned and len(streams) == len(returned))}


def lines(streams: list) -> str:
    return "\n".join(f"  - {s['agent']} {s.get('ticket') or 'no ticket'}: {s['why']}; next: {s['next']}" for s in streams[:12])


def rejected_this_turn(transcript) -> bool:
    """True when a user rejection sits after the last real user prompt in the transcript tail."""
    if not transcript:
        return False
    seen = False
    for raw in _tail_lines(Path(str(transcript))):
        try:
            rec = json.loads(raw)
        except ValueError:
            continue
        if not isinstance(rec, dict) or rec.get("type") != "user":
            continue
        content = (rec.get("message") or {}).get("content")
        if isinstance(content, str):
            seen = False  # a plain-text user turn starts a new turn
        elif isinstance(content, list) and any(isinstance(c, dict) and c.get("type") == "tool_result" and REJECT_RE.search(str(c.get("content"))) for c in content):
            seen = True
        if rec.get("toolDenialKind") == "user-rejected":
            seen = True
    return seen


def state_path(session: str) -> Path:
    return Path(os.environ.get("AH_HOME") or Path.home()) / ".agent-harness" / "state" / "idle-guard" / f"{re.sub(r'[^A-Za-z0-9._-]', '_', session)[:120]}.json"


def _count(session: str, sig: str, bump: bool) -> int:
    path = state_path(session)
    try:
        state = json.loads(path.read_text())
    except (OSError, ValueError):
        state = {}
    n = int((state.get("blocks") or {}).get(sig, 0)) if isinstance(state, dict) else 0
    if bump:
        try:
            path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            tmp = path.with_suffix(".tmp")
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as fh:
                json.dump({"blocks": {sig: n + 1}}, fh)
            os.replace(tmp, path)
        except OSError:
            pass
    return n


def cmd_stop(payload: dict, now: float | None = None) -> dict:
    session = str(payload.get("session_id") or "")
    if not session or "/" in session or session in (".", ".."):
        return {}
    if os.environ.get("CLAUDE_CODE_ENTRYPOINT", "").startswith("sdk") or payload.get("agent_id"):
        return {}
    try:
        home = Path(os.environ.get("AH_HOME") or Path.home())
        a = assess(home, session, now)
        rejected = rejected_this_turn(payload.get("transcript_path"))
    except Exception:  # noqa: BLE001 - no WAL, a partial install or a bug: fail open, never trap the turn
        return {}
    if a["idle"]:
        head = (f"Main idle {int((a['idle_s'] or 0) // 60)} min with {len(a['streams'])} stream(s) holding a non-user next step "
                f"(goodqa#15943). Act on them before ending the turn:\n")
    elif a["all_waiting_on_user"]:
        head = ("Every owner waits on a user ask while another owner holds a result nobody took (goodqa#15943). "
                "A wait on one ask excuses only that owner:\n")
    elif rejected and a["streams"]:
        head = "A tool call was rejected this turn, and independent work exists (goodqa#15943):\n"
    else:
        return {}
    text = head + lines(a["streams"]) + "\n" + REMINDER
    sig = hashlib.sha256((",".join(sorted(s["agent"] for s in a["streams"])) + f"|{int(a['last_progress'])}").encode()).hexdigest()[:16]
    count = _count(session, sig, bump=False)
    if payload.get("stop_hook_active") or count >= MAX_STOP_BLOCKS:
        return {"systemMessage": "idle guard: " + text}
    _count(session, sig, bump=True)
    return {"decision": "block", "reason": text}


def cmd_reject(payload: dict) -> dict:
    """One line of context after a user rejection (PostToolUseFailure, PermissionDenied) or at the next prompt."""
    event = payload.get("hook_event_name") or ""
    if event == "UserPromptSubmit":
        hit = rejected_this_turn(payload.get("transcript_path"))
    else:
        blob = " ".join(str(payload.get(k) or "") for k in ("error", "tool_response", "reason", "message"))
        hit = bool(REJECT_RE.search(blob) or payload.get("is_interrupt") is True or event == "PermissionDenied")
    if not hit:
        return {}
    return {"hookSpecificOutput": {"hookEventName": event or "PostToolUseFailure", "additionalContext": REMINDER}}


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    try:
        payload = json.loads(sys.stdin.read() or "{}")
        if not isinstance(payload, dict):
            return 0
        out = cmd_reject(payload) if argv[:1] == ["reject"] else cmd_stop(payload) if argv[:1] == ["stop"] else {}
    except Exception:  # noqa: BLE001 - a hook never breaks the session
        return 0
    if out:
        print(json.dumps(out))
    return 0


if __name__ == "__main__":
    sys.exit(main())
