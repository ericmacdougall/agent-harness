#!/usr/bin/env python3
"""Main-idle guard (GoodQA goodqa#15943).

Evidence: 2026-11-13 21:50Z to 2026-11-14 01:50Z main froze every stream after the user rejected one AskUserQuestion,
ran only the 30-minute checkpoint and reported "holding". dropped_gate stayed clear (every owner had a `waiting`
disposition) and nothing noticed that main was idle while non-user next steps existed.

assess() answers one question from the WALs and the owner view: has nothing progressed for N minutes while some stream
holds a next step that does not need the user? Whether a stream needs main is ah.owners()'s answer, never re-derived
here: an owner is actionable exactly when its row is decision_required or has `attention` (an untaken result or
handoff, an invalid wait, a wait on a ticket or agent, a silent owner); it is a genuine user wait only when it is not
actionable and its `wait_on` is an open ask (owners() already checked the ask is its own). Modes (argv[1]):
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
MAX_STOP_BLOCKS = 2
TAIL_BYTES = 1 << 20
REMINDER = "A rejected question pauses only that question; keep every independent stream moving."
MAIN_PROGRESS = {"commit", "check", "intent", "subagent", "subagent_stop", "result", "handoff", "deploy"}
MAIN_PROGRESS_TOOLS = {"Agent", "Write", "Edit", "NotebookEdit"}
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


def actionable(r: dict) -> dict | None:
    """The stream main must act on for one `ah owners` row, or None. Pure classification: an owner needs main exactly
    when ah.owners() marks it decision_required or puts anything in its `attention` (goodqa#15943, rescue of r1-r4).
    No acknowledgement, wait or ask-ownership rule is re-derived here; a missing signal is fixed in ah.owners()."""
    attention = [str(a) for a in r.get("attention") or []]
    flags = [str(f) for f in r.get("flags") or []]
    if not (r.get("decision_required") or attention):
        return None
    signals = attention + (["decision_required"] if r.get("decision_required") else []) + \
        [f for f in flags if f == "handoff-unacked" or f.startswith(("wait-target-", "wait-ask-"))]
    state, ref = str(r.get("state") or ""), r.get("wait_on") or "a ticket"
    if "handoff-unacked" in flags or "result-unacked" in attention:
        why, nxt = f"returned a {state} nobody took", "review its result, then merge, resume or close it"
    elif "wait-invalid" in attention:
        why = f"its wait on {ref} is not its own ({'/'.join(f for f in flags if f.startswith('wait-ask-'))})"
        nxt = "work an independent item, or raise an ask that names this owner"
    elif "wait-not-user" in attention:
        why, nxt = f"waiting on {ref}, not a user ask", f"work {ref} now, or record the real user ask it needs"
    elif r.get("decision_required"):
        why = f"{state} with no live disposition ({', '.join(f for f in flags if f != 'unregistered-owner') or 'decision required'})"
        nxt = "resume, reassign or close it (ah task dispose)"
    else:
        why, nxt = f"{state}: {', '.join(attention)}", "look at it: resume it, or record what it waits on"
    return {"agent": r["agent_id"], "ticket": r.get("ticket"), "why": why, "next": nxt, "signals": signals}


def assess(home: Path, session: str, now: float | None = None, idle_minutes: float | None = None) -> dict:
    """{idle, idle_s, last_progress, streams: [{agent, ticket, why, next, signals}], returned, user_waiters,
    all_waiting_on_user}. ah.owners() is the single source of truth for whether an owner needs main; this only
    classifies its rows into actionable streams and genuine user waits, plus main's own progress time."""
    import ah  # noqa: PLC0415
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
        agent = r["agent_id"]
        last = ah.parse_ts(r.get("last_activity")) or 0.0
        progress = max(progress, last, ah.transcript_mtime(home, session, agent, dirs) if r.get("type") != "task-wal" else 0.0)
        item = actionable(r)
        if item:  # actionable always wins over a user wait (receipt r4 F1)
            streams.append(item)
            if "result-unacked" in item["signals"] or "handoff-unacked" in item["signals"]:
                returned.append(item)
        elif r.get("wait_on") and ah.ASK_ID_RE.match(r["wait_on"]):
            user_waiters += 1  # owners() raised nothing, so this is a live wait on the owner's own open ask
        elif str(r.get("state") or "").startswith(("live", "working")):
            active += 1
    idle_s = now - progress if progress else None
    return {"idle": bool(streams) and idle_s is not None and idle_s >= limit, "idle_s": idle_s, "last_progress": progress,
            "streams": streams, "returned": returned, "user_waiters": user_waiters,
            "all_waiting_on_user": bool(user_waiters and not active and returned and len(streams) == len(returned))}


def lines(streams: list) -> str:
    return "\n".join(f"  - {s['agent']} {s.get('ticket') or 'no ticket'}: {s['why']}; next: {s['next']}" for s in streams[:12])


def _human_turn(rec: dict) -> bool:
    """A human-typed prompt, by provenance.user_authorship()'s rules (receipt r6 F1): string or text-block content
    with origin kind `human`; never a task notification, peer message, reminder, meta or compaction record, scheduled
    wakeup or tool result. Without provenance.py (a partial install) only an unmarked plain-string turn counts."""
    try:
        import provenance  # noqa: PLC0415 - installed beside this file
    except ImportError:
        return isinstance((rec.get("message") or {}).get("content"), str) and "toolUseResult" not in rec
    _text, reason = provenance.user_authorship(rec)
    return reason is None


def rejected_this_turn(transcript) -> bool:
    """True when a user rejection sits after the last human prompt in the transcript tail."""
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
        if _human_turn(rec):
            seen = False  # a human prompt starts a new turn
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
