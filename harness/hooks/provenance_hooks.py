#!/usr/bin/env python3
"""Claude Code hooks that keep user-directed asks traceable (see provenance.py and docs/provenance.md). None of them
ever blocks a turn or a tool call for provenance.

  provenance_hooks.py ask-gate    PreToolUse on AskUserQuestion: one advisory line when a question names no
                                  registered `[ask:<id>]`; denies only a modal question while the user is away or
                                  from a sub-agent (ask_presence, which is about presence, not provenance)
  provenance_hooks.py stop-lint   Stop: one advisory line, once per sentence per session, when the final message says
                                  something is needed from the owner and names no registered `[ask:<id>]`
  provenance_hooks.py prompt      UserPromptSubmit: hand the agent that advisory line on its next turn
  provenance_hooks.py answer      PostToolUse on AskUserQuestion: a withdrawing answer revokes this session's
                                  published central decisions (goodqa#16651; prompt and stop-lint do the same for
                                  typed turns and queued messages)
  provenance_hooks.py calibrate   measure the stop-lint detector on a transcript (no hook payload)

Modes come from provenance_policy.json (`ask_user_question`, `stop_lint`: off | warn; an old "enforce" reads as warn).
Every hook fails open on its own bugs (stderr note, exit 0).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import time
from pathlib import Path

import provenance as prov
import safe_input

ASK_ID = re.compile(r"\[ask:\s*([A-Za-z0-9_-]{4,40})\s*\]")
TAIL_BYTES = 4 * 1024 * 1024

# Only explicit needed-from-you phrasing is an ask (owner, 2026-11-24: optional suggestions, offers, questions in
# passing and status notes are not). Short and literal on purpose: a miss costs nothing, a false hit nags.
NEEDED = re.compile(
    r"(?i)\b(?:needed from you|needs? from you|(?:i|we) (?:still )?need you to|waiting on you|waiting for you to|blocked on you|"
    r"(?:action|input|decision)s? (?:needed|required) from you|required from you)\b")
# A negation before the phrase in the same sentence cancels it ("Nothing is needed from you").
NEGATION = re.compile(r"(?i)\b(?:nothing|no|not|none|never|don'?t|do not|doesn'?t|does not|isn'?t|aren'?t)\b")
EMPTY_ITEM = re.compile(r"(?i)^\W*(?:none|nothing|n/?a|no(?:ne| \w+)?|nil|all clear|not applicable)\W*$")
_BULLET_HEAD = re.compile(r"^(\s{0,40})(?:[-*+]|\d{1,3}[.)])\s")
MAX_LINE_CHARS = 2000  # a longer line is cut before any pattern runs
FENCE = re.compile(r"^\s*(`{3,}|~{3,})(.*)$")
QUOTED = re.compile(r"`[^`\n]{0,200}`|\"[^\"\n]{0,200}\"|\u201c[^\u201d\n]{0,200}\u201d")
MAX_ITEMS = 50


def _bullet(line: str):
    head = _BULLET_HEAD.match(line)
    body = line[head.end():].strip() if head else ""
    return (head.group(1), body) if body else None


def detect(text: str) -> list:
    """[{line, text}] for each needed-from-you item in a message. A heading ("What I need from you:") makes each
    bullet under it an item; a sentence with the phrase is an item by itself. Fenced code and quoted text are skipped;
    an unclosed fence is not trusted to hide the rest."""
    lines = [line[:MAX_LINE_CHARS] for line in text.split("\n")]
    items = _detect(lines, honour_fences=True)
    if items is None:
        items = _detect(lines, honour_fences=False) or []
    return items[:MAX_ITEMS]


def _detect(lines: list, honour_fences: bool):
    items, fence, i = [], None, 0
    while i < len(lines) and len(items) < MAX_ITEMS:
        line = lines[i]
        marker = FENCE.match(line) if honour_fences else None
        if marker:
            char, length = marker.group(1)[0], len(marker.group(1))
            if fence is None:
                if marker.group(1) not in marker.group(2):  # ```x``` on one line opens nothing
                    fence = (char, length)
            elif char == fence[0] and length >= fence[1] and not marker.group(2).strip():
                fence = None
            i += 1
            continue
        if fence is not None or not line.strip():
            i += 1
            continue
        for sentence in re.split(r"(?<=[.!?])\s+", line.strip()):
            plain = QUOTED.sub(" ", sentence).replace("\u2019", "'").replace("\u2018", "'")
            found = NEEDED.search(plain)
            if not found or NEGATION.search(plain[:found.start()]):
                continue
            rest = plain[found.end():].strip(" \t:*_-")
            if rest and EMPTY_ITEM.match(rest):
                break
            if rest:
                items.append({"line": i + 1, "text": sentence.strip()})
                break
            j, bullets, saw = i + 1, [], False  # a heading: its bullets are the items
            while j < len(lines) and j - i <= 80:
                bullet = _bullet(lines[j])
                if bullet:
                    saw, number, body, j = True, j + 1, bullet[1], j + 1
                    while j < len(lines) and lines[j].strip() and len(lines[j]) - len(lines[j].lstrip()) > len(bullet[0]):
                        body += " " + lines[j].strip()
                        j += 1
                    if not EMPTY_ITEM.match(body):
                        bullets.append({"line": number, "text": body})
                    continue
                if lines[j].strip() or saw:
                    break
                j += 1
            if bullets:
                items.extend(bullets)
            elif not saw:
                items.append({"line": i + 1, "text": sentence.strip()})
            i = max(i, j - 1)
            break
        i += 1
    if fence is not None and honour_fences:
        return None
    return items


def cite(item_text: str, session: str, home=None) -> dict:
    """{ok, how, problem} for one item: ok when it names an ask registered in this session's WALs (whatever its
    source) or carries an inline `[src: ...]`. Fails open when the ledger cannot be read."""
    found = ASK_ID.search(item_text)
    if found:
        try:
            ask = find_ask(session, found.group(1), home)
        except prov.Problem:
            return {"ok": True, "how": "unchecked"}
        if ask is None:
            return {"ok": False, "problem": f"[ask:{found.group(1)}] is not in this session's ledger"}
        return {"ok": True, "how": "ask"}
    if prov.inline_source(item_text):
        return {"ok": True, "how": "src"}
    return {"ok": False, "problem": "no registered [ask:<id>]"}


def find_ask(session: str, ask_id: str, home=None):
    if not prov.ID_RE.match(ask_id):
        return None
    wals = prov.session_wals(session, home)
    if not wals:  # no WAL at all: hooks or HOME are misconfigured, so do not judge on a guess
        raise prov.Problem("file-unreadable", "no WAL files for this session")
    for path in wals:
        try:
            for line in prov._lines_containing(path, f'"{ask_id}"'.encode()):  # compact or spaced JSON
                if line is None:
                    continue
                try:
                    record = prov.loads_line(line)
                except ValueError:
                    continue
                if isinstance(record, dict) and record.get("id") == ask_id and record.get("event") == "ask":
                    return record
        except prov.Problem as problem:
            if problem.code in ("scan-timeout", "file-too-large", "file-not-regular", "file-unreadable"):
                raise
            continue
    return None


def lint_message(text: str, session: str, home=None) -> list:
    """Needed-from-you items in a final message that name no registered ask."""
    bad, memo = [], {}
    for item in detect(text):
        if item["text"] not in memo:
            memo[item["text"]] = cite(item["text"], session, home)
        outcome = memo[item["text"]]
        if not outcome["ok"]:
            bad.append(dict(item, problem=outcome["problem"]))
    return bad


# --------------------------------------------------------------------------- hook plumbing

def read_payload() -> dict:
    try:
        raw = safe_input.read_stdin_bounded(4 * 1024 * 1024)
        data = prov.loads_line(raw) if raw.strip() else {}
        return data if isinstance(data, dict) else {}
    except (ValueError, OSError, safe_input.InputRejected):
        return {}


TAIL_WINDOW = 2 * 1024 * 1024
MAX_MESSAGE = 200_000


def last_assistant_text(payload: dict) -> str:
    direct = payload.get("last_assistant_message")
    if isinstance(direct, str) and direct.strip():
        return direct[-MAX_MESSAGE:]
    path = payload.get("transcript_path")
    if not isinstance(path, str) or not path:
        return ""
    try:  # regular file under ~/.claude/projects only; at most the last TAIL_WINDOW bytes are read
        tail = prov.read_tail(path, TAIL_WINDOW, root=prov.claude_home() / "projects")
    except prov.Problem as problem:
        print(f"provenance_hooks: transcript_path rejected ({problem.code}); lint skipped", file=sys.stderr)
        return ""
    for raw in reversed(tail.split(b"\n")):
        if (b'"type":"assistant"' not in raw and b'"type":"user"' not in raw) or len(raw) > prov.MAX_LINE:
            continue
        try:
            record = prov.loads_line(raw)
        except ValueError:
            continue
        if isinstance(record, dict) and record.get("type") == "user" and "toolUseResult" not in record:
            return ""  # a real user turn came after the last assistant text: nothing new to lint
        if not isinstance(record, dict) or record.get("type") != "assistant" or record.get("isSidechain"):
            continue
        content = (record.get("message") or {}).get("content")
        pieces = [b.get("text", "") for b in content if isinstance(b, dict) and b.get("type") == "text"] \
            if isinstance(content, list) else ([content] if isinstance(content, str) else [])
        text = "\n".join(p for p in pieces if isinstance(p, str)).strip()
        if text:
            return text[-MAX_MESSAGE:]
    return ""


def valid_session(session: str) -> bool:
    return bool(prov.SESSION_RE.match(session)) and session not in (".", "..")


def reminder_path(session: str) -> Path:
    return Path.home() / ".agent-harness" / "work" / prov.safe_name(session) / "provenance-reminder.txt"


def advisory_line(bad: list) -> str:
    """One short line: the first unregistered item and the fix."""
    more = f" (+{len(bad) - 1} more)" if len(bad) > 1 else ""
    return (f"provenance: \"{prov.clip(bad[0]['text'], 80)}\"{more} tells the owner something is needed from them but "
            "names no registered ask; register it (wal_note.py --event ask) and cite [ask:<id>].")


SEEN_MAX = 500


def lint_state_path(session: str) -> Path:
    return Path(os.environ.get("AH_HOME") or Path.home()) / ".agent-harness" / "state" / "provenance-lint" / f"{prov.safe_name(session)}.json"


def first_sighting(session: str, bad: list) -> list:
    """The items not flagged before in this session (the same sentence is flagged once); records them. On a state
    error everything counts as new: one extra advisory line is cheaper than a silent miss."""
    keys = [hashlib.sha256(prov.norm(item["text"]).lower().encode()).hexdigest()[:20] for item in bad]
    path = lint_state_path(session)
    try:
        state = safe_input.safe_json_loads(safe_input.read_bounded(path, 1 << 16).decode("utf-8", "replace"))
        seen = [k for k in state.get("seen", []) if isinstance(k, str)] if isinstance(state, dict) else []
    except Exception:  # noqa: BLE001 - missing or unreadable: nothing seen yet
        seen = []
    fresh = [item for item, key in zip(bad, keys) if key not in seen]
    if fresh:
        try:
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            tmp = path.with_suffix(f".{os.getpid()}.tmp")
            tmp.write_text(json.dumps({"seen": (seen + [k for k in keys if k not in seen])[-SEEN_MAX:]}), encoding="utf-8")
            os.replace(tmp, path)
        except OSError:
            pass
    return fresh


def cmd_stop_lint(payload: dict) -> dict:
    """The lint result is computed first and printed before the central sweep (goodqa#16651, queued messages)
    runs, so slow central work can never cost the lint outcome. Never blocks."""
    result = _stop_lint(payload)
    session = str(payload.get("session_id") or "")
    if valid_session(session) and central_enabled():
        if result:
            print(json.dumps(result), flush=True)
            result = {}
        central_note(session, payload, "stop")  # never raises; the watchdog may cut it short, the queue survives
    return result


def _stop_lint(payload: dict) -> dict:
    session = str(payload.get("session_id") or "")
    if not valid_session(session) or prov.load_policy().get("stop_lint", "warn") == "off":
        return {}
    bad = lint_message(last_assistant_text(payload), session)
    if not bad:
        try:
            reminder_path(session).unlink()  # a clean message clears an older reminder
        except OSError:
            pass
        return {}
    fresh = first_sighting(session, bad)
    if not fresh:
        return {}
    line = advisory_line(fresh)
    try:  # the agent gets the same line on its next turn via the prompt hook
        path = reminder_path(session)
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        path.write_text(line + "\n", encoding="utf-8")
    except OSError:
        pass
    return {"systemMessage": line}


def central_enabled() -> bool:
    """True when this host has central decisions configured: the same path central_decisions.Store uses (the passwd
    home, never $HOME). Checked before importing central_decisions, whose import (escalation) would otherwise add
    about a second to every Stop, prompt and answer hook on hosts that do not use the feature."""
    try:
        import pwd  # noqa: PLC0415
        home = Path(pwd.getpwuid(os.getuid()).pw_dir)
    except (ImportError, KeyError, OSError):
        home = Path.home()
    return (home / ".agent-harness" / "decisions" / "config.json").exists()


def central_note(session: str, payload: dict, event: str = "prompt"):
    """goodqa#16651: a later user turn naming the top rung or withdrawing (typed, answered to a question, or queued
    mid-turn) revokes this session's published central decisions. Only runs when this host has central decisions
    enabled; never raises."""
    try:
        if not central_enabled():
            return None
        import central_decisions as cd  # noqa: PLC0415
        store = cd.Store()
        if not store.config.exists():
            return None
        if event == "answer":
            return cd.on_ask_answer(session, payload.get("tool_response"), store=store)
        if event == "stop":
            return cd.on_stop(session, store=store)
        return cd.on_user_prompt(session, payload.get("prompt"), store=store)
    except Exception:  # noqa: BLE001
        return None


def cmd_answer(payload: dict) -> dict:
    if payload.get("tool_name") != "AskUserQuestion":
        return {}
    session = str(payload.get("session_id") or "")
    if not valid_session(session):
        return {}
    note = central_note(session, payload, "answer")
    if not note:
        return {}
    return {"hookSpecificOutput": {"hookEventName": "PostToolUse", "additionalContext": "Central decisions: " + note}}


def cmd_prompt(payload: dict) -> dict:
    session = str(payload.get("session_id") or "")
    if not valid_session(session):
        return {}
    note = central_note(session, payload)
    result = _reminder(session)
    if note:
        context = "Central decisions: " + note
        if result:
            context = result["hookSpecificOutput"]["additionalContext"] + "\n" + context
        return {"hookSpecificOutput": {"hookEventName": "UserPromptSubmit", "additionalContext": context}}
    return result


def _reminder(session: str) -> dict:
    path = reminder_path(session)
    claimed = path.with_name(f"{path.name}.{os.getpid()}")
    try:
        os.rename(path, claimed)  # atomic claim: two concurrent prompt hooks cannot both deliver it
    except OSError:
        return {}
    try:
        text = prov.read_small(claimed, 1 << 16).decode("utf-8", "replace")
    except (OSError, prov.Problem):
        return {}
    finally:
        try:
            claimed.unlink()  # never leave a claimed file behind, even when the read failed
        except OSError:
            pass
    return {"hookSpecificOutput": {"hookEventName": "UserPromptSubmit", "additionalContext": text.strip()}}


PRESENCE_MINUTES_DEFAULT = 10


def last_human_turn(session: str) -> float:
    """Epoch of the newest `prompt` event in the session main WAL (the UserPromptSubmit hook writes one per human
    turn), or 0.0. Reads only the tail, never the prompt text."""
    import os  # noqa: PLC0415
    path = Path(os.environ.get("AH_HOME") or Path.home()) / ".claude" / "wals" / session / "main.jsonl"
    newest = 0.0
    try:
        tail = safe_input.read_tail(path, 262144)
        if True:
            for raw in tail.splitlines():
                if b'"prompt"' not in raw:
                    continue
                try:
                    rec = json.loads(raw)
                except ValueError:
                    continue
                if isinstance(rec, dict) and rec.get("event") == "prompt":
                    import datetime as dt  # noqa: PLC0415
                    try:
                        ts = dt.datetime.fromisoformat(str(rec.get("at")).replace("Z", "+00:00"))
                        if ts.tzinfo is None:
                            ts = ts.replace(tzinfo=dt.timezone.utc)
                        newest = max(newest, ts.timestamp())
                    except (TypeError, ValueError):
                        pass
    except OSError:
        return 0.0
    return newest


def user_present(session: str, now: float | None = None) -> bool:
    import os, time  # noqa: PLC0415
    minutes = prov.load_policy().get("ask_presence_minutes", PRESENCE_MINUTES_DEFAULT)
    override = os.environ.get("AH_USER_PRESENT")  # tests and the console can pin presence
    if override in ("0", "1"):
        return override == "1"
    now = time.time() if now is None else now
    return now - last_human_turn(session) <= float(minutes) * 60


def notify_pending_ask(session: str, ids: list, why: str) -> None:
    """Ring alert per ask so the console, the prompt context and the digest carry it (P16/P17). Best effort."""
    try:
        import ops_watch  # noqa: PLC0415
        for ask_id in ids or ["none"]:
            ops_watch.emit({"host": ops_watch.default_host(), "source": "ask-gate", "event": "raise", "severity": "warning",
                            "key": f"ask:{ask_id}:pending-user", "message": f"ask {ask_id} awaits the user ({why}); owner keeps working",
                            "detail": {"session": session[:8], "ask": ask_id}})
    except Exception:  # noqa: BLE001 - the gate decision never depends on the ring
        pass


def presence_block(payload: dict, session: str, ids: list) -> dict:
    """P17 (goodqa#14791 I17): a modal question is allowed only to the interactive main while the user is present.
    Otherwise the ask stays registered, the user is notified through the ring, and the caller continues."""
    import os  # noqa: PLC0415
    mode = prov.load_policy().get("ask_presence", "enforce")
    if mode == "off":
        return {}
    ask_list = ", ".join(f"[ask:{i}]" for i in ids) or "the registered ask"
    if payload.get("agent_id") or os.environ.get("CLAUDE_CODE_ENTRYPOINT", "").startswith("sdk"):
        reason = (f"Sub-agents never call AskUserQuestion: route the question to main with SendMessage, citing {ask_list}, "
                  "record `ah task dispose --agent <you> --kind waiting --ref <ask id> --until <ISO>` if you must wait, "
                  "and continue every independent step.")
        notify_pending_ask(session, ids, "asked by a sub-agent")
    elif not user_present(session):
        reason = (f"The user is away (no human turn within the presence window): {ask_list} stays registered and the user "
                  "is notified; do not block on a modal. Continue all independent work, and if an item must wait, record "
                  "`ah task dispose --agent <owner> --kind waiting --ref <ask id> --until <ISO>`. The answer routes back "
                  "by ask id (`ah user-msg`).")
        notify_pending_ask(session, ids, "user away")
    else:
        return {}
    if mode == "enforce":
        return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                       "permissionDecisionReason": "Ask gate: " + reason}}
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "additionalContext": "(warn mode) Ask gate: " + reason}}


def cmd_ask_gate(payload: dict) -> dict:
    """Never denies for provenance: a question without a registered ask gets one advisory line. Presence (a modal
    while the user is away, or from a sub-agent) is still decided by presence_block."""
    if prov.load_policy().get("ask_user_question", "warn") == "off" or payload.get("tool_name") != "AskUserQuestion":
        return {}
    session = str(payload.get("session_id") or "")
    tool_input = payload.get("tool_input")
    questions = tool_input.get("questions") if isinstance(tool_input, dict) else None
    if not valid_session(session) or not isinstance(questions, list) or not questions:
        return {}
    unregistered = []
    for index, question in enumerate(questions, 1):
        body = question if isinstance(question, str) else str((question or {}).get("question", "")) \
            if isinstance(question, dict) else ""
        if not cite(body, session)["ok"]:
            unregistered.append(index)
    ids = [m.group(1) for m in ASK_ID.finditer(json.dumps(questions, ensure_ascii=False))]
    away = presence_block(payload, session, ids)
    if away:
        return away
    notes = []
    if unregistered:
        notes.append(f"provenance: question {', '.join(map(str, unregistered))} names no registered ask; register it "
                     "(wal_note.py --event ask) and put [ask:<id>] in the question.")
    for ask_id in ids:  # make an id reused for an unrelated question visible to the user
        try:
            ask = find_ask(session, ask_id)
        except prov.Problem:
            ask = None
        if ask:
            notes.append(f"[ask:{ask_id}] = {prov.clip(ask.get('note', ''), 100)}")
    if not notes:
        return {}
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "additionalContext": "Provenance ask ledger: " + "; ".join(notes)}}


# --------------------------------------------------------------------------- calibration

def assistant_messages(path: str) -> list:
    out = []
    for _, raw in safe_input.iter_jsonl_lines(path, prov.MAX_LINE):
        if raw is None or b'"type":"assistant"' not in raw:
            continue
        try:
            record = prov.loads_line(raw)
        except ValueError:
            continue
        if not isinstance(record, dict) or record.get("type") != "assistant" or record.get("isSidechain"):
            continue
        content = (record.get("message") or {}).get("content")
        if isinstance(content, list):
            text = "\n".join(b.get("text", "") for b in content if isinstance(b, dict) and b.get("type") == "text").strip()
            if text:
                out.append({"uuid": record.get("uuid"), "text": text})
    return out


RSS_LIMIT_BYTES = 512 * 1024 * 1024
WALL_LIMIT_SECONDS = 8.0
CPU_LIMIT_SECONDS = 6


def peak_rss_bytes() -> int:
    import resource
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return peak if sys.platform == "darwin" else peak * 1024  # macOS reports bytes, Linux kilobytes


def install_limits(rss_limit=RSS_LIMIT_BYTES, wall_limit=WALL_LIMIT_SECONDS):
    """Backstop against a runaway read or loop: exit 0 (fail open) instead of eating the machine.
    RLIMIT_AS and RLIMIT_DATA are not enforced on macOS, so a watchdog thread polls the peak RSS and the wall
    clock; RLIMIT_CPU is the last resort for a thread that never yields."""
    import threading
    try:
        import resource
        resource.setrlimit(resource.RLIMIT_CPU, (CPU_LIMIT_SECONDS, CPU_LIMIT_SECONDS + 5))
    except (ImportError, ValueError, OSError):
        pass
    started = time.monotonic()

    def watch():
        while True:
            time.sleep(0.02)
            try:
                rss = peak_rss_bytes()
            except Exception:
                return
            if rss > rss_limit or time.monotonic() - started > wall_limit:
                print(f"provenance_hooks: limit exceeded (rss {rss >> 20} MiB, "
                      f"{time.monotonic() - started:.1f}s); skipped", file=sys.stderr, flush=True)
                try:
                    sys.stdout.flush()
                except Exception:
                    pass
                os._exit(0)

    thread = threading.Thread(target=watch, daemon=True)
    thread.start()
    return thread


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] not in ("ask-gate", "stop-lint", "prompt", "answer", "calibrate", "show-message"):
        print(__doc__, file=sys.stderr)
        return 3
    command = argv[0]
    if command in ("show-message", "calibrate") and len(argv) < (3 if command == "show-message" else 2):
        print(f"usage: provenance_hooks.py {command} <transcript> " + ("<uuid>" if command == "show-message" else "[limit]"), file=sys.stderr)
        return 3
    if command == "show-message":
        for message in assistant_messages(argv[1]):
            if message["uuid"] == argv[2]:
                print(message["text"])
                return 0
        print("message not found", file=sys.stderr)
        return 2
    if command == "calibrate":
        messages = assistant_messages(argv[1])
        limit = int(argv[2]) if len(argv) > 2 else 200
        for message in messages[-limit:]:
            hits = detect(message["text"])
            print(json.dumps({"uuid": message["uuid"], "items": len(hits), "chars": len(message["text"])}))
        return 0
    install_limits()
    try:
        payload = read_payload()
        handler = {"ask-gate": cmd_ask_gate, "stop-lint": cmd_stop_lint, "prompt": cmd_prompt,
                   "answer": cmd_answer}[command]
        result = handler(payload)
    except Exception as error:  # fail open: a lint bug must not trap the agent
        print(f"provenance_hooks {command}: skipped ({type(error).__name__})", file=sys.stderr)
        return 0
    if result:
        print(json.dumps(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
