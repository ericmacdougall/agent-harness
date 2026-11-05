#!/usr/bin/env python3
"""Claude Code hooks that keep user-directed asks traceable (see provenance.py and docs/provenance.md).

  provenance_hooks.py ask-gate    PreToolUse on AskUserQuestion: every question names `[ask:<id>]`, an open or
                                  closed ledger ask whose Source resolves
  provenance_hooks.py stop-lint   Stop: the final assistant message's "need from you" items each carry
                                  `[ask:<id>]` or an inline `[src: <source>]` that resolves
  provenance_hooks.py prompt      UserPromptSubmit: hand the agent a reminder left by a warn-mode stop-lint
  provenance_hooks.py calibrate   measure the stop-lint detector on a transcript (no hook payload)

Modes come from provenance_policy.json (`ask_user_question`, `stop_lint`: off | warn | enforce). Every hook
fails open on its own bugs (stderr note, exit 0): a broken lint must never trap the agent or the user.
One-line disable: set the policy key to "off", or remove the hook entry from settings.json.
"""

from __future__ import annotations

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

# A heading or label line that introduces a list of things the agent wants from the user. A bare
# "Decisions" or "Decisions made" is a log of what the agent did, so the qualifier is required.
SECTION = re.compile(
    r"(?i)^(?:what (?:i|we) need(?: from you)?|things (?:i|we) need(?: from you)?|(?:i|we) need (?:from you|these from you)|"
    r"needs? from you|needed from you|your call|decisions? (?:needed|for you|i need(?: from you)?)|"
    r"waiting on you|blocked on you|questions? for you|open questions?(?: for you)?|asks? for you|"
    r"for you to (?:decide|confirm)|needs? your (?:decision|input|approval))\b[^.!?]{0,40}$")
# A sentence that itself asks the user for something.
INLINE = re.compile(
    r"(?i)\b(?:i|we) (?:still )?need(?:s)? (?:you to|your (?:decision|input|approval|key|token|password|credentials?))\b|"
    r"\bneed(?:s|ed)? [^.\n]{0,60} from you\b|"
    r"\bplease (?:provide|confirm|supply|send|decide|approve|share)\b|"
    r"\b(?:can|could) you (?:please )?(?:provide|confirm|supply|send|share)\b|"
    r"\b(?:still )?(?:waiting|blocked) (?:on|for) (?:you|your (?:answer|reply|decision|ok|approval))\b|"
    r"\b(?:tell|let) me (?:know )?(?:if|when|whether|which) (?:you|it|the)\b|"
    r"\bsay if you (?:want|prefer)\b|\bwhich one do you want\b|\bwait(?:s)? until you (?:tell|say|confirm|let)\b|"
    r"\bwaiting for you to\b")
# A negation in the same sentence cancels the match: "nothing is waiting on you", "I don't need anything from you",
# and the courtesy closer "tell me if you want more detail".
NEGATED = re.compile(
    r"(?i)\b(?:nothing|no one|none|neither|never)\b[^.\n]{0,60}\b(?:you|your)\b|"
    r"\b(?:don'?t|do not|doesn'?t|does not|didn'?t|isn'?t|aren'?t|not|n'?t) (?:need|needed|waiting|blocked|require)[^.\n]{0,40}\b(?:you|your)\b|"
    r"\bnothing (?:is )?(?:needed|required)\b|\bno (?:action|input|decision)s? (?:is |are )?(?:needed|required)\b|"
    r"\bif you(?:'d)? (?:want|like|prefer|need|have) (?:any )?(?:more|further|additional|another|other|me to (?:go deeper|elaborate|explain|expand|dig))|"
    r"\b(?:more|further|additional) (?:detail|details|info|information|context|help|explanation)\b|"
    r"\b(?:let me know|tell me) (?:if|when) you(?:'re| are| have|'ve| run| hit| see| need any| want any| would like)[^.\n]{0,40}(?:question|issue|concern|problem|ready|anything else)|"
    r"\b(?:you asked me to|asked me to|the (?:log|error|message|output|docs?|file|prompt) (?:says?|reads?|shows?))\b")
EMPTY_ITEM = re.compile(r"(?i)^\W*(?:none|nothing|n/?a|no(?:ne| \w+)?|nil|all clear|not applicable)\W*$")
_BULLET_HEAD = re.compile(r"^(\s{0,40})(?:[-*+]|\d{1,3}[.)])\s")


class _BulletMatch:
    def __init__(self, indent, body):
        self._indent, self._body = indent, body

    def group(self, number):
        return self._indent if number == 1 else self._body


class _Bullet:
    """Linear stand-in for a bullet regex: `match` returns None or an object with group(1) indent, group(2) body."""

    @staticmethod
    def match(line):
        head = _BULLET_HEAD.match(line)
        if not head:
            return None
        body = line[head.end():].strip()
        return _BulletMatch(head.group(1), body) if body else None


BULLET = _Bullet()
MAX_LINE_CHARS = 2000  # a longer line is cut before any pattern runs: nothing here needs the rest of a 100 KB line
FENCE = re.compile(r"^\s*(`{3,}|~{3,})(.*)$")
QUOTED = re.compile(r"`[^`\n]{0,200}`|\"[^\"\n]{0,200}\"|\u201c[^\u201d\n]{0,200}\u201d")
MAX_ITEMS = 50


def strip_md(line: str) -> str:
    # str.strip is linear; the earlier regex form was quadratic on one very long line
    return line.strip(" \t>#*_`|").rstrip(" \t*_`|:.!?").strip()


def detect(text: str) -> list:
    """[{line, text}] for each user-directed ask item in a message. Conservative: negations, quoted text,
    courtesy closers and empty sections are ignored, and fenced code is skipped (an unclosed fence is not trusted)."""
    items = _detect(text.split("\n"), honour_fences=True)
    if items is None:  # a fence never closed: do not let it hide the rest of the message
        items = _detect(text.split("\n"), honour_fences=False) or []
    return items[:MAX_ITEMS]


def _detect(lines: list, honour_fences: bool):
    lines = [line[:MAX_LINE_CHARS] for line in lines]
    items, seen = [], set()
    fence = None  # (char, length) of the open fence
    i = 0

    def add(number, body):
        body = body.strip()
        if number not in seen and body and not EMPTY_ITEM.match(body):
            seen.add(number)
            items.append({"line": number + 1, "text": body})

    def block_end(start, indent):
        """Index after a bullet's indented continuation lines and sub-bullets."""
        j = start + 1
        while j < len(lines) and len(items) < 4 * MAX_ITEMS:
            nxt = lines[j]
            if not nxt.strip():
                break
            if len(nxt) - len(nxt.lstrip()) > indent:
                j += 1
                continue
            break
        return j

    while i < len(lines):
        line = lines[i]
        marker = FENCE.match(line) if honour_fences else None
        if marker:
            char, length = marker.group(1)[0], len(marker.group(1))
            if fence is None:
                if marker.group(1) not in marker.group(2):  # ```x``` on one line opens and closes nothing
                    fence = (char, length)
            elif char == fence[0] and length >= fence[1] and not marker.group(2).strip():
                fence = None
            i += 1
            continue
        if fence is not None or not line.strip():
            i += 1
            continue
        label = strip_md(line)
        if len(label) <= 100 and SECTION.match(label) and not BULLET.match(line) and not NEGATED.search(label):
            j, found = i + 1, 0
            while j < len(lines) and j - i <= 80:
                if honour_fences and FENCE.match(lines[j]):
                    break
                bullet = BULLET.match(lines[j])
                if bullet:
                    end = block_end(j, len(bullet.group(1)))
                    add(j, " ".join(part.strip() for part in [bullet.group(2)] + lines[j + 1:end]))
                    found += 1
                    j = end
                    continue
                if lines[j].strip() and found and not lines[j].startswith((" ", "\t")):
                    break  # list ended with a normal paragraph line
                if lines[j].strip() and not found and re.match(r"^\s*#", lines[j]):
                    break  # next heading before any bullet
                if not lines[j].strip() and found and j + 1 < len(lines) and not BULLET.match(lines[j + 1]) \
                        and not lines[j + 1].startswith((" ", "\t")):
                    break
                j += 1
            if not found:  # "Your call: pick A or B." with the ask on the same line
                after = line.split(":", 1)[1].strip() if ":" in line else ""
                if after:
                    add(i, after)
            i = max(j, i + 1)
            continue
        for sentence in re.split(r"(?<=[.!?])\s+", line.strip()):
            plain = QUOTED.sub(" ", sentence).replace("\u2019", "'").replace("\u2018", "'")  # words inside quotes or code spans are not the agent's ask
            if INLINE.search(plain) and not NEGATED.search(plain):
                add(i, sentence)
                break
        i += 1
    if fence is not None and honour_fences:
        return None
    return items


def cite(item_text: str, session: str, home=None) -> dict:
    """{ok, how, problem} for one detected item."""
    found = ASK_ID.search(item_text)
    if found:
        ask = find_ask(session, found.group(1), home)
        if ask is None:
            return {"ok": False, "problem": f"[ask:{found.group(1)}] is not in this session's ledger"}
        result = prov.resolve(ask.get("source") or "", {"home": home})
        if not result["ok"] or prov.weak_problem(result):
            return {"ok": False, "problem": f"[ask:{found.group(1)}] has an untraceable source"}
        return {"ok": True, "how": "ask", "label": result["label"]}
    inline = prov.inline_source(item_text)
    if inline:
        result = prov.resolve(inline, {"home": home})
        if result["ok"] and not prov.weak_problem(result):
            return {"ok": True, "how": "src", "label": result["label"]}
        first = result["problems"][0]["message"] if result["problems"] else (prov.weak_problem(result) or "rejected")
        return {"ok": False, "problem": "[src: ...] does not resolve: " + prov.clip(first, 100)}
    return {"ok": False, "problem": "no [ask:<id>] or [src: <source>]"}


def find_ask(session: str, ask_id: str, home=None):
    if not prov.ID_RE.match(ask_id):
        return None
    wals = prov.session_wals(session, home)
    if not wals:  # no WAL at all: hooks or HOME are misconfigured, so do not deny on a guess
        raise prov.Problem("file-unreadable", "no WAL files for this session")
    for path in wals:
        try:
            for line in prov._lines_containing(path, f'"id":"{ask_id}"'.encode()):
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
                raise  # cannot decide: callers fail open instead of denying on a guess
            continue
    return None


def lint_message(text: str, session: str, home=None) -> list:
    """Uncited or untraceable ask items in a final message."""
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


def format_problems(bad: list) -> str:
    rows = [f"  - line {b['line']}: \"{prov.clip(b['text'], 90)}\" ({b['problem']})" for b in bad[:12]]
    if len(bad) > 12:
        rows.append(f"  - ... {len(bad) - 12} more")
    return ("These items ask something of the user without a traceable origin:\n" + "\n".join(rows) +
            "\nRegister each with `wal_note.py --event ask --source ...`, then cite `[ask:<id>]` (or an inline "
            "`[src: user:<session>/<uuid> \"words\"]`), or drop the item or relabel it as your assumption. "
            "Build the list from `provenance.py asks --session <id>`.")


QUARANTINE_EVENTS = ("scope", "decision")
QUARANTINE_MAX_BLOCKS = 3
TOOL_WRITERS = frozenset({"escalation", "ahd", "dropped_gate", "ah-run"})


def quarantined_entries(session: str, now: float, older_than_s: float) -> list:
    """Unsourced scope/decision rows of the session main WAL older than the grace (P11, goodqa#14791)."""
    import os  # noqa: PLC0415
    path = Path(os.environ.get("AH_HOME") or Path.home()) / ".claude" / "wals" / session / "main.jsonl"
    out = []
    try:
        tail = safe_input.read_tail(path, 4 << 20)
    except Exception:  # noqa: BLE001
        return out
    recs = []
    for raw in tail.splitlines():
        try:
            rec = json.loads(raw)
        except ValueError:
            continue
        if isinstance(rec, dict):
            recs.append(rec)
    recited = {r.get("recites") for r in recs if r.get("recites") and r.get("source") and not r.get("unsourced")}  # only a backed re-cite clears (M2)
    for rec in recs:
        if rec.get("event") not in QUARANTINE_EVENTS or not rec.get("unsourced") or rec.get("id") in recited \
                or rec.get("by") in TOOL_WRITERS:  # the allowlist, not any claim (M1)
            continue
        ts = None
        try:
            import datetime as dt  # noqa: PLC0415
            ts = dt.datetime.fromisoformat(str(rec.get("at")).replace("Z", "+00:00")).timestamp()
        except (TypeError, ValueError):
            pass
        if ts is not None and now - ts >= older_than_s:
            out.append({"id": rec.get("id"), "event": rec["event"], "age_s": int(now - ts), "note": prov.clip(str(rec.get("note") or ""), 80)})
    return out


def quarantine_state_path(session: str) -> Path:
    import os  # noqa: PLC0415
    return Path(os.environ.get("AH_HOME") or Path.home()) / ".agent-harness" / "state" / "provenance-lint" / f"{session}.json"


def quarantine_block(session: str, payload: dict, now: float | None = None) -> dict:
    """Block the turn end (bounded per signature) while quarantined scope/decision rows are older than the grace."""
    import os, time  # noqa: PLC0415
    policy = prov.load_policy()
    mode = policy.get("quarantine_lint", "enforce")
    if mode == "off" or os.environ.get("CLAUDE_CODE_ENTRYPOINT", "").startswith("sdk") or payload.get("agent_id"):
        return {}
    now = time.time() if now is None else now
    rows = quarantined_entries(session, now, float(policy.get("quarantine_minutes", 10)) * 60)
    if not rows:
        return {}
    ids = sorted(str(r["id"]) for r in rows)
    text = (f"{len(rows)} WAL {'entry' if len(rows) == 1 else 'entries'} without a source for over the grace (goodqa#14791 P11): "
            + "; ".join(f"{r['event']} {r['id']} ({r['age_s'] // 60}m): {r['note']}" for r in rows[:6])
            + ". Cite each with `python3 ~/.claude/hooks/ah.py note --source auto --dry-run --wal <this WAL> --id <id>` "
              "then without --dry-run, or relabel it as your assumption (inferred: ...). Nothing was dropped.")
    import hashlib  # noqa: PLC0415
    sig = hashlib.sha256(",".join(ids).encode()).hexdigest()[:16]
    state_path = quarantine_state_path(session)
    try:
        state = safe_input.safe_json_loads(safe_input.read_bounded(state_path, 65536).decode("utf-8", "replace"))
        state = state if isinstance(state, dict) else {}
    except Exception:  # noqa: BLE001
        state = {}
    count = int((state.get("blocks") or {}).get(sig, 0))
    if mode != "enforce" or payload.get("stop_hook_active") or count >= QUARANTINE_MAX_BLOCKS:
        return {"systemMessage": "provenance quarantine: " + text}
    state.setdefault("blocks", {})[sig] = count + 1
    try:
        state_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        tmp = state_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(state), encoding="utf-8")
        os.replace(tmp, state_path)
    except OSError:
        pass
    return {"decision": "block", "reason": "Provenance quarantine: " + text}


def cmd_stop_lint(payload: dict) -> dict:
    session = str(payload.get("session_id") or "")
    if not valid_session(session):
        return {}
    quarantine = quarantine_block(session, payload)  # its own policy key, independent of stop_lint (review minor)
    if quarantine.get("decision") == "block":
        return quarantine
    mode = prov.load_policy().get("stop_lint", "warn")
    if mode == "off":
        return quarantine
    carried = quarantine.get("systemMessage")
    bad = lint_message(last_assistant_text(payload), session)
    if not bad and carried:
        return {"systemMessage": carried}
    if not bad:
        try:
            reminder_path(session).unlink()  # a clean message clears an older warn-mode reminder
        except OSError:
            pass
        return {}
    text = format_problems(bad)
    if mode == "enforce" and not payload.get("stop_hook_active"):
        return {"decision": "block", "reason": "Provenance: " + text}
    if mode == "enforce":  # second Stop in a row: let it through, say so, and do not queue a stale reminder
        return {"systemMessage": "provenance (stop-lint enforce, already blocked once): " + str(len(bad)) + " ask item(s) still uncited"}
    try:  # warn: tell the user now, and the agent on its next turn via the prompt hook
        path = reminder_path(session)
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        path.write_text(text + "\n", encoding="utf-8")
    except OSError:
        pass
    return {"systemMessage": "provenance warning (stop-lint, warn mode): " + str(len(bad)) + " ask item(s) without a traceable origin"
            + ((" " + carried) if carried else "")}


def cmd_prompt(payload: dict) -> dict:
    session = str(payload.get("session_id") or "")
    if not valid_session(session):
        return {}
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
    return {"hookSpecificOutput": {"hookEventName": "UserPromptSubmit",
                                   "additionalContext": "Provenance reminder: your last message had untraceable asks. " + text}}


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
    mode = prov.load_policy().get("ask_user_question", "enforce")
    if mode == "off" or payload.get("tool_name") != "AskUserQuestion":
        return {}
    session = str(payload.get("session_id") or "")
    tool_input = payload.get("tool_input")
    questions = tool_input.get("questions") if isinstance(tool_input, dict) else None
    if not valid_session(session) or not isinstance(questions, list) or not questions:
        return {}
    problems = []
    for index, question in enumerate(questions, 1):
        body = question if isinstance(question, str) else str((question or {}).get("question", "")) \
            if isinstance(question, dict) else ""
        outcome = cite(body, session)
        if not outcome["ok"]:
            problems.append(f"question {index}: {outcome['problem']}")
    ids = [m.group(1) for m in ASK_ID.finditer(json.dumps(questions, ensure_ascii=False))]
    if not problems:
        away = presence_block(payload, session, ids)
        if away:
            return away
        shown = [f"[ask:{m.group(1)}] = {prov.clip((find_ask(session, m.group(1)) or {}).get('note', ''), 100)}"
                 for m in ASK_ID.finditer(json.dumps(questions, ensure_ascii=False))]
        if shown:  # make an id reused for an unrelated question visible to the user
            return {"hookSpecificOutput": {"hookEventName": "PreToolUse",
                                           "additionalContext": "Provenance ask ledger: " + "; ".join(shown)}}
        return {}
    reason = ("Provenance: AskUserQuestion needs a traceable origin for each question. " + "; ".join(problems) +
              ". Register it with `wal_note.py --event ask --note ... --reason ... --source ...`, then put "
              "`[ask:<id>]` in the question text. If you cannot trace it to the user, a ticket or a file, do not ask.")
    if mode == "enforce":
        return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                       "permissionDecisionReason": reason}}
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "additionalContext": "(warn mode) " + reason}}


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
    if not argv or argv[0] not in ("ask-gate", "stop-lint", "prompt", "calibrate", "show-message"):
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
        handler = {"ask-gate": cmd_ask_gate, "stop-lint": cmd_stop_lint, "prompt": cmd_prompt}[command]
        result = handler(payload)
    except Exception as error:  # fail open: a lint bug must not trap the agent
        print(f"provenance_hooks {command}: skipped ({type(error).__name__})", file=sys.stderr)
        return 0
    if result:
        print(json.dumps(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
