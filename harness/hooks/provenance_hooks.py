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
from pathlib import Path

import provenance as prov

ASK_ID = re.compile(r"\[ask:\s*([A-Za-z0-9_-]{4,40})\s*\]")
TAIL_BYTES = 4 * 1024 * 1024

# A heading or label line that introduces a list of things the agent wants from the user.
SECTION = re.compile(
    r"(?i)^(?:what (?:i|we) need(?: from you)?|things (?:i|we) need(?: from you)?|(?:i|we) need (?:from you|these from you)|"
    r"needs? from you|needed from you|your call|decisions?(?: needed| for you| i need(?: from you)?)?|"
    r"waiting on you|blocked on you|questions? for you|open questions?|asks? for you|"
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
# A negation in the same sentence cancels the match: "nothing is waiting on you", "I don't need anything from you".
NEGATED = re.compile(
    r"(?i)\b(?:nothing|no one|none|neither|never)\b[^.\n]{0,60}\b(?:you|your)\b|"
    r"\b(?:don'?t|do not|doesn'?t|does not|didn'?t|isn'?t|aren'?t|not|n'?t) (?:need|needed|waiting|blocked|require)[^.\n]{0,40}\b(?:you|your)\b|"
    r"\bnothing (?:is )?(?:needed|required)\b|\bno (?:action|input|decision)s? (?:is |are )?(?:needed|required)\b")
BULLET = re.compile(r"^\s*(?:[-*+]|\d{1,3}[.)])\s+(.*\S)")
FENCE = re.compile(r"^\s*(```|~~~)")


def strip_md(line: str) -> str:
    return re.sub(r"^[\s>#*_`|]+|[\s*_`|:.!?]+$", "", line).strip()


def detect(text: str) -> list:
    """[{line, text, ref}] for each user-directed ask item in a message (conservative; code fences are skipped)."""
    lines = text.split("\n")
    items, in_fence, i = [], False, 0
    seen = set()

    def add(number, body):
        if number not in seen:
            seen.add(number)
            items.append({"line": number + 1, "text": body.strip()})

    while i < len(lines):
        line = lines[i]
        if FENCE.match(line):
            in_fence = not in_fence
            i += 1
            continue
        if in_fence or not line.strip():
            i += 1
            continue
        label = strip_md(line)
        if len(label) <= 100 and SECTION.match(label) and not BULLET.match(line) and not NEGATED.search(label):
            j, found = i + 1, 0
            while j < len(lines):
                if FENCE.match(lines[j]):
                    break
                bullet = BULLET.match(lines[j])
                if bullet:
                    add(j, bullet.group(1))
                    found += 1
                elif lines[j].strip() and found and not lines[j].startswith((" ", "\t")):
                    break  # list ended with a normal paragraph line
                elif lines[j].strip() and not found and re.match(r"^\s*#", lines[j]):
                    break  # next heading before any bullet
                elif not lines[j].strip() and found and j + 1 < len(lines) and not BULLET.match(lines[j + 1]) \
                        and not lines[j + 1].startswith((" ", "\t")):
                    break
                j += 1
                if j - i > 60:
                    break
            if not found:  # "Your call: pick A or B." with the ask on the same line
                after = line.split(":", 1)[1].strip() if ":" in line else ""
                if after:
                    add(i, after)
            i = max(j, i + 1)
            continue
        for sentence in re.split(r"(?<=[.!?])\s+", line.strip()):
            if INLINE.search(sentence) and not NEGATED.search(sentence):
                add(i, sentence)
                break
        i += 1
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
    for path in prov.session_wals(session, home):
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
        except prov.Problem:
            continue
    return None


def lint_message(text: str, session: str, home=None) -> list:
    """Uncited or untraceable ask items in a final message."""
    bad = []
    for item in detect(text):
        outcome = cite(item["text"], session, home)
        if not outcome["ok"]:
            bad.append(dict(item, problem=outcome["problem"]))
    return bad


# --------------------------------------------------------------------------- hook plumbing

def read_payload() -> dict:
    try:
        raw = sys.stdin.read(8 * 1024 * 1024)
        data = prov.loads_line(raw) if raw.strip() else {}
        return data if isinstance(data, dict) else {}
    except (ValueError, OSError):
        return {}


def last_assistant_text(payload: dict) -> str:
    direct = payload.get("last_assistant_message")
    if isinstance(direct, str) and direct.strip():
        return direct
    path = payload.get("transcript_path")
    if not isinstance(path, str):
        return ""
    try:
        with open(path, "rb") as handle:
            size = os.fstat(handle.fileno()).st_size
            handle.seek(max(0, size - TAIL_BYTES))
            tail = handle.read()
    except OSError:
        return ""
    for raw in reversed(tail.split(b"\n")):
        if b'"type":"assistant"' not in raw or len(raw) > prov.MAX_LINE:
            continue
        try:
            record = prov.loads_line(raw)
        except ValueError:
            continue
        if not isinstance(record, dict) or record.get("type") != "assistant" or record.get("isSidechain"):
            continue
        content = (record.get("message") or {}).get("content")
        pieces = [b.get("text", "") for b in content if isinstance(b, dict) and b.get("type") == "text"] \
            if isinstance(content, list) else ([content] if isinstance(content, str) else [])
        text = "\n".join(p for p in pieces if isinstance(p, str)).strip()
        if text:
            return text
    return ""


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


def cmd_stop_lint(payload: dict) -> dict:
    mode = prov.load_policy().get("stop_lint", "warn")
    if mode == "off":
        return {}
    session = str(payload.get("session_id") or "")
    if not prov.SESSION_RE.match(session):
        return {}
    bad = lint_message(last_assistant_text(payload), session)
    if not bad:
        return {}
    text = format_problems(bad)
    if mode == "enforce" and not payload.get("stop_hook_active"):
        return {"decision": "block", "reason": "Provenance: " + text}
    try:  # warn: tell the user now, and the agent on its next turn via the prompt hook
        path = reminder_path(session)
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        path.write_text(text + "\n", encoding="utf-8")
    except OSError:
        pass
    return {"systemMessage": "provenance warning (stop-lint, warn mode): " + str(len(bad)) + " ask item(s) without a traceable origin"}


def cmd_prompt(payload: dict) -> dict:
    session = str(payload.get("session_id") or "")
    if not prov.SESSION_RE.match(session):
        return {}
    path = reminder_path(session)
    try:
        text = path.read_text(encoding="utf-8")
        path.unlink()
    except OSError:
        return {}
    return {"hookSpecificOutput": {"hookEventName": "UserPromptSubmit",
                                   "additionalContext": "Provenance reminder: your last message had untraceable asks. " + text}}


def cmd_ask_gate(payload: dict) -> dict:
    mode = prov.load_policy().get("ask_user_question", "enforce")
    if mode == "off" or payload.get("tool_name") != "AskUserQuestion":
        return {}
    session = str(payload.get("session_id") or "")
    questions = (payload.get("tool_input") or {}).get("questions")
    if not prov.SESSION_RE.match(session) or not isinstance(questions, list) or not questions:
        return {}
    problems = []
    for index, question in enumerate(questions, 1):
        body = question if isinstance(question, str) else str((question or {}).get("question", "")) \
            if isinstance(question, dict) else ""
        outcome = cite(body, session)
        if not outcome["ok"]:
            problems.append(f"question {index}: {outcome['problem']}")
    if not problems:
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
    with open(path, "rb") as handle:
        for raw in handle:
            if b'"type":"assistant"' not in raw or len(raw) > prov.MAX_LINE:
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


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] not in ("ask-gate", "stop-lint", "prompt", "calibrate"):
        print(__doc__, file=sys.stderr)
        return 3
    command = argv[0]
    if command == "calibrate":
        messages = assistant_messages(argv[1])
        limit = int(argv[2]) if len(argv) > 2 else 200
        for message in messages[-limit:]:
            hits = detect(message["text"])
            print(json.dumps({"uuid": message["uuid"], "items": len(hits), "chars": len(message["text"])}))
        return 0
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
