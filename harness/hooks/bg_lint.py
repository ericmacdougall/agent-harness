#!/usr/bin/env python3
"""bg_lint: advisory PreToolUse lint for shell chains that report success without evidence (GoodQA #14513, #14472).

WARN ONLY. It never blocks: it always exits 0 and emits at most an `additionalContext` message naming bg_job.py.

Patterns flagged (see docs/rules/bg-launch.json and tests/data/bg_lint_*.json):
  success-echo   a success-like echo (started, launched, running, done, ok) reached after `;` or `&`, or after a
                 `&` that ended a line, instead of `&&`. `cmd1; nohup suite & echo started` prints started even
                 when cmd1 failed.
  wait-loop-tail a wait or poll loop (while/until/for with sleep, kill -0, pgrep, is-active ...) whose last command
                 is ls, cat or tail: the loop's exit status is then that command's, not the job's.
  pipestatus     PIPESTATUS read after `X=$(a | b)`: it holds the assignment's single status, so a per-stage check
                 written that way can never fail.

Lint reads stdin once, bounded; any internal error is swallowed (an advisory must not break a tool call).
Stdlib only; Python 3.9+.
"""

from __future__ import annotations

import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

MAX_COMMAND_CHARS = 200_000
SUCCESS_WORD = re.compile(r"\b(started|launched|running|done|ok)\b", re.IGNORECASE)
POLL_HINT = re.compile(r"\b(sleep|pgrep|is-active|is-system-running|inotifywait)\b|\bkill\s+-0\b")
LOOP_START = re.compile(r"^(while|until|for)\b")
TAIL_CMDS = {"ls", "cat", "tail"}
SAFE = "Use `python3 ~/.claude/hooks/bg_job.py launch|wait` (reports STARTED only on proof, wait returns the real exit status)."


def split_top_level(command):
    """[(operator_before, text)] split at ; && || | & and newline outside quotes, $(...) and backticks."""
    segments, buf, op = [], [], ""
    i, n = 0, len(command)
    quote = None
    depth = 0
    tick = False
    while i < n:
        c = command[i]
        if quote:
            buf.append(c)
            if c == "\\" and quote == '"' and i + 1 < n:
                buf.append(command[i + 1])
                i += 1
            elif c == quote:
                quote = None
            i += 1
            continue
        if c == "\\" and i + 1 < n:
            buf.append(c + command[i + 1])
            i += 2
            continue
        if c in "'\"":
            quote = c
            buf.append(c)
        elif c == "`":
            tick = not tick
            buf.append(c)
        elif c == "(" or (c == "$" and command[i + 1:i + 2] == "("):
            depth += 1
            buf.append(c)
        elif c == ")":
            depth = max(0, depth - 1)
            buf.append(c)
        elif depth == 0 and not tick and c in ";&|\n":
            two = command[i:i + 2]
            prev = command[i - 1] if i else ""
            if c == "&" and (prev in "<>" or command[i + 1:i + 2] == ">"):
                buf.append(c)  # 2>&1, &>file
            elif two in ("&&", "||"):
                segments.append((op, "".join(buf)))
                buf, op = [], two
                i += 1
            elif c == "\n" and not "".join(buf).strip():
                pass  # blank line or newline right after an operator: keep that operator (`... &` newline echo)
            else:
                segments.append((op, "".join(buf)))
                buf, op = [], c
        else:
            buf.append(c)
        i += 1
    segments.append((op, "".join(buf)))
    return [(o, t.strip()) for o, t in segments if t.strip()]


def first_word(text):
    text = re.sub(r"^(do|then|else|time|nohup)\s+", "", text.strip())
    m = re.match(r"[A-Za-z0-9_./-]+", text)
    return os.path.basename(m.group(0)) if m else ""


def find_success_echo(segments):
    hits = []
    for idx, (op, text) in enumerate(segments):
        if idx == 0 or op not in (";", "&"):
            continue
        if first_word(text) in ("echo", "printf") and SUCCESS_WORD.search(text):
            hits.append(text[:60])
    return hits


def find_wait_loop_tail(command, segments):
    texts = [t for _, t in segments]
    last_done = max((i for i, t in enumerate(texts) if first_word(t) == "done"), default=None)
    if last_done is None:
        return None
    loop_head = next((i for i, t in enumerate(texts) if LOOP_START.match(t)), None)
    if loop_head is None or not POLL_HINT.search(" ".join(texts[loop_head:last_done + 1])):
        # also allow poll hint in the loop condition via kill -0 which POLL_HINT covers; no hint -> not a wait loop
        return None
    after = [t for t in texts[last_done + 1:] if t]
    if after:
        last = after[-1]
        # trailing `&& echo ...`/`|| ...` after a ls/cat/tail still leaves the status of that command or the echo
        return last[:60] if first_word(last) in TAIL_CMDS else None
    body_last = next((t for t in reversed(texts[:last_done]) if t), "")
    return body_last[:60] if first_word(body_last) in TAIL_CMDS else None


def find_pipestatus_after_substitution(command):
    for m in re.finditer(r"(?:^|[\s;&|(])(?:(?:local|export|declare|readonly)\s+)?[A-Za-z_][A-Za-z0-9_]*=(\$\(|`)", command):
        start = m.end()
        if m.group(1) == "`":
            end = command.find("`", start)
            end = len(command) if end < 0 else end
        else:
            depth, end = 1, start
            while end < len(command) and depth:
                depth += {"(": 1, ")": -1}.get(command[end], 0)
                end += 1
        inner = command[start:end]
        if re.search(r"(?<!\|)\|(?!\|)", inner) and "PIPESTATUS" in command[end:]:
            return command[m.start():end].strip()[:60]
    return None


def lint(command):
    """List of (code, message) warnings. Pure; the corpus tests call this directly."""
    if not isinstance(command, str) or not command.strip():
        return []
    command = command[:MAX_COMMAND_CHARS]
    segments = split_top_level(command)
    out = []
    for text in find_success_echo(segments)[:1]:
        out.append(("success-echo", "A success message (`%s`) follows `;` or `&`, so it prints even if the earlier "
                                    "command failed. Chain with `&&`, and report a launch only after bg_job.py "
                                    "prints STARTED. %s" % (text, SAFE)))
    hit = find_wait_loop_tail(command, segments)
    if hit:
        out.append(("wait-loop-tail", "This wait/poll loop ends with `%s`; the loop's exit status is that command's, "
                                      "not the job's, so a failed job can look like success. %s" % (hit, SAFE)))
    hit = find_pipestatus_after_substitution(command)
    if hit:
        out.append(("pipestatus", "PIPESTATUS is read after a command-substitution assignment (`%s`); it holds only "
                                  "the assignment's status. Run the pipeline directly and read PIPESTATUS at once, "
                                  "use `set -o pipefail`, or write each stage's status to its own file." % hit))
    return out


def hook(stdin):
    try:
        import safe_input
        data = safe_input.safe_json_loads(safe_input.read_stdin_bounded(1024 * 1024), 50, 1024 * 1024)
        if not isinstance(data, dict) or data.get("tool_name") not in ("Bash", "PowerShell"):
            return None
        tool_input = data.get("tool_input")
        command = tool_input.get("command") if isinstance(tool_input, dict) else None
        found = lint(command)
        if not found:
            return None
        message = "bg_lint (advisory, not blocking): " + " | ".join("[%s] %s" % w for w in found)
        return json.dumps({"hookSpecificOutput": {"hookEventName": "PreToolUse", "additionalContext": message}})
    except Exception:
        return None


def main():
    output = hook(sys.stdin)
    if output:
        print(output)
    return 0  # advisory: never blocks


if __name__ == "__main__":
    sys.exit(main())
