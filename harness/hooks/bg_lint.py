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
  self-match-pgrep  a while/until loop polling `pgrep -f PATTERN` (or `ps | grep PATTERN` without `grep -v grep`)
                 whose pattern also occurs in the loop's own shell command line, so it never exits. Suggests the
                 `[t]sc` bracket trick, a PID wait or an exit file (incident 2026-11-06: 12 h on dev2).

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
SUCCESS_WORD = re.compile(r"\b(started|launched|running|done|ok|submitted|queued|spawned|in background)\b", re.IGNORECASE)
POLL_HINT = re.compile(r"\b(sleep|pgrep|is-active|is-system-running|inotifywait)\b|\bkill\s+-0\b")
LOOP_START = re.compile(r"^(while|until|for)\b")
TAIL_CMDS = {"ls", "cat", "tail", "grep", "head", "wc", "stat"}
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
        if c == "#" and (i == 0 or command[i - 1] in " \t\n;&|(") and depth == 0 and not tick:
            while i < n and command[i] != "\n":  # comment: its apostrophes must not open a quote
                i += 1
            continue
        if c == "'" and command[i - 1:i] == "$":
            j = i + 1  # $'...' ANSI-C quoting honours backslash escapes
            while j < n and command[j] != "'":
                j += 2 if command[j] == "\\" else 1
            buf.append(command[i:j + 1])
            i = j + 1
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


def first_word(text, keep_keywords=False):
    text = text.strip()
    if not keep_keywords:
        text = re.sub(r"^(do|then|else|time|nohup)\s+", "", text)
    m = re.match(r"[A-Za-z0-9_./-]+", text)
    return os.path.basename(m.group(0)) if m else ""


def find_success_echo(segments):
    hits = []
    for idx, (op, text) in enumerate(segments):
        if idx == 0 or op not in (";", "&"):
            continue
        if first_word(text, True) in ("echo", "printf") and SUCCESS_WORD.search(text):
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


PGREP_CALL = re.compile(r"(?<![\w./-])pgrep\s+((?:-\S+\s+)*)(?:\"([^\"]*)\"|'([^']*)'|(\$?[^\s;&|)]+))")
PS_GREP_CALL = re.compile(r"(?<![\w./-])ps\b[^|;&\n]*\|\s*grep\s+((?:-\S+\s+)*)(?:\"([^\"]*)\"|'([^']*)'|([^\s;&|)]+))")
GREP_V_GREP = re.compile(r"\bgrep\s+(?:-\S+\s+)*-v\s+['\"]?grep\b")


def _self_matching(flags, pattern):
    """True when a full-command-line match on `pattern` also matches the shell running the loop: the loop's own
    `bash -c '... pgrep -f PATTERN ...'` argv contains the pattern verbatim unless it uses the `[t]sc` trick."""
    if not pattern or pattern.startswith("$") or pattern.startswith("["):
        return False  # a variable or the bracket trick: cannot tell, or deliberately excluded
    return "x" not in flags  # -x needs the whole line to equal the pattern, which the loop's shell line never does


def find_self_matching_wait(segments):
    """A while/until loop that polls `pgrep -f PATTERN` or `ps | grep PATTERN` with a pattern that occurs in the
    loop's own command line (incident 2026-11-06: `while pgrep -f "tsc --noEmit"` ran 12 h on dev2 because it
    matched the ssh'd bash that ran the loop)."""
    texts = [t for _, t in segments]
    loop_head = next((i for i, t in enumerate(texts) if LOOP_START.match(t)), None)
    last_done = max((i for i, t in enumerate(texts) if first_word(t) == "done"), default=None)
    if loop_head is None or last_done is None or last_done < loop_head:
        return None
    body = " ".join(f"{op} {t}" for op, t in segments[loop_head:last_done + 1])  # keep `|` so ps | grep is visible
    for m in PGREP_CALL.finditer(body):
        flags = "".join(f for f in m.group(1).split() if f.startswith("-") and not f.startswith("--"))
        full = "f" in flags or "--full" in m.group(1)
        pattern = m.group(2) or m.group(3) or m.group(4) or ""
        if full and _self_matching(flags, pattern):
            return "pgrep -f " + pattern[:40], "[%s]%s" % (pattern[0], pattern[1:40]) if pattern[0].isalnum() else "[t]sc ..."
    if not GREP_V_GREP.search(body):
        for m in PS_GREP_CALL.finditer(body):
            flags = "".join(f for f in m.group(1).split() if f.startswith("-") and not f.startswith("--"))
            pattern = m.group(2) or m.group(3) or m.group(4) or ""
            if "v" not in flags and _self_matching(flags, pattern):
                return "ps | grep " + pattern[:40], "[%s]%s" % (pattern[0], pattern[1:40]) if pattern[0].isalnum() else "[v]itest ..."
    return None


FILE_TEST = re.compile(r"(?:\[\[?\s+!?\s*-[fesrdL]\s+\S+|\btest\s+!?\s*-[fesrdL]\s+\S+|\bls\s+(?:-\S+\s+)*\S+\s*(?:>|2>|\|))")
LOOP_BOUND = re.compile(r"\btimeout\b|\bSECONDS\b|date\s+\+?%?s|\$\(\(|\(\(|\bseq\b|\bexpr\b|\blet\b|\{1\.\.\d+\}|-(?:lt|le|gt|ge)\b|"
                        r"\bdeadline\b|\bmax_?(?:wait|tries|iter\w*)\b|\bkill\s+-0\b|\binotifywait\s+(?:-\S+\s+)*-t\b|\bpgrep\b", re.IGNORECASE)


def find_unbounded_file_wait(segments):
    """A while/until loop that sleeps until a file exists, with no deadline in the loop (GoodQA #15565: a waiter sat 12 h
    on a file nothing produced). The loop must name its producer and give up: bg_job.py wait-file does both."""
    texts = [t for _, t in segments]
    loop_head = next((i for i, t in enumerate(texts) if re.match(r"^(while|until)\b", t)), None)
    last_done = max((i for i, t in enumerate(texts) if first_word(t) == "done"), default=None)
    if loop_head is None or last_done is None or last_done < loop_head:
        return None
    head = texts[loop_head]
    body = " ".join(texts[loop_head:last_done + 1])
    if not re.search(r"\bsleep\b|inotifywait", body) or not FILE_TEST.search(head) or LOOP_BOUND.search(body):
        return None
    return head[:60]


MAX_SUBST_SCAN = 4096
MAX_SUBST_MATCHES = 200


def find_pipestatus_after_substitution(command):
    if "PIPESTATUS" not in command:
        return None  # cheap exit; also bounds the work on huge commands
    for count, m in enumerate(re.finditer(r"(?:^|[\s;&|(])(?:(?:local|export|declare|readonly)\s+)?[A-Za-z_][A-Za-z0-9_]*=(\$\(|`)", command)):
        if count >= MAX_SUBST_MATCHES:
            return None
        start = m.end()
        limit = min(len(command), start + MAX_SUBST_SCAN)
        if m.group(1) == "`":
            end = command.find("`", start, limit)
            end = limit if end < 0 else end
        else:
            depth, end = 1, start
            while end < limit and depth:
                depth += {"(": 1, ")": -1}.get(command[end], 0)
                end += 1
        inner = command[start:end]
        if re.search(r"(?<!\|)\|(?!\|)", inner) and command.find("PIPESTATUS", end) >= 0:
            return command[m.start():end].strip()[:60]
    return None


WRAPPERS = {"ssh", "bash", "sh", "zsh", "dash"}
MAX_NESTED = 8


def nested_commands(segments):
    """Quoted script arguments of ssh/bash -c/sh -c: the incident chain ran on a remote host."""
    import shlex
    found = []
    for _, text in segments:
        if first_word(text) in WRAPPERS and len(found) < MAX_NESTED:
            try:
                words = shlex.split(text)
            except ValueError:
                continue
            found += [w for w in words[1:] if (";" in w or "&" in w or "|" in w) and not w.startswith("-")][:MAX_NESTED]
    return found[:MAX_NESTED]


def lint(command, _depth=0):
    """List of (code, message) warnings. Pure; the corpus tests call this directly."""
    if not isinstance(command, str) or not command.strip():
        return []
    command = command[:MAX_COMMAND_CHARS]
    segments = split_top_level(command)
    out = []
    if _depth < 2:
        for inner in nested_commands(segments):
            out += [w for w in lint(inner, _depth + 1) if w[0] not in [o[0] for o in out]]
    for text in find_success_echo(segments)[:1]:
        out.append(("success-echo", "A success message (`%s`) follows `;` or `&`, so it prints even if the earlier "
                                    "command failed. Chain with `&&`, and report a launch only after bg_job.py "
                                    "prints STARTED. %s" % (text, SAFE)))
    hit = find_wait_loop_tail(command, segments)
    if hit:
        out.append(("wait-loop-tail", "This wait/poll loop ends with `%s`; the loop's exit status is that command's, "
                                      "not the job's, so a failed job can look like success. %s" % (hit, SAFE)))
    hit = find_self_matching_wait(segments)
    if hit:
        out.append(("self-match-pgrep", "This wait loop polls `%s`, and that pattern also occurs in the command line "
                                        "of the shell running the loop, so the match never goes away and the loop "
                                        "never exits (one ran 12 h on dev2; a loop typed into an already-running shell "
                                        "is the exception). Use the bracket trick (`%s`), wait on a PID (`kill -0 $PID` "
                                        "or `bg_job.py wait`), or poll for an exit file written by the job "
                                        "(`cmd; echo $? > done.txt`)." % hit))
    hit = find_unbounded_file_wait(segments)
    if hit:
        out.append(("file-wait-unbounded", "This loop (`%s`) waits for a file with no deadline and does not check that "
                                           "anything is still producing it, so it can wait for ever on a file nothing "
                                           "writes (a waiter sat 12 h this way). Use `python3 ~/.claude/hooks/bg_job.py "
                                           "wait-file --file F --producer job:NAME|pid:N --timeout S`: it names the "
                                           "producer, stops when the producer is gone or time runs out, and raises an "
                                           "alert." % hit))
    hit = find_pipestatus_after_substitution(command)
    if hit:
        out.append(("pipestatus", "PIPESTATUS is read after a command-substitution assignment (`%s`); it holds only "
                                  "the assignment's status. Run the pipeline directly and read PIPESTATUS at once, "
                                  "use `set -o pipefail`, or write each stage's status to its own file (see bg_job.py docs)." % hit))
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
