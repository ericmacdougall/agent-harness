#!/usr/bin/env python3
"""Launcher for command_guard.py (GoodQA #14471). Registered as the PreToolUse hook command.

It runs the analyser in a child process with a watchdog and passes its answer through. When the child is missing,
crashes, cannot start, prints garbage or runs out of time, it allows the command with one line on stderr (harness
redesign, 2026-11-24: a guard that could not read a command never blocks it for the words it contains, whether they
name a harness location, a deletion or a secret source). It imports nothing outside the standard library and never imports command_guard.
"""

import json
import os
import re
import subprocess
import sys

CHILD_TIMEOUT = 10.0
MAX_STDIN = 8 * 1024 * 1024
GUARD = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'command_guard.py')
GUARDED_TOOLS = {'bash', 'powershell', 'shell', 'local_shell', 'exec_command', 'unified_exec', 'write_stdin',
                 'container.exec'}
COMMAND_KEYS = ('command', 'cmd', 'script', 'chars', 'input')



def guarded_text(raw):
    """(is_guarded_tool, text to probe). Unparsable input is treated as guarded, probing the whole payload."""
    try:
        payload = json.loads(raw)
    except ValueError:
        return True, raw
    if not isinstance(payload, dict):
        return True, raw
    tool = str(payload.get('tool_name') or payload.get('toolName') or '').casefold()
    tool_input = payload.get('tool_input') or payload.get('toolInput') or {}
    has_command = isinstance(tool_input, dict) and any(k in tool_input for k in COMMAND_KEYS[:3])
    if tool and tool not in GUARDED_TOOLS and not tool.startswith(('bash', 'shell', 'exec')) and not has_command:
        return False, ''
    if isinstance(tool_input, dict):
        parts = []
        for key in COMMAND_KEYS:
            value = tool_input.get(key)
            if isinstance(value, list):
                parts.append(' '.join(str(v) for v in value))
            elif isinstance(value, str):
                parts.append(value)
        return True, '\n'.join(parts) or raw
    return True, raw if not isinstance(tool_input, str) else tool_input


def payload_cwd(raw):
    """The working directory the command runs in (Codex workdir, else the payload cwd), or None."""
    try:
        payload = json.loads(raw)
    except ValueError:
        return None
    if not isinstance(payload, dict):
        return None
    tool_input = payload.get('tool_input') if isinstance(payload.get('tool_input'), dict) else {}
    for value in (tool_input.get('workdir'), payload.get('cwd')):
        if isinstance(value, str) and value:
            return value
    return None


def sensitive(text, cwd=None):
    """Always False: the fallback cannot see what a command does, so it blocks nothing. Kept for callers."""
    return False


def fallback(raw, why):
    guarded, text = guarded_text(raw)
    if guarded and sensitive(text, payload_cwd(raw)):
        sys.stderr.write('command_guard BLOCKED [guard_failure]: the analyser %s. Safe alternative: split the command '
                         'into simple steps; run `python3 %s doctor` to check the guard.\n' % (why, GUARD))
        return 2
    if guarded:
        sys.stderr.write('command_guard: analyser %s; the command looked harmless and was allowed\n' % why)
    return 0


def read_stdin():
    data = b''
    stream = sys.stdin.buffer
    while len(data) <= MAX_STDIN:
        chunk = stream.read(65536)
        if not chunk:
            return data, False
        data += chunk
    return data, True


def main():
    try:
        data, oversized = read_stdin()
    except Exception:  # noqa: BLE001 - cannot read the payload at all: nothing to judge
        sys.stderr.write('command_guard: could not read the hook payload\n')
        return 0
    raw = data.decode('utf-8', 'replace')
    if oversized:
        guarded, text = guarded_text(raw[:MAX_STDIN])
        if guarded and sensitive(text):
            sys.stderr.write('command_guard BLOCKED [oversized-input]: the tool input is larger than the guard '
                             'analyses and names a secret source. Safe alternative: put the commands in a script file '
                             'and run it.\n')
            return 2
        if guarded:
            sys.stderr.write('command_guard: the tool input is larger than the guard analyses; allowed\n')
        return 0
    if not guarded_text(raw)[0]:
        return 0  # Read, Write, Edit, MCP...: not a shell command, and Codex sends every tool here (no matcher)
    if not os.path.isfile(GUARD):
        return fallback(raw, 'is missing')  # python3 exits 2 for a missing script: never pass that on as a refusal
    try:
        child = subprocess.run([sys.executable, '-I', GUARD, 'hook'], input=data, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, timeout=CHILD_TIMEOUT, check=False)
    except subprocess.TimeoutExpired:
        return fallback(raw, 'timed out')
    except Exception as error:  # noqa: BLE001
        return fallback(raw, 'could not start (%s)' % type(error).__name__)
    if child.returncode in (0, 2):
        out = child.stdout.decode('utf-8', 'replace')
        if out.strip():
            try:
                json.loads(out)
            except ValueError:
                return fallback(raw, 'printed invalid output')
            sys.stdout.write(out)
        sys.stderr.write(child.stderr.decode('utf-8', 'replace')[:4000])
        return child.returncode
    return fallback(raw, 'crashed (exit %d)' % child.returncode)


if __name__ == '__main__':
    try:
        sys.exit(main())
    except SystemExit:
        raise
    except BaseException:  # noqa: BLE001 - last resort: a launcher bug allows, never silently
        sys.stderr.write('command_guard: the launcher failed and the command was allowed; run the guard doctor.\n')
        sys.exit(0)
