"""Caller proof for `ah lane` commands (S1): one-shot stamps written by a PreToolUse hook, never read from the
environment or the command line.

A hook that runs on main's Bash calls calls ``stamp_command`` with the hook payload; it stamps only when the payload is
proven main's (``caller_identity.is_main``) and the command is a real `ah.py lane <command>`. For a sub-agent's own
checkpoint it stamps the agent id from the payload (``agent_id`` is set only on sub-agent payloads). The `ah lane`
command then consumes the stamp with ``caller_identity.take_stamp``; a missing stamp means "not proven".

Wiring this into a live hook is part of the install and belongs to main (the PR does not install hooks).
"""
from __future__ import annotations

import os
import re
import shlex

MAIN_ONLY = ("new", "start", "bind", "set-live-target", "resolve-ledger")
LANE_ID = re.compile(r"^lane_[0-9A-Z]{26}$|^lane_[A-Za-z0-9._:-]{1,90}$")
TICKET = re.compile(r"^GoodQA [a-z0-9][a-z0-9-]{0,60}#[0-9]{1,9}$")


def parse(command: str):
    """``(subcommand, key)`` of a plain `ah.py lane ...` command, else None. Anything with shell metacharacters or
    a nested command is not stamped."""
    if not isinstance(command, str) or re.search(r"[;&|`$<>(){}\n\\]", command):
        return None
    try:
        words = shlex.split(command)
    except ValueError:
        return None
    if len(words) < 4 or not words[0].startswith("python") or not words[1].endswith("ah.py") or words[2] != "lane":
        return None
    sub, rest = words[3], words[4:]
    flag = {"new": "--ticket"}.get(sub, "--lane")
    key = None
    for i, w in enumerate(rest):
        if w == flag and i + 1 < len(rest):
            key = rest[i + 1]
        elif w.startswith(flag + "="):
            key = w.split("=", 1)[1]
    return (sub, key) if key else None


def stamp_command(payload, home=None, now=None, claude_dir=None):
    """Stamp a one-shot proof for the command in a PreToolUse payload. Returns the purpose stamped, or None."""
    import caller_identity as ci  # noqa: PLC0415
    if not isinstance(payload, dict) or payload.get("tool_name") not in ("Bash", None):
        return None
    command = (payload.get("tool_input") or {}).get("command")
    parsed = parse(command)
    if not parsed:
        return None
    sub, key = parsed
    if not (LANE_ID.match(key) or TICKET.match(key)):
        return None
    tool_use_id = payload.get("tool_use_id")
    if ci.is_main(payload, claude_dir):
        ci.put_stamp("lane-main", [sub, key], session=str(payload.get("session_id") or ""), home=home, now=now,
                     tool_use_id=tool_use_id, transcript=payload.get("transcript_path"))
        return "lane-main"
    agent = payload.get("agent_id")
    if sub == "checkpoint" and isinstance(agent, str) and re.match(r"^[A-Za-z0-9_-]{1,64}$", agent):
        # the agent id travels in the stamp's session field: it comes from the payload, never from the caller
        ci.put_stamp("lane-holder", [key], session=agent, home=home, now=now)
        return "lane-holder"
    return None


def is_main(command, key, home=None):
    import caller_identity as ci  # noqa: PLC0415
    return ci.take_stamp("lane-main", [command, key], home=home, bound=True) is not None


def holder_identity(lane, home=None):
    """The agent id stamped for this lane's checkpoint call, else None."""
    import caller_identity as ci  # noqa: PLC0415
    got = ci.take_stamp("lane-holder", [lane], home=home)
    return got.get("session") if got else None
