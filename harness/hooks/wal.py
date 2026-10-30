#!/usr/bin/env python3
"""Claude Code hook: private, append-only write-ahead logs per session and agent."""

import hashlib
import fcntl
import json
import os
import re
import sys
import stat
from contextlib import ExitStack
from datetime import datetime, timezone
from pathlib import Path


def safe_id(value: object) -> str:
    original = str(value or "unknown")
    cleaned = re.sub(r"[^A-Za-z0-9._-]", "_", original)
    # Only lowercase unescaped IDs use their original spelling. Escaping every
    # uppercase ID keeps Foo and foo distinct on case-insensitive filesystems.
    if (cleaned == original and cleaned == cleaned.lower() and len(cleaned) <= 120
            and cleaned.strip(".") and not cleaned.startswith("z-")):
        return cleaned
    # Escaped IDs live in a reserved namespace. An ordinary ID equal to an
    # escaped result is escaped again, so direct alias construction fails.
    digest = hashlib.sha256(original.encode(errors="replace")).hexdigest()[:20]
    stem = cleaned.lower()[:97].strip(".") or "_"
    return f"z-{stem}-{digest}"


def append(path: Path, record: dict) -> None:
    root = Path.home() / ".claude" / "wals"
    if (path.parent.parent != root or path.suffix != ".jsonl"
            or not re.fullmatch(r"[A-Za-z0-9._-]{1,120}", path.parent.name)
            or path.parent.name in {".", ".."}):
        raise ValueError("WAL path must be a per-session JSONL under ~/.claude/wals")
    payload = (json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n").encode()
    root.parent.mkdir(mode=0o700, exist_ok=True)
    # Pin each directory with an fd: never follow a redirected session or WAL path.
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    with ExitStack() as stack:
        directory = os.open(root.parent, flags)
        stack.callback(os.close, directory)
        for name in ("wals", path.parent.name):
            try:
                os.mkdir(name, mode=0o700, dir_fd=directory)
            except FileExistsError:
                pass
            directory = os.open(name, flags, dir_fd=directory)
            stack.callback(os.close, directory)
            os.fchmod(directory, 0o700)
        fd = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW | os.O_NONBLOCK,
                     0o600, dir_fd=directory)
        stack.callback(os.close, fd)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError("WAL must be a regular file with no hard links")
        os.fchmod(fd, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX)
        # A short write must not silently report a complete record.
        with os.fdopen(fd, "ab", closefd=False) as handle:
            handle.write(payload)
            handle.flush()
        os.fsync(fd)


def main() -> None:
    event = sys.argv[1]
    data = json.load(sys.stdin)
    session_id = data.get("session_id")
    if not session_id:
        raise ValueError("Claude Code did not supply a session_id; refusing to use a shared WAL")
    root = Path.home() / ".claude" / "wals" / safe_id(session_id)
    main_wal = root / "main.jsonl"
    record = {
        "at": datetime.now(timezone.utc).isoformat(),
        "event": event,
        "cwd": data.get("cwd", ""),
    }
    if event == "session":
        record["source"] = data.get("source", "")
        append(main_wal, record)
        print(json.dumps({"hookSpecificOutput": {"hookEventName": "SessionStart", "additionalContext": f"Session WAL: {main_wal}. Record task ownership, decisions, changes, checks, commits and handoffs; omit secrets and PII."}}))
    elif event == "prompt":
        prompt = str(data.get("prompt", ""))
        record["prompt_chars"] = len(prompt)
        append(main_wal, record)
        print(json.dumps({"hookSpecificOutput": {"hookEventName": "UserPromptSubmit", "additionalContext": f"Session WAL: {main_wal}. Follow Agent Harness triage. Record a human-readable intent before edits; the hook metadata alone is insufficient. Use the fast path for small fixes. For substantive work, brief and reuse a background owner, then review, test, publish the feature branch and integrate locally. Ask about material ambiguity and keep the user updated. Never log secrets or PII."}}))
    elif event == "subagent":
        agent_id = safe_id(data.get("agent_id"))
        agent_type = safe_id(data.get("agent_type"))
        agent_wal = root / f"agent-{agent_id}.jsonl"
        record.update({"agent_id": agent_id, "agent_type": agent_type})
        append(main_wal, record)
        append(agent_wal, record)
        print(json.dumps({"hookSpecificOutput": {"hookEventName": "SubagentStart", "additionalContext": f"Your private WAL: {agent_wal}. Read the main scope brief and decision log in {main_wal}; challenge omissions and harmful shortcuts. Before editing, record intent, assumptions, domain invariants, a risk table and negative acceptance cases. Then log decisions, tests, commits, blockers and handoff. Do not log secrets or PII."}}))
    elif event == "pretool":
        agent_id = data.get("agent_id")
        wal = root / f"agent-{safe_id(agent_id)}.jsonl" if agent_id else main_wal
        tool_input = data.get("tool_input") or {}
        target = tool_input.get("file_path") or tool_input.get("command") or ""
        record.update({
            "agent_id": safe_id(agent_id) if agent_id else None,
            "tool": data.get("tool_name", ""),
            "tool_use_id": data.get("tool_use_id", ""),
            "target_chars": len(str(target)),
        })
        append(wal, record)
    else:
        raise ValueError(f"unknown event: {event}")


if __name__ == "__main__":
    main()
