#!/usr/bin/env python3
"""Claude Code hook: private, append-only write-ahead logs per session and agent."""

import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path


def safe_id(value: object) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", str(value or "unknown"))[:120]


def append(path: Path, record: dict) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    payload = (json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n").encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        os.write(fd, payload)
        os.fsync(fd)
    finally:
        os.close(fd)


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
        record["prompt_sha256"] = hashlib.sha256(prompt.encode()).hexdigest()
        record["prompt_chars"] = len(prompt)
        append(main_wal, record)
        print(json.dumps({"hookSpecificOutput": {"hookEventName": "UserPromptSubmit", "additionalContext": f"Session WAL: {main_wal}. Follow Agent Harness triage. Record a human-readable intent before edits; the hook metadata alone is insufficient. Use the fast path for small fixes. For substantive work, brief and reuse a background owner, then review, test, publish the feature branch and integrate locally. Ask about material ambiguity and keep the user updated. Never log secrets or PII."}}))
    elif event == "subagent":
        agent_id = safe_id(data.get("agent_id"))
        agent_type = safe_id(data.get("agent_type"))
        agent_wal = root / f"{agent_id}.jsonl"
        record.update({"agent_id": agent_id, "agent_type": agent_type})
        append(main_wal, record)
        append(agent_wal, record)
        print(json.dumps({"hookSpecificOutput": {"hookEventName": "SubagentStart", "additionalContext": f"Your private WAL: {agent_wal}. Read the main scope brief and decision log in {main_wal}; challenge omissions and harmful shortcuts. Before editing, record intent, assumptions, domain invariants, a risk table and negative acceptance cases. Then log decisions, tests, commits, blockers and handoff. Do not log secrets or PII."}}))
    elif event == "pretool":
        agent_id = data.get("agent_id")
        wal = root / f"{safe_id(agent_id)}.jsonl" if agent_id else main_wal
        tool_input = data.get("tool_input") or {}
        target = tool_input.get("file_path") or tool_input.get("command") or ""
        record.update({
            "agent_id": safe_id(agent_id) if agent_id else None,
            "tool": data.get("tool_name", ""),
            "tool_use_id": data.get("tool_use_id", ""),
            "target_sha256": hashlib.sha256(str(target).encode()).hexdigest() if target else None,
        })
        append(wal, record)
    else:
        raise ValueError(f"unknown event: {event}")


if __name__ == "__main__":
    main()
