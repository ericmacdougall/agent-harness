#!/usr/bin/env python3
"""Claude Code hook: private, append-only write-ahead logs per session and agent."""

import hashlib
import fcntl
import json
import os
import re
import sys
import stat
import time
from contextlib import ExitStack
from datetime import datetime, timezone
from pathlib import Path


try:
    import wal_segments
except ImportError:  # an install that has not shipped the module yet: plain append, noted on stderr
    wal_segments = None


class WalSegmentsMissing(RuntimeError):
    """wal_segments.py is not installed but something needs it (rotation is on, or segment files exist)."""


def require_segments(directory=None) -> None:
    """Fail-closed gate for writers, readers and gates: returns None when wal_segments is importable, or when nothing
    needs it (no enable file and no segment-shaped file in `directory`). Otherwise raises WalSegmentsMissing, because
    appending to or reading only the live file of a rotated WAL silently loses or hides records."""
    if wal_segments is not None:
        return None
    reason = None
    if (Path.home() / ".agent-harness" / "state" / "wal-rotation.on").is_file():
        reason = "~/.agent-harness/state/wal-rotation.on exists"
    elif directory is not None:
        try:
            with os.scandir(directory) as it:
                if any(re.search(r"\.\d{4,}\.jsonl$", e.name) for e in it):
                    reason = f"segment files exist in {directory}"
        except OSError:
            pass
    if reason:
        raise WalSegmentsMissing(f"wal_segments.py is missing but {reason}: refusing to continue without it "
                                 "(install wal_segments.py beside wal.py)")
    return None


def warn_missing_segments() -> None:
    print("wal: wal_segments.py is not installed; appending without rotation support", file=sys.stderr)


def safe_id(value: object) -> str:
    original = str(value or "unknown")
    cleaned = re.sub(r"[^A-Za-z0-9._-]", "_", original)
    # Only lowercase unescaped IDs use their original spelling. Escaping every
    # uppercase ID keeps Foo and foo distinct on case-insensitive filesystems.
    if (cleaned == original and cleaned == cleaned.lower() and len(cleaned) <= 120
            and cleaned.strip(".") and not cleaned.startswith("z-")
            and not re.search(r"\.\d{4,}$", cleaned)):  # segment-shaped stems are reserved (docs/wal-segments.md)
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
        pinned = [(root.parent, None, directory)]
        for name in ("wals", path.parent.name):
            try:
                os.mkdir(name, mode=0o700, dir_fd=directory)
            except FileExistsError:
                pass
            parent_fd = directory
            directory = os.open(name, flags, dir_fd=directory)
            stack.callback(os.close, directory)
            pinned.append((name, parent_fd, directory))
            os.fchmod(directory, 0o700)

        def current_directory():
            try:
                for name, parent_fd, opened_fd in pinned:
                    named = (os.stat(name, follow_symlinks=False) if parent_fd is None
                             else os.stat(name, dir_fd=parent_fd, follow_symlinks=False))
                    opened = os.fstat(opened_fd)
                    if (not stat.S_ISDIR(named.st_mode)
                            or (named.st_dev, named.st_ino) != (opened.st_dev, opened.st_ino)):
                        return False
            except OSError:
                return False
            return True

        # The open/lock/crash-tail/rotate/write/fsync flow is one implementation shared by every writer
        # (wal_segments.append_line, docs/wal-segments.md). If the module is missing, fall back to a plain append.
        if wal_segments is not None:
            wal_segments.append_line(directory, path.name, payload, current_directory)
            return
        require_segments(path.parent)  # fail closed when rotation is on or segment files exist
        warn_missing_segments()
        fd = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=directory)
        stack.callback(os.close, fd)
        fcntl.flock(fd, fcntl.LOCK_EX)
        os.write(fd, payload)
        os.fsync(fd)


def work_dir_context(session_id: str, event: str, data: dict) -> str:
    """Announce the durable per-session work directory; never fail the WAL hook over it."""
    try:
        import workdir
        path = workdir.ensure_session_dir(session_id)
    except Exception as exc:  # the WAL is the fail-closed record, not the work dir
        return (f" Durable work dir unavailable ({exc.__class__.__name__}); keep scripts, run kits, packets, "
                "TSVs, filters and job state in a private directory under ~/.agent-harness/work, not /tmp.")
    if event == "prompt":  # repeated every turn: keep it short
        return (f" Durable work dir: {path}/ for anything needed after a restart; /tmp and the scratchpad "
                "are disposable.")
    text = (f" Durable work dir: {path}/ (mode 0700). Put scripts, run kits, review packets, TSVs, filters, "
            "job state and anything needed after a restart there; /tmp and the session scratchpad are "
            "for disposable output only, and a reboot or retention pruning can delete them.")
    if event == "subagent":
        agent = safe_id(data.get("agent_id"))
        text += f" Shared by this session's agents: keep your files in {path}/agent-{agent}/ or a task-named subfolder."
    if event == "session":
        text += (" A resumed session keeps its session id and so this directory; a fork gets a new one, and "
                 "earlier session directories remain under ~/.agent-harness/work/.")
        try:
            text += workdir.scratchpad_drift_warning(data.get("scratchpad_dir"))
            if data.get("source") == "startup":
                text += workdir.retention_hint(session_id)
            workdir.spawn_task_output_prune(session_id=session_id)  # detached, at most daily
        except Exception:
            pass
    return text


def ops_alert_context(event: str, session: str = "") -> str:
    """Active ops-watch alerts from ~/.agent-harness/state/alerts.jsonl (docs/ops-watch.md). Never raises."""
    try:
        import ops_watch
        return ops_watch.injection_text(Path.home(), max_chars=400 if event == "prompt" else 700, session=session)
    except Exception:  # the prompt hook blocks on failure; a missing alert line must never block a prompt
        return ""


def tmp_advisory_output(data: dict) -> tuple:
    """Advisory only: count and message for durable state written under /tmp; never raises."""
    try:
        import workdir
        paths = workdir.tmp_advisory(str(data.get("tool_name", "")), data.get("tool_input"),
                                     data.get("scratchpad_dir"))
        if not paths:
            return 0, None
        message = workdir.advisory_message(paths, data.get("session_id"))
        output = {"hookSpecificOutput": {"hookEventName": "PreToolUse", "additionalContext": message}}
        if workdir.first_advisory(data.get("session_id")):
            output["systemMessage"] = message  # shown to the user once per session
        return len(paths), json.dumps(output)
    except Exception:
        return 0, None


# Types that own or review work and need the full brief; every other type gets a WAL and a short note.
OWNER_AGENT_TYPES = {"task-owner", "fixer", "red-team", "click-tester", "general-purpose", "claude"}


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
    }
    if event == "session":
        record["source"] = data.get("source", "")
        append(main_wal, record)
        print(json.dumps({"hookSpecificOutput": {"hookEventName": "SessionStart", "additionalContext": f"Session WAL: {main_wal}. Record task ownership, decisions, changes, checks, commits and handoffs; omit secrets and PII." + work_dir_context(session_id, event, data) + ops_alert_context(event, session_id)}}))
    elif event == "prompt":
        prompt = str(data.get("prompt", ""))
        record["prompt_chars"] = len(prompt)
        append(main_wal, record)
        print(json.dumps({"hookSpecificOutput": {"hookEventName": "UserPromptSubmit", "additionalContext": f"Session WAL: {main_wal}. Follow Agent Harness triage. Record a human-readable intent before edits; the hook metadata alone is insufficient. Use the fast path for small fixes. For substantive work, brief and reuse a background owner, then review, test, publish the feature branch and integrate locally. Ask about material ambiguity and keep the user updated. Never log secrets or PII." + work_dir_context(session_id, event, data) + ops_alert_context(event, session_id)}}))
    elif event == "subagent":
        agent_id = safe_id(data.get("agent_id"))
        agent_type = safe_id(data.get("agent_type"))
        agent_wal = root / f"agent-{agent_id}.jsonl"
        record.update({"agent_id": agent_id, "agent_type": agent_type})
        append(main_wal, record)
        append(agent_wal, record)
        if agent_type in OWNER_AGENT_TYPES:
            context = (f"Your private WAL: {agent_wal}. Read the main scope brief and decision log in {main_wal}; challenge "
                       "omissions and harmful shortcuts. Before editing, record intent, assumptions, domain invariants, a risk "
                       "table and negative acceptance cases. Then log decisions, tests, commits, blockers and handoff. Do not "
                       "log secrets or PII.")
        else:
            # Short-lived or read-only types (Explore, Plan, statusline-setup, claude-code-guide): a WAL for liveness and
            # results, no owner brief and no instruction to read the (large) main WAL.
            context = f"Your private WAL: {agent_wal}. Record results and blockers there; do not log secrets or PII."
        print(json.dumps({"hookSpecificOutput": {"hookEventName": "SubagentStart", "additionalContext": context + work_dir_context(session_id, event, data) + ops_alert_context(event, session_id)}}))
    elif event == "subagent_stop":
        # SubagentStop: lets spec_flow.py record when a click-test agent finished. Only ids that
        # SubagentStart logged are recorded, so spurious stops (empty agent_type) leave no trace.
        agent_id = safe_id(data.get("agent_id"))
        agent_wal = root / f"agent-{agent_id}.jsonl"
        if data.get("agent_id") and (wal_segments.exists(agent_wal) if wal_segments else agent_wal.exists()):
            record.update({"agent_id": agent_id, "agent_type": safe_id(data.get("agent_type"))})
            append(main_wal, record)
            append(agent_wal, record)
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
        advisories, output = tmp_advisory_output(data)
        if advisories:
            record["tmp_advisory"] = advisories  # a count only: paths stay out of the WAL
        append(wal, record)
        if output:
            print(output)
    else:
        raise ValueError(f"unknown event: {event}")


if __name__ == "__main__":
    main()
