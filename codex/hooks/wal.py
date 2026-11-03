#!/usr/bin/env python3
"""Codex hook and note writer: private metadata-only WALs per session and agent."""

from __future__ import annotations

import argparse
import hashlib
import fcntl
import json
import os
import re
import secrets
import sys
import stat
import time
from contextlib import ExitStack, contextmanager
from datetime import datetime, timezone
from pathlib import Path


EVENTS = {'intent', 'scope', 'decision', 'risk', 'check', 'commit', 'blocker', 'status', 'handoff', 'result'}
SECRET_PATTERN = re.compile(
    r'(?i)(?:\bgh[pousr]_[A-Za-z0-9_]+|\bgithub_pat_[A-Za-z0-9_]+|'
    r'\bsk-[A-Za-z0-9-]{12,}|\bAKIA[A-Z0-9]{12}|'
    r'\bBearer\s+\S+|\bxox[baprs]-[A-Za-z0-9-]{6,}|'
    # Match credential names at the end of snake/kebab keys, including quoted
    # JSON keys. Do not mistake metrics such as token_count for credentials.
    r'\b(?:[a-z0-9]+[_-])*(?:password|passwd|secret|token|api[_-]?key|'
    r'access[_-]?key|private[_-]?key|credentials?)(?:[_-]value)?[\x22\x27]?\s*[:=]\s*[\x22\x27]?\S+|'
    r'\b[a-z][a-z0-9]*(?:Secret|Token|Password|ApiKey|AccessKey|PrivateKey|Credentials?)'
    r'[\x22\x27]?\s*[:=]\s*[\x22\x27]?\S+|'
    # Any userinfo in a URL authority may contain a credential or private user.
    # The authority ends at /, ?, or #, so ordinary path/query @ signs are safe.
    r'\b[a-z][a-z0-9+.-]*://[^\s/?#@]+@[^\s/?#]+|'
    r'-----BEGIN (?:RSA |OPENSSH |EC |DSA )?PRIVATE KEY-----)'
)


def wal_root() -> Path:
    return Path.home() / '.agent-harness' / 'codex-wals'


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


@contextmanager
def session_directory(session: str):
    root = wal_root()
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,120}", session) or session in {".", ".."}:
        raise ValueError("invalid session directory")
    root.parent.mkdir(mode=0o700, exist_ok=True)
    # Pin each directory with an fd: never follow a redirected session or WAL path.
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    with ExitStack() as stack:
        directory = os.open(root.parent, flags)
        stack.callback(os.close, directory)
        pinned = [(root.parent, None, directory)]
        for name in ("codex-wals", session):
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

        yield directory, current_directory


def append(path: Path, record: dict) -> None:
    root = wal_root()
    if (path.parent.parent != root or path.suffix != ".jsonl"
            or not re.fullmatch(r"[A-Za-z0-9._-]{1,120}", path.parent.name)
            or path.parent.name in {".", ".."}):
        raise ValueError("WAL path must be a per-session JSONL under ~/.agent-harness/codex-wals")
    payload = (json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n").encode()
    with session_directory(path.parent.name) as (directory, current_directory), ExitStack() as stack:
        file_flags = os.O_RDWR | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW | os.O_NONBLOCK
        for attempt in range(4):
            if not current_directory():
                raise ValueError("WAL session directory changed")
            try:
                fd = os.open(path.name, file_flags, 0o600, dir_fd=directory)
                break
            except FileNotFoundError:
                # A concurrent first write has occasionally observed ENOENT on
                # macOS despite O_CREAT. Retry only while the named session
                # directory still resolves to the pinned inode, never after a
                # directory replacement or removal.
                if attempt == 3 or not current_directory():
                    raise
                time.sleep(0.01 * (attempt + 1))
        stack.callback(os.close, fd)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError("WAL must be a regular file with no hard links")

        def current_target():
            if not current_directory():
                return False
            try:
                named = os.stat(path.name, dir_fd=directory, follow_symlinks=False)
                opened = os.fstat(fd)
            except OSError:
                return False
            return (stat.S_ISREG(named.st_mode) and named.st_nlink == 1
                    and (named.st_dev, named.st_ino) == (opened.st_dev, opened.st_ino))

        os.fchmod(fd, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX)
        if not current_target():
            raise ValueError("WAL target changed before append")
        # A killed writer may leave a partial final record. Under the file lock,
        # remove only that unterminated suffix before adding the next JSONL line.
        end = os.lseek(fd, 0, os.SEEK_END)
        if end and os.pread(fd, 1, end - 1) != b"\n":
            scan = min(end, 65_536)
            tail = os.pread(fd, scan, end - scan)
            last_newline = tail.rfind(b"\n")
            if last_newline < 0 and end > scan:
                raise ValueError("WAL crash tail exceeds recovery budget")
            os.ftruncate(fd, end - scan + last_newline + 1)
            if not current_target():
                raise ValueError("WAL target changed during crash recovery")
        # A short write must not silently report a complete record.
        with os.fdopen(fd, "ab", closefd=False) as handle:
            handle.write(payload)
            handle.flush()
        os.fsync(fd)
        if not current_target():
            raise ValueError("WAL target changed during append")


WORK_STATES = {"active", "blocked", "handoff", "complete", "paused"}
STATE_FILE = "continuation.json"
CONTINUE_REASON = (
    "The session still has active tracked work. Continue with the next authorized "
    "step or reconcile the running check. Only mark completion after verification. "
    "Honor any explicit user stop. If external action is required or a durable "
    "monitor owns the work, record the evidence in the WAL and update the checkpoint."
)
UNFINISHED = "The session has unfinished tracked work. Its continuation allowance has been used or cannot be applied."
UNAVAILABLE = "The continuation checkpoint could not be read or updated. Check its status before claiming completion."


def state_file(directory: int, name: str, flags: int) -> int:
    fd = os.open(name, flags | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=directory)
    info = os.fstat(fd)
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
            or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600):
        os.close(fd)
        raise ValueError("invalid private continuation file")
    return fd


def read_checkpoint(directory: int) -> dict | None:
    try:
        fd = state_file(directory, STATE_FILE, os.O_RDONLY)
    except FileNotFoundError:
        return None
    with os.fdopen(fd, "rb") as handle:
        data = handle.read(513)
    if len(data) > 512:
        raise ValueError("oversize continuation checkpoint")
    state = json.loads(data)
    if (not isinstance(state, dict) or set(state) != {"state", "used"}
            or not isinstance(state["state"], str) or state["state"] not in WORK_STATES
            or not isinstance(state["used"], bool)):
        raise ValueError("invalid continuation checkpoint")
    return state


def save_checkpoint(directory: int, current_directory, state: dict) -> None:
    temp = "continuation-" + secrets.token_hex(12)
    fd = state_file(directory, temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
    try:
        with os.fdopen(fd, "w") as handle:
            json.dump(state, handle)
            handle.flush()
            os.fsync(handle.fileno())
        if not current_directory():
            raise ValueError("continuation directory changed")
        os.replace(temp, STATE_FILE, src_dir_fd=directory, dst_dir_fd=directory)
        os.fsync(directory)
    finally:
        try:
            os.unlink(temp, dir_fd=directory)
        except FileNotFoundError:
            pass


def checkpoint(session: str, action: str) -> tuple[dict | None, bool]:
    with session_directory(session) as (directory, current_directory):
        # The stable lock serializes the budget claim and explicit status changes.
        lock = state_file(directory, "continuation.lock", os.O_RDWR | os.O_CREAT)
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            named = os.stat("continuation.lock", dir_fd=directory, follow_symlinks=False)
            if not os.path.samestat(named, os.fstat(lock)) or not current_directory():
                raise ValueError("continuation lock or directory changed")
            state = read_checkpoint(directory)
            active = state is not None and state["state"] == "active"
            claimed = action == "claim" and active and not state["used"]
            if claimed:
                state = {"state": "active", "used": True}
            elif action in WORK_STATES and not (action == "active" and active):
                state = {"state": action, "used": False}
            elif action == "interrupt" and active:
                state = {"state": "paused", "used": False}
            else:
                return state, False
            save_checkpoint(directory, current_directory, state)
            return state, claimed
        finally:
            os.close(lock)


def lifecycle_hook(data: dict, session: str) -> None:
    interrupt = data["hook_event_name"] == "Interrupt"
    may_claim = (isinstance(data.get("turn_id"), str) and bool(data["turn_id"])
                 and data.get("stop_hook_active") is False)
    action = "interrupt" if interrupt else "claim" if may_claim else "status"
    try:
        state, claimed = checkpoint(session, action)
    except (OSError, ValueError):
        result = {"systemMessage": UNAVAILABLE}
    else:
        if claimed:
            result = {"decision": "block", "reason": CONTINUE_REASON}
        elif state is not None and state["state"] == "active":
            result = {"systemMessage": UNFINISHED}
        else:
            result = {}
    print(json.dumps(result))


def checkpoint_context(session: str, text: str) -> str:
    try:
        state, _ = checkpoint(session, "status")
    except (OSError, ValueError):
        return text + " " + UNAVAILABLE
    if state is not None and state["state"] == "active":
        return text + " An active work checkpoint remains open. Reconcile its WAL and live evidence."
    return text


def hook() -> None:
    data = json.load(sys.stdin)
    event = data.get('hook_event_name')
    session_id = data.get("session_id")
    if not session_id:
        raise ValueError("Codex did not supply a session_id; refusing to use a shared WAL")
    session = safe_id(session_id)
    if event in {"Stop", "Interrupt"}:
        lifecycle_hook(data, session)
        return
    root = wal_root() / session
    main_wal = root / "main.jsonl"
    record = {
        "at": datetime.now(timezone.utc).isoformat(),
        "event": event,
    }
    if event == "SessionStart":
        record["source"] = data.get("source", "")
        append(main_wal, record)
        print(json.dumps({"hookSpecificOutput": {"hookEventName": event, "additionalContext": checkpoint_context(session, f"Session WAL: {main_wal}. Add redacted intent before edits, then decisions, checks, commits and handoffs. Hook metadata is not a semantic work log.")}}))
    elif event == "UserPromptSubmit":
        prompt = str(data.get("prompt", ""))
        record["prompt_chars"] = len(prompt)
        append(main_wal, record)
        print(json.dumps({"hookSpecificOutput": {"hookEventName": event, "additionalContext": checkpoint_context(session, f"Session WAL: {main_wal}. Use the fast path for small changes. For substantive work, scope and coordinate an owner. Record redacted intent before editing.")}}))
    elif event == "SubagentStart":
        agent_id = safe_id(data.get("agent_id"))
        agent_type = safe_id(data.get("agent_type"))
        agent_wal = root / f"agent-{agent_id}.jsonl"
        record.update({"agent_id": agent_id, "agent_type": agent_type})
        append(main_wal, record)
        append(agent_wal, record)
        print(json.dumps({"hookSpecificOutput": {"hookEventName": event, "additionalContext": f"Your private WAL: {agent_wal}. Read the main scope brief and decisions in {main_wal}; record redacted intent, tests, commits and handoff."}}))
    elif event == "PreToolUse":
        agent_id = data.get("agent_id")
        wal = root / f"agent-{safe_id(agent_id)}.jsonl" if agent_id else main_wal
        tool_input = data.get("tool_input") or {}
        input_chars = len(json.dumps(tool_input, ensure_ascii=False))
        record.update({
            "agent_id": safe_id(agent_id) if agent_id else None,
            "tool": data.get("tool_name", ""),
            "tool_use_id": data.get("tool_use_id", ""),
            "input_chars": input_chars,
        })
        append(wal, record)
    else:
        raise ValueError(f"unknown event: {event}")


def note(wal: Path, event: str, text: str) -> None:
    path = wal.expanduser().absolute()
    if event not in EVENTS:
        raise ValueError('unsupported WAL event')
    message = text.strip()
    if not message or len(message) > 4000:
        raise ValueError('note must be 1 to 4000 characters')
    if SECRET_PATTERN.search(message):
        raise ValueError('note appears to contain a credential; redact it first')
    append(path, {'at': datetime.now(timezone.utc).isoformat(), 'event': event, 'note': message})
    print(json.dumps({'status': 'WROTE', 'event': event, 'wal': str(path)}))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    subcommands = parser.add_subparsers(dest='command', required=True)
    subcommands.add_parser('hook')
    manual = subcommands.add_parser('start-manual')
    manual.add_argument('--label', default='manual')
    entry = subcommands.add_parser('note')
    entry.add_argument('--wal', type=Path, required=True)
    entry.add_argument('--event', choices=sorted(EVENTS), required=True)
    entry.add_argument('--note', required=True)
    continuation = subcommands.add_parser('continuation')
    continuation.add_argument('--wal', type=Path, required=True)
    continuation.add_argument('state', choices=sorted(WORK_STATES | {'status'}))
    args = parser.parse_args()
    if args.command == 'hook':
        hook()
    elif args.command == 'start-manual':
        path = wal_root() / safe_id(args.label + '-' + secrets.token_hex(8)) / 'main.jsonl'
        append(path, {'at': datetime.now(timezone.utc).isoformat(), 'event': 'manual-start'})
        print(json.dumps({'status': 'STARTED', 'wal': str(path)}))
    elif args.command == 'continuation':
        path = args.wal.expanduser().absolute()
        if path.name != 'main.jsonl' or path.parent.parent != wal_root():
            parser.error('continuation requires a main session WAL path')
        try:
            state, _ = checkpoint(path.parent.name, args.state)
        except (OSError, ValueError):
            parser.error(UNAVAILABLE)
        print(json.dumps(state or {'state': 'untracked', 'used': False}))
    else:
        note(args.wal, args.event, args.note)


if __name__ == "__main__":
    main()
