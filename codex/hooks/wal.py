#!/usr/bin/env python3
"""Codex hook and note writer: private metadata-only WALs per session and agent."""

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
from contextlib import ExitStack
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


def append(path: Path, record: dict) -> None:
    root = wal_root()
    if (path.parent.parent != root or path.suffix != ".jsonl"
            or not re.fullmatch(r"[A-Za-z0-9._-]{1,120}", path.parent.name)
            or path.parent.name in {".", ".."}):
        raise ValueError("WAL path must be a per-session JSONL under ~/.agent-harness/codex-wals")
    payload = (json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n").encode()
    root.parent.mkdir(mode=0o700, exist_ok=True)
    # Pin each directory with an fd: never follow a redirected session or WAL path.
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    with ExitStack() as stack:
        directory = os.open(root.parent, flags)
        stack.callback(os.close, directory)
        pinned = [(root.parent, None, directory)]
        for name in ("codex-wals", path.parent.name):
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


def hook() -> None:
    data = json.load(sys.stdin)
    event = data.get('hook_event_name')
    session_id = data.get("session_id")
    if not session_id:
        raise ValueError("Codex did not supply a session_id; refusing to use a shared WAL")
    root = wal_root() / safe_id(session_id)
    main_wal = root / "main.jsonl"
    record = {
        "at": datetime.now(timezone.utc).isoformat(),
        "event": event,
    }
    if event == "SessionStart":
        record["source"] = data.get("source", "")
        append(main_wal, record)
        print(json.dumps({"hookSpecificOutput": {"hookEventName": event, "additionalContext": f"Session WAL: {main_wal}. Add redacted intent before edits, then decisions, checks, commits and handoffs. Hook metadata is not a semantic work log."}}))
    elif event == "UserPromptSubmit":
        prompt = str(data.get("prompt", ""))
        record["prompt_chars"] = len(prompt)
        append(main_wal, record)
        print(json.dumps({"hookSpecificOutput": {"hookEventName": event, "additionalContext": f"Session WAL: {main_wal}. Use the fast path for small changes. For substantive work, scope and coordinate an owner. Record redacted intent before editing."}}))
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
    args = parser.parse_args()
    if args.command == 'hook':
        hook()
    elif args.command == 'start-manual':
        path = wal_root() / safe_id(args.label + '-' + secrets.token_hex(8)) / 'main.jsonl'
        append(path, {'at': datetime.now(timezone.utc).isoformat(), 'event': 'manual-start'})
        print(json.dumps({'status': 'STARTED', 'wal': str(path)}))
    else:
        note(args.wal, args.event, args.note)


if __name__ == "__main__":
    main()
