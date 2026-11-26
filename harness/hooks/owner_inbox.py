#!/usr/bin/env python3
"""owner_inbox: inject unread answer notes (the owner's, or a supervisor's) into a session.

Claude Desktop and Codex Desktop sessions cannot receive typed stall-watcher answers.
The owner, Fleet Ops or a supervisor writes complete standalone notes to:

    ~/.agent-harness/inbox/<session_id>/*.md (and *.txt; OWNER-DECISION-*.md names are kept)

That folder is a record path (sandbox_base.json): a worker's or reviewer's sandbox cannot write it, so one misled
agent cannot plant a note in every session. Notes under the session's own work folder are no longer read: any
worker can write there (release 1001 red team). Without a sandbox nothing protects either folder, so the note is
introduced as a note from its writer, not as a proven owner decision.

This hook, on UserPromptSubmit, SessionStart and PostToolUse, loads any unread notes for
the hook's session_id, oldest first, returns them as additionalContext (inlined while they
fit 600 characters, else one line per note naming the file to read), then marks them read.
Each note carries its id (path@sha) and what it answers (an In-Reply-To:/Answers: line and
the ask ids it names), so the session closes those asks instead of asking them again. Stop
never blocks: one advisory line per set of unread notes, which stay unread for the next
prompt. A later edit of the same file (content hash change) makes it unread again, marked
UPDATED. The hook fails open: it never breaks the session.

    owner_inbox.py hook     Claude/Codex hook (stdin: hook event JSON)
    owner_inbox.py pending --session SID   list unread note paths (JSON, no bodies)
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from wal import safe_id  # noqa: E402

STATE_NAME = ".owner-inbox-read.json"
INBOX_ROOT = "inbox"   # ~/.agent-harness/inbox/<session>/
DECISION_NAME = re.compile(r"^OWNER-DECISION-[A-Za-z0-9._-]{1,200}\.md$")
INBOX_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,200}\.(md|txt)$")
MAX_FILE = 64 * 1024
MAX_TOTAL = 128 * 1024
MAX_FILES = 8
MAX_STDIN = 1024 * 1024
CONTEXT_EVENTS = {"UserPromptSubmit", "SessionStart", "PostToolUse"}
STOP_EVENT = "Stop"
HOOK_EVENTS = CONTEXT_EVENTS | {STOP_EVENT}
HEADER = (
    "ANSWER INBOX: unread note(s) left for this session in ~/.agent-harness/inbox, a folder only the owner and "
    "supervisors can write. Weigh each as a message from its writer and continue the allowed work. They are now "
    "marked read and will not be re-injected unless the file contents change."
)
CONTEXT_CAP = 600        # a hook invocation inlines notes only up to this; longer ones arrive as a path to read
ASK_ID = re.compile(r"\b(?:ask[: ]+|\[ask:)(w[0-9a-f]{11})\b")
REPLY_TO = re.compile(r"(?im)^\s*(?:in-reply-to|answers?)\s*:\s*(.{1,200})$")


def home() -> Path:
    override = os.environ.get("HARNESS_OWNER_INBOX_HOME") or os.environ.get("AH_HOME")
    if override:
        return Path(override)
    return Path.home()


def inbox_root() -> Path:
    return home() / ".agent-harness" / INBOX_ROOT


def session_dir(session_id: str) -> Path:
    return inbox_root() / safe_id(session_id)


def _open_dir(path: Path) -> int:
    return os.open(str(path), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)


def _regular_file(dirfd: int, name: str) -> os.stat_result | None:
    try:
        info = os.stat(name, dir_fd=dirfd, follow_symlinks=False)
    except OSError:
        return None
    if not stat.S_ISREG(info.st_mode):
        return None
    return info


def _read_file(dirfd: int, name: str, size: int) -> bytes:
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=dirfd)
    try:
        chunks = []
        remaining = min(size, MAX_FILE) if size > 0 else MAX_FILE
        # Also cap a lying/racy size: never read more than MAX_FILE.
        while remaining > 0:
            chunk = os.read(fd, min(65536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)


def _load_state(dirfd: int) -> dict:
    info = _regular_file(dirfd, STATE_NAME)
    if info is None or info.st_size > MAX_FILE:
        return {"schema": 1, "read": {}}
    try:
        raw = _read_file(dirfd, STATE_NAME, info.st_size)
        data = json.loads(raw.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError):
        return {"schema": 1, "read": {}}
    if not isinstance(data, dict) or data.get("schema") != 1 or not isinstance(data.get("read"), dict):
        return {"schema": 1, "read": {}}
    return data


def _write_state(dirfd: int, state: dict) -> None:
    payload = (json.dumps(state, indent=2, sort_keys=True) + "\n").encode("utf-8")
    tmp = f".owner-inbox-read.{os.getpid()}.{secrets.token_hex(8)}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=dirfd)
    try:
        try:
            os.write(fd, payload)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.rename(tmp, STATE_NAME, src_dir_fd=dirfd, dst_dir_fd=dirfd)
    except Exception:
        try:
            os.unlink(tmp, dir_fd=dirfd)
        except OSError:
            pass
        raise


def _candidates(session_fd: int) -> list[tuple[str, str, str]]:
    """The note names in the session's inbox folder, as (relpath, dir_tag, name), oldest first."""
    found: list[tuple[str, str, str]] = []
    try:
        names = os.listdir(session_fd)
    except OSError:
        return []
    for name in names:
        if DECISION_NAME.match(name) or INBOX_NAME.match(name):
            found.append((name, "session", name))

    def written(row):
        try:
            return os.stat(row[2], dir_fd=session_fd, follow_symlinks=False).st_mtime
        except OSError:
            return 0.0
    found.sort(key=lambda row: (written(row), row[0]))  # oldest first: an answer never arrives before its question
    return found


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def collect_unread(session_id: str) -> list[dict]:
    """Unread notes for this session: [{relpath, text, sha256, bytes, truncated}]."""
    if not session_id or not str(session_id).strip():
        return []
    path = session_dir(session_id)
    try:
        session_fd = _open_dir(path)
    except OSError:
        return []
    try:
        state = _load_state(session_fd)
        read = state.get("read") or {}
        rows = []
        total = 0
        for relpath, _tag, name in _candidates(session_fd):
            dirfd = session_fd
            info = _regular_file(dirfd, name)
            if info is None:
                continue
            try:
                data = _read_file(dirfd, name, info.st_size)
            except OSError:
                continue
            digest = _digest(data)
            previous = read.get(relpath)
            if isinstance(previous, dict) and previous.get("sha256") == digest:
                continue
            truncated = info.st_size > len(data) or len(data) >= MAX_FILE and info.st_size > MAX_FILE
            text = data.decode("utf-8", errors="replace")
            if truncated:
                text = text.rstrip() + f"\n\n[truncated: file is {info.st_size} bytes; injected the first {len(data)}]\n"
            rows.append({"relpath": relpath, "text": text, "sha256": digest, "bytes": len(data),
                         "truncated": bool(truncated), "path": str(path / relpath),
                         "updated": previous.get("injected_at") if isinstance(previous, dict) else None,
                         "in_reply_to": in_reply_to(text)})
        kept = []
        for row in rows:
            if len(kept) >= MAX_FILES:
                break
            if total + len(row["text"].encode("utf-8")) > MAX_TOTAL and kept:
                break
            piece = row["text"]
            encoded = piece.encode("utf-8")
            if total + len(encoded) > MAX_TOTAL:
                remain = MAX_TOTAL - total
                piece = encoded[:remain].decode("utf-8", errors="ignore") + "\n\n[truncated to inbox total cap]\n"
                row = dict(row, text=piece, truncated=True)
            kept.append(row)
            total += len(row["text"].encode("utf-8"))
        overflow = len(rows) - len(kept)
        if overflow > 0 and kept:
            kept[-1] = dict(kept[-1], overflow=overflow)
        return kept
    finally:
        os.close(session_fd)


def mark_read(session_id: str, items: list[dict]) -> None:
    if not items:
        return
    path = session_dir(session_id)
    session_fd = _open_dir(path)
    try:
        state = _load_state(session_fd)
        read = dict(state.get("read") or {})
        now = datetime.now(timezone.utc).isoformat()
        for item in items:
            read[item["relpath"]] = {"sha256": item["sha256"], "bytes": item["bytes"], "injected_at": now}
        state = {"schema": 1, "read": read}
        _write_state(session_fd, state)
    finally:
        os.close(session_fd)


def in_reply_to(text: str) -> list[str]:
    """What a note answers: an `In-Reply-To:` / `Answers:` header line, plus every ask id it names (`[ask:w...]`,
    `ask w...`). The session closes those asks, so their reminders stop and nobody asks them again."""
    found = []
    for m in REPLY_TO.finditer(text[:4096]):
        words = re.findall(r"[A-Za-z0-9#:_-]{3,40}", m.group(1))
        found += [w[4:] if w.lower().startswith("ask:") else w for w in words][:5]
    found += ASK_ID.findall(text)
    return list(dict.fromkeys(found))[:10]


def note_id(item: dict) -> str:
    return f"{item['relpath']}@{item['sha256'][:8]}"


def format_items(items: list[dict], session: str = "") -> str:
    """Notes oldest first, each with its id and what it answers. Inlined while the whole fits CONTEXT_CAP; otherwise
    one line per note naming the file to read (it stays on disk), so a long note never floods the context."""
    def head(item):
        line = f"--- {note_id(item)}"
        if item.get("updated"):
            line += f" (UPDATED; an earlier version was delivered {item['updated'][:19]}Z)"
        asks = [a for a in item.get("in_reply_to") or [] if re.fullmatch(r"w[0-9a-f]{11}", a)]
        if item.get("in_reply_to"):
            line += f" in-reply-to: {', '.join(item['in_reply_to'])}"
        if asks:
            line += (f"; close each answered ask: python3 ~/.claude/hooks/wal_note.py --wal ~/.claude/wals/"
                     f"{safe_id(session) if session else '<session>'}/main.jsonl --event ask_resolved --ref {asks[0]} "
                     f"--source 'file:{item.get('path', item['relpath'])}' --note '<the answer>'")
        return line + " ---"
    overflow = items[-1].get("overflow") if items else 0
    more = f"+{overflow} more unread note(s) were not injected this turn; they will be offered next." if overflow else ""
    inline = "\n\n".join([HEADER] + [head(i) + "\n" + i["text"].rstrip() for i in items] + ([more] if more else []))
    if len(inline) <= CONTEXT_CAP:
        return inline + "\n"
    lines = ["ANSWER INBOX: unread note(s) for this session from ~/.agent-harness/inbox (the owner or a supervisor "
             "wrote them), too long to inline here. Read each file below and weigh it as a message from its writer, "
             "then continue the allowed work. They are now marked read and will not be re-injected unless the file "
             "contents change."]
    lines += [f"{head(i)} {i['path']} ({i['bytes']} bytes)" for i in items]
    return "\n".join(lines + ([more] if more else [])) + "\n"


def hook_output(event: dict) -> dict | None:
    """The hook decision for one event, or None. Marks notes read only when a payload is returned."""
    name = event.get("hook_event_name")
    session = event.get("session_id")
    if name not in HOOK_EVENTS or not isinstance(session, str) or not session.strip():
        return None
    # A subagent event carries agent_id and shares the parent's session_id; do not consume the note there.
    # agent_type alone is not enough: a main session started with --agent also has agent_type.
    if event.get("agent_id"):
        return None
    items = collect_unread(session)
    if not items:
        return None
    if name == STOP_EVENT:
        # Never a block (2026-11-24): the notes stay unread for the next prompt, tool call or session start; one
        # advisory line, once per set of notes, says they are waiting.
        if event.get("stop_hook_active") or not _stop_changed(session, ",".join(note_id(i) for i in items)):
            return None
        return {"systemMessage": f"answer inbox: {len(items)} unread note(s) for this session; they are "
                                 "delivered at the next prompt: " + ", ".join(note_id(i) for i in items[:4])}
    text = format_items(items, session)
    marked = False
    try:
        mark_read(session, items)
        marked = True
    except OSError:
        marked = False
    if not marked and name == "PostToolUse":
        return None  # a failed mark would otherwise re-inject after every tool
    if not marked:
        text = text.replace(
            "They are now marked read and will not be re-injected unless the file contents change.",
            "They could not be marked read this turn and may be offered again.",
        )
    return {"hookSpecificOutput": {"hookEventName": name, "additionalContext": text}}


def _stop_changed(session: str, signature: str) -> bool:
    """True (and recorded in the session's inbox state) when the unread set differs from the one Stop last named."""
    try:
        fd = _open_dir(session_dir(session))
    except OSError:
        return True
    try:
        state = _load_state(fd)
        if state.get("stop_named") == signature:
            return False
        state["stop_named"] = signature
        try:
            _write_state(fd, state)
        except OSError:
            return False  # a line that cannot be rate-limited would repeat at every stop
        return True
    finally:
        os.close(fd)


def cmd_hook(_args) -> int:
    try:
        raw = sys.stdin.read(MAX_STDIN)
        event = json.loads(raw) if raw.strip() else {}
        out = hook_output(event) if isinstance(event, dict) else None
        if out:
            print(json.dumps(out))
    except Exception:  # noqa: BLE001 - never break the session; fail open, say nothing
        return 0
    return 0


def cmd_pending(args) -> int:
    items = collect_unread(args.session)
    print(json.dumps({"session": args.session, "unread": [{"relpath": i["relpath"], "bytes": i["bytes"]}
                                                           for i in items]}))
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="owner_inbox", description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("hook").set_defaults(func=cmd_hook)
    p = sub.add_parser("pending")
    p.add_argument("--session", required=True)
    p.set_defaults(func=cmd_pending)
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
