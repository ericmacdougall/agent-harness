"""Who is calling a hook, and one-shot stamps that only the main agent's hook writes (goodqa#15253).

A payload without agent_id does not prove that main is calling (#134 red-team B7).
Native runtime evidence or ambiguous native context denies legacy Claude-main
fallback; OpenAI origin does not authenticate a thread or role. Otherwise the payload has no agent_id and no agent_type, its
session_id is a Claude session id, and its transcript_path is the regular file
<claude home>/projects/<project>/<session_id>.jsonl. A sub-agent transcript is under .../<session_id>/subagents/,
and a Codex rollout is under ~/.codex, so neither qualifies.

Limit: a sub-agent that launches its own `claude -p` starts a new main session with its own transcript; that call is
main here. Threat model, as for the other gates: careless agents, not one that edits the hooks or the stamp files.

Stamps: a PreToolUse hook that has proven main records a stamp for one purpose and key. The process the command
starts takes it (single use, at most STAMP_TTL_SECONDS old). A command no main hook saw, such as one in a copied
script, a script file or a sub-agent's shell, finds no stamp.

Bound stamps (goodqa#15754 red-team F1): PreToolUse runs before the permission check and before the other PreToolUse
hooks have decided, so a stamp keyed by argv alone outlived a call that never ran (another hook denied it, the user
rejected it, `cd /nonexistent && ...` failed first) and the next process with the same argv was taken for main. A
bound stamp also records main's tool_use_id, main's transcript path and that transcript's size when the stamp was
written. take_stamp(bound=True) honours it only while that call is still running: Claude Code appends the call's
tool_result (or the refusal) to main's transcript when the call ends or is refused, so a transcript that already holds
`"tool_use_id":"<id>"` after the recorded offset means the call is over and the stamp is dead. mission_gate's
PostToolUse / PostToolUseFailure / PermissionDenied hook also deletes the call's stamp (drop_tool_stamps). A stamp
without a tool_use_id, a missing or shrunken transcript, or more than BOUND_SCAN_BYTES of transcript growth is
refused: the main-only path fails closed. Limit: a command started in the background (run_in_background) gets its
tool_result at once, so a main-only command must run in the foreground.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import time
import uuid
from pathlib import Path

from native_context import native_deny_reason

SESSION_ID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
STAMP_TTL_SECONDS = 600
STAMP_DIR = "main-stamps"
BOUND_SCAN_BYTES = 32 << 20  # transcript growth read to see whether the stamped call has ended; more is refused
TOOL_USE_ID = re.compile(r"^[A-Za-z0-9_-]{8,128}$")


def claude_home(home=None) -> Path:
    if home:
        return Path(home)
    configured = os.environ.get("CLAUDE_CONFIG_DIR")
    return Path(configured) if configured else Path.home() / ".claude"


def is_main(payload, claude_dir=None) -> bool:
    """True only for a Claude Code main-agent payload, proven by its own transcript path (see module doc)."""
    if not isinstance(payload, dict) or payload.get("agent_id") or payload.get("agent_type"):
        return False
    if native_deny_reason(payload):
        return False
    session, path = payload.get("session_id"), payload.get("transcript_path")
    if not isinstance(session, str) or not SESSION_ID.match(session) or not isinstance(path, str) or "\x00" in path:
        return False
    try:
        projects = os.path.realpath(str(claude_home(claude_dir) / "projects"))
        real = Path(os.path.realpath(path))
        return (real.name == session + ".jsonl" and str(real.parent.parent) == projects and real.is_file()
                and not real.is_symlink())
    except (OSError, ValueError):
        return False


def stamp_dir(home=None) -> Path:
    return Path(home or Path.home()) / ".agent-harness" / "state" / STAMP_DIR


def stamp_key(purpose: str, parts) -> str:
    text = "|".join([purpose] + [str(p).strip().lower() for p in parts])
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()[:40]


def put_stamp(purpose: str, parts, session: str = "", home=None, now=None, tool_use_id=None, transcript=None) -> None:
    """Record a one-shot stamp. With tool_use_id and transcript (main's proven transcript path) the stamp is bound to
    that one tool call: see take_stamp(bound=True)."""
    folder = stamp_dir(home)
    folder.mkdir(parents=True, exist_ok=True, mode=0o700)
    key = stamp_key(purpose, parts)
    record = {"purpose": purpose, "session": str(session)[:80], "ts": now or time.time()}
    if isinstance(tool_use_id, str) and TOOL_USE_ID.match(tool_use_id) and transcript:
        try:
            size = os.stat(str(transcript)).st_size
        except OSError:
            size = None
        if size is not None:
            record.update(tool_use_id=tool_use_id, transcript=str(transcript)[:4096], offset=size)
    tmp = folder / ("%s.%s.tmp" % (key, uuid.uuid4().hex[:8]))
    tmp.write_text(json.dumps(record), encoding="utf-8")
    os.chmod(str(tmp), 0o600)
    os.replace(str(tmp), str(folder / (key + ".json")))


def take_stamp(purpose: str, parts, home=None, now=None, bound: bool = False, ttl=None):
    """The stamp record (consumed) or None: missing, already used, expired or unreadable. bound=True also requires a
    stamp bound to a tool call that has not ended yet (call_still_running); ttl overrides STAMP_TTL_SECONDS.
    Every check runs BEFORE the stamp is claimed (PR 226 review M1): a caller that cannot prove the stamp (wrong
    purpose, too old for its TTL, cannot see main's call still running) leaves it in place, so a probe never burns
    main's stamp. Of two callers that both pass, the atomic rename lets only one consume it."""
    folder = stamp_dir(home)
    path = folder / (stamp_key(purpose, parts) + ".json")
    raw = _read_stamp(path)
    if raw is None or not _stamp_ok(raw, purpose, now, bound, ttl):
        return None
    claimed = folder / (path.stem + ".%s.claimed" % uuid.uuid4().hex[:8])
    try:
        os.rename(str(path), str(claimed))  # atomic: of two takers only one wins
    except OSError:
        return None
    got = _read_stamp(claimed)
    if got != raw and (got is None or not _stamp_ok(got, purpose, now, bound, ttl)):
        # a new stamp replaced the checked one between the read and the claim and this caller cannot prove it: put
        # it back unless yet another stamp has arrived meanwhile
        try:
            os.link(str(claimed), str(path))
        except OSError:
            pass
        got = None
    try:
        os.unlink(str(claimed))
    except OSError:
        pass
    return json.loads(got.decode("utf-8")) if got is not None else None


def _read_stamp(path: Path):
    """The raw bytes of one stamp file (no symlink, regular file, at most 4096 bytes) or None."""
    try:
        fd = os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    except OSError:
        return None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return None
        return os.read(fd, 4096)
    except OSError:
        return None
    finally:
        os.close(fd)


def _stamp_ok(raw: bytes, purpose: str, now, bound: bool, ttl) -> bool:
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return False
    if not isinstance(data, dict) or data.get("purpose") != purpose:
        return False
    try:
        if (now or time.time()) - float(data["ts"]) > (STAMP_TTL_SECONDS if ttl is None else ttl):
            return False
    except (KeyError, TypeError, ValueError):
        return False
    return not bound or call_still_running(data)


def call_still_running(data) -> bool:
    """True only when the stamp names a tool call (tool_use_id, transcript, offset) whose tool_result is not yet in
    main's transcript. Anything unreadable or unexpected is False (fail closed)."""
    if not isinstance(data, dict):
        return False
    tool_use_id, transcript, offset = data.get("tool_use_id"), data.get("transcript"), data.get("offset")
    if not isinstance(tool_use_id, str) or not TOOL_USE_ID.match(tool_use_id) or not isinstance(transcript, str) \
            or "\x00" in transcript or not isinstance(offset, int) or isinstance(offset, bool) or offset < 0:
        return False
    try:
        if os.path.islink(transcript):
            return False
        fd = os.open(transcript, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    except OSError:
        return False
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size < offset or info.st_size - offset > BOUND_SCAN_BYTES:
            return False
        os.lseek(fd, offset, os.SEEK_SET)
        chunks, left = [], info.st_size - offset
        while left > 0:
            chunk = os.read(fd, min(left, 1 << 20))
            if not chunk:
                break
            chunks.append(chunk)
            left -= len(chunk)
    except OSError:
        return False
    finally:
        os.close(fd)
    ended = re.compile(rb'"tool_use_id"\s*:\s*"' + re.escape(tool_use_id.encode()) + rb'"')
    return not ended.search(b"".join(chunks))


def drop_tool_stamps(tool_use_id, home=None, now=None) -> int:
    """Delete every stamp bound to this tool call (its PostToolUse / PostToolUseFailure / PermissionDenied hook: the
    call is over, so an unconsumed stamp must not outlive it), plus any stamp older than STAMP_TTL_SECONDS. Returns
    how many were removed. Best effort; never raises."""
    if not isinstance(tool_use_id, str) or not TOOL_USE_ID.match(tool_use_id):
        return 0
    removed = 0
    try:
        folder = stamp_dir(home)
        if folder.is_symlink() or not folder.is_dir():
            return 0
        for path in folder.glob("*.json"):
            try:
                if path.is_symlink():
                    continue
                with open(str(path), "rb") as handle:
                    data = json.loads(handle.read(8192).decode("utf-8"))
                stale = (now or time.time()) - float(data.get("ts") or 0) > STAMP_TTL_SECONDS
                if data.get("tool_use_id") == tool_use_id or stale:
                    os.unlink(str(path))
                    removed += 1
            except (OSError, ValueError, TypeError, AttributeError):
                continue
    except OSError:
        pass
    return removed
