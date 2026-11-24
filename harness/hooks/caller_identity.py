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
`"tool_use_id":"<id>"` after the recorded offset means the call is over and the stamp is dead. Only the transcript's
own copy records (COPY_RECORDS, goodqa#16811 round 2) are skipped: a data-flow-records line can name a call before its
result. A line naming the call that does not parse also ends it. mission_gate's
PostToolUse / PostToolUseFailure / PermissionDenied hook also deletes the call's stamp (drop_tool_stamps). A stamp
without a tool_use_id, a missing or shrunken transcript, or more than BOUND_SCAN_BYTES of transcript growth is
refused: the main-only path fails closed.

Background calls (goodqa#16811 round 2, main's ruling Q1 = b): a command started with run_in_background gets one
tool_result at once, saying it started in the background, so the plain rule above would see the call as over before
the command's own process takes the stamp. A stamp put with background=True therefore accepts exactly one record
naming the call after the offset, of exactly one shape (BACKGROUND_ACK: a "user" record whose only content block is
the call's tool_result with is_error false, and whose toolUseResult is a mapping with a non-empty string
backgroundTaskId and no interrupted flag). COPY_RECORDS are skipped here too. Any other record naming the call (a hook denial, a rejected permission, a launch error, an is_error result, a second
record) ends it, and so does a line naming the call that does not parse. mission_gate's PostToolUse hook, which runs
at once for a background launch, leaves a background stamp alone; PostToolUseFailure and PermissionDenied still
delete it. Limits, stated rather than controlled: a background stamp cannot see the command's process end, so until
it is taken or expires (the taker's ttl) another process with the same purpose and key can take it; and neither kind
of stamp can tell main's process from another one that starts while main's call is still running or waiting at a
permission prompt.
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
COPY_RECORDS = frozenset(("api-request-blob", "data-flow-records"))  # Claude Code's copies of a message already logged


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


def put_stamp(purpose: str, parts, session: str = "", home=None, now=None, tool_use_id=None, transcript=None,
              background: bool = False, require_bound: bool = False) -> bool:
    """Record a one-shot stamp and return whether it is bound. With tool_use_id and transcript (main's proven
    transcript path) the stamp is bound to that one tool call: see take_stamp(bound=True). background=True (only
    for a bound stamp) marks a call started with run_in_background (module doc). require_bound=True writes nothing
    when the stamp cannot be bound, so no stamp that a bound take would refuse is left behind."""
    record = {"purpose": purpose, "session": str(session)[:80], "ts": now or time.time()}
    if isinstance(transcript, os.PathLike):
        transcript = os.fspath(transcript)
    if isinstance(tool_use_id, str) and TOOL_USE_ID.match(tool_use_id) and isinstance(transcript, str) \
            and transcript and "\x00" not in transcript and len(transcript) <= 4096:
        try:
            size = os.stat(transcript).st_size
        except (OSError, ValueError):
            size = None
        if size is not None:
            record.update(tool_use_id=tool_use_id, transcript=transcript, offset=size)
            if background is True:
                record["background"] = True
    bound = "tool_use_id" in record
    if require_bound and not bound:
        return False
    folder = stamp_dir(home)
    folder.mkdir(parents=True, exist_ok=True, mode=0o700)
    key = stamp_key(purpose, parts)
    tmp = folder / ("%s.%s.tmp" % (key, uuid.uuid4().hex[:8]))
    tmp.write_text(json.dumps(record), encoding="utf-8")
    os.chmod(str(tmp), 0o600)
    os.replace(str(tmp), str(folder / (key + ".json")))
    return bound


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
    main's transcript; for a background stamp, whose only record so far is the BACKGROUND_ACK (module doc).
    Anything unreadable or unexpected is False (fail closed)."""
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
    grown = b"".join(chunks)
    if not ended.search(grown):
        return True
    return _records_say_running(grown, ended, tool_use_id, data.get("background") is True)


def _records_say_running(grown: bytes, ended, tool_use_id: str, background: bool) -> bool:
    """Whether the records naming the call after the offset leave it running. COPY_RECORDS are skipped (Claude Code
    writes a data-flow-records line naming a call before the call's own result: 3 of 5255 real foreground calls).
    A foreground call is over at any other record naming it; a background call is running while that is exactly one
    BACKGROUND_ACK. A line naming the call that is not a whole JSON object ends it."""
    acks = 0
    for line in grown.split(b"\n"):
        if not ended.search(line):
            continue
        try:
            record = json.loads(line.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            return False
        if not isinstance(record, dict):
            return False
        if record.get("type") in COPY_RECORDS:
            continue
        if not background:
            return False
        acks += 1
        if acks > 1 or not _is_background_ack(record, tool_use_id):
            return False
    return True


def _is_background_ack(record: dict, tool_use_id: str) -> bool:
    """BACKGROUND_ACK: Claude Code's "started in the background" result for this call, and nothing else."""
    message = record.get("message")
    content = message.get("content") if isinstance(message, dict) else None
    if record.get("type") != "user" or not isinstance(content, list) or len(content) != 1:
        return False
    block, result = content[0], record.get("toolUseResult")
    if not isinstance(block, dict) or block.get("type") != "tool_result" or block.get("tool_use_id") != tool_use_id \
            or block.get("is_error") is not False:
        return False
    if not isinstance(result, dict) or result.get("interrupted") is True:
        return False
    task = result.get("backgroundTaskId")
    return isinstance(task, str) and bool(task.strip())


def drop_tool_stamps(tool_use_id, home=None, now=None, event=None) -> int:
    """Delete every stamp bound to this tool call (its PostToolUse / PostToolUseFailure / PermissionDenied hook: the
    call is over, so an unconsumed stamp must not outlive it), plus any stamp older than STAMP_TTL_SECONDS. On
    event "PostToolUse" a background stamp of the call is kept: that event fires as soon as a background command
    has started, before its process takes the stamp. Returns how many were removed. Best effort; never raises."""
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
                started = event == "PostToolUse" and data.get("background") is True
                if (data.get("tool_use_id") == tool_use_id and not started) or stale:
                    os.unlink(str(path))
                    removed += 1
            except (OSError, ValueError, TypeError, AttributeError):
                continue
    except OSError:
        pass
    return removed
