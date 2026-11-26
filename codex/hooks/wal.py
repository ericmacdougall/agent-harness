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


def ops_alert_context(event: str, session: str = "") -> str:
    """Ops-watch alerts for the Codex side (parity with harness/hooks/wal.py, goodqa#14613 M9): one summary line at
    SessionStart (ops_watch.session_summary: counts, at most a few about this machine or session, the status command)
    and nothing on a prompt or a sub-agent start (2026-11-24: no per-prompt repetition). ops_watch is looked up next
    to this hook, then in the Claude hooks dir, then in a repo checkout. Never raises."""
    if event != "SessionStart":
        return ""
    try:
        import importlib.util
        here = Path(__file__).resolve().parent
        candidates = [here / "ops_watch.py", Path.home() / ".claude" / "hooks" / "ops_watch.py"]
        checkout = here.parent.parent
        if (checkout / ".git").exists():  # a repo checkout only: installed under ~/.codex this would be ~/harness/hooks
            candidates.append(checkout / "harness" / "hooks" / "ops_watch.py")
        for candidate in candidates:
            if candidate.is_file():
                spec = importlib.util.spec_from_file_location("ops_watch_codex", candidate)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                text = module.session_summary(Path.home(), session)[0]
                return (" " + text) if text else ""
    except Exception:  # an alert line must never block a prompt or a session start
        pass
    return ""


def degraded_note(error: OSError) -> str:
    """The note a hook answers with when its WAL append fails (ENOSPC, EACCES, EROFS): the turn proceeds, the
    operator is told, and recovery commands stay possible. Codex blocks the turn on a non-zero hook exit."""
    import errno
    name = errno.errorcode.get(getattr(error, "errno", 0) or 0, type(error).__name__)
    return (f" WAL append failed ({name}): this turn is not journaled; free space or fix permissions on the WAL "
            "directory (recovery commands only until it works).")


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
MAX_CONTINUATIONS = 4
MAX_ASSISTANT_MESSAGE = 65_536
STATE_FILE = "continuation.json"
INTERRUPT_FILE = "continuation.interrupt"
CONTINUE_REASON = (
    "The session still has active tracked work. Continue with the next authorized "
    "step or reconcile the running check. Only mark completion after verification. "
    "Honor any explicit user stop. If external action is required or a durable "
    "monitor owns the work, record the evidence in the WAL and update the checkpoint."
)
UNFINISHED = "The session has unfinished tracked work. Its continuation allowance has been used or cannot be applied."
UNAVAILABLE = "The continuation checkpoint could not be read or updated. Check its status before claiming completion."


class ContinuationBudgetError(ValueError):
    pass


def state_file(directory: int, name: str, flags: int) -> int:
    fd = os.open(name, flags | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=directory)
    info = os.fstat(fd)
    if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
            or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o600):
        os.close(fd)
        raise ValueError("invalid private continuation file")
    return fd


def read_private(directory: int, name: str, limit: int) -> bytes | None:
    try:
        fd = state_file(directory, name, os.O_RDONLY)
    except FileNotFoundError:
        return None
    with os.fdopen(fd, "rb") as handle:
        data = handle.read(limit + 1)
    if len(data) > limit:
        raise ValueError("oversize continuation file")
    return data


def read_interrupt(directory: int) -> tuple[str | None, str | None]:
    marker = read_private(directory, INTERRUPT_FILE, 97)
    if marker is None:
        return None, None
    match = re.fullmatch(r"([0-9a-f]{32})(?::([0-9a-f]{64}))?", marker.decode("ascii"))
    if match is None:
        raise ValueError("invalid interrupt generation")
    return match[1], match[2]


def checkpoint_fields(pairs: list[tuple[str, object]]) -> dict:
    fields = dict(pairs)
    if len(fields) != len(pairs):
        raise ValueError("duplicate continuation field")
    return fields


def valid_digest(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def read_checkpoint(directory: int) -> dict | None:
    data = read_private(directory, STATE_FILE, 1024)
    if data is None:
        return None
    try:
        state = json.loads(data, object_pairs_hook=checkpoint_fields)
    except RecursionError as error:
        raise ValueError("invalid continuation checkpoint") from error
    if (not isinstance(state, dict) or not {"state", "interrupt"} <= state.keys()
            or not isinstance(state["state"], str) or state["state"] not in WORK_STATES
            or (state["interrupt"] is not None and (
                not isinstance(state["interrupt"], str)
                or not re.fullmatch(r"[0-9a-f]{32}", state["interrupt"])
            ))):
        raise ValueError("invalid continuation checkpoint")
    if set(state) == {"state", "interrupt", "used"} and isinstance(state["used"], bool):
        return state
    if set(state) == {"state", "interrupt", "limit", "claims", "repeat_open"}:
        limit = state["limit"]
        claims = state["claims"]
        repeat_open = state["repeat_open"]
        if (type(limit) is int and 1 <= limit <= MAX_CONTINUATIONS
                and isinstance(claims, list) and len(claims) <= limit
                and all(isinstance(claim, list) and len(claim) == 2 and valid_digest(claim[0])
                        and (claim[1] is None or valid_digest(claim[1])) for claim in claims)
                and len({tuple(claim) for claim in claims}) == len(claims)
                and isinstance(repeat_open, bool)
                and (not repeat_open or (claims and claims[-1][1] is not None))):
            return state
    raise ValueError("invalid continuation checkpoint")


def continuation_budget(state: dict | None) -> tuple[int, int]:
    if state is None:
        return 0, 0
    if "limit" in state:
        return state["limit"], len(state["claims"])
    return 1, int(state["used"])


def output_digest(message: object) -> str | None:
    if not isinstance(message, str) or len(message) > MAX_ASSISTANT_MESSAGE:
        return None
    normalized = message.strip()
    if not normalized:
        return None
    try:
        return hashlib.sha256(normalized.encode("utf-8")).hexdigest()
    except UnicodeEncodeError:
        return None


def spend_continuation(
    state: dict, turn_digest: str, assistant_digest: str | None, repeated_stop: bool,
) -> dict | None:
    limit, spent = continuation_budget(state)
    if spent >= limit:
        return None
    if "limit" not in state:
        return None if repeated_stop else {**state, "used": True}
    claims = state["claims"]
    claim = [turn_digest, assistant_digest]
    if repeated_stop:
        # Codex can invoke several Stop hooks. A repeated Stop only belongs to
        # this checkpoint after our own latest claim for the same native turn.
        if (not state["repeat_open"] or claims[-1][0] != turn_digest
                or assistant_digest is None or claim in claims):
            return None
    elif any(claimed_turn == turn_digest for claimed_turn, _ in claims):
        return None
    return {**state, "claims": [*claims, claim], "repeat_open": assistant_digest is not None}


def replace_private(directory: int, current_directory, name: str, data: bytes) -> None:
    temp = "continuation-" + secrets.token_hex(12)
    fd = state_file(directory, temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        if not current_directory():
            raise ValueError("continuation directory changed")
        os.replace(temp, name, src_dir_fd=directory, dst_dir_fd=directory)
        os.fsync(directory)
    finally:
        try:
            os.unlink(temp, dir_fd=directory)
        except FileNotFoundError:
            pass


def visible_checkpoint(state: dict | None, marker: str | None) -> dict | None:
    if state is not None and state["state"] == "active" and marker != state["interrupt"]:
        return {**state, "state": "paused"}
    return state


def checkpoint(
    session: str,
    action: str,
    *,
    turn_digest: str | None = None,
    assistant_digest: str | None = None,
    repeated_stop: bool = False,
    max_continuations: int | None = None,
) -> tuple[dict | None, bool]:
    with session_directory(session) as (directory, current_directory):
        if not current_directory():
            raise ValueError("continuation directory changed")
        if action == "interrupt":
            # Independent of the claim lock: an interrupt must not be lost to
            # contention. Bind the latest generation and interrupted turn in
            # one write so resume cannot admit a late first Stop from that turn.
            marker = secrets.token_hex(16)
            if turn_digest is not None:
                marker = f"{marker}:{turn_digest}"
            replace_private(directory, current_directory, INTERRUPT_FILE, marker.encode("ascii"))
            return None, False
        if action in {"claim", "status"}:
            marker, _ = read_interrupt(directory)
            state = visible_checkpoint(read_checkpoint(directory), marker)
            if action == "status" or state is None or state["state"] != "active":
                return state, False
        lock = state_file(directory, "continuation.lock", os.O_RDWR | os.O_CREAT)
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            named = os.stat("continuation.lock", dir_fd=directory, follow_symlinks=False)
            if not os.path.samestat(named, os.fstat(lock)) or not current_directory():
                raise ValueError("continuation lock or directory changed")
            marker, interrupted_turn = read_interrupt(directory)
            state = visible_checkpoint(read_checkpoint(directory), marker)
            if action == "claim":
                if (state is None or state["state"] != "active" or not turn_digest
                        or turn_digest == interrupted_turn):
                    return state, False
                claimed_state = spend_continuation(state, turn_digest, assistant_digest, repeated_stop)
                if claimed_state is None:
                    return state, False
                state = claimed_state
            else:
                state = state if state is not None else {"used": False}
                if max_continuations is not None:
                    if "limit" in state:
                        if state["limit"] != max_continuations:
                            raise ContinuationBudgetError("cannot change the configured continuation budget")
                    elif state["used"]:
                        raise ContinuationBudgetError("cannot change the continuation budget after its first pass")
                    else:
                        state = {"limit": max_continuations, "claims": [], "repeat_open": False}
                if "limit" in state and (action != "active" or state.get("state") != "active"):
                    # Resuming authorized work cannot revive callbacks from a
                    # native turn that was already interrupted or put on hold.
                    state = {**state, "repeat_open": False}
                state = {**state, "state": action, "interrupt": marker}
            replace_private(directory, current_directory, STATE_FILE, json.dumps(state).encode())
            latest_marker, _ = read_interrupt(directory)
            visible = visible_checkpoint(state, latest_marker)
            return visible, action == "claim" and visible["state"] == "active"
        finally:
            os.close(lock)


def lifecycle_hook(data: dict, session: str) -> None:
    interrupt = data["hook_event_name"] == "Interrupt"
    turn_id = data.get("turn_id")
    has_turn = isinstance(turn_id, str) and re.fullmatch(r"[!-~]{1,256}", turn_id)
    repeated_stop = data.get("stop_hook_active")
    may_claim = (not interrupt and has_turn and isinstance(repeated_stop, bool)
                 and data.get("agent_id") is None and data.get("agent_type") is None)
    action = "interrupt" if interrupt else "claim" if may_claim else "status"
    turn_digest = hashlib.sha256(turn_id.encode("ascii")).hexdigest() if has_turn and (interrupt or may_claim) else None
    assistant_digest = output_digest(data.get("last_assistant_message")) if may_claim else None
    try:
        state, claimed = checkpoint(session, action, turn_digest=turn_digest,
                                    assistant_digest=assistant_digest, repeated_stop=repeated_stop is True)
    except (OSError, ValueError):
        result = {"systemMessage": UNAVAILABLE}
    else:
        if claimed:
            result = {"decision": "block", "reason": CONTINUE_REASON}
        elif state is not None and state["state"] == "active":
            result = {"systemMessage": UNFINISHED}
        else:
            result = {}
    if not interrupt and not result.get("decision"):  # P18 (goodqa#14791): the dropped-owner gate, same rule as Claude
        try:
            import dropped_gate  # noqa: PLC0415 - shipped beside this hook by install_codex
            gate = dropped_gate.cmd_stop(dict(data, session_id=session))
        except Exception:  # noqa: BLE001 - never block a Codex turn on a gate error
            gate = {}
        if gate:
            if result.get("systemMessage"):
                if gate.get("decision") == "block":
                    gate["reason"] = result["systemMessage"] + " " + gate.get("reason", "")
                elif gate.get("systemMessage"):
                    gate["systemMessage"] = result["systemMessage"] + " " + gate["systemMessage"]
            result = gate
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
        note = ""
        try:
            append(main_wal, record)
        except OSError as error:
            note = degraded_note(error)
        print(json.dumps({"hookSpecificOutput": {"hookEventName": event, "additionalContext": checkpoint_context(session, f"Session WAL: {main_wal}. Add redacted intent before edits, then decisions, checks, commits and handoffs. Hook metadata is not a semantic work log.") + note + ops_alert_context(event, session)}}))
    elif event == "UserPromptSubmit":
        prompt = str(data.get("prompt", ""))
        record["prompt_chars"] = len(prompt)
        note = ""
        try:
            append(main_wal, record)
        except OSError as error:
            # A full or read-only disk must not block the prompt (the turn would otherwise be refused): degrade
            # to a note so the operator can run the recovery commands.
            note = degraded_note(error)
        print(json.dumps({"hookSpecificOutput": {"hookEventName": event, "additionalContext": checkpoint_context(session, f"Session WAL: {main_wal}. Use the fast path for small changes. For substantive work, scope and coordinate an owner. Record redacted intent before editing.") + note + ops_alert_context(event)}}))
    elif event == "SubagentStart":
        agent_id = safe_id(data.get("agent_id"))
        agent_type = safe_id(data.get("agent_type"))
        agent_wal = root / f"agent-{agent_id}.jsonl"
        record.update({"agent_id": agent_id, "agent_type": agent_type})
        note = ""
        try:
            append(main_wal, record)
            append(agent_wal, record)
        except OSError as error:
            note = degraded_note(error)
        print(json.dumps({"hookSpecificOutput": {"hookEventName": event, "additionalContext": f"Your private WAL: {agent_wal}. Read the main scope brief and decisions in {main_wal}; record redacted intent, tests, commits and handoff." + note + ops_alert_context(event)}}))
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
    continuation.add_argument('--max-continuations', type=int, choices=range(1, MAX_CONTINUATIONS + 1),
                              help='set an explicit per-session budget with active before the first pass')
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
        if args.max_continuations is not None and args.state != 'active':
            parser.error('--max-continuations requires active')
        try:
            state, _ = checkpoint(path.parent.name, args.state, max_continuations=args.max_continuations)
        except ContinuationBudgetError as error:
            parser.error(str(error))
        except (OSError, ValueError):
            parser.error(UNAVAILABLE)
        limit, spent = continuation_budget(state)
        print(json.dumps({'state': state['state'] if state else 'untracked', 'used': spent > 0,
                          'limit': limit, 'remaining': limit - spent}))
    else:
        note(args.wal, args.event, args.note)


if __name__ == "__main__":
    main()
