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


def work_dir_context(session_id: str, event: str, data: dict) -> str:
    """Announce the durable per-session work directory (once per session start, compaction or agent); never fail
    the WAL hook over it."""
    try:
        import workdir
        path = workdir.ensure_session_dir(session_id)
    except Exception as exc:  # the WAL is the fail-closed record, not the work dir
        return (f" Durable work dir unavailable ({exc.__class__.__name__}); keep scripts and job state in a "
                "private directory under ~/.agent-harness/work, not /tmp.")
    if event == "subagent":
        return f" Work files: {path}/agent-{safe_id(data.get('agent_id'))}/."
    return f" Durable work dir: {path}/; /tmp and the session scratchpad are for disposable output only."


def session_extras(session_id: str, data: dict) -> str:
    """Startup-only warnings (scratchpad drift, retention) and the detached daily prune; '' when none. Never raises."""
    try:
        import workdir
        text = workdir.scratchpad_drift_warning(data.get("scratchpad_dir"))
        if data.get("source") == "startup":
            text += workdir.retention_hint(session_id)
        workdir.spawn_task_output_prune(session_id=session_id)  # detached, at most daily
        return text
    except Exception:
        return ""


# ---- context budget ---------------------------------------------------------------------------------------------
# What the hooks add to a session's context is budgeted here (the owner's review, 2026-11-24: the WAL path, a triage
# reminder and 120-plus ops alerts arrived on every prompt, sometimes four times in one turn). One small state file
# per session, ~/.agent-harness/state/context/<session>.json, records what the session was already told:
#   emit    {name: {"at", "fp"}}  the last emission of each hook registration, so a second registration of the same
#                                  script firing for the same prompt or start (within DUP_WINDOW_S) stays silent
#   seen    {alert id: at}        ops alerts this session was shown or counted, so each id reaches it at most once
#   rate    {key: at}             rate limits ("at most once per 30 min") for other hooks
#   sig     {key: signature}      the last state a hook reported, so a hook can speak only on a change
#   announced                     when the WAL path and work dir were last given (SessionStart, or a first prompt)
# The file is advisory: unreadable or locked state never blocks anything (it only costs a repeated line), writes
# are atomic (temp file + rename, 0600), and files untouched for CONTEXT_KEEP_S are pruned at most once a day.

CONTEXT_CAP = 600
CONTEXT_KEEP_S = 7 * 86400
DUP_WINDOW_S = 20
SEEN_MAX = 4000
LOCK_WAIT_S = 1.0


def context_dir(home=None) -> Path:
    return Path(home or Path.home()) / ".agent-harness" / "state" / "context"


def is_subagent(data) -> bool:
    """A sub-agent's hook payload names its agent. agent_type alone is not enough: a main session started with
    --agent carries it too."""
    return isinstance(data, dict) and bool(data.get("agent_id"))


def cap_text(parts, limit: int = CONTEXT_CAP) -> str:
    """Join parts in priority order, dropping whole lower-priority parts that do not fit; the first part is cut
    to the limit if it alone is too long."""
    out = ""
    for part in parts:
        if not part:
            continue
        if len(out) + len(part) <= limit:
            out += part
        elif not out:
            out = part[:limit - 3] + "..."
    return out


class ContextState:
    """`with ContextState(session) as state:` load, lock, then save on exit. `state` is a dict; `ok` says whether
    the lock was taken and the file can be trusted. Never raises."""

    def __init__(self, session, home=None):
        self.session, self.home, self.lock, self.ok, self.state = str(session or ""), home, None, False, {}

    def _path(self) -> Path:
        return context_dir(self.home) / (safe_id(self.session) + ".json")

    def __enter__(self) -> dict:
        try:
            directory = context_dir(self.home)
            directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            fd = os.open(directory / (safe_id(self.session) + ".lock"), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
            deadline = time.monotonic() + LOCK_WAIT_S
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except OSError:
                    if time.monotonic() > deadline:
                        os.close(fd)
                        return self.state
                    time.sleep(0.02)
            self.lock = fd
            self.ok = True
            self.state = self._load()
        except Exception:  # noqa: BLE001 - advisory state: no lock means no dedupe, never a failed hook
            self.ok = False
        return self.state

    def _load(self) -> dict:
        try:
            fd = os.open(self._path(), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except OSError:
            return {}
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                return {}
            data = json.loads(os.read(fd, 1 << 20).decode("utf-8", "replace"))
        except (OSError, ValueError):
            return {}
        finally:
            os.close(fd)
        return data if isinstance(data, dict) else {}

    def __exit__(self, *exc):
        try:
            if self.ok:
                self.state["updated"] = time.time()
                seen = self.state.get("seen")
                if isinstance(seen, dict) and len(seen) > SEEN_MAX:
                    self.state["seen"] = dict(sorted(seen.items(), key=lambda kv: kv[1] if isinstance(kv[1], (int, float)) else 0)[-SEEN_MAX:])
                directory = context_dir(self.home)
                tmp = directory / f".{safe_id(self.session)}.{os.getpid()}.{time.monotonic_ns()}.tmp"
                fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                try:
                    with os.fdopen(fd, "w", encoding="utf-8") as handle:
                        json.dump(self.state, handle, separators=(",", ":"), default=str)
                    os.replace(tmp, self._path())
                except Exception:
                    try:
                        os.unlink(tmp)
                    except OSError:
                        pass
                    raise
                prune_context(self.home)
        except Exception:  # noqa: BLE001
            pass
        finally:
            if self.lock is not None:
                try:
                    os.close(self.lock)
                except OSError:
                    pass
        return False


def prune_context(home=None, now=None) -> int:
    """Remove context state (and lock) files untouched for CONTEXT_KEEP_S; runs at most once a day. Never raises."""
    now = time.time() if now is None else now
    directory = context_dir(home)
    marker = directory / ".pruned"
    try:
        if marker.exists() and now - marker.stat().st_mtime < 86400:
            return 0
        marker.touch(mode=0o600)
        os.utime(marker, (now, now))
        removed = 0
        for entry in os.scandir(directory):
            if entry.name.startswith(".") or not entry.name.endswith((".json", ".lock")):
                continue
            if entry.is_file(follow_symlinks=False) and now - entry.stat(follow_symlinks=False).st_mtime > CONTEXT_KEEP_S:
                try:
                    os.unlink(entry.path)
                    removed += 1
                except OSError:
                    pass
        return removed
    except OSError:
        return 0


def payload_fingerprint(data) -> str:
    """Two registrations of one hook receive the identical payload; a new prompt or start never does."""
    try:
        blob = json.dumps(data, sort_keys=True, ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        blob = repr(data)
    return hashlib.sha256(blob.encode("utf-8", "replace")).hexdigest()[:20]


def claim_emission(state: dict, name: str, fingerprint: str, now=None, window: float = DUP_WINDOW_S) -> bool:
    """True when this registration may speak: no registration of `name` spoke for the same fingerprint (the same
    prompt or start) within `window` seconds. Records the emission."""
    now = time.time() if now is None else now
    emits = state.setdefault("emit", {})
    if not isinstance(emits, dict):
        emits = state["emit"] = {}
    last = emits.get(name)
    if isinstance(last, dict) and last.get("fp") == fingerprint and isinstance(last.get("at"), (int, float)) \
            and 0 <= now - last["at"] < window:
        return False
    emits[name] = {"at": now, "fp": fingerprint}
    return True


def rate_ok(state: dict, key: str, every_s: float, now=None) -> bool:
    """True (and recorded) at most once per `every_s` for `key`."""
    now = time.time() if now is None else now
    rates = state.setdefault("rate", {})
    if not isinstance(rates, dict):
        rates = state["rate"] = {}
    last = rates.get(key)
    if isinstance(last, (int, float)) and 0 <= now - last < every_s:
        return False
    rates[key] = now
    return True


def changed(state: dict, key: str, signature: str) -> bool:
    """True (and recorded) when `signature` differs from the last one recorded for `key`."""
    sigs = state.setdefault("sig", {})
    if not isinstance(sigs, dict):
        sigs = state["sig"] = {}
    if sigs.get(key) == signature:
        return False
    sigs[key] = signature
    return True


def budget_once(session, name: str, fingerprint: str = "", *, every_s: float = 0, signature: str | None = None,
                home=None) -> bool:
    """One call for the other hooks: may `name` speak now? Silent repeats of the same registration within the
    duplicate window, and (when given) more than once per `every_s`, or the same `signature` as last time, all
    answer False. No session id, or state that cannot be locked, answers True (a repeated line beats a lost one)."""
    if not session:
        return True
    with ContextState(session, home) as state:
        if not isinstance(state, dict):
            return True
        now = time.time()
        if fingerprint and not claim_emission(state, name, fingerprint, now):
            return False
        if signature is not None and not changed(state, name, signature):
            return False
        if every_s and not rate_ok(state, name, every_s, now):
            return False
        return True


def ops_session_line(state: dict, session: str, room: int = CONTEXT_CAP) -> str:
    """The SessionStart ops line (counts, at most three alerts about this machine or this session, the status
    command) in at most `room` characters; every active alert id is recorded as seen. Never raises."""
    try:
        import ops_watch
        text, ids = ops_watch.session_summary(Path.home(), session, limit=room)
        seen = state.setdefault("seen", {})
        now = time.time()
        for alert_id in ids:
            seen.setdefault(alert_id, now)
        return text
    except Exception:  # the prompt hook blocks on failure; a missing alert line must never block a prompt
        return ""


def ops_prompt_line(state: dict, session: str) -> str:
    """Per prompt: only critical alerts this session can act on that it has not seen; '' otherwise. Never raises."""
    try:
        import ops_watch
        seen = state.setdefault("seen", {})
        text, ids = ops_watch.new_alerts_text(Path.home(), session, set(seen))
        now = time.time()
        for alert_id in ids:
            seen.setdefault(alert_id, now)
        return text
    except Exception:
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
        # Every SessionStart (startup, resume, clear, compact) gives the WAL path and work dir once: a compaction drops
        # them from context. A second registration of this hook for the same start stays silent.
        record["source"] = data.get("source", "")
        append(main_wal, record)
        with ContextState(session_id) as state:
            if not claim_emission(state, "wal:session", payload_fingerprint(data)):
                return
            state["announced"] = time.time()
            base = cap_text([f"Session WAL: {main_wal}.", work_dir_context(session_id, event, data)])
            extras = session_extras(session_id, data)
            ops = ops_session_line(state, session_id, CONTEXT_CAP - len(base) - len(extras) - 1)
            text = cap_text([base, (" " + ops).rstrip(), extras])
        print(json.dumps({"hookSpecificOutput": {"hookEventName": "SessionStart", "additionalContext": text}}))
    elif event == "prompt":
        # Per prompt: nothing, unless this session was never told its WAL (no SessionStart reached it), or a critical
        # alert it can act on is new. The triage reminder lives in the instructions, not here.
        prompt = str(data.get("prompt", ""))
        record["prompt_chars"] = len(prompt)
        append(main_wal, record)
        if is_subagent(data):
            return
        with ContextState(session_id) as state:
            if not claim_emission(state, "wal:prompt", payload_fingerprint(data)):
                return
            if not state.get("announced"):
                state["announced"] = time.time()
                base = cap_text([f"Session WAL: {main_wal}.", work_dir_context(session_id, "session-late", data)])
                text = cap_text([base, (" " + ops_session_line(state, session_id, CONTEXT_CAP - len(base) - 1)).rstrip()])
            else:
                text = cap_text([ops_prompt_line(state, session_id)])
        if text:
            print(json.dumps({"hookSpecificOutput": {"hookEventName": "UserPromptSubmit", "additionalContext": text}}))
    elif event == "subagent":
        # A sub-agent gets its WAL path once (and an owner type one line of brief); never ops alerts or reminders.
        agent_id = safe_id(data.get("agent_id"))
        agent_type = safe_id(data.get("agent_type"))
        agent_wal = root / f"agent-{agent_id}.jsonl"
        record.update({"agent_id": agent_id, "agent_type": agent_type})
        append(main_wal, record)
        append(agent_wal, record)
        with ContextState(session_id) as state:
            if not claim_emission(state, "wal:subagent:" + agent_id, "start", window=3600):
                return
        if agent_type in OWNER_AGENT_TYPES:
            context = (f"Your private WAL: {agent_wal}. Read the main scope brief in {main_wal}; record intent before "
                       "editing, then decisions, tests, commits, blockers and handoff. No secrets or PII.")
        else:
            context = f"Your private WAL: {agent_wal}. Record results and blockers there; no secrets or PII."
        text = cap_text([context, work_dir_context(session_id, event, data)])
        print(json.dumps({"hookSpecificOutput": {"hookEventName": "SubagentStart", "additionalContext": text}}))
    elif event == "subagent_stop":
        # SubagentStop: lets spec_flow.py record when a click-test agent finished. Only ids that
        # SubagentStart logged are recorded, so spurious stops (empty agent_type) leave no trace.
        agent_id = safe_id(data.get("agent_id"))
        agent_wal = root / f"agent-{agent_id}.jsonl"
        if data.get("agent_id") and agent_wal.exists():
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
