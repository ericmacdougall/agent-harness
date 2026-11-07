#!/usr/bin/env python3
"""Stop/SubagentStop hook: nudge a human-readable WAL entry when real work has piled up without one
(rule W04, goodqa#14908; ported from Hawkeye's hawkeye-wal-cadence.py).

Why: on 2026-09-12 a session interrupted mid-turn had landed 9 proven fixes across 2 files with zero
journal entries. The commit-time WAL gate never fired, because nothing had been committed. The
harness records hook metadata for every tool call, but metadata does not say what was verified,
and HARNESS.md asks for a human-readable entry after each milestone. This hook checks for that
entry at each turn end, whichever tool produced the diff.

What it checks. The agent's work counts when it is a git worktree with at least MIN_CHANGED_LINES
uncommitted SOURCE lines, tracked or untracked, outside docs/, plans/ and similar journal paths.
At Stop that worktree is the cwd, and only when the cwd is a linked worktree (the primary checkout
is the user's). For a subagent it is only a worktree under its own work folder
~/.agent-harness/work/<session>/agent-<id>/, never its cwd. If that agent's WAL (main.jsonl, or
agent-<id>.jsonl) has no human entry (a wal_note.py row with a note) in the last WAL_STALE_S
seconds, the hook blocks once with exit 2 and tells the agent what to record.

Bounded like Hawkeye's original:
- at most one nudge per agent per distinct diff fingerprint;
- never on a repeated stop (stop_hook_active);
- HARNESS_WAL_CADENCE=off disables it;
- every internal error fails open, because a broken nudge must never wedge a session.
Register it without onFailure.

Hawkeye's knowledge-net replication (kn ingest) is not ported; it belongs to Hawkeye's knowledge tool.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

WAL_STALE_S = 20 * 60
MIN_CHANGED_LINES = 40
JOURNAL_PREFIXES = ("plans/", "devstate/", "audit/", "docs/")
JOURNAL_EXACT = ("README.md", "CONTRIBUTING.md")
HUMAN_EVENTS = {"intent", "scope", "decision", "risk", "check", "commit", "blocker", "status", "handoff", "result",
                "requirement", "ask", "ask_resolved"}
WAL_TAIL_BYTES = 2 * 1024 * 1024
MAX_AGENT_WORKTREES = 12
MAX_ASKED = 400
STATE_MAX_BYTES = 256 * 1024
GIT_TIMEOUT = 8
SAFE_ID = re.compile(r"^[A-Za-z0-9._-]{1,120}$")


def home() -> Path:
    return Path(os.environ.get("AH_HOME") or Path.home())


def safe_id(value) -> str:
    try:
        import wal  # the WAL writer's own naming, so the two never disagree
        return wal.safe_id(value)
    except Exception:  # noqa: BLE001
        text = str(value or "unknown")
        return text if SAFE_ID.match(text) else re.sub(r"[^A-Za-z0-9._-]", "_", text)[:120]


def git(cwd, *args):
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env["GIT_OPTIONAL_LOCKS"] = "0"  # a read-only check must not take the index lock
    r = subprocess.run(("git", "-c", "core.fsmonitor=false", "-C", str(cwd)) + args, capture_output=True, text=True,
                       timeout=GIT_TIMEOUT, env=env, stdin=subprocess.DEVNULL)
    return r.returncode, r.stdout


def is_source(path: str) -> bool:
    if path in JOURNAL_EXACT or path.startswith(JOURNAL_PREFIXES):
        return False
    return not ("/verification/" in path or path.startswith("verification/"))


def is_linked_worktree(cwd) -> bool:
    rc, common = git(cwd, "rev-parse", "--path-format=absolute", "--git-common-dir")
    rc2, gitdir = git(cwd, "rev-parse", "--path-format=absolute", "--git-dir")
    return rc == 0 and rc2 == 0 and os.path.realpath(common.strip()) != os.path.realpath(gitdir.strip())


def pending_source_diff(cwd):
    """(fingerprint, files, changed_lines) of uncommitted source work, or None."""
    rc, top = git(cwd, "rev-parse", "--show-toplevel")
    if rc != 0 or not top.strip():
        return None
    top = top.strip()
    rc, names = git(top, "diff", "HEAD", "--name-only")
    if rc != 0:
        return None
    tracked = [f for f in names.splitlines() if f.strip() and is_source(f.strip())]
    rc, others = git(top, "ls-files", "--others", "--exclude-standard")
    untracked = [f for f in others.splitlines() if f.strip() and is_source(f.strip())] if rc == 0 else []
    files = sorted(set(tracked + untracked))
    if not files:
        return None
    rc, diff = git(top, "diff", "HEAD", "--", *tracked) if tracked else (0, "")
    changed = sum(1 for ln in diff.splitlines() if ln[:1] in "+-" and not ln.startswith(("+++", "---")))
    h = hashlib.sha256(top.encode())
    h.update(diff.encode("utf-8", "replace"))
    for f in files:
        h.update(f.encode("utf-8", "replace"))
        if f in untracked:
            data = _read_prefix(os.path.join(top, f), 2 << 20)
            if data is None:
                continue
            h.update(data)
            changed += data.count(b"\n")
    return h.hexdigest()[:32], files, changed, top


def agent_worktrees(session: str, agent: str) -> list:
    """Git worktrees directly under this agent's work folder (the harness convention for owner worktrees)."""
    base = home() / ".agent-harness" / "work" / safe_id(session) / ("agent-" + safe_id(agent))
    found = []
    try:
        entries = sorted(os.scandir(base), key=lambda e: e.name)
    except OSError:
        return found
    for entry in entries:
        if len(found) >= MAX_AGENT_WORKTREES:
            break
        try:
            if entry.is_dir(follow_symlinks=False) and os.path.exists(os.path.join(entry.path, ".git")):
                found.append(entry.path)
        except OSError:
            continue
    return found


def wal_path(session: str, agent: str) -> Path:
    root = home() / ".claude" / "wals" / safe_id(session)
    return root / ("agent-%s.jsonl" % safe_id(agent) if agent else "main.jsonl")


def last_human_entry_age(path: Path, now: float):
    """Seconds since the newest human-readable entry, or None when there is none in the readable tail."""
    import safe_input  # noqa: PLC0415
    if not os.path.lexists(path):
        return None
    try:
        tail = safe_input.read_tail(path, WAL_TAIL_BYTES)
    except safe_input.InputRejected:
        return None
    newest = None
    for line in tail.splitlines():
        try:
            row = json.loads(line)
        except (ValueError, UnicodeDecodeError, RecursionError):
            continue
        if not isinstance(row, dict) or row.get("event") not in HUMAN_EVENTS or not isinstance(row.get("note"), str):
            continue
        stamp = row.get("at")
        try:
            from datetime import datetime  # noqa: PLC0415
            ts = datetime.fromisoformat(str(stamp).replace("Z", "+00:00")).timestamp()
        except (TypeError, ValueError):
            continue
        newest = ts if newest is None or ts > newest else newest
    return None if newest is None else max(0.0, now - newest)


def state_file(session: str) -> Path:
    return home() / ".agent-harness" / "state" / "wal-cadence" / ("%s.json" % safe_id(session))


def _read_prefix(path, limit: int):
    """Up to `limit` bytes of a regular file (never a FIFO, device or a symlink to one), or None."""
    import safe_input  # noqa: PLC0415
    try:
        fd = safe_input.open_regular_file(path)
    except safe_input.InputRejected:
        return None
    try:
        return os.read(fd, limit)
    except OSError:
        return None
    finally:
        os.close(fd)


def _load_state(session: str) -> dict:
    import safe_input  # noqa: PLC0415
    path = state_file(session)
    if not os.path.lexists(path):
        return {}
    try:
        data = safe_input.safe_json_loads(safe_input.read_bounded(path, STATE_MAX_BYTES).decode("utf-8", "replace"))
    except (ValueError, safe_input.InputRejected):
        return {}
    return data if isinstance(data, dict) else {}


def already_asked(session: str, key: str) -> bool:
    return key in (_load_state(session).get("asked") or {})


def remember(session: str, key: str, now: float) -> None:
    path = state_file(session)
    try:
        data = _load_state(session)
        asked = data.get("asked") if isinstance(data.get("asked"), dict) else {}
        asked[key] = int(now)
        if len(asked) > MAX_ASKED:
            asked = dict(sorted(asked.items(), key=lambda kv: kv[1])[-MAX_ASKED:])
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(path.name + ".%d.tmp" % os.getpid())
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            json.dump({"asked": asked}, fh)
        os.replace(tmp, path)
    except OSError:
        pass


def message(found, wal: Path, age) -> str:
    fp, files, changed, top = found
    shown = "\n    ".join(files[:10]) + ("" if len(files) <= 10 else "\n    ... and %d more" % (len(files) - 10))
    when = ("there is no human-readable entry in your WAL" if age is None
            else "your last human-readable WAL entry is %d minutes old" % int(age // 60))
    return ("NO DURABLE RECORD OF THIS WORK YET (rule W04): %d file(s), about %d changed lines uncommitted in %s, "
            "and %s.\n    %s\n\nHook metadata is not a record of what was verified. Before stopping, append what you "
            "have actually done and checked (files, branch, the check command and its real result, next step):\n"
            "  python3 ~/.claude/hooks/wal_note.py --wal %s --event status --note '<files, branch, check and result, "
            "next step>'\nThis asks once per distinct diff; stopping again on the same work is not blocked, and any "
            "WAL note clears it. HARNESS_WAL_CADENCE=off disables it."
            % (len(files), changed, top, when, shown, wal))


def evaluate(ev, now=None):
    """None, or (key, message, session) for the one nudge this stop earns."""
    now = time.time() if now is None else now
    if not isinstance(ev, dict) or os.environ.get("HARNESS_WAL_CADENCE", "").lower() == "off":
        return None
    event = ev.get("hook_event_name")
    if event not in ("Stop", "SubagentStop") or ev.get("stop_hook_active"):
        return None
    session = str(ev.get("session_id") or "")
    if not session:
        return None
    agent = str(ev.get("agent_id") or "") if event == "SubagentStop" else ""
    if event == "SubagentStop" and not agent:
        return None
    cwd = ev.get("cwd") or os.getcwd()
    candidates = []
    if event == "SubagentStop":
        # only trees under this agent's own work folder: a subagent's cwd is often main's checkout or
        # another owner's tree, and blocking it there would be for work it does not own (goodqa#14908 F5)
        candidates = agent_worktrees(session, agent)
    elif is_linked_worktree(cwd):
        candidates = [cwd]
    seen = set()
    for cand in candidates:
        found = pending_source_diff(cand)
        if not found or found[3] in seen:
            continue
        seen.add(found[3])
        if found[2] < MIN_CHANGED_LINES:
            continue
        wal = wal_path(session, agent)
        age = last_human_entry_age(wal, now)
        if age is not None and age < WAL_STALE_S:
            return None
        key = "%s:%s" % (agent or "main", found[0])
        if already_asked(session, key):
            continue
        return key, message(found, wal, age), session
    return None


def main() -> int:
    try:
        import safe_input  # noqa: PLC0415
        ev = safe_input.safe_json_loads(safe_input.read_stdin_bounded().decode("utf-8", "replace") or "{}")
        result = evaluate(ev)
        if not result:
            return 0
        key, text, session = result
        remember(session, key, time.time())
    except Exception:  # noqa: BLE001 - a broken nudge must never wedge a session
        return 0
    sys.stderr.write(text + "\n")
    return 2


if __name__ == "__main__":
    sys.exit(main())
