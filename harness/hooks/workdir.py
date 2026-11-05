#!/usr/bin/env python3
"""Durable per-session work directories, a /tmp advisory, and retention pruning.

Claude Code's scratchpad and /tmp are wiped by a reboot. Anything an agent
needs after a restart (scripts, run kits, review packets, TSVs, filters, job
state) belongs in ~/.agent-harness/work/<session-id>/ instead.

    python3 workdir.py prune            # dry run: list what retention would remove
    python3 workdir.py prune --apply    # remove eligible directories

Pruning only removes directories this module created (marker file present) and
Claude Code session directories inside the durable scratch root. It never
touches WALs, transcripts or logs under ~/.claude or ~/.codex.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import shutil
import stat
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

MARKER = ".agent-harness-session.json"
KEEP = ".keep"
DONE = ".done"
DONE_NOTE = "WORKDIR_DONE"
ADVISORY_SHOWN = ".advisory-shown"
TASK_OUTPUT = "tasks"  # Claude Code background-task output: kept unless explicitly included
STAMP = ".retention-checked"
DAY = 86400
DEFAULT_DONE_DAYS = 14
DEFAULT_IDLE_DAYS = 45
DEFAULT_SCRATCH_DAYS = 7
DEFAULT_TASK_OUTPUT_DAYS = 14
TASK_STAMP = ".task-output-pruned"
TASK_OUTPUT_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*\.output")  # plain names only: no newlines or path tricks
TASK_REPORT = ".task-output-prune.json"
SESSION_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
SCRATCHPAD_PATTERN = re.compile(r"/claude-\d+/[^/]+/[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}/scratchpad(?:/|$)")
DURABLE_SUFFIXES = {".py", ".sh", ".bash", ".zsh", ".js", ".mjs", ".cjs", ".ts", ".rb", ".pl",
                    ".json", ".jsonl", ".yaml", ".yml", ".toml", ".tsv", ".csv", ".md", ".txt",
                    ".conf", ".filter"}
KIT_OR_PACKET = re.compile(r"(?:^|[-_.])(?:run-?)?(?:kit|packet)s?(?:[-_.]|$)")
MAX_ADVISORY_INPUT = 65536  # larger inputs skip the advisory so the fail-closed hook stays fast
MAX_ADVISORY_CANDIDATES = 32
ADVISORY_SECONDS = 0.5
SCRIPT_SUFFIXES = {".py", ".sh", ".bash", ".zsh", ".js", ".mjs", ".cjs", ".ts", ".rb", ".pl"}
WALK_BUDGET = 20000
WRITE_TOOLS = {"Write", "Edit", "MultiEdit", "NotebookEdit"}
COPY_COMMANDS = {"cp", "mv", "install", "rsync", "ln"}


def home() -> Path:
    return Path.home()


def work_root() -> Path:
    return home() / ".agent-harness" / "work"


def scratch_root() -> Path:
    """The durable CLAUDE_CODE_TMPDIR value the installer configures."""
    return home() / ".agent-harness" / "scratch"


def safe_name(session_id: str) -> str:
    from wal import safe_id  # same escaping as the session WAL directory
    return safe_id(session_id)


def _open_dir(name: str, parent_fd: int | None, create: bool) -> int:
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    if create:
        try:
            if parent_fd is None:
                os.mkdir(name, 0o700)
            else:
                os.mkdir(name, 0o700, dir_fd=parent_fd)
        except FileExistsError:
            pass
    return os.open(name, flags) if parent_fd is None else os.open(name, flags, dir_fd=parent_fd)


def ensure_session_dir(session_id: str) -> Path:
    """Create ~/.agent-harness/work/<id>/ (0700) without following symlinks; return its path."""
    name = safe_name(session_id)
    target = work_root() / name
    fds = []
    try:
        fds.append(_open_dir(str(home()), None, False))
        for part, chmod in ((".agent-harness", False), ("work", True), (name, True)):
            fds.append(_open_dir(part, fds[-1], True))
            if chmod:
                os.fchmod(fds[-1], 0o700)
        directory = fds[-1]
        try:
            fd = os.open(MARKER, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600,
                         dir_fd=directory)
        except FileExistsError:
            info = os.stat(MARKER, dir_fd=directory, follow_symlinks=False)
            if not stat.S_ISREG(info.st_mode):
                raise ValueError("work directory marker is not a regular file")
            os.utime(MARKER, dir_fd=directory, follow_symlinks=False)
        else:
            with os.fdopen(fd, "w") as handle:
                json.dump({"schema": 1, "session_id": str(session_id),
                           "created_at": datetime.now(timezone.utc).isoformat()}, handle)
                handle.write("\n")
    finally:
        for fd in reversed(fds):
            os.close(fd)
    return target


def durable_hint(session_id: str | None) -> str:
    if not session_id:
        return str(work_root() / "<session-id>")
    return str(work_root() / safe_name(session_id))


# --------------------------------------------------------------------------- advisory

_PREFIX_CACHE: dict = {}


def _tmp_prefixes(scratchpad_dir: str | None) -> list[str]:
    key = (os.environ.get("TMPDIR"), scratchpad_dir)
    if key not in _PREFIX_CACHE:
        _PREFIX_CACHE.clear()
        _PREFIX_CACHE[key] = _compute_prefixes(scratchpad_dir)
    return _PREFIX_CACHE[key]


def _compute_prefixes(scratchpad_dir: str | None) -> list[str]:
    prefixes = ["/tmp/", "/private/tmp/", "/var/folders/", "/private/var/folders/", "/dev/shm/"]
    for value in (os.environ.get("TMPDIR"), scratchpad_dir):
        if value and os.path.isabs(value):
            prefixes.append(value.rstrip("/") + "/")
            try:
                prefixes.append(os.path.realpath(value).rstrip("/") + "/")
            except OSError:
                pass
    return prefixes


def _expand(token: str) -> str:
    for name in ("TMPDIR", "CLAUDE_CODE_TMPDIR"):
        for form in (f"${{{name}}}", f"${name}"):
            if token.startswith(form):
                base = os.environ.get(name) or ("/tmp" if name == "TMPDIR" else "")
                if base:
                    return base.rstrip("/") + token[len(form):]
    if token.startswith("~/"):
        return str(home()) + token[1:]
    return token


def _under(path: str, root: str) -> bool:
    root = root.rstrip("/")
    return path == root or path.startswith(root + "/")


def location_kind(path: str, scratchpad_dir: str | None = None) -> str | None:
    """'tmp' (wiped on reboot), 'scratch' (disposable, pruned) or None (not disposable)."""
    path = _expand(path)
    if not os.path.isabs(path):
        return None
    normal = os.path.normpath(path)
    if _under(normal, str(work_root())):
        return None
    tmp = [prefix for prefix in _tmp_prefixes(None)]
    in_tmp = any(_under(normal, prefix) for prefix in tmp)
    if _under(normal, str(scratch_root())):
        return "scratch"
    if scratchpad_dir and os.path.isabs(scratchpad_dir) and _under(normal, os.path.normpath(scratchpad_dir)):
        return "tmp" if in_tmp else "scratch"
    if in_tmp:
        return "tmp"
    return "scratch" if SCRATCHPAD_PATTERN.search(normal) else None


def is_disposable_location(path: str, scratchpad_dir: str | None = None) -> bool:
    return location_kind(path, scratchpad_dir) is not None


def is_durable_state_name(path: str) -> bool:
    name = os.path.basename(path.rstrip("/")).lower()
    if not name:
        return False
    if KIT_OR_PACKET.search(os.path.splitext(name)[0]):
        return True
    return os.path.splitext(name)[1] in DURABLE_SUFFIXES


def _bash_targets(command: str) -> list[str]:
    """Paths a shell command would create or overwrite, best effort."""
    targets: list[str] = []
    try:
        lexer = shlex.shlex(command, posix=True, punctuation_chars=";&|<>()")
        lexer.whitespace_split = True
        tokens = list(lexer)
    except ValueError:
        # Unbalanced quoting (often a heredoc body): fall back to plain redirection and tee targets.
        found = re.findall(r"(?:^|[^<>])>{1,2}\|?\s*['\"]?([^\s;&|<>'\"]+)", command)
        found += re.findall(r"\btee\s+(?:-a\s+)?['\"]?([^\s;&|<>'\"]+)", command)
        return found
    segment: list[str] = []

    def finish(words: list[str]) -> None:
        words = [w for w in words if w]
        while words and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", words[0]):
            words = words[1:]
        while words and words[0] in {"sudo", "env", "command", "exec", "nohup", "time"}:
            wrapper, words = words[0], words[1:]
            while wrapper == "sudo" and words and words[0].startswith("-"):
                takes_value = words[0] in {"-u", "-g", "-C", "-D", "-h", "-p", "-r", "-t", "-U"}
                words = words[2:] if takes_value else words[1:]
        if not words:
            return
        name = os.path.basename(words[0])
        args = words[1:]
        if name == "tee":
            targets.extend(a for a in args if not a.startswith("-"))
        elif name == "touch":
            targets.extend(a for a in args if not a.startswith("-"))
        elif name in COPY_COMMANDS:
            plain = [a for a in args if not a.startswith("-")]
            directory = next((b for a, b in zip(args, args[1:]) if a in {"-t", "--target-directory"}), None)
            directory = directory or next((a.split("=", 1)[1] for a in args
                                           if a.startswith("--target-directory=")), None)
            if directory:
                targets.extend(os.path.join(directory, os.path.basename(src))
                               for src in plain if src != directory)
            elif len(plain) >= 2:
                destination = plain[-1]
                if is_durable_state_name(destination):
                    targets.append(destination)
                else:
                    targets.extend(os.path.join(destination, os.path.basename(src))
                                   for src in plain[:-1])
        elif name in {"curl", "wget"}:
            for flag, value in zip(args, args[1:]):
                if flag in {"-o", "--output", "-O", "--output-document"}:
                    targets.append(value)
            for arg in args:  # attached forms: -o/tmp/x, --output=/tmp/x
                if re.match(r"-[oO][^-]", arg):
                    targets.append(arg[2:])
                elif arg.startswith(("--output=", "--output-document=")):
                    targets.append(arg.split("=", 1)[1])

    index = 0
    while index < len(tokens):
        token = tokens[index]
        if set(token) <= set(";&|()") and token:
            finish(segment)
            segment = []
        elif token in {">", ">>", ">|", "&>", "&>>"} or re.fullmatch(r"\d?>>?", token or "x"):
            if index + 1 < len(tokens) and not set(tokens[index + 1]) <= set("&|;<>"):
                targets.append(tokens[index + 1])
                index += 1
        elif token in {"<", "<<", "<<<"}:
            index += 1  # input redirection: skip its operand
        else:
            segment.append(token)
        index += 1
    finish(segment)
    return targets


def tmp_advisory(tool_name: str, tool_input: object, scratchpad_dir: str | None = None) -> list[tuple[str, str]]:
    """(path, kind) pairs for durable-state files this call would write in a disposable location."""
    if os.environ.get("AGENT_HARNESS_TMP_ADVISORY") == "0" or not isinstance(tool_input, dict):
        return []
    if tool_name in WRITE_TOOLS:
        raw = tool_input.get("file_path") or tool_input.get("notebook_path") or ""
        candidates = [raw] if isinstance(raw, str) and len(raw) <= MAX_ADVISORY_INPUT else []
    elif tool_name == "Bash":
        command = tool_input.get("command")
        if not isinstance(command, str) or len(command) > MAX_ADVISORY_INPUT:
            return []
        candidates = _bash_targets(command)
    else:
        return []
    found: list[tuple[str, str]] = []
    seen: set[str] = set()
    deadline = time.monotonic() + ADVISORY_SECONDS
    for raw in candidates[:MAX_ADVISORY_CANDIDATES]:
        if time.monotonic() > deadline:
            break
        if not isinstance(raw, str) or not raw or raw in seen or not is_durable_state_name(raw):
            continue
        seen.add(raw)
        kind = location_kind(raw, scratchpad_dir)
        # In the relocated (reboot-surviving) scratchpad, ordinary notes and data are expected;
        # only scripts, kits and packets, which outlive a 7-day prune, get the advisory there.
        if kind == "scratch" and not _script_or_kit(raw):
            continue
        if kind:
            found.append((_expand(raw), kind))
    return found


def _script_or_kit(path: str) -> bool:
    name = os.path.basename(path.rstrip("/")).lower()
    stem, suffix = os.path.splitext(name)
    return suffix in SCRIPT_SUFFIXES or bool(KIT_OR_PACKET.search(stem))


def advisory_message(found: list[tuple[str, str]], session_id: str | None) -> str:
    paths = [path for path, _ in found]
    shown = ", ".join(paths[:3]) + (f" and {len(paths) - 3} more" if len(paths) > 3 else "")
    where = []
    if any(kind == "tmp" for _, kind in found):
        where.append("/tmp or the system temp directory, which a reboot wipes")
    if any(kind == "scratch" for _, kind in found):
        where.append(f"the session scratchpad, which is disposable and pruned after "
                     f"{DEFAULT_SCRATCH_DAYS} idle days")
    return (f"Advisory: {shown} is in {' and '.join(where)}. Scripts, run kits, review packets, TSVs, "
            f"filters and job state needed after a restart belong in the durable work directory "
            f"{durable_hint(session_id)}/. Disposable output may stay where it is. This call was not blocked.")


def first_advisory(session_id: str | None) -> bool:
    """True once per session, so the user-facing systemMessage is not repeated on every call."""
    if not session_id:
        return True
    try:
        directory = ensure_session_dir(session_id)
        fd = os.open(directory / ADVISORY_SHOWN, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        os.close(fd)
        return True
    except FileExistsError:
        return False
    except OSError:
        return True


def scratchpad_drift_warning(scratchpad_dir: object) -> str:
    """Warn when Claude Code still puts the scratchpad in reboot-wiped temp space."""
    if not isinstance(scratchpad_dir, str) or not os.path.isabs(scratchpad_dir):
        return ""
    normal = os.path.normpath(scratchpad_dir)
    if _under(normal, str(scratch_root())):
        return ""
    if any(_under(normal, prefix) for prefix in _tmp_prefixes(None)):
        return (f" Warning: this session's scratchpad {normal} is in reboot-wiped temp space, so the "
                f"CLAUDE_CODE_TMPDIR relocation is not in effect (a session started before install keeps "
                f"its old path). Keep nothing there that must survive a restart.")
    return ""


# --------------------------------------------------------------------------- retention

def _mtime(path: Path) -> float:
    try:
        return os.stat(path, follow_symlinks=False).st_mtime
    except OSError:
        return 0.0


def _transcripts(session_id: str, project: str | None = None) -> list[Path]:
    """Claude Code transcript files for a session: a live session keeps writing its transcript."""
    if not SESSION_UUID.fullmatch(str(session_id)):
        return []
    projects = home() / ".claude" / "projects"
    if project:
        return [projects / project / f"{session_id}.jsonl"]
    try:
        return [Path(e.path) / f"{session_id}.jsonl" for e in os.scandir(projects)
                if e.is_dir(follow_symlinks=False)]
    except OSError:
        return []


def _activity(directory: Path, wal: Path, budget: int | None = None,
              extra: list | None = None) -> tuple[float, int, bool]:
    """(latest mtime, total bytes, complete) over the tree, never following symlinks."""
    budget = WALK_BUDGET if budget is None else budget
    latest = max([_mtime(directory), _mtime(wal), _mtime(wal.parent)] + [_mtime(p) for p in extra or []])
    size, seen, stack = 0, 0, [str(directory)]
    while stack:
        current = stack.pop()
        try:
            with os.scandir(current) as entries:
                for entry in entries:
                    seen += 1
                    if seen > budget:
                        return latest, size, False
                    try:
                        info = entry.stat(follow_symlinks=False)
                    except OSError:
                        continue
                    latest = max(latest, info.st_mtime)
                    if stat.S_ISDIR(info.st_mode):
                        stack.append(entry.path)
                    else:
                        size += info.st_size
        except OSError:
            return latest, size, False
    return latest, size, True


def _marked_done(wal: Path) -> bool:
    """The task is done when its last human WAL entry is a status note starting WORKDIR_DONE."""
    try:
        with open(wal, "rb") as handle:
            handle.seek(0, os.SEEK_END)
            size = handle.tell()
            handle.seek(max(0, size - 262144))
            lines = handle.read().splitlines()
    except OSError:
        return False
    for line in reversed(lines):
        try:
            record = json.loads(line)
            event = record.get("event")
        except (ValueError, AttributeError):
            continue
        if event not in {"session", "prompt", "pretool", "subagent"}:
            return event == "status" and str(record.get("note", "")).startswith(DONE_NOTE)
    return False


def _unpushed_repos(path: Path, max_depth: int = 3, budget_s: float = 20.0) -> list:
    """Git checkouts under `path` with commits on no remote (bounded walk and time; a failed git read counts as
    unpushed, because uncertainty must never delete work: goodqa#14791 G7)."""
    import subprocess  # noqa: PLC0415
    found, deadline = [], time.monotonic() + budget_s
    base_depth = len(Path(path).parts)
    for root, dirs, _files in os.walk(path):
        if len(Path(root).parts) - base_depth >= max_depth:
            dirs[:] = []
        if ".git" in dirs or os.path.isfile(os.path.join(root, ".git")):
            dirs[:] = [d for d in dirs if d != ".git"]
            if time.monotonic() > deadline:
                found.append({"repo": root, "reason": "budget exhausted: treated as unpushed"})
                continue
            try:
                r = subprocess.run(["git", "-C", root, "log", "--branches", "--not", "--remotes", "--oneline", "-1"],
                                   capture_output=True, text=True, timeout=10, env={**os.environ, "GIT_OPTIONAL_LOCKS": "0"})
                if r.returncode != 0 or r.stdout.strip():
                    found.append({"repo": root, "reason": "unpushed commits" if r.returncode == 0 else f"git exit {r.returncode}"})
            except (OSError, subprocess.SubprocessError):
                found.append({"repo": root, "reason": "git unavailable: treated as unpushed"})
    return found


def _protected(path: Path) -> bool:
    real = os.path.realpath(path)
    for root in (home() / ".claude", home() / ".codex", home() / ".agent-harness" / "codex-wals"):
        base = os.path.realpath(root)
        if real == base or real.startswith(base + "/"):
            return True
    return False


def _redirected_to_tmp(path: Path) -> bool:
    """A scratch root that resolves somewhere else under /tmp is system temp, not ours to prune."""
    real = os.path.realpath(path)
    return real != os.path.normpath(path) and any(_under(real, root) for root in ("/tmp", "/private/tmp"))


def _wal_for(session_name: str) -> Path:
    return home() / ".claude" / "wals" / session_name / "main.jsonl"


def candidates(now: float | None = None, *, done_days: float = DEFAULT_DONE_DAYS,
               idle_days: float = DEFAULT_IDLE_DAYS, scratch_days: float = DEFAULT_SCRATCH_DAYS,
               current_session: str | None = None) -> list[dict]:
    now = time.time() if now is None else now
    current = safe_name(current_session) if current_session else None
    found: list[dict] = []
    root = work_root()
    try:
        entries = sorted(os.scandir(root), key=lambda e: e.name)
    except OSError:
        entries = []
    for entry in entries:
        path = Path(entry.path)
        if entry.is_symlink() or not entry.is_dir(follow_symlinks=False) or entry.name == current:
            continue
        marker = path / MARKER
        try:
            info = os.stat(marker, follow_symlinks=False)
        except OSError:
            continue  # not created by this module: never pruned
        if not stat.S_ISREG(info.st_mode) or os.path.lexists(path / KEEP) or _protected(path) or _unpushed_repos(path):
            continue
        try:
            recorded = json.loads(marker.read_text()).get("session_id")
        except (OSError, ValueError, AttributeError):
            continue
        if not isinstance(recorded, str) or safe_name(recorded) != entry.name:
            continue
        wal = _wal_for(entry.name)
        latest, size, complete = _activity(path, wal, extra=_transcripts(recorded))
        idle = (now - latest) / DAY
        done = os.path.lexists(path / DONE) or _marked_done(wal)
        if idle >= max(1.0, min(done_days if done else idle_days, idle_days)):
            found.append({"kind": "work", "path": str(path), "idle_days": round(idle, 1),
                          "bytes": size, "eligible": complete,
                          "reason": ("marked done" if done and idle < idle_days else "idle")
                          if complete else "needs_review: too many entries to assess"})
    scratch = scratch_root()
    uid = os.getuid() if hasattr(os, "getuid") else None
    base = scratch / (f"claude-{uid}" if uid is not None else "claude")
    if (not os.path.islink(scratch) and not os.path.islink(base) and not _protected(base)
            and not _protected(scratch) and not _redirected_to_tmp(base)):
        try:
            projects = sorted(os.scandir(base), key=lambda e: e.name)
        except OSError:
            projects = []
        for project in projects:
            if project.is_symlink() or not project.is_dir(follow_symlinks=False):
                found.append({"kind": "unmanaged", "path": project.path, "eligible": False,
                              "reason": "not a project directory; never pruned"})
                continue
            try:
                sessions = sorted(os.scandir(project.path), key=lambda e: e.name)
            except OSError:
                continue
            for session in sessions:
                if session.name == current:
                    continue
                if (session.is_symlink() or not session.is_dir(follow_symlinks=False)
                        or not SESSION_UUID.fullmatch(session.name)):
                    found.append({"kind": "unmanaged", "path": session.path, "eligible": False,
                                  "reason": "not a session directory; never pruned"})
                    continue
                path = Path(session.path)
                if os.path.lexists(path / KEEP):
                    continue
                latest, size, complete = _activity(path, _wal_for(session.name),
                                                   extra=_transcripts(session.name, project.name))
                idle = (now - latest) / DAY
                if idle >= max(1.0, scratch_days):
                    found.append({"kind": "scratch", "path": str(path), "idle_days": round(idle, 1),
                                  "bytes": size, "eligible": complete,
                                  "reason": "idle" if complete else "needs_review: too many entries to assess"})
    return found


def _same_dir(path: Path, fd: int) -> bool:
    try:
        named, opened = os.stat(path, follow_symlinks=False), os.fstat(fd)
    except OSError:
        return False
    return stat.S_ISDIR(named.st_mode) and (named.st_dev, named.st_ino) == (opened.st_dev, opened.st_ino)


def _remove_session_dir(path: Path, include_task_output: bool) -> list[str]:
    """Remove a scratch session dir through a pinned fd; keep task output unless included."""
    kept = []
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        if not _same_dir(path, fd):
            raise OSError("session directory changed")
        for name in os.listdir(fd):
            if name == TASK_OUTPUT and not include_task_output:
                kept.append(str(path / name))
                continue
            info = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if stat.S_ISDIR(info.st_mode):
                if not _same_dir(path, fd):
                    raise OSError("session directory changed")
                shutil.rmtree(path / name)  # rmtree itself refuses to follow symlinks
            else:
                os.unlink(name, dir_fd=fd)
    finally:
        os.close(fd)
    if not kept:
        os.rmdir(path)
    return kept


def prune(apply: bool, include_task_output: bool = False, **kwargs) -> dict:
    found = candidates(**kwargs)
    removed, partial, errors = [], [], []
    eligible = [item for item in found if item.get("eligible")]
    if apply and eligible:
        if not getattr(shutil.rmtree, "avoids_symlink_attacks", False):
            return {"status": "REFUSED", "reason": "shutil.rmtree is not symlink-safe on this platform",
                    "candidates": found, "removed": [], "errors": []}
        for item in eligible:
            path = Path(item["path"])
            if os.path.islink(path) or _protected(path):
                errors.append({"path": item["path"], "error": "refused: symlink or protected path"})
                continue
            try:
                if item["kind"] == "scratch":
                    kept = _remove_session_dir(path, include_task_output)
                    if kept:
                        item["kept"] = kept
                        partial.append(item["path"])
                        continue
                else:
                    shutil.rmtree(path)
                removed.append(item["path"])
            except OSError as exc:
                errors.append({"path": item["path"], "error": exc.__class__.__name__})
    return {"status": "APPLIED" if apply else "DRY_RUN", "candidates": found,
            "removed": removed, "partially_removed": partial, "errors": errors}


def retention_hint(session_id: str | None, now: float | None = None) -> str:
    """At most once per day, a one-line advisory if anything is past retention. Never deletes."""
    now = time.time() if now is None else now
    stamp = work_root() / STAMP
    try:
        if os.path.islink(stamp) or now - _mtime(stamp) < DAY:
            return ""
        count, complete = _quick_count(now, safe_name(session_id) if session_id else None)
        fd = os.open(stamp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        os.close(fd)
        os.utime(stamp, (now, now))
    except OSError:
        return ""
    if not count and complete:
        return ""
    amount = f"{count}{'' if complete else '+'}"
    return (f" About {amount} durable work or scratch directories may be past retention; review with "
            f"`python3 ~/.claude/hooks/workdir.py prune` (dry run) and remove with `--apply`.")


def _quick_count(now: float, current: str | None, budget: int = 2000, seconds: float = 0.3) -> tuple[int, bool]:
    """Top-level estimate for SessionStart: never walks trees, stops at a fixed budget."""
    deadline, seen, count = time.monotonic() + seconds, 0, 0
    roots = [(work_root(), DEFAULT_IDLE_DAYS, True)]
    uid = os.getuid() if hasattr(os, "getuid") else None
    base = scratch_root() / (f"claude-{uid}" if uid is not None else "claude")
    try:
        projects = [Path(e.path) for e in os.scandir(base) if e.is_dir(follow_symlinks=False)]
    except OSError:
        projects = []
    roots += [(project, DEFAULT_SCRATCH_DAYS, False) for project in projects]
    for root, days, needs_marker in roots:
        try:
            entries = os.scandir(root)
        except OSError:
            continue
        with entries:
            for entry in entries:
                seen += 1
                if seen > budget or time.monotonic() > deadline:
                    return count, False
                if entry.name == current or not entry.is_dir(follow_symlinks=False):
                    continue
                path = Path(entry.path)
                if needs_marker and not os.path.lexists(path / MARKER):
                    continue
                if not needs_marker and not SESSION_UUID.fullmatch(entry.name):
                    continue
                if os.path.lexists(path / KEEP):
                    continue
                latest = max(_mtime(path), _mtime(_wal_for(entry.name)),
                             *(_mtime(t) for t in _transcripts(entry.name, None if needs_marker else root.name)))
                if now - latest >= days * DAY:
                    count += 1
    return count, True


# --------------------------------------------------------------------------- task output

def _scratch_base() -> Path:
    uid = os.getuid() if hasattr(os, "getuid") else None
    return scratch_root() / (f"claude-{uid}" if uid is not None else "claude")


def durable_tmp_disabled() -> bool:
    """The installer's remembered --no-durable-tmp choice."""
    try:
        state = json.loads((home() / ".agent-harness" / "install-state.json").read_text())
    except (OSError, ValueError):
        return False
    return isinstance(state, dict) and state.get("durable_tmp") is False


def task_output_candidates(now: float | None = None, days: float = DEFAULT_TASK_OUTPUT_DAYS,
                           current_session: str | None = None) -> list[Path]:
    """Old Claude Code background-task output files in the durable scratch root only."""
    now = time.time() if now is None else now
    base, found = _scratch_base(), []
    if os.path.islink(scratch_root()) or os.path.islink(base) or _redirected_to_tmp(base):
        return []
    try:
        projects = [e for e in os.scandir(base) if e.is_dir(follow_symlinks=False)]
    except OSError:
        return []
    for project in projects:
        try:
            sessions = [e for e in os.scandir(project.path)
                        if e.is_dir(follow_symlinks=False) and SESSION_UUID.fullmatch(e.name)
                        and e.name != current_session and not os.path.lexists(Path(e.path) / KEEP)]
        except OSError:
            continue
        for session in sessions:
            tasks = Path(session.path) / TASK_OUTPUT
            if os.path.islink(tasks):
                continue
            try:
                entries = list(os.scandir(tasks))
            except OSError:
                continue
            for entry in entries:
                try:
                    info = entry.stat(follow_symlinks=False)
                except OSError:
                    continue
                if (TASK_OUTPUT_NAME.fullmatch(entry.name) and stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                        and now - info.st_mtime >= days * DAY):
                    found.append(Path(entry.path))
    return sorted(found)


def open_files(paths: list[Path], run=None) -> set | None:
    """Real paths among `paths` that a live process holds open; None when that cannot be determined."""
    if not paths:
        return set()
    wanted = {os.path.realpath(p) for p in paths}
    if os.path.isdir("/proc/self/fd"):
        held = set()
        for pid in os.listdir("/proc"):
            if not pid.isdigit():
                continue
            try:
                fds = os.listdir(f"/proc/{pid}/fd")
            except OSError:
                continue  # another user's or an exited process
            for fd in fds:
                try:
                    target = os.readlink(f"/proc/{pid}/fd/{fd}")
                except OSError:
                    continue
                if target in wanted:
                    held.add(target)
        return held
    import subprocess
    run = run or subprocess.run
    held = set()
    for start in range(0, len(paths), 200):
        batch = [str(p) for p in paths[start:start + 200]]
        try:
            result = run(["lsof", "-nP", "-Fn", "--", *batch], capture_output=True, text=True, timeout=60)
        except (OSError, subprocess.SubprocessError):
            return None
        # lsof exits 1 whenever any listed file is not open, while still listing the open ones.
        if result.returncode not in (0, 1):
            return None
        held.update(os.path.realpath(line[1:]) for line in result.stdout.splitlines() if line.startswith("n"))
    return held & wanted


BACKUP_CONFIG = "task-output-backup.json"
CRYPT_REMOTE = "AHTASKCRYPT"  # an env-only rclone crypt remote: the key never touches rclone.conf


def load_backup_config() -> dict | None:
    """~/.agent-harness/task-output-backup.json: {"remote": "<rclone remote:path>", "password_command": [...]}.

    The password command prints the encryption passphrase (for example from the macOS keychain or a
    secret manager); the passphrase is never stored by the harness.
    """
    path = home() / ".agent-harness" / BACKUP_CONFIG
    try:
        info = os.stat(path, follow_symlinks=False)
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077:
            return None  # must be a private regular file
        config = json.loads(path.read_text())
    except (OSError, ValueError):
        return None
    if (not isinstance(config, dict) or not isinstance(config.get("remote"), str) or ":" not in config["remote"]
            or not isinstance(config.get("password_command"), list) or not config["password_command"]
            or not all(isinstance(part, str) for part in config["password_command"])):
        return None
    return config


def _host() -> str:
    import socket
    return re.sub(r"[^A-Za-z0-9._-]", "_", socket.gethostname().split(".")[0]) or "host"


def rclone_backup(files: list[Path], base: Path, config: dict, run=None) -> tuple[set, str]:
    """Copy files to an encrypted rclone crypt remote and cryptcheck them; return (verified, error)."""
    import subprocess
    run = run or subprocess.run
    rclone = config.get("rclone") or "rclone"
    try:
        secret = run(config["password_command"], capture_output=True, text=True, timeout=30)
        passphrase = secret.stdout.strip() if secret.returncode == 0 else ""
        if not passphrase:
            return set(), "password command failed or printed nothing"
        obscured = run([rclone, "obscure", "-"], input=passphrase, capture_output=True, text=True, timeout=30)
        if obscured.returncode != 0 or not obscured.stdout.strip():
            return set(), "rclone obscure failed"
    except (OSError, subprocess.SubprocessError) as exc:
        return set(), f"backup setup failed ({exc.__class__.__name__})"
    prefix = f"RCLONE_CONFIG_{CRYPT_REMOTE}_"
    env = {**os.environ, prefix + "TYPE": "crypt",
           prefix + "REMOTE": config["remote"].rstrip("/") + "/" + _host(),
           prefix + "PASSWORD": obscured.stdout.strip(),
           prefix + "FILENAME_ENCRYPTION": "standard", prefix + "DIRECTORY_NAME_ENCRYPTION": "true"}
    relative = [str(p.relative_to(base)) for p in files]
    fd, listing = None, work_root() / f".task-output-list-{os.getpid()}"
    try:
        work_root().mkdir(mode=0o700, parents=True, exist_ok=True)
        fd = os.open(listing, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w") as handle:
            handle.write("\n".join(relative) + "\n")
        target = CRYPT_REMOTE.lower() + ":"
        common = ["--files-from-raw", str(listing), str(base), target]
        copy = run([rclone, "copy", "--no-traverse", *common], env=env,
                   capture_output=True, text=True, timeout=3600)
        if copy.returncode != 0:
            return set(), f"upload failed (rclone exit {copy.returncode}); deleted nothing"
        check = run([rclone, "cryptcheck", "--one-way", "--combined", "-", *common], env=env,
                    capture_output=True, text=True, timeout=3600)
        if check.returncode != 0:
            return set(), f"verification failed (rclone exit {check.returncode}); deleted nothing"
        # Trust only files cryptcheck itself reports as matching ("= path"), never the request list.
        matched = {line[2:] for line in check.stdout.splitlines() if line.startswith("= ")}
        verified = {str(base / r) for r in relative if r in matched}
        return verified, "" if verified else "verification matched no files; deleted nothing"
    except (OSError, subprocess.SubprocessError) as exc:
        return set(), f"backup failed ({exc.__class__.__name__}); deleted nothing"
    finally:
        try:
            os.unlink(listing)
        except OSError:
            pass


def prune_task_output(apply: bool, days: float = DEFAULT_TASK_OUTPUT_DAYS, now: float | None = None,
                      open_check=open_files, current_session: str | None = None, backup=None,
                      config=None) -> dict:
    """List old task output; with apply, delete only files an encrypted backup has verified."""
    now = time.time() if now is None else now
    found = task_output_candidates(now, days, current_session)
    held = open_check(found)
    if held is None:
        return {"status": "SKIPPED", "reason": "could not determine which files are open; deleted nothing",
                "candidates": [str(p) for p in found], "removed": []}
    removable = [p for p in found if os.path.realpath(p) not in held]
    report = {"status": "DRY_RUN", "candidates": [str(p) for p in removable], "open": sorted(held),
              "removed": [], "errors": []}
    if not apply or not removable:
        return report
    config = load_backup_config() if config is None else config
    if not config:
        report.update(status="REPORT_ONLY", reason=f"no encrypted backup configured in "
                      f"~/.agent-harness/{BACKUP_CONFIG}; deleted nothing")
        return report
    snapshot = {}
    for path in removable:
        try:
            info = os.stat(path, follow_symlinks=False)
            snapshot[str(path)] = (info.st_size, info.st_mtime_ns)
        except OSError:
            pass
    verified, error = (backup or rclone_backup)([Path(p) for p in snapshot], _scratch_base(), config)
    if error or not verified:
        report.update(status="BACKUP_FAILED", reason=error or "nothing verified; deleted nothing")
        return report
    for path, (size, mtime_ns) in snapshot.items():
        if path not in verified:
            continue
        try:
            info = os.stat(path, follow_symlinks=False)
            # Delete only the exact bytes that were backed up and are still old.
            if (stat.S_ISREG(info.st_mode) and not _protected(Path(path))
                    and (info.st_size, info.st_mtime_ns) == (size, mtime_ns)
                    and now - info.st_mtime >= days * DAY):
                os.unlink(path)
                report["removed"].append(path)
        except OSError as exc:
            report["errors"].append({"path": path, "error": exc.__class__.__name__})
    report["status"] = "APPLIED"
    return report


def spawn_task_output_prune(now: float | None = None, popen=None, session_id: str | None = None) -> bool:
    """At most daily, start a detached task-output prune so the session hook never waits on lsof.

    Deletion happens only for files an encrypted backup verified (see load_backup_config); with no
    backup configured the job only reports. AGENT_HARNESS_TASK_OUTPUT_PRUNE=off disables it.
    """
    import subprocess
    now = time.time() if now is None else now
    stamp = work_root() / TASK_STAMP
    try:
        if (os.environ.get("AGENT_HARNESS_TASK_OUTPUT_PRUNE") == "off" or durable_tmp_disabled()
                or not _scratch_base().is_dir() or os.path.islink(stamp)
                or now - _mtime(stamp) < DAY):
            return False
        work_root().mkdir(mode=0o700, parents=True, exist_ok=True)
        os.close(os.open(stamp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600))
        os.utime(stamp, (now, now))
        mode = ["--apply"]  # still deletes nothing without a verified encrypted backup
        current = ["--current-session", session_id] if session_id and SESSION_UUID.fullmatch(session_id) else []
        (popen or subprocess.Popen)([sys.executable, str(Path(__file__).resolve()), "prune-task-output", *mode,
                                     *current, "--report", str(work_root() / TASK_REPORT)],
                                    stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                    stderr=subprocess.DEVNULL, start_new_session=True, close_fds=True)
        return True
    except OSError:
        return False


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="action", required=True)
    cmd = sub.add_parser("prune", help="list (default) or remove directories past retention")
    cmd.add_argument("--apply", action="store_true", help="delete eligible directories")
    cmd.add_argument("--done-days", type=float, default=DEFAULT_DONE_DAYS,
                     help="idle days once the work is marked done (.done file, or a WAL status note "
                          "starting WORKDIR_DONE)")
    cmd.add_argument("--idle-days", type=float, default=DEFAULT_IDLE_DAYS,
                     help="idle days after which any marked work directory is eligible")
    cmd.add_argument("--scratch-days", type=float, default=DEFAULT_SCRATCH_DAYS,
                     help="idle days for session directories in the durable scratch root")
    cmd.add_argument("--current-session", help="session id that is never eligible")
    cmd.add_argument("--include-task-output", action="store_true",
                     help="also delete Claude Code task output (tasks/); it is not backed up")
    task = sub.add_parser("prune-task-output",
                          help=f"list (default) or remove Claude task output older than {DEFAULT_TASK_OUTPUT_DAYS} "
                               "days that no live process holds open; with --apply, deletes only files an "
                               "encrypted rclone backup verified (SessionStart runs it daily)")
    task.add_argument("--apply", action="store_true", help="delete; otherwise list")
    task.add_argument("--days", type=float, default=DEFAULT_TASK_OUTPUT_DAYS)
    task.add_argument("--report", type=Path, help="also write the JSON result to this private file")
    task.add_argument("--current-session", help="session id whose task output is never removed")
    args = parser.parse_args(argv)
    if args.action == "prune-task-output":
        if args.days < 1:
            parser.error("retention periods must be at least 1 day")
        result = prune_task_output(args.apply, args.days, current_session=args.current_session)
        text = json.dumps(result, indent=2)
        print(text)
        if args.report:
            fd = os.open(args.report, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "w") as handle:
                handle.write(text + "\n")
        return 0 if not result.get("errors") else 1
    for value in (args.done_days, args.idle_days, args.scratch_days):
        if value < 1:
            parser.error("retention periods must be at least 1 day")
    result = prune(args.apply, include_task_output=args.include_task_output, done_days=args.done_days, idle_days=args.idle_days,
                   scratch_days=args.scratch_days,
                   current_session=args.current_session or os.environ.get("CLAUDE_CODE_SESSION_ID"))
    print(json.dumps(result, indent=2))
    return 0 if not result["errors"] and result["status"] != "REFUSED" else 1


if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    sys.exit(main())
