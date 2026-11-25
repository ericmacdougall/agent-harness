#!/usr/bin/env python3
"""Claude Code hook: private, append-only write-ahead logs per session and agent."""

import hashlib
import fcntl
import json
import os
import re
import shlex
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


WAL_ROOT_ERROR = "WAL path must be a per-session JSONL under ~/.claude/wals"
SESSION_NAME_RE = re.compile(r"[A-Za-z0-9._-]{1,120}")
# A WAL that cannot be written safely (hard link, symlink, directory, oversize crash tail, a swap that will not settle)
# never blocks the session (goodqa#17145). The row goes to its own O_EXCL side file in the same private directory and is
# merged back, verified, by the next append once the WAL is a plain single-link file again.
PENDING_MAX_FILES = 50_000
LOCK_SECONDS = 3.0  # a WAL lock held longer than this diverts the row instead of stalling the hook
PENDING_MAX_BYTES = 65_536
MERGE_SCAN_BYTES = 4_194_304
LINK_SEARCH_SECONDS = 0.6
LINK_SEARCH_ENTRIES = 200_000
LINK_SCAN_TTL = 120
LAST_RESULT = "written"  # the last append's outcome: written, deferred (kept in a side file) or not_saved
NOTICES: list = []  # human-readable warnings the current hook invocation prints; one process is one hook call


def _notice(text: str) -> None:
    if text not in NOTICES:
        NOTICES.append(text)
    print("wal.py: " + text, file=sys.stderr)


def _quoted(value: object, limit: int = 160) -> str:
    """A path or name as inert data for a warning: only path-safe characters survive (anything else becomes ?), then
    it is JSON-quoted and length-capped, so a hostile file name cannot carry sentences into the model's context."""
    clean = re.sub(r"[^A-Za-z0-9._/~+@=:,-]", "?", str(value))
    return json.dumps(clean[:limit] + ("..." if len(clean) > limit else ""))


def _lock(fd: int, seconds: float) -> bool:
    """flock(LOCK_EX) with a bound: True when held, False when another holder kept it for `seconds`."""
    deadline = time.monotonic() + seconds
    while True:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return True
        except BlockingIOError:
            if time.monotonic() >= deadline:
                return False
            time.sleep(0.02)


def _pending_re(wal_name: str):
    return re.compile(re.escape(wal_name) + r"\.pending-(\d{20})-(\d+)-([0-9a-f]{8})")


def _pending_names(directory: int, wal_name: str) -> list:
    pattern = _pending_re(wal_name)
    try:
        names = os.listdir(directory)
    except OSError:
        return []
    return sorted(name for name in names if pattern.fullmatch(name))


def link_roots() -> list:
    """Where an extra hard link of a WAL is likely to live: stash and backup roots, plus the live trees themselves."""
    override = os.environ.get("HARNESS_WAL_LINK_ROOTS")
    if override is not None:
        return [Path(p) for p in override.split(os.pathsep) if p]
    home = Path.home()
    return [home / ".claude" / name for name in ("agent-harness-backups", "backups", "spares", "wals", "projects")] + [
        home / ".agent-harness" / name for name in ("backups", "stash", "transcript-archive", "archive")] + [
        home / ".codex" / "sessions"]


def find_other_links(dev: int, ino: int, own: Path, want: int) -> tuple:
    """(paths, complete): other names of the inode under link_roots(), by inode, stat only, no symlink or device
    crossing, bounded in entries and time. `complete` is False when a bound ended the search."""
    deadline = time.monotonic() + LINK_SEARCH_SECONDS
    seen, found, complete = 0, [], True
    stack = [str(root) for root in link_roots() if root.is_dir()]
    own_text = str(own)
    while stack and len(found) < want:
        top = stack.pop()
        try:
            with os.scandir(top) as entries:
                for entry in entries:
                    seen += 1
                    if seen > LINK_SEARCH_ENTRIES or time.monotonic() > deadline:
                        return found, False
                    try:
                        if entry.is_symlink():
                            continue
                        if entry.is_dir(follow_symlinks=False):
                            if entry.stat(follow_symlinks=False).st_dev == dev:
                                stack.append(entry.path)
                        elif entry.inode() == ino and entry.path != own_text:
                            info = entry.stat(follow_symlinks=False)
                            if (info.st_dev, info.st_ino) == (dev, ino):
                                found.append(entry.path)
                    except OSError:
                        continue
        except OSError:
            continue
    return found, complete and not stack


def recover_command(wal: Path) -> str:
    return "python3 %s recover %s" % (shlex.quote(str(Path(__file__).resolve())), shlex.quote(str(wal)))


def _link_report(directory: int, wal: Path, info) -> str:
    """The loud part of the warning for a WAL with more than one link; cached briefly so a long outage stays cheap."""
    cache_name = wal.name + ".linkscan"
    found, complete = None, True
    try:
        fd = os.open(cache_name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        try:
            cached = json.loads(os.read(fd, 65_536))
        finally:
            os.close(fd)
        if (cached.get("ino"), cached.get("dev"), cached.get("nlink")) == (info.st_ino, info.st_dev, info.st_nlink) \
                and time.time() - float(cached.get("at", 0)) < LINK_SCAN_TTL:
            found, complete = [str(p) for p in cached["found"]], bool(cached.get("complete", True))
    except (OSError, ValueError, KeyError, TypeError):
        pass
    if found is None:
        found, complete = find_other_links(info.st_dev, info.st_ino, wal, info.st_nlink - 1)
        try:
            tmp = "%s.tmp-%d" % (cache_name, os.getpid())
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
            with os.fdopen(fd, "w") as handle:
                json.dump({"ino": info.st_ino, "dev": info.st_dev, "nlink": info.st_nlink, "at": time.time(),
                           "found": found, "complete": complete}, handle)
            os.rename(tmp, cache_name, src_dir_fd=directory, dst_dir_fd=directory)
        except OSError:
            pass
    if found:
        shown = ", ".join(_quoted(p) for p in found[:5]) + (" and more" if len(found) > 5 else "")
        where = "Other link path(s) of this inode, found by inode and shown as quoted data: %s." % shown
    else:
        where = ("The other %d link(s) were not found under the stash and backup roots (search is bounded%s); find them "
                 "with: find / -xdev -inum %d -not -path %s 2>/dev/null"
                 % (info.st_nlink - 1, "" if complete else " and ended early", info.st_ino, shlex.quote(str(wal))))
    return where


def _divert(directory: int, wal: Path, record: dict, reason: str, info=None) -> bool:
    """Keep the row in its own private side file instead of writing to an unsafe WAL. Never raises. Returns False."""
    try:
        names = _pending_names(directory, wal.name)
        full = len(names) >= PENDING_MAX_FILES
        saved = False
        if not full:
            for _ in range(6):
                name = "%s.pending-%020d-%d-%s" % (wal.name, time.time_ns(), os.getpid(), os.urandom(4).hex())
                row = dict(record, deferred_id=name, deferred_reason=reason)
                data = (json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n").encode()
                temp = name + ".tmp"
                try:
                    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
                except FileExistsError:
                    continue
                with os.fdopen(fd, "wb") as handle:
                    handle.write(data)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.rename(temp, name, src_dir_fd=directory, dst_dir_fd=directory)  # complete or absent, never partial
                saved = True
                break
        count = len(names) + (1 if saved else 0)
        _set_result("deferred" if saved else "not_saved")
        if not saved:
            print(json.dumps(record, ensure_ascii=False, separators=(",", ":")), file=sys.stderr)
        head = ("WAL INTEGRITY WARNING (goodqa#17145): %s %s, so the hook did not write to it and Bash was NOT blocked."
                % (_quoted(wal), reason))
        kept = ("%d audit row(s) are kept in private side file(s) %s* and merge back, verified, once the WAL is a plain "
                "single-link file." % (count, _quoted(str(wal) + ".pending-")) if saved else
                "THIS AUDIT ROW COULD NOT BE SAVED (side file limit or disk error); it was printed to stderr only.")
        where = _link_report(directory, wal, info) if info is not None and info.st_nlink > 1 else ""
        fix = ("To heal now (a hard-linked WAL gets its own private inode and the other link keeps the old copy; any other "
               "damaged WAL is moved aside as .quarantined-*; nothing is deleted): %s" % recover_command(wal))
        _notice(" ".join(part for part in (head, kept, where, fix) if part))
    except Exception as exc:  # the divert is the safety net: it must never become the lockout
        _notice("WAL INTEGRITY WARNING: %s could not be written and its side file failed (%s); run %s"
                % (_quoted(wal), exc.__class__.__name__, recover_command(wal)))
    return False


def _read_side(directory: int, name: str):
    """(record dict, linked) for one side file, or None after quarantining a bad one."""
    try:
        fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    except OSError:
        return None
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_size > PENDING_MAX_BYTES or info.st_uid != os.getuid()):
            raise ValueError("side file is not a small regular file of this user")
        raw = os.read(fd, PENDING_MAX_BYTES + 1)
        text = raw.decode("utf-8")
        record = json.loads(text)
        if not isinstance(record, dict) or text.count("\n") != 1 or not text.endswith("\n") \
                or record.get("deferred_id") != name:
            raise ValueError("side file is not exactly one row for itself")
        return record, info.st_nlink > 1
    except (ValueError, OSError):
        try:
            os.rename(name, name + ".rejected", src_dir_fd=directory, dst_dir_fd=directory)
        except OSError:
            pass
        _notice("a malformed or foreign side file %s was set aside as .rejected and not merged" % _quoted(name))
        return None
    finally:
        os.close(fd)


def _merge_pending(directory: int, wal: Path, fd: int) -> None:
    """Under the WAL lock: append every side-file row to the WAL, read the bytes back, and only then remove the side
    files. Rows already in the WAL tail (a crash after the append, before the cleanup) are skipped by their id."""
    names = _pending_names(directory, wal.name)
    if not names:
        return
    end = os.lseek(fd, 0, os.SEEK_END)
    start = max(0, end - MERGE_SCAN_BYTES)
    tail = os.pread(fd, end - start, start) if end else b""
    present = set(re.findall(rb'"deferred_id":"([^"]+)"', tail))
    done, lines = [], []
    for name in names:
        side = _read_side(directory, name)
        if side is None:
            continue
        record, linked = side
        done.append(name)
        if name.encode() in present:
            continue
        if linked:
            record["side_file_linked"] = True  # someone gave the side file a second name before it was merged
        line = (json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n").encode()
        lines.append(line)
    if lines:
        blob = b"".join(lines)
        with os.fdopen(fd, "ab", closefd=False) as handle:
            handle.write(blob)
            handle.flush()
        os.fsync(fd)
        if os.pread(fd, len(blob), end) != blob:
            _notice("merging %d side-file row(s) into %s could not be verified; the side files were kept (a retry skips "
                    "rows already present)" % (len(lines), _quoted(wal)))
            return
    for name in done:
        try:
            os.unlink(name, dir_fd=directory)
        except OSError:
            pass


def _open_session(stack: ExitStack, session: str):
    """Pin ~/.claude, wals and the session directory by fd; returns (directory fd, still_pinned())."""
    root = Path.home() / ".claude"
    root.mkdir(mode=0o700, exist_ok=True)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    directory = os.open(root, flags)
    stack.callback(os.close, directory)
    pinned = [(root, None, directory)]
    for name in ("wals", session):
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

    return directory, current_directory


def _check_wal_path(path: Path) -> None:
    root = Path.home() / ".claude" / "wals"
    if (path.parent.parent != root or path.suffix != ".jsonl" or not SESSION_NAME_RE.fullmatch(path.parent.name)
            or path.parent.name in {".", ".."}):
        raise ValueError(WAL_ROOT_ERROR)


def _set_result(value: str) -> None:
    global LAST_RESULT
    LAST_RESULT = value


def _no_safe_directory(path: Path, record: dict, exc: Exception) -> bool:
    """The wals or session directory is itself unsafe (a symlink, a file, replaced): no private place exists to keep the
    row, so print it, warn loudly and do not block. Only the user can repair a directory; recover cannot."""
    print(json.dumps(record, ensure_ascii=False, separators=(",", ":")), file=sys.stderr)
    _set_result("not_saved")
    _notice("WAL INTEGRITY WARNING: the directory of %s is not safe to write (%s), so this audit row was printed to stderr "
            "only and Bash was NOT blocked. Ask the user to inspect ~/.claude/wals/%s: it must be a real directory owned by "
            "the user, not a symlink or a file." % (_quoted(path), exc.__class__.__name__, re.sub(r"[^A-Za-z0-9._-]", "?",
                                                                                                    path.parent.name)))
    return False


def append(path: Path, record: dict) -> bool:
    """Append one JSONL row. True when it reached the WAL; False when the WAL was unsafe to write and the row was kept
    in a side file instead (a warning was printed). Nothing is ever appended through a hard link, a symlink or a
    directory. Path-shape errors still raise: they are caller bugs, not file state."""
    _check_wal_path(path)
    _set_result("written")
    payload = (json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n").encode()
    with ExitStack() as stack:
        try:
            directory, current_directory = _open_session(stack, path.parent.name)
        except (OSError, ValueError) as exc:  # a symlinked or missing wals or session directory: nothing safe to write
            return _no_safe_directory(path, record, exc)
        file_flags = os.O_RDWR | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW | os.O_NONBLOCK
        reason = "could not be opened safely"
        for attempt in range(4):
            if not current_directory():
                return _no_safe_directory(path, record, ValueError("the session directory changed while it was in use"))
            try:
                fd = os.open(path.name, file_flags, 0o600, dir_fd=directory)
            except FileNotFoundError:
                # A concurrent first write has occasionally observed ENOENT on macOS despite O_CREAT. Retry only
                # while the named session directory still resolves to the pinned inode.
                if not current_directory():
                    return _no_safe_directory(path, record, ValueError("the session directory changed while it was in use"))
                if attempt == 3:
                    return _divert(directory, path, record, "could not be created (it stays missing)")
                time.sleep(0.01 * (attempt + 1))
                continue
            except OSError as exc:  # ELOOP (symlink), EISDIR (directory), ENXIO...: never followed, never fatal
                return _divert(directory, path, record, "is not a plain file (%s)" % exc.__class__.__name__)
            try:
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode):
                    return _divert(directory, path, record, "is not a regular file")
                if info.st_nlink != 1:
                    return _divert(directory, path, record, "has %d hard links (inode %d)" % (info.st_nlink, info.st_ino),
                                   info)
                try:
                    os.fchmod(fd, 0o600)
                except OSError as exc:  # a WAL owned by another user: not ours to write
                    return _divert(directory, path, record, "cannot be made private (%s)" % exc.__class__.__name__)
                if not _lock(fd, LOCK_SECONDS):
                    return _divert(directory, path, record, "is locked by another process")

                def named():
                    try:
                        return os.stat(path.name, dir_fd=directory, follow_symlinks=False)
                    except OSError:
                        return None

                held = os.fstat(fd)
                now = named()
                if (held.st_nlink == 0 or now is None or not stat.S_ISREG(now.st_mode)
                        or (now.st_dev, now.st_ino) != (held.st_dev, held.st_ino) or not current_directory()):
                    reason = "was replaced while it was being opened"
                    continue  # a recovery swapped the file: retry on the new inode, nothing written yet
                if held.st_nlink != 1:  # linked after the first check: never write through it
                    return _divert(directory, path, record, "gained a hard link (inode %d)" % held.st_ino, held)
                # A killed writer may leave a partial final record. Under the file lock, remove only that
                # unterminated suffix before adding the next JSONL line.
                end = os.lseek(fd, 0, os.SEEK_END)
                if end and os.pread(fd, 1, end - 1) != b"\n":
                    scan = min(end, 65_536)
                    tail = os.pread(fd, scan, end - scan)
                    last_newline = tail.rfind(b"\n")
                    if last_newline < 0 and end > scan:
                        return _divert(directory, path, record, "has a crash tail over the recovery budget")
                    os.ftruncate(fd, end - scan + last_newline + 1)
                try:
                    _merge_pending(directory, path, fd)
                    # A short write must not silently report a complete record.
                    with os.fdopen(fd, "ab", closefd=False) as handle:
                        handle.write(payload)
                        handle.flush()
                    os.fsync(fd)
                except OSError as exc:  # disk full, quota, I/O error: keep the row if anything still can
                    return _divert(directory, path, record, "could not be written (%s)" % exc.__class__.__name__)
                if not current_directory():
                    _notice("WAL INTEGRITY WARNING: the session directory of %s changed during the append; the row is in "
                            "the moved directory. Check the wals tree." % _quoted(path))
                    return False
                after, still = os.fstat(fd), named()
                if still is None or (still.st_dev, still.st_ino) != (after.st_dev, after.st_ino):
                    # the row went into an inode that is no longer the WAL: keep it in a side file as well
                    return _divert(directory, path, record, "was replaced during the append")
                if after.st_nlink != 1:
                    _notice("WAL INTEGRITY WARNING: %s gained a hard link during the append (inode %d); the row is in "
                            "the WAL. Heal with: %s" % (_quoted(path), after.st_ino, recover_command(path)))
                return True
            finally:
                os.close(fd)
        return _divert(directory, path, record, reason)


def recover(path: Path) -> str:
    """Heal an unsafe WAL without deleting anything: a linked WAL is copied to a private inode that replaces the name
    (the other links keep the old bytes); a symlink, directory, other special file or oversize crash tail is moved
    aside as .quarantined-*. Then any side-file rows are merged. Returns a one-line report."""
    _check_wal_path(path)
    with ExitStack() as stack:
        directory, current_directory = _open_session(stack, path.parent.name)
        try:
            info = os.stat(path.name, dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            info = None
        report = "WAL %s is already a plain single-link file" % path
        if info is not None:
            plain = stat.S_ISREG(info.st_mode)
            fd = os.open(path.name, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory) if plain else None
            try:
                if plain:
                    if not _lock(fd, 10.0):
                        raise ValueError("the WAL is locked by another process; retry in a moment or ask the user which "
                                         "process holds it")
                    held = os.fstat(fd)
                    bad_tail = False
                    if held.st_size:
                        last = os.pread(fd, 1, held.st_size - 1)
                        bad_tail = last != b"\n" and held.st_size > 65_536 \
                            and os.pread(fd, 65_536, held.st_size - 65_536).rfind(b"\n") < 0
                    if held.st_nlink != 1 and not bad_tail:
                        tmp = "%s.recover-%d-%s" % (path.name, os.getpid(), os.urandom(4).hex())
                        out = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
                        try:
                            offset = 0
                            while offset < held.st_size:
                                chunk = os.pread(fd, min(1_048_576, held.st_size - offset), offset)
                                if not chunk:
                                    break
                                os.write(out, chunk)
                                offset += len(chunk)
                            os.fsync(out)
                        finally:
                            os.close(out)
                        if offset != held.st_size:
                            os.unlink(tmp, dir_fd=directory)
                            raise ValueError("short read while copying the WAL; nothing was changed")
                        os.rename(tmp, path.name, src_dir_fd=directory, dst_dir_fd=directory)
                        os.fsync(directory)
                        report = ("WAL %s now has its own inode (it had %d links); no link was removed and the old "
                                  "copy is untouched" % (path, held.st_nlink))
                    elif bad_tail:
                        plain = False
                    else:
                        pass
            finally:
                if fd is not None:
                    os.close(fd)
            if not plain:
                aside = "%s.quarantined-%d" % (path.name, time.time_ns())
                os.rename(path.name, aside, src_dir_fd=directory, dst_dir_fd=directory)
                report = "WAL %s was not safe to append to; it was moved aside as %s and a fresh WAL starts at the " \
                         "next row" % (path, aside)
        # merge any side rows into the (new) WAL; creating it first when it was moved aside or never existed
        fd = os.open(path.name, os.O_RDWR | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600,
                     dir_fd=directory)
        try:
            if os.fstat(fd).st_nlink == 1 and stat.S_ISREG(os.fstat(fd).st_mode) and _lock(fd, 10.0):
                end = os.lseek(fd, 0, os.SEEK_END)
                if end and os.pread(fd, 1, end - 1) != b"\n":
                    os.write(fd, b"\n")
                _merge_pending(directory, path, fd)
        finally:
            os.close(fd)
        return report


EVENT_NAMES = {"session": "SessionStart", "prompt": "UserPromptSubmit", "subagent": "SubagentStart",
               "subagent_stop": "SubagentStop", "pretool": "PreToolUse"}


def emit(event: str, output: dict = None) -> None:
    """Print the hook's one JSON answer, with any WAL warning folded in so it reaches the model and the user."""
    if NOTICES:
        warning = " | ".join(NOTICES)
        output = dict(output or {})
        specific = dict(output.get("hookSpecificOutput") or {})
        if event != "subagent_stop":
            specific["hookEventName"] = EVENT_NAMES.get(event, "PreToolUse")
            specific["additionalContext"] = (specific.get("additionalContext", "") + " " + warning).strip()
            output["hookSpecificOutput"] = specific
        output["systemMessage"] = (output.get("systemMessage", "") + " " + warning).strip()
    if output:
        print(json.dumps(output))


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
    if event == "recover":  # python3 wal.py recover WALPATH: heal an unsafe WAL (goodqa#17145)
        try:
            print(recover(Path(sys.argv[2])))
        except (IndexError, ValueError, OSError) as exc:
            print("wal.py recover refused: %s (usage: wal.py recover <session WAL under the harness wals tree>)" % exc,
                  file=sys.stderr)
            sys.exit(2)
        return
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
        emit(event, {"hookSpecificOutput": {"hookEventName": "SessionStart", "additionalContext": f"Session WAL: {main_wal}. Record task ownership, decisions, changes, checks, commits and handoffs; omit secrets and PII." + work_dir_context(session_id, event, data) + ops_alert_context(event, session_id)}})
    elif event == "prompt":
        prompt = str(data.get("prompt", ""))
        record["prompt_chars"] = len(prompt)
        append(main_wal, record)
        emit(event, {"hookSpecificOutput": {"hookEventName": "UserPromptSubmit", "additionalContext": f"Session WAL: {main_wal}. Follow Agent Harness triage. Record a human-readable intent before edits; the hook metadata alone is insufficient. Use the fast path for small fixes. For substantive work, brief and reuse a background owner, then review, test, publish the feature branch and integrate locally. Ask about material ambiguity and keep the user updated. Never log secrets or PII." + work_dir_context(session_id, event, data) + ops_alert_context(event, session_id)}})
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
        emit(event, {"hookSpecificOutput": {"hookEventName": "SubagentStart", "additionalContext": context + work_dir_context(session_id, event, data) + ops_alert_context(event, session_id)}})
    elif event == "subagent_stop":
        # SubagentStop: lets spec_flow.py record when a click-test agent finished. Only ids that
        # SubagentStart logged are recorded, so spurious stops (empty agent_type) leave no trace.
        agent_id = safe_id(data.get("agent_id"))
        agent_wal = root / f"agent-{agent_id}.jsonl"
        if data.get("agent_id") and agent_wal.exists():
            record.update({"agent_id": agent_id, "agent_type": safe_id(data.get("agent_type"))})
            append(main_wal, record)
            append(agent_wal, record)
        emit(event)
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
        emit(event, json.loads(output) if output else None)
    else:
        raise ValueError(f"unknown event: {event}")


if __name__ == "__main__":
    main()
