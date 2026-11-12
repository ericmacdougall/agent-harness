"""Recognize the supported Desktop review root at the existing review hook seam."""
from __future__ import annotations

import ctypes as ct
import os
from pathlib import Path
import pwd
import re
import sqlite3
import stat
import sys
import time

from native_context import CodeIdentity, DarwinBackend, OPENAI_TEAM, _valid_process, probe_runtime_origin

_UUID = r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}"
_SESSION_ID = re.compile(_UUID)
_TOOL_ID = re.compile("exec-" + _UUID)
_CDHASH = re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}")
_CHILD_FIELDS = (
    "agent_id", "agentId", "agent_type", "agentType", "agent_path", "agentPath",
    "agent_role", "agentRole", "parent_thread_id", "parentThreadId",
    "attached_thread_parent_id", "attachedThreadParentId",
)
_DESKTOP_IDENTIFIER = "com.openai.codex"
_DESKTOP_REQUIREMENT = (
    f'anchor apple generic and identifier "{_DESKTOP_IDENTIFIER}" '
    f'and certificate leaf[subject.OU] = "{OPENAI_TEAM}"'
)
_APP_EXECUTABLE = ("Contents", "MacOS", "ChatGPT")
_APP_RUNTIME = "Contents/Resources/codex-cli/CodexCLI.app/Contents/MacOS/codex"
_MAX_DATABASE_BYTES = 256 * 1024 * 1024
_MAX_WAL_BYTES = 64 * 1024 * 1024
_MAX_SHM_BYTES = 4 * 1024 * 1024
_BUSY_SECONDS = 0.05
_QUERY_SECONDS = 0.20

# Bound the projection before SQLite hands a value to Python. Oversized or
# unexpected values cannot be interpreted as a missing child marker.
_TEXT_COLUMNS = ("id", "source", "thread_source", "originator", "agent_path", "agent_role",
                 "attached_thread_parent_id")
_THREAD_QUERY = "SELECT " + ", ".join(
    f"CASE WHEN {name} IS NULL OR (typeof({name}) = 'text' AND "
    f"length(CAST({name} AS BLOB)) <= 512) THEN {name} ELSE X'' END"
    for name in _TEXT_COLUMNS
) + ", CASE WHEN typeof(archived) = 'integer' THEN archived ELSE X'' END FROM main.threads WHERE id = ? LIMIT 2"


def _current_session(payload):
    if not isinstance(payload, dict) or any(payload.get(name) is not None for name in _CHILD_FIELDS):
        return None
    if payload.get("hook_event_name") != "PreToolUse" or payload.get("tool_name") != "Bash":
        return None
    session, tool_id = payload.get("session_id"), payload.get("tool_use_id")
    if (not isinstance(session, str) or not _SESSION_ID.fullmatch(session)
            or not isinstance(tool_id, str) or not _TOOL_ID.fullmatch(tool_id)):
        return None
    aliases = {
        "sessionId": session, "thread_id": session, "threadId": session,
        "toolUseId": tool_id, "tool_name": "Bash", "toolName": "Bash",
        "hookEventName": "PreToolUse",
    }
    if any(key in payload and payload[key] != value for key, value in aliases.items()):
        return None
    return session


def _path_identity(path, uid, file_type, maximum=None, *, optional=False):
    try:
        info = path.lstat()
    except FileNotFoundError:
        if optional:
            return None
        raise
    if (info.st_uid != uid or stat.S_IFMT(info.st_mode) != file_type or info.st_mode & 0o022
            or (maximum is not None and (info.st_nlink != 1 or info.st_size > maximum))):
        raise ValueError("unqualified native metadata path")
    return info.st_dev, info.st_ino, info.st_uid, info.st_mode


def _database_binding(home, db, uid):
    if home.resolve(strict=True) != home or db.parent.resolve(strict=True) != db.parent:
        raise ValueError("aliased native metadata directory")
    return (
        _path_identity(home, uid, stat.S_IFDIR),
        _path_identity(db.parent, uid, stat.S_IFDIR),
        _path_identity(db, uid, stat.S_IFREG, _MAX_DATABASE_BYTES),
        _path_identity(db.with_name(db.name + "-wal"), uid, stat.S_IFREG, _MAX_WAL_BYTES, optional=True),
        _path_identity(db.with_name(db.name + "-shm"), uid, stat.S_IFREG, _MAX_SHM_BYTES, optional=True),
    )


def _read_thread(home, uid, ident):
    """Bound one read-only SQLite snapshot and retain source path identities."""
    if not isinstance(ident, str) or not _SESSION_ID.fullmatch(ident):
        return None
    db = home / ".codex" / "state_5.sqlite"
    deadline = time.monotonic() + _QUERY_SECONDS
    try:
        before = _database_binding(home, db, uid)
        fd = os.open(db, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            info = os.fstat(fd)
            if (info.st_dev, info.st_ino, info.st_uid, info.st_mode) != before[2]:
                return None
            header = os.pread(fd, 20, 0)
        finally:
            os.close(fd)
        if len(header) != 20 or header[:16] != b"SQLite format 3\0":
            return None
        # Keep SQLite's real live-WAL view. Missing WAL companions can require
        # sidecar creation, which is outside this read-only adapter's scope.
        if header[18:20] == b"\x02\x02":
            if before[3] is None or before[4] is None:
                return None
        elif header[18:20] != b"\x01\x01" or before[3] is not None or before[4] is not None:
            return None
        if _path_identity(db.with_name(db.name + "-journal"), uid, stat.S_IFREG,
                          _MAX_WAL_BYTES, optional=True) is not None:
            return None

        conn = sqlite3.connect(db.as_uri() + "?mode=ro", uri=True, timeout=_BUSY_SECONDS)
        try:
            conn.set_progress_handler(lambda: int(time.monotonic() > deadline), 100)
            conn.execute("PRAGMA trusted_schema=OFF")
            conn.execute("PRAGMA query_only=ON")
            table = conn.execute("PRAGMA main.table_list('threads')").fetchmany(2)
            if len(table) != 1 or table[0][:3] != ("main", "threads", "table"):
                return None
            plain = conn.execute(
                "SELECT count(*) FROM pragma_table_xinfo('threads', 'main') "
                "WHERE name IN ('id', 'source', 'thread_source', 'originator', 'agent_path', "
                "'agent_role', 'attached_thread_parent_id', 'archived') AND hidden=0"
            ).fetchone()
            if plain != (8,):
                return None
            rows = conn.execute(_THREAD_QUERY, (ident,)).fetchmany(2)
        finally:
            conn.close()
        if time.monotonic() > deadline or _database_binding(home, db, uid) != before or len(rows) != 1:
            return None
        row = rows[0]
        if any(value is not None and type(value) is not str for value in row[:-1]) or type(row[-1]) is not int:
            return None
        return row, before
    except (OSError, sqlite3.Error, ValueError, TypeError, OverflowError):
        return None


class _DesktopBackend(DarwinBackend):
    def desktop_signature(self, pid):
        """Check the running GUI guest with the GUI-specific fixed requirement."""
        owned = []

        def hold(value):
            if not value:
                raise OSError("Desktop code identity unavailable")
            owned.append(value)
            return value

        def check(status):
            if status != 0:
                raise OSError("Desktop code identity not verified")

        try:
            number = ct.c_int64(pid)
            pid_value = hold(self.cf.CFNumberCreate(None, 4, ct.byref(number)))
            keys = (ct.c_void_p * 1)(self._constant("kSecGuestAttributePid"))
            values = (ct.c_void_p * 1)(pid_value)
            attributes = hold(self.cf.CFDictionaryCreate(None, keys, values, 1, None, None))
            guest = ct.c_void_p()
            check(self.sec.SecCodeCopyGuestWithAttributes(None, attributes, 0, ct.byref(guest)))
            hold(guest.value)
            rule = hold(self.cf.CFStringCreateWithCString(None, _DESKTOP_REQUIREMENT.encode(), 0x08000100))
            requirement = ct.c_void_p()
            check(self.sec.SecRequirementCreateWithString(rule, 0, ct.byref(requirement)))
            hold(requirement.value)
            check(self.sec.SecCodeCheckValidity(guest, 0, requirement))
            information = ct.c_void_p()
            check(self.sec.SecCodeCopySigningInformation(guest, 2, ct.byref(information)))
            hold(information.value)

            def field(name):
                return self.cf.CFDictionaryGetValue(information, self._constant(name))

            unique = field("kSecCodeInfoUnique")
            length = self.cf.CFDataGetLength(unique) if unique else 0
            if length not in (20, 32):
                raise OSError("Desktop code hash unavailable")
            pointer = self.cf.CFDataGetBytePtr(unique)
            if not pointer:
                raise OSError("Desktop code hash unavailable")
            cdhash = ct.string_at(pointer, length).hex()
            executable = field("kSecCodeInfoMainExecutable")
            if not executable:
                raise OSError("Desktop signed executable unavailable")
            path = hold(self.cf.CFURLCopyFileSystemPath(executable, 0))
            return CodeIdentity(self._text(field("kSecCodeInfoIdentifier")),
                                self._text(field("kSecCodeInfoTeamIdentifier")), cdhash, self._text(path))
        finally:
            for value in reversed(owned):
                self.cf.CFRelease(value)


class _ProcessSnapshot:
    """Retain the kernel identities used by the existing nearest-runtime probe."""
    def __init__(self, backend):
        self.backend = backend
        self.observed = {}

    def process(self, pid):
        current = self.backend.process(pid)
        if not _valid_process(current, pid) or self.observed.setdefault(pid, current) != current:
            raise OSError("native process identity changed")
        return current

    def signature(self, pid):
        return self.backend.signature(pid)

    def recheck(self):
        for pid in self.observed:
            self.process(pid)


def _same_package(runtime, gui):
    app = Path(gui.executable)
    if app.parts[-3:] != _APP_EXECUTABLE:
        return False
    bundle = app.parents[2]
    return bundle.suffix == ".app" and runtime.executable == str(bundle / _APP_RUNTIME)


def _is_desktop_root(payload, pid, backend, read_thread):
    session = _current_session(payload)
    if session is None:
        return False
    try:
        first_row = read_thread(session)
        root_row = (session, "vscode", "user", "Codex Desktop", None, None, None, 0)
        if first_row is None or first_row[0] != root_row or type(first_row[0][-1]) is not int:
            return False

        snapshot = _ProcessSnapshot(backend)
        origin = probe_runtime_origin(pid, backend=snapshot)
        if origin.origin != "openai" or origin.reason != "running_code_verified" or not origin.native_lineage:
            return False
        runtime = snapshot.process(origin.runtime_pid)
        if runtime.parent <= 1:
            return False
        gui = snapshot.process(runtime.parent)
        caller = snapshot.observed[pid]
        if not (caller.uid == runtime.uid == gui.uid and _same_package(runtime, gui)):
            return False
        gui_code = backend.desktop_signature(gui.pid)
        if (not isinstance(gui_code, CodeIdentity) or gui_code.identifier != _DESKTOP_IDENTIFIER
                or gui_code.team != OPENAI_TEAM or gui_code.executable != gui.executable
                or not isinstance(gui_code.cdhash, str) or not _CDHASH.fullmatch(gui_code.cdhash)):
            return False
        if read_thread(session) != first_row:
            return False
        snapshot.recheck()
        if backend.desktop_signature(gui.pid) != gui_code or backend.signature(runtime.pid) != origin.code:
            return False
        snapshot.recheck()
        return True
    except (OSError, ValueError, TypeError, KeyError, AttributeError, OverflowError):
        return False


def is_desktop_review_root(payload):
    """The user-driven Codex Desktop root session. Callers: the review stamp and, by the user's decision (answer
    b6714826, goodqa#15565: a Codex Desktop root may record merge waivers), merge_gate._may_record_waiver. The caller
    owns command and receipt policy; a spawned child, standalone CLI or unqualified row is never a root."""
    if sys.platform != "darwin" or _current_session(payload) is None:
        return False
    try:
        uid = os.getuid()
        home = Path(pwd.getpwuid(uid).pw_dir)
        backend = _DesktopBackend()
    except (OSError, KeyError, ValueError):
        return False
    return _is_desktop_root(payload, os.getpid(), backend, lambda ident: _read_thread(home, uid, ident))
