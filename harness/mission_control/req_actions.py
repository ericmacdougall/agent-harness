"""The user's archive and restore clicks for requirements (GoodQA goodqa#15920, spec v2 AC-12).

The only write path of the cleanup feature. It records, never deletes: one signed JSON line per click, appended to
MC_HOME/requirements/actions.jsonl, which is also the audit log. A row says who (the dashboard session, as the user's
click, never as `user:` words), when, which requirement (id and the digest of the text the page showed), the action
(archive or restore), why (required text), the rule ("manual") and the source (`mc:<session>/<row id>`). The latest
verified row per requirement overrides the automatic archive rule: an archive moves it to the Archive view, a restore
keeps it live whatever the rules say. A row with a bad signature, a bad shape or an unknown action is ignored.

Nothing here touches `ah requirements` or the harness ledger: the archive is a view over unchanged records.
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import stat
import threading
import time
from pathlib import Path

import mc_chat

ACTIONS = ("archive", "restore")
REASON_MAX = 300
MAX_BYTES = 4 * 1024 * 1024
REQ_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
SESSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{7,63}$")


class ActionError(Exception):
    def __init__(self, code: str, message: str, status: int = 400):
        super().__init__(message)
        self.code, self.status = code, status


class ReqActions:
    def __init__(self, root: Path, key: bytes):
        self.folder = Path(root) / "requirements"
        self.path = self.folder / "actions.jsonl"
        self.key = key
        self.lock = threading.Lock()
        self._cache: tuple | None = None

    def _ensure(self) -> None:
        self.folder.mkdir(mode=0o700, parents=True, exist_ok=True)
        if self.folder.is_symlink():
            raise ActionError("unsafe-path", "the requirements folder is a symlink", 500)

    def _read_rows(self) -> list[dict]:
        try:
            fd = os.open(self.path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        except OSError:
            return []
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                return []
            with os.fdopen(fd, "rb") as handle:
                data = handle.read(MAX_BYTES + 1)
        except OSError:
            return []
        rows = []
        for line in data[:MAX_BYTES].split(b"\n"):
            try:
                row = json.loads(line.decode("utf-8"))
            except (ValueError, UnicodeDecodeError):
                continue
            if self._valid(row):
                rows.append(row)
        return rows

    def _valid(self, row) -> bool:
        return (isinstance(row, dict) and row.get("action") in ACTIONS and isinstance(row.get("req"), str)
                and REQ_ID_RE.match(row["req"]) and isinstance(row.get("reason"), str) and row["reason"].strip()
                and isinstance(row.get("id"), str) and isinstance(row.get("source"), str) and row["source"].startswith("mc:")
                and mc_chat.verified(row, self.key))

    def all(self) -> list[dict]:
        """Every verified row, oldest first: the audit trail."""
        return self._read_rows()

    def latest(self) -> dict:
        """requirement id -> its latest verified archive or restore row."""
        try:
            info = os.stat(self.path)
            sig = (info.st_mtime_ns, info.st_size)
        except OSError:
            return {}
        if self._cache and self._cache[0] == sig:
            return self._cache[1]
        out: dict = {}
        for row in self._read_rows():
            out[row["req"]] = row
        self._cache = (sig, out)
        return out

    def record(self, *, session: str, req: str, action: str, reason: str, digest: str, client_key: str,
               now: float | None = None) -> tuple[dict, bool]:
        """Append one signed row. Idempotent per client_key: the same click returns the same row; the same key with
        different content is a conflict. Raises ActionError for anything unsourced or malformed."""
        if not isinstance(session, str) or not SESSION_RE.match(session):
            raise ActionError("no-main", "Mission Control does not know main's session yet", 409)
        if action not in ACTIONS:
            raise ActionError("bad-action", "action must be archive or restore")
        if not isinstance(req, str) or not REQ_ID_RE.match(req):
            raise ActionError("bad-requirement", "not a requirement id")
        if not isinstance(client_key, str) or not mc_chat.CLIENT_KEY_RE.fullmatch(client_key):
            raise ActionError("bad-key", "client_key must be 8-64 url-safe characters")
        if not isinstance(reason, str) or not reason.strip() or len(reason) > REASON_MAX or "\x00" in reason:
            raise ActionError("bad-reason", f"a reason of 1 to {REASON_MAX} characters is required")
        clean = " ".join(mc_chat._redact(reason).split())
        row_id = "ra-" + hashlib.sha256(client_key.encode("utf-8")).hexdigest()[:20]
        with self.lock:
            self._ensure()
            fd = os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0), 0o600)
            try:
                if not stat.S_ISREG(os.fstat(fd).st_mode):
                    raise ActionError("unsafe-path", "the action log is not a regular file", 500)
                fcntl.flock(fd, fcntl.LOCK_EX)
                for row in self._read_rows():
                    if row["id"] == row_id:
                        if (row["req"], row["action"], row["digest"], row["reason"]) != (req, action, digest, clean):
                            raise ActionError("key-conflict", "this request id was already used for a different action", 409)
                        return row, False
                if os.fstat(fd).st_size > MAX_BYTES:
                    raise ActionError("log-full", "the action log is full; nothing was recorded", 507)
                stamp = mc_chat.now_iso(time.time() if now is None else now)
                row = mc_chat.sign({
                    "v": 1, "id": row_id, "at": stamp, "session": session, "req": req, "action": action, "reason": clean,
                    "rule": "manual", "digest": digest, "client_key": client_key, "origin": "dashboard",
                    "source": f'mc:{session}/{row_id} "Dashboard click: {action} requirement {req}"',
                }, self.key)
                line = (json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n").encode("utf-8")
                size = os.fstat(fd).st_size
                if size > 0 and os.pread(fd, 1, size - 1) != b"\n":
                    line = b"\n" + line  # a cut-off last line must not swallow this row
                os.write(fd, line)
                os.fsync(fd)
            finally:
                os.close(fd)
            self._cache = None
        return row, True
