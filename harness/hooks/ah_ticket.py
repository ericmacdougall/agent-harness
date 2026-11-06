"""ah ticket create: file a GoodQA ticket through the harness's own adapter, with an idempotency key.

A shared path so every agent can file tickets without hand-rolling MCP calls. The key becomes GoodQA's operationId
(server-side idempotent) and is recorded in a local ledger, so a retry after a lost response, a restart or a
double-click returns the same ticket instead of filing a second one.
"""
from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import stat
import time
import uuid
from pathlib import Path

TYPES = ("bug", "blocker", "task", "improvement", "idea", "risk", "test_gap", "question", "epic", "decision")
PRIORITIES = ("immediate", "urgent", "high", "medium", "low", "none")
SLUG = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
KEY = re.compile(r"^[A-Za-z0-9._:-]{8,128}$")
MAX_BODY = 60_000
MAX_TITLE = 200


class TicketCreateError(Exception):
    def __init__(self, code, message, exit_code=2):
        super().__init__(message)
        self.code, self.exit_code = code, exit_code


def _read_body(path: str) -> str:
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        raise TicketCreateError("bad_request", "--body-file cannot be opened (a regular file, not a symlink)")
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_BODY:
            raise TicketCreateError("bad_request", "--body-file must be a regular file of at most %d bytes" % MAX_BODY)
        return os.read(fd, MAX_BODY + 1).decode("utf-8", "replace")
    finally:
        os.close(fd)


def _ledger(home: Path) -> Path:
    d = home / ".agent-harness" / "state" / "ah"
    d.mkdir(mode=0o700, parents=True, exist_ok=True)
    return d / "ticket-create.jsonl"


def _rows(path: Path):
    try:
        lines = path.read_text().splitlines()
    except OSError:
        return []
    out = []
    for line in lines:
        try:
            out.append(json.loads(line))
        except ValueError:
            continue
    return out


def _append(path: Path, row: dict) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        os.write(fd, (json.dumps(row, separators=(",", ":")) + "\n").encode())
        os.fsync(fd)
    finally:
        os.close(fd)


def derive_key(project: str, title: str, body: str) -> str:
    return "tc-" + hashlib.sha256("\0".join((project, title, body)).encode()).hexdigest()[:32]


def create(project, title, body_file, type_="task", priority=None, key=None, home=None, adapter=None, mod=None,
           redactor=None):
    home = home or Path.home()
    if not SLUG.match(project or ""):
        raise TicketCreateError("bad_request", "--project must be a project slug such as goodqa")
    title = " ".join((title or "").split())
    if not title or len(title) > MAX_TITLE:
        raise TicketCreateError("bad_request", "--title must be 1 to %d characters" % MAX_TITLE)
    if type_ not in TYPES:
        raise TicketCreateError("bad_request", "--type must be one of %s" % ", ".join(TYPES))
    if priority is not None and priority not in PRIORITIES:
        raise TicketCreateError("bad_request", "--priority must be one of %s" % ", ".join(PRIORITIES))
    body = _read_body(body_file)
    if redactor is None:
        import redact
        redactor = redact.redact
    title, body = redactor(title), redactor(body)
    key = key or derive_key(project, title, body)
    if not KEY.match(key):
        raise TicketCreateError("bad_request", "--key must be 8 to 128 characters of letters, digits and ._:-")
    path = _ledger(home)
    lock = os.open(str(path) + ".lock", os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX)
        done = next((r for r in reversed(_rows(path)) if r.get("key") == key and r.get("status") == "created"), None)
        if done:
            return dict(done["result"], deduplicated=True, key=key)
        if adapter is None:
            import ah
            adapter, mod = ah.load_adapter(home)
        operation_id = str(uuid.uuid5(uuid.NAMESPACE_URL, "ah-ticket-create:" + key))
        _append(path, {"at": time.time(), "key": key, "status": "pending", "project": project, "title": title[:120]})
        try:
            org = adapter.org_id()
            projects = adapter.call("list_projects", {"orgId": org})
            match = next((p for p in (projects.get("projects") or []) if isinstance(p, dict) and p.get("slug") == project),
                         None) if isinstance(projects, dict) else None
            if match is None:
                raise TicketCreateError("project_not_found", "project %r is not visible to this credential" % project, 3)
            args = {"projectId": match["id"], "title": title, "description": body, "type": type_,
                    "operationId": operation_id}
            if priority:
                args["priority"] = priority
            data = adapter.call("create_issue", args)
        except Exception as error:
            if isinstance(error, TicketCreateError):
                _append(path, {"at": time.time(), "key": key, "status": "failed", "why": error.code})
                raise
            unavailable = mod.TicketSystemUnavailable if mod else ()
            outcome = "uncertain" if isinstance(error, unavailable) else "failed"
            _append(path, {"at": time.time(), "key": key, "status": outcome, "why": type(error).__name__})
            if isinstance(error, unavailable):
                raise TicketCreateError("ticket_unavailable", "%s; retry with the same --key %s (the server dedupes on it)"
                                        % (str(error)[:200], key), 3)
            raise
        if not isinstance(data, dict) or "__error__" in data:
            code = data.get("__error__", "error") if isinstance(data, dict) else "error"
            _append(path, {"at": time.time(), "key": key, "status": "failed", "why": str(code)})
            raise TicketCreateError("ticket_unavailable", "GoodQA create_issue failed (%s)" % code, 3)
        issue = data.get("issue", data)
        number = issue.get("number") if isinstance(issue, dict) else None
        if not isinstance(number, int):
            _append(path, {"at": time.time(), "key": key, "status": "uncertain", "why": "no number in response"})
            raise TicketCreateError("ticket_unavailable", "GoodQA answered without a ticket number; retry with --key %s" % key, 3)
        result = {"ok": True, "ticket": "GoodQA %s#%d" % (project, number), "number": number, "id": issue.get("id"),
                  "project": project, "title": title}
        _append(path, {"at": time.time(), "key": key, "status": "created", "result": result})
        return dict(result, deduplicated=False, key=key)
    finally:
        os.close(lock)
