"""`ah worktree-remove`: remove ONE verified linked git worktree on this Mac or on t2-dev (goodqa#15565).

command_guard refuses `git worktree remove` outside a few shapes, and it cannot see another host's files. The only
thing this command does is hand a literal path to the fixed verifier `command_guard.py remove-worktree` ON the target
host: the same checks the guard's own exemption applies (a registered linked worktree, clean, nothing private that
would be lost, its exact HEAD live on an allowlisted remote), a scope check (strictly under the home directory, never
harness or credential state), a check that no process works inside it, an identity re-check around the verification,
and then the plain non-forced `git worktree remove`. Nothing here accepts a flag that relaxes a check; there is no
--force, and the caller cannot supply branch refs: `--remote-auth` only makes the verifier read the remote with the
target host's OWN credentials (a private repository), in a scrubbed environment (red-team of PR 212, F1 and F2).

The caller's audit row is written before anything runs (fail closed) and again with the outcome; the verifier writes its
own row on the target host.
"""
from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
import sys
import time
import uuid
from pathlib import Path

HERE = Path(__file__).resolve().parent
REMOTE_HOSTS = ("t2-dev",)
HOSTS = ("local",) + REMOTE_HOSTS
MAX_REASON = 500
VERIFIER_VERSION = 2
PATH_RE = re.compile(r"/[A-Za-z0-9_@+=:,.-]+(?:/[A-Za-z0-9_@+=:,.-]+)*")


class WorktreeError(Exception):
    def __init__(self, code, message, exit_code=2):
        super().__init__(message)
        self.code, self.exit_code = code, exit_code


def _now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _redact(text):
    return re.sub(r"(?i)(token|password|secret|key|authorization)[=: ]+\S+", r"\1=[redacted]", str(text))


def audit(home, record):
    """Append one JSON row; raises when it cannot (the caller stops before acting)."""
    path = Path(home) / ".agent-harness" / "worktree-audit.jsonl"
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    record = dict(record, at=_now(), by="ah")
    for key in ("reason", "why"):
        if record.get(key):
            record[key] = _redact(record[key])[:MAX_REASON]
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        os.fchmod(fd, 0o600)
        os.write(fd, (json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n").encode())
        os.fsync(fd)
    finally:
        os.close(fd)


def check_path(path):
    if not isinstance(path, str) or not 2 <= len(path) <= 1024 or not PATH_RE.fullmatch(path) or ".." in path.split("/"):
        raise WorktreeError("bad_request", "--path must be one literal absolute path (letters, digits and _@+=:,.- only, "
                            "no dot segments, no trailing slash)")
    return path


def _argv(host, path, authenticated):
    tail = ["remove-worktree", "--path", path] + (["--remote-auth"] if authenticated else [])
    if host == "local":
        return [sys.executable, "-I", str(HERE / "command_guard.py"), *tail]
    cmd = "python3 -I .claude/hooks/command_guard.py " + " ".join(shlex.quote(t) for t in tail)
    return ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "--", host, cmd]


# The longest a healthy call can take, from command_guard's own bounds: verification VERIFY_SECONDS (120), the process
# scan (lsof 20), git's removal REMOVE_SECONDS (900), the ssh connect (10) and slack for JSON and startup (50). A large
# removal is a long call: run it in the background, it is not meant for a foreground tool call.
VERIFY_SECONDS, SCAN_SECONDS, REMOVE_SECONDS, CONNECT_SECONDS, SLACK_SECONDS = 120, 20, 900, 10, 50
CALL_TIMEOUT = VERIFY_SECONDS + SCAN_SECONDS + REMOVE_SECONDS + CONNECT_SECONDS + SLACK_SECONDS


def _call(runner, host, path, authenticated):
    try:
        done = runner(_argv(host, path, authenticated), capture_output=True, text=True, timeout=CALL_TIMEOUT)
        data = json.loads(done.stdout)
    except (OSError, subprocess.SubprocessError, ValueError):
        raise WorktreeError("host_unreachable", "could not run the verifier on %s" % host, 3)
    if not isinstance(data, dict) or not isinstance(data.get("removable"), bool):
        raise WorktreeError("host_unreachable", "unexpected answer from the verifier on %s (nothing removed)" % host, 3)
    if data.get("verifier") != VERIFIER_VERSION:
        raise WorktreeError("verifier_outdated", "the verifier on %s is not version %d: install command_guard.py there "
                            "(nothing was removed)" % (host, VERIFIER_VERSION), 3)
    if data.get("removed") not in (None, True, False):
        raise WorktreeError("host_unreachable", "malformed answer from %s (nothing is assumed removed)" % host, 3)
    return data


def remove(host, path, reason, authenticated=False, session="", agent="", home=None, runner=subprocess.run):
    if host not in HOSTS:
        raise WorktreeError("bad_request", "--host must be one of %s" % ", ".join(HOSTS))
    path = check_path(path)
    reason = (reason or "").strip()
    if not reason or len(reason) > MAX_REASON or re.search(r"[\x00-\x08\x0b-\x1f\x7f]", reason):
        raise WorktreeError("reason_required", "--reason is mandatory, printable and at most %d characters" % MAX_REASON)
    if host == "local":
        cwd = os.path.realpath(os.getcwd())
        if cwd == path or cwd.startswith(path + os.sep):
            raise WorktreeError("bad_request", "the current directory is inside the worktree being removed")
    home = Path(home or Path.home())
    run_id = "wtr-" + uuid.uuid4().hex[:12]
    who = {"session": session or None, "agent": agent or None}
    try:
        audit(home, {"event": "start", "run": run_id, "host": host, "path": path, "reason": reason,
                     "remote_auth": bool(authenticated), "caller": who})
    except OSError:
        raise WorktreeError("audit_failed", "could not write the audit row; nothing was removed", 3)
    # Once the runner has been started the outcome is UNKNOWN until the verifier answers: a killed ssh client does not stop
    # the remote command, so "no answer" is never recorded as "not removed" (removed: null).
    outcome = {"event": "result", "run": run_id, "host": host, "path": path, "removed": None,
               "why": "no answer from the verifier (outcome unknown)"}
    try:
        result = _call(runner, host, path, authenticated)
        removed = result.get("removed") is True and result.get("removable") is True
        outcome.update(removed=removed, head=result.get("head"), freed_bytes=result.get("freed_bytes"),
                       directory_removed=result.get("directory_removed"),
                       registry_entry_left=result.get("registry_entry_left"), why=result.get("reason"))
    except WorktreeError as error:
        outcome.update(why="%s: %s (outcome unknown, check the host)" % (error.code, error))
        raise
    finally:
        try:
            audit(home, outcome)
        except OSError:
            outcome["audit_warning"] = "the outcome row could not be written"
    answer = {"ok": removed, "run": run_id, "host": host, "path": path, "removed": removed, "head": result.get("head"),
              "freed_bytes": result.get("freed_bytes"), "reason": _redact(result.get("reason") or "") or None,
              "directory_removed": result.get("directory_removed"),
              "registry_entry_left": result.get("registry_entry_left")}
    if "audit_warning" in outcome:
        answer["audit_warning"] = outcome["audit_warning"]
    return answer
