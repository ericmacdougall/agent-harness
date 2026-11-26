"""`ah worktree-remove`: free ONE dead linked git worktree on this machine or a configured remote host.

It hands a literal path to the fixed verifier `command_guard.py free-worktree` ON the target host, which applies the
user's rules of 2026-11-24 (see command_guard.free_worktree):
  * any agent: a worktree with no uncommitted changes whose HEAD is on a remote branch (or merged), or whose owning
    session has ended, is removed (a commit only it reaches is saved to refs/rescue/<name> first);
  * --rescue (the guard admits it only for a supervisor of the project or a Fable/Astra caller): uncommitted changes
    go to a patch under the caller's work dir and unpushed commits to refs/rescue/<name>, then it is removed --force.
A process working inside the worktree still stops it. No ticket, WAL note or reason is required (--reason is logged
when given). `--remote-auth` is accepted for old callers and ignored: the new verifier reads no remote.

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


def _remote_hosts():
    """~/.agent-harness/local.json `remote_worktree_hosts` (plain host names); none by default."""
    try:
        if str(HERE) not in sys.path:
            sys.path.insert(0, str(HERE))
        import ah_local  # noqa: PLC0415
        return tuple(h for h in ah_local.str_list("remote_worktree_hosts") if re.fullmatch(r"[A-Za-z0-9._-]{1,60}", h)
                     and h != "local")
    except Exception:  # noqa: BLE001
        return ()


REMOTE_HOSTS = _remote_hosts()
HOSTS = ("local",) + REMOTE_HOSTS
MAX_REASON = 500
VERIFIER_VERSION = 3
PATH_RE = re.compile(r"/[A-Za-z0-9_@+=:,.-]+(?:/[A-Za-z0-9_@+=:,.-]+)*")


class WorktreeError(Exception):
    def __init__(self, code, message, exit_code=2):
        super().__init__(message)
        self.code, self.exit_code = code, exit_code


def _now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _redact(text):
    return re.sub(r"(?i)(token|password|secret|key|authorization)[=: ]+\S+", r"\1=[redacted]", str(text))


def _skipped(result):
    """The verifier's list of unreadable processes it skipped (goodqa#15870), as at most 20 short printable strings, or None."""
    items = result.get("skipped_processes")
    if not isinstance(items, list):
        return None
    return [re.sub(r"[^\x20-\x7e]", "?", str(item))[:60] for item in items[:20]]


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


def _argv(host, path, authenticated=False, rescue=False, session="", dry_run=False):
    tail = ["free-worktree", "--path", path] + (["--rescue"] if rescue else []) + (["--dry-run"] if dry_run else [])
    if session and re.fullmatch(r"[0-9A-Fa-f-]{8,64}", session):
        tail += ["--session", session]
    if host == "local":
        return [sys.executable, "-I", str(HERE / "command_guard.py"), *tail]
    cmd = "python3 -I .claude/hooks/command_guard.py " + " ".join(shlex.quote(t) for t in tail)
    return ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "--", host, cmd]


# The longest a healthy call can take, from command_guard's own bounds: verification VERIFY_SECONDS (120), the process
# scan (lsof 20), git's removal REMOVE_SECONDS (900), the ssh connect (10) and slack for JSON and startup (50). A large
# removal is a long call: run it in the background, it is not meant for a foreground tool call.
VERIFY_SECONDS, SCAN_SECONDS, REMOVE_SECONDS, CONNECT_SECONDS, SLACK_SECONDS = 120, 20, 900, 10, 50
CALL_TIMEOUT = VERIFY_SECONDS + SCAN_SECONDS + REMOVE_SECONDS + CONNECT_SECONDS + SLACK_SECONDS


UNKNOWN = "the outcome is unknown: the removal may already have happened, check the host before retrying"


def _call(runner, host, path, authenticated, rescue=False, session="", dry_run=False):
    """Run the verifier. Once the runner has started, every failure here leaves the outcome UNKNOWN: the remote command
    keeps running after an ssh client dies and a garbled answer may still come from a verifier that removed the tree,
    so no message from here says that nothing was removed."""
    try:
        done = runner(_argv(host, path, authenticated, rescue, session, dry_run), capture_output=True, text=True,
                      timeout=CALL_TIMEOUT)
        data = json.loads(done.stdout)
    except (OSError, subprocess.SubprocessError, ValueError):
        raise WorktreeError("host_unreachable", "could not run the verifier on %s (%s)" % (host, UNKNOWN), 3)
    if not isinstance(data, dict) or not isinstance(data.get("removable"), bool):
        raise WorktreeError("host_unreachable", "unexpected answer from the verifier on %s (%s)" % (host, UNKNOWN), 3)
    if data.get("verifier") != VERIFIER_VERSION:
        raise WorktreeError("verifier_outdated", "the verifier on %s is not version %d: install command_guard.py there "
                            "(%s)" % (host, VERIFIER_VERSION, UNKNOWN), 3)
    if data.get("removed") not in (None, True, False):
        raise WorktreeError("host_unreachable", "malformed answer from %s (%s)" % (host, UNKNOWN), 3)
    if data["removable"] is False and data.get("removed") is True:
        # a verifier that refused cannot also have removed: the answer contradicts itself (receipt r5 N1)
        raise WorktreeError("host_unreachable", "contradictory answer from %s (%s)" % (host, UNKNOWN), 3)
    return data


def remove(host, path, reason=None, authenticated=False, session="", agent="", home=None, runner=subprocess.run,
           rescue=False, dry_run=False):
    if host not in HOSTS:
        raise WorktreeError("bad_request", "--host must be one of %s" % ", ".join(HOSTS))
    path = check_path(path)
    reason = re.sub(r"[\x00-\x08\x0b-\x1f\x7f]", " ", (reason or "").strip())[:MAX_REASON] or "not given"
    if host == "local":
        cwd = os.path.realpath(os.getcwd())
        if cwd == path or cwd.startswith(path + os.sep):
            raise WorktreeError("bad_request", "the current directory is inside the worktree being removed")
    home = Path(home or Path.home())
    run_id = "wtr-" + uuid.uuid4().hex[:12]
    who = {"session": session or None, "agent": agent or None}
    try:
        audit(home, {"event": "start", "run": run_id, "host": host, "path": path, "reason": reason,
                     "rescue": bool(rescue), "dry_run": bool(dry_run), "caller": who})
    except OSError:
        raise WorktreeError("audit_failed", "could not write the audit row; nothing was run, nothing was removed", 3)
    # Once the runner has been started the outcome is UNKNOWN until the verifier answers: a killed ssh client does not stop
    # the remote command, so "no answer" is never recorded as "not removed" (removed: null).
    outcome = {"event": "result", "run": run_id, "host": host, "path": path, "removed": None,
               "why": "no answer from the verifier (outcome unknown)"}
    try:
        result = _call(runner, host, path, authenticated, rescue, session, dry_run)
        # A definite outcome needs a definite answer: `removable: false` is a refusal (nothing ran); `removable: true`
        # needs a real boolean `removed`, and a null or missing one is an unknown outcome (red-team r4 F2).
        partly = False
        if result.get("removable") is False:
            removed = False
        elif isinstance(result.get("removed"), bool):
            removed = result["removed"]
            if removed is False:
                # removable true and not removed: the removal STARTED and did not complete (a timeout, a git error after it
                # began deleting). The tree may be partly deleted, and the verifier cannot always tell a clean failure
                # from a partial one, so it is not recorded as a definite "not removed" (receipt r5 N2).
                removed, partly = None, True
        else:
            removed = None
        if partly:
            why = (result.get("reason") or "") + " (the removal started and did not complete: the worktree may be partly " \
                                                 "deleted, check the host before retrying)"
        else:
            why = result.get("reason") if removed is not None else (result.get("reason") or "") + " (" + UNKNOWN + ")"
        outcome.update(removed=removed, head=result.get("head"), freed_bytes=result.get("freed_bytes"),
                       directory_removed=result.get("directory_removed"),
                       registry_entry_left=result.get("registry_entry_left"), why=why,
                       skipped_processes=_skipped(result))
    except WorktreeError as error:
        outcome.update(why="%s: %s (outcome unknown, check the host)" % (error.code, error))
        raise
    finally:
        try:
            audit(home, outcome)
        except OSError:
            outcome["audit_warning"] = "the outcome row could not be written"
    answer = {"ok": removed is True, "run": run_id, "host": host, "path": path, "removed": removed,
              "head": result.get("head"), "freed_bytes": result.get("freed_bytes"),
              "reason": _redact(outcome["why"] or "") or None,
              "directory_removed": result.get("directory_removed"),
              "registry_entry_left": result.get("registry_entry_left"),
              "skipped_processes": outcome.get("skipped_processes"),
              "rescue_ref": result.get("rescue_ref"), "patch": result.get("patch")}
    if dry_run:
        answer.update(ok=bool(result.get("removable")), removed=False, would=result.get("would"))
    if "audit_warning" in outcome:
        answer["audit_warning"] = outcome["audit_warning"]
    step = next_step(result)
    if step:
        answer["next"] = step
    return answer


NEXT_STALE = ("run `git fetch --prune <the remote that holds the deleted branch>` in the registry repository (the checkout "
              "the worktree was added from) on the same host first, but only when every fetch refspec of that remote "
              "writes under refs/remotes/<that remote>/ and pruneTags is not set; prune deletes local branches or tags "
              "through any other destination (for example +refs/*:refs/* or +refs/heads/*:refs/heads/up/*). Then "
              "repeat the same ah worktree-remove call")


def next_step(result):
    """The fixed next step for a stale-tracking-ref refusal (goodqa#16943), or None. The verifier keeps that rule. The
    text names no path, host or remote: a value read from the repository can be wrong or harmful to run (#333 review
    rounds 1 and 2), so the caller fills in the remote it knows."""
    if result.get("removable") is not False or "stale or names a moved" not in str(result.get("reason") or ""):
        return None
    return NEXT_STALE
