"""`ah worktree-remove`: remove ONE verified linked git worktree on this Mac or on t2-dev (goodqa#15565).

command_guard refuses `git worktree remove` outside a few shapes, and it cannot see another host's files. The only
thing this command does is hand a literal path to the fixed verifier `command_guard.py remove-worktree` ON the target
host: the same checks the guard's own exemption applies (a registered linked worktree, clean, nothing private that
would be lost, its exact HEAD live on an allowlisted remote), a scope check (strictly under the home directory, never
harness or credential state), an identity re-check around the verification, and then the plain non-forced
`git worktree remove`. Nothing here accepts a flag that relaxes a check; there is no --force.

`--remote-heads-from HOST` is for a private repository the target cannot read: ah runs `git ls-remote --heads` for the
URLs the target reports (github.com only, strict pattern) on HOST, which has credentials, and passes the refs to the
verifier on stdin. The verifier still checks the exact HEAD against them.

Every call writes an audit row before it acts (fail closed) and a row with the outcome.
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
PATH_RE = re.compile(r"/[A-Za-z0-9_@+=:,.-]+(?:/[A-Za-z0-9_@+=:,.-]+)*")
GITHUB_URL = re.compile(r"(?:https://github\.com/[\w.-]+/[\w.-]+?(?:\.git)?|git@github\.com:[\w.-]+/[\w.-]+?(?:\.git)?)")
SHA = re.compile(r"[0-9a-f]{40,64}")


class WorktreeError(Exception):
    def __init__(self, code, message, exit_code=2):
        super().__init__(message)
        self.code, self.exit_code = code, exit_code


def _now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _redact(text):
    return re.sub(r"(?i)(token|password|secret|key)[=: ]+\S+", r"\1=[redacted]", str(text))


def audit(home, record):
    """Append one JSON row; raises when it cannot (the caller stops before acting)."""
    path = Path(home) / ".agent-harness" / "worktree-audit.jsonl"
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    record = dict(record, at=_now())
    if record.get("reason"):
        record["reason"] = _redact(record["reason"])[:MAX_REASON]
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


def _argv(host, sub, path, extra=()):
    tail = ["verify-worktree" if sub == "verify" else "remove-worktree", "--path", path, *extra]
    if host == "local":
        return [sys.executable, "-I", str(HERE / "command_guard.py"), *tail]
    cmd = "python3 -I .claude/hooks/command_guard.py " + " ".join(shlex.quote(t) for t in tail)
    return ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "--", host, cmd]


def _call(runner, host, sub, path, heads=None, expect_head=None):
    extra = []
    if heads is not None:
        extra.append("--heads-stdin")
    if expect_head:
        extra += ["--expect-head", expect_head]
    try:
        done = runner(_argv(host, sub, path, extra), capture_output=True, text=True, timeout=420,
                      input=json.dumps(heads) if heads is not None else None)
        data = json.loads(done.stdout)
    except (OSError, subprocess.SubprocessError, ValueError):
        raise WorktreeError("host_unreachable", "could not run the verifier on %s" % host, 3)
    if not isinstance(data, dict) or not isinstance(data.get("removable"), bool):
        raise WorktreeError("host_unreachable", "unexpected answer from the verifier on %s (nothing removed)" % host, 3)
    if data.get("removed") not in (None, True, False):
        raise WorktreeError("host_unreachable", "malformed answer from %s (nothing is assumed removed)" % host, 3)
    return data


def fetch_heads(runner, source, urls):
    """{url: {ref: sha}} from `git ls-remote --heads` run on `source` (credentialed), only for github.com URLs."""
    heads = {}
    for url in urls:
        if not isinstance(url, str) or not GITHUB_URL.fullmatch(url):
            raise WorktreeError("bad_request", "--remote-heads-from reads only github.com remotes; refusing a remote URL")
        cmd = ["git", "-c", "protocol.allow=never", "-c", "protocol.https.allow=always", "-c", "protocol.ssh.allow=always",
               "ls-remote", "--heads", "--", url]
        if source == "local":
            argv, env = cmd, dict(os.environ, GIT_TERMINAL_PROMPT="0")
        else:
            argv, env = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "--", source,
                         "GIT_TERMINAL_PROMPT=0 " + " ".join(shlex.quote(t) for t in cmd)], None
        try:
            done = runner(argv, capture_output=True, text=True, timeout=60, env=env)
        except (OSError, subprocess.SubprocessError):
            raise WorktreeError("host_unreachable", "ls-remote on %s did not run" % source, 3)
        if done.returncode != 0:
            raise WorktreeError("remote_unreadable", "ls-remote on %s could not read the remote" % source, 3)
        refs = {}
        for line in done.stdout.splitlines():
            sha, _, ref = line.partition("\t")
            if SHA.fullmatch(sha) and ref.startswith("refs/heads/"):
                refs[ref] = sha
        if not refs:
            raise WorktreeError("remote_unreadable", "ls-remote on %s returned no branches" % source, 3)
        heads[url] = refs
    return heads


def remove(host, path, reason, heads_from=None, session="", agent="", home=None, runner=subprocess.run):
    if host not in HOSTS:
        raise WorktreeError("bad_request", "--host must be one of %s" % ", ".join(HOSTS))
    if heads_from is not None and heads_from not in HOSTS:
        raise WorktreeError("bad_request", "--remote-heads-from must be one of %s" % ", ".join(HOSTS))
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
                     "heads_from": heads_from, "caller": who})
    except OSError:
        raise WorktreeError("audit_failed", "could not write the audit row; nothing was removed", 3)
    heads = expect = None
    if heads_from is not None:
        report = _call(runner, host, "verify", path)
        expect = report.get("head") if isinstance(report.get("head"), str) and SHA.fullmatch(report["head"]) else None
        if not report.get("removable") and not str(report.get("reason") or "").startswith("the remote did not answer"):
            audit(home, {"event": "refused", "run": run_id, "host": host, "path": path, "why": report.get("reason")})
            return {"ok": False, "run": run_id, "host": host, "path": path, "removed": False,
                    "reason": report.get("reason")}
        urls = [u for group in (report.get("urls") or {}).values() for u in (group if isinstance(group, list) else [])]
        if not urls or not expect:
            raise WorktreeError("remote_unreadable", "the verifier reported no remote URL or HEAD to check", 3)
        heads = fetch_heads(runner, heads_from, urls)
    result = _call(runner, host, "remove", path, heads=heads, expect_head=expect)
    removed = result.get("removed") is True and result.get("removable") is True
    audit(home, {"event": "result", "run": run_id, "host": host, "path": path, "removed": removed,
                 "head": result.get("head"), "freed_bytes": result.get("freed_bytes"), "why": result.get("reason")})
    return {"ok": removed, "run": run_id, "host": host, "path": path, "removed": removed, "head": result.get("head"),
            "freed_bytes": result.get("freed_bytes"), "reason": result.get("reason")}
