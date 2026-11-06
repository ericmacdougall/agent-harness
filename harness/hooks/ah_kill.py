"""ah kill: signal your own runaway processes, with refusals no flag overrides and an audit row for every pid.

Flow per request: probe every target (cmdline, cwd, user, start, parent) -> refuse the unsafe ones -> write the
audit intent rows (fail closed: no audit row, no signal) -> SIGTERM (children first with --tree) -> after the grace
period SIGKILL whatever is left -> write one result row per pid. Before every signal the pid identity (start time and
command) is probed again, so a reused pid is never hit.

Audit: ~/.agent-harness/kill-audit.jsonl (append-only, 0600) and the caller's WAL (best effort, reported).
"""
from __future__ import annotations

import datetime as dt
import fcntl
import hashlib
import json
import os
import pwd
import re
import shlex
import signal
import subprocess
import sys
import time
import uuid
from pathlib import Path

HOSTS = ("dev2", "t2-dev", "ah-mac-mini")
MAX_PIDS = 64
MAX_TREE = 256
MAX_CMD = 300
MAX_REASON = 500
DEFAULT_GRACE = 10.0
MAX_GRACE = 300.0
# Executable base names (case-insensitive) that are never signalled.
PROTECTED_COMM = {"netwatch", "iterm2", "alacritty", "kitty", "wezterm", "gnome-terminal", "ssh-agent", "sshd", "launchd", "systemd", "init", "claude", "codex", "finder", "terminal", "tailscale",
                  "tailscaled", "dropbox", "goodqa", "solve", "google chrome", "google chrome helper", "tmux", "screen",
                  "login", "sudo"}
# App bundles of the user's GUI apps. "Google Chrome for Testing.app" deliberately does not match Chrome.
PROTECTED_PATH = re.compile(
    r"/(Google Chrome|Terminal|Finder|GoodQA[^/]*|Tailscale[^/]*|Dropbox[^/]*|Solve[^/]*)\.app(/|$)", re.I)
SYSTEM_PATH = re.compile(r"^(/System/|/usr/libexec/|/sbin/|/usr/sbin/)")
SHELLS = {"zsh", "bash", "sh", "fish", "dash", "ksh", "tcsh", "csh", "-zsh", "-bash"}
PID_LIST = re.compile(r"[0-9]+(?:,[0-9]+)*")


class KillError(Exception):
    def __init__(self, code, message, exit_code=2):
        super().__init__(message)
        self.code, self.exit_code = code, exit_code


def _redact(text: str) -> str:
    try:
        import redact
        return redact.redact(text)
    except Exception:  # a missing redactor must never leak: drop the text instead
        return "[command withheld: redactor unavailable]"


def _clip(text: str, limit: int = MAX_CMD) -> str:
    text = _redact(text or "")
    return text if len(text) <= limit else text[:limit] + "...[+%d]" % (len(text) - limit)


def _now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat()


class Probe:
    """Process facts from ps (and lsof for the cwd on macOS). Tests replace this with a fake."""

    def _ps(self, *fields, pid=None):
        argv = ["ps", "-o", ",".join(f + "=" for f in fields)]
        argv += ["-p", str(pid)] if pid is not None else ["-A"]
        env = dict(os.environ, LC_ALL="C", LANG="C")
        try:
            r = subprocess.run(argv, capture_output=True, text=True, timeout=15, env=env)
        except (OSError, subprocess.SubprocessError):
            raise KillError("probe_failed", "ps could not be run; nothing was signalled")
        if r.returncode not in (0, 1) or (r.returncode == 1 and r.stderr.strip()):
            raise KillError("probe_failed", "ps failed (exit %d); nothing was signalled" % r.returncode)
        return r.stdout

    def info(self, pid: int):
        """dict or None when the pid does not exist."""
        out = self._ps("ppid", "uid", "stat", "lstart", "command", pid=pid).strip("\n")
        if not out.strip():
            return None
        m = re.match(r"\s*(\d+)\s+(-?\d+)\s+(\S+)\s+(\w{3}\s+\w{3}\s+\d+\s+[\d:]{8}\s+\d{4})\s+(.*)$", out.split("\n")[0])
        if not m:
            return None
        comm = self._ps("comm", pid=pid).strip()
        return {"pid": pid, "ppid": int(m.group(1)), "uid": int(m.group(2)), "stat": m.group(3),
                "start": " ".join(m.group(4).split()), "command": m.group(5).strip(), "comm": comm}

    def user(self, uid: int) -> str:
        try:
            return pwd.getpwuid(uid).pw_name
        except KeyError:
            return str(uid)

    def cwd(self, pid: int):
        if sys.platform.startswith("linux"):
            try:
                return os.readlink("/proc/%d/cwd" % pid)
            except OSError:
                return None
        try:
            r = subprocess.run(["lsof", "-a", "-p", str(pid), "-d", "cwd", "-Fn"], capture_output=True, text=True,
                               timeout=8)
        except (OSError, subprocess.SubprocessError):
            return None
        for line in r.stdout.splitlines():
            if line.startswith("n"):
                return line[1:]
        return None

    def table(self):
        """{pid: ppid} for every process."""
        rows = {}
        for line in self._ps("pid", "ppid").splitlines():
            parts = line.split()
            if len(parts) == 2 and parts[0].isdigit() and parts[1].isdigit():
                rows[int(parts[0])] = int(parts[1])
        return rows

    def signal(self, pid: int, sig: int) -> None:
        os.kill(pid, sig)


def fingerprint(info) -> str:
    return hashlib.sha256((info["start"] + "\0" + info["command"]).encode("utf-8", "replace")).hexdigest()[:16]


def protected_ids(probe, own_pid: int):
    """The caller's own pid, every ancestor, and the main session process (CLAUDE_PID)."""
    ids, pid, table = {own_pid}, own_pid, None
    for _ in range(64):
        info = probe.info(pid)
        if not info or info["ppid"] <= 1:
            break
        pid = info["ppid"]
        if pid in ids:
            break
        ids.add(pid)
    for var in ("CLAUDE_PID", "AH_MAIN_PID"):
        value = os.environ.get(var, "")
        if value.isdigit():
            ids.add(int(value))
    return ids


def refusal(info, my_uid: int, protected: set):
    """Reason string when this process may never be signalled, else None. No flag reaches this function."""
    pid = info["pid"]
    if pid <= 1:
        return "pid 1 and below are never signalled"
    if pid in protected:
        return "the caller's own process, an ancestor or the main session"
    if info["uid"] == 0:
        return "root-owned (kernel or system process)"
    if info["uid"] != my_uid:
        return "owned by another user"
    comm = info.get("comm") or ""
    first = (info.get("command") or "").split(" ")[0]
    if SYSTEM_PATH.match(comm) or SYSTEM_PATH.match(first) or SYSTEM_PATH.match(info.get("command") or ""):
        return "system process (/System or /usr/libexec)"
    base = os.path.basename(comm).lower()
    if base in PROTECTED_COMM or os.path.basename(first).lower() in {"sshd", "launchd"}:
        return "protected process (%s)" % base
    if base in SHELLS and (comm.startswith("-") or len((info.get("command") or "").split()) <= 1):
        return "interactive shell"
    if PROTECTED_PATH.search(comm) or PROTECTED_PATH.search(info.get("command") or ""):
        return "protected GUI app"
    return None


def descendants(table: dict, root: int):
    """Depth-first, deepest last in discovery order; returned reversed so children come before parents."""
    kids = {}
    for pid, ppid in table.items():
        kids.setdefault(ppid, []).append(pid)
    order, stack, seen = [], [root], {root}
    while stack and len(order) < MAX_TREE:
        cur = stack.pop()
        for c in sorted(kids.get(cur, [])):
            if c not in seen:
                seen.add(c)
                order.append(c)
                stack.append(c)
    return list(reversed(order))


class Audit:
    def __init__(self, home: Path, wal_path=None, caller=None):
        self.path = home / ".agent-harness" / "kill-audit.jsonl"
        self.wal_path, self.caller = wal_path, caller
        self.wal_ok = None

    def row(self, record: dict) -> None:
        """Append to the audit log; raises when it cannot (callers fail closed before any signal)."""
        if record.get("reason"):
            record["reason"] = _redact(record["reason"])
        record = dict(record, at=_now_iso(), caller=self.caller)
        line = (json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n").encode()
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            os.fchmod(fd, 0o600)
            fcntl.flock(fd, fcntl.LOCK_EX)
            os.write(fd, line)
            os.fsync(fd)
        finally:
            os.close(fd)

    def wal(self, note: str) -> None:
        if not self.wal_path:
            return
        try:
            import wal
            wal.append(Path(self.wal_path), {"at": _now_iso(), "event": "status", "id": "w" + uuid.uuid4().hex[:11],
                                             "note": note[:3900]})
            self.wal_ok = self.wal_ok is not False
        except Exception:
            self.wal_ok = False


def default_wal(home: Path, session: str, explicit=None):
    if explicit:
        return explicit
    if session and re.fullmatch(r"[A-Za-z0-9._-]{1,120}", session):
        return str(home / ".claude" / "wals" / session / "main.jsonl")
    return None


def parse_pids(text: str):
    if not PID_LIST.fullmatch(text or ""):
        raise KillError("bad_request", "--pid needs digits: N[,N...]")
    pids = []
    for p in text.split(","):
        n = int(p)
        if n > 4194304:
            raise KillError("bad_request", "pid out of range")
        if n not in pids:
            pids.append(n)
    if len(pids) > MAX_PIDS:
        raise KillError("bad_request", "at most %d pids per call" % MAX_PIDS)
    return pids


def snapshot(probe, pid, my_uid, protected, root=None, role="target"):
    info = probe.info(pid)
    if info is None:
        return {"pid": pid, "role": role, "root": root, "status": "gone", "detail": "no such process"}
    rec = {"pid": pid, "role": role, "root": root, "ppid": info["ppid"], "user": probe.user(info["uid"]),
           "uid": info["uid"], "start": info["start"], "cmd": _clip(info["command"]), "cwd": probe.cwd(pid),
           "id": fingerprint(info), "_info": info}
    why = refusal(info, my_uid, protected)
    if why:
        rec["status"], rec["detail"] = "refused", why
    elif info["stat"].startswith("Z"):
        rec["status"], rec["detail"] = "gone", "already a zombie"
    return rec


def same_process(probe, rec) -> bool:
    now = probe.info(rec["pid"])
    if not now or fingerprint(now) != rec["id"] or now["stat"].startswith("Z"):
        return False
    # A tree child must still hang under the parent it had when the tree was read.
    return rec.get("role") != "child" or now["ppid"] == rec["ppid"]


def alive(probe, rec) -> bool:
    try:
        now = probe.info(rec["pid"])
    except KillError:
        return True  # cannot tell: never report an exit that was not seen
    return bool(now) and fingerprint(now) == rec["id"] and not now["stat"].startswith("Z")


def kill_local(pids, reason, tree=False, grace=DEFAULT_GRACE, home=None, probe=None, sleep=time.sleep,
               clock=time.monotonic, session="", agent="", wal_path=None, via=None, own_pid=None):
    reason = (reason or "").strip()
    if not reason:
        raise KillError("reason_required", "--reason is mandatory and must not be empty")
    if len(reason) > MAX_REASON:
        raise KillError("bad_request", "--reason is longer than %d characters" % MAX_REASON)
    if not 0 <= grace <= MAX_GRACE:
        raise KillError("bad_request", "--grace must be 0..%d seconds" % int(MAX_GRACE))
    home = home or Path.home()
    probe = probe or Probe()
    own_pid = own_pid or os.getpid()
    my_uid = os.getuid()
    caller = {"session": session or None, "agent": agent or None, "ppid_chain_root": own_pid,
              "user": probe.user(my_uid), "via": via}
    audit = Audit(home, default_wal(home, session, wal_path), caller)
    protected = protected_ids(probe, own_pid)
    run_id = "k" + uuid.uuid4().hex[:12]
    table = probe.table() if tree else {}
    plan, seen = [], set()
    for root in pids:
        batch = []
        for child in (descendants(table, root) if tree else []):
            batch.append(snapshot(probe, child, my_uid, protected, root=root, role="child"))
        batch.append(snapshot(probe, root, my_uid, protected, role="target"))
        if tree and batch[-1].get("status") == "refused":
            # A refused root must not be bypassed by killing its children: the user asked for the tree.
            for rec in batch[:-1]:
                if "status" not in rec:
                    rec["status"], rec["detail"] = "refused", "root of the tree was refused"
        for rec in batch:
            if rec["pid"] not in seen:
                seen.add(rec["pid"])
                plan.append(rec)
    live = [r for r in plan if "status" not in r]
    # Intent rows first: fail closed. Nothing is signalled unless every row is on disk.
    for rec in plan:
        audit.row({"event": "intent" if rec in live else "refused", "run": run_id, "reason": reason,
                   "tree": tree, "grace": grace, **_public(rec)})
    audit.wal("ah kill %s: reason=%s targets=%s" % (run_id, _clip(reason, 200), ", ".join(
        "%d(%s)%s" % (r["pid"], os.path.basename((r.get("cmd") or "").split(" ")[0]), "" if r in live else " " + r["status"].upper())
        for r in plan)))
    # Phase 1: SIGTERM in plan order (children before their root).
    for rec in live:
        _send(probe, audit, run_id, rec, signal.SIGTERM, "TERM")
    # Phase 2: wait out the grace, then SIGKILL survivors.
    deadline = clock() + grace
    pending = [r for r in live if r.get("sent")]
    while pending and clock() < deadline:
        pending = [r for r in pending if alive(probe, r)]
        if pending:
            sleep(min(0.1, max(0.0, deadline - clock())))
    for rec in live:
        if not rec.get("sent"):
            continue
        if not alive(probe, rec):
            rec["status"], rec["detail"] = "exited", "after SIGTERM"
            continue
        if _send(probe, audit, run_id, rec, signal.SIGKILL, "KILL"):
            for _ in range(20):  # SIGKILL cannot be caught, but the exit is not instant
                if not alive(probe, rec):
                    break
                sleep(0.1)
            if alive(probe, rec):
                rec["status"], rec["detail"] = "survived", "still alive after SIGKILL"
            else:
                rec["status"], rec["detail"] = "killed", "SIGKILL after %gs grace" % grace
        elif "status" not in rec:
            rec["status"], rec["detail"] = "gone", "exited before SIGKILL"
    for rec in plan:
        if "status" not in rec:
            rec["status"], rec["detail"] = "unknown", "no signal was sent"
        audit.row({"event": "result", "run": run_id, **_public(rec)})
    summary = ", ".join("%d=%s" % (r["pid"], r["status"]) for r in plan)
    audit.wal("ah kill %s result: %s" % (run_id, summary))
    ok = all(r["status"] in ("exited", "killed", "gone") for r in plan)
    return {"ok": ok, "run": run_id, "audit": str(audit.path), "wal": audit.wal_ok,
            "results": [_public(r, result=True) for r in plan]}


def _send(probe, audit, run_id, rec, sig, name) -> bool:
    """Recheck identity, then signal. False (and a status) when the pid is not the audited process."""
    try:
        same = same_process(probe, rec)
        now = None if same else probe.info(rec["pid"])
    except KillError:
        rec["status"], rec["detail"] = "unknown", "ps failed before the signal; not signalled"
        return False
    if not same:
        if now is None or (name == "KILL" and fingerprint(now) == rec["id"]):
            rec["status"], rec["detail"] = "gone", "no longer running"
        else:
            rec["status"], rec["detail"] = "changed", "pid now belongs to a different process; not signalled"
        return False
    try:
        probe.signal(rec["pid"], sig)
    except ProcessLookupError:
        rec["status"], rec["detail"] = "gone", "exited before the signal"
        return False
    except PermissionError:
        rec["status"], rec["detail"] = "refused", "operating system denied the signal"
        return False
    rec["sent"] = True
    audit.row({"event": "signal", "run": run_id, "pid": rec["pid"], "signal": name, "id": rec["id"]})
    return True


def _public(rec, result=False):
    out = {k: v for k, v in rec.items() if not k.startswith("_") and k != "sent"}
    return out


def kill_remote(host, pids, reason, tree, grace, session="", agent="", home=None, runner=subprocess.run):
    if host not in HOSTS:
        raise KillError("bad_request", "--host must be one of %s" % ", ".join(HOSTS))
    home = home or Path.home()
    cmd = "python3 .claude/hooks/ah.py kill --pid %s --reason %s --grace %g --via %s" % (
        ",".join(str(p) for p in pids), shlex.quote(reason), grace, shlex.quote(session or agent or "unknown"))
    if tree:
        cmd += " --tree"
    argv = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "--", host, cmd]
    audit = Audit(home, default_wal(home, session), {"session": session or None, "agent": agent or None})
    audit.row({"event": "remote", "host": host, "pids": pids, "reason": reason, "tree": tree})
    audit.wal("ah kill on %s: pids=%s reason=%s" % (host, pids, _clip(reason, 200)))
    try:
        r = runner(argv, capture_output=True, text=True, timeout=grace * 2 + 60)
        data = json.loads(r.stdout)
    except (OSError, subprocess.SubprocessError, ValueError):
        audit.row({"event": "remote_result", "host": host, "status": "unreachable-or-unparsable"})
        raise KillError("host_unreachable", "could not run ah kill on %s" % host, 3)
    audit.row({"event": "remote_result", "host": host, "ok": data.get("ok"), "run": data.get("run")})
    data["host"] = host
    audit.wal("ah kill on %s result: ok=%s run=%s" % (host, data.get("ok"), data.get("run")))
    return data
