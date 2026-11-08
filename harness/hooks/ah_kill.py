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
import hmac
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
DAEMON_NAMES = {"rclone", "harness-console", "netwatch", "hookd", "ahd", "ahd_peek", "log_backup", "log-backup"}
SESSION_COMM = {"claude", "codex"}
DAEMON_PREFIXES = ("rclone", "harness-console", "netwatch", "hookd", "log_backup", "log-backup")
MCP_WORD = re.compile(r"(?i)(?<![a-z])mcp(?![a-z])|modelcontextprotocol")
REJECT_ROOTS = {"/", "/tmp", "/private/tmp", "/var", "/private/var", "/var/tmp", "/opt", "/usr", "/private", "/etc",
                "/home", "/Users", "/mnt", "/srv", "/root"}
SESSION_ENV = re.compile(r"CLAUDE_CODE_SESSION_ID=([A-Za-z0-9._-]{1,128})")
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

    def git_top(self, path):
        """Worktree root for a directory, or None (also None for HOME and system roots)."""
        if not path or not os.path.isdir(path):
            return None
        try:
            r = subprocess.run(["git", "-C", path, "rev-parse", "--show-toplevel"], capture_output=True, text=True,
                               timeout=8)
        except (OSError, subprocess.SubprocessError):
            return None
        top = r.stdout.strip()
        if r.returncode != 0 or not top or top in REJECT_ROOTS or top == str(Path.home()):
            return None
        return top

    def session_env(self, pid: int):
        """CLAUDE_CODE_SESSION_ID of a process, best effort (ps eww shows the environment of own processes)."""
        out = ""
        try:
            r = subprocess.run(["ps", "eww", "-o", "command=", "-p", str(pid)], capture_output=True, text=True,
                               timeout=8, env=dict(os.environ, LC_ALL="C"))
            out = r.stdout
        except (OSError, subprocess.SubprocessError):
            return None
        m = SESSION_ENV.search(out)
        return m.group(1) if m else None

    def cpu(self, pid: int):
        """Current %CPU as a float, or None."""
        out = self._ps("%cpu", pid=pid).strip()
        try:
            return float(out.split()[0]) if out else None
        except ValueError:
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


def is_session_process(info) -> bool:
    """A claude/codex process, however it was launched (a node-wrapped install shows comm=node)."""
    names = [os.path.basename(info.get("comm") or "").lower()]
    names += [os.path.basename(w).lower() for w in (info.get("command") or "").split()[:3]]
    return any(n in SESSION_COMM for n in names)


def interactive_shell(info, base) -> bool:
    if base not in SHELLS:
        return False
    comm = info.get("comm") or ""
    words = (info.get("command") or "").split()[1:]
    if comm.startswith("-") or not words:
        return True
    if any(re.fullmatch(r"-[a-z]*[il][a-z]*", w) for w in words if w.startswith("-") and not w.startswith("--")):
        return True
    return not any(not w.startswith("-") for w in words)  # no script or -c program: it reads the terminal


def refusal(info, my_uid: int, protected: set, probe=None, table=None, skip_approvable=False):
    """Reason string when this process may never be signalled, else None. No flag reaches this function, except
    skip_approvable: with a verified --approved-by, the APPROVABLE reasons are skipped and every other one applies."""
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
    if os.path.basename(first).lower() in {"sshd", "launchd"}:
        return "protected process (%s)" % base
    if base in PROTECTED_COMM and not (skip_approvable and base in APPROVABLE_COMM):
        return "protected process (%s)" % base
    if is_session_process(info) and not skip_approvable:
        return "claude/codex session process"
    if interactive_shell(info, base):
        return "interactive shell"
    if PROTECTED_PATH.search(comm) or PROTECTED_PATH.search(info.get("command") or ""):
        return "protected GUI app"
    words = [comm] + (info.get("command") or "").split()[:8]
    for w in words:
        name = re.sub(r"\.(py|sh)$", "", os.path.basename(w).lower())
        if (name in DAEMON_NAMES or name.startswith(DAEMON_PREFIXES)) and not (
                skip_approvable and name.startswith("harness-console")):
            return "harness daemon or backup job (%s)" % name
    if probe is not None and table is not None and MCP_WORD.search(info.get("command") or ""):
        owner = session_ancestor(probe, table, pid)
        if owner is not None:  # stopping one breaks that session's tools, mine included
            return "MCP server of a live claude/codex session (pid %d)" % owner
    return None


# ---- --approved-by (goodqa#15253): a stop of a stale protected process that the user approved

APPROVABLE_COMM = {"claude", "codex"}
# Only the harness console daemon: backups (rclone, log_backup), netwatch, hookd and ahd stay unstoppable here.
APPROVABLE = re.compile(r"^(?:harness daemon or backup job \(harness-console[\w.-]*\)$|claude/codex session process$|"
                        r"protected process \((?:claude|codex)\)$)")
APPROVAL_MAX_AGE_S = 24 * 3600
APPROVED_IDLE_S = 24 * 3600
ASK_ID = re.compile(r"[A-Za-z0-9_-]{4,40}")


def _provenance():
    import importlib.util  # noqa: PLC0415
    spec = importlib.util.spec_from_file_location("provenance", str(Path(__file__).resolve().with_name("provenance.py")))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _epoch_iso(value):
    try:
        return dt.datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp()
    except (TypeError, ValueError):
        return None


def _epoch_lstart(value):
    try:
        return time.mktime(time.strptime(" ".join(str(value).split()), "%a %b %d %H:%M:%S %Y"))
    except (TypeError, ValueError, OverflowError):
        return None


def resolve_approval(ask_id, session, home, now=None, prov=None):
    """The verified approval {ask, source, uuid, text, at} or KillError. The ask must be one of this session's, resolved
    by a source that provenance traces to a real human turn at most APPROVAL_MAX_AGE_S old."""
    if not ask_id or not ASK_ID.fullmatch(ask_id):
        raise KillError("bad_request", "--approved-by needs the id of a resolved ask (wal_note --event ask)")
    if not session or not SESSION_ID.fullmatch(session):
        raise KillError("bad_request", "--approved-by needs this session's id (--session or CLAUDE_CODE_SESSION_ID)")
    prov = prov or _provenance()
    claude = Path(home) / ".claude"
    try:
        entries = prov.ledger(session, claude)
    except Exception as error:  # noqa: BLE001
        raise KillError("approval_invalid", "the asks ledger could not be read (%s)" % type(error).__name__)
    ask = next((r for r in entries if r.get("id") == ask_id), None)
    if ask is None:
        raise KillError("approval_invalid", "no ask %s in this session's WALs" % ask_id)
    closed = ask.get("_closed") or {}
    if not closed.get("source"):
        raise KillError("approval_invalid", "ask %s has no ask_resolved entry citing the user's answer" % ask_id)
    result = prov.resolve(closed["source"], {"home": claude, "want_text": True})
    node = next((n for n in result.get("chain", []) if n.get("kind") == "user"), None)
    if not result.get("ok") or result.get("origin") != "user" or result.get("assumption") or result.get("weak") \
            or node is None:
        raise KillError("approval_invalid", "ask %s was not resolved by a verified human turn (user:, answer: or "
                        "queue:); a ticket, pasted text or inference cannot approve a stop" % ask_id)
    at = _epoch_iso(node.get("timestamp"))
    now = time.time() if now is None else now
    if at is None or not 0 <= now - at <= APPROVAL_MAX_AGE_S:
        raise KillError("approval_invalid", "the approving human turn is missing a time or older than %d h"
                        % (APPROVAL_MAX_AGE_S // 3600))
    return {"ask": ask_id, "source": _clip(closed["source"], 200), "uuid": node.get("uuid"),
            "text": str(node.get("text") or ""), "at": node.get("timestamp")}


# Delta red-team D-F3: a program name ("claude") or a bare number ("the 2025 runs") is not an approval, and a
# negation ("do not touch pid 4242") is not one either. The approving text must list the exact pid after "pid" or
# "pids", and must not contain a negation anywhere.
_PID_LIST = re.compile(r"\bpids?\b[\s:#=]*((?:\d+(?:\s*(?:,|and|&|/|\+)\s*|\s+))*\d+)(?![\d])", re.I)
_NEGATION = re.compile(r"\b(?:not|never|no|don'?t|dont|leave|keep|except|spare|without)\b|n['\u2019]t\b", re.I)


def approved_pids(text):
    """The pids an approving human text explicitly lists ("pid 4242", "pids 10968, 28579 and 39962")."""
    out = set()
    for found in _PID_LIST.finditer(text or ""):
        out.update(int(n) for n in re.findall(r"\d+", found.group(1)))
    return out


def _named(text, pid, root, info):
    """True when the approving human text lists this pid, or its --tree root's pid, and negates nothing."""
    if _NEGATION.search(text or ""):
        return False
    return bool(approved_pids(text) & ({pid, root} - {None}))


def approval_problem(probe, info, pid, root, scope):
    """None when the verified approval in scope covers this process, else the reason it does not."""
    approval = scope["approval"]
    if not _named(approval["text"], pid, root, info):
        return "the approving answer does not list pid %d (\"pid %d\") or it contains a negation" % (pid, pid)
    started = _epoch_lstart(info.get("start"))
    if started is None:
        return "its start time cannot be read"
    if scope["now"] - started < APPROVED_IDLE_S:
        return "it started less than %d h ago" % (APPROVED_IDLE_S // 3600)
    if scope.get("session_start") is None or started >= scope["session_start"]:
        return "it did not start before the current session"
    if not (info.get("stat") or "").startswith(("S", "I")):
        return "it is not sleeping"
    cpu = getattr(probe, "cpu", None)
    try:
        used = cpu(pid) if cpu else None
    except Exception:  # noqa: BLE001
        used = None
    if used is None or used > 0.0:
        return "it is using CPU or its CPU use cannot be read"
    return None


def session_ancestor(probe, table, pid):
    """Nearest claude/codex ancestor of pid (exclusive), or None."""
    seen = set()
    for _ in range(12):
        pid = table.get(pid)
        if not pid or pid <= 1 or pid in seen:
            return None
        seen.add(pid)
        info = probe.info(pid)
        if info and is_session_process(info):
            return pid
    return None


def in_own_scope(probe, table, pid, cwd, roots, worktree):
    """True when pid descends from one of `roots` or its cwd is in the caller's worktree (same git root, nested
    worktrees excluded). The roots are only the ah process itself, so in practice own scope means "same worktree as
    the caller's cwd"; anything else needs --foreign. Known limit: the caller's cwd is caller-chosen, so a stop made
    after cd into another checkout counts as own; the caller cwd is recorded in the audit row to keep it visible."""
    seen, cur = set(), pid
    for _ in range(64):
        if cur in roots:
            return True
        cur = table.get(cur)
        if not cur or cur <= 1 or cur in seen:
            break
        seen.add(cur)
    # Equality of git roots, not a path prefix: a worktree nested inside the caller's checkout is someone else's.
    return bool(worktree and cwd and probe.git_top(cwd) == worktree)


SESSION_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")


def session_work_dir(home, session):
    """The real path of ~/.agent-harness/work/<session>, or a KillError when the session id is unusable."""
    if not session or not SESSION_ID.fullmatch(session) or session in (".", ".."):
        raise KillError("bad_request", "--session-scope needs this session's id (--session or CLAUDE_CODE_SESSION_ID)")
    return os.path.realpath(os.path.join(str(home), ".agent-harness", "work", session))


def _inside(path, root):
    if not path or not root or "\x00" in path:
        return False
    real = os.path.realpath(os.path.normpath(path))
    return real == root or real.startswith(root.rstrip("/") + "/")


def _kill_guard():
    import importlib.util  # noqa: PLC0415
    spec = importlib.util.spec_from_file_location("kill_guard", str(Path(__file__).resolve().with_name("kill_guard.py")))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


MAX_LEDGERS = 500


def session_spawns(home, root, kg=None):
    """{(pid, start)} that `kill_guard.py spawn` recorded for a worktree inside the session work dir `root`.

    Exact ownership (goodqa#15253): only HMAC-valid local ledger entries count, read from the ledger file named for
    their own root. A cwd or a path in argv never does. Real paths, so work/sess-10 or ../sess-2 never match."""
    kg = kg or _kill_guard()
    key = kg.read_key(str(home))
    if not key:
        return set()
    found = set()
    for path in sorted(kg.state_dir(str(home)).glob("ledger-*.jsonl"))[:MAX_LEDGERS]:
        data = kg._read_secure_file(path, 1 << 20, tail=True)
        for line in (data or b"").decode("utf-8", "replace").splitlines()[-2000:]:
            try:
                entry = json.loads(line)
                pid, start, ts = int(entry["pid"]), str(entry["start"]), int(entry["ts"])
                entry_root, mac = str(entry["root"]), str(entry["mac"])
            except (ValueError, KeyError, TypeError):
                continue
            if entry_root.startswith("remote:") or os.path.realpath(entry_root) != entry_root:
                continue
            if not _inside(entry_root, root) or kg.ledger_path(entry_root, str(home)) != path:
                continue
            if hmac.compare_digest(mac, kg.ledger_mac(key, entry_root, pid, start, ts)):
                found.add((pid, start))
    return found


def spawn_start(probe, pid):
    """The process start time in the spawn ledger's format (kill_guard.Probe.start), or None."""
    getter = getattr(probe, "spawn_start", None)
    if getter is not None:
        return getter(pid)
    try:
        return _kill_guard().Probe().start(pid)
    except Exception:  # noqa: BLE001 - an unreadable start time proves nothing
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


def snapshot(probe, pid, my_uid, protected, root=None, role="target", scope=None):
    info = probe.info(pid)
    if info is None:
        return {"pid": pid, "role": role, "root": root, "status": "gone", "detail": "no such process"}
    rec = {"pid": pid, "role": role, "root": root, "ppid": info["ppid"], "user": probe.user(info["uid"]),
           "uid": info["uid"], "start": info["start"], "cmd": _clip(info["command"]), "cwd": probe.cwd(pid),
           "id": fingerprint(info), "_info": info}
    table = scope["table"] if scope else None
    why = refusal(info, my_uid, protected, probe if scope else None, table)
    approval = scope.get("approval") if scope else None
    if approval and not info["stat"].startswith("Z") and (
            (why and APPROVABLE.match(why)) or (not why and not in_own_scope(
                probe, table, pid, rec["cwd"], scope["roots"], scope["worktree"]))):
        rest = refusal(info, my_uid, protected, probe, table, skip_approvable=True)
        bound = rest or approval_problem(probe, info, pid, root, scope)
        if bound is None:
            rec["scope"], rec["approved"], rec["approved_by"] = "approved", True, approval["ask"]
            rec["lifted"] = why  # the refusal the user's approval lifted (None: it was only outside the caller's tree)
            return rec
        if why:
            why = "%s; --approved-by %s does not cover it: %s" % (why, approval["ask"], bound)
    if why:
        rec["status"], rec["detail"] = "refused", why
    elif info["stat"].startswith("Z"):
        rec["status"], rec["detail"] = "gone", "already a zombie"
    elif scope and scope.get("session_spawns") and not in_own_scope(
            probe, table, pid, rec["cwd"], scope["roots"], scope["worktree"]) and (
            pid, spawn_start(probe, pid)) in scope["session_spawns"]:
        rec["scope"] = "session-spawn"  # spawned by a worktree in main's session work dir: audited, no notice
    elif scope and not in_own_scope(probe, table, pid, rec["cwd"], scope["roots"], scope["worktree"]):
        rec["scope"] = "foreign"
        if not scope["foreign"]:
            rec["status"] = "refused"
            rec["detail"] = ("foreign: outside your worktree and process tree; pass --foreign to stop it "
                             "(audited, and main is notified)")
        else:
            owner = session_ancestor(probe, table, pid)
            rec["foreign"] = True
            rec["target_worktree"] = probe.git_top(rec["cwd"])
            rec["owner_pid"] = owner
            rec["owner_session"] = probe.session_env(owner) if owner else None
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
               clock=time.monotonic, session="", agent="", wal_path=None, via=None, own_pid=None, foreign=False,
               worktree="auto", notify=None, session_scope=False, approved_by=None, approval_resolver=None,
               now=None):
    reason = (reason or "").strip()
    if not reason:
        raise KillError("reason_required", "--reason is mandatory and must not be empty")
    if len(reason) > MAX_REASON:
        raise KillError("bad_request", "--reason is longer than %d characters" % MAX_REASON)
    if not 0 <= grace <= MAX_GRACE:
        raise KillError("bad_request", "--grace must be 0..%d seconds" % int(MAX_GRACE))
    home = home or Path.home()
    session_dir = session_work_dir(home, session) if session_scope else None
    probe = probe or Probe()
    own_pid = own_pid or os.getpid()
    my_uid = os.getuid()
    caller = {"session": session or None, "agent": agent or None, "ppid_chain_root": own_pid,
              "user": probe.user(my_uid), "via": via}
    # The caller's own cwd decides "own worktree", and a caller can cd anywhere: record it so a stop made from
    # another agent's checkout is visible in the audit row and the ops-watch notice instead of silent.
    caller["cwd"] = _clip(os.getcwd(), 200)
    audit = Audit(home, default_wal(home, session, wal_path), caller)
    protected = protected_ids(probe, own_pid)
    run_id = "k" + uuid.uuid4().hex[:12]
    table = probe.table()
    # Own scope is the caller's own process tree and its worktree. The session process is deliberately not a root:
    # every agent of a session hangs under it, so it would make every owner's processes "own".
    roots = {own_pid}
    if worktree == "auto":
        worktree = probe.git_top(os.getcwd())
    scope = {"table": table, "roots": roots, "worktree": worktree, "foreign": foreign,
             "session_spawns": session_spawns(home, session_dir) if session_dir else set()}
    if approved_by:
        scope["approval"] = (approval_resolver or resolve_approval)(approved_by, session, home)
        scope["now"] = time.time() if now is None else now
        owner = session_ancestor(probe, table, own_pid)
        owner_info = probe.info(owner) if owner else None
        scope["session_start"] = _epoch_lstart(owner_info["start"]) if owner_info else None
    plan, seen = [], set()
    for root in pids:
        batch = []
        for child in (descendants(table, root) if tree else []):
            batch.append(snapshot(probe, child, my_uid, protected, root=root, role="child", scope=scope))
        batch.append(snapshot(probe, root, my_uid, protected, role="target", scope=scope))
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
    approved_live = [r for r in live if r.get("approved")]
    if approved_live:
        approval = scope["approval"]
        event = {"host": _host(), "source": "ops-watch", "event": "raise", "severity": "high", "check": "ah-kill",
                 "key": "ah-kill:approved:" + run_id,
                 "message": "ah kill --approved-by %s stopped/will stop %d user-approved stale process(es): %s (reason: %s)" % (
                     approval["ask"], len(approved_live), ", ".join(str(r["pid"]) for r in approved_live), _clip(reason, 120)),
                 "detail": {"run": run_id, "caller": caller, "reason": _clip(reason, 200), "ask": approval["ask"],
                            "source": approval["source"], "targets": [
                                {"pid": r["pid"], "cmd": _clip(r["cmd"], 120), "cwd": r["cwd"], "start": r.get("start"),
                                 "lifted": r.get("lifted")} for r in approved_live]}}
        try:
            (notify or _ops_notice)(home, event)
        except Exception as error:  # an approved stop without its notice is not allowed
            audit.row({"event": "aborted", "run": run_id, "why": "ops-watch notice failed: %s" % type(error).__name__})
            raise KillError("notice_failed", "could not raise the ops-watch notice for an approved stop; nothing was signalled", 3)
    foreign_live = [r for r in live if r.get("foreign")]
    if foreign_live:
        event = {"host": _host(), "source": "ops-watch", "event": "raise", "severity": "high", "check": "ah-kill",
                 "key": "ah-kill:foreign:" + run_id,
                 "message": "ah kill --foreign stopped/will stop %d process(es) outside the caller's tree: %s (reason: %s)" % (
                     len(foreign_live), ", ".join(str(r["pid"]) for r in foreign_live), _clip(reason, 120)),
                 "detail": {"run": run_id, "caller": caller, "reason": _clip(reason, 200), "targets": [
                     {"pid": r["pid"], "cmd": _clip(r["cmd"], 120), "cwd": r["cwd"], "worktree": r.get("target_worktree"),
                      "owner_session": r.get("owner_session")} for r in foreign_live]}}
        try:
            (notify or _ops_notice)(home, event)
        except Exception as error:  # the notice is the point of --foreign: no notice, no signal
            audit.row({"event": "aborted", "run": run_id, "why": "ops-watch notice failed: %s" % type(error).__name__})
            raise KillError("notice_failed", "could not raise the ops-watch notice for a foreign stop; nothing was signalled", 3)
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


def _host():
    import socket
    return socket.gethostname().split(".")[0]


def _ops_notice(home, event):
    import ops_watch
    event = dict(event, host=ops_watch.default_host())
    ops_watch.emit(event, home=home)


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


def kill_remote(host, pids, reason, tree, grace, session="", agent="", home=None, runner=subprocess.run, foreign=False, notify=None):
    if host not in HOSTS:
        raise KillError("bad_request", "--host must be one of %s" % ", ".join(HOSTS))
    home = home or Path.home()
    reason = (reason or "").strip()
    if not reason:
        raise KillError("reason_required", "--reason is mandatory and must not be empty")
    if len(reason) > MAX_REASON or not 0 <= grace <= MAX_GRACE:
        raise KillError("bad_request", "--reason or --grace is out of range")
    if not foreign:
        raise KillError("foreign_required", "--host targets are outside this session's tree and worktree; pass --foreign "
                        "(audited, and main is notified)")
    cmd = "python3 -I .claude/hooks/ah.py kill --pid %s --reason %s --grace %g --via %s" % (
        ",".join(str(p) for p in pids), shlex.quote(reason), grace, shlex.quote(session or agent or "unknown"))
    if tree:
        cmd += " --tree"
    if foreign:
        cmd += " --foreign"
    argv = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "--", host, cmd]
    audit = Audit(home, default_wal(home, session), {"session": session or None, "agent": agent or None})
    audit.row({"event": "remote", "host": host, "pids": pids, "reason": reason, "tree": tree})
    event = {"host": _host(), "source": "ops-watch", "event": "raise", "severity": "high", "check": "ah-kill",
             "key": "ah-kill:foreign:remote-" + uuid.uuid4().hex[:10],
             "message": "ah kill --foreign on %s for pids %s (reason: %s)" % (host, ",".join(str(p) for p in pids), _clip(reason, 120)),
             "detail": {"host": host, "pids": pids, "caller": {"session": session or None, "agent": agent or None}}}
    try:
        (notify or _ops_notice)(home, event)
    except Exception as error:  # no notice, no remote stop
        audit.row({"event": "aborted", "host": host, "why": "ops-watch notice failed: %s" % type(error).__name__})
        raise KillError("notice_failed", "could not raise the ops-watch notice; nothing was signalled", 3)
    audit.wal("ah kill on %s: pids=%s reason=%s" % (host, pids, _clip(reason, 200)))
    try:
        r = runner(argv, capture_output=True, text=True, timeout=grace * 2 + 60)
        data = json.loads(r.stdout)
    except (OSError, subprocess.SubprocessError, ValueError):
        audit.row({"event": "remote_result", "host": host, "status": "unreachable-or-unparsable"})
        raise KillError("host_unreachable", "could not run ah kill on %s" % host, 3)
    if not isinstance(data, dict):
        audit.row({"event": "remote_result", "host": host, "status": "unparsable"})
        raise KillError("host_unreachable", "unexpected answer from %s" % host, 3)
    audit.row({"event": "remote_result", "host": host, "ok": data.get("ok"), "run": data.get("run")})
    data["host"] = host
    audit.wal("ah kill on %s result: ok=%s run=%s" % (host, data.get("ok"), data.get("run")))
    return data
