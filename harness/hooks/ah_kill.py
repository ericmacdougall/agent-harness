"""ah kill: signal your own runaway processes, with refusals no flag overrides and an audit row for every pid.

Flow per request: probe every target (cmdline, cwd, user, start, parent) -> refuse the unsafe ones -> write the
audit intent rows (fail closed: no audit row, no signal) -> SIGTERM (children first with --tree) -> after the grace
period SIGKILL whatever is left -> write one result row per pid. Before every signal the pid identity (start time and
command) is probed again, so a reused pid is never hit.

Who may stop what (redesign 2026-11-24; roles from ah_roles via the CLI's session and agent ids): the caller's own
tree, worktree and session spawns with no flag; a supervisor also its supervised projects; a top-rung caller anything
with --foreign and no ask record, except harness daemons (a harness maintainer may) and staging/live services; anyone
else's --foreign needs --approved-by <ask> whose human answer names the pid. Never: pid 1, the caller's own session
chain, root, another user, system processes. kill_guard no longer judges `ah kill`; this file is the check.

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


def _local():
    """harness/hooks/ah_local.py (the owner's ~/.agent-harness/local.json), or None."""
    try:
        import sys  # noqa: PLC0415
        here = str(Path(__file__).resolve().parent)
        if here not in sys.path:
            sys.path.insert(0, here)
        import ah_local  # noqa: PLC0415
        return ah_local
    except Exception:  # noqa: BLE001
        return None


_LOCAL = _local()
# ssh hosts `ah kill --host` serves: the hosts of ~/.agent-harness/local.json (none by default).
HOSTS = tuple(h for h in (_LOCAL.host_names() if _LOCAL else ())
              if h not in (_LOCAL.host_names(os_name="windows") if _LOCAL else ()))
# Windows OpenSSH hosts (goodqa#15275): ah.py is not installed there, so ah kill reads and stops the process itself
# over ssh with PowerShell. Windows OpenSSH does not end a session's processes when the client disconnects, so
# orphaned remote PowerShell children need this audited path.
WINDOWS_HOSTS = _LOCAL.host_names(os_name="windows") if _LOCAL else ()
# Delta red-team D-F4: a Windows stop is an allowlist, not a deny list. It may stop only an orphaned shell (its parent
# is gone, or the parent pid now belongs to a newer process) that the ssh login user owns and that is not part of the
# ssh session running the check. That is exactly the orphaned PowerShell children it exists for. "The login user" is
# GetOwner of the checking shell itself: on a workgroup machine $env:USERDOMAIN is WORKGROUP while GetOwner says the
# machine name (found live, goodqa#15275). Anything else
# (claude, codex, node, adb, sshd-session, WSL, Defender, ...) is refused.
WINDOWS_ALLOWED = {"powershell", "pwsh", "cmd"}
WIN_SENTINEL = "AHK1 "  # D-F5: the answer is the last line with this prefix; profile or CLIXML noise is ignored
_ISO = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,7})?(?:Z|[+-]\d{2}:\d{2})")
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


def _who(session, agent) -> str:
    """The caller part of an aggregated ops-watch alert key: one row per caller session (else agent), not one per run.
    Characters outside the ring key alphabet are dropped."""
    raw = str(session)[:12] if session else (str(agent)[:40] if agent else "nosession")
    return re.sub(r"[^A-Za-z0-9._-]", "", raw) or "nosession"


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


def refusal(info, my_uid: int, protected: set, probe=None, table=None):
    """Reason string when this process is not signalled by default, else None. role_refusal decides which reasons a
    role or the owner's approval lifts (HARD ones never)."""
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
    if base in PROTECTED_COMM:
        return "protected process (%s)" % base
    if is_session_process(info):
        return "claude/codex session process"
    if interactive_shell(info, base):
        return "interactive shell"
    if PROTECTED_PATH.search(comm) or PROTECTED_PATH.search(info.get("command") or ""):
        return "protected GUI app"
    words = [comm] + (info.get("command") or "").split()[:8]
    for w in words:
        name = re.sub(r"\.(py|sh)$", "", os.path.basename(w).lower())
        if name in DAEMON_NAMES or name.startswith(DAEMON_PREFIXES):
            return "harness daemon or backup job (%s)" % name
    if any(p.search(info.get("command") or "") for p in _live_patterns()):
        return LIVE
    if probe is not None and table is not None and MCP_WORD.search(info.get("command") or ""):
        owner = session_ancestor(probe, table, pid)
        if owner is not None:  # stopping one breaks that session's tools, mine included
            return "MCP server of a live claude/codex session (pid %d)" % owner
    return None


# ---- --approved-by (goodqa#15253): a stop of a stale protected process that the user approved

APPROVAL_MAX_AGE_S = 24 * 3600
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
    """None when the verified approval in scope covers this process (the owner's answer lists its pid, or its --tree
    root's, and negates nothing), else the reason it does not."""
    if not _named(scope["approval"]["text"], pid, root, info):
        return "the approving answer does not list pid %d (\"pid %d\") or it contains a negation" % (pid, pid)
    return None


# ---- roles (ah_roles is the one place that knows them)

HARD = re.compile(r"^(?:pid 1 and below|the caller's own process|root-owned|owned by another user|system process|"
                  r"protected process \((?:sshd|launchd|init|systemd)\))")
DAEMON = re.compile(r"^harness daemon or backup job")
LIVE = "staging/live service (kill_guard_policy.json staging_live)"


def caller_roles(home, session, agent=""):
    """{"top", "maintainer", "supervised": [real paths]} for the caller."""
    try:
        import ah_roles  # noqa: PLC0415
        payload = ah_roles.cli_payload(home=home, session=session or "", agent=agent)
        top = ah_roles.is_top_rung(payload)
        fn = getattr(ah_roles, "may_edit_harness", None)
        maintainer = bool(fn(payload) if fn else (top and ah_roles.is_supervisor(payload, home)))
        return {"top": top, "maintainer": maintainer,
                "supervised": [os.path.realpath(str(p)) for p in ah_roles.supervised_roots(payload, home)]}
    except Exception:  # noqa: BLE001
        return {"top": False, "maintainer": False, "supervised": []}


def _live_patterns():
    try:
        # input-ok: the shipped policy file beside this script
        policy = json.loads(Path(__file__).resolve().with_name("kill_guard_policy.json").read_text())
        return [re.compile(p) for p in policy.get("staging_live") or [] if isinstance(p, str)]
    except (OSError, ValueError, re.error):
        return []


def role_refusal(why, info, roles, approval_ok):
    """What is left of a refusal once the caller's role or the owner's approval is counted. Hard refusals stay for
    everyone; staging/live stays unless the owner approved; a harness daemon stays unless approved or the caller is a
    harness maintainer; everything else is lifted for a top-rung caller or by an approval."""
    if not why or HARD.match(why):
        return why
    if why == LIVE:
        return None if approval_ok else why
    if DAEMON.match(why):
        return None if approval_ok or roles.get("maintainer") else why
    return None if approval_ok or roles.get("top") else why


def store_approval(pid, cwd, owner_only=False):
    """A live `kill` record of the approvals store (ah_approvals) covering this pid (and its cwd as the project), or
    None. owner_only: only a record the owner granted (staging/live services). Never raises."""
    try:
        import ah_approvals  # noqa: PLC0415 - a sibling module; absent on older installs
        facts = {"pids": [int(pid)]}
        if cwd:
            facts["project"] = cwd
        record = ah_approvals.allowed("kill", **facts)
    except Exception:  # noqa: BLE001
        return None
    if record and owner_only and record.get("granted_by") != "user":
        return None
    return record


def approve_hint(pid) -> str:
    """The `ah approve kill ...` line a refusal names (ah_approvals.command_hint), or a fixed fallback."""
    try:
        import ah_approvals  # noqa: PLC0415
        return ah_approvals.command_hint("kill", pids=[int(pid)])
    except Exception:  # noqa: BLE001
        return 'ah approve kill --pids %d --reason "<why>"' % int(pid)


def in_supervised(info, cwd, roles):
    paths = [p for p in [cwd] + (info.get("command") or "").split()[:4] if p and p.startswith("/")]
    return any(_inside(p, r) for p in paths for r in roles.get("supervised") or [])


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
    scope = scope or {}
    table, roles = scope.get("table"), scope.get("roles") or {}
    approval = scope.get("approval")
    approved = bool(approval) and approval_problem(probe, info, pid, root, scope) is None
    first = refusal(info, my_uid, protected, probe if scope else None, table)
    stored = None  # an `ah approve kill` record covering this pid (never for a HARD refusal)
    if first and not HARD.match(first) and not approved:
        stored = store_approval(pid, rec["cwd"], owner_only=(first == LIVE))
    why = role_refusal(first, info, roles, approved or bool(stored))
    if why:
        if approval and not approved and not HARD.match(why):
            why += "; --approved-by %s does not cover it: %s" % (approval["ask"], approval_problem(probe, info, pid, root, scope))
        if not HARD.match(why):
            why += "; the owner approves it with: " + approve_hint(pid)
        rec["status"], rec["detail"] = "refused", why
        return rec
    if stored:
        rec["approved_by"] = stored.get("id")
    if first:
        rec["lifted"] = first  # the refusal a role or the owner's approval lifted
    if info["stat"].startswith("Z"):
        rec["status"], rec["detail"] = "gone", "already a zombie"
        return rec
    if not scope or in_own_scope(probe, table, pid, rec["cwd"], scope["roots"], scope["worktree"]):
        return rec
    if scope.get("session_spawns") and (pid, spawn_start(probe, pid)) in scope["session_spawns"]:
        rec["scope"] = "session-spawn"  # spawned by a worktree in this session's work dir
        return rec
    if in_supervised(info, rec["cwd"], roles):
        rec["scope"] = "supervised"  # a project the caller supervises: its own to stop
        return rec
    rec["scope"] = "foreign"
    if approved:
        rec["scope"], rec["approved"], rec["approved_by"] = "approved", True, approval["ask"]
        return rec  # the owner's approval: one info notice for approved stops, not a foreign page
    stored = stored or store_approval(pid, rec["cwd"])
    if stored:
        rec["scope"], rec["approved"], rec["approved_by"] = "approved", True, stored.get("id")
        return rec  # an `ah approve kill` record covers it
    if not scope["foreign"]:
        rec["status"] = "refused"
        rec["detail"] = ("foreign: outside your worktree, process tree and supervised projects; "
                         + ("pass --foreign (audited, main is notified)" if roles.get("top") else
                            "the owner approves it with: " + approve_hint(pid)))
        return rec
    elif not roles.get("top"):
        rec["status"] = "refused"
        rec["detail"] = ("foreign: --foreign needs the owner's approval for this pid (or a supervisor or top-rung "
                         "caller); the owner approves it with: " + approve_hint(pid))
        return rec
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
               now=None, roles=None):
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
    if roles is None:
        roles = caller_roles(home, session, agent)
    caller["roles"] = {k: v for k, v in roles.items() if k != "supervised"}
    scope = {"table": table, "roots": roots, "worktree": worktree, "foreign": foreign, "roles": roles,
             "session_spawns": session_spawns(home, session_dir) if session_dir else set()}
    if approved_by:
        scope["approval"] = (approval_resolver or resolve_approval)(approved_by, session, home)
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
    approved_live = [r for r in live if r.get("approved") or (r.get("lifted") and scope.get("approval"))]
    if approved_live:
        # --approved-by <ask>, or an `ah approve kill` record of the approvals store (rec["approved_by"] is its id)
        approval = scope.get("approval") or {"ask": ",".join(sorted({str(r.get("approved_by")) for r in approved_live})),
                                             "source": "ah approvals"}
        # A verified user approval is a record, not a page: info, one aggregated row per caller session (fleet round item 3).
        event = {"host": _host(), "source": "ops-watch", "event": "raise", "severity": "info", "check": "ah-kill",
                 "key": "ah-kill:approved:" + _who(session, agent),
                 "message": "ah kill approved by %s stopped/will stop %d user-approved stale process(es): %s (reason: %s)" % (
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
        # Stopping the caller's OWN session's processes outside its tree is info; another owner's stays high. One
        # aggregated row per caller session either way, so 40 stops are one alert, not 40.
        own_session = bool(session) and all(r.get("owner_session") == session for r in foreign_live)
        event = {"host": _host(), "source": "ops-watch", "event": "raise", "severity": "info" if own_session else "high",
                 "check": "ah-kill", "key": "ah-kill:foreign:" + _who(session, agent) + (":own" if own_session else ""),
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


def _powershell(host, script):
    """ssh argv that runs SCRIPT in Windows PowerShell. -EncodedCommand (base64 UTF-16LE) avoids every layer of quoting
    between this argv, the remote default shell and PowerShell."""
    import base64  # noqa: PLC0415
    encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    return ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "--", host,
            "powershell -NoProfile -NonInteractive -EncodedCommand " + encoded]


_WIN_READ = r"""$ErrorActionPreference='Stop'
$mo = Invoke-CimMethod -InputObject (Get-CimInstance Win32_Process -Filter "ProcessId=$PID") -MethodName GetOwner
$me = if ($mo.ReturnValue -eq 0) { "$($mo.Domain)\$($mo.User)" } else { '?' }
$chain = @(); $q = $PID
for ($k = 0; $k -lt 16 -and $q; $k++) { $chain += [int]$q; $x = Get-CimInstance Win32_Process -Filter "ProcessId=$q"; if (-not $x) { break }; $q = [int]$x.ParentProcessId }
$p = Get-CimInstance Win32_Process -Filter 'ProcessId=%d'
if (-not $p) { 'AHK1 {"found":false}'; exit }
$o = Invoke-CimMethod -InputObject $p -MethodName GetOwner
$owner = if ($o.ReturnValue -eq 0) { "$($o.Domain)\$($o.User)" } else { '' }
$parent = Get-CimInstance Win32_Process -Filter ('ProcessId=' + [int]$p.ParentProcessId)
$orphan = (-not $parent) -or ($parent.CreationDate -gt $p.CreationDate)
'AHK1 ' + ([pscustomobject]@{found=$true; pid=[int]$p.ProcessId; ppid=[int]$p.ParentProcessId; name=[string]$p.Name; created=$p.CreationDate.ToUniversalTime().ToString('o'); cmd=[string]$p.CommandLine; owner=$owner; mine=(($owner -ne '') -and ($owner -eq $me)); self=($chain -contains [int]$p.ProcessId); orphan=[bool]$orphan} | ConvertTo-Json -Compress)
"""
# The stop re-reads the process in the same remote script and re-checks its creation time and owner, so a reused pid
# or a process of another user is not stopped. Stop-Process -Force is immediate on Windows; there is no grace period.
_WIN_STOP = r"""$ErrorActionPreference='Stop'
$mo = Invoke-CimMethod -InputObject (Get-CimInstance Win32_Process -Filter "ProcessId=$PID") -MethodName GetOwner
$me = if ($mo.ReturnValue -eq 0) { "$($mo.Domain)\$($mo.User)" } else { '?' }
$p = Get-CimInstance Win32_Process -Filter 'ProcessId=%d'
if (-not $p) { 'AHK1 {"status":"gone"}'; exit }
if ($p.CreationDate.ToUniversalTime().ToString('o') -ne '%s') { 'AHK1 {"status":"changed"}'; exit }
$o = Invoke-CimMethod -InputObject $p -MethodName GetOwner
if ($o.ReturnValue -ne 0 -or "$($o.Domain)\$($o.User)" -ne $me) { 'AHK1 {"status":"changed"}'; exit }
try { Stop-Process -Id %d -Force -ErrorAction Stop; 'AHK1 {"status":"stopped"}' } catch { 'AHK1 {"status":"refused"}' }
"""


def _win_call(runner, host, script, timeout):
    try:
        r = runner(_powershell(host, script), capture_output=True, text=True, timeout=timeout)
        lines = [line.strip() for line in (r.stdout or "").splitlines() if line.strip().startswith(WIN_SENTINEL)]
        data = json.loads(lines[-1][len(WIN_SENTINEL):]) if lines else None
    except (OSError, subprocess.SubprocessError, ValueError):
        data = None
    return data if isinstance(data, dict) else None


def kill_remote_windows(host, pids, reason, tree, grace, session="", agent="", home=None, runner=subprocess.run,
                        foreign=False, notify=None):
    """Stop one orphaned shell on a Windows OpenSSH host: main only (kill_guard), --foreign audit and ops-watch notice,
    one pid per call, owner and identity recorded before the stop and rechecked in the stop script."""
    home = home or Path.home()
    reason = (reason or "").strip()
    if not reason:
        raise KillError("reason_required", "--reason is mandatory and must not be empty")
    if len(reason) > MAX_REASON or not 0 <= grace <= MAX_GRACE:
        raise KillError("bad_request", "--reason or --grace is out of range")
    if len(pids) != 1 or not isinstance(pids[0], int) or isinstance(pids[0], bool):
        raise KillError("bad_request", "a Windows --host stop takes exactly one pid per call")
    pid = pids[0]
    if pid <= 4:
        raise KillError("bad_request", "pid %d is a Windows system process" % pid)
    if tree:
        raise KillError("bad_request", "--tree is not supported on a Windows --host; stop each pid by itself")
    if not foreign:
        raise KillError("foreign_required", "--host targets are outside this session's tree and worktree; pass --foreign "
                        "(audited, and main is notified)")
    audit = Audit(home, default_wal(home, session), {"session": session or None, "agent": agent or None})
    run_id = "kw-" + uuid.uuid4().hex[:10]
    audit.row({"event": "remote", "host": host, "pids": [pid], "reason": reason, "tree": False, "run": run_id})
    ident = _win_call(runner, host, _WIN_READ % pid, 60)
    if ident is None:
        audit.row({"event": "remote_result", "host": host, "run": run_id, "status": "unreachable-or-unparsable"})
        raise KillError("host_unreachable", "could not read pid %d on %s" % (pid, host), 3)
    rec = {"pid": pid, "host": host}
    if ident.get("found") is False:
        rec.update(status="gone", detail="no such process")
    elif ident.get("pid") != pid or not isinstance(ident.get("created"), str) or not _ISO.fullmatch(ident["created"]):
        audit.row({"event": "remote_result", "host": host, "run": run_id, "status": "unparsable"})
        raise KillError("host_unreachable", "unexpected answer from %s" % host, 3)
    elif not all(isinstance(ident.get(k), bool) for k in ("mine", "self", "orphan")):
        audit.row({"event": "remote_result", "host": host, "run": run_id, "status": "unparsable"})
        raise KillError("host_unreachable", "unexpected answer from %s" % host, 3)
    else:
        name = str(ident.get("name") or "")
        rec.update(name=_clip(name, 80), ppid=ident.get("ppid"), created=ident["created"],
                   cmd=_clip(str(ident.get("cmd") or ""), MAX_CMD), owner=_clip(str(ident.get("owner") or ""), 80),
                   orphan=ident["orphan"])
        audit.row({"event": "identity", "run": run_id, "host": host, "pid": pid, "ppid": rec["ppid"],
                   "name": rec["name"], "created": rec["created"], "cmd": rec["cmd"], "owner": rec["owner"],
                   "orphan": rec["orphan"]})
        base = name.lower()[:-4] if name.lower().endswith(".exe") else name.lower()
        if base not in WINDOWS_ALLOWED:
            rec.update(status="refused", detail="only an orphaned %s is stopped on a Windows host, not %s" % (
                "/".join(sorted(WINDOWS_ALLOWED)), base or "an unnamed process"))
        elif not ident["mine"]:
            rec.update(status="refused", detail="owned by another user (%s)" % (rec["owner"] or "unknown"))
        elif ident["self"]:
            rec.update(status="refused", detail="part of the ssh session running this check")
        elif not ident["orphan"]:
            rec.update(status="refused", detail="its parent pid %s is still running; stop the parent first" % rec["ppid"])
    if "status" not in rec:
        event = {"host": _host(), "source": "ops-watch", "event": "raise", "severity": "high", "check": "ah-kill",
                 "key": "ah-kill:foreign:remote-%s-%s" % (host, _who(session, agent)),
                 "message": "ah kill --foreign on %s for pid %d %s (reason: %s)" % (
                     host, pid, _clip(rec["cmd"] or rec["name"], 80), _clip(reason, 120)),
                 "detail": {"host": host, "pids": [pid], "caller": {"session": session or None, "agent": agent or None}}}
        try:
            (notify or _ops_notice)(home, event)
        except Exception as error:  # no notice, no remote stop
            audit.row({"event": "aborted", "host": host, "run": run_id,
                       "why": "ops-watch notice failed: %s" % type(error).__name__})
            raise KillError("notice_failed", "could not raise the ops-watch notice; nothing was signalled", 3)
        audit.wal("ah kill on %s: pid=%d reason=%s cmd=%s" % (host, pid, _clip(reason, 200), _clip(rec["cmd"], 120)))
        done = _win_call(runner, host, _WIN_STOP % (pid, rec["created"], pid), 60)
        status = done.get("status") if done else None
        if status not in ("stopped", "gone", "changed", "refused"):
            rec.update(status="unknown", detail="no parsable answer to the stop; check the host")
        else:
            rec["status"] = status
            rec["detail"] = {"stopped": "Stop-Process -Force", "gone": "exited before the stop",
                             "changed": "pid now belongs to a different process; not stopped",
                             "refused": "Stop-Process was denied"}[status]
    audit.row({"event": "remote_result", "host": host, "run": run_id, "pid": pid, "status": rec["status"]})
    audit.wal("ah kill on %s result: pid=%d status=%s" % (host, pid, rec["status"]))
    return {"ok": rec["status"] in ("stopped", "gone"), "run": run_id, "host": host, "results": [rec]}


def kill_remote(host, pids, reason, tree, grace, session="", agent="", home=None, runner=subprocess.run, foreign=False, notify=None):
    if host in WINDOWS_HOSTS:
        return kill_remote_windows(host, pids, reason, tree, grace, session, agent, home, runner, foreign, notify)
    if host not in HOSTS:
        raise KillError("bad_request", "--host must be one of %s" % ", ".join(HOSTS + WINDOWS_HOSTS))
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
             "key": "ah-kill:foreign:remote-%s-%s" % (host, _who(session, agent)),
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
