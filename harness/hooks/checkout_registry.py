#!/usr/bin/env python3
"""checkout_registry.py: hook-written ownership rows for the git checkouts agents create (goodqa#16947, spec v3).

A Claude agent's `git clone` or `git worktree add` run through Bash on this machine, and each isolation worktree Claude
Code makes for a subagent (`<repo>/.claude/worktrees/agent-<agent_id>`), gets at most ONE signed `created` row naming
the session and agent that made it. The row exists only when a hook saw the checkout being born during that agent's own
call. Stream B's owner removal accepts only `held(identity)` as ownership proof; the janitor reads the same rows.

    ~/.agent-harness/state/checkouts/local.jsonl
    {"v":1,"event":"created","kind":"isolation|worktree|clone","host":"local","path":<realpath>,"dev":N,"ino":N,
     "btime_ns":N,"common_dir":<realpath>,"session":...,"agent":<agent id or null>,"task":null,"created_at":<utc>,
     "tool_use_id":<id or null for isolation>,"mac":<HMAC-SHA256>}

IDENTITY is (host, dev, ino, btime_ns). ext4 reuses an inode number at once (40 of 40 on t2-dev), and a moved checkout
keeps both inode and birth time, so: no btime means no row; a Bash row needs btime >= a clock mark taken at PreToolUse;
a path seen absent retires every row for it ("observed-absent"); two created rows for one identity mean no owner. A
row owns that one checkout, never what is nested under its path.

THE RULE: a missing row is safe; a wrong row deletes someone's work. The command text only PROPOSES a path. A Bash
row needs, all observed: Pre saw the path absent (ENOENT), pinned the nearest existing folder above it, took the clock
mark and claimed the path under the lock with no other live claim; Post (PostToolUse or PostToolUseFailure) carries
the same tool_use_id, session, agent and command hash as the signed pending record; the payload's transcript is the
session's own and holds that Bash tool_use; the path is now a checkout top, not a link, under home, at the pinned
folder (same dev and ino), born after the mark; a clone's origin is the command's URL, a worktree is linked and shares
the named repo's common dir; nothing holds the identity yet. Anything unsure: no row, and one reason code in
state/checkouts/decisions.jsonl.

`mac(row)` and `verify(row)` are the only signing functions; `held(identity)` is the only ownership check (verify alone
does not bind a row to its host file). Key: state/checkouts/registry.key, 32 random bytes, 0600, made O_EXCL through no
link in an owner-only folder; rotating it voids every row (the kill switch). Trust boundary as kill_guard's ledger:
careless or hurried agents, not a hostile process of the same uid that reads the key.

SubagentStop writes a DATA note for the parent (inbox/data-checkout-<agent>.md, which owner_inbox injects as data, not
instructions): what the agent still holds and a verdict. It never removes anything and calls no removal route.

Not covered (disclosed in docs/checkout-registry.md): Codex (no PostToolUse), `ssh t2-dev '...'` checkouts (PR 2; here
an ssh command naming clone or worktree proposes nothing and the hooks start no ssh), gh repo clone, cp/rsync/ditto
copies, the EnterWorktree tool, --bare/--mirror, clones inside scripts, run_in_background clones, WorktreeCreate.

    checkout_registry.py hook pretool|posttool|posttool-failure|denied|subagent-start|subagent-stop
    checkout_registry.py stat --path P     read-only JSON about one path
    checkout_registry.py list              read-only: verified rows, failures, what is held
"""
from __future__ import annotations

import argparse
import contextlib
import fcntl
import glob
import hashlib
import hmac
import json
import os
import re
import shlex
import stat as stat_mod
import subprocess
import sys
import time
from pathlib import Path

VERSION = 1
HOST = "local"
HOSTS = ("local",)                  # PR 2 adds "t2-dev"
KINDS = ("isolation", "worktree", "clone")
GIT_TIMEOUT = 5
STAT_TIMEOUT = 5
PENDING_TTL = 2 * 3600
ISO_WINDOW_NS = 300 * 10 ** 9
ISO_RETRY_S = 60                    # a failed isolation check is not repeated on every tool call
STOP_BUDGET = 15.0
MAX_LINE = 8192
MAX_FILE = 64 * 1024 * 1024
MAX_DECISIONS = 4 * 1024 * 1024
TRANSCRIPT_SCAN = 16 * 1024 * 1024
NEST_SCAN_ENTRIES = 5000
NEST_SCAN_DEPTH = 6
MAX_CANDIDATES = 4
ID_RE = re.compile(r"[A-Za-z0-9_-]{1,80}")
UNSAFE_PATH = re.compile(r"[$`*?\[\]{}\\\n\r\t\"'<>|;&]")
UNSAFE_TEXT = re.compile(r"[^A-Za-z0-9._/@:+=, -]")
STAT_OUT = re.compile(r"(\d+)(?:\.(\d{1,9}))?")


HOOK_BUDGET = {"pretool": 8.0, "posttool": 8.0, "posttool-failure": 8.0, "denied": 8.0, "subagent-start": 15.0,
               "subagent-stop": 18.0}
_DEADLINE = None                    # monotonic time by which the running hook must be done (set by hook())


def _left(cap: float) -> float:
    """Seconds a subprocess may still take: at most `cap`, never past the whole-hook deadline."""
    if _DEADLINE is None:
        return cap
    return min(cap, _DEADLINE - time.monotonic())


class Unsure(Exception):
    """The command names a checkout this module cannot resolve with certainty: propose nothing."""


# --------------------------------------------------------------------------- state, key and signing

def home() -> Path:
    return Path(os.path.expanduser("~"))


def state_dir() -> Path:
    return home() / ".agent-harness" / "state" / "checkouts"


def claude_dir() -> Path:
    configured = os.environ.get("CLAUDE_CONFIG_DIR")
    return Path(configured) if configured else home() / ".claude"


def _secure_dir(path: Path, create: bool) -> bool:
    if create:
        try:
            os.makedirs(str(path), mode=0o700, exist_ok=True)
        except OSError:
            return False
    try:
        st = os.lstat(str(path))
    except OSError:
        return False
    return stat_mod.S_ISDIR(st.st_mode) and st.st_uid == os.getuid() and not (st.st_mode & 0o022)


def _read_secure(path: Path, limit: int) -> "bytes | None":
    try:
        fd = os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError:
        return None
    try:
        st = os.fstat(fd)
        if not stat_mod.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or st.st_mode & 0o077:
            return None
        if st.st_size > limit:
            os.lseek(fd, st.st_size - limit, os.SEEK_SET)
        chunks, left = [], limit
        while left > 0:
            b = os.read(fd, min(left, 1 << 20))
            if not b:
                break
            chunks.append(b)
            left -= len(b)
        return b"".join(chunks)
    except OSError:
        return None
    finally:
        os.close(fd)


def read_key() -> "bytes | None":
    if not _secure_dir(state_dir(), create=False):
        return None
    data = _read_secure(state_dir() / "registry.key", 256)
    return data if data and len(data) == 32 else None


def ensure_key() -> "bytes | None":
    """The key, created once with O_EXCL; None when the state folder or key is unsafe (a link, not ours, writable)."""
    if not _secure_dir(state_dir(), create=True):
        return None
    key = read_key()
    if key:
        return key
    try:
        fd = os.open(str(state_dir() / "registry.key"),
                     os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0), 0o600)
    except FileExistsError:
        return read_key()
    except OSError:
        return None
    try:
        os.write(fd, os.urandom(32))
        os.fsync(fd)
    finally:
        os.close(fd)
    return read_key()


def canonical(row: dict) -> bytes:
    return json.dumps({k: v for k, v in row.items() if k != "mac"}, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def mac(row: dict, key: "bytes | None" = None) -> "str | None":
    """HMAC-SHA256 of the canonical JSON of every field except `mac`. None without a safe key."""
    key = key or read_key()
    return hmac.new(key, canonical(row), hashlib.sha256).hexdigest() if key else None


def verify(row, key: "bytes | None" = None) -> bool:
    """True only for an unmodified v1 row signed with this machine's key. It does NOT bind the row to a host file:
    ownership is held(identity)."""
    if not isinstance(row, dict) or row.get("v") != VERSION or not isinstance(row.get("mac"), str):
        return False
    want = mac(row, key)
    return bool(want) and hmac.compare_digest(want, row["mac"])


def _utc() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _private_append(path: Path, data: bytes, limit: "int | None" = None) -> None:
    fd = os.open(str(path), os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        st = os.fstat(fd)
        if not stat_mod.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or st.st_mode & 0o077:
            return
        if limit is not None and st.st_size > limit:
            return
        os.write(fd, data)
    finally:
        os.close(fd)


def decide(code: str, **ctx) -> None:
    """One reason code per decision (AC-5). Bounded; never secrets (paths, ids and codes only)."""
    try:
        if not _secure_dir(state_dir(), create=True):
            return
        line = {"at": _utc(), "code": code}
        line.update({k: _safe(v) for k, v in ctx.items()})
        log = state_dir() / "decisions.jsonl"
        with contextlib.suppress(OSError):
            if log.lstat().st_size > MAX_DECISIONS:
                os.replace(str(log), str(state_dir() / "decisions.1.jsonl"))   # keep one older file, never grow
        _private_append(log, (json.dumps(line) + "\n").encode("utf-8")[:MAX_LINE])
    except OSError:
        pass


def _safe(value, limit: int = 300) -> str:
    return UNSAFE_TEXT.sub("?", str(value))[:limit]


# --------------------------------------------------------------------------- the ledger

@contextlib.contextmanager
def _locked():
    """One exclusive lock per machine around every check-and-append and every claim."""
    fd = os.open(str(state_dir() / ".lock"), os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def ledger_path(host: str = HOST) -> Path:
    if host not in HOSTS:
        raise ValueError("unknown host %r" % host)
    return state_dir() / ("%s.jsonl" % host)


def rows(host: str = HOST, key: "bytes | None" = None) -> "tuple[list, int]":
    """(verified rows of this host's file, how many lines failed). The whole file is read (bounded at 64 MB). A row
    whose `host` names another host fails: a row pasted between files never counts."""
    key = key or read_key()
    data = _read_secure(ledger_path(host), MAX_FILE)
    good, bad = [], 0
    for line in (data or b"").decode("utf-8", "replace").splitlines():
        if not line.strip():
            continue
        try:
            row = json.loads(line)
        except ValueError:
            bad += 1
            continue
        if key and verify(row, key) and row.get("host") == host:
            good.append(row)
        else:
            bad += 1
    return good, bad


def identity(row: dict) -> tuple:
    return (row.get("host"), row.get("dev"), row.get("ino"), row.get("btime_ns"))


def current(host: str = HOST, key: "bytes | None" = None) -> dict:
    """{identity: created row} for every checkout whose rows end in exactly one owner. Two created rows for one
    identity under different owners mean no owner, until a removed row ends both."""
    live, contested = {}, set()
    for row in rows(host, key)[0]:
        ident = identity(row)
        if row.get("event") == "created":
            held_row = live.get(ident)
            if held_row and (held_row.get("session"), held_row.get("agent")) != (row.get("session"), row.get("agent")):
                contested.add(ident)
            elif not held_row:
                live[ident] = row
        elif row.get("event") == "removed":
            live.pop(ident, None)
            contested.discard(ident)
    return {k: v for k, v in live.items() if k not in contested}


def held(ident: dict) -> "dict | None":
    """THE ownership check for stream B: the current created row for exactly (host, dev, ino, btime_ns), read from
    that host's own file and verified; None when nothing or more than one owner holds it."""
    host = ident.get("host")
    if host not in HOSTS:
        return None
    return current(host).get(identity(ident))


def _append(row: dict, key: bytes) -> dict:
    """Caller holds the lock. Repairs a missing trailing newline (a crash mid-append), writes one line, fsyncs."""
    row = dict(row)
    row["mac"] = mac(row, key)
    line = (json.dumps(row, separators=(",", ":"), ensure_ascii=False) + "\n").encode("utf-8")
    if len(line) > MAX_LINE:
        raise ValueError("row too long")
    fd = os.open(str(ledger_path(row["host"])), os.O_RDWR | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
                 0o600)
    try:
        st = os.fstat(fd)
        if not stat_mod.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or st.st_mode & 0o077:
            raise OSError("ledger is not a private regular file")
        if st.st_size and os.pread(fd, 1, st.st_size - 1) != b"\n":
            os.write(fd, b"\n")
        os.write(fd, line)
        os.fsync(fd)
    finally:
        os.close(fd)
    return row


def write_created(info: dict, kind: str, session: str, agent, tool_use_id) -> "tuple[dict | None, str]":
    """(row, code). Appends one `created` row unless the identity is already held: same owner gives
    `already-held`, another owner `second-owner`."""
    key = ensure_key()
    if not key or kind not in KINDS or not session:
        return None, "no-key"
    row = {"v": VERSION, "event": "created", "kind": kind, "host": HOST, "path": info["realpath"], "dev": info["dev"],
           "ino": info["ino"], "btime_ns": info["btime_ns"], "common_dir": info.get("common_dir"), "session": session,
           "agent": agent or None, "task": None, "created_at": _utc(), "tool_use_id": tool_use_id or None}
    with _locked():
        live = current(HOST, key)
        held_row = live.get(identity(row))
        if held_row:
            same = (held_row.get("session"), held_row.get("agent")) == (session, agent or None)
            return None, "already-held" if same else "second-owner"
        if any(identity(r) == identity(row) and r.get("event") == "created" for r in rows(HOST, key)[0]):
            return None, "contested-identity"      # a created row exists but the identity counts as owned by no one
        return _append(row, key), "written"


def _removed_row(held_row: dict, by: str, route: str) -> dict:
    return {"v": VERSION, "event": "removed", "kind": held_row["kind"], "host": held_row["host"],
            "path": held_row["path"], "dev": held_row["dev"], "ino": held_row["ino"],
            "btime_ns": held_row["btime_ns"], "common_dir": held_row.get("common_dir"),
            "session": held_row["session"], "agent": held_row.get("agent"), "task": held_row.get("task"),
            "by": _safe(by, 200), "route": _safe(route, 200), "removed_at": _utc()}


def append_removed(ident: dict, by: str, route: str) -> "dict | None":
    """For stream B's route, after a successful removal: one `removed` row for an identity held now. None when
    nothing is held under exactly that identity (a forged or unmatched removal changes nothing)."""
    key = ensure_key()
    if not key or ident.get("host") not in HOSTS:
        return None
    with _locked():
        held_row = current(ident["host"], key).get(identity(ident))
        return _append(_removed_row(held_row, by, route), key) if held_row else None


def retire_absent(real: str, key: bytes) -> int:
    """Caller has just seen `real` absent (ENOENT): every row still held for that path is dead."""
    n = 0
    with _locked():
        for row in current(HOST, key).values():
            if row.get("path") == real:
                _append(_removed_row(row, "checkout_registry", "observed-absent"), key)
                n += 1
    if n:
        decide("observed-absent", path=real, rows=n)
    return n


# --------------------------------------------------------------------------- facts about one path (read-only)

def _git_env() -> dict:
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update({"GIT_CONFIG_NOSYSTEM": "1", "GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0", "LC_ALL": "C"})
    return env


def _git(path: str, *args, timeout: float = GIT_TIMEOUT, raw: bool = False) -> "str | None":
    """git hardened against the repo it reads: no fsmonitor, no hooks, no optional locks, no GIT_* from the caller.
    None (unsure) once the whole-hook deadline has passed. raw keeps the output byte-exact (porcelain -z starts with
    a significant space)."""
    timeout = _left(timeout)
    if timeout <= 0.2:
        return None
    try:
        r = subprocess.run(["git", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null",
                            "-c", "core.untrackedCache=false", "--no-optional-locks", "-C", path, *args],
                           capture_output=True, text=True, timeout=timeout, env=_git_env(),
                           stdin=subprocess.DEVNULL)
    except (OSError, subprocess.SubprocessError):
        return None
    if r.returncode != 0:
        return None
    return r.stdout if raw else r.stdout.strip()


def birth_ns(path: str) -> "int | None":
    """Birth time in ns of the object at path (not following a link); None when the platform cannot say."""
    if sys.platform == "darwin":
        try:
            st = os.lstat(path)
        except OSError:
            return None
        ns = getattr(st, "st_birthtime_ns", None)
        if ns:
            return int(ns)
        bt = getattr(st, "st_birthtime", None)
        return int(round(bt * 1e9)) if bt else None
    limit = _left(STAT_TIMEOUT)
    if limit <= 0.2:
        return None
    try:
        r = subprocess.run(["/usr/bin/stat", "-c", "%.9W", "--", path], capture_output=True, text=True,
                           timeout=limit, env={"LC_ALL": "C", "PATH": "/usr/bin:/bin"}, stdin=subprocess.DEVNULL)
    except (OSError, subprocess.SubprocessError):
        return None
    m = STAT_OUT.fullmatch(r.stdout.strip()) if r.returncode == 0 else None
    if not m or int(m.group(1)) == 0:
        return None
    return int(m.group(1)) * 10 ** 9 + int((m.group(2) or "0").ljust(9, "0"))


def clock_mark() -> "int | None":
    """The birth time of a fresh file: the same kernel clock that will stamp a checkout made after it."""
    d = state_dir() / "pending"
    if not _secure_dir(d, create=True):
        return None
    p = d / (".mark-%d-%s" % (os.getpid(), os.urandom(6).hex()))
    try:
        fd = os.open(str(p), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        os.close(fd)
        return birth_ns(str(p))
    except OSError:
        return None
    finally:
        with contextlib.suppress(OSError):
            p.unlink()


def _anchor(p: str) -> "dict | None":
    """The nearest existing folder above an absent path, and the part below it (git makes missing leading folders)."""
    rest, cur = [], os.path.abspath(p)
    while True:
        parent, name = os.path.split(cur)
        rest.insert(0, name)
        if parent == cur:
            return None
        try:
            st = os.stat(parent)
        except FileNotFoundError:
            cur = parent
            continue
        except OSError:
            return None
        if not stat_mod.S_ISDIR(st.st_mode):
            return None
        return {"realpath": os.path.realpath(parent), "dev": st.st_dev, "ino": st.st_ino, "rest": "/".join(rest)}


def stat_path(path: str) -> dict:
    """Read-only facts: exists (True; False only for ENOENT; None when unreadable), link, realpath, dev, ino, btime_ns,
    in_home, checkout (the path IS a checkout's top), linked (its .git is a file), common_dir; anchor when absent."""
    p = os.path.expanduser(path)
    out = {"path": path, "exists": None, "link": False, "checkout": False}
    try:
        st = os.lstat(p)
    except FileNotFoundError:
        out.update(exists=False, anchor=_anchor(p))
        return out
    except OSError:
        return out
    out["exists"] = True
    out["link"] = stat_mod.S_ISLNK(st.st_mode)
    if out["link"] or not stat_mod.S_ISDIR(st.st_mode):
        return out
    real = os.path.realpath(p)
    h = os.path.realpath(str(home()))
    out.update({"realpath": real, "dev": st.st_dev, "ino": st.st_ino, "btime_ns": birth_ns(p),
                "in_home": real.startswith(h + os.sep)})
    dotgit = os.path.join(real, ".git")
    if not os.path.lexists(dotgit):
        return out
    top = _git(real, "rev-parse", "--show-toplevel")
    common = _git(real, "rev-parse", "--path-format=absolute", "--git-common-dir")
    if top and os.path.realpath(top) == real and common:
        out.update({"checkout": True, "linked": os.path.isfile(dotgit) and not os.path.islink(dotgit),
                    "common_dir": os.path.realpath(common)})
    return out


def _dir_identity(real: str) -> "tuple | None":
    try:
        st = os.lstat(real)
    except OSError:
        return None
    return (st.st_dev, st.st_ino) if stat_mod.S_ISDIR(st.st_mode) else None


# --------------------------------------------------------------------------- what a Bash command proposes

CLONE_VALUE = {"-b", "--branch", "--depth", "--reference", "--reference-if-able", "-c", "--config", "--filter",
               "--template", "-j", "--jobs", "--shallow-since", "--shallow-exclude", "--server-option",
               "--bundle-uri", "--revision"}
CLONE_FLAG = {"-q", "--quiet", "-v", "--verbose", "--progress", "--no-checkout", "-n", "--single-branch",
              "--no-single-branch", "--no-tags", "--tags", "--recurse-submodules", "--recursive",
              "--shallow-submodules", "--no-shallow-submodules", "--no-hardlinks", "-l", "--local", "--no-local",
              "-s", "--shared", "--sparse", "--dissociate", "--remote-submodules", "--no-remote-submodules",
              "--also-filter-submodules", "--reject-shallow", "--no-reject-shallow"}
# deliberately absent (unsure): --bare, --mirror (no worktree top), -o/--origin (another remote name),
# --separate-git-dir, -u/--upload-pack
WT_VALUE = {"-b", "-B", "--reason"}
WT_FLAG = {"-f", "--force", "--detach", "-d", "--checkout", "--no-checkout", "--lock", "--orphan", "--track",
           "--no-track", "--guess-remote", "--no-guess-remote", "-q", "--quiet", "--relative-paths",
           "--no-relative-paths"}
CHDIR = {"cd", "pushd", "popd"}
REMOTE_SHELLS = {"ssh", "mosh", "docker", "kubectl", "podman", "lxc", "incus", "multipass", "vagrant"}
OPERATOR_CHARS = ";&|()\n"
WRAPPERS = {"env", "command", "nohup", "time", "exec", "sudo", "nice", "builtin"}
ASSIGN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=")
REDIR_OP = re.compile(r"\d*(?:>>|>|<>|<)")
REDIR_ATTACHED = re.compile(r"\d*(?:>>|>|<>|<)[^<>&|;]+")
MENTION = re.compile(r"\b(clone|worktree)\b")


HEREDOC = re.compile(r"<<(-?)[ \t]*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\2")


def _strip_heredocs(cmd: str) -> str:
    """Drop every heredoc body (it is data fed to a command, never a command line here) and its `<<WORD` operator. A
    body that runs as a script (`bash <<EOF`) is therefore not read: a miss, which is safe. Unterminated: unsure."""
    if "<<<" in cmd:
        raise Unsure("here-string")
    lines, out, i = cmd.split("\n"), [], 0
    while i < len(lines):
        delims = []
        out.append(HEREDOC.sub(lambda m: delims.append((m.group(1) == "-", m.group(3))) or " ", lines[i]))
        i += 1
        for strip_tabs, word in delims:
            while i < len(lines) and (lines[i].lstrip("\t") if strip_tabs else lines[i]) != word:
                i += 1
            if i >= len(lines):
                raise Unsure("unterminated heredoc")
            i += 1
    if "<<" in "\n".join(out):
        raise Unsure("heredoc")
    return "\n".join(out)


def _split(cmd: str) -> list:
    """[(separator before it, words)] for each simple command, quote-aware (an operator inside quotes stays in its
    word). Heredoc bodies, redirections, leading assignments and option-free wrappers are dropped. Unclosed quotes and
    wrapper options are unsure."""
    cmd = _strip_heredocs(cmd)
    lex = shlex.shlex(cmd, posix=True, punctuation_chars=OPERATOR_CHARS)
    lex.whitespace = " \t\r"
    lex.whitespace_split = True
    lex.commenters = ""
    try:
        tokens = list(lex)
    except ValueError as e:
        raise Unsure("unparsable: %s" % e) from None
    out, cur, sep, i = [], [], "", 0
    while i < len(tokens):
        t = tokens[i]
        if REDIR_OP.fullmatch(t):
            i += 3 if i + 1 < len(tokens) and tokens[i + 1] == "&" else 2
            continue
        if REDIR_ATTACHED.fullmatch(t):
            i += 1
            continue
        if t and all(c in OPERATOR_CHARS for c in t):
            out.append((sep, cur))
            cur, sep = [], t
        else:
            cur.append(t)
        i += 1
    out.append((sep, cur))
    cleaned = []
    for sep, words in out:
        for j, w in enumerate(words):
            if w.startswith("#"):
                words = words[:j]
                break
        while words and (ASSIGN.match(words[0]) or os.path.basename(words[0]) in WRAPPERS):
            if os.path.basename(words[0]) in WRAPPERS and len(words) > 1 and words[1].startswith("-"):
                raise Unsure("wrapper option")
            words = words[1:]
        cleaned.append((sep, words))
    return cleaned


def _parse_opts(words: list, value: set, flag: set) -> list:
    pos, i = [], 0
    while i < len(words):
        w = words[i]
        if w == "--":
            pos += words[i + 1:]
            break
        if w.startswith("--"):
            name = w.split("=", 1)[0]
            if name in value:
                i += 1 if "=" in w else 2
                continue
            if name in flag:
                i += 1
                continue
            raise Unsure("unknown option " + name)
        if w.startswith("-") and w != "-":
            if w in value:
                i += 2
                continue
            if w in flag:
                i += 1
                continue
            raise Unsure("unknown option " + w)
        pos.append(w)
        i += 1
    return pos


def _resolve(raw: str, base: "str | None") -> str:
    if not raw or UNSAFE_PATH.search(raw):
        raise Unsure("path needs the shell")
    if raw == "~" or raw.startswith("~/"):
        return os.path.normpath(os.path.expanduser(raw))
    if raw.startswith("~"):
        raise Unsure("another user's home")
    if raw.startswith("/"):
        return os.path.normpath(raw)
    if base is None:
        raise Unsure("relative path without a known directory")
    return os.path.normpath(os.path.join(base, raw))


def _is_url(u: str) -> bool:
    return "://" in u or bool(re.match(r"^[^/]+:", u))


def _clone_dir(url: str) -> str:
    tail = re.split(r"[/:]", url.rstrip("/"))[-1]
    if tail.endswith(".git"):
        tail = tail[:-4]
    if not tail or tail in (".", ".."):
        raise Unsure("cannot tell the clone's folder")
    return tail


def _git_candidate(words: list, base: "str | None") -> "dict | None":
    i = 1
    while i < len(words) and words[i].startswith("-"):
        w = words[i]
        if w == "-C" and i + 1 < len(words):
            base = _resolve(words[i + 1], base)
            i += 2
        elif w == "-c" and i + 1 < len(words):
            i += 2
        elif w in ("--no-pager", "-P", "--no-replace-objects", "--literal-pathspecs", "--no-optional-locks"):
            i += 1
        else:
            raise Unsure("git option " + w)          # --git-dir, --work-tree, --namespace and the rest
    rest = words[i:]
    if not rest:
        return None
    if rest[0] == "clone":
        pos = _parse_opts(rest[1:], CLONE_VALUE, CLONE_FLAG)
        if not pos:
            return None
        if len(pos) > 2:
            raise Unsure("too many clone arguments")
        url = pos[0]
        if UNSAFE_PATH.search(url):
            raise Unsure("url needs the shell")
        url = url if _is_url(url) else _resolve(url, base)
        target = pos[1] if len(pos) > 1 else _clone_dir(pos[0])
        return {"kind": "clone", "path": _resolve(target, base), "url": url}
    if rest[0] == "worktree" and len(rest) > 1 and rest[1] == "add":
        pos = _parse_opts(rest[2:], WT_VALUE, WT_FLAG)
        if not pos or len(pos) > 2:
            raise Unsure("worktree add without one path")
        if base is None:
            raise Unsure("worktree add without a known repository")
        return {"kind": "worktree", "path": _resolve(pos[0], base), "repo": base}
    return None


def propose(cmd: str, cwd: str) -> "tuple[list, str | None]":
    """([candidate], None) or ([], reason). A candidate is only a proposal; Post decides from observed state."""
    if not MENTION.search(cmd):
        return [], None
    out = []
    try:
        base = os.path.realpath(cwd) if cwd and os.path.isabs(cwd) else None
        pure = True                     # every separator so far is `&&`, so a cd before it really ran
        moved = False
        for sep, words in _split(cmd):
            if sep not in ("", "&&"):
                pure = False
                if moved:
                    base = None         # after `;`, `||`, `|`, `&` or a subshell a cd may not have happened
            if not words:
                continue
            name = os.path.basename(words[0])
            if name in CHDIR:
                moved = True
                args = words[1:]
                if not pure or name == "popd" or len(args) > 1 or (args and args[0].startswith("-")):
                    base = None
                else:
                    try:
                        base = _resolve(args[0], base) if args else str(home())
                    except Unsure:
                        base = None
                continue
            if name in REMOTE_SHELLS:
                if MENTION.search(" ".join(words[1:])):
                    raise Unsure("a remote command (remote rows are PR 2)")
                continue
            if name != "git":
                continue
            got = _git_candidate(words, base)
            if got:
                out.append(got)
    except Unsure as e:
        return [], "unsure: %s" % e
    if len(out) > MAX_CANDIDATES:
        return [], "unsure: too many candidates"
    return out, None


def candidates(cmd: str, cwd: str) -> list:
    return propose(cmd, cwd)[0]


# --------------------------------------------------------------------------- pending records and claims

def _pending_path(tool_use_id: str) -> Path:
    return state_dir() / "pending" / (hashlib.sha256(tool_use_id.encode("utf-8")).hexdigest() + ".json")


def _write_pending(record: dict, key: bytes) -> None:
    d = state_dir() / "pending"
    if not _secure_dir(d, create=True):
        return
    now = time.time()
    for old in d.iterdir():                                    # expired records of calls that never finished
        with contextlib.suppress(OSError):
            if old.is_file() and now - old.lstat().st_mtime > PENDING_TTL:
                old.unlink()
    record = dict(record, mac=mac(record, key))
    p = _pending_path(record["tool_use_id"])
    tmp = p.with_name(p.name + ".%d.tmp" % os.getpid())
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        os.write(fd, json.dumps(record).encode("utf-8"))
    finally:
        os.close(fd)
    os.replace(str(tmp), str(p))


def _take_pending(tool_use_id: str, key: bytes) -> "tuple[dict | None, str]":
    p = _pending_path(tool_use_id)
    data = _read_secure(p, 65536)
    with contextlib.suppress(OSError):
        p.unlink()
    try:
        rec = json.loads(data) if data else None
    except ValueError:
        return None, "pending-bad-mac"
    if not isinstance(rec, dict):
        return None, "pending-bad-mac"
    if not verify(rec, key):
        return rec, "pending-bad-mac"        # returned only so the caller can drop this call's own claims
    if not isinstance(rec.get("at"), (int, float)) or not 0 <= time.time() - rec["at"] <= PENDING_TTL:
        return rec, "pending-expired"
    return rec, "ok"


def _claim_file(kind: str, real: str) -> Path:
    return state_dir() / kind / hashlib.sha256(("%s\0%s" % (HOST, real)).encode("utf-8")).hexdigest()


def _fresh(p: Path) -> bool:
    try:
        return time.time() - p.lstat().st_mtime <= PENDING_TTL
    except OSError:
        return False


def _claim(real: str, tool_use_id: str) -> bool:
    """Under the lock: one tool call at a time may expect a path. A second call expecting it marks it contested, and
    then neither call writes a row."""
    for kind in ("claims", "contested"):
        if not _secure_dir(state_dir() / kind, create=True):
            return False
    with _locked():
        claim = _claim_file("claims", real)
        data = _read_secure(claim, 4096) if _fresh(claim) else None
        holder = data.decode("utf-8", "replace") if data else None
        if holder and holder != tool_use_id:
            mark = _claim_file("contested", real)
            fd = os.open(str(mark), os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0), 0o600)
            os.close(fd)
            os.utime(str(mark))
            return False
        if _fresh(_claim_file("contested", real)):
            return False
        tmp = claim.with_name(claim.name + ".%d.tmp" % os.getpid())
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            os.write(fd, tool_use_id.encode("utf-8"))
        finally:
            os.close(fd)
        os.replace(str(tmp), str(claim))
    return True


def _release(real: str, tool_use_id: str) -> bool:
    """Drop our claim; True when the path was contested meanwhile (then no row)."""
    with _locked():
        claim = _claim_file("claims", real)
        data = _read_secure(claim, 4096)
        if data and data.decode("utf-8", "replace") == tool_use_id:
            with contextlib.suppress(OSError):
                claim.unlink()
        return _fresh(_claim_file("contested", real))


# --------------------------------------------------------------------------- transcript binding

def _projects() -> str:
    return os.path.realpath(str(claude_dir() / "projects"))


def _regular(p: str) -> bool:
    try:
        return stat_mod.S_ISREG(os.lstat(p).st_mode)
    except OSError:
        return False


def subagent_transcript(session: str, agent: str) -> "str | None":
    hits = glob.glob(os.path.join(_projects(), "*", session, "subagents", "agent-%s.jsonl" % agent))
    hits = [h for h in hits if _regular(h)]
    return hits[0] if len(hits) == 1 else None


def _transcript_for(payload: dict, session: str, agent) -> "str | None":
    """The transcript that must hold this agent's tool calls, proven by the payload's own transcript_path: the
    session's main transcript (projects/<p>/<session>.jsonl) or, for an agent, its subagent transcript."""
    tp = payload.get("transcript_path")
    if not isinstance(tp, str) or "\x00" in tp or not _regular(tp):
        return None
    real = os.path.realpath(tp)
    projects = _projects()
    main_form = os.path.basename(real) == session + ".jsonl" and os.path.dirname(os.path.dirname(real)) == projects
    sub_form = bool(agent) and os.path.basename(real) == "agent-%s.jsonl" % agent and \
        os.path.basename(os.path.dirname(real)) == "subagents" and \
        os.path.basename(os.path.dirname(os.path.dirname(real))) == session and \
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(real)))) == projects
    if not (main_form or sub_form):
        return None
    if not agent:
        return real
    if sub_form:
        return real
    sub = os.path.join(os.path.dirname(real), session, "subagents", "agent-%s.jsonl" % agent)
    return sub if _regular(sub) else None


def _find_tool_use(obj, tool_use_id: str):
    if isinstance(obj, dict):
        if obj.get("type") == "tool_use" and obj.get("id") == tool_use_id:
            return obj
        for v in obj.values():
            got = _find_tool_use(v, tool_use_id)
            if got:
                return got
    elif isinstance(obj, list):
        for v in obj:
            got = _find_tool_use(v, tool_use_id)
            if got:
                return got
    return None


def bound_to_transcript(payload: dict, session: str, agent, tool_use_id: str, cmd_sha: str) -> bool:
    path = _transcript_for(payload, session, agent)
    if not path:
        return False
    try:
        with open(path, "rb") as fh:
            size = os.fstat(fh.fileno()).st_size
            fh.seek(max(0, size - TRANSCRIPT_SCAN))
            data = fh.read(TRANSCRIPT_SCAN)
    except OSError:
        return False
    needle = tool_use_id.encode("utf-8")
    for line in data.splitlines():
        if needle not in line:
            continue
        try:
            use = _find_tool_use(json.loads(line), tool_use_id)
        except ValueError:
            continue
        if use and use.get("name") == "Bash":
            command = (use.get("input") or {}).get("command")
            return isinstance(command, str) and _sha(command) == cmd_sha
    return False


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


# --------------------------------------------------------------------------- hooks

def _ids(payload: dict) -> "tuple[str | None, str | None]":
    session, agent = payload.get("session_id"), payload.get("agent_id")
    session = session if isinstance(session, str) and ID_RE.fullmatch(session) else None
    agent = agent if isinstance(agent, str) and ID_RE.fullmatch(agent) else None
    return session, agent


def _bash(payload: dict) -> "tuple[str, str | None]":
    ti = payload.get("tool_input") or {}
    tid = payload.get("tool_use_id")
    cmd = ti.get("command") if isinstance(ti, dict) else None
    return (cmd if isinstance(cmd, str) else ""), (tid if isinstance(tid, str) and 0 < len(tid) <= 128 else None)


def pretool(payload: dict) -> None:
    session, agent = _ids(payload)
    if not session:
        return
    cwd = str(payload.get("cwd") or "")
    if agent:
        isolation_from_cwd(cwd, session, agent)
    if payload.get("tool_name") != "Bash":
        return
    cmd, tid = _bash(payload)
    if not tid or len(cmd) > 64 * 1024:
        return
    cands, why = propose(cmd, cwd)
    if why:
        decide("unsure", tool_use_id=tid, why=why)
    if not cands:
        return
    key = ensure_key()
    mark = clock_mark() if key else None
    if not key or mark is None:
        decide("no-mark", tool_use_id=tid)
        return
    keep = []
    for c in cands:
        f = stat_path(c["path"])
        if f.get("exists") is True:
            decide("existed-at-pre", tool_use_id=tid, path=c["path"])
            continue
        if f.get("exists") is None or not f.get("anchor"):
            decide("unreadable-at-pre", tool_use_id=tid, path=c["path"])
            continue
        a = f["anchor"]
        expect = a["realpath"].rstrip("/") + "/" + a["rest"]
        retire_absent(expect, key)
        entry = {"kind": c["kind"], "path": c["path"], "expect": expect, "anchor": a["realpath"],
                 "anchor_dev": a["dev"], "anchor_ino": a["ino"]}
        if c["kind"] == "worktree":
            common = _git(c["repo"], "rev-parse", "--path-format=absolute", "--git-common-dir")
            if not common:
                decide("repo-unknown", tool_use_id=tid, path=c["path"])
                continue
            entry["repo_common"] = os.path.realpath(common)
        else:
            entry["url"] = c["url"]
        if not _claim(expect, tid):
            decide("contested", tool_use_id=tid, path=expect)
            continue
        keep.append(entry)
    if keep:
        _write_pending({"v": VERSION, "tool_use_id": tid, "session": session, "agent": agent, "at": time.time(),
                        "cmd_sha": _sha(cmd), "mark_ns": mark, "cands": keep}, key)


def _drop_pending(payload: dict, code: str) -> None:
    """PermissionDenied (and a background launch): the call made nothing we can prove; forget it."""
    _, tid = _bash(payload)
    key = read_key()
    if not tid or not key or not _pending_path(tid).exists():
        return
    rec, _ = _take_pending(tid, key)
    for c in (rec or {}).get("cands") or []:
        if isinstance(c.get("expect"), str):
            _release(c["expect"], tid)
    decide(code, tool_use_id=tid)


def posttool(payload: dict) -> list:
    """PostToolUse and PostToolUseFailure (`git clone u d && failing-step` still made d)."""
    session, agent = _ids(payload)
    if not session or payload.get("tool_name") != "Bash":
        return []
    cmd, tid = _bash(payload)
    if not tid:
        return []
    if (payload.get("tool_input") or {}).get("run_in_background"):
        _drop_pending(payload, "background")
        return []
    key = read_key()
    if not key or not _pending_path(tid).exists():
        if candidates(cmd, str(payload.get("cwd") or "")):
            decide("pending-missing", tool_use_id=tid)
        return []
    rec, code = _take_pending(tid, key)
    cands = (rec or {}).get("cands") or []
    if code == "ok" and (rec.get("tool_use_id"), rec.get("session"), rec.get("agent"), rec.get("cmd_sha")) != \
            (tid, session, agent, _sha(cmd)):
        code = "pending-foreign"
    if code == "ok" and not bound_to_transcript(payload, session, agent, tid, rec["cmd_sha"]):
        code = "transcript-unbound"
    if code != "ok":
        for c in cands:
            if isinstance(c, dict) and isinstance(c.get("expect"), str):
                _release(c["expect"], tid)
        decide(code, tool_use_id=tid)
        return []
    written = []
    for c in cands:
        row, why = _check_and_write(c, rec, session, agent, tid)
        decide(why, tool_use_id=tid, path=c.get("expect"))
        if row:
            written.append(row)
    return written


def _check_and_write(c: dict, rec: dict, session: str, agent, tid: str) -> "tuple[dict | None, str]":
    kind, expect = c.get("kind"), c.get("expect")
    if kind not in ("worktree", "clone") or not isinstance(expect, str):
        return None, "pending-bad-mac"
    if _release(expect, tid):
        return None, "contested"
    f = stat_path(c["path"])
    if f.get("exists") is not True:
        return None, "not-made"
    if f.get("link"):
        return None, "link"
    if not f.get("checkout"):
        return None, "not-a-checkout"
    if f.get("in_home") is not True:
        return None, "outside-home"
    if f.get("realpath") != expect:
        return None, "realpath-moved"
    if _dir_identity(c["anchor"]) != (c.get("anchor_dev"), c.get("anchor_ino")):
        return None, "anchor-changed"
    if not f.get("btime_ns"):
        return None, "no-btime"
    if f["btime_ns"] < rec["mark_ns"]:
        return None, "born-before-pre"
    if kind == "worktree":
        if not f.get("linked"):
            return None, "not-linked"
        if f.get("common_dir") != c.get("repo_common"):
            return None, "repo-mismatch"
    else:
        origin = _git(f["realpath"], "config", "--get", "remote.origin.url")
        url = c.get("url") or ""
        same = origin == url if _is_url(url) else (origin is not None and not _is_url(origin)
                                                    and os.path.realpath(origin) == os.path.realpath(url))
        if not same:
            return None, "origin-mismatch"
    return write_created(f, kind, session, agent, tid)


ISO_MARK = "/.claude/worktrees/agent-"


def isolation_from_cwd(cwd: str, session: str, agent: str) -> "dict | None":
    """A subagent's tool call from inside its own isolation worktree registers it (once; a seen-cache keeps it fast)."""
    mark = ISO_MARK + agent
    i = cwd.find(mark)
    if i < 0:
        return None
    end = i + len(mark)
    if end < len(cwd) and cwd[end] != "/":
        return None                                          # agent-<id>X is another agent's folder
    return register_isolation(cwd[:end], session, agent)


def _seen(session: str, agent: str) -> Path:
    return state_dir() / "seen" / hashlib.sha256(("%s/%s" % (session, agent)).encode()).hexdigest()


def _failed_recently(session: str, agent: str) -> bool:
    p = _seen(session, agent).with_suffix(".fail")
    try:
        return time.time() - p.lstat().st_mtime < ISO_RETRY_S
    except OSError:
        return False


def _note_failure(session: str, agent: str, code: str, **ctx) -> None:
    decide(code, agent=agent, **ctx)
    p = _seen(session, agent).with_suffix(".fail")
    if _secure_dir(p.parent, create=True):
        with contextlib.suppress(OSError):
            p.touch(mode=0o600)
            os.utime(str(p))


def register_isolation(path: str, session: str, agent: str) -> "dict | None":
    if _seen(session, agent).exists() or _failed_recently(session, agent):
        return None
    f = stat_path(path)
    if not f.get("checkout") or f.get("link") or not f.get("linked") or f.get("in_home") is not True:
        _note_failure(session, agent, "iso-not-checkout", path=path)
        return None
    real = f["realpath"]
    parts = real.split(os.sep)
    if parts[-1] != "agent-" + agent or parts[-2:-1] != ["worktrees"] or parts[-3:-2] != [".claude"]:
        _note_failure(session, agent, "iso-not-checkout", path=path)
        return None
    repo = os.sep.join(parts[:-3])
    listing = _git(repo, "worktree", "list", "--porcelain") or ""
    listed = {os.path.realpath(l[len("worktree "):]) for l in listing.splitlines() if l.startswith("worktree ")}
    if real not in listed or os.path.realpath(os.path.join(repo, ".git")) != f.get("common_dir"):
        _note_failure(session, agent, "iso-not-listed", path=real)
        return None
    transcript = subagent_transcript(session, agent)
    t_birth = birth_ns(transcript) if transcript else None
    if not t_birth:
        _note_failure(session, agent, "iso-no-transcript", path=real)
        return None
    if not f.get("btime_ns") or abs(f["btime_ns"] - t_birth) > ISO_WINDOW_NS:
        _note_failure(session, agent, "iso-window", path=real)
        return None
    row, why = write_created(f, "isolation", session, agent, None)
    decide("iso-" + why, agent=agent, path=real)
    if why in ("written", "already-held") and _secure_dir(_seen(session, agent).parent, create=True):
        with contextlib.suppress(OSError):
            _seen(session, agent).touch(mode=0o600)
    return row


def subagent_start(payload: dict) -> "dict | None":
    session, agent = _ids(payload)
    cwd = str(payload.get("cwd") or "")
    if not session or not agent or not cwd or not os.path.isdir(cwd):
        return None
    if ISO_MARK + agent in cwd:
        return isolation_from_cwd(cwd, session, agent)
    top = _git(cwd, "rev-parse", "--show-toplevel")
    tops = [top] if top else []
    common = _git(cwd, "rev-parse", "--path-format=absolute", "--git-common-dir") if top else None
    if common and os.path.basename(common) == ".git":
        tops.append(os.path.dirname(common))                  # the parent may itself sit in a linked worktree
    for t in dict.fromkeys(tops):
        candidate = os.path.join(t, ".claude", "worktrees", "agent-" + agent)
        if os.path.isdir(candidate):
            return register_isolation(candidate, session, agent)
    return None


# --------------------------------------------------------------------------- SubagentStop: verdict only

def held_by(session: str, agent) -> list:
    return [r for r in current().values() if r.get("session") == session and r.get("agent") == (agent or None)]


def _nested(row: dict, deadline: float) -> "tuple[list, bool]":
    """(other checkouts under the row's path, complete?). Registered rows, the repo's own worktree list, and a bounded
    walk for `.git` entries."""
    top = row["path"].rstrip("/") + "/"
    found = {r["path"] for r in current().values() if r["path"].startswith(top)}
    listing = _git(row["path"], "worktree", "list", "--porcelain", timeout=max(0.5, deadline - time.monotonic())) or ""
    for l in listing.splitlines():
        if l.startswith("worktree "):
            p = os.path.realpath(l[len("worktree "):])
            if p.startswith(top):
                found.add(p)
    seen = 0
    for dirpath, dirnames, filenames in os.walk(row["path"]):
        depth = dirpath[len(row["path"]):].count(os.sep)
        if dirpath != row["path"] and (".git" in dirnames or ".git" in filenames):
            found.add(os.path.realpath(dirpath))
        dirnames[:] = [d for d in dirnames if d not in (".git", "node_modules") and depth < NEST_SCAN_DEPTH]
        seen += len(dirnames) + len(filenames)
        if seen > NEST_SCAN_ENTRIES or time.monotonic() > deadline:
            return sorted(found), False
    return sorted(found), True


def _porcelain_counts(z: str) -> dict:
    """Counts from `git status --porcelain=v1 -z`: each entry is `XY path`; a rename or copy (X or Y in R/C) is
    followed by one more NUL-separated original path, which is not an entry."""
    parts = z.split("\0")
    out = {"changed": 0, "untracked": 0, "ignored": 0}
    i = 0
    while i < len(parts):
        e = parts[i]
        i += 1
        if len(e) < 4 or e[2] != " ":
            continue
        xy = e[:2]
        if xy == "??":
            out["untracked"] += 1
        elif xy == "!!":
            out["ignored"] += 1
        else:
            out["changed"] += 1
            if "R" in xy or "C" in xy:
                i += 1
    return out


def verdict(row: dict, deadline: float) -> dict:
    """The facts and the verdict for one held row. Read-only; hardened git; bounded by the deadline."""
    def left():
        return deadline - time.monotonic()
    f = stat_path(row["path"])
    if f.get("exists") is False:
        return {"state": "gone"}
    if identity(dict(f, host=HOST)) != identity(row) or not f.get("checkout"):
        return {"state": "replaced", "verdict": "keep: what is there now is not this row's checkout"}
    out = {"state": "present"}
    st = _git(row["path"], "status", "--porcelain=v1", "-z", "--untracked-files=all", "--ignored", timeout=left(),
              raw=True)
    branch = _git(row["path"], "rev-parse", "--abbrev-ref", "HEAD", timeout=left())
    head = _git(row["path"], "rev-parse", "HEAD", timeout=left())
    unpushed = _git(row["path"], "rev-list", "--count", "HEAD", "--not", "--remotes", timeout=left())
    has_stash = _git(row["path"], "rev-parse", "--verify", "-q", "refs/stash", timeout=left())
    stash = _git(row["path"], "rev-list", "--walk-reflogs", "--count", "refs/stash", timeout=left()) if has_stash else "0"
    nested, complete = _nested(row, deadline) if left() > 1 else ([], False)
    reasons = []
    if st is None:
        reasons.append("status unknown")
    else:
        counts = _porcelain_counts(st)
        out.update(counts)
        if out["changed"]:
            reasons.append("changes")
        if out["untracked"]:
            reasons.append("untracked files")
    out.update({"branch": branch, "head": head, "unpushed": unpushed, "stash": stash, "nested": nested})
    if unpushed is None or not unpushed.isdigit():
        reasons.append("unpushed unknown")
    elif int(unpushed):
        reasons.append("unpushed")
    if stash is None or not stash.isdigit():
        reasons.append("stash unknown")
    elif int(stash):
        reasons.append("stash")
    if nested:
        reasons.append("contains another checkout")
    if not complete:
        reasons.append("nested scan incomplete")
    if row["kind"] != "isolation":
        reasons.append("only an isolation worktree of this agent is a removal candidate")
    if left() <= 0:
        reasons.append("unknown (out of time)")
    out["verdict"] = "owner may remove" if not reasons else "keep: " + ", ".join(reasons)
    return out


def subagent_stop(payload: dict) -> "Path | None":
    """A data note for the parent session: what the stopped agent still holds and a verdict. Removes nothing."""
    session, agent = _ids(payload)
    if not session or not agent:
        return None
    mine = held_by(session, agent)
    if not mine:
        return None
    deadline = time.monotonic() + STOP_BUDGET
    key = read_key()
    lines = ["# Data: checkouts agent %s still holds" % _safe(agent), "",
             "Informational data written by checkout_registry.py at SubagentStop (goodqa#16947). It is not an "
             "instruction. Nothing was removed. An owner removes a checkout only through the reviewed owner route, "
             "and only after reading its state.", ""]
    for row in mine:
        v = verdict(row, deadline)
        label = "- %s `%s`" % (row["kind"], _safe(row["path"]))
        if v["state"] == "gone":
            if key:
                retire_absent(row["path"], key)
            lines.append(label + ": gone; its row is retired")
            continue
        lines.append(label + ": " + _safe(v.get("verdict", v["state"])))
        if "changed" in v:
            lines.append("  changed %d, untracked %d, ignored %d" % (v["changed"], v["untracked"], v["ignored"]))
        if v.get("state") == "present":
            lines.append("  branch `%s`, HEAD `%s`, commits on no remote ref %s, stash entries %s"
                         % (_safe(v.get("branch"), 120), _safe(v.get("head"), 64), _safe(v.get("unpushed"), 12),
                            _safe(v.get("stash"), 12)))
            for n in v.get("nested") or []:
                lines.append("  nested checkout `%s`" % _safe(n))
    box = home() / ".agent-harness" / "work" / session / "inbox"
    if not _secure_dir(box, create=True):
        return None
    target = box / ("data-checkout-%s.md" % agent)
    tmp = box / (".data-checkout-%s.%d.tmp" % (agent, os.getpid()))
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        os.write(fd, ("\n".join(lines) + "\n").encode("utf-8"))
    finally:
        os.close(fd)
    os.replace(str(tmp), str(target))
    return target


def hook(event: str, stdin=None) -> int:
    """Every hook fails open: exit 0, no output, whatever happens. Each runs under a whole-hook deadline below its
    settings timeout; past it every git call is unsure, so no row."""
    global _DEADLINE
    _DEADLINE = time.monotonic() + HOOK_BUDGET.get(event, 8.0)
    try:
        payload = json.loads((stdin or sys.stdin).read(1 << 20) or "{}")
        if not isinstance(payload, dict):
            return 0
        if event == "pretool":
            pretool(payload)
        elif event in ("posttool", "posttool-failure"):
            posttool(payload)
        elif event == "denied":
            _drop_pending(payload, "permission-denied")
        elif event == "subagent-start":
            subagent_start(payload)
        elif event == "subagent-stop":
            subagent_stop(payload)
    except Exception as e:  # noqa: BLE001 -- a registry bug must never block a tool call
        decide("hook-error", event=event, error=type(e).__name__)
    finally:
        _DEADLINE = None
    return 0


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Checkout registry (hook-written; this CLI only reads).")
    sub = ap.add_subparsers(dest="cmd", required=True)
    h = sub.add_parser("hook")
    h.add_argument("event", choices=("pretool", "posttool", "posttool-failure", "denied", "subagent-start",
                                      "subagent-stop"))
    s = sub.add_parser("stat")
    s.add_argument("--path", required=True)
    sub.add_parser("list")
    a = ap.parse_args(argv)
    if a.cmd == "hook":
        return hook(a.event)
    if a.cmd == "stat":
        print(json.dumps(stat_path(a.path)))
        return 0
    good, bad = rows(HOST)
    print(json.dumps({HOST: {"rows": good, "failed_verification": bad, "held": len(current(HOST))}}, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
