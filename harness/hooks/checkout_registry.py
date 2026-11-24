#!/usr/bin/env python3
"""checkout_registry.py: hook-written ownership rows for the git checkouts agents create (goodqa#16947, spec v3.2).

A Claude agent's `git clone` or `git worktree add` run through Bash on this machine, and each isolation worktree Claude
Code makes for a subagent (`<repo>/.claude/worktrees/agent-<agent_id>`), gets at most ONE signed `created` row naming
the session and agent that made it. The row exists only when a hook saw the checkout being born during that agent's own
call. Stream B's owner removal accepts only `held(identity)` as ownership proof; the janitor reads the same rows.

    ~/.agent-harness/state/checkouts/local.jsonl
    {"v":1,"event":"created","kind":"isolation|worktree|clone","host":"local","path":<realpath>,"dev":N,"ino":N,
     "btime_ns":N,"common_dir":<realpath>,"session":...,"agent":<agent id or null>,"task":null,"created_at":<utc>,
     "tool_use_id":<id or null for isolation>,"mac":<HMAC-SHA256>}

IDENTITY is (host, dev, ino, btime_ns, gen). ext4 reuses an inode number at once (40 of 40 on t2-dev), even inside one
clock tick (249 of 300 in-process rounds kept dev, ino and btime), and a moved checkout keeps inode and birth time. So:
no btime, or on Linux no inode generation, means no row; a Bash row needs the checkout, its .git and a worktree's admin
folder born between a Pre and a Post clock mark on the marker's filesystem; a path seen absent retires its rows (Rule
14); two created rows for one identity mean no owner. A row owns that one checkout, never what is nested under it.

THE RULE: a missing row is safe; a wrong row deletes someone's work. The command text only PROPOSES a path. A Bash
row needs, all observed: Pre saw the path absent (ENOENT), pinned the nearest existing folder above it, took the clock
mark and claimed the path (NFC casefolded key) under the lock with no other live claim; Post (PostToolUse or
PostToolUseFailure) carries the same tool_use_id, session, agent and command hash as the signed pending record; the
payload's transcript is the session's own, and an agent's call is found in its own subagent file; the path is now a
checkout top, not a link, under home, at exactly the expected realpath, the pinned folder unchanged, born inside the
call; a clone's origin is the command's URL, a worktree is linked and shares the named repo's common dir; nothing
holds the identity yet. Anything unsure: no row, and one reason code in state/checkouts/decisions.jsonl.

GIT: no hook runs porcelain (status, log, diff, show, stash ...); _git refuses it. A repo whose own config names a
program (filter, textconv, fsmonitor, hooksPath, gpg program) gets "keep" before any content-reading command runs.

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
    checkout_registry.py retire --path P   Rule 14 only: end ownership of a checkout that is gone
    checkout_registry.py list              read-only: verified rows, failures, what is held
"""
from __future__ import annotations

import argparse
import array
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
import struct
import subprocess
import sys
import time
import unicodedata
from pathlib import Path

VERSION = 1
HOST = "local"
HOSTS = ("local",)                  # PR 2 adds "t2-dev"
KINDS = ("isolation", "worktree", "clone")
GIT_TIMEOUT = 5
STAT_TIMEOUT = 5
PENDING_TTL = 2 * 3600
ISO_WINDOW_NS = 120 * 10 ** 9       # transcript born 0..120 s after its isolation worktree (197 of 197 pairs <= 29 s)
ISO_RETRY_S = 60                    # a failed isolation check is not repeated on every tool call
LOCK_WAIT = 2.0
LOCAL_FS_LINUX = {"ext2/ext3", "xfs", "btrfs", "tmpfs", "zfs", "f2fs", "bcachefs"}
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


class LockTimeout(Exception):
    """The registry lock was not free within LOCK_WAIT: no row (code lock-timeout)."""


class LedgerTooLarge(Exception):
    """The ledger is over MAX_FILE: held() is None and the writer refuses (code ledger-too-large)."""


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
    """Rule 13: one exclusive lock per machine around every re-check-and-append and every claim. The wait polls
    LOCK_NB up to LOCK_WAIT (never past the hook deadline); then LockTimeout. A dead holder's flock is released by the
    kernel."""
    fd = os.open(str(state_dir() / "registry.lock"), os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        st = os.fstat(fd)
        if not stat_mod.S_ISREG(st.st_mode) or st.st_uid != os.getuid() or st.st_mode & 0o077:
            raise LockTimeout("lock file is not a private regular file")
        end = time.monotonic() + max(0.0, _left(LOCK_WAIT))
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= end:
                    raise LockTimeout("registry lock busy")
                time.sleep(0.02)
        yield
    finally:
        os.close(fd)


def state_is_local() -> bool:
    """Rule 13: the state folder must be on a local filesystem (flock over NFS, SMB or FUSE is not reliable)."""
    d = str(state_dir())
    try:
        if sys.platform == "darwin":
            r = subprocess.run(["/sbin/mount"], capture_output=True, text=True, timeout=_left(STAT_TIMEOUT),
                               env={"LC_ALL": "C", "PATH": "/usr/bin:/bin:/sbin"}, stdin=subprocess.DEVNULL)
            real, best, flags = os.path.realpath(d), "", ""
            for line in r.stdout.splitlines():
                m = re.match(r".+? on (/.*?) \((.*)\)$", line)
                if m and (real == m.group(1) or real.startswith(m.group(1).rstrip("/") + "/")) \
                        and len(m.group(1)) > len(best):
                    best, flags = m.group(1), m.group(2)
            return r.returncode == 0 and "local" in [f.strip() for f in flags.split(",")]
        r = subprocess.run(["/usr/bin/stat", "-f", "-c", "%T", "--", d], capture_output=True, text=True,
                           timeout=_left(STAT_TIMEOUT), env={"LC_ALL": "C", "PATH": "/usr/bin:/bin"},
                           stdin=subprocess.DEVNULL)
        return r.returncode == 0 and r.stdout.strip() in LOCAL_FS_LINUX
    except (OSError, subprocess.SubprocessError, ValueError):
        return False


def ledger_path(host: str = HOST) -> Path:
    if host not in HOSTS:
        raise ValueError("unknown host %r" % host)
    return state_dir() / ("%s.jsonl" % host)


def rows(host: str = HOST, key: "bytes | None" = None) -> "tuple[list, int]":
    """(verified rows of this host's file, how many lines failed). The whole file is read (bounded at 64 MB). A row
    whose `host` names another host fails: a row pasted between files never counts."""
    key = key or read_key()
    with contextlib.suppress(OSError):
        if os.lstat(str(ledger_path(host))).st_size > MAX_FILE:
            raise LedgerTooLarge(host)                  # never judge ownership from part of the file
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
    return (row.get("host"), row.get("dev"), row.get("ino"), row.get("btime_ns"), row.get("gen"))


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
    try:
        return current(host).get(identity(ident))
    except LedgerTooLarge:
        return None


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
    if not state_is_local():
        return None, "state-not-local"
    if sys.platform != "darwin" and info.get("gen") is None:
        return None, "no-generation"
    row = {"v": VERSION, "event": "created", "kind": kind, "host": HOST, "path": info["realpath"], "dev": info["dev"],
           "ino": info["ino"], "btime_ns": info["btime_ns"], "gen": info.get("gen"), "common_dir": info.get("common_dir"), "session": session,
           "agent": agent or None, "task": None, "created_at": _utc(), "tool_use_id": tool_use_id or None}
    try:
        with _locked():
            live = current(HOST, key)
            held_row = live.get(identity(row))
            if held_row:
                same = (held_row.get("session"), held_row.get("agent")) == (session, agent or None)
                return None, "already-held" if same else "second-owner"
            if any(identity(r) == identity(row) and r.get("event") == "created" for r in rows(HOST, key)[0]):
                return None, "contested-identity"      # a created row exists but counts as owned by no one
            return _append(row, key), "written"
    except LockTimeout:
        return None, "lock-timeout"
    except LedgerTooLarge:
        return None, "ledger-too-large"


def _removed_row(held_row: dict, by: str, route: str) -> dict:
    return {"v": VERSION, "event": "removed", "kind": held_row["kind"], "host": held_row["host"],
            "path": held_row["path"], "dev": held_row["dev"], "ino": held_row["ino"],
            "btime_ns": held_row["btime_ns"], "gen": held_row.get("gen"), "common_dir": held_row.get("common_dir"),
            "session": held_row["session"], "agent": held_row.get("agent"), "task": held_row.get("task"),
            "by": _safe(by, 200), "route": _safe(route, 200), "removed_at": _utc()}


def append_removed(ident: dict, by: str, route: str) -> "dict | None":
    """For stream B's route, after a successful removal: one `removed` row for an identity held now. None when
    nothing is held under exactly that identity (a forged or unmatched removal changes nothing)."""
    key = ensure_key()
    if not key or ident.get("host") not in HOSTS:
        return None
    try:
        with _locked():
            held_row = current(ident["host"], key).get(identity(ident))
            return _append(_removed_row(held_row, by, route), key) if held_row else None
    except (LockTimeout, LedgerTooLarge):
        return None


def _absent_on(path: str, dev) -> bool:
    """Rule 14 observation: `path` is ENOENT and the nearest existing folder above it is on st_dev `dev` (so an
    unmounted volume or a missing mount never counts as the checkout being gone)."""
    try:
        os.lstat(path)
        return False
    except FileNotFoundError:
        pass
    except OSError:
        return False
    a = _anchor(path)
    return bool(a) and a["dev"] == dev


def retire_absent(real: str, key: bytes) -> int:
    """Rule 14: retire every row held for exactly `real` when two lstats under the lock give ENOENT and the nearest
    existing folder is on the row's own st_dev. Retirement only removes ownership; a retired row is never permission
    to delete anything."""
    n = 0
    try:
        with _locked():
            for row in current(HOST, key).values():
                if row.get("path") == real and _absent_on(real, row.get("dev")) and _absent_on(real, row.get("dev")):
                    _append(_removed_row(row, "checkout_registry", "observed-absent"), key)
                    n += 1
    except (LockTimeout, LedgerTooLarge) as e:
        decide("lock-timeout" if isinstance(e, LockTimeout) else "ledger-too-large", path=real)
        return 0
    if n:
        decide("observed-absent", path=real, rows=n)
    return n


# --------------------------------------------------------------------------- facts about one path (read-only)

def _git_env() -> dict:
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update({"GIT_CONFIG_NOSYSTEM": "1", "GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0", "LC_ALL": "C",
                "GIT_NO_LAZY_FETCH": "1"})
    return env


GIT_HARDEN = ("-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", "-c", "core.untrackedCache=false",
              "-c", "log.showSignature=false", "-c", "protocol.allow=never", "--no-optional-locks")
# Rule 12: a hook never runs a porcelain command that can start a repo-configured program (status, log, diff, stash
# list, show). Every git call goes through _git, and _git refuses these.
PORCELAIN = {"status", "log", "diff", "show", "stash", "blame", "grep", "archive", "fetch", "pull", "push", "commit",
             "checkout", "switch", "merge", "rebase", "cherry-pick", "am", "apply", "gc", "maintenance"}


def _git(path: str, *args, timeout: float = GIT_TIMEOUT, raw: bool = False) -> "str | None":
    """git hardened against the repo it reads: no fsmonitor, no hooks, no optional locks, no GIT_* from the caller.
    None (unsure) once the whole-hook deadline has passed. raw keeps the output byte-exact (porcelain -z starts with
    a significant space)."""
    if not args or args[0] in PORCELAIN:
        raise ValueError("porcelain git is not allowed in a hook: %r" % (args[:1],))
    timeout = _left(timeout)
    if timeout <= 0.2:
        return None
    try:
        r = subprocess.run(["git", *GIT_HARDEN, "-C", path, *args],
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


FS_IOC_GETVERSION = (2 << 30) | (struct.calcsize("l") << 16) | (ord("v") << 8) | 1     # _IOR('v', 1, long)


def inode_generation(path: str) -> "int | None":
    """Linux: the inode generation (FS_IOC_GETVERSION), which ext4 changes whenever it reuses an inode number, even
    within one clock tick (probe P8: 249 of 300 in-process rounds had equal dev, ino and btime; the generation
    differed in all). Unprivileged; kept across a rename. None when it cannot be read. Not used on macOS (APFS does
    not reuse an inode number)."""
    if sys.platform == "darwin":
        return None
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
    except OSError:
        return None
    try:
        buf = array.array("l", [0])
        fcntl.ioctl(fd, FS_IOC_GETVERSION, buf, True)
        return buf[0] & 0xFFFFFFFF
    except OSError:
        return None
    finally:
        os.close(fd)


def clock_mark() -> "tuple[int, int] | None":
    """(birth time in ns, st_dev) of a fresh file in state/checkouts/marks/: the clock that stamps a new checkout on
    the same filesystem. Pre and Post each take one; a checkout must be born between them (Rule 8)."""
    d = state_dir() / "marks"
    if not _secure_dir(d, create=True):
        return None
    p = d / ("mark-%d-%s" % (os.getpid(), os.urandom(6).hex()))
    try:
        fd = os.open(str(p), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            dev = os.fstat(fd).st_dev
        finally:
            os.close(fd)
        ns = birth_ns(str(p))
        return (ns, dev) if ns else None
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
                "gen": inode_generation(p),
                "in_home": real.startswith(h + os.sep)})
    dotgit = os.path.join(real, ".git")
    if not os.path.lexists(dotgit):
        return out
    top = _git(real, "rev-parse", "--show-toplevel")
    common = _git(real, "rev-parse", "--path-format=absolute", "--git-common-dir")
    admin = _git(real, "rev-parse", "--absolute-git-dir")
    if top and os.path.realpath(top) == real and common and admin:
        linked = os.path.isfile(dotgit) and not os.path.islink(dotgit)
        out.update({"checkout": True, "linked": linked, "common_dir": os.path.realpath(common),
                    "git_dir": os.path.realpath(admin), "dotgit_btime_ns": birth_ns(dotgit),
                    "admin_btime_ns": birth_ns(os.path.realpath(admin)) if linked else None})
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


def claim_key(expect: str) -> str:
    """Rule 4: the expected path, NFC-normalized and casefolded. It does not depend on which ancestor existed at Pre,
    and it matches case and normalization variants (APFS is insensitive to both; on Linux it only over-matches)."""
    return unicodedata.normalize("NFC", expect).casefold()


def _claim_file(kind: str, real: str) -> Path:
    data = ("%s\0%s" % (HOST, claim_key(real))).encode("utf-8", "surrogateescape")    # non-UTF-8 path bytes hash
    return state_dir() / kind / hashlib.sha256(data).hexdigest()


def _fresh(p: Path) -> bool:
    try:
        return time.time() - p.lstat().st_mtime <= PENDING_TTL
    except OSError:
        return False


def _claim(real: str, tool_use_id: str) -> str:
    """Under the lock: one tool call at a time may expect a path (by claim_key). A second call expecting it marks it
    contested, and then neither call writes a row. A claim file that exists but cannot be read counts as someone
    else's live claim. Returns "ok", "contested" or "lock-timeout"."""
    for kind in ("claims", "contested"):
        if not _secure_dir(state_dir() / kind, create=True):
            return "contested"
    try:
        with _locked():
            claim = _claim_file("claims", real)
            holder = None
            if _fresh(claim):
                data = _read_secure(claim, 4096)
                holder = data.decode("utf-8", "replace") if data else "\0unreadable"
            if holder and holder != tool_use_id:
                mark = _claim_file("contested", real)
                fd = os.open(str(mark), os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0), 0o600)
                os.close(fd)
                os.utime(str(mark))
                return "contested"
            if _fresh(_claim_file("contested", real)):
                return "contested"
            tmp = claim.with_name(claim.name + ".%d.tmp" % os.getpid())
            fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
            try:
                os.write(fd, tool_use_id.encode("utf-8"))
            finally:
                os.close(fd)
            os.replace(str(tmp), str(claim))
    except LockTimeout:
        return "lock-timeout"
    except OSError:
        return "contested"
    return "ok"


def _release(real: str, tool_use_id: str) -> bool:
    """Drop our claim; True when the path was contested meanwhile, or when that cannot be known (then no row)."""
    try:
        with _locked():
            claim = _claim_file("claims", real)
            data = _read_secure(claim, 4096)
            if data and data.decode("utf-8", "replace") == tool_use_id:
                with contextlib.suppress(OSError):
                    claim.unlink()
            return _fresh(_claim_file("contested", real))
    except (LockTimeout, OSError):
        return True


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
        got = _claim(expect, tid)
        if got != "ok":
            decide(got, tool_use_id=tid, path=expect)
            continue
        keep.append(entry)
    if keep:
        _write_pending({"v": VERSION, "tool_use_id": tid, "session": session, "agent": agent, "at": time.time(),
                        "cmd_sha": _sha(cmd), "mark_ns": mark[0], "mark_dev": mark[1], "cands": keep}, key)


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
    post_mark = clock_mark()                 # Rule 8: taken before any Post observation, so a later object fails
    written = []
    for c in cands:
        if post_mark is None:
            _release(c.get("expect") or "", tid)
            decide("no-mark", tool_use_id=tid, path=c.get("expect"))
            continue
        row, why = _check_and_write(c, dict(rec, post_mark_ns=post_mark[0]), session, agent, tid)
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
    if f.get("realpath") != expect:                  # byte for byte; casefolding is for the claim key only
        return None, "realpath-moved"
    if _dir_identity(c["anchor"]) != (c.get("anchor_dev"), c.get("anchor_ino")):
        return None, "anchor-changed"
    if f.get("dev") != rec.get("mark_dev"):
        return None, "other-fs"
    if kind == "worktree":
        if not f.get("linked"):
            return None, "not-linked"
        if f.get("common_dir") != c.get("repo_common"):
            return None, "repo-mismatch"
    births = [f.get("btime_ns"), f.get("dotgit_btime_ns")] + ([f.get("admin_btime_ns")] if kind == "worktree" else [])
    if not all(births):
        return None, "no-btime"
    if not all(rec["mark_ns"] <= b <= rec["post_mark_ns"] for b in births):
        return None, "born-outside-call"
    if kind == "clone":
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
        decide("iso-no-transcript", agent=agent, path=real)   # never cached: SubagentStart may precede the transcript
        return None
    if not f.get("btime_ns") or not 0 <= t_birth - f["btime_ns"] <= ISO_WINDOW_NS:
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


REPO_PROGRAM_KEY = re.compile(r"(filter\..+|diff\..+\.textconv|diff\.external|core\.fsmonitor|core\.hookspath"
                              r"|gpg\.(.+\.)?program)", re.I)


def _trusted_config_files() -> set:
    """The user's own global git config files (Rule 12); everything else a checkout reads is the repo's own."""
    xdg = os.environ.get("XDG_CONFIG_HOME") or str(home() / ".config")
    return {os.path.realpath(str(home() / ".gitconfig")), os.path.realpath(os.path.join(xdg, "git", "config"))}


def repo_programs(path: str, timeout: float) -> "list | None":
    """Config keys that can make git start a program, set by the repo's own config (its local and worktree files and
    anything they include). None when unknown. Reads config only; runs nothing."""
    z = _git(path, "config", "--list", "--show-origin", "--includes", "-z", timeout=timeout, raw=True)
    if z is None:
        return None
    parts = z.split("\0")
    trusted = _trusted_config_files()
    found = []
    for i in range(0, len(parts) - 1, 2):
        origin, entry = parts[i], parts[i + 1]
        key = entry.split("\n", 1)[0]
        if origin.startswith("command line:") or not REPO_PROGRAM_KEY.fullmatch(key):
            continue
        if origin.startswith("file:") and os.path.realpath(origin[len("file:"):]) in trusted:
            continue
        found.append(key)
    return found


def _names(z: "str | None") -> "set | None":
    return None if z is None else {n for n in z.split("\0") if n}


def regenerable(top: str, entry: str) -> bool:
    """An ignored entry that a build or install recreates: node_modules beside a package.json, a virtualenv (a folder
    holding pyvenv.cfg), __pycache__ and *.pyc. Anything else ignored may be someone's only copy."""
    full = os.path.join(top, entry.rstrip("/"))
    if _regenerable_path(full):
        return True
    if not entry.endswith("/") or os.path.islink(full):
        return False
    # `ls-files --directory` collapses a folder that holds only ignored files into one entry: judge what is in it.
    seen = 0
    for dirpath, dirnames, filenames in os.walk(full):
        dirnames[:] = [d for d in dirnames if not _regenerable_path(os.path.join(dirpath, d))]
        for fn in filenames:
            if not _regenerable_path(os.path.join(dirpath, fn)):
                return False
        seen += len(dirnames) + len(filenames)
        if seen > NEST_SCAN_ENTRIES:
            return False                                     # too much to judge: keep
    return True


def _regenerable_path(full: str) -> bool:
    name = os.path.basename(full)
    if os.path.islink(full):
        return False
    if name == "node_modules" and os.path.isfile(os.path.join(os.path.dirname(full), "package.json")):
        return True
    if os.path.isdir(full) and os.path.isfile(os.path.join(full, "pyvenv.cfg")):
        return True
    if name == "__pycache__" and os.path.isdir(full):
        return True
    return name.endswith(".pyc") and os.path.isfile(full)


def verdict(row: dict, deadline: float) -> dict:
    """The facts and the verdict for one held row. Read-only. Rule 12: plumbing only, and nothing that reads file
    content runs until the repo is known to configure no program."""
    def left():
        return deadline - time.monotonic()
    f = stat_path(row["path"])
    if f.get("exists") is False:
        return {"state": "gone"}
    if identity(dict(f, host=HOST)) != identity(row) or not f.get("checkout"):
        return {"state": "replaced", "verdict": "keep: what is there now is not this row's checkout"}
    top = row["path"]
    out = {"state": "present"}
    reasons = []
    programs = repo_programs(top, left())
    if programs is None:
        reasons.append("config unknown")
    elif programs:
        reasons.append("repo config runs programs")
    changed = untracked = ignored = None
    if programs == []:
        work = _names(_git(top, "diff-files", "--name-only", "-z", timeout=left(), raw=True))
        staged = _names(_git(top, "diff-index", "--cached", "--name-only", "-z", "HEAD", timeout=left(), raw=True))
        changed = None if work is None or staged is None else len(work | staged)
        untracked = _names(_git(top, "ls-files", "--others", "--exclude-standard", "-z", timeout=left(), raw=True))
        ignored = _names(_git(top, "ls-files", "--others", "--ignored", "--exclude-standard", "--directory", "-z",
                              timeout=left(), raw=True))
        if changed is None or untracked is None or ignored is None:
            reasons.append("status unknown")
        else:
            out.update({"changed": changed, "untracked": len(untracked), "ignored": len(ignored)})
            if changed:
                reasons.append("changes")
            if untracked:
                reasons.append("untracked files")
            if any(not regenerable(top, e) for e in ignored):
                reasons.append("ignored files")
    branch = _git(top, "rev-parse", "--abbrev-ref", "HEAD", timeout=left())
    head = _git(top, "rev-parse", "HEAD", timeout=left())
    unpushed = _git(top, "rev-list", "--count", "HEAD", "--not", "--remotes", timeout=left())
    has_stash = _git(top, "rev-parse", "--verify", "-q", "refs/stash", timeout=left())
    stash = _git(top, "rev-list", "--walk-reflogs", "--count", "refs/stash", timeout=left()) if has_stash else "0"
    nested, complete = _nested(row, deadline) if left() > 1 else ([], False)
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
    ap = argparse.ArgumentParser(description="Checkout registry (hook-written; this CLI reads, and `retire` only ends "
                                             "ownership of a checkout that is gone).")
    sub = ap.add_subparsers(dest="cmd", required=True)
    h = sub.add_parser("hook")
    h.add_argument("event", choices=("pretool", "posttool", "posttool-failure", "denied", "subagent-start",
                                      "subagent-stop"))
    s = sub.add_parser("stat")
    s.add_argument("--path", required=True)
    r = sub.add_parser("retire", help="Rule 14: retire the rows of an absent path (removes ownership only)")
    r.add_argument("--path", required=True)
    sub.add_parser("list")
    a = ap.parse_args(argv)
    if a.cmd == "hook":
        return hook(a.event)
    if a.cmd == "stat":
        print(json.dumps(stat_path(a.path)))
        return 0
    if a.cmd == "retire":
        key = read_key()
        p = os.path.abspath(os.path.expanduser(a.path))
        anchor = _anchor(p) if not os.path.lexists(p) else None
        if anchor:
            p = anchor["realpath"].rstrip("/") + "/" + anchor["rest"]      # the same expected path Pre would compute
        n = retire_absent(p, key) if key and anchor else 0
        print(json.dumps({"path": p, "retired": n}))
        return 0
    good, bad = rows(HOST)
    print(json.dumps({HOST: {"rows": good, "failed_verification": bad, "held": len(current(HOST))}}, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
