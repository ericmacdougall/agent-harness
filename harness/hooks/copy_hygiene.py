#!/usr/bin/env python3
"""Copy hygiene: one reusable test copy per PR or lane, a disk-low guard, a /dev/shm guard, and an idle-copy reaper
that is report-only by default.

WHY. On 2026-11-21 t2-dev's root volume reached 0 bytes free: ~/.agent-harness/work held 117 GB, most of it per-round
click-test copies (work/<session>/tester-1408-r3, tester-1408-r4, tester-1409-r1, ...). Each review round made a new
full copy and nothing removed the old ones. Sessions also held 50 of the host's 56 GB of /dev/shm (RAM) with scratch.

WHAT.
  acquire       `copy_hygiene.py acquire --repo <checkout> --key <pr-1408|lane> [--ref <ref>]` returns ONE stable path
                (~/.agent-harness/test-copies/<repo>-<id>/<key>) per repository and PR/lane. The first call makes a
                detached linked worktree; later calls reuse it and check out the requested commit. It refuses (exit 4)
                when a ref move could disturb tracked, untracked or ignored data. --require-reuse forbids creating a
                missing copy. --run COMMAND ... holds the lease for the command in the verified checkout. It
                refuses to create a copy below the free-space floor (exit 3) and writes an alert.
  pretool       PreToolUse Bash hook. Below the floor it denies commands that create copies (git clone, git worktree
                add, cp -r/-R/-a, rsync -r/-a, ditto) with a clear alert. Wrapper options do not hide a copy
                (`timeout 120 git clone`). The quoted remote command of a plain `ssh host '...'` is not charged
                to this machine (it copies on the far host); every other command keeps the base reading. See
                copy_commands and the ssh section below.
                It always denies writing scratch INTO
                /dev/shm (RAM); reading, copying out of and removing from /dev/shm stay allowed. Silent otherwise.
                Fails OPEN on any internal error.
  session-start SessionStart hook: at most every 6 h starts a detached report-only `reap`, and prints one line when the
                last report found idle copies or a total over the cap.
  reap          `copy_hygiene.py reap [--apply] [--json]` lists idle copies (older than max_age_hours) and, when the
                total is over max_total_gb, the oldest copies above the cap. REPORT-ONLY unless BOTH the config value
                "reaper_delete_enabled": true (a literal JSON true) is set in ~/.agent-harness/state/copy-hygiene.json
                AND --apply is passed. The installer never sets it, so installing or a first run deletes nothing.
                Even when enabled it removes only an indexed managed linked checkout with no tracked, untracked or
                ignored changes, no stash, no local commits missing from its remotes, no live or unknown use, and
                an idle exclusive lease. It uses plain `git worktree remove` (no --force). Legacy copies are report-only.

  protected     Paths a live service depends on are NEVER deleted (2026-11-21: cleanups on t2-dev removed
                ~/coordinator-v2/rc/agent-harness, claude-rc's WorkingDirectory, plus ~/pp-ci/runner and the ~/pp-ci/nm
                caches the pp gate runs from). Protected: every absolute path named anywhere in a systemd unit
                (system, --user, runtime, transient and generated units and drop-ins; WorkingDirectory=, Exec*=,
                Environment=, paths inside `bash -c '...'` strings; %h/~ expanded, a path cut at an unresolved
                specifier such as %i), every path in a launchd plist, the source of a `systemctl link`ed unit, and
                the config's protected_paths. Deleting a protected path or any directory containing one, or emptying
                one with `<dir>/*`, is refused; single files or build output inside it stay allowed. The pretool hook
                checks rm / rmdir / unlink / shred / trash / gio remove / mv (sources) / find -delete or -exec rm /
                find | xargs rm / git [-C dir] worktree remove, follows `cd`, `bash -c`, sudo/env/timeout wrappers,
                $HOME/$PWD and {a,b}; a relative target under an unknown directory is matched by path tail. It fails
                OPEN on an internal error (with an alert). The reaper fails CLOSED: if any unit file can't be read it
                deletes nothing. `copy_hygiene.py protected [--check <path>]` lists or explains (exit 1 = protected),
                the one choke point other cleaners should call: exit 0 is the only go-ahead, and checking children one
                by one does not cover emptying a directory (check the directory). Known gap: a command sent with
                `ssh host '...'` is not checked by any hook on the far host (the remote host's hook only sees agent
                sessions running there). `rsync --delete` into a service directory and `git clean` are not treated
                as deletes.
  ssh           What is and is not checked for ssh (goodqa#16811). The protected-delete and /dev/shm checks still
                read an ssh's quoted payload as if it ran here (over-reading, never under-reading). The disk-floor
                copy check reads every command the base way and drops exactly one shape: a plain remote ssh
                (_plain_remote_ssh). It must be on a line shell_words.scan verifies (bash and zsh read it as known
                commands), with nothing on the line that may change what `ssh` runs (alias, eval, source, `.`,
                hash, export, a PATH-like assignment, `env -S`, a program word built at run time). Its program word
                is `ssh` or the system ssh by an absolute path, with sudo/timeout/nice-style wrappers allowed but no
                assignment, and no ProxyCommand/LocalCommand/KnownHostsCommand/Include/Match option and no -F or -I.
                Every option, option value and the host are spelled out: no expansion, glob, brace or tilde.
                OpenSSH also parses options after the host, so the first word after it must start with literal
                text other than `-`. The same rule applies inside `bash -c '...'`. Anything else gets the base
                reading. That covers every other command on the line (`ssh h '...' && git clone a b`) and the whole
                line whenever shell_words cannot verify it: `$(...)` or backticks outside single quotes, a comment,
                a backslash, ANSI-C quoting, a heredoc or unbalanced quotes.
                The code that eval, alias, trap and `env -S` carry in their words is read as a command line too.
                Not checked (not before goodqa#16811 either):
                  - a command hidden in a variable's value or a file: `C='git clone u d'; $C`, a sourced file, or
                    `X='-oProxyCommand=git clone ...'; ssh "$X" h`. That ssh gets the base reading, and the base
                    reading cannot see inside $X;
                  - whether the host is really another machine: `ssh localhost '...'` or an alias of this machine
                    copies onto this disk uncounted (the hook does no DNS or ssh-config reading);
                  - a redirect of the remote output onto this disk: `ssh devbox 'tar c dir' > local.tar` writes
                    remote data here and is not counted;
                  - the far host's own floor.
  scratch       `copy_hygiene.py scratch [--key <name>]` creates and prints a private (0700) disk-backed scratch
                directory, ~/.agent-harness/scratch/<session>, the replacement for /dev/shm:
                `export TMPDIR=$(python3 ~/.claude/hooks/copy_hygiene.py scratch)`. Refused below the disk floor; its
                size is shown in the reap report (scratch is never reaped).

Config (~/.agent-harness/state/copy-hygiene.json; every key optional):
  min_free_gb (25), min_free_pct (10; the floor is the smaller of the two), max_age_hours (24), max_total_gb (60),
  reaper_delete_enabled (false), roots ([~/.agent-harness/work]), name_patterns (["tester-*", "test-copy-*",
  "click-test-*"]), protected_paths ([]).
Env: HARNESS_COPY_HYGIENE_MIN_FREE_GB overrides min_free_gb; HARNESS_COPY_HYGIENE_HOME relocates the state (tests);
HARNESS_COPY_HYGIENE_UNIT_DIRS (os.pathsep list) replaces the systemd/launchd directories scanned (tests).
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import fcntl
import fnmatch
import glob
import hashlib
import json
import os
import plistlib
import pwd
import re
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time

if os.path.dirname(os.path.abspath(__file__)) not in sys.path:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import shell_words  # noqa: E402  (goodqa#16811: the one shell reader shared with merge_gate)


GB = 1024 ** 3
DEFAULTS = {
    "min_free_gb": 25.0,
    "min_free_pct": 10.0,
    "max_age_hours": 24.0,
    "max_total_gb": 60.0,
    "reaper_delete_enabled": False,
    "roots": None,                     # None = [<home>/.agent-harness/work]
    "name_patterns": ["tester-*", "test-copy-*", "click-test-*"],
    "protected_paths": [],
}
GIT_TIMEOUT = 60
REPORT_EVERY_S = 6 * 3600
PREFIXES = frozenset(("sudo", "command", "time", "env", "nice", "nohup", "exec", "builtin", "ionice", "timeout"))
ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
SHM = "/dev/shm"
SHM_ENV = re.compile(r"\b(?:TMPDIR|TMP|TEMP|CLAUDE_CODE_TMPDIR|XDG_CACHE_HOME|XDG_RUNTIME_DIR)=[\"']?/dev/shm(?:/|\b|$)")
SHM_REDIRECT = re.compile(r"(?:^|[^<0-9])(?:&|\d)?>>?\|?\s*[\"']?/dev/shm(?:/|\s|$|[\"'])")


# ---------------------------------------------------------------- config and state
def home() -> str:
    return os.environ.get("HARNESS_COPY_HYGIENE_HOME") or os.path.expanduser("~")


def state_dir() -> str:
    return os.path.join(home(), ".agent-harness", "state")


def config_path() -> str:
    return os.path.join(state_dir(), "copy-hygiene.json")


def copies_root() -> str:
    return os.path.join(os.path.realpath(home()), ".agent-harness", "test-copies")


def _num(v, default: float) -> float:
    try:
        f = float(v)
        return f if f >= 0 else default
    except (TypeError, ValueError):
        return default


def normalize(cfg: dict) -> dict:
    out = dict(DEFAULTS)
    out.update({k: v for k, v in (cfg or {}).items() if k in DEFAULTS})
    for k in ("min_free_gb", "min_free_pct", "max_age_hours", "max_total_gb"):
        out[k] = _num(out[k], DEFAULTS[k])
    out["reaper_delete_enabled"] = out.get("reaper_delete_enabled") is True    # only a literal true enables deletion
    roots = out.get("roots")
    if isinstance(roots, str):
        roots = [roots]
    if not isinstance(roots, list) or not roots:
        roots = [os.path.join(home(), ".agent-harness", "work")]
    out["roots"] = [os.path.expanduser(str(r)) for r in roots]
    pats = out.get("name_patterns")
    if isinstance(pats, str):
        pats = [pats]
    pats = [str(p) for p in pats if str(p).strip("*")] if isinstance(pats, list) else []
    out["name_patterns"] = pats or list(DEFAULTS["name_patterns"])
    prot = out.get("protected_paths")
    if isinstance(prot, str):
        prot = [prot]
    out["protected_paths"] = [os.path.expanduser(str(x)) for x in prot if str(x).strip()] if isinstance(prot, list) else []
    return out


def load_config() -> dict:
    user = {}
    try:
        with open(config_path()) as f:
            d = json.load(f)
        if isinstance(d, dict):
            user = d
    except (OSError, ValueError):
        pass
    env = os.environ.get("HARNESS_COPY_HYGIENE_MIN_FREE_GB")
    if env:
        user = dict(user, min_free_gb=env)
    return normalize(user)


def _atomic_write(path: str, text: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix=".tmp-")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(text)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def alert(kind: str, detail: dict) -> None:
    """Append one row to the alert log; never raises."""
    try:
        os.makedirs(state_dir(), exist_ok=True)
        row = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "kind": kind}
        row.update(detail)
        with open(os.path.join(state_dir(), "copy-hygiene-alerts.jsonl"), "a") as f:
            f.write(json.dumps(row) + "\n")
    except OSError:
        pass


# ---------------------------------------------------------------- disk floor
def _existing(path: str) -> str:
    p = os.path.abspath(path)
    while p and not os.path.exists(p):
        p = os.path.dirname(p)
    return p or "/"


def free_bytes(path: str) -> int:
    st = os.statvfs(_existing(path))
    return st.f_bavail * st.f_frsize


def volume_bytes(path: str) -> int:
    st = os.statvfs(_existing(path))
    return st.f_blocks * st.f_frsize


def floor_gb(path: str, cfg: dict) -> float:
    try:
        pct = volume_bytes(path) * cfg["min_free_pct"] / 100 / GB
    except OSError:
        pct = cfg["min_free_gb"]
    return min(cfg["min_free_gb"], pct) if cfg["min_free_pct"] > 0 else cfg["min_free_gb"]


def disk_low(path: str, cfg: dict) -> "tuple[bool, float, float]":
    gb = free_bytes(path) / GB
    fl = floor_gb(path, cfg)
    return gb < fl, gb, fl


def low_disk_message(path: str, free_gb: float, fl: float) -> str:
    return (f"DISK LOW: {free_gb:.1f} GB free on the volume holding {path} (floor {fl:.1f} GB). The harness refuses to "
            "create another copy. Reuse your PR's test copy with `python3 ~/.claude/hooks/copy_hygiene.py acquire "
            "--repo <checkout> --key pr-<N>`, and run `python3 ~/.claude/hooks/copy_hygiene.py reap` to list idle "
            "copies (removing them needs the owner's OK). Only the owner changes the floor (min_free_gb / min_free_pct in "
            "~/.agent-harness/state/copy-hygiene.json); do not lower it to get around this.")


# ---------------------------------------------------------------- git helpers
def git(cwd: str, *args: str) -> "tuple[int, str]":
    try:
        # A caller inspecting another Git index must not redirect managed-copy operations.
        env = {k: v for k, v in os.environ.items() if k not in {
            "GIT_DIR", "GIT_COMMON_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY",
            "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_NAMESPACE", "GIT_CONFIG", "GIT_CONFIG_COUNT",
            "GIT_CONFIG_PARAMETERS", "GIT_PREFIX", "GIT_IMPLICIT_WORK_TREE", "GIT_QUARANTINE_PATH",
        }}
        env.update(GIT_OPTIONAL_LOCKS="0", GIT_TERMINAL_PROMPT="0", GIT_NO_REPLACE_OBJECTS="1", GIT_NO_LAZY_FETCH="1")
        p = subprocess.run(["git", "-C", cwd, *args], capture_output=True, text=True, timeout=GIT_TIMEOUT,
                           env=env)
        return p.returncode, (p.stdout + p.stderr).strip()
    except (OSError, subprocess.TimeoutExpired, UnicodeError) as e:
        return 99, str(e)


def safe_key(key: str) -> str:
    k = re.sub(r"[^A-Za-z0-9._-]+", "-", str(key)).strip("-.")
    if not k or set(k) <= {"."}:
        raise ValueError(f"unusable key: {key!r}")
    return k[:80]


def repo_identity(top: str, read_git=None) -> "tuple[str, str]":
    """(<repo name>-<8 hex>, common dir): one id for every worktree of a repository, distinct for same-named repos."""
    rc, common = (read_git or git)(top, "rev-parse", "--path-format=absolute", "--git-common-dir")
    common = os.path.realpath(common.splitlines()[-1].strip()) if rc == 0 and common else os.path.realpath(top)
    base = os.path.basename(os.path.dirname(common)) if os.path.basename(common) == ".git" else os.path.basename(common)
    base = re.sub(r"\.git$", "", base) or "repo"
    return f"{safe_key(base)}-{hashlib.sha256(common.encode()).hexdigest()[:8]}", common


def index_path() -> str:
    return os.path.join(state_dir(), "copy-hygiene-index.json")


def load_index() -> dict:
    try:
        with open(index_path()) as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def touch_index(path: str, **extra) -> None:
    """Best effort: a full disk or a race must not fail a reuse that already succeeded."""
    try:
        os.makedirs(state_dir(), exist_ok=True)
        with open(index_path() + ".lock", "w") as lk:
            fcntl.flock(lk, fcntl.LOCK_EX)
            idx = load_index()
            rec = idx.get(path, {})
            rec.update(extra, last_used=time.time())
            idx[path] = rec
            _atomic_write(index_path(), json.dumps(idx, indent=1))
    except OSError:
        pass


# ---------------------------------------------------------------- acquire
@contextmanager
def copy_lock(path: str, *, create: bool = True, wait: bool = False):
    """Hold the permanent sibling lease and expose its verified descriptor."""
    if os.path.realpath(os.path.dirname(path)) != os.path.dirname(path):
        raise ValueError("copy lock parent is redirected")
    lock_path = path + ".lock"
    flags = os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK | (os.O_CREAT if create else 0)
    descriptor = os.open(lock_path, flags, 0o600)
    try:
        opened = os.fstat(descriptor)
        if (not stat.S_ISREG(opened.st_mode) or opened.st_uid != os.geteuid()
                or opened.st_nlink != 1 or opened.st_mode & 0o022):
            raise ValueError("Unsafe reusable-copy lock")
        fcntl.flock(descriptor, fcntl.LOCK_EX | (0 if wait else fcntl.LOCK_NB))
        named = os.lstat(lock_path)
        if (named.st_dev, named.st_ino) != (opened.st_dev, opened.st_ino):
            raise ValueError("Reusable-copy lock changed")
        yield descriptor
    finally:
        os.close(descriptor)


COPY_GENERATION = re.compile(rb"[0-9a-f]{32}\n")


def copy_lock_record(descriptor):
    return os.pread(descriptor, 43, 0)


def copy_retirement_unconfirmed(descriptor):
    record = copy_lock_record(descriptor)
    return bool(record and not COPY_GENERATION.fullmatch(record))


def copy_generation(descriptor):
    value = copy_lock_record(descriptor)
    return value[:-1].decode("ascii") if COPY_GENERATION.fullmatch(value) else None


def write_copy_lock_record(descriptor, value):
    if os.pwrite(descriptor, value, 0) != len(value):
        raise OSError("Could not record reusable-copy state")
    os.ftruncate(descriptor, len(value))
    os.fsync(descriptor)


def set_copy_retirement(descriptor, generation, *, pending):
    active = generation.encode("ascii") + b"\n"
    if not COPY_GENERATION.fullmatch(active):
        raise ValueError("Invalid reusable-copy generation")
    retiring = b"retiring " + active
    expected, replacement = (active, retiring) if pending else (retiring, active)
    if copy_lock_record(descriptor) != expected:
        raise ValueError("Reusable-copy retirement state changed")
    write_copy_lock_record(descriptor, replacement)



def managed_head(path: str, key: str, common: str) -> "str | None":
    rec = load_index().get(path)
    if not isinstance(rec, dict) or not isinstance(rec.get("repo"), str) or rec.get("key") != key:
        return None
    rc, origin_common = git(rec["repo"], "rev-parse", "--path-format=absolute", "--git-common-dir")
    if rc or os.path.realpath(origin_common) != common:
        return None
    dotgit = os.path.join(path, ".git")
    if os.path.realpath(path) != path or os.path.islink(dotgit) or not os.path.isfile(dotgit):
        return None
    rc, top = git(path, "rev-parse", "--show-toplevel", "--path-format=absolute", "--git-common-dir")
    if rc or top.splitlines() != [path, common]:
        return None
    rc, head = git(path, "rev-parse", "--verify", "HEAD^{commit}")
    if rc or not re.fullmatch(r"[a-f0-9]{40}|[a-f0-9]{64}", head):
        return None
    rc, rows = git(common, "worktree", "list", "--porcelain", "-z")
    if rc or not any(set(row.split("\0")) == {f"worktree {path}", f"HEAD {head}", "detached"}
                     for row in rows.split("\0\0")):
        return None
    return head


def copy_changes(path: str, *, include_local=True) -> str:
    rc, files = git(path, "ls-files", "-v", "-z")
    if rc or any(not entry.startswith("H ") for entry in files.rstrip("\0").split("\0") if entry):
        return "unknown or nonstandard Git index"
    options = ("--ignored", "--untracked-files=all") if include_local else ("--untracked-files=no",)
    rc, status = git(path, "status", "--porcelain", "--ignore-submodules=none", *options)
    return "could not establish clean status" if rc else "tracked, untracked or ignored changes" if status else ""


def acquire(repo: str, key: str, ref: str = "HEAD", cfg: "dict | None" = None, *,
            require_reuse: bool = False, run=None) -> dict:
    cfg = normalize(cfg) if cfg is not None else load_config()
    try:
        k = safe_key(key)
    except ValueError as e:
        return {"ok": False, "error": str(e)}
    repo = os.path.abspath(repo)
    rc, top = git(repo, "rev-parse", "--show-toplevel")
    if rc != 0:
        return {"ok": False, "error": f"not a git checkout: {repo}"}
    top = top.splitlines()[-1].strip()
    # Resolve the ref in the SOURCE checkout: "HEAD" inside the copy would mean the copy's own commit.
    rc, sha = git(top, "rev-parse", "--verify", "--quiet", "--end-of-options", ref + "^{commit}")
    if rc != 0 or not sha:
        return {"ok": False, "error": f"unknown ref in {top}: {ref}"}
    sha = sha.splitlines()[-1].strip()
    rid, common = repo_identity(top)
    path = os.path.join(copies_root(), rid, k)
    stale = {"ok": False, "stale": True, "path": path, "wanted": sha}
    if require_reuse and not os.path.lexists(path):
        return dict(stale, error="no managed copy exists and --require-reuse forbids creating one")
    try:
        if os.path.realpath(os.path.dirname(path)) != os.path.dirname(path):
            return dict(stale, error="managed copy parent is redirected")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with copy_lock(path) as descriptor:
            if copy_retirement_unconfirmed(descriptor):
                return {"ok": False, "refused": "retirement-unconfirmed", "path": path,
                        "error": "Reusable-copy retirement is unconfirmed. Inspect the enrolled task's cleanup receipt."}
            # Renew the generation even at the same HEAD before another use can start.
            write_copy_lock_record(descriptor, os.urandom(16).hex().encode("ascii") + b"\n")
            reused = os.path.lexists(path)
            cur = None
            if reused:
                cur = managed_head(path, key, common)
                if cur is None:
                    return dict(stale, error="existing copy does not have verified managed Git registration")
                if cur != sha:
                    if changes := copy_changes(path):
                        return dict(stale, commit=cur, error=f"{changes}; checkout left at its previous commit")
                    rc, changed = git(path, "diff", "--name-only", "-z", "--no-renames", "--no-ext-diff",
                                      "--no-textconv", "--diff-filter=DMRT", cur, sha, "--")
                    if rc or any(protected_git_path(p) for p in changed.rstrip("\0").split("\0") if p):
                        return dict(stale, commit=cur, error="tracked protected logs or WAL evidence may change")
                    rc, local = git(path, "log", "--oneline", "-1", "HEAD", "--not", "--remotes", "--branches")
                    if rc or local:
                        return dict(stale, commit=cur, error="could not prove previous HEAD is saved on a branch")
                    rc, out = git(path, "checkout", "--no-overwrite-ignore", "--detach", "--quiet", sha)
                    if rc:
                        return dict(stale, commit=cur, error=out[-300:])
            else:
                if require_reuse:
                    return dict(stale, error="managed copy disappeared; --require-reuse forbids creating another")
                low, gb, fl = disk_low(path, cfg)
                if low:
                    alert("disk-low-refused-acquire", {"path": path, "free_gb": round(gb, 2), "floor_gb": round(fl, 2)})
                    return {"ok": False, "refused": "disk-low", "free_gb": round(gb, 2), "error": low_disk_message(path, gb, fl)}
                rc, out = git(common, "worktree", "add", "--detach", path, sha)
                if rc:
                    return {"ok": False, "error": out[-300:]}
            touch_index(path, repo=top, key=key)
            if managed_head(path, key, common) != sha:
                return dict(stale, error="could not confirm the managed checkout at the requested commit")
            if run and (changes := copy_changes(path, include_local=False)):
                return dict(stale, commit=sha, error=f"{changes}; leased command refused")
            result = {"ok": True, "path": path, "commit": sha, "reused": reused, "moved": cur != sha}
            if run:
                try:
                    result["exit_code"] = run(result)
                finally:
                    touch_index(path, repo=top, key=key)
            return result
    except BlockingIOError:
        return dict(stale, error="managed copy lease is currently held")
    except (OSError, ValueError):
        return dict(stale, error="could not acquire a verified managed copy lease")


# ---------------------------------------------------------------- protected paths (live services)
# Unit and job directories scanned. Duplicates through symlinks (merged /usr) are scanned once.
SYSTEM_UNIT_DIRS = ("/etc/systemd/system", "/etc/systemd/system.control", "/run/systemd/system",
                    "/run/systemd/system.control", "/run/systemd/transient", "/run/systemd/generator",
                    "/run/systemd/generator.early", "/run/systemd/generator.late", "/usr/local/lib/systemd/system",
                    "/lib/systemd/system", "/usr/lib/systemd/system")
USER_UNIT_DIRS_GLOBAL = ("/etc/systemd/user", "/usr/local/lib/systemd/user", "/usr/lib/systemd/user")
USER_UNIT_DIRS_HOME = (".config/systemd/user", ".config/systemd/user.control", ".local/share/systemd/user")
LAUNCHD_DIRS_GLOBAL = ("/Library/LaunchAgents", "/Library/LaunchDaemons")
UNIT_SUFFIXES = (".service", ".socket", ".mount", ".automount", ".path", ".timer", ".swap", ".conf")
# Keys whose values never name a path the unit depends on.
UNIT_SKIP_KEYS = frozenset(("Description", "Documentation", "After", "Before", "Wants", "Requires", "WantedBy",
                            "RequiredBy", "Alias", "Also", "Conflicts", "PartOf", "BindsTo", "Requisite"))
_PATH_TOKEN = re.compile(r"(%h|~|/)[^\s;&|'\"`()<>,:]*")
_SPEC = re.compile(r"%[A-Za-z%]")
PROTECTED_CACHE_TTL_S = 60


def _unit_dirs() -> "list[tuple[str, str]]":
    """(directory, 'user' | 'system')."""
    env = os.environ.get("HARNESS_COPY_HYGIENE_UNIT_DIRS")
    if env is not None:
        return [(d, "user") for d in env.split(os.pathsep) if d]
    h = home()
    out = [(d, "system") for d in SYSTEM_UNIT_DIRS + LAUNCHD_DIRS_GLOBAL]
    out += [(d, "user") for d in USER_UNIT_DIRS_GLOBAL]
    xdg = os.environ.get("XDG_CONFIG_HOME")
    if xdg:
        out.append((os.path.join(xdg, "systemd", "user"), "user"))
    out += [(os.path.join(h, d), "user") for d in USER_UNIT_DIRS_HOME]
    try:
        run = f"/run/user/{os.getuid()}/systemd"
        out += [(os.path.join(run, d), "user") for d in ("user", "transient", "generator", "user.control")]
    except AttributeError:
        pass
    out.append((os.path.join(h, "Library", "LaunchAgents"), "user"))
    return out


def _user_home(user: str) -> str:
    try:
        return pwd.getpwuid(int(user)).pw_dir if str(user).isdigit() else pwd.getpwnam(user).pw_dir
    except (KeyError, TypeError, ValueError):
        return ""


def _expand_one(tok: str, homes: "list[str]") -> "list[str]":
    if tok.startswith("~") and not (tok == "~" or tok.startswith("~/")):
        return []                                      # ~user forms: not resolved
    outs = []
    for h in homes or [""]:
        t = tok
        if t == "~" or t.startswith("~/"):
            if not h:
                continue
            t = h + t[1:]
        if "%h" in t:
            if not h:
                continue
            t = t.replace("%h", h)
        m = _SPEC.search(t)                           # unresolved specifier (%i, %t, ...): protect the prefix
        if m:
            t = t[:m.start()]
            t = t if t.endswith("/") else os.path.dirname(t)
        if t.startswith("/"):
            outs.append(os.path.normpath(t))
    return outs


def _paths_in(value: str, homes: "list[str]") -> "list[str]":
    """Every absolute path named in a value: plain words, Exec prefixes (-/@/+/!), K=/path, --opt=/path, -C/path,
    file:/path, PATH-like lists, and paths inside shell strings such as `bash -lc 'cd %h/x && ./run'`."""
    out = []
    value = re.sub(r"\$\{HOME\}|\$HOME(?![A-Za-z0-9_])", "%h", value)
    for m in _PATH_TOKEN.finditer(value):
        i = m.start()
        prev = value[i - 1] if i else " "
        if prev.isalnum() or prev in "._$}%~/":
            if not (i >= 2 and value[i - 2] == "-" and prev.isalpha()):      # allow -C/path, -I/path
                continue
        tok = m.group(0).rstrip(".")
        if tok in ("~", "%h") or len(tok) > 1 or tok == "/":
            out.extend(_expand_one(tok, homes))
    try:                                          # quoted words with spaces: WorkingDirectory="/a b", "/x y/run"
        for w in shlex.split(value):
            w = w.lstrip("-@+!:|")
            if " " in w and w.startswith(("/", "~/", "%h")):
                out.extend(_expand_one(w, homes))
    except ValueError:
        pass
    return out


def _unit_text(path: str) -> str:
    with open(path, errors="replace") as f:
        return re.sub(r"\\\n", " ", f.read(1 << 20))


def _unit_user(text: str) -> str:
    m = None
    for m in re.finditer(r"^\s*User\s*=\s*(\S*)", text, re.M):
        pass
    return m.group(1) if m else ""


def _parse_unit(text: str, homes: "list[str]") -> "list[str]":
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line[0] in "#;[" or "=" not in line:
            continue
        key, val = (x.strip() for x in line.split("=", 1))
        if key in UNIT_SKIP_KEYS:
            continue
        if key == "WorkingDirectory" and val.lstrip("-").strip('"') == "~":
            out.extend(h for h in homes if h)
            continue
        out.extend(_paths_in(val, homes))
    return out


def _parse_plist(path: str, homes: "list[str]") -> "list[str]":
    with open(path, "rb") as f:
        d = plistlib.load(f)
    if not isinstance(d, dict):
        return []
    vals = [str(d.get(k) or "") for k in ("WorkingDirectory", "Program", "StandardOutPath", "StandardErrorPath",
                                            "StandardInPath", "RootDirectory")]
    for k in ("ProgramArguments", "WatchPaths", "QueueDirectories"):
        vals += [str(x) for x in (d.get(k) or []) if isinstance(x, (str, int))]
    env = d.get("EnvironmentVariables")
    if isinstance(env, dict):
        vals += [str(v) for v in env.values()]
    out = []
    for v in vals:
        out.extend(_paths_in(v, homes))
    return out


def _scan_files(dirs) -> "tuple[list, int, list]":
    """([(file, scope)], errors, signature) with duplicate directories (symlinks) removed."""
    seen, files, errors, sig = set(), [], 0, []
    for d, scope in dirs:
        try:
            st = os.stat(d)
        except FileNotFoundError:
            continue
        except OSError:
            errors += 1
            continue
        if not os.path.isdir(d):
            continue
        rd = os.path.realpath(d)
        if rd in seen:
            continue
        seen.add(rd)
        sig.append((rd, st.st_mtime_ns))
        try:
            names = sorted(os.listdir(d))
        except OSError:
            errors += 1
            continue
        for n in names:
            f = os.path.join(d, n)
            if n.endswith(".d") and os.path.isdir(f):
                try:
                    sig.append((f, os.stat(f).st_mtime_ns))
                    files += [(os.path.join(f, c), scope) for c in sorted(os.listdir(f)) if c.endswith(".conf")]
                except OSError:
                    errors += 1
            elif n.endswith(UNIT_SUFFIXES) or n.endswith(".plist"):
                files.append((f, scope))
    return files, errors, sig


def _scan_units() -> "tuple[dict, int]":
    files, errors, _sig = _scan_files(_unit_dirs())
    users = {}                                      # unit name -> User= (drop-ins inherit the parent's)
    texts = {}
    for f, scope in files:
        if f.endswith(".plist") or scope != "system":
            continue
        try:
            texts[f] = _unit_text(f)
        except OSError:
            continue
        u = _unit_user(texts[f])
        if u and not (f.endswith(".conf") and not os.path.dirname(f).endswith(".d")):
            unit = os.path.basename(os.path.dirname(f))[:-2] if f.endswith(".conf") else os.path.basename(f)
            users[unit] = u
    out = {}
    def add(p, src):
        for q in {os.path.normpath(p), os.path.realpath(p)}:
            out.setdefault(_k(q), (q, src))
    for f, scope in files:
        try:
            if scope == "user":
                homes = [home()]
            else:
                unit = os.path.basename(os.path.dirname(f))[:-2] if f.endswith(".conf") else os.path.basename(f)
                homes = sorted({"/root", _user_home(users.get(unit, ""))} - {""})
            if f.endswith(".plist"):
                names = _parse_plist(f, homes if scope == "user" else homes + [home()])
            else:
                names = _parse_unit(texts[f] if f in texts else _unit_text(f), homes)
            if os.path.islink(f):                   # `systemctl link` from a checkout: keep the unit's source
                names.append(os.path.realpath(f))
        except Exception:      # noqa: BLE001 -- unreadable unit: counted, so callers can fail closed
            if os.path.exists(f):
                errors += 1
            continue
        for p in names:
            add(p, f)
    return out, errors


def _k(p: str) -> str:
    """Comparison key: APFS/HFS+ are case-insensitive by default."""
    return p.lower() if sys.platform == "darwin" else p


def protected_scan(cfg: "dict | None" = None, *, fresh: bool = False) -> "tuple[dict, int]":
    """Service dependencies and unreadable-unit count. Destructive callers can bypass the advisory cache."""
    cfg = normalize(cfg) if cfg is not None else load_config()
    if fresh:
        prot, errors = _scan_units()
    else:
        _f, _e, sig = _scan_files(_unit_dirs())
        cache = os.path.join(state_dir(), "copy-hygiene-protected.json")
        key = hashlib.sha256(
            json.dumps([sig, os.environ.get("HARNESS_COPY_HYGIENE_UNIT_DIRS"), home()]).encode()
        ).hexdigest()
        prot, errors = None, 0
        try:
            with open(cache) as f:
                c = json.load(f)
            if c.get("key") == key and time.time() - float(c.get("ts", 0)) < PROTECTED_CACHE_TTL_S:
                prot = {k: tuple(v) for k, v in c["prot"].items()}
                errors = int(c.get("errors", 0))
        except (OSError, ValueError, KeyError, TypeError, AttributeError):
            prot = None
        if prot is None:
            prot, errors = _scan_units()
            try:
                _atomic_write(cache, json.dumps({"key": key, "ts": time.time(), "prot": prot, "errors": errors}))
            except OSError:
                pass
    prot = dict(prot)
    for p in cfg.get("protected_paths") or []:
        p = os.path.normpath(os.path.expanduser(p))
        for q in {p, os.path.realpath(p)}:
            prot.setdefault(_k(q), (q, "config protected_paths"))
    return prot, errors


def protected_paths(cfg: "dict | None" = None) -> "dict[str, str]":
    """{path: where it is named} for every path a systemd unit or launchd job (or the config) names."""
    prot, _errors = protected_scan(cfg)
    return {v[0]: v[1] for v in prot.values()}


def protecting(path: str, prot: dict) -> "tuple[str, str] | None":
    """(protected path, source) when deleting `path` would delete a protected path: it is one or contains one.
    `prot` is protected_paths() output or protected_scan()[0]. The target's parent is resolved (symlinked parents
    are followed) but a symlink target itself is not: removing a link does not remove what it points to."""
    p = os.path.normpath(path)
    cands = {p, os.path.join(os.path.realpath(os.path.dirname(p)), os.path.basename(p)) if p != "/" else "/"}
    items = [(_k(k), v if isinstance(v, tuple) else (k, v)) for k, v in prot.items()]
    for c in cands:
        ck = _k(c)
        pre = ck.rstrip("/") + "/"
        for kk, (orig, src) in items:
            if kk == ck or kk.startswith(pre):
                return orig, src
    return None


def protecting_tail(rel: str, prot: dict) -> "tuple[str, str] | None":
    """For a relative target whose base directory is unknown (`cd $X && rm -rf runner`): match by path tail.
    Only protected paths under the home directory or from the config are tail-matched, so `rm -rf bin` after an
    unknown cd is not refused because some system unit names /usr/bin/..."""
    rel = os.path.normpath(rel)
    while rel.startswith("./"):
        rel = rel[2:]
    if not rel or rel in (".", "..") or rel.startswith("../"):
        return None
    tail = "/" + _k(rel)
    hks = {_k(home().rstrip("/")) + "/", _k(os.path.realpath(home()).rstrip("/")) + "/"}
    for k, v in prot.items():
        orig, src = v if isinstance(v, tuple) else (k, v)
        kk = _k(orig)
        if not (any(kk.startswith(h) for h in hks) or src == "config protected_paths"):
            continue
        if kk.endswith(tail) or (tail + "/") in kk:
            return orig, src
    return None


# ---------------------------------------------------------------- command analysis
SIMPLE_SPLIT = re.compile(r"\|\||&&|[;|&\n]|\$\(|`|\(|\)")


def simple_commands(cmd: str) -> list:
    """argv lists of the simple commands in a shell line (quote-aware enough for policy; never raises).

    It splits inside quotes on purpose: the protected-delete and /dev/shm checks rely on reading every command a
    quoted `bash -c '...'` or ssh payload might run. Only the disk-floor copy check reads lines through
    copy_commands instead (goodqa#16811)."""
    out = []
    for seg in SIMPLE_SPLIT.split(cmd):
        seg = seg.strip()
        if not seg:
            continue
        try:
            words = shlex.split(seg, comments=True)
        except ValueError:
            words = seg.split()
        while words and (ASSIGN.match(words[0]) or os.path.basename(words[0]) in PREFIXES):
            words = words[1:]
        if words:
            out.append(words)
    return out


# ---------------------------------------------------------------- copy check: ssh remote payloads
# The disk-floor copy check reads every command the base way (_legacy_copy_commands) except ONE shape it can prove
# from the text alone: an ssh that runs only on the far host (_plain_remote_ssh). Nothing is relaxed by listing bad
# shapes; a shape this section does not recognise keeps the base reading (goodqa#16811 round 2).

# ssh options that make the LOCAL machine run or load something; an ssh carrying one keeps the strict reading. `-F`
# names a config file that may hold one, and the hook reads no ssh config. PKCS11Provider and SecurityKeyProvider load a
# local library; they are matched here as well as in SSH_LOCAL_KEYWORDS, so a quoted keyword cannot slip past.
SSH_LOCAL_COMMAND = re.compile(r"proxycommand|localcommand|knownhostscommand|pkcs11provider|securitykeyprovider|^-F", re.I)
# The program words trusted to be the system ssh: `ssh` looked up on PATH (see LOOKUP_VARIABLES) or its usual
# absolute paths. `./ssh`, `bin/ssh` or `~/bin/ssh` may be any local script.
SSH_PROGRAMS = frozenset(("ssh", "/usr/bin/ssh", "/bin/ssh", "/usr/local/bin/ssh", "/opt/homebrew/bin/ssh"))
# ssh(1) option letters (OpenSSH 9.x and 10.x). Any other letter, and -F (a config file) or -I (a PKCS#11 library),
# is something this rule does not model: the base reading.
SSH_VALUE_LETTERS = frozenset("BbcDEeiJLlmOopPQRSWw")
SSH_FLAG_LETTERS = frozenset("246AaCfGgKkMNnqsTtVvXxYy")
# -o keywords that run or load something on this machine (an Include or Match may pull in any of them).
SSH_LOCAL_KEYWORDS = frozenset(("proxycommand", "localcommand", "permitlocalcommand", "knownhostscommand", "include",
                                "match", "pkcs11provider", "securitykeyprovider"))
# Commands that can change what a later program name on the line runs, or run text as code in this shell
# (`alias ssh=...`, `eval 'ssh(){ ...; }'`, `hash -p ./x ssh`, `. ./defs`, `export PATH=...`). With one on the line,
# `ssh` may not be ssh, so the ssh rule is off for the line.
REDEFINES = frozenset(("alias", "eval", "source", ".", "hash", "enable", "autoload", "functions", "zmodload", "emulate",
                       "trap", "typeset", "declare", "export", "local", "readonly", "integer", "float", "setopt",
                       "unsetopt", "shopt", "fc", "r", "disable", "unhash", "unfunction"))
# Variables that change where a program is found, what a child shell reads first, or what ssh loads or runs.
LOOKUP_VARIABLES = frozenset(("PATH", "path", "FPATH", "fpath", "BASH_ENV", "ENV", "ZDOTDIR", "HOME", "LD_PRELOAD",
                              "LD_LIBRARY_PATH", "DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH", "SSH_ASKPASS",
                              "SSH_ASKPASS_REQUIRE"))
_SET_FLAGS = re.compile(r"[-+][euxvo]+")
_SET_OPTIONS = frozenset(("pipefail", "errexit", "nounset", "xtrace", "verbose"))
# Unquoted characters that let the shell build a word (bash, and zsh with EXTENDED_GLOB): glob, brace, tilde, `^`
# and `#`. An unquoted `=` at the start of a word is zsh's command-path expansion.
_BUILT_WORD = frozenset("*?[]{}~^#")


def _spelled_out(word) -> bool:
    """True when the shell passes `word` exactly as written: no parameter expansion and no unquoted glob, brace,
    tilde, `^`, `#` or leading `=`."""
    if word.expansions:
        return False
    return not any(char in _BUILT_WORD or (char == "=" and at == word.start) for at, char in word.unquoted)


def _not_an_option(word) -> bool:
    """True when ssh's option parser stops at `word` whatever the shell makes of it: its first character is written
    as literal text and is not `-`, so an expansion or glob later in the word cannot change it. Judged on the value
    (Word.lead), not on offsets: `''"$X"` starts with an expansion. An empty word is not an option either."""
    if word.lead == "quoted":
        return not word.value.startswith("-")
    if word.lead == "unquoted":
        return word.value[:1] not in _BUILT_WORD and word.value[:1] not in "-="
    return word.lead == ""


def _command_words(segment):
    """(prefix, rest) as Word lists: the assignments and wrapper words _unwrap drops, then the program and its
    arguments. _unwrap only ever drops leading words, so the split is by count."""
    kept = len(_unwrap(list(segment.argv)))
    cut = len(segment.words) - kept
    return segment.words[:cut], segment.words[cut:]


def _ssh_option(value):
    """(ok, letter, inline value or None) for one ssh option word. ok is False for a letter this rule does not
    model, and for -F and -I."""
    for index in range(1, len(value)):
        letter = value[index]
        if letter in SSH_VALUE_LETTERS:
            return True, letter, value[index + 1:] or None
        if letter not in SSH_FLAG_LETTERS:
            return False, letter, None
    return True, "", None


def _ssh_value_ok(letter, value) -> bool:
    if letter != "o":
        return True
    # OpenSSH strips double quotes from a -o keyword (`-o '"PKCS11Provider" x.so'` sets PKCS11Provider; `ssh -G`
    # on 9.6 shows it), so they are dropped before the lookup. A keyword ssh would reject is refused here too.
    keyword = re.split(r"[=\s]", value.replace('"', "").strip(), maxsplit=1)[0].lower()
    return keyword not in SSH_LOCAL_KEYWORDS and "\n" not in value and "\r" not in value


def _ssh_runs_remotely(words) -> bool:
    """True when ssh(1) reads `words` (the Word objects after the program word) as options, a host and a remote
    command, with every option, option value and the host spelled out. OpenSSH parses options before the host and
    again after it, up to the first word that is not an option (OpenSSH 9.6 does; `ssh -G` shows it); that word
    starts the remote command, and nothing after it is parsed here. So the first word after the host must be
    _not_an_option, and the words after it are the far host's text."""
    host = False
    index = 0
    while index < len(words):
        word = words[index]
        if host and _not_an_option(word):
            return True
        if not _spelled_out(word):
            return False
        value = word.value
        if value.startswith("-") and value != "-":
            ok, letter, inline = _ssh_option(value)
            if not ok:
                return False
            if letter and inline is None:
                index += 1
                if index >= len(words) or not _spelled_out(words[index]):
                    return False
                inline = words[index].value
            if letter and not _ssh_value_ok(letter, inline):
                return False
            index += 1
            continue
        if host:
            return True  # a bare `-` after the host: not an option, the remote command starts here
        host = True
        index += 1
    return host


def _env_split_strings(words):
    """[(value, words after it)] for every `env -S VALUE` among a command's wrapper words: GNU env splits VALUE into
    more arguments, a program included. Short clusters (`-iS...`, `-S...`) and long abbreviations (`--s`,
    `--split-string=...`) count."""
    found, index = [], 0
    while index < len(words):
        if os.path.basename(words[index]) != "env":
            index += 1
            continue
        index += 1
        while index < len(words) and words[index].startswith("-") and words[index] != "-":
            word, value = words[index], None
            if word.startswith("--"):
                name, eq, inline = word.partition("=")
                if len(name) > 2 and "--split-string".startswith(name):
                    value = inline if eq else None
                    if not eq:
                        index += 1
                        value = words[index] if index < len(words) else ""
            elif "S" in word[1:]:
                value = word[word.index("S", 1) + 1:]
                if not value:
                    index += 1
                    value = words[index] if index < len(words) else ""
            elif word in ("-u", "-C") and index + 1 < len(words):
                index += 1
            index += 1
            if value is not None:
                found.append((value, words[index:]))
    return found


_ZSH_CODE_ARRAY = re.compile(r"(?:functions|aliases|galiases|saliases)\[[^\]]*\]=(.*)", re.S)


def _hidden_code(argv):
    """Shell code a command runs that its words carry as plain text, besides the `sh -c` script read separately:
    env's -S string with the words after it, eval's arguments, an alias value (also zsh's `aliases[x]=...` and
    `functions[x]=...`), a trap action. Each is read as a command line, so `eval 'git clone a b'` and
    `alias ssh='cp -a r c'` are charged like the copies they run."""
    out = [value + (" " + shlex.join(after) if after else "") for value, after in _env_split_strings(list(argv))]
    words = _unwrap(list(argv))
    if words:
        name, args = words[0], words[1:]
        array = _ZSH_CODE_ARRAY.fullmatch(name)
        if array:
            out.append(array[1])
        if name == "eval":
            out.append(" ".join(args))
        elif name == "alias":
            out.extend(arg.split("=", 1)[1] for arg in args if "=" in arg and not arg.startswith("-"))
        elif name == "trap":
            rest = [arg for arg in args if arg != "--"]
            if len(rest) >= 2 and not rest[0].startswith("-"):
                out.append(rest[0])
    return [code for code in out if code.strip()]


def _line_redefines(scan) -> bool:
    """True when a command on this verified line may change what a later `ssh` runs: a REDEFINES command, a `set`
    beyond -e/-u/-x/-v/-o pipefail, an assignment to a LOOKUP_VARIABLES name (`PATH=./bin ssh`, `PATH=x;`), an
    `env -S`, or a program or wrapper word the text does not spell out (`$CMD`, zsh `functions[ssh]=...`)."""
    for segment in scan.segments:
        prefix, rest = _command_words(segment)
        for word in prefix:
            assigned = ASSIGN.match(word.value)
            if assigned and assigned[0][:-1] in LOOKUP_VARIABLES:
                return True
            if not assigned and not _spelled_out(word):
                return True
        if not rest:
            continue
        if not _spelled_out(rest[0]) or _env_split_strings([word.value for word in prefix]):
            return True
        name = rest[0].value
        if name in REDEFINES:
            return True
        if name == "set" and not all(_SET_FLAGS.fullmatch(word.value) or word.value in _SET_OPTIONS
                                     for word in rest[1:]):
            return True
    return False


def _plain_remote_ssh(segment) -> bool:
    """True for the one shape the disk-floor check does not charge here (goodqa#16811): an ssh whose arguments run
    only on the far host, proven from the text alone.
    - The program word is spelled out and is `ssh` or the system ssh by an absolute path (SSH_PROGRAMS).
    - No assignment on the command (`PATH=./bin ssh`, `LD_PRELOAD=x ssh`, `env A=1 ssh`), no `env -S`, and every
      wrapper word before it is spelled out (`env "$X" ssh` could be `env -S ...`).
    - No ProxyCommand, LocalCommand or KnownHostsCommand anywhere, and no -F config (SSH_LOCAL_COMMAND).
    - Every option, option value and the host are spelled out, and the first word after the host is plainly not an
      option (_ssh_runs_remotely).
    The caller also requires a verified line on which nothing redefines a program (_line_redefines).

    Not proven: that the host is another machine. `ssh localhost '...'` or an ssh alias of this machine copies onto
    this disk and is not counted (documented gap; the hook does no DNS or ssh-config reading). Not counted either:
    a redirect of the remote output onto this disk, `ssh devbox 'tar c dir' > local.tar` (documented gap)."""
    prefix, rest = _command_words(segment)
    if not rest or not _spelled_out(rest[0]) or rest[0].value not in SSH_PROGRAMS:
        return False
    values = [word.value for word in prefix]
    if any(word.assignment or ASSIGN.match(word.value) or not _spelled_out(word) for word in prefix):
        return False
    if _env_split_strings(values) or any(SSH_LOCAL_COMMAND.search(word.value) for word in rest):
        return False
    return _ssh_runs_remotely(rest[1:])


def _legacy_copy_commands(cmd: str, depth: int) -> list:
    """The strict (base) reading: split on every separator even inside quotes (the simple_commands reading), drop
    wrappers, read `sh -c` scripts and _hidden_code the same way, strictly. Over-reads, never under-reads."""
    out = []
    for seg in SIMPLE_SPLIT.split(cmd):
        seg = seg.strip()
        if not seg:
            continue
        try:
            words = shlex.split(seg, comments=True)
        except ValueError:
            words = seg.split()
        if depth < 4:
            for code in _hidden_code(words):
                out.extend(copy_commands(code, depth + 1, strict=True))
        words = _unwrap(words)
        if not words:
            continue
        out.append(words)
        if depth < 4 and len(words) >= 3 and os.path.basename(words[0]) in SHELLS and words[1] == "-c":
            out.extend(copy_commands(words[2], depth + 1, strict=True))
    return out


def copy_commands(cmd: str, depth: int = 0, strict: bool = False) -> list:
    """argv lists the disk-floor copy check reads (goodqa#16811).

    Every command gets the base reading (_legacy_copy_commands: split at every separator, even inside quotes), plus
    the script of `sh|bash|zsh|dash|ksh -c SCRIPT` and the code _hidden_code finds, up to 4 levels deep. The one
    exception: on a line shell_words.scan verifies, a segment _plain_remote_ssh proves to be an ssh that runs only on
    the far host is dropped, so `ssh host 'cd x && git clone ...'` is not charged to this machine; every other
    command on the line, one after the ssh included, is still read.

    The exception is off (strict) for the whole line, and inside its `sh -c` scripts and hidden code, when the line
    cannot be verified (a comment, a backslash, `$(` or a backtick outside single quotes, ANSI-C quoting, a heredoc,
    unbalanced quotes, ...) or when something on it may change what `ssh` runs (_line_redefines). A `sh -c` script
    is read with the ssh rule (R1-D1: `bash -c 'ssh h "git clone a b"'` is remote) only when the script word holds
    no expansion; otherwise its text may gain code at run time and it is read strictly too."""
    scan = shell_words.scan(cmd)
    if not scan.verified:
        return _legacy_copy_commands(cmd, depth)
    strict = strict or _line_redefines(scan)
    out = []
    for segment in scan.segments:
        _, rest = _command_words(segment)
        if not rest:
            continue
        if depth < 4:
            for code in _hidden_code(segment.argv):
                out.extend(copy_commands(code, depth + 1, strict=True))
        if not strict and _plain_remote_ssh(segment):
            continue
        words = [word.value for word in rest]
        out.append(words)
        if (depth < 4 and len(rest) >= 3 and os.path.basename(words[0]) in SHELLS
                and re.fullmatch(r"-[A-Za-z]*c[A-Za-z]*", words[1])):
            script = rest[2]
            literal = _spelled_out(script)
            out.extend(copy_commands(script.value, depth + 1, strict=strict or not literal))
            if literal:
                # The script was read just above, with the ssh rule; the words around it (wrappers, the positional
                # arguments a script may run as "$@") keep the base reading.
                out.extend(_legacy_copy_commands(
                    cmd[segment.start:script.start] + "true" + cmd[script.end:segment.end], depth))
                continue
        out.extend(_legacy_copy_commands(cmd[segment.start:segment.end], depth))
    return out


def _opts(words: list) -> "tuple[set, list]":
    """(short-option letters + long options, positional args) after the command name."""
    flags, pos, end = set(), [], False
    for w in words[1:]:
        if end or not w.startswith("-") or w == "-":
            pos.append(w)
        elif w == "--":
            end = True
        elif w.startswith("--"):
            flags.add(w.split("=", 1)[0])
        else:
            flags.update(w[1:])
    return flags, pos


def is_copy_command(words: list) -> bool:
    name = os.path.basename(words[0])
    flags, pos = _opts(words)
    if name == "git":
        # skip `-C <dir>` / `-c k=v` values
        i, args = 1, []
        while i < len(words):
            if words[i] in ("-C", "-c", "--git-dir", "--work-tree"):
                i += 2; continue
            args.append(words[i]); i += 1
        args = [a for a in args if not a.startswith("-")]
        return bool(args) and (args[0] == "clone" or (args[0] == "worktree" and len(args) > 1 and args[1] == "add"))
    if name == "cp":
        return bool(flags & {"r", "R", "a", "--recursive", "--archive"})
    if name == "rsync":
        return bool(flags & {"r", "a", "--recursive", "--archive"}) and not any(":" in p.split("/")[0] for p in pos[-1:])
    return name == "ditto"


def _dest(words: list) -> "list[str]":
    """Paths a command WRITES to (best effort, per verb)."""
    name = os.path.basename(words[0])
    flags, pos = _opts(words)
    out = []
    for i, w in enumerate(words):
        if w in ("-t", "--target-directory", "-d", "-o", "--output") and i + 1 < len(words):
            if name in ("cp", "mv", "ln", "install") and w in ("-t", "--target-directory"):
                out.append(words[i + 1])
            if name == "unzip" and w == "-d":
                out.append(words[i + 1])
            if name in ("curl", "wget") and w in ("-o", "--output"):
                out.append(words[i + 1])
        if w.startswith("--target-directory="):
            out.append(w.split("=", 1)[1])
        if name == "dd" and w.startswith("of="):
            out.append(w[3:])
    if name in ("cp", "mv", "ln", "install", "rsync", "ditto", "scp") and len(pos) >= 2:
        out.append(pos[-1])
    if name in ("mkdir", "touch", "tee", "mkfifo", "truncate"):
        out.extend(pos)
    if name == "mktemp":
        for i, w in enumerate(words):
            if w in ("-p", "--tmpdir") and i + 1 < len(words):
                out.append(words[i + 1])
            elif w.startswith("--tmpdir="):
                out.append(w.split("=", 1)[1])
        out.extend(p for p in pos if p.startswith(SHM))
    if name == "tar" and (("x" in flags) or "--extract" in flags or (words[1:2] and not words[1].startswith("-") and "x" in words[1])):
        for i, w in enumerate(words):
            if w in ("-C", "--directory") and i + 1 < len(words):
                out.append(words[i + 1])
    if name == "git" and is_copy_command(words) and pos:
        out.append(pos[-1])
    return out


DELETE_VERBS = frozenset(("rm", "rmdir", "unlink", "shred", "trash", "trash-put", "srm"))
# Name filters narrow what find deletes; time/size filters alone do not when the root itself is a service directory.
FIND_NAME_SELECTORS = frozenset(("-name", "-iname", "-path", "-ipath", "-wholename", "-regex", "-iregex", "-lname",
                                 "-samefile", "-inum"))
FIND_SELECTORS = FIND_NAME_SELECTORS | frozenset(("-newer", "-mtime", "-mmin", "-atime", "-amin", "-ctime", "-cmin",
                                                  "-size", "-empty", "-user", "-perm", "-links"))
FIND_EXEC_DELETERS = frozenset(("rm", "rmdir", "shred", "unlink", "trash", "trash-put", "srm", "mv"))
SHELLS = frozenset(("bash", "sh", "zsh", "dash", "ksh"))
KEYWORDS = frozenset(("then", "do", "else", "elif", "if", "while", "until", "{", "!", "}"))
# $name, ${name}, ${name<op>...} (:? :- := % # / ...), ${arr[@]}, and specials ($$ $1 $@ ...).
_VAR = re.compile(r"\$(?:\{([^{}]*)\}|(\w+)|[@*#?$!0-9-])")
_EMPTYING = re.compile(r"^[*?.\[\]!^]*[*?][*?.\[\]!^]*$")       # *, .*, **, ?*, [!.]*, .[!.]*, ..?*
_PUSH, _POP = "\0push", "\0pop"
_DEFAULT = "\0default:"     # marks a ${X:-default} value so its own variables are expanded too


BRACE_CAP = 256     # alternatives one word may expand to before the delete check refuses it as unanalysable
_BRACE_GROUP = re.compile(r"\{([^{}]*,[^{}]*)\}")


class BraceOverflow(ValueError):
    """A word expands to more than BRACE_CAP alternatives. The delete check cannot list every target, so the hook
    refuses the command (goodqa#17182) instead of judging a truncated list that could miss a protected path."""


def _expand_braces(s: str, cap: int = BRACE_CAP) -> "list[str]":
    """Every brace alternative of s, innermost comma group first. Generation stops as soon as more than `cap`
    alternatives exist and raises BraceOverflow: the old recursion built all 2^k results of k groups before it
    truncated (17 real commands over the 5 s hook budget, and a timed-out PreToolUse hook lets the command run)."""
    done, todo = [], [s]
    while todo:
        w = todo.pop()
        m = _BRACE_GROUP.search(w)
        if not m:
            done.append(w)
            if len(done) > cap:
                raise BraceOverflow(s)
            continue
        alts = [w[:m.start()] + alt + w[m.end():] for alt in m.group(1).split(",")]
        todo.extend(reversed(alts))      # depth first, left to right: the old result order
        if len(done) + len(todo) > cap:  # every pending word yields at least one result, so the total is past cap
            raise BraceOverflow(s)
    return done


# Quoted or backslash-escaped `{` `,` `}` are masked while a segment is split into words, so that brace expansion,
# which no shell applies to quoted text, skips them; _cmd_lines unmasks every word before anything else reads it.
_MASK = {"{": "", ",": "", "}": ""}
_UNMASK = str.maketrans({v: k for k, v in _MASK.items()})
# The command names delete_targets_line takes targets or bindings from. Only their words are brace-expanded, so code
# in a heredoc body or a quoted ssh/node script is never expanded (goodqa#17182 replay: 48 commands refused by the cap).
_BRACE_NAMES = DELETE_VERBS | {"mv", "gio", "find", "xargs", "git", "cd", "pushd", "for"}


def _unmask(s: str) -> str:
    return s.translate(_UNMASK)


def _mask_quoted_braces(seg: str) -> str:
    """seg with the braces and commas inside quotes, or after a backslash outside single quotes, masked. An unclosed
    quote leaves seg as it is: expanding too much is the safe direction."""
    out, q, i, n = [], "", 0, len(seg)
    while i < n:
        c = seg[i]
        if c == "\\" and q != "'" and i + 1 < n:
            out.append(c + _MASK.get(seg[i + 1], seg[i + 1]))
            i += 2
            continue
        if q:
            if c == q:
                q = ""
            out.append(_MASK.get(c, c))
        else:
            if c in "'\"":
                q = c
            out.append(c)
        i += 1
    return seg if q else "".join(out)


def _expand_command_braces(words: list) -> list:
    """Brace-expand a simple command's words when its name is one delete_targets_line reads, including a name that is
    itself a brace word (`{rm,-rf,/p}`, `/bin/r{m,m}`); other commands' words, such as code after `f(` in a heredoc
    body, are left as they are. A name word past the cap raises BraceOverflow when it could spell one of those names
    (every alternative is built from the word's own characters, so one lacking a letter of each name cannot)."""
    try:
        names = _expand_braces(words[0]) if _BRACE_GROUP.search(words[0]) else [words[0]]
    except BraceOverflow:
        if any(set(n) <= set(words[0]) for n in _BRACE_NAMES):
            raise
        return words
    if not any(os.path.basename(n) in _BRACE_NAMES for n in names):
        return words
    return [x for w in words for x in _expand_braces(w)]


def _var_value(m, env: dict) -> "list[str] | None":
    """Values for one _VAR match, or None when unknown. ${D:?}, ${D%/} and the like use D's value (the suffix
    operators only trim); an unknown ${D:-x} / ${D:=x} / ${D-x} uses its default text."""
    body = m.group(1)
    if body is None:
        return env.get(m.group(2)) if m.group(2) else None
    nm = re.match(r"^\w+", body)
    if not nm:
        return None
    name, op = nm.group(0), body[nm.end():]
    vals = env.get(name)
    if vals and (op == "" or op.startswith(("?", ":?")) or op == "%/"):
        return vals                                 # value unchanged (or only a trailing slash trimmed)
    d = re.match(r"^:?[-=](.*)$", op)
    if d and not vals:
        return [_DEFAULT + d.group(1)]
    if d and vals:
        return vals
    if vals and op == "%/*":                        # ${D%/*}: D's parent
        return [x for v in vals for x in (v, os.path.dirname(v.rstrip("/")) or "/")]
    if vals and op.startswith("%") and "/" in op:    # ${D%%/*}, ${D%/*/*}: some ancestor of D
        out = []
        for v in vals:
            a = v.rstrip("/") or "/"
            while True:
                out.append(a)
                if a in ("/", ""):
                    break
                a = os.path.dirname(a)
        return out
    return None                                     # ${D%/*}, ${D:+x}, ${D/a/b}, ${D:0:3}, ${D#..}: unknown


def _expand_vars(s: str, cwd: "str | None", vars_: "dict | None" = None) -> "list[str]":
    """Expand to a fixpoint, so nested forms such as ${X:-${HOME}/pp-ci} resolve (inner first, then outer)."""
    outs = [s]
    for _ in range(6):
        nxt = list(dict.fromkeys(x for o in outs for x in _expand_vars_once(o, cwd, vars_)))[:256]
        if nxt == outs:
            break
        outs = nxt
    return outs


def _expand_vars_once(s: str, cwd: "str | None", vars_: "dict | None" = None) -> "list[str]":
    """Every expansion of the known variables in s (HOME, PWD, TMPDIR, USER, same-line assignments and for-lists);
    unknown ones are left in place for _resolve."""
    env = {"HOME": [os.path.expanduser("~")], "TMPDIR": [os.environ.get("TMPDIR", "/tmp")],
           "USER": [os.environ.get("USER", "")]}
    if cwd:
        env["PWD"] = [cwd]
    env.update(vars_ or {})                         # a same-line reassignment shadows HOME/TMPDIR/...
    outs = [("", s)]
    done = []
    for _ in range(64):
        if not outs:
            break
        nxt = []
        for head, rest in outs:
            m = _VAR.search(rest)
            if not m:
                done.append(head + rest)
                continue
            vals = _var_value(m, env)
            if vals is None:
                nxt.append((head + rest[:m.end()], rest[m.end():]))
            else:
                for v in vals:
                    if v.startswith(_DEFAULT):          # rescan a default value: ${X:-$HOME/pp-ci}
                        nxt.append((head + rest[:m.start()], v[len(_DEFAULT):] + rest[m.end():]))
                    else:
                        nxt.append((head + rest[:m.start()] + v, rest[m.end():]))
        outs = nxt[:256]
    done.extend(h + r for h, r in outs)
    return done[:256]


def _cmd_lines(cmd: str) -> "list[tuple[list, str]]":
    """[(argv, separator before it)] for each simple command, keeping `|` so `find ... | xargs rm` is seen.
    `( ... )` subshells, `$( ... )` / backtick / `<( ... )` / `>( ... )` bodies and `bash -c '<line>'` bodies are
    bracketed by _PUSH/_POP so a `cd` inside them does not leak out."""
    out = []
    sep = ";"
    cmd = _unmask(cmd)          # a mask character typed in the command is read as the brace it stands for
    for seg, nsep, bodies in _split_line(cmd):
        cur_sep, sep = sep, nsep
        seg = seg.strip()
        if seg:
            for body in bodies:
                out.append(([_PUSH], ";"))
                out.extend(_cmd_lines(body))
                out.append(([_POP], ";"))
            seg = _mask_quoted_braces(_strip_comment(seg))
            try:
                words = shlex.split(seg)                # not comments=True: it cuts `${f##*/}` mid-word
            except ValueError:
                words = [w.strip("'\"") for w in seg.split()]
            words = _unwrap(words)
            if words and os.path.basename(_unmask(words[0])) in SHELLS:
                j = next((i for i, w in enumerate(words[1:], 1) if re.match(r"^-[a-zA-Z]*c[a-zA-Z]*$", w)), 0)
                if j and j + 1 < len(words):
                    out.append(([_PUSH], cur_sep))
                    out.extend(_cmd_lines(_unmask(words[j + 1])))    # the inner shell expands its own braces
                    out.append(([_POP], ";"))
                    words = []
            if words:
                out.append(([_unmask(w) for w in _expand_command_braces(words)], cur_sep))
        if nsep == "(":
            out.append(([_PUSH], nsep))
        elif nsep == ")":
            out.append(([_POP], nsep))
    return out


def _strip_comment(seg: str) -> str:
    """Drop a shell comment: `#` outside quotes at the start of a word."""
    q = ""
    for i, c in enumerate(seg):
        if q:
            if c == q:
                q = ""
        elif c in "'\"":
            q = c
        elif c == "#" and (i == 0 or seg[i - 1].isspace()):
            return seg[:i]
    return seg


SUBST = "${__SUBST__}"        # placeholder for a command substitution: an unresolved variable to _resolve


def _split_line(cmd: str) -> "list[tuple[str, str, list]]":
    """[(segment, separator after it, substitution bodies)], splitting on ; & && || | newline ( ) outside quotes. `$( ... )`,
    backticks and process substitutions (`<( ... )`, `>( ... )`) stay inside their word as SUBST (so `rm -rf $(pwd)/x`,
    `D=$(mktemp -d)` and `done < <(find R)` keep their shape); their bodies are returned for separate analysis."""
    out, buf, q, i, bodies = [], [], "", 0, []
    while i < len(cmd):
        c = cmd[i]
        if q == "'":
            buf.append(c)
            if c == "'":
                q = ""
            i += 1; continue
        if c == "\\" and i + 1 < len(cmd):
            buf.append(cmd[i:i + 2]); i += 2; continue
        if cmd.startswith("$(", i):
            depth, j, qq = 1, i + 2, ""
            while j < len(cmd) and depth:
                ch = cmd[j]
                if qq:
                    if ch == "\\" and qq == '"':
                        j += 2; continue
                    if ch == qq:
                        qq = ""
                elif ch == "\\":
                    j += 2; continue
                elif ch in "'\"":
                    qq = ch
                elif ch == "(":
                    depth += 1
                elif ch == ")":
                    depth -= 1
                j += 1
            bodies.append(cmd[i + 2:j - 1] if depth == 0 else cmd[i + 2:])
            buf.append(SUBST); i = j; continue
        if c == "`":
            j = cmd.find("`", i + 1)
            j = len(cmd) if j < 0 else j
            bodies.append(cmd[i + 1:j])
            buf.append(SUBST); i = j + 1; continue
        if q == '"':
            buf.append(c)
            if c == '"':
                q = ""
            i += 1; continue
        if c in "'\"":
            q = c; buf.append(c); i += 1; continue
        if c in "<>" and i + 1 < len(cmd) and cmd[i + 1] == "(":
            depth, j, qq = 1, i + 2, ""
            while j < len(cmd) and depth:
                ch = cmd[j]
                if qq:
                    if ch == "\\" and qq == '"':
                        j += 2; continue
                    if ch == qq:
                        qq = ""
                elif ch == "\\":
                    j += 2; continue
                elif ch in "'\"":
                    qq = ch
                elif ch == "(":
                    depth += 1
                elif ch == ")":
                    depth -= 1
                j += 1
            bodies.append(cmd[i + 2:j - 1] if depth == 0 else cmd[i + 2:])
            buf.append(SUBST); i = j; continue
        two = cmd[i:i + 2]
        if two in ("&&", "||"):
            out.append(("".join(buf), two, bodies)); buf, bodies = [], []; i += 2; continue
        if c in ";|&\n()":
            out.append(("".join(buf), c, bodies)); buf, bodies = [], []; i += 1; continue
        buf.append(c); i += 1
    out.append(("".join(buf), ";", bodies))
    return out


def _unwrap(words: list) -> list:
    """Drop shell keywords (then, do, if, !, {), VAR=val prefixes, sudo/env/nohup/nice/timeout/time/command/exec
    and their options (sudo -u x, timeout 5, nice -n 5)."""
    takes_value = {"sudo": {"-u", "-g", "-C", "-D", "-h", "-p", "-r", "-t", "-U"}, "env": {"-u", "-C", "-S"},
                   "nice": {"-n"}, "ionice": {"-c", "-n", "-p"}, "timeout": {"-s", "-k", "--signal", "--kill-after"}}
    while words and (words[0] in KEYWORDS or (ASSIGN.match(words[0]) and not all(ASSIGN.match(w) for w in words))
                     or (not ASSIGN.match(words[0]) and os.path.basename(words[0]) in PREFIXES)):
        name = words[0] if ASSIGN.match(words[0]) else os.path.basename(words[0])
        words = words[1:]
        if name in KEYWORDS or ASSIGN.match(name):
            continue
        while words and words[0].startswith("-") and words[0] != "-":
            w = words.pop(0)
            if w in takes_value.get(name, ()) and words:
                words.pop(0)
        if name == "timeout" and words and re.match(r"^\d+(\.\d+)?[smhd]?$", words[0]):
            words = words[1:]
    return words


def _resolve(raw: str, bases: list, vars_: "dict | None" = None,
             recursive: bool = True) -> "list[tuple[str, bool, str]]":
    """[(path, known, kind)] for a raw argument. `bases` are the possible current directories (None = unknown).
    known=False: a relative path under an unknown directory (matched by tail). kind "pattern": the path holds `*`
    where an unresolved variable or command substitution stood; it is refused only when a protected path or one
    of its ancestors matches the pattern (`~/pp-ci/$d` matches ~/pp-ci/runner; `out_$n.log` matches nothing).
    A wildcard that empties a directory (`dir/*`, `dir/.*`, `dir/**`) also yields the directory itself, resolved
    through symlinks, as does a trailing slash (`rm -rf link/`). Empty words are never targets."""
    out = []
    for b in bases or [None]:
        for r in (x for e in _expand_vars(raw, b, vars_) for x in _expand_braces(e)):
            if not r:
                continue
            r = os.path.expanduser(r)
            kind = ""
            if "$" in r and _VAR.search(r):
                m = _VAR.match(r)
                if m:                                       # starts with an unknown variable: unknown base
                    rest = _VAR.sub("", r[m.end():])        # later unknown variables taken as empty
                    if rest.startswith("/"):
                        out.extend((p, k, "") for p, k in _resolve_unknown(rest.lstrip("/")))
                    continue
                z = _VAR.sub("\0", r)                      # slash-free sentinel per unknown variable
                comps = z.split("/")
                # Unset variables are empty in a fresh shell: check the target with every one of them empty. For
                # a recursive delete an emptied component turns into `dir/` or `dir/*`, i.e. the directory itself.
                # A non-recursive delete can't remove the directory a trailing empty variable leaves, but an
                # empty middle component (`runner/$d/gate.sh`) still names a real file.
                last = comps[-1].replace("\0", "") if comps else ""
                if recursive or last:
                    empty = z.replace("\0", "")
                    if "$" not in empty and empty.strip("/") and empty != r:
                        out.extend(_resolve(empty, [b], None, recursive))
                # Trailing components made only of variables and wildcards widen to their directory.
                while recursive and comps and (comps[-1].replace("\0", "") == ""
                                               or _EMPTYING.match(comps[-1].replace("\0", "*"))):
                    comps.pop()
                r = "/".join(comps).replace("\0", "*") or "/"
                kind = "pattern"
            if not r.startswith("/"):
                if b is None:
                    if kind != "pattern":
                        out.extend((p, k, "") for p, k in _resolve_unknown(r))
                    continue
                r = os.path.join(b, r)
            if kind == "pattern":
                out.append((os.path.normpath(r), True, "pattern"))
                continue
            base = os.path.basename(r.rstrip("/"))
            if _EMPTYING.match(base) or (r.endswith("/") and len(r) > 1):
                parent = r.rstrip("/") if not _EMPTYING.match(base) else os.path.dirname(r.rstrip("/"))
                for par in (glob.glob(parent) if any(ch in parent for ch in "*?[") else [parent]):
                    out.append((os.path.normpath(par), True, ""))
                    out.append((os.path.realpath(par), True, ""))
            hits = glob.glob(r) if any(ch in r for ch in "*?[") else [r]
            out.extend((os.path.normpath(h), True, "") for h in hits)
    return out


def _resolve_unknown(rel: str) -> "list[tuple[str, bool]]":
    rel = rel.rstrip("/")
    while rel and _EMPTYING.match(os.path.basename(rel)):
        rel = os.path.dirname(rel)
    return [(rel, False)] if rel and not any(ch in rel for ch in "*?[") else []


def _find_roots(words: list) -> list:
    i, roots = 1, []
    while i < len(words) and (words[i] in ("-H", "-L", "-P", "-D") or re.match(r"^-O\d?$", words[i])):
        i += 2 if words[i] == "-D" else 1
    while i < len(words) and not words[i].startswith("-") and words[i] not in ("(", "!", ")"):
        roots.append(words[i]); i += 1
    return roots or ["."]


FIND_ACTIONS_PRINT = frozenset(("-print", "-print0", "-printf", "-fprint", "-fprint0", "-ls", "-fls"))
FIND_EXEC = frozenset(("-exec", "-execdir", "-ok", "-okdir"))
# Tests and options that take one argument (so the argument is never read as an operator).
FIND_ONE_ARG = (FIND_SELECTORS - {"-empty"}) | frozenset(("-type", "-xtype", "-maxdepth", "-mindepth", "-group", "-uid", "-gid",
                                           "-fstype", "-printf", "-fprint", "-fprint0", "-fls", "-used", "-anewer",
                                           "-cnewer", "-context", "-files0-from"))


def _exec_deletes(args: list) -> bool:
    rest = _unwrap(list(args))
    if not rest:
        return False
    if os.path.basename(rest[0]) in FIND_EXEC_DELETERS:
        return True
    if os.path.basename(rest[0]) in SHELLS:
        j = next((k for k, x in enumerate(rest[1:], 1) if re.match(r"^-[a-zA-Z]*c[a-zA-Z]*$", x)), 0)
        body = rest[j + 1] if j and j + 1 < len(rest) else ""
        return any(t and os.path.basename(t[0]) in FIND_EXEC_DELETERS for t, _s in _cmd_lines(body))
    return False


def _find_parse(words: list) -> "dict":
    """Parse a find expression (the words after the roots) by find's grammar: OR of AND-chains, ! / -not, groups,
    and -exec ... ; / + arguments skipped as a unit. For every action the selectors ANDed before it on its own path
    decide whether it is narrowed. Returns {"deletes": bool, "delete_mode": m, "print_mode": m}, where m is
    "below" (every such action is narrowed by a positive name test), "root-selective" (narrowed only by time/size
    tests) or "" (some action runs on everything)."""
    i = 1
    while i < len(words) and (words[i] in ("-H", "-L", "-P", "-D") or re.match(r"^-O\d?$", words[i])):
        i += 2 if words[i] == "-D" else 1
    while i < len(words) and not words[i].startswith("-") and words[i] not in ("(", "!", ")"):
        i += 1
    toks = words[i:]
    pos = [0]
    acts = []                                   # (kind, name_narrowed, sel_narrowed)

    def peek():
        return toks[pos[0]] if pos[0] < len(toks) else None

    def or_expr(ctx):
        n, s_ = and_expr(ctx)
        allnarrow = [(n, s_)]
        while peek() in ("-o", "-or", ","):
            pos[0] += 1
            allnarrow.append(and_expr(ctx))
        return all(a for a, _b in allnarrow), all(b for _a, b in allnarrow)

    def and_expr(ctx):
        name_n, sel_n = ctx
        while peek() is not None and peek() not in ("-o", "-or", ",", ")"):
            if peek() in ("-a", "-and"):
                pos[0] += 1
                continue
            n, s_ = unary((name_n, sel_n))
            name_n, sel_n = name_n or n, sel_n or s_
        return name_n, sel_n

    def unary(ctx):
        t = peek()
        if t in ("!", "-not"):
            pos[0] += 1
            unary(ctx)                          # actions inside still count; a negated test narrows nothing
            return False, False
        if t == "(":
            pos[0] += 1
            r = or_expr(ctx)
            if peek() == ")":
                pos[0] += 1
            return r
        pos[0] += 1
        if t in FIND_EXEC:
            j = pos[0]
            while j < len(toks) and toks[j] not in (";", "+"):
                j += 1
            args = toks[pos[0]:j]
            pos[0] = j + 1
            acts.append(("delete" if _exec_deletes(args) else "other", ctx[0], ctx[1]))
            return False, False
        if t == "-delete":
            acts.append(("delete", ctx[0], ctx[1]))
            return False, False
        if t in FIND_ACTIONS_PRINT:
            if t in FIND_ONE_ARG:
                pos[0] += 1
            acts.append(("print", ctx[0], ctx[1]))
            return False, False
        if t in FIND_ONE_ARG:
            arg = peek()
            pos[0] += 1
            if t in FIND_NAME_SELECTORS:
                return (not (arg is not None and _EMPTYING.match(arg))), True
            return False, t in FIND_SELECTORS
        if t == "-empty":
            return False, True
        return False, False                     # -prune, -true, -xdev, -depth, ...

    try:
        whole = (False, False)
        while pos[0] < len(toks):
            whole = or_expr((False, False))
            if peek() == ")":                   # unbalanced: skip and keep parsing
                pos[0] += 1
    except Exception:                           # noqa: BLE001 -- unparseable: assume it deletes everything
        return {"deletes": True, "delete_mode": "", "print_mode": ""}
    if not any(k in ("print", "delete", "other") for k, _n, _s in acts):
        acts.append(("print", whole[0], whole[1]))          # implicit -print of the whole expression

    def mode(kind):
        sel = [(n, s_) for k, n, s_ in acts if k == kind]
        if not sel:
            return None
        if all(n for n, _s in sel):
            return "below"
        if all(n or s_ for n, s_ in sel):
            return "root-selective"
        return ""
    return {"deletes": any(k == "delete" for k, _n, _s in acts), "delete_mode": mode("delete") or "",
            "print_mode": mode("print") if mode("print") is not None else ""}


def _read_var(words: list):
    """The destination of `read [opts] var` / `read -r d < ...`, skipping flags and redirections."""
    rpos = [w for w in words[1:] if not w.startswith("-") and w not in ("<", ">", ">>", "<>", "<&", ">&")
            and "__SUBST__" not in w]
    return rpos[-1] if rpos else None


def _inherit_finds(words: list, subst_finds: list, var_finds: dict) -> list:
    """Find contexts reaching a word list via `$(find)` / `<(find)` or `$var` that already holds one."""
    feeds = list(subst_finds) if any("__SUBST__" in w for w in words) else []
    for w in words:
        for m in _VAR.finditer(w):
            vn = m.group(2) or re.match(r"^\w*", m.group(1) or "").group(0)
            feeds.extend(var_finds.get(vn, []))
    return feeds


def delete_targets_line(cmd: str, cwd: str) -> "list[tuple[str, bool, str]]":
    """[(path, known, mode)] a command line would delete or move away.
    Tracks `cd` / `pushd` (an unresolvable one, `cd -` or `popd` makes the directory unknown; after a cd that is not
    joined by `&&` both the old and new directory are checked, since the cd may have failed), `( )` and `bash -c`
    scopes, same-line `NAME=value` and `for x in ...` lists, and `find ... | ... | xargs rm` through a pipeline.
    Find output stored in a variable (`old=$(find R); rm -rf $old` / `for d in $old`) or fed to a `read` loop
    (`find R | while read d` / `while read d; do ...; done < <(find R)`) is treated as the delete target list.
    Two passes so a process substitution after `done` still binds the preceding `read`.
    mode "below": a find with name filters deletes only some entries, so it is refused only when a protected path
    lies strictly inside its root; "" means the path itself (and everything inside it) goes."""
    var_finds, out = {}, []
    parsed = _cmd_lines(cmd)
    for bind_only in (True, False):
        bases = [cwd if str(cwd).startswith("/") else None]
        stack, pending_old, vars_ = [], [], {}
        find_ctx, subst_finds, last_read = None, [], None
        if not bind_only:
            out = []
        for words, sep in parsed:
            if words == [_PUSH]:
                stack.append((list(bases), list(pending_old), dict(vars_), find_ctx))
                find_ctx = None
                continue
            if words == [_POP]:
                inner = find_ctx
                if stack:
                    bases, pending_old, vars_, find_ctx = stack.pop()
                if inner is not None:
                    subst_finds.append(inner)            # every substituted find feeding the next outer command
                continue
            if sep != "&&" and pending_old:
                bases = list(dict.fromkeys(bases + pending_old))
                pending_old = []
            if sep != "|":
                find_ctx = None
            name = os.path.basename(words[0])             # _cmd_lines already brace-expanded what this reads
            # find output bound to a loop variable: `for d in $(find R); do rm -rf "$d"` / `for d in $old`
            if name == "for" and len(words) >= 3 and words[2] == "in":
                inherited = _inherit_finds(words[3:], subst_finds, var_finds)
                if inherited:
                    var_finds[words[1]] = inherited
            if name == "read":
                rv = _read_var(words)
                if rv:
                    if sep == "|" and find_ctx is not None:
                        var_finds[rv] = [find_ctx]
                    elif subst_finds:
                        var_finds[rv] = list(subst_finds)
                    last_read = rv
            # `while read d; do rm ...; done < <(find R)`: the substitution sits on `done`, after the loop body
            if last_read and subst_finds and any("__SUBST__" in w for w in words) and (
                    name == "done" or name.startswith("done<") or any(w == "<" or w.startswith("<") for w in words)):
                var_finds[last_read] = list(subst_finds)
            if not bind_only and name in DELETE_VERBS:
                feeds = _inherit_finds(words, subst_finds, var_finds)
                for roots_, fp_, fb_ in feeds:           # the find's output is the target list
                    for r in roots_:
                        for p, k, kind in _resolve(r, fb_, vars_):
                            out.append((p, k, kind or fp_["print_mode"]))
            if name in ("export", "local", "declare", "readonly", "typeset") and len(words) > 1:
                words = [w for w in words[1:] if not w.startswith("-")] or words
            if words and all(ASSIGN.match(w) for w in words):
                for w in words:
                    k, v = w.split("=", 1)
                    vals = [x for b in bases for x in _expand_vars(v, b, vars_)]
                    vars_[k] = [os.path.expanduser(x) for x in vals]
                    if subst_finds and "__SUBST__" in v:
                        var_finds[k] = list(subst_finds)
                if not stack:
                    subst_finds = []
                continue
            if name == "for" and len(words) >= 3 and words[2] == "in":
                vars_[words[1]] = [os.path.expanduser(x) for w in words[3:] for x in _expand_vars(w, bases[0], vars_)]
                if not stack:
                    subst_finds = []
                continue
            if not stack and name not in ("find",):
                subst_finds = []
            flags, pos = _opts(words)
            if name in ("cd", "pushd", "popd"):
                t = pos[0] if pos else ("~" if name == "cd" else None)
                res = _resolve(t, bases, vars_) if t and t != "-" and name != "popd" else []
                new = [p for p, k, kind in res if k and not kind and os.path.isabs(p)]
                pending_old = list(dict.fromkeys(pending_old + bases))      # every directory the line may still be in
                bases = new[:1] if len(new) == 1 or (new and len(set(new)) == 1) else [None]
                continue
            raw, gbases, mode, recursive = [], bases, "", True
            if name in DELETE_VERBS:
                raw = pos
                # Recursive unless every option is a literal flag without r/R: `rm $OPTS x` and `rm -${R}f x` may be.
                recursive = (name in ("trash", "trash-put") or bool(flags & {"r", "R", "--recursive"})
                             or any(_VAR.fullmatch(w) or (w.startswith("-") and "$" in w) for w in words[1:]))
            elif name == "gio" and pos[:1] in (["remove"], ["trash"]):
                raw = pos[1:]
            elif name == "mv":
                tdir = any(w in ("-t", "--target-directory") or w.startswith("--target-directory=") for w in words)
                raw = list(pos) if tdir else pos[:-1]
                if tdir:
                    for i, w in enumerate(words):
                        if w in ("-t", "--target-directory") and i + 1 < len(words) and words[i + 1] in raw:
                            raw.remove(words[i + 1])
            elif name == "find":
                roots = _find_roots(words)
                fp = _find_parse(words)
                find_ctx = (roots, fp, list(bases))
                if not fp["deletes"]:
                    continue
            elif name == "xargs" and find_ctx is not None:
                if not any(os.path.basename(w) in FIND_EXEC_DELETERS for w in words[1:]):
                    continue
            elif name == "git":
                i, args, gb = 1, [], bases
                while i < len(words):
                    if words[i] == "-C" and i + 1 < len(words):
                        r = [p for p, k, kind in _resolve(words[i + 1], gb, vars_) if k and not kind]
                        gb = r[:1] if r else [None]
                        i += 2; continue
                    if words[i] in ("-c", "--git-dir", "--work-tree") and i + 1 < len(words):
                        i += 2; continue
                    if not words[i].startswith("-"):
                        args.append(words[i])
                    i += 1
                if len(args) >= 3 and args[0] == "worktree" and args[1] == "remove":
                    raw, gbases = [args[-1]], gb
            if name in ("find", "xargs") and find_ctx is not None:
                roots, fp, fb = find_ctx
                fmode = fp["delete_mode"] if name == "find" else fp["print_mode"]
                for r in roots:
                    for p, k, kind in _resolve(r, fb, vars_):
                        out.append((p, k, kind or fmode))
                        if k and not kind:
                            out.append((os.path.realpath(p), k, fmode))
                find_ctx = None if name == "xargs" else find_ctx
                continue
            out.extend((p, k, kind or mode) for r in raw for p, k, kind in _resolve(r, gbases, vars_, recursive))
    return out


def delete_targets(words: list, cwd: str) -> "list[str]":
    """Known absolute targets of one argv (kept for callers; the hook uses delete_targets_line)."""
    return [p for p, known, _m in delete_targets_line(shlex.join(words), cwd) if known]


def protected_delete(cmd: str, cwd: str, cfg: "dict | None" = None) -> "tuple[str, str, str] | None":
    """(target, protected path, source) for the first deletion that would remove a protected path."""
    targets = delete_targets_line(cmd, cwd)
    if not targets:
        return None
    prot, errors = protected_scan(cfg)
    if errors:
        alert("protected-units-unreadable", {"errors": errors})
    for t, known, mode in targets:
        if known and mode == "pattern":
            hit = None
            for key, v in prot.items():
                o, src = v if isinstance(v, tuple) else (key, v)
                anc = o
                while anc and anc != "/":
                    if fnmatch.fnmatchcase(_k(anc), _k(t)):
                        hit = (o, src)
                        break
                    anc = os.path.dirname(anc)
                if hit:
                    break
        elif known and mode in ("below", "root-selective"):
            pre = _k(os.path.normpath(t)).rstrip("/") + "/"
            hit = next(((o, src) for kk, (o, src) in ((_k(v[0]), v) for v in prot.values()) if kk.startswith(pre)),
                       None)
            if not hit and mode == "root-selective":     # time/size filters only: emptying the service dir itself
                exact = _k(os.path.normpath(t))
                hit = next(((o, src) for kk, (o, src) in ((_k(v[0]), v) for v in prot.values()) if kk == exact),
                           None)
        else:
            hit = protecting(t, prot) if known else protecting_tail(t, prot)
        if hit:
            return t, hit[0], hit[1]
    return None


def writes_into_shm(cmd: str, cwd: str = "") -> bool:
    if SHM_ENV.search(cmd) or SHM_REDIRECT.search(cmd):
        return True
    in_shm_cwd = str(cwd).startswith(SHM + "/") or str(cwd) == SHM
    for words in simple_commands(cmd):
        for d in _dest(words):
            if d == SHM or d.startswith(SHM + "/"):
                return True
            if in_shm_cwd and not d.startswith("/") and not d.startswith("~"):
                return True
    return False


# ---------------------------------------------------------------- PreToolUse hook
def pretool(event: dict, cfg: "dict | None" = None) -> "tuple[int, str]":
    """(exit code, stderr). 2 denies; 0 allows. Fails open."""
    try:
        if event.get("tool_name") != "Bash":
            return 0, ""
        cmd = str((event.get("tool_input") or {}).get("command") or "")
        if len(cmd) > 256 * 1024:
            return 0, ""
        cwd = str(event.get("cwd") or "")
        if re.search(r"\b(rm|rmdir|unlink|shred|trash|trash-put|gio|srm|find|worktree|mv|xargs)\b", cmd):
            if os.environ.get("HARNESS_COPY_HYGIENE_UNIT_DIRS") is not None:
                alert("test-override-active", {"var": "HARNESS_COPY_HYGIENE_UNIT_DIRS"})
            try:
                hit = protected_delete(cmd, cwd, cfg)
            except BraceOverflow:   # fail CLOSED: a partial target list could miss a protected path (goodqa#17182)
                alert("protected-check-unanalysable", {"reason": "brace-overflow", "cap": BRACE_CAP})
                return 2, (f"UNANALYSABLE DELETE: a word in this command expands to more than {BRACE_CAP} brace "
                           "alternatives, too many to check every target against the protected service paths. Split "
                           "the command into smaller ones (fewer `{a,b}` groups per word), or list the paths "
                           "explicitly.\n")
            except Exception as e:  # noqa: BLE001 -- documented choice: fail OPEN (a broken check must not block
                hit = None          # every rm in every session) but leave an alert for the owner
                alert("protected-check-error", {"error": f"{type(e).__name__}: {str(e)[:160]}"})
            if hit:
                alert("protected-delete-denied", {"target": hit[0][:200], "protected": hit[1][:200],
                                                  "source": hit[2][:200]})
                return 2, (f"PROTECTED PATH: deleting or moving {hit[0]} would remove {hit[1]}, which a service "
                           f"depends on (named in {hit[2]}). On 2026-11-21 cleanups deleted claude-rc's working folder "
                           "and the pp gate's runner and caches this way. Leave it. Deleting single files or build "
                           "output inside it is fine; emptying it is not. If the service is truly retired, the owner "
                           "removes its unit file first. `python3 ~/.claude/hooks/copy_hygiene.py protected --check "
                           "<path>` explains any path.\n")
        if SHM in cmd or cwd.startswith(SHM):
            if writes_into_shm(cmd, cwd):
                alert("shm-write-denied", {"cwd": cwd[:200]})
                return 2, ("SCRATCH IN RAM REFUSED: /dev/shm is memory, not disk (2026-11-21: sessions filled 50 of "
                           "t2-dev's 56 GB). Use disk-backed scratch instead: `export TMPDIR=$(python3 "
                           "~/.claude/hooks/copy_hygiene.py scratch --key " + safe_key(str(event.get("session_id") or "session")) +
                           ")` (private, under ~/.agent-harness/scratch/). Reading, copying out of and removing files in /dev/shm stay allowed.\n")
        copying = [w for w in copy_commands(cmd) if is_copy_command(w)]
        if not copying:
            return 0, ""
        cfg = normalize(cfg) if cfg is not None else load_config()
        target = home()
        for w in copying:
            d = _dest(w)
            if d and d[-1].startswith("/"):
                target = d[-1]
            elif d and d[-1].startswith("~"):
                target = os.path.expanduser(d[-1])
            elif cwd.startswith("/"):
                target = cwd
        low, gb, fl = disk_low(target, cfg)
        if not low:
            return 0, ""
        alert("disk-low-denied-copy", {"target": target[:200], "free_gb": round(gb, 2), "floor_gb": round(fl, 2),
                                       "command": os.path.basename(copying[0][0])})
        return 2, low_disk_message(target, gb, fl) + "\n"
    except Exception:          # noqa: BLE001 -- fail open
        return 0, ""


# ---------------------------------------------------------------- reap
def dir_size(path: str) -> "int | None":
    try:
        p = subprocess.run(["du", "-sk", path], capture_output=True, text=True, timeout=600)
        return int(p.stdout.split()[0]) * 1024
    except (OSError, ValueError, IndexError, subprocess.TimeoutExpired):
        return None


def last_activity(path: str, idx: dict) -> float:
    """Newest of index use, mtime and ctime of the copy and its top entries. ctime cannot be carried over by cp -a,
    rsync -a or tar -x, so a copy made minutes ago never looks old."""
    t = float((idx.get(path) or {}).get("last_used") or 0)
    def see(p):
        nonlocal t
        try:
            st = os.lstat(p)
            t = max(t, st.st_mtime, st.st_ctime)
        except OSError:
            pass
    for rel in ("", ".git", ".git/HEAD", ".git/index"):
        see(os.path.join(path, rel))
    try:
        with os.scandir(path) as it:
            for e in it:
                see(e.path)
    except OSError:
        pass
    return t


def candidates(cfg: dict) -> list:
    pats = cfg["name_patterns"]
    seen, out = set(), []
    def add(p):
        rp = os.path.realpath(p)
        if rp not in seen and os.path.isdir(p) and not os.path.islink(p):
            seen.add(rp); out.append(p)
    cr = copies_root()
    if os.path.isdir(cr):
        for repo in sorted(os.listdir(cr)):
            rd = os.path.join(cr, repo)
            if os.path.isdir(rd) and not os.path.islink(rd):
                for k in sorted(os.listdir(rd)):
                    if not k.endswith(".lock"):
                        add(os.path.join(rd, k))
    for root in cfg["roots"]:
        if not os.path.isdir(root):
            continue
        for sess in sorted(os.listdir(root)):
            sd = os.path.join(root, sess)
            if not os.path.isdir(sd) or os.path.islink(sd):
                continue
            if any(fnmatch.fnmatch(sess, p) for p in pats):
                add(sd); continue
            try:
                for e in sorted(os.listdir(sd)):
                    if any(fnmatch.fnmatch(e, p) for p in pats):
                        add(os.path.join(sd, e))
            except OSError:
                pass
    return out


def in_use(path: str) -> bool:
    """True when a process has its cwd or an open file under path (lsof; unknown counts as in use)."""
    if not shutil.which("lsof"):
        return True
    try:
        p = subprocess.run(["lsof", "-t", "+w", "+D", path], capture_output=True, text=True, timeout=300)
        # lsof uses 1 for no match. Treat diagnostics or any other exit as unknown.
        return p.returncode != 1 or bool(p.stdout.strip() or p.stderr.strip())
    except (OSError, subprocess.TimeoutExpired, UnicodeError):
        return True


def protected_git_path(path: str) -> bool:
    parts = path.casefold().split("/")
    if any(p in {"wal", "wals", "codex-wals"} or p.startswith(("wal-", "wal_", "wal."))
           or p.endswith(".wal.jsonl") for p in parts):
        return True
    if parts[-1] == "main.jsonl":
        return True
    if any(p in {".claude", ".codex"} for p in parts[:-1]):
        return any(p in {"projects", "sessions", "transcripts", "archived_sessions", "file-history", "logs"}
                   or p.startswith("history") for p in parts[1:])
    return parts[-1].startswith(("claude-", "codex-")) and parts[-1].endswith((".log", ".jsonl"))


def deletable(path: str, head: str = "HEAD") -> "tuple[bool, str]":
    if not os.path.exists(os.path.join(path, ".git")):
        return False, "not a git checkout (kept; check by hand)"
    if changes := copy_changes(path):
        return False, changes
    rc, tracked = git(path, "ls-files", "-z")
    if rc:
        return False, "could not check tracked protection"
    if any(protected_git_path(p) for p in tracked.rstrip("\0").split("\0") if p):
        return False, "tracked protected logs or WAL evidence"
    rc, stash = git(path, "stash", "list")
    if rc != 0 or stash:
        return False, "has a stash"
    rc, remote = git(path, "branch", "-r", "--contains", head)
    if rc != 0 or not remote.strip():
        return False, "HEAD is on no remote ref"
    rc, local = git(path, "log", "--oneline", "-1", "--branches", "--not", "--remotes")
    if rc != 0 or local:
        return False, "a local branch has commits on no remote"
    if in_use(path):
        return False, "a process is working in it or liveness is unknown"
    return True, "clean and pushed"


def copy_snapshot(path: str):
    """Bind retirement to the verified physical directory, registration, HEAD, tree and index."""
    rec = load_index().get(path)
    if not isinstance(rec, dict) or not isinstance(rec.get("repo"), str):
        return None
    rc, common = git(rec["repo"], "rev-parse", "--path-format=absolute", "--git-common-dir")
    if rc:
        return None
    common = os.path.realpath(common)
    head = managed_head(path, os.path.basename(path), common)
    if head is None:
        return None
    rc, tree = git(path, "rev-parse", "--verify", head + "^{tree}")
    if rc or not re.fullmatch(r"[a-f0-9]{40}|[a-f0-9]{64}", tree):
        return None
    rc, index = git(path, "rev-parse", "--path-format=absolute", "--git-path", "index")
    if (rc or os.path.dirname(os.path.dirname(index)) != os.path.join(common, "worktrees")
            or os.path.realpath(index) != index):
        return None
    source = os.lstat(path)
    digest = hashlib.sha256()
    fd = os.open(index, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as f:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            return None
        for data in iter(lambda: f.read(1 << 20), b""):
            digest.update(data)
        current = os.lstat(index)
        index_identity = (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns)
        if index_identity != (current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns, current.st_ctime_ns):
            return None
    return (common, head, tree, source.st_dev, source.st_ino, index, index_identity, digest.digest())


def remove_copy(path: str, prot: "dict | None" = None, *, expected=None) -> "tuple[bool, str]":
    try:
        if prot is None:
            prot, errors = protected_scan()
            if errors:
                return False, "could not read service units"
        hit = protecting(path, prot)
        if hit:
            return False, f"protected: a service uses {hit[0]}"
        if expected is None or copy_snapshot(path) != expected:
            return False, "managed checkout identity changed or is unverified"
        rc, out = git(expected[0], "worktree", "remove", path)
        return rc == 0, (out[-200:] if rc else "git worktree remove")
    except OSError as e:
        return False, f"{type(e).__name__}: {str(e)[:160]}"


def retire_copy(path: str, cfg: dict, planned_activity: float) -> str:
    if os.path.dirname(os.path.dirname(path)) != copies_root():
        return "kept: legacy or unmanaged copy; report only"
    try:
        with copy_lock(path) as descriptor:
            if copy_retirement_unconfirmed(descriptor):
                return "kept: reusable-copy retirement is unconfirmed"
            if last_activity(path, load_index()) > planned_activity:
                return "kept: copy was used after planning"
            expected = copy_snapshot(path)
            if expected is None:
                return "kept: managed checkout identity unverified"
            head = expected[1]
            ok, why = deletable(path, head)
            if not ok:
                return f"kept: {why}"
            prot, errors = protected_scan(cfg, fresh=True)
            if errors or protecting(path, prot):
                return "kept: service protection changed or is unknown"
            if copy_snapshot(path) != expected or last_activity(path, load_index()) > planned_activity:
                return "kept: managed checkout identity or activity changed"
            ok, why = deletable(path, head)
            if not ok:
                return f"kept: {why}"
            if last_activity(path, load_index()) > planned_activity:
                return "kept: copy was used after planning"
            done, why = remove_copy(path, prot, expected=expected)
            return "removed" if done else f"remove failed: {why}"
    except BlockingIOError:
        return "kept: managed copy lease is currently held"
    except (OSError, ValueError):
        return "kept: managed lease or directory identity unavailable"


def reap(apply: bool = False, cfg: "dict | None" = None, now: "float | None" = None) -> dict:
    cfg = normalize(cfg) if cfg is not None else load_config()
    now = now or time.time()
    idx = load_index()
    rows = []
    activities = {}
    for p in candidates(cfg):
        size = dir_size(p)
        activities[p] = last_activity(p, idx)
        rows.append({"path": p, "bytes": size or 0, "size_known": size is not None,
                     "idle_hours": round((now - activities[p]) / 3600, 1)})
    rows.sort(key=lambda r: -r["idle_hours"])            # oldest first
    total = sum(r["bytes"] for r in rows)
    over = total - cfg["max_total_gb"] * GB
    for r in rows:
        reasons = []
        if r["idle_hours"] >= cfg["max_age_hours"]:
            reasons.append(f"idle {r['idle_hours']}h >= {cfg['max_age_hours']}h")
        elif over > 0 and r["idle_hours"] >= 1:
            reasons.append(f"total {total / GB:.1f} GB over cap {cfg['max_total_gb']} GB")
        if reasons:
            over -= r["bytes"]
        r["reap"] = bool(reasons)
        r["why"] = "; ".join(reasons)
    deleting = bool(apply and cfg["reaper_delete_enabled"])
    try:
        prot, errors = protected_scan(cfg)
    except Exception:          # noqa: BLE001 -- cannot tell what services use: delete nothing
        prot, errors = None, 1
    for r in rows:
        hit = protecting(r["path"], prot) if prot else None
        if r["reap"] and (hit or errors):
            r["reap"] = False
            r["action"] = (f"kept: protected, a service uses {hit[0]} ({hit[1]})" if hit
                           else "kept: could not read service units")
            continue
        if not r["reap"]:
            r["action"] = "keep"
        elif not deleting:
            r["action"] = "would-remove (report-only)"
        else:
            r["action"] = retire_copy(r["path"], cfg, activities[r["path"]])
    res = {"mode": "delete" if deleting else "report-only", "delete_enabled": cfg["reaper_delete_enabled"],
           "total_gb": round(total / GB, 2), "cap_gb": cfg["max_total_gb"], "max_age_hours": cfg["max_age_hours"],
           "size_unknown": sum(not r["size_known"] for r in rows), "copies": rows, "ts": int(now)}
    if os.path.isdir(scratch_root()):           # scratch is reported, never reaped: it may hold a session's work
        sz = dir_size(scratch_root())
        res["scratch_gb"] = round((sz or 0) / GB, 2)
    if apply and not cfg["reaper_delete_enabled"]:
        res["note"] = ("--apply ignored: deletion needs \"reaper_delete_enabled\": true in " + config_path() +
                       " (the owner's OK first)")
    if any(r["reap"] for r in rows):
        alert("reap-candidates", {"mode": res["mode"], "count": sum(r["reap"] for r in rows),
                                  "gb": round(sum(r["bytes"] for r in rows if r["reap"]) / GB, 2)})
    return res


def report_path() -> str:
    return os.path.join(state_dir(), "copy-hygiene-report.json")


def session_start() -> str:
    """One line for the session when the last report found something; starts a detached report every 6 h."""
    msg = ""
    try:
        with open(report_path()) as f:
            rep = json.load(f)
        n = sum(1 for c in rep.get("copies", []) if c.get("reap"))
        gb = sum(c.get("bytes", 0) for c in rep.get("copies", []) if c.get("reap")) / GB
        if n:
            msg = (f"Test copies: {n} idle copies hold {gb:.1f} GB (all copies {rep.get('total_gb')} GB, cap "
                   f"{rep.get('cap_gb')} GB). Reuse one copy per PR (`copy_hygiene.py acquire`); "
                   "`copy_hygiene.py reap` lists them. Removing them needs the owner's OK.")
        age = time.time() - float(rep.get("ts") or 0)
    except (OSError, ValueError, TypeError):
        age = REPORT_EVERY_S + 1
    if age > REPORT_EVERY_S:
        try:
            os.makedirs(state_dir(), exist_ok=True)
            marker = os.path.join(state_dir(), "copy-hygiene-report.started")
            if time.time() - (os.path.getmtime(marker) if os.path.exists(marker) else 0) > REPORT_EVERY_S:
                open(marker, "w").close()
                subprocess.Popen([sys.executable, "-B", os.path.abspath(__file__), "reap", "--write-report"],
                                 stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                 start_new_session=True, close_fds=True)
        except OSError:
            pass
    return msg


def scratch_root() -> str:
    return os.path.join(home(), ".agent-harness", "scratch")


def scratch(key: str = "") -> "str | None":
    """A private disk-backed scratch directory (the replacement for /dev/shm), one per session. Returns None (and
    alerts) when the disk is below the copy floor, so scratch can't fill the disk the way it filled /dev/shm."""
    key = key or os.environ.get("CLAUDE_SESSION_ID") or os.environ.get("CODEX_SESSION_ID") or \
        f"{time.strftime('%Y%m%d')}-{os.getppid()}"
    d = os.path.join(scratch_root(), safe_key(key))
    cfg = load_config()
    low, gb, fl = disk_low(home(), cfg)
    if low:
        alert("disk-low-refused-scratch", {"free_gb": round(gb, 2), "floor_gb": round(fl, 2)})
        return None
    os.makedirs(d, mode=0o700, exist_ok=True)
    os.chmod(d, 0o700)
    return d


def acquire_cli(args) -> int:
    def run_command(result):
        print(json.dumps(result), flush=True)
        try:
            rc = subprocess.call(args.run, cwd=result["path"])
        except OSError:
            print("could not start leased command", file=sys.stderr)
            return 127
        return rc if rc >= 0 else 128 - rc

    res = acquire(args.repo, args.key, args.ref, require_reuse=args.require_reuse,
                  run=run_command if args.run else None)
    if "exit_code" in res:
        return res["exit_code"]
    print(json.dumps(res), flush=True)
    return 0 if res.get("ok") else (3 if res.get("refused") else 4 if res.get("stale") else 1)


def supervise_acquire(args) -> int:
    """A child owns the lease, so controller death does not release it during the command.

    Do not pass the lock FD to the command. A detached command descendant must not hold the
    lease forever; commands must wait for any descendants using the worktree.
    """
    pid = os.fork()
    if pid == 0:
        # Caught handlers reset on exec, so a normally behaved payload still gets the
        # foreground signal. The supervisor keeps waiting if the payload handles it.
        for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            signal.signal(signum, lambda *_: None)
        try:
            code = acquire_cli(args)
        except KeyboardInterrupt:
            code = 130
        except BaseException:
            print("leased acquire failed", file=sys.stderr, flush=True)
            code = 1
        os._exit(code)
    try:
        _, status = os.waitpid(pid, 0)
    except KeyboardInterrupt:
        return 130
    code = os.waitstatus_to_exitcode(status)
    return code if code >= 0 else 128 - code


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="copy_hygiene.py")
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("acquire"); a.add_argument("--repo", required=True); a.add_argument("--key", required=True)
    a.add_argument("--ref", default="HEAD")
    a.add_argument("--require-reuse", action="store_true", help="refuse when the managed copy is missing")
    a.add_argument("--run", nargs=argparse.REMAINDER, help="hold an exclusive lease while running COMMAND ... in the copy")
    r = sub.add_parser("reap"); r.add_argument("--apply", action="store_true"); r.add_argument("--json", action="store_true")
    r.add_argument("--write-report", action="store_true", help="store the report for the SessionStart line")
    sub.add_parser("pretool")
    sub.add_parser("session-start")
    sub.add_parser("check-disk")
    sc = sub.add_parser("scratch"); sc.add_argument("--key", default="")
    pr = sub.add_parser("protected", help="list protected paths, or --check <path> (exit 1 when protected)")
    pr.add_argument("--check", default="")
    finish = sub.add_parser("finish", help="verify and optionally retire one completed task's indexed copy")
    finish.add_argument("--repo", required=True)
    finish.add_argument("--key", required=True)
    finish.add_argument("--expect-head", required=True)
    archive = sub.add_parser("archive-artifact", help="verify and optionally retire one completed task artifact to B2")
    archive.add_argument("--name", required=True)
    archive.add_argument("--b2-remote")
    archive.add_argument("--max-bytes", type=int, help="explicit artifact limit, up to 4 GiB (defaults to 256 MiB)")
    for scoped in (finish, archive):
        scoped.add_argument("--task-dir", required=True)
        scoped.add_argument("--apply", action="store_true")
    args = ap.parse_args(argv)
    if args.cmd in ("finish", "archive-artifact"):
        sys.path.insert(0, os.path.dirname(os.path.realpath(__file__)))
        import lifecycle_cleanup

        return lifecycle_cleanup.run(args)
    if args.cmd == "acquire" and args.run == []:
        ap.error("--run requires a command")
    if args.cmd == "scratch":
        d = scratch(args.key)
        if not d:
            sys.stderr.write(low_disk_message(home(), *disk_low(home(), load_config())[1:]) + "\n")
            return 3
        print(d)
        return 0
    if args.cmd == "protected":
        prot, errors = protected_scan()
        if args.check:
            path = os.path.abspath(os.path.expanduser(args.check))
            hit = protecting(path, prot)
            if hit:
                print(f"PROTECTED: deleting {path} would remove {hit[0]} (named in {hit[1]})")
                return 1
            if errors:
                print(f"UNKNOWN: {errors} service unit file(s) could not be read; treat {path} as protected")
                return 1
            print(f"not protected: {path}")
            return 0
        for _k2, (path, src) in sorted(prot.items()):
            print(f"{path}\t{src}")
        if errors:
            print(f"# {errors} unit file(s) could not be read", file=sys.stderr)
        return 0
    if args.cmd == "pretool":
        try:
            raw = sys.stdin.read(1 << 20) if not sys.stdin.isatty() else ""
            ev = json.loads(raw) if raw.strip() else {}
        except Exception:      # noqa: BLE001
            return 0
        code, err = pretool(ev if isinstance(ev, dict) else {})
        if err:
            sys.stderr.write(err)
        return code
    if args.cmd == "session-start":
        try:
            if not sys.stdin.isatty():
                sys.stdin.read(1 << 20)
            msg = session_start()
        except Exception:      # noqa: BLE001
            return 0
        if msg:
            print(json.dumps({"systemMessage": msg}))
        return 0
    if args.cmd == "acquire":
        return supervise_acquire(args) if args.run else acquire_cli(args)
    if args.cmd == "check-disk":
        cfg = load_config()
        low, gb, fl = disk_low(copies_root(), cfg)
        print(json.dumps({"free_gb": round(gb, 2), "floor_gb": round(fl, 2), "low": low}))
        return 3 if low else 0
    res = reap(apply=args.apply)
    if args.write_report:
        try:
            _atomic_write(report_path(), json.dumps(res))
        except OSError:
            pass
    if args.json:
        print(json.dumps(res, indent=1))
    elif not args.write_report:
        print(f"test copies: {len(res['copies'])}, {res['total_gb']} GB (cap {res['cap_gb']} GB, idle limit "
              f"{res['max_age_hours']} h), mode {res['mode']}")
        for c in res["copies"]:
            print(f"  {c['action']:<34} {c['bytes'] / GB:7.1f} GB  idle {c['idle_hours']:>7}h  {c['path']}  {c['why']}")
        if res.get("note"):
            print(res["note"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
