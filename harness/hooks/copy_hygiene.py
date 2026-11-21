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
                when tracked changes would have to be discarded, so a round never silently tests an older commit. It
                refuses to create a copy below the free-space floor (exit 3) and writes an alert.
  pretool       PreToolUse Bash hook. Below the floor it denies commands that create copies (git clone, git worktree
                add, cp -r/-R/-a, rsync -r/-a, ditto) with a clear alert. It always denies writing scratch INTO
                /dev/shm (RAM); reading, copying out of and removing from /dev/shm stay allowed. Silent otherwise.
                Fails OPEN on any internal error.
  session-start SessionStart hook: at most every 6 h starts a detached report-only `reap`, and prints one line when the
                last report found idle copies or a total over the cap.
  reap          `copy_hygiene.py reap [--apply] [--json]` lists idle copies (older than max_age_hours) and, when the
                total is over max_total_gb, the oldest copies above the cap. REPORT-ONLY unless BOTH the config value
                "reaper_delete_enabled": true (a literal JSON true) is set in ~/.agent-harness/state/copy-hygiene.json
                AND --apply is passed. The installer never sets it, so installing or a first run deletes nothing.
                Even when enabled it removes only a git checkout with no tracked or untracked changes, no stash, no
                local commits missing from its remotes, no ignored files except regenerable build output, and no
                process inside it. Linked worktrees go through plain `git worktree remove` (no --force).

Config (~/.agent-harness/state/copy-hygiene.json; every key optional):
  min_free_gb (25), min_free_pct (10; the floor is the smaller of the two), max_age_hours (24), max_total_gb (60),
  reaper_delete_enabled (false), roots ([~/.agent-harness/work]), name_patterns (["tester-*", "test-copy-*",
  "click-test-*"]).
Env: HARNESS_COPY_HYGIENE_MIN_FREE_GB overrides min_free_gb; HARNESS_COPY_HYGIENE_HOME relocates the state (tests).
"""
from __future__ import annotations

import argparse
import fcntl
import fnmatch
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tempfile
import time

GB = 1024 ** 3
DEFAULTS = {
    "min_free_gb": 25.0,
    "min_free_pct": 10.0,
    "max_age_hours": 24.0,
    "max_total_gb": 60.0,
    "reaper_delete_enabled": False,
    "roots": None,                     # None = [<home>/.agent-harness/work]
    "name_patterns": ["tester-*", "test-copy-*", "click-test-*"],
}
GIT_TIMEOUT = 60
REPORT_EVERY_S = 6 * 3600
REGENERABLE_IGNORED = ("node_modules", ".next", "dist", "build", "target", ".venv", "venv", "__pycache__",
                       ".pytest_cache", ".mypy_cache", ".ruff_cache", "coverage", ".turbo", ".cache", ".parcel-cache",
                       ".gradle", "DerivedData", ".nuxt", ".svelte-kit", "out")
PREFIXES = frozenset(("sudo", "command", "time", "env", "nice", "nohup", "exec", "builtin", "ionice", "timeout"))
ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
SHM = "/dev/shm"
SHM_ENV = re.compile(r"\b(?:TMPDIR|TMP|TEMP|CLAUDE_CODE_TMPDIR|XDG_CACHE_HOME|XDG_RUNTIME_DIR)=[\"']?/dev/shm(?:/|\b|$)")
SHM_REDIRECT = re.compile(r"(?:^|[^<0-9&])\d?>>?\|?\s*[\"']?/dev/shm(?:/|\s|$|[\"'])")


# ---------------------------------------------------------------- config and state
def home() -> str:
    return os.environ.get("HARNESS_COPY_HYGIENE_HOME") or os.path.expanduser("~")


def state_dir() -> str:
    return os.path.join(home(), ".agent-harness", "state")


def config_path() -> str:
    return os.path.join(state_dir(), "copy-hygiene.json")


def copies_root() -> str:
    return os.path.join(home(), ".agent-harness", "test-copies")


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
            "copies (removing them needs the owner's OK).")


# ---------------------------------------------------------------- git helpers
def git(cwd: str, *args: str) -> "tuple[int, str]":
    try:
        p = subprocess.run(["git", "-C", cwd, *args], capture_output=True, text=True, timeout=GIT_TIMEOUT,
                           env=dict(os.environ, GIT_OPTIONAL_LOCKS="0", GIT_TERMINAL_PROMPT="0"))
        return p.returncode, (p.stdout + p.stderr).strip()
    except (OSError, subprocess.TimeoutExpired) as e:
        return 99, str(e)


def safe_key(key: str) -> str:
    k = re.sub(r"[^A-Za-z0-9._-]+", "-", str(key)).strip("-.")
    if not k or set(k) <= {"."}:
        raise ValueError(f"unusable key: {key!r}")
    return k[:80]


def repo_identity(top: str) -> "tuple[str, str]":
    """(<repo name>-<8 hex>, common dir): one id for every worktree of a repository, distinct for same-named repos."""
    rc, common = git(top, "rev-parse", "--path-format=absolute", "--git-common-dir")
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
def acquire(repo: str, key: str, ref: str = "HEAD", cfg: "dict | None" = None) -> dict:
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
    rc, sha = git(top, "rev-parse", "--verify", "--quiet", ref + "^{commit}")
    if rc != 0 or not sha:
        return {"ok": False, "error": f"unknown ref in {top}: {ref}"}
    sha = sha.splitlines()[-1].strip()
    rid, common = repo_identity(top)
    path = os.path.join(copies_root(), rid, k)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path + ".lock", "w") as lk:            # one acquire per copy at a time
        fcntl.flock(lk, fcntl.LOCK_EX)
        if os.path.isdir(path):
            rc, cur = git(path, "rev-parse", "HEAD")
            if rc != 0:
                return {"ok": False, "path": path, "error": f"existing copy is not a usable checkout: {path}; "
                        "move it aside by hand (nothing was changed)"}
            cur = cur.strip()
            if cur != sha:
                rc, dirty = git(path, "status", "--porcelain", "--untracked-files=no")
                if rc != 0 or dirty:
                    touch_index(path, repo=top, key=key)
                    return {"ok": False, "stale": True, "path": path, "commit": cur, "wanted": sha,
                            "error": "the copy has uncommitted tracked changes and is still at an older commit; "
                                     "commit or remove them, then acquire again (nothing was discarded)"}
                rc, local = git(path, "log", "--oneline", "-1", "HEAD", "--not", "--remotes", "--branches")
                if rc == 0 and local:
                    return {"ok": False, "stale": True, "path": path, "commit": cur, "wanted": sha,
                            "error": "the copy's HEAD holds a commit on no branch or remote; save it on a branch first"}
                rc, out = git(path, "checkout", "--detach", "--quiet", sha)
                if rc != 0:
                    return {"ok": False, "stale": True, "path": path, "commit": cur, "wanted": sha, "error": out[-300:]}
            touch_index(path, repo=top, key=key)
            return {"ok": True, "path": path, "commit": sha, "reused": True, "moved": cur != sha}
        low, gb, fl = disk_low(path, cfg)
        if low:
            alert("disk-low-refused-acquire", {"path": path, "free_gb": round(gb, 2), "floor_gb": round(fl, 2)})
            return {"ok": False, "refused": "disk-low", "free_gb": round(gb, 2), "error": low_disk_message(path, gb, fl)}
        rc, out = git(common if os.path.isdir(common) else top, "worktree", "add", "--detach", path, sha)
        if rc != 0:
            return {"ok": False, "error": out[-300:]}
        touch_index(path, repo=top, key=key)
        return {"ok": True, "path": path, "commit": sha, "reused": False, "moved": True}


# ---------------------------------------------------------------- command analysis
def simple_commands(cmd: str) -> list:
    """argv lists of the simple commands in a shell line (quote-aware enough for policy; never raises)."""
    out = []
    for seg in re.split(r"\|\||&&|[;|&\n]|\$\(|`|\(|\)", cmd):
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
        if SHM in cmd or cwd.startswith(SHM):
            if writes_into_shm(cmd, cwd):
                alert("shm-write-denied", {"cwd": cwd[:200]})
                return 2, ("SCRATCH IN RAM REFUSED: /dev/shm is memory, not disk (2026-11-21: sessions filled 50 of "
                           "t2-dev's 56 GB). Write scratch under your session's work directory in ~/.agent-harness/work/ "
                           "instead. Reading, copying out of and removing files in /dev/shm stay allowed.\n")
        copying = [w for w in simple_commands(cmd) if is_copy_command(w)]
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
        p = subprocess.run(["lsof", "-t", "+D", path], capture_output=True, text=True, timeout=300)
        return bool(p.stdout.strip())
    except (OSError, subprocess.TimeoutExpired):
        return True


def deletable(path: str) -> "tuple[bool, str]":
    if not os.path.exists(os.path.join(path, ".git")):
        return False, "not a git checkout (kept; check by hand)"
    rc, dirty = git(path, "status", "--porcelain", "--untracked-files=all")
    if rc != 0:
        return False, "git status failed"
    if dirty:
        return False, "uncommitted or untracked changes"
    rc, stash = git(path, "stash", "list")
    if rc != 0 or stash:
        return False, "has a stash"
    rc, remote = git(path, "branch", "-r", "--contains", "HEAD")
    if rc != 0 or not remote.strip():
        return False, "HEAD is on no remote ref"
    rc, local = git(path, "log", "--oneline", "-1", "--branches", "--not", "--remotes")
    if rc != 0 or local:
        return False, "a local branch has commits on no remote"
    rc, ign = git(path, "status", "--porcelain", "--ignored")
    if rc != 0:
        return False, "git status --ignored failed"
    for line in ign.splitlines():
        if line.startswith("!! "):
            first = line[3:].strip().strip('"').rstrip("/").split("/")
            if not any(part in REGENERABLE_IGNORED for part in first):
                return False, f"ignored files that may be evidence ({line[3:].strip()[:80]})"
    if in_use(path):
        return False, "a process is working in it"
    return True, "clean and pushed"


def remove_copy(path: str) -> "tuple[bool, str]":
    try:
        dotgit = os.path.join(path, ".git")
        if os.path.isfile(dotgit):   # linked worktree
            rc, common = git(path, "rev-parse", "--path-format=absolute", "--git-common-dir")
            if rc != 0:
                return False, "cannot find the main repository"
            main = os.path.dirname(common.strip()) if os.path.basename(common.strip()) == ".git" else common.strip()
            rc, out = git(main, "worktree", "remove", path)
            return rc == 0, (out[-200:] if rc else "git worktree remove")
        shutil.rmtree(path)
        return True, "removed standalone clone"
    except OSError as e:
        return False, f"{type(e).__name__}: {str(e)[:160]}"


def reap(apply: bool = False, cfg: "dict | None" = None, now: "float | None" = None) -> dict:
    cfg = normalize(cfg) if cfg is not None else load_config()
    now = now or time.time()
    idx = load_index()
    rows = []
    for p in candidates(cfg):
        size = dir_size(p)
        rows.append({"path": p, "bytes": size or 0, "size_known": size is not None,
                     "idle_hours": round((now - last_activity(p, idx)) / 3600, 1)})
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
    for r in rows:
        if not r["reap"]:
            r["action"] = "keep"
        elif not deleting:
            r["action"] = "would-remove (report-only)"
        else:
            ok, why = deletable(r["path"])
            if not ok:
                r["action"] = f"kept: {why}"
            else:
                done, msg = remove_copy(r["path"])
                r["action"] = "removed" if done else f"remove failed: {msg}"
    res = {"mode": "delete" if deleting else "report-only", "delete_enabled": cfg["reaper_delete_enabled"],
           "total_gb": round(total / GB, 2), "cap_gb": cfg["max_total_gb"], "max_age_hours": cfg["max_age_hours"],
           "size_unknown": sum(not r["size_known"] for r in rows), "copies": rows, "ts": int(now)}
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


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="copy_hygiene.py")
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("acquire"); a.add_argument("--repo", required=True); a.add_argument("--key", required=True)
    a.add_argument("--ref", default="HEAD")
    r = sub.add_parser("reap"); r.add_argument("--apply", action="store_true"); r.add_argument("--json", action="store_true")
    r.add_argument("--write-report", action="store_true", help="store the report for the SessionStart line")
    sub.add_parser("pretool")
    sub.add_parser("session-start")
    sub.add_parser("check-disk")
    args = ap.parse_args(argv)
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
        res = acquire(args.repo, args.key, args.ref)
        print(json.dumps(res))
        return 0 if res.get("ok") else (3 if res.get("refused") else 4 if res.get("stale") else 1)
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
