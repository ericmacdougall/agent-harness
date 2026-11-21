#!/usr/bin/env python3
"""Copy hygiene: one reusable test copy per PR or lane, a disk-low guard, a /dev/shm guard, and an idle-copy reaper
that is report-only by default.

WHY. On 2026-11-21 t2-dev's root volume reached 0 bytes free: ~/.agent-harness/work held 117 GB, most of it per-round
click-test copies (work/<session>/tester-1408-r3, tester-1408-r4, tester-1409-r1, ...). Each review round made a new
full copy and nothing removed the old ones. Sessions also held 50 of the host's 56 GB of /dev/shm (RAM) with scratch.

WHAT.
  acquire       `copy_hygiene.py acquire --repo <checkout> --key <pr-1408|lane> [--ref <ref>]` returns ONE stable path
                (~/.agent-harness/test-copies/<repo>-<id>/<key>) per repository and PR/lane, backed by ONE shared bare
                mirror per repository (~/.agent-harness/mirrors/<host>/<repo>-<id>.git, temp clone + rename, a lock per
                mirror and per key). `--url <remote> --key K` works without a checkout. The first call makes a detached
                linked worktree; later calls reuse it and check out the requested commit; a branch name resolves
                through refs/remotes/origin/<ref> in the freshly fetched mirror. It refuses (exit 4) when tracked
                changes, or a commit that is on no remote and not in your checkout, would be lost, so a round never
                silently tests an older commit. It refuses to create a mirror or copy below the free-space floor
                (exit 3) and writes an alert. Every refusal exits nonzero.
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
                local commits missing from what the remote advertises (fresh ls-remote), no ignored files except the
                one regenerable list (hygiene_safety.REGENERABLE_IGNORED), no process using it (cwd, exe, open files,
                memory maps), and nothing a systemd unit, cron job, container or launchd plist references. Linked
                worktrees go through plain `git worktree remove` (no --force). The same rule and the same switch serve
                workspace_janitor.py (session-end release, hourly TTL sweep); see hygiene_safety.py.

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

import hygiene_safety as S

GB = S.GB
DEFAULTS = {
    "min_free_gb": 25.0,
    "min_free_pct": 10.0,
    "max_age_hours": 24.0,
    "max_total_gb": 60.0,
    "reaper_delete_enabled": False,
    "roots": None,                     # None = [<home>/.agent-harness/work]
    "name_patterns": ["tester-*", "test-copy-*", "click-test-*"],
    # workspace_janitor.py reads the same file (one config, one deletion switch):
    "shm_ttl_hours": 6.0,
    "mirror_ttl_days": 14.0,           # shared bare mirrors with no worktree left are removed after this many idle days
    "protect_names": ["yates", "optinrouter"],
    "default_memory": "4g",
}
GIT_TIMEOUT = 60
REPORT_EVERY_S = 6 * 3600
REGENERABLE_IGNORED = S.REGENERABLE_IGNORED      # the ONE regenerable list lives in hygiene_safety
PREFIXES = S.PREFIXES
ASSIGN = S.ASSIGN
SHM = "/dev/shm"
SHM_ENV = re.compile(r"\b(?:TMPDIR|TMP|TEMP|CLAUDE_CODE_TMPDIR|XDG_CACHE_HOME|XDG_RUNTIME_DIR)=[\"']?/dev/shm(?:/|\b|$)")
SHM_REDIRECT = re.compile(r"(?:^|[^<0-9])(?:&|\d)?>>?\|?\s*[\"']?/dev/shm(?:/|\s|$|[\"'])")


# ---------------------------------------------------------------- config and state
def home() -> str:
    return S.home()


def state_dir() -> str:
    return S.state_dir()


def config_path() -> str:
    return os.path.join(state_dir(), "copy-hygiene.json")


def copies_root() -> str:
    return os.path.join(home(), ".agent-harness", "test-copies")


def under_copies(path: str) -> bool:
    """True for a path inside test-copies, compared by realpath on BOTH sides (a symlinked home must not skip the lock)."""
    return os.path.realpath(path).startswith(os.path.realpath(copies_root()) + os.sep)


def _num(v, default: float) -> float:
    try:
        f = float(v)
        return f if f >= 0 else default
    except (TypeError, ValueError):
        return default


def normalize(cfg: dict) -> dict:
    out = dict(DEFAULTS)
    out.update({k: v for k, v in (cfg or {}).items() if k in DEFAULTS})
    for k in ("min_free_gb", "min_free_pct", "max_age_hours", "max_total_gb", "shm_ttl_hours", "mirror_ttl_days"):
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
    pn = out.get("protect_names")
    out["protect_names"] = [str(x).lower() for x in pn if str(x).strip()] if isinstance(pn, list) else list(DEFAULTS["protect_names"])
    out["default_memory"] = str(out.get("default_memory") or DEFAULTS["default_memory"])
    return out


def deletion_enabled(cfg: dict) -> bool:
    """THE one deletion switch, shared with workspace_janitor: the owner's config AND no HARNESS_JANITOR=off kill switch."""
    return bool(cfg.get("reaper_delete_enabled")) and os.environ.get("HARNESS_JANITOR", "").lower() != "off"


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
    """Append one row to the single alert/audit record; never raises."""
    S.alert(kind, detail)


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
    rc, out, err = S.git(cwd, *args, t=GIT_TIMEOUT)
    return (99 if rc == -1 else rc), (out + err).strip()


safe_key = S.safe_key


def parse_url(url: str) -> "tuple[str, str]":
    """(host, repo path) of a remote URL or a local repository path; the same repo over https and ssh gives one pair."""
    if url.startswith("/") or url.startswith("file://"):
        p = url[7:] if url.startswith("file://") else url
        return "local", re.sub(r"\.git$", "", p.strip("/"))
    m = re.match(r"^(?:[A-Za-z][A-Za-z0-9+.-]*://)?(?:[^@/]+@)?([^/:]+)(?::\d+(?=/))?[:/]+(.+?)(?:\.git)?/?$", url)
    if not m or ".." in m.group(2).split("/"):
        raise ValueError("cannot parse repo url: %s" % re.sub(r"://[^@/]+@", "://", url))
    return m.group(1).lower(), m.group(2)


def mirror_id(url: str) -> "tuple[str, str, str]":
    """(<name>-<10 hex of host/path>, host dir, name): one shared id for a repository, whoever asks."""
    host, path = parse_url(url)
    name = safe_key(path.split("/")[-1] or "repo")
    return "%s-%s" % (name, hashlib.sha256(("%s/%s" % (host, path)).encode()).hexdigest()[:10]), safe_key(host), name


def mirror_path(url: str) -> str:
    rid, host, _ = mirror_id(url)
    return os.path.join(home(), ".agent-harness", "mirrors", host, rid + ".git")


def source_url(top: str) -> str:
    """The origin URL of a checkout (a relative remote path made absolute); the checkout itself when it has no origin."""
    rc, out, _ = S.git(top, "remote", "get-url", "origin")
    url = out.strip()
    if rc != 0 or not url:
        return os.path.realpath(top)
    if "://" not in url and not re.match(r"^[^/]+@[^/]+:", url) and not url.startswith("/"):
        cand = os.path.realpath(os.path.join(top, os.path.expanduser(url)))
        if os.path.exists(cand):
            return cand
    return url


def ensure_mirror(url: str, cfg: dict) -> "tuple[str, dict | None]":
    """(mirror path, None) once the shared bare mirror exists and is freshly fetched; (path, error result) otherwise.
    Call with the mirror lock held. The first clone goes to a temp folder and is renamed into place, so a half-finished
    clone is never reused. Branch copies under refs/heads are deleted after the clone: only refs/remotes/origin/* is
    maintained, so a branch name can never resolve to a commit from the day the mirror was made."""
    m = mirror_path(url)
    if not os.path.isdir(m):
        low, gb, fl = disk_low(os.path.dirname(m), cfg)
        if low:
            alert("disk-low-refused-acquire", {"path": m, "free_gb": round(gb, 2), "floor_gb": round(fl, 2)})
            return m, {"ok": False, "refused": "disk-low", "free_gb": round(gb, 2), "error": low_disk_message(m, gb, fl)}
        tmp = "%s.tmp-%d" % (m, os.getpid())
        shutil.rmtree(tmp, ignore_errors=True)

        def fail(msg: str) -> "tuple[str, dict]":
            shutil.rmtree(tmp, ignore_errors=True)
            return m, {"ok": False, "error": "mirror clone failed: " + msg[-300:]}
        rc, _, err = S.git(os.path.dirname(m), "clone", "--bare", "--quiet", "--filter=blob:none", url, tmp, t=3600)
        if rc != 0:
            return fail(err)
        rc, refs, err = S.git(tmp, "for-each-ref", "--format=%(refname)", "refs/heads")
        if rc != 0:
            return fail(err)
        for ref in refs.split():
            rc, _, err = S.git(tmp, "update-ref", "-d", ref)
            if rc != 0:
                return fail(err)
        rc, _, err = S.git(tmp, "config", "remote.origin.fetch", "+refs/heads/*:refs/remotes/origin/*")
        if rc != 0:
            return fail(err)
        rc, _, err = S.git(tmp, "fetch", "--prune", "--quiet", "origin", t=3600)
        if rc != 0:
            return fail(err)
        rc, _, err = S.git(tmp, "remote", "set-head", "origin", "-a")
        if rc != 0:
            return fail(err)
        os.rename(tmp, m)
        return m, None
    rc, _, err = S.git(m, "fetch", "--prune", "--quiet", "origin", t=1800)
    if rc != 0:
        return m, {"ok": False, "error": "mirror fetch failed (nothing was changed): " + err.strip()[-300:]}
    if S.git(m, "rev-parse", "--verify", "--quiet", "refs/remotes/origin/HEAD")[0] != 0:
        S.git(m, "remote", "set-head", "origin", "-a")             # best effort; a missing HEAD is reported at resolve time
    return m, None


def resolve_ref(m: str, ref: str, source: "str | None") -> "str | None":
    """Commit for ref. A branch name resolves through refs/remotes/origin/<ref> in the freshly fetched mirror FIRST."""
    ref = ref or "HEAD"
    if re.fullmatch(r"[0-9a-f]{40}", ref):
        return ref
    plain = ref != "HEAD" and not re.search(r"[~^@:{}\s]|\.\.", ref)
    if plain:
        for cand in ("refs/remotes/origin/" + ref, "refs/remotes/" + ref, "refs/tags/" + ref):
            rc, out, _ = S.git(m, "rev-parse", "--verify", "--quiet", cand + "^{commit}")
            if rc == 0 and out.strip():
                return out.strip()
    where, target = (source, ref) if source else (m, "refs/remotes/origin/HEAD" if ref == "HEAD" else ref)
    rc, out, _ = S.git(where, "rev-parse", "--verify", "--quiet", target + "^{commit}")
    return out.strip() if rc == 0 and out.strip() else None


def _leave_ok(path: str, cur: str, source: "str | None") -> bool:
    """The copy's HEAD commit loses nothing when the copy moves: on the remote, or still held by the source checkout."""
    rc, local = git(path, "rev-list", "-1", cur, "--not", "--remotes")
    if rc == 0 and not local:
        return True
    if not source:
        return False
    if S.git(source, "cat-file", "-e", cur + "^{commit}")[0] != 0:
        return False
    if S.git(source, "merge-base", "--is-ancestor", cur, "HEAD")[0] == 0:
        return True
    rc, out, _ = S.git(source, "for-each-ref", "--contains", cur, "--count=1", "--format=%(refname)")
    return rc == 0 and bool(out.strip())


def lock_path(path: str):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fh = open(path, "a")
    fcntl.flock(fh, fcntl.LOCK_EX)
    return fh


# ---------------------------------------------------------------- acquire
def acquire(repo: str, key: str, ref: str = "HEAD", cfg: "dict | None" = None, url: str = "") -> dict:
    """THE reuse API: one stable detached worktree per (repository, key) at ~/.agent-harness/test-copies/<id>/<key>,
    backed by one shared bare mirror per repository. `repo` is any checkout of the repository (its origin URL picks the
    mirror); with `url` and no `repo` the URL does. A lock per key and per mirror serialises runners."""
    cfg = normalize(cfg) if cfg is not None else load_config()
    try:
        k = safe_key(key)
    except ValueError as e:
        return {"ok": False, "error": str(e)}
    source = None
    if repo:
        repo = os.path.abspath(repo)
        rc, top = git(repo, "rev-parse", "--show-toplevel")
        if rc != 0:
            return {"ok": False, "error": f"not a git checkout: {repo}"}
        source = top.splitlines()[-1].strip()
        url = url or source_url(source)
    if not url:
        return {"ok": False, "error": "need --repo <checkout> or --url <remote>"}
    try:
        rid, _, _ = mirror_id(url)
    except ValueError as e:
        return {"ok": False, "error": str(e)}
    m = mirror_path(url)
    path = os.path.join(copies_root(), rid, k)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with lock_path(path + ".lock"), lock_path(m + ".lock"):
        m, err = ensure_mirror(url, cfg)
        if err:
            return err
        sha = resolve_ref(m, ref, source)
        if not sha:
            return {"ok": False, "error": f"unknown ref {ref!r} in {source or url}"}
        if S.git(m, "cat-file", "-e", sha + "^{commit}")[0] != 0:
            if not source or S.git(m, "fetch", "--quiet", "--no-tags", source, sha, t=600)[0] != 0 \
                    or S.git(m, "cat-file", "-e", sha + "^{commit}")[0] != 0:
                return {"ok": False, "error": f"commit {sha[:12]} is not on the remote and could not be fetched; push it first"}
        if os.path.isdir(path):
            rc, cur = git(path, "rev-parse", "HEAD")
            if rc != 0:
                return {"ok": False, "path": path, "error": f"existing copy is not a usable checkout: {path}; "
                        "move it aside by hand (nothing was changed)"}
            cur = cur.strip()
            if cur != sha:
                rc, dirty = git(path, "status", "--porcelain", "--untracked-files=no")
                if rc != 0 or dirty:
                    touch_index(path, repo=source or url, key=key)
                    return {"ok": False, "stale": True, "path": path, "commit": cur, "wanted": sha,
                            "error": "the copy has uncommitted tracked changes and is still at an older commit; "
                                     "commit or remove them, then acquire again (nothing was discarded)"}
                if not _leave_ok(path, cur, source):
                    return {"ok": False, "stale": True, "path": path, "commit": cur, "wanted": sha,
                            "error": "the copy's HEAD holds a commit that is on no remote and not in your checkout; "
                                     "push it or save it on a branch first (nothing was discarded)"}
                rc, out = git(path, "checkout", "--detach", "--quiet", sha)
                if rc != 0:
                    return {"ok": False, "stale": True, "path": path, "commit": cur, "wanted": sha, "error": out[-300:]}
            touch_index(path, repo=source or url, key=key)
            return {"ok": True, "path": path, "commit": sha, "reused": True, "moved": cur != sha}
        low, gb, fl = disk_low(path, cfg)
        if low:
            alert("disk-low-refused-acquire", {"path": path, "free_gb": round(gb, 2), "floor_gb": round(fl, 2)})
            return {"ok": False, "refused": "disk-low", "free_gb": round(gb, 2), "error": low_disk_message(path, gb, fl)}
        rc, out = git(m, "worktree", "add", "--detach", path, sha)
        if rc != 0:
            shutil.rmtree(path, ignore_errors=True)
            git(m, "worktree", "prune")
            return {"ok": False, "error": out[-300:]}
        touch_index(path, repo=source or url, key=key)
        return {"ok": True, "path": path, "commit": sha, "reused": False, "moved": True}


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


# ---------------------------------------------------------------- command analysis
simple_commands = S.simple_commands


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
        if not os.path.isdir(root) or not S.within_allowed(root, strictly_inside=False):
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


def in_use(path: str, used: "set | None" = None) -> bool:
    """True when a process uses path (cwd, root, exe, open file or memory map); unknown counts as in use."""
    try:
        return S.is_used(path, S.in_use_paths() if used is None else used)
    except S.ProbeError:
        return True


def deletable(path: str, used: "set | None" = None, refs: "set | None" = None) -> "tuple[bool, str]":
    """The ONE rule (hygiene_safety.recoverable) plus in-use and service references."""
    if not os.path.exists(os.path.join(path, ".git")):
        return False, "not a git checkout (kept; check by hand)"
    ok, why = S.recoverable(path)
    if not ok:
        return False, why
    if in_use(path, used):
        return False, "a process is working in it"
    if refs is not None and S.referenced(path, refs):
        return False, "referenced by a systemd unit, cron job, container or launchd plist"
    return True, "clean and pushed"


def remove_copy(path: str) -> "tuple[bool, str]":
    ok, msg = S.remove_checkout(path)
    return ok, (msg or "removed")


def _reap_one(r: dict, now: float) -> str:
    """Decide on one copy with the key lock HELD and nothing carried over from the scan: an acquire that only touched the
    index (the worktree's HEAD lives in the mirror) must stop the removal, so the idle time is re-read from the index
    and the process and service probes are run again right before the removal."""
    path = r["path"]
    lk = S.lock_nonblocking(path + ".lock") if under_copies(path) else None
    if under_copies(path) and lk is None:
        return "kept: locked by a running acquire"
    try:
        idle = (now - last_activity(path, load_index())) / 3600
        if idle < r["min_idle_hours"]:
            return f"kept: used since the scan (idle {round(idle, 1)}h)"
        try:
            used, refs = S.in_use_paths(), S.service_refs()
        except S.ProbeError as e:               # a failed probe keeps everything
            return f"kept: liveness probe failed: {e}"
        ok, why = deletable(path, used, refs)
        if not ok:
            return f"kept: {why}"
        done, msg = remove_copy(path)
        return "removed" if done else f"remove failed: {msg}"
    finally:
        if lk:
            lk.close()


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
    deleting = bool(apply and deletion_enabled(cfg))
    for r in rows:
        if r["reap"]:
            r["min_idle_hours"] = cfg["max_age_hours"] if r["idle_hours"] >= cfg["max_age_hours"] else 1
    for r in rows:
        if not r["reap"]:
            r["action"] = "keep"
        elif not deleting:
            r["action"] = "would-remove (report-only)"
        else:
            r["action"] = _reap_one(r, now)
    res = {"mode": "delete" if deleting else "report-only", "delete_enabled": deletion_enabled(cfg),
           "total_gb": round(total / GB, 2), "cap_gb": cfg["max_total_gb"], "max_age_hours": cfg["max_age_hours"],
           "size_unknown": sum(not r["size_known"] for r in rows), "copies": rows, "ts": int(now)}
    if apply and not deletion_enabled(cfg):
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
            tail = ("The janitor removes the ones that are verified recoverable (clean, pushed, not in use)."
                    if deletion_enabled(load_config()) else
                    "Cleanup is report-only until the owner sets \"reaper_delete_enabled\": true in "
                    "~/.agent-harness/state/copy-hygiene.json; removing them needs the owner's OK.")
            msg = (f"Test copies: {n} idle copies hold {gb:.1f} GB (all copies {rep.get('total_gb')} GB, cap "
                   f"{rep.get('cap_gb')} GB). Reuse one copy per PR (`copy_hygiene.py acquire`); "
                   f"`copy_hygiene.py reap` lists them. {tail}")
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
    a = sub.add_parser("acquire"); a.add_argument("--repo", default=""); a.add_argument("--url", default="")
    a.add_argument("--key", required=True); a.add_argument("--ref", default="HEAD")
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
        res = acquire(args.repo, args.key, args.ref, url=args.url)
        print(json.dumps(res))
        if not res.get("ok"):
            sys.stderr.write("acquire refused: %s\n" % res.get("error", ""))
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
