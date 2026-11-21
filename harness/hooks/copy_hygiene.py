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
                `ssh host '...'` is not checked by any hook (the remote host's hook only sees agent sessions running
                there). `rsync --delete` into a service directory and `git clean` are not treated as deletes.
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
    "protected_paths": [],
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
    prot = out.get("protected_paths")
    if isinstance(prot, str):
        prot = [prot]
    out["protected_paths"] = [os.path.expanduser(str(x)) for x in prot if str(x).strip()] if isinstance(prot, list) else []
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


def resolved_note(ref: str, source: "str | None", sha: str) -> dict:
    """{} or the warning when a branch name resolved to the remote's commit although the source checkout's branch of
    the same name is somewhere else (it may be ahead: its commits are NOT in the copy)."""
    if not source or not ref or ref == "HEAD" or re.fullmatch(r"[0-9a-f]{40}", ref):
        return {}
    rc, out, _ = S.git(source, "rev-parse", "--verify", "--quiet", ref + "^{commit}")
    local = out.strip()
    if rc != 0 or not local or local == sha:
        return {}
    return {"resolved_from": "remote", "source_commit": local,
            "warning": "%r resolved to the remote's commit %s, but your checkout's %r is at %s; push it or pass the "
                       "commit id to use yours" % (ref, sha[:12], ref, local[:12])}


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
            return {"ok": True, "path": path, "commit": sha, "reused": True, "moved": cur != sha,
                    **resolved_note(ref, source, sha)}
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
        return {"ok": True, "path": path, "commit": sha, "reused": False, "moved": True,
                **resolved_note(ref, source, sha)}


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


def protected_scan(cfg: "dict | None" = None, fresh: bool = False) -> "tuple[dict, int]":
    """({key: (path, where it is named)}, unreadable-unit count). Cached for 60 s keyed on the directory mtimes;
    fresh=True ignores the cache (every removal uses it: the cache can be a minute old)."""
    cfg = normalize(cfg) if cfg is not None else load_config()
    _f, _e, sig = _scan_files(_unit_dirs())
    cache = os.path.join(state_dir(), "copy-hygiene-protected.json")
    key = hashlib.sha256(json.dumps([sig, os.environ.get("HARNESS_COPY_HYGIENE_UNIT_DIRS"), home()]).encode()).hexdigest()
    prot, errors = None, 0
    try:
        with open(cache) as f:
            c = json.load(f)
        if not fresh and c.get("key") == key and time.time() - float(c.get("ts", 0)) < PROTECTED_CACHE_TTL_S:
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


def _expand_braces(s: str) -> "list[str]":
    m = re.search(r"\{([^{}]*,[^{}]*)\}", s)
    if not m:
        return [s]
    out = []
    for alt in m.group(1).split(","):
        out.extend(_expand_braces(s[:m.start()] + alt + s[m.end():]))
    return out[:256]


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
    if vals and op.startswith("%") and "/" in op:    # ${D%/*}: usually D's parent; check D and its parent
        return [x for v in vals for x in (v, os.path.dirname(v.rstrip("/")) or "/")]
    return None                                     # ${D%/*}, ${D:+x}, ${D/a/b}, ${D:0:3}, ${D#..}: unknown


def _expand_vars(s: str, cwd: "str | None", vars_: "dict | None" = None) -> "list[str]":
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
    `( ... )` subshells, `$( ... )` / backtick bodies and `bash -c '<line>'` bodies are bracketed by _PUSH/_POP so
    a `cd` inside them does not leak out."""
    out = []
    sep = ";"
    for seg, nsep, bodies in _split_line(cmd):
        cur_sep, sep = sep, nsep
        seg = seg.strip()
        if seg:
            for body in bodies:
                out.append(([_PUSH], ";"))
                out.extend(_cmd_lines(body))
                out.append(([_POP], ";"))
            seg = _strip_comment(seg)
            try:
                words = shlex.split(seg)                # not comments=True: it cuts `${f##*/}` mid-word
            except ValueError:
                words = [w.strip("'\"") for w in seg.split()]
            words = _unwrap(words)
            if words and os.path.basename(words[0]) in SHELLS:
                j = next((i for i, w in enumerate(words[1:], 1) if re.match(r"^-[a-zA-Z]*c[a-zA-Z]*$", w)), 0)
                if j and j + 1 < len(words):
                    out.append(([_PUSH], cur_sep))
                    out.extend(_cmd_lines(words[j + 1]))
                    out.append(([_POP], ";"))
                    words = []
            if words:
                out.append((words, cur_sep))
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
    """[(segment, separator after it, substitution bodies)], splitting on ; & && || | newline ( ) outside quotes. `$( ... )` and
    backtick substitutions stay inside their word as SUBST (so `rm -rf $(pwd)/x` and `D=$(mktemp -d)` keep their
    shape); their bodies are returned for separate analysis."""
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
                   "nice": {"-n"}, "ionice": {"-c", "-n", "-p"}, "timeout": {"-s", "-k", "--signal", "--kill-after"},
                   "stdbuf": {"-i", "-o", "-e"}, "doas": {"-u", "-C"}}
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
            if "$" in r:
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
                if recursive:
                    empty = z.replace("\0", "")
                    if empty.strip("/"):
                        out.extend(_resolve(empty, [b], None))
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


def _find_deletes(words: list) -> bool:
    if "-delete" in words:
        return True
    for i, w in enumerate(words):
        if w in ("-exec", "-execdir", "-ok", "-okdir") and i + 1 < len(words):
            rest = _unwrap(words[i + 1:])
            if rest and os.path.basename(rest[0]) in FIND_EXEC_DELETERS:
                return True
            if rest and os.path.basename(rest[0]) in SHELLS:
                j = next((k for k, x in enumerate(rest[1:], 1) if re.match(r"^-[a-zA-Z]*c[a-zA-Z]*$", x)), 0)
                body = rest[j + 1] if j and j + 1 < len(rest) else ""
                if any(t and os.path.basename(t[0]) in FIND_EXEC_DELETERS for t, _s in _cmd_lines(body)):
                    return True
    return False


def _find_selective(words: list) -> "tuple[bool, bool]":
    """(any selector, a positive name selector). `-name '*'` is not a name selector; a selector right after `!` /
    `-not`, or inside a negated `\( ... \)` group, is negative and does not narrow what is deleted."""
    sel = name_sel = False
    neg_depth, depth = [], 0
    for i, w in enumerate(words):
        prev_neg = i > 0 and words[i - 1] in ("!", "-not")
        if w == "(":
            depth += 1
            if prev_neg:
                neg_depth.append(depth)
        elif w == ")":
            if neg_depth and neg_depth[-1] == depth:
                neg_depth.pop()
            depth -= 1
        elif w in FIND_SELECTORS:
            sel = True
            if (w in FIND_NAME_SELECTORS and not prev_neg and not neg_depth
                    and not (i + 1 < len(words) and _EMPTYING.match(words[i + 1]))):
                name_sel = True
    return sel, name_sel

def delete_targets_line(cmd: str, cwd: str) -> "list[tuple[str, bool, str]]":
    """[(path, known, mode)] a command line would delete or move away.
    Tracks `cd` / `pushd` (an unresolvable one, `cd -` or `popd` makes the directory unknown; after a cd that is not
    joined by `&&` both the old and new directory are checked, since the cd may have failed), `( )` and `bash -c`
    scopes, same-line `NAME=value` and `for x in ...` lists, and `find ... | ... | xargs rm` through a pipeline.
    mode "below": a find with name filters deletes only some entries, so it is refused only when a protected path
    lies strictly inside its root; "" means the path itself (and everything inside it) goes."""
    bases = [cwd if str(cwd).startswith("/") else None]
    stack, pending_old, vars_ = [], [], {}
    out, find_ctx = [], None
    for words, sep in _cmd_lines(cmd):
        if words == [_PUSH]:
            stack.append((list(bases), list(pending_old), dict(vars_), find_ctx))
            continue
        if words == [_POP]:
            if stack:
                bases, pending_old, vars_, find_ctx = stack.pop()
            continue
        if sep != "&&" and pending_old:
            bases = list(dict.fromkeys(bases + pending_old))
            pending_old = []
        if sep != "|":
            find_ctx = None
        words = [x for w in words for x in _expand_braces(w)]
        name = os.path.basename(words[0])
        if name in ("export", "local", "declare", "readonly", "typeset") and len(words) > 1:
            words = [w for w in words[1:] if not w.startswith("-")] or words
        if words and all(ASSIGN.match(w) for w in words):
            for w in words:
                k, v = w.split("=", 1)
                vals = [x for b in bases for x in _expand_vars(v, b, vars_)]
                vars_[k] = [os.path.expanduser(x) for x in vals]
            continue
        if name == "for" and len(words) >= 3 and words[2] == "in":
            vars_[words[1]] = [os.path.expanduser(x) for w in words[3:] for x in _expand_vars(w, bases[0], vars_)]
            continue
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
            recursive = name in ("trash", "trash-put") or bool(flags & {"r", "R", "--recursive"})
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
            find_ctx = (roots, _find_selective(words), list(bases))
            if not _find_deletes(words):
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
            roots, (sel, name_sel), fb = find_ctx
            for r in roots:
                fmode = "below" if name_sel else ("root-selective" if sel else "")
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
        if not S.within_allowed(root, strictly_inside=False):
            alert("root-ignored", {"root": root, "why": "outside ~/.agent-harness/{work,checkouts,test-copies}"})
            continue
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


def safe_remove(path: str, kind: str = "checkout", cfg: "dict | None" = None) -> "tuple[bool, str]":
    """THE removal choke point (copies, session folders, mirrors; PR #284's rule for every deletion). Immediately before
    any removal it re-reads the service units WITHOUT the cache and refuses a path a service uses (or contains one),
    a configured protect_names match, and anything it cannot check (fails closed). kind: "checkout" (git worktree
    remove, or a clone), "tree" (a mirror or other folder), "empty-tree" (only empty folders, removed bottom-up with
    rmdir; stops at the first one that is not empty, so a file written meanwhile survives)."""
    try:
        cfg = normalize(cfg) if cfg is not None else load_config()
        prot, errors = protected_scan(cfg, fresh=True)
        if errors:
            return False, "could not read service units"
        hit = protecting(path, prot)
        if hit:
            return False, f"protected: a service uses {hit[0]}"
        why = S.protected_name(path, cfg)
        if why:
            return False, why
    except Exception as e:      # noqa: BLE001 -- cannot tell what services use: delete nothing
        return False, f"protection check failed: {type(e).__name__}"
    if kind == "empty-tree":
        if S.mounts_under(path):
            return False, "mount point inside"
        try:
            for dp, _dn, fn in os.walk(path, topdown=False):
                if fn:
                    return False, "a file is present: " + os.path.join(dp, fn[0])[:120]
                os.rmdir(dp)                     # ENOTEMPTY (or a symlink) stops here
        except OSError as e:
            return False, "not empty (%s)" % type(e).__name__
        return True, "removed"
    ok, msg = S.remove_checkout(path) if kind == "checkout" else S.remove_tree(path)
    return ok, (msg or "removed")


def remove_copy(path: str, cfg: "dict | None" = None) -> "tuple[bool, str]":
    """Remove one checkout through safe_remove."""
    return safe_remove(path, "checkout", cfg)


def _reap_one(r: dict, now: float, cfg: "dict | None" = None) -> str:
    """Decide on one copy with the key lock HELD and nothing carried over from the scan: an acquire that only touched the
    index (the worktree's HEAD lives in the mirror) must stop the removal, so the idle time is re-read from the index
    and the process, service and protected-path probes are run again right before the removal."""
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
        try:
            prot, errors = protected_scan(cfg)
        except Exception:      # noqa: BLE001
            prot, errors = {}, 1
        if errors:
            return "kept: could not read service units"
        hit = protecting(path, prot)
        if hit:
            return f"kept: protected, a service uses {hit[0]} ({hit[1]})"
        why = S.protected_name(path, normalize(cfg) if cfg is not None else load_config())
        if why:
            return f"kept: {why}"
        ok, why = deletable(path, used, refs)
        if not ok:
            return f"kept: {why}"
        done, msg = remove_copy(path, cfg)
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
    try:
        prot, errors = protected_scan(cfg)
    except Exception:          # noqa: BLE001 -- cannot tell what services use: delete nothing
        prot, errors = None, 1
    for r in rows:
        if r["reap"]:
            r["min_idle_hours"] = cfg["max_age_hours"] if r["idle_hours"] >= cfg["max_age_hours"] else 1
    for r in rows:
        hit = protecting(r["path"], prot) if prot else None
        pn = S.protected_name(r["path"], cfg) if r["reap"] else ""
        if r["reap"] and pn:
            r["reap"] = False
            r["action"] = "kept: " + pn
            continue
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
            r["action"] = _reap_one(r, now, cfg)
    res = {"mode": "delete" if deleting else "report-only", "delete_enabled": deletion_enabled(cfg),
           "total_gb": round(total / GB, 2), "cap_gb": cfg["max_total_gb"], "max_age_hours": cfg["max_age_hours"],
           "size_unknown": sum(not r["size_known"] for r in rows), "copies": rows, "ts": int(now)}
    if os.path.isdir(scratch_root()):           # scratch is reported, never reaped: it may hold a session's work
        sz = dir_size(scratch_root())
        res["scratch_gb"] = round((sz or 0) / GB, 2)
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
    sc = sub.add_parser("scratch"); sc.add_argument("--key", default="")
    pr = sub.add_parser("protected", help="list protected paths, or --check <path> (exit 1 when protected)")
    pr.add_argument("--check", default="")
    args = ap.parse_args(argv)
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
