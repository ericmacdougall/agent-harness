#!/usr/bin/env python3
"""Read-only checkout and work-dir inventory (harness stream D, goodqa#16947).

Writes nothing. Never fetches, never prunes, never changes a ref or a file.
Prints TSV rows to stdout; a per-row problem goes in the note column.

The checkouts it reads are agent-writable, so git runs with core.fsmonitor and core.hooksPath turned off, the
untracked cache off, no optional locks (`git status` never rewrites an index), and without the variables that
redirect a repository or inject config. Remote URLs are printed without userinfo (no token or password).

Who runs it: main or the user, from a checkout of origin/main. An isolated agent may not (its git commands are
confined to its own worktree, and this tool must not become the way around that).

Usage:
  python3 -I scripts/checkout_inventory.py repos <path-or-glob> [...]
      each main checkout found (deduplicated by git common dir) and all its linked worktrees
  python3 -I scripts/checkout_inventory.py workdirs <dir>
      one row per child directory (for example ~/.agent-harness/work session dirs)

repos columns:
  repo kind path branch head exists locked prunable dirty unpushed merged_main upstream
  last_touched_utc size_mb note
  note       on the main row also: origin=<url without userinfo>; fetched=<FETCH_HEAD time or never>;
             stashes=N when the repository has stashes (shared by all its worktrees)
  dirty      lines of `git status --porcelain` (tracked changes and untracked files, not ignored)
  unpushed   commits reachable from HEAD and from no remote-tracking ref, as last fetched
  merged_main  yes when HEAD is an ancestor of origin/main (or origin/master); a squash merge shows no
  The remote-tracking refs are whatever the last fetch left: this tool does not fetch.

workdirs columns:
  name size_mb last_write_utc git_dirs node_modules venvs build_dirs log_files
"""
import glob
import os
import subprocess
import sys
import time

_REDIRECT = {"GIT_DIR", "GIT_COMMON_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY",
             "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_NAMESPACE", "GIT_CONFIG", "GIT_CONFIG_COUNT",
             "GIT_CONFIG_PARAMETERS", "GIT_PREFIX", "GIT_IMPLICIT_WORK_TREE", "GIT_QUARANTINE_PATH"}
GIT_ENV = {k: v for k, v in os.environ.items() if k not in _REDIRECT and not k.startswith("GIT_CONFIG_")}
GIT_ENV.update(GIT_OPTIONAL_LOCKS="0", GIT_TERMINAL_PROMPT="0", LC_ALL="C")
# Checkouts are agent-writable: never let their config start a program (fsmonitor, hooks).
GIT_FLAGS = ["-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", "-c", "core.untrackedCache=false"]
BUILD_NAMES = {"dist", "build", "target", ".next", ".turbo", ".gradle", "out", ".pytest_cache",
               "__pycache__"}
VENV_NAMES = {".venv", "venv", ".tox"}
LOG_SUFFIXES = (".log", ".jsonl", ".wal")


def git(cwd, *args, timeout=120):
    try:
        p = subprocess.run(["git", *GIT_FLAGS, "-C", cwd, *args], capture_output=True, text=True,
                           env=GIT_ENV, timeout=timeout)
        return p.returncode, p.stdout, p.stderr.strip()
    except Exception as e:  # timeout, missing git
        return 99, "", str(e)


def redact_url(url):
    """Drop any userinfo (a token or password) from a remote URL before it is printed."""
    if "://" in url:
        scheme, rest = url.split("://", 1)
        host, sep, tail = rest.partition("/")
        if "@" in host:
            host = host.rsplit("@", 1)[1]
        return scheme + "://" + host + sep + tail
    return url


def size_mb(path):
    try:
        p = subprocess.run(["du", "-sk", path], capture_output=True, text=True, timeout=1800)
        return str(int(p.stdout.split()[0]) // 1024)
    except Exception:
        return "?"


def utc(ts):
    return time.strftime("%Y-%m-%dT%H:%MZ", time.gmtime(ts)) if ts else "-"


def last_touched(path):
    """Newest mtime among the top-level entries and the worktree's git index, HEAD and reflog."""
    best = 0.0
    try:
        for entry in os.scandir(path):
            try:
                best = max(best, entry.stat(follow_symlinks=False).st_mtime)
            except OSError:
                pass
    except OSError:
        return 0
    rc, out, _ = git(path, "rev-parse", "--git-dir")
    if rc == 0:
        gd = out.strip()
        if not os.path.isabs(gd):
            gd = os.path.join(path, gd)
        for f in ("index", "HEAD", "logs/HEAD"):
            try:
                best = max(best, os.stat(os.path.join(gd, f)).st_mtime)
            except OSError:
                pass
    return best


def main_ref(cwd):
    for ref in ("refs/remotes/origin/main", "refs/remotes/origin/master"):
        rc, _, _ = git(cwd, "rev-parse", "-q", "--verify", ref)
        if rc == 0:
            return ref
    return None


def worktrees(main):
    rc, out, err = git(main, "worktree", "list", "--porcelain")
    if rc != 0:
        return None, err
    rows, cur = [], {}
    for line in out.splitlines() + [""]:
        if not line:
            if cur:
                rows.append(cur)
            cur = {}
            continue
        k, _, v = line.partition(" ")
        cur[k] = v if v else True
    return rows, ""


def repo_rows(main):
    wts, err = worktrees(main)
    if wts is None:
        print("\t".join([main, "error", main] + ["-"] * 11 + ["worktree list failed: " + err[:120]]))
        return
    mref = main_ref(main)
    for i, wt in enumerate(wts):
        path = str(wt.get("worktree", "?"))
        kind = "main" if i == 0 else "linked"
        branch = str(wt.get("branch", "(detached)")).replace("refs/heads/", "")
        head = str(wt.get("HEAD", "-"))[:10]
        exists = os.path.isdir(path)
        note = []
        dirty = unpushed = merged = "?"
        upstream = "-"
        if exists:
            rc, out, e = git(path, "status", "--porcelain", "--untracked-files=normal")
            if rc == 0:
                dirty = str(len(out.splitlines()))
            else:
                note.append("status failed: " + e[:80])
            rc, out, _ = git(path, "rev-list", "--count", "HEAD", "--not", "--remotes")
            if rc == 0:
                unpushed = out.strip()
            if mref:
                rc, _, _ = git(path, "merge-base", "--is-ancestor", "HEAD", mref)
                merged = {0: "yes", 1: "no"}.get(rc, "?")
            else:
                merged = "no-origin-main"
            rc, out, _ = git(path, "rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{upstream}")
            if rc == 0:
                upstream = out.strip()
            rc, out, _ = git(path, "stash", "list")
            if rc == 0 and out.strip() and kind == "main":
                note.append("stashes=%d (shared by all worktrees)" % len(out.splitlines()))
        if kind == "main":
            rc, out, _ = git(main, "remote", "get-url", "origin")
            note.append("origin=" + (redact_url(out.strip()) if rc == 0 else "none"))
            gd = os.path.join(main, ".git")
            try:
                note.append("fetched=" + utc(os.stat(os.path.join(gd, "FETCH_HEAD")).st_mtime))
            except OSError:
                note.append("fetched=never")
        print("\t".join([main, kind, path, branch, head, "yes" if exists else "no",
                         "yes" if "locked" in wt else "no", "yes" if "prunable" in wt else "no",
                         dirty, unpushed, merged, upstream,
                         utc(last_touched(path)) if exists else "-",
                         size_mb(path) if exists else "0", "; ".join(note)]))
        sys.stdout.flush()


def walk_kinds(root):
    counts = {"git": 0, "node_modules": 0, "venv": 0, "build": 0, "log": 0}
    newest = 0.0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        keep = []
        for d in dirnames:
            if d == ".git":
                counts["git"] += 1
            elif d == "node_modules":
                counts["node_modules"] += 1
            elif d in VENV_NAMES:
                counts["venv"] += 1
            elif d in BUILD_NAMES:
                counts["build"] += 1
            else:
                keep.append(d)
        dirnames[:] = keep  # counted heavy dirs are not descended
        for f in filenames:
            if f.endswith(LOG_SUFFIXES):
                counts["log"] += 1
            try:
                newest = max(newest, os.lstat(os.path.join(dirpath, f)).st_mtime)
            except OSError:
                pass
    return counts, newest


def workdir_rows(base):
    for entry in sorted(os.scandir(base), key=lambda e: e.name):
        if not entry.is_dir(follow_symlinks=False):
            continue
        counts, newest = walk_kinds(entry.path)
        print("\t".join([entry.name, size_mb(entry.path), utc(newest), str(counts["git"]),
                         str(counts["node_modules"]), str(counts["venv"]), str(counts["build"]),
                         str(counts["log"])]))
        sys.stdout.flush()


def main():
    if len(sys.argv) < 3 or sys.argv[1] not in ("repos", "workdirs"):
        print(__doc__, file=sys.stderr)
        return 2
    if sys.argv[1] == "workdirs":
        workdir_rows(os.path.expanduser(sys.argv[2]))
        return 0
    seen = set()
    for pat in sys.argv[2:]:
        for p in sorted(glob.glob(os.path.expanduser(pat))):
            if not os.path.isdir(p) or not os.path.exists(os.path.join(p, ".git")):
                continue
            rc, out, _ = git(p, "rev-parse", "--git-common-dir")
            common = out.strip() if rc == 0 else ".git"
            if not os.path.isabs(common):
                common = os.path.join(p, common)
            common = os.path.realpath(common)
            if common in seen:
                continue
            seen.add(common)
            # list from the main checkout of that common dir
            repo_rows(os.path.dirname(common) if common.endswith("/.git") else p)
    return 0


if __name__ == "__main__":
    sys.exit(main())
