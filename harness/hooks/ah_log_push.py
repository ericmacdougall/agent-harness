#!/usr/bin/env python3
"""`ah log-push <path>...`: move harness logs into a PRIVATE git repository, then delete the local copy.

    ah log-push --setup <url> [--branch B] [--subdir D] [--max-mb N]   write ~/.agent-harness/log-repo.json
    ah log-push [--dry-run] [--max-mb N] <path>...                     push, verify, delete, audit

For each run: every given file (a directory: every regular file below it) must sit under ~/.claude, ~/.codex or
~/.agent-harness, be at most the size limit (default 95 MB per file, so GitHub's 100 MB push limit is never hit) and
not be a symlink. The files are written as blobs into a cache repository, one commit on top of the remote branch
places them at <subdir>/<path relative to the home>, and the commit is pushed (never forced). Then the branch is
fetched back from the remote and each file's blob id there is compared with the blob id of the local bytes, hashed
again at that moment. Only a file whose bytes match is deleted (by this process, in Python, after the check); a file
that changed while it was pushed (a live WAL) is kept and reported. Empty directories left by a pushed directory are
removed. One row per run goes to ~/.agent-harness/logs/log-push.jsonl.

The repository must be private: a github.com URL is checked with `gh repo view --json visibility` on setup and on
every push (only PRIVATE passes; public, internal or unknown is refused with the reason), and a local path or file://
URL is private by nature. Any other host's visibility cannot be checked, so it is refused. Nothing is redacted and
no file contents are printed. Standard library only (plus the git and gh binaries).
"""
from __future__ import annotations

import argparse
import json
import os
import re
import socket
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path

DEFAULT_MAX_MB = 95
CONFIG_NAME = "log-repo.json"
AUDIT_REL = ("logs", "log-push.jsonl")
GITHUB = re.compile(r"^(?:https://(?:[^/@\s]+@)?github\.com/|git@github\.com:|ssh://git@github\.com/)"
                    r"(?P<owner>[\w.-]+)/(?P<repo>[\w.-]+?)(?:\.git)?/?$")
BRANCH = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,100}$")
SUBDIR = re.compile(r"^[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*$")
ROOTS = (".claude", ".codex", ".agent-harness")


class PushError(Exception):
    def __init__(self, code, message, exit_code=2):
        super().__init__(message)
        self.code, self.exit_code = code, exit_code


def _now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def state(home=None) -> Path:
    return Path(home or Path.home()) / ".agent-harness"


def shown_url(url: str) -> str:
    """The URL without any user:password@ part (never print or log a credential)."""
    return re.sub(r"(?<=://)[^/@\s]+@", "", str(url))


# ---- privacy of the repository --------------------------------------------------------------------------------

def _local_url(url: str):
    if url.startswith("file://"):
        return url[len("file://"):]
    if url.startswith("/") or url.startswith("~"):
        return os.path.expanduser(url)
    return None


def visibility_refusal(url: str, gh_runner=subprocess.run) -> str | None:
    """None when the repository is private; else why it is refused."""
    if not isinstance(url, str) or not url or "\x00" in url or url.startswith("-"):
        return "the repository URL is not valid"
    local = _local_url(url)
    if local is not None:
        return None if os.path.isdir(local) else "the local repository %s does not exist" % local
    m = GITHUB.match(url)
    if not m:
        return ("the visibility of a repository on this host cannot be checked, so it is refused; use a private "
                "github.com repository or a local path")
    name = "%s/%s" % (m.group("owner"), m.group("repo"))
    if name.lower().endswith("/agent-harness"):
        return "the agent-harness repository is public; logs never go there"
    try:
        done = gh_runner(["gh", "repo", "view", name, "--json", "visibility", "-q", ".visibility"],
                         capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError) as error:
        return "visibility unknown (gh could not run: %s), so it is refused" % type(error).__name__
    seen = (done.stdout or "").strip().upper()
    if done.returncode != 0 or not seen:
        return "visibility unknown (gh repo view failed), so it is refused"
    if seen != "PRIVATE":
        return "the repository is %s, not PRIVATE; logs go only to a private repository" % seen.lower()
    return None


# ---- config ---------------------------------------------------------------------------------------------------

def load_config(home=None) -> dict:
    try:
        data = json.loads((state(home) / CONFIG_NAME).read_text())
    except (OSError, ValueError):
        raise PushError("not_configured", "no log repository is set: run `ah log-push --setup <private repo url>`")
    if not isinstance(data, dict) or not isinstance(data.get("url"), str):
        raise PushError("not_configured", "%s is not valid: run `ah log-push --setup <url>` again" % CONFIG_NAME)
    data.setdefault("branch", "main")
    data.setdefault("subdir", "logs/" + _host())
    data.setdefault("max_file_mb", DEFAULT_MAX_MB)
    if not BRANCH.match(str(data["branch"])) or ".." in str(data["branch"]):
        raise PushError("bad_config", "the configured branch is not a plain branch name")
    if not SUBDIR.match(str(data["subdir"])) or ".." in str(data["subdir"]).split("/"):
        raise PushError("bad_config", "the configured subdir is not a plain relative path")
    return data


def _host() -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "-", socket.gethostname().split(".")[0] or "host")[:60]


def setup(url, branch="main", subdir=None, max_mb=DEFAULT_MAX_MB, home=None, gh_runner=subprocess.run) -> dict:
    why = visibility_refusal(url, gh_runner)
    if why:
        raise PushError("not_private", "refused: " + why)
    data = {"url": url, "branch": branch or "main", "subdir": subdir or "logs/" + _host(), "max_file_mb": max_mb}
    if not BRANCH.match(data["branch"]) or not SUBDIR.match(data["subdir"]) or ".." in data["subdir"].split("/"):
        raise PushError("bad_request", "--branch and --subdir must be plain names")
    if not isinstance(max_mb, (int, float)) or not 0 < max_mb <= 2000:
        raise PushError("bad_request", "--max-mb must be between 0 and 2000")
    directory = state(home)
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    tmp = directory / (".%s.%d" % (CONFIG_NAME, os.getpid()))
    tmp.write_text(json.dumps(data, indent=1) + "\n")
    os.chmod(tmp, 0o600)
    os.replace(tmp, directory / CONFIG_NAME)
    return dict(data, url=shown_url(url))


# ---- what to push ---------------------------------------------------------------------------------------------

def collect(paths, home, max_bytes):
    """[(local path, path relative to home)] for every regular file named or below a named directory. Refuses the whole
    run (nothing pushed, nothing deleted) for a path outside the harness roots, a symlink or a file over the limit."""
    home = os.path.realpath(str(home))
    files, too_big = [], []
    for given in paths:
        p = os.path.abspath(os.path.expanduser(given))
        if os.path.islink(p):
            raise PushError("bad_path", "%s is a symlink; give the real path" % given)
        real = os.path.realpath(p)
        rel = os.path.relpath(real, home)
        if rel.startswith("..") or rel.split(os.sep)[0] not in ROOTS or rel in ROOTS:
            raise PushError("bad_path", "%s is not inside ~/.claude, ~/.codex or ~/.agent-harness (and not one of "
                                        "those roots itself); log-push only moves harness logs" % given)
        if rel.split(os.sep)[:2] in ([".agent-harness", "logs"],) and real.endswith("log-push.jsonl"):
            raise PushError("bad_path", "the log-push audit log itself is never pushed away")
        if not os.path.exists(real):
            raise PushError("bad_path", "%s does not exist" % given)
        walk = [real] if os.path.isfile(real) else []
        if os.path.isdir(real):
            for top, dirs, names in os.walk(real):
                dirs.sort()
                for name in sorted(names):
                    walk.append(os.path.join(top, name))
        for f in walk:
            st = os.lstat(f)
            if stat.S_ISLNK(st.st_mode):
                raise PushError("bad_path", "%s contains a symlink (%s); log-push copies regular files only"
                                % (given, os.path.relpath(f, real)))
            if not stat.S_ISREG(st.st_mode):
                continue
            if st.st_size > max_bytes:
                too_big.append((f, st.st_size))
            files.append((f, os.path.relpath(f, home), st.st_mode))
    if too_big:
        listing = ", ".join("%s (%.1f MB)" % (f, size / 1e6) for f, size in too_big[:5])
        raise PushError("too_large", "refused: %d file(s) over the %.0f MB per-file limit, nothing was pushed: %s. "
                                     "Split or compress them, or raise the limit with --max-mb"
                        % (len(too_big), max_bytes / 1e6, listing))
    if not files:
        raise PushError("bad_path", "no regular files to push")
    return files


# ---- git ------------------------------------------------------------------------------------------------------

def _env(extra=None):
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(GIT_TERMINAL_PROMPT="0", LC_ALL="C", GIT_AUTHOR_NAME=os.environ.get("GIT_AUTHOR_NAME", "ah log-push"),
               GIT_AUTHOR_EMAIL=os.environ.get("GIT_AUTHOR_EMAIL", "log-push@localhost"),
               GIT_COMMITTER_NAME=os.environ.get("GIT_COMMITTER_NAME", "ah log-push"),
               GIT_COMMITTER_EMAIL=os.environ.get("GIT_COMMITTER_EMAIL", "log-push@localhost"))
    env.update(extra or {})
    return env


def git(repo, *args, env=None, stdin=None, timeout=600):
    done = subprocess.run(["git", "-c", "core.hooksPath=/dev/null", "-c", "protocol.ext.allow=never", "-C", str(repo),
                           *args], input=stdin, capture_output=True, timeout=timeout, env=_env(env))
    if done.returncode != 0:
        raise PushError("git_failed", "git %s failed: %s" % (args[0], shown_url(done.stderr.decode("utf-8", "replace")
                                                                                  .strip()[:300])), 3)
    return done.stdout.decode("utf-8", "replace")


def _cache(home):
    cache = state(home) / "log-push" / "cache.git"
    if not (cache / "HEAD").exists():
        cache.mkdir(mode=0o700, parents=True, exist_ok=True)
        git(cache, "init", "--bare", "-q")
    return cache


def _remote_tip(cache, url, branch):
    """The remote branch's commit (fetched into the cache), or None when the branch does not exist yet."""
    listing = git(cache, "ls-remote", "--heads", "--", url, "refs/heads/" + branch, timeout=120)
    if not listing.strip():
        return None
    git(cache, "fetch", "-q", "--depth=1", "--", url, "+refs/heads/%s:refs/log-push/tip" % branch, timeout=600)
    return git(cache, "rev-parse", "refs/log-push/tip").strip()


def blob_id(cache, path) -> str:
    return git(cache, "hash-object", "--no-filters", "--", path).strip()


def build_commit(cache, parent, entries, message):
    """A commit on top of `parent` (None: a first commit) adding [(dest path, local path, mode)]."""
    with tempfile.TemporaryDirectory(prefix="log-push-index-") as tmp:
        index = {"GIT_INDEX_FILE": os.path.join(tmp, "index")}
        if parent:
            git(cache, "read-tree", parent, env=index)
        for dest, local, mode in entries:
            sha = git(cache, "hash-object", "-w", "--no-filters", "--", local).strip()
            git(cache, "update-index", "--add", "--cacheinfo",
                "%s,%s,%s" % ("100755" if mode & 0o111 else "100644", sha, dest), env=index)
        tree = git(cache, "write-tree", env=index).strip()
    args = ["commit-tree", tree, "-m", message] + (["-p", parent] if parent else [])
    return git(cache, *args).strip()


def audit(home, row):
    path = state(home).joinpath(*AUDIT_REL)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        os.write(fd, (json.dumps(dict(row, at=_now()), separators=(",", ":")) + "\n").encode())
        os.fsync(fd)
    finally:
        os.close(fd)


def _prune_empty(directories):
    for top in sorted(directories, key=len, reverse=True):
        for current, _dirs, _files in sorted(os.walk(top, topdown=False), key=lambda t: len(t[0]), reverse=True):
            try:
                os.rmdir(current)
            except OSError:
                pass


def push(paths, dry_run=False, max_mb=None, home=None, gh_runner=subprocess.run) -> dict:
    home = Path(home or Path.home())
    cfg = load_config(home)
    limit_mb = float(max_mb if max_mb is not None else cfg.get("max_file_mb") or DEFAULT_MAX_MB)
    files = collect(paths, home, int(limit_mb * 1e6))
    why = visibility_refusal(cfg["url"], gh_runner)
    if why:
        raise PushError("not_private", "refused: " + why)
    entries = [(cfg["subdir"].rstrip("/") + "/" + rel.replace(os.sep, "/"), local, mode) for local, rel, mode in files]
    total = sum(os.path.getsize(local) for _d, local, _m in entries)
    report = {"ok": False, "dry_run": dry_run, "repo": shown_url(cfg["url"]), "branch": cfg["branch"],
              "files": len(entries), "bytes": total, "deleted": 0, "kept": []}
    if dry_run:
        report.update(ok=True, would_push=[d for d, _l, _m in entries[:50]])
        return report
    cache = _cache(home)
    hashes = {local: blob_id(cache, local) for _d, local, _m in entries}
    commit = None
    for attempt in range(2):  # a push that lost a race is rebuilt once on the new tip, never forced
        parent = _remote_tip(cache, cfg["url"], cfg["branch"])
        commit = build_commit(cache, parent, entries, "log-push: %d file(s) from %s" % (len(entries), _host()))
        try:
            git(cache, "push", "-q", "--", cfg["url"], "%s:refs/heads/%s" % (commit, cfg["branch"]), timeout=1800)
            break
        except PushError:
            if attempt:
                raise
    # verify: fetch the branch back and compare each file's blob id there with the local bytes now
    git(cache, "fetch", "-q", "--depth=1", "--", cfg["url"], "+refs/heads/%s:refs/log-push/check" % cfg["branch"],
        timeout=600)
    deleted, kept, pruned = 0, [], set()
    for dest, local, _m in entries:
        try:
            there = git(cache, "rev-parse", "refs/log-push/check:" + dest).strip()
        except PushError:
            there = None
        now = blob_id(cache, local) if os.path.isfile(local) else None
        if there and there == hashes[local] == now:
            os.unlink(local)
            deleted += 1
        else:
            kept.append({"path": local, "why": "changed while it was pushed" if there == hashes[local]
                         else "not found on the remote with the same bytes"})
    for given in paths:
        real = os.path.realpath(os.path.expanduser(given))
        if os.path.isdir(real):
            pruned.add(real)
    _prune_empty(pruned)
    report.update(ok=not kept, commit=commit, deleted=deleted, kept=kept[:50])
    audit(home, {"event": "log-push", "repo": report["repo"], "branch": cfg["branch"], "commit": commit,
                 "files": len(entries), "bytes": total, "deleted": deleted, "kept": len(kept),
                 "paths": [os.path.realpath(os.path.expanduser(p)) for p in paths][:50],
                 "session": os.environ.get("CLAUDE_CODE_SESSION_ID") or os.environ.get("CLAUDE_SESSION_ID") or None})
    return report


def main(argv=None, home=None) -> int:
    parser = argparse.ArgumentParser(prog="ah log-push", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("paths", nargs="*")
    parser.add_argument("--setup", metavar="URL")
    parser.add_argument("--branch")
    parser.add_argument("--subdir")
    parser.add_argument("--max-mb", type=float, dest="max_mb")
    parser.add_argument("--dry-run", action="store_true", dest="dry_run")
    args = parser.parse_args(argv)
    try:
        if args.setup:
            if args.paths:
                raise PushError("bad_request", "--setup takes no paths")
            out = setup(args.setup, args.branch or "main", args.subdir, args.max_mb or DEFAULT_MAX_MB, home=home)
        else:
            if not args.paths:
                raise PushError("bad_request", "give at least one path (or --setup <url>)")
            out = push(args.paths, args.dry_run, args.max_mb, home=home)
    except PushError as error:
        print(json.dumps({"ok": False, "error": error.code, "message": str(error)}))
        return error.exit_code
    print(json.dumps(out, indent=1))
    return 0 if out.get("ok") else 1


if __name__ == "__main__":
    sys.exit(main())
