"""ahc daemon-owned clones (GoodQA goodqa#16034 AC-3, NEG-3, spec D4; hardened for goodqa#16049 PR 258 v3).

The daemon never runs git inside an owner's checkout. An owner-controlled `.git/config` (core.fsmonitor,
core.hooksPath, filters, sshCommand) or a hook would run with the daemon's authority. Instead the daemon keeps one
full, non-shallow clone per repo under its own root (D4, kept by the spec owner's and main's ruling on PR 258 v3).

A reused clone carries state from earlier reviews, so before every use that state is shown to be unable to carry
behaviour:
  * The whole `.git` tree is walked without following links, bounded by MAX_GIT_ENTRIES and MAX_GIT_DEPTH, against
    an allowlist: HEAD, config, packed-refs, index, FETCH_HEAD, ORIG_HEAD, and objects/ and refs/ with their usual
    names. Every entry must be a directory or regular file owned by this uid, and no directory may be group- or
    other-writable. Anything else quarantines the clone: hooks/ with any content, info/, worktrees/, modules/,
    logs/, objects/info/alternates, a symlink anywhere (PR 258 v3 F1: `.git/config.ahc-tmp`), a foreign owner, or
    a tree past the bounds. A quarantined clone is renamed into rejected/ and never repaired in place. Then a fresh
    clone is made into a new directory that ahc creates exclusively (ahc_fs.make_fresh_dir), never an existing one.
  * The local config is rewritten from scratch every time (origin URL and fetch refspec only) through ahc_fs. It is
    never merged into the old file, and it is never written through a link.
  * Every git command runs with GIT_CONFIG_NOSYSTEM=1, GIT_CONFIG_GLOBAL=/dev/null and GIT_TERMINAL_PROMPT=0, and
    under umask 077. Its command line carries `-c core.hooksPath=/dev/null -c core.fsmonitor=false`, which override
    any repo config. Transports are https only: `protocol.allow=never` plus `protocol.https.allow=always`.
    `allow_file` adds the local file transport for tests with local fixture remotes.
  * Clones use an empty template (`--template=`), so git itself creates no hooks/, info/ or description.

What remains (L10): while git runs, a process with this uid could plant into the clone. The root chain is 0700 and
owned by this uid, which ahc_core.claim_root enforces at every start, so no other user can.
Stdlib only; every child is an argv list with a timeout.
"""
from __future__ import annotations

import os
import re
import stat
import sys
import time
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ahc_core  # noqa: E402
import ahc_fs as fs  # noqa: E402

SAFE = ["-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false",
        "-c", "core.logAllRefUpdates=false", "-c", "protocol.allow=never", "-c", "protocol.https.allow=always",
        "-c", "protocol.ext.allow=never", "-c", "advice.detachedHead=false"]
FILE_TRANSPORT = ["-c", "protocol.file.allow=always"]
GIT_ENV = {"GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull, "GIT_TERMINAL_PROMPT": "0"}
SLUG = re.compile(r"^([A-Za-z0-9_.-]{1,100})/([A-Za-z0-9_.-]{1,100})$")
HEAD_RE = re.compile(r"^[0-9a-f]{40}$")
GIT_TIMEOUT = 900
MAX_GIT_ENTRIES = 200_000      # a fresh clone of a large repo is far below this once objects are packed
MAX_GIT_DEPTH = 12             # refs/remotes/origin/<branch with slashes> is the deepest legitimate path
GIT_TOP = {"HEAD": "file", "config": "file", "packed-refs": "file", "index": "file", "FETCH_HEAD": "file",
           "ORIG_HEAD": "file", "objects": "dir", "refs": "dir"}
OBJECT_FILE = re.compile(r"^[0-9a-f]{38,62}$")
OBJECT_DIR = re.compile(r"^[0-9a-f]{2}$")
PACK_FILE = re.compile(r"^(pack-[0-9a-f]{40,64}\.(pack|idx|rev|keep|mtimes|bitmap|promisor)|multi-pack-index)$")
OBJECT_INFO = {"packs", "commit-graph"}
REF_NAME = re.compile(r"^[A-Za-z0-9_.@+-][A-Za-z0-9_.@+/-]*$")
_lstat = os.lstat              # a seam for the foreign-owner test (no test can chown without root)


class CloneError(RuntimeError):
    pass


def _git(args, cwd=None, env=None, timeout=GIT_TIMEOUT, check=True, allow_file=False):
    """One git child in AC-13's git form: the resolved absolute git, SAFE, and the form's minimal environment
    (goodqa#16049 slice 1 (b) replaces the merge of the daemon's whole environment; `env` is accepted for old
    callers and ignored). Under an active launch policy its resolved git and env are used."""
    import ahc_guard  # noqa: PLC0415
    policy = ahc_guard.active()
    if policy is not None and "git" in policy.exe:
        git, genv = policy.exe["git"], policy.env("git")
    else:
        home = str(Path.home())
        dirs = ahc_guard.trusted_dirs(home)
        git, genv = ahc_guard.resolve("git", dirs) or "git", ahc_guard.form_env("git", dirs, home)
    argv = [git, *SAFE, *(FILE_TRANSPORT if allow_file else []), *args]
    rc, out, err = ahc_core.run_argv(argv, timeout, cwd=cwd, env=genv)
    if check and rc != 0:
        raise CloneError(f"git {args[0]} failed (exit {rc}): {err.strip()[-300:]}")
    return SimpleNamespace(returncode=rc, stdout=out, stderr=err)


def canonical_config_text(url):
    """The only local config the daemon's clone may carry. It is written whole every time, never combined with
    the old file."""
    return ("[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n\tlogallrefupdates = false\n"
            "\thooksPath = /dev/null\n\tfsmonitor = false\n\tuntrackedCache = false\n"
            f"[remote \"origin\"]\n\turl = {url}\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n")


def _canonical_config(ahc_root, path, url):
    fs.write_file(ahc_root, Path(path) / ".git" / "config", canonical_config_text(url))


def clone_dir(root, repo):
    match = SLUG.match(repo or "")
    if not match or match.group(1) in (".", "..") or match.group(2) in (".", ".."):
        raise CloneError("repo must be owner/name")
    return Path(root) / f"{match.group(1)}__{match.group(2)}"


def _allowed(rel, is_dir):
    """Whether `rel` (the parts of a path inside .git) is an entry git itself keeps in a daemon clone."""
    top = rel[0]
    if len(rel) == 1:
        return GIT_TOP.get(top) == ("dir" if is_dir else "file")
    if top == "refs":
        return all(REF_NAME.match(part) and part not in (".", "..") for part in rel[1:])
    if top != "objects":
        return False
    second = rel[1]
    if len(rel) == 2:
        return is_dir and (bool(OBJECT_DIR.match(second)) or second in ("pack", "info"))
    if len(rel) == 3:
        if second == "pack":
            return not is_dir and bool(PACK_FILE.match(rel[2]))
        if second == "info":
            return not is_dir and rel[2] in OBJECT_INFO          # never alternates or http-alternates
        return not is_dir and bool(OBJECT_DIR.match(second)) and bool(OBJECT_FILE.match(rel[2]))
    return False


def git_dir_problem(git_dir, max_entries=None, max_depth=None):
    """Why the daemon clone's .git cannot be reused, or None. Walks without following any link, and stops at the
    first problem or at a bound (fail closed: past a bound the clone is not reused)."""
    max_entries = MAX_GIT_ENTRIES if max_entries is None else max_entries
    max_depth = MAX_GIT_DEPTH if max_depth is None else max_depth
    uid = os.geteuid()
    count = 0
    stack = [(Path(git_dir), ())]
    while stack:
        directory, rel_dir = stack.pop()
        try:
            names = sorted(os.listdir(str(directory)))
        except OSError as error:
            return "%s cannot be listed (%s)" % ("/".join(rel_dir) or ".git", type(error).__name__)
        for name in names:
            count += 1
            if count > max_entries:
                return "more than %d entries in .git" % max_entries
            rel = rel_dir + (name,)
            where = "/".join(rel)
            if len(rel) > max_depth:
                return "%s is deeper than %d levels" % (where, max_depth)
            try:
                info = _lstat(str(directory / name))
            except OSError as error:
                return "%s cannot be checked (%s)" % (where, type(error).__name__)
            if stat.S_ISLNK(info.st_mode):
                return "%s is a symlink" % where
            is_dir = stat.S_ISDIR(info.st_mode)
            if not is_dir and not stat.S_ISREG(info.st_mode):
                return "%s is a special file" % where
            if info.st_uid != uid:
                return "%s is owned by uid %d" % (where, info.st_uid)
            if is_dir and stat.S_IMODE(info.st_mode) & (stat.S_IWGRP | stat.S_IWOTH):
                return "%s is writable by group or others" % where
            if not _allowed(rel, is_dir):
                return "%s is not an entry git keeps in a daemon clone" % where
            if is_dir:
                stack.append((directory / name, rel))
    return None


def _quarantine(ahc_root, path, reason):
    """Move a clone that cannot be reused into rejected/ under a unique name. It is renamed, never repaired in
    place, never deleted and never followed."""
    target = Path(ahc_root) / "rejected" / ("clone-%s.%d.%d" % (path.name, time.time_ns(), os.getpid()))
    fs.make_dirs(ahc_root, target.parent)
    fs.rename(ahc_root, path, target)
    fs.write_file(ahc_root, target.with_name(target.name + ".reason"), reason + "\n")
    return target


def prepare(root, repo, url, head, base, env=None, allow_file=False):
    """Return the path of the daemon-owned clone checked out at `head` (detached, clean, full history).

    `root` is the clones directory, <ahc root>/clones. Every write ahc itself makes goes through ahc_fs from the
    ahc root. Raises CloneError."""
    if not (HEAD_RE.match(head or "") and HEAD_RE.match(base or "")):
        raise CloneError("head and base must be full SHAs")
    if "\n" in url or url.startswith("-"):
        raise CloneError("bad clone URL")
    clones = Path(root)
    ahc_root = clones.parent
    path = clone_dir(clones, repo)
    old_umask = os.umask(0o077)
    try:
        try:
            fs.make_dirs(ahc_root, clones)
            if os.path.lexists(str(path)):
                with fs.directory(ahc_root, path):          # the clone directory itself: ours, 0700, not a link
                    pass
                git_dir = path / ".git"
                problem = git_dir_problem(git_dir) if os.path.lexists(str(git_dir)) else "the clone has no .git"
                if not problem and not stat.S_ISDIR(os.lstat(str(git_dir)).st_mode):
                    problem = ".git is not a directory"
                if problem:
                    _quarantine(ahc_root, path, "ahc clone quarantined before reuse: " + problem)
            if not os.path.lexists(str(path)):
                fs.make_fresh_dir(ahc_root, path)               # exclusive: never an existing directory
                _git(["clone", "--quiet", "--no-checkout", "--template=", "--", url, str(path)], cwd=str(clones),
                     env=env, allow_file=allow_file)
            _canonical_config(ahc_root, path, url)
        except (fs.UnsafePath, FileExistsError) as error:
            raise CloneError("clone path is not ahc's own: %s" % error) from None
        run = dict(cwd=path, env=env, allow_file=allow_file)
        _git(["fetch", "--quiet", "--no-tags", "origin", "+refs/heads/*:refs/remotes/origin/*"], **run)
        for sha in (head, base):
            if _git(["cat-file", "-e", sha + "^{commit}"], check=False, **run).returncode != 0:
                # GitHub serves PR heads by SHA even from forks; a plain branch fetch may not include them
                _git(["fetch", "--quiet", "--no-tags", "origin", sha], check=False, **run)
            if _git(["cat-file", "-e", sha + "^{commit}"], check=False, **run).returncode != 0:
                raise CloneError(f"commit {sha[:12]} is not available from the remote")
        _git(["checkout", "--quiet", "--force", "--detach", head], **run)
        _git(["clean", "-ffdxq"], **run)
        actual = _git(["rev-parse", "HEAD"], **run).stdout.strip()
        shallow = _git(["rev-parse", "--is-shallow-repository"], **run).stdout.strip()
    finally:
        os.umask(old_umask)
    if actual != head or shallow != "false":
        raise CloneError("clone is not at the exact head or is shallow")
    return str(path)
