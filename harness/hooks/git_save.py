#!/usr/bin/env python3
"""Save whatever in one git checkout exists nowhere else, and prove it (docs/lifecycle.md).

`ah reap` deletes a checkout only on the strength of `save()["ok"]`; the Stop hook calls save() after every turn.
The proof is exact: a pushed ref counts only when `git ls-remote` shows that ref with that commit id; a bundle only
when `git bundle verify` passes, it lists every ref with its id and the file sits outside the checkout. Unknown means
keep: a git error, a timeout or any doubt gives ok False with the reason. Nothing here reads command text or blocks a
tool call, and the checkout's index, refs and working tree are never touched (a snapshot only adds objects). A nested
checkout or a submodule is its own checkout: it is skipped here, call save() on it separately.
Nothing saved is ever changed in place without positive evidence that it is this checkout's own copy (the life token
its first save wrote in its git dir is the one recorded, and the commits it named are still here) and never once
`ah reap` began to delete the checkout: otherwise the save gets new names (a new stamp), so the copy of a checkout
that went before, or a proven copy, is never touched. A superproject's git calls never look inside its submodules
(--ignore-submodules=dirty), so no program a submodule's own config names runs.
Network steps run in a scratch repository, so the checkout's own git config (url.insteadOf, core.sshCommand,
credential.helper) never applies to them, and a checkout whose own config names a filter program is kept unread.
Standard library only. Every git call has a timeout, no prompt, no pager, no optional locks and runs no hooks.
"""
from __future__ import annotations

import contextlib
import fnmatch
import hashlib
import ipaddress
import json
import os
import re
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ah_local  # noqa: E402
import ah_log_push  # noqa: E402  (the URL without credentials, the GitHub URL shape and the host name live there)
import redact  # noqa: E402  (the secret shapes: a file whose content matches one is held back like a .env)

GIT = ("git", "--no-pager", "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false",
       "-c", "commit.gpgsign=false", "-c", "http.lowSpeedLimit=1000", "-c", "http.lowSpeedTime=10")
KEPT_ENV = ("GIT_CONFIG", "GIT_SSH", "GIT_ASKPASS", "GIT_CEILING")   # every other GIT_* variable is dropped
NET_SECONDS = 60
NET_SHARE = 0.5                # network steps may use this part of a save's budget; the rest is kept for a bundle
MAX_FILE = 20 * 1024 * 1024    # a larger file is never put in a snapshot; a larger ignored file keeps the checkout
SCAN_MAX = 1024 * 1024         # the content of a file up to this size is checked for secret shapes; larger: by name
SCAN_TOTAL = 16 * 1024 * 1024  # more new content than this in unpushed commits: they go to the local bundle
REAPING = "ah-reaping"         # in the git dir while `ah reap` deletes the checkout: no save may run over it
LIFE = "ah-life"               # in the git dir: a random token of this life of the checkout, written by its first save
HELD_MAX = 200 * 1024 * 1024   # more held bytes than this are not copied: the save is not ok and the checkout stays
MAX_KEEPERS = 5000             # more ignored files than this are not judged: the save is not ok and the checkout stays
HEX = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?")
SECRET_NAMES = (".env*", "*.pem", "*.key", "id_rsa*", "id_dsa*", "id_ecdsa*", "id_ed25519*", "*.p12", "*.pfx", ".netrc",
                ".npmrc", ".pypirc", "*credentials*.json", "*.tfvars", "auth.json", "*.keystore", ".pgpass", "*.ppk",
                "*.jks", "*kubeconfig*", ".htpasswd", ".dockercfg", "*.docker/config.json", ".s3cfg", ".boto",
                ".git-credentials")
REBUILDABLE = frozenset(("node_modules", ".venv", "venv", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache",
                         ".next", ".nuxt", ".turbo", ".parcel-cache", ".gradle", ".tox"))
_DEADLINE = [None, None]   # set by save(): no git call outlives the caller's budget, no network step its share
_HOOKS_OFF: dict = {}


class SaveError(Exception):
    """Something could not be read or proven, so the checkout must be kept. The message is the reason."""


def _run(argv, timeout, env, data=b""):
    """(exit code, stdout, stderr) as bytes. The command gets a process group of its own, and on a timeout the whole
    group is killed, so no git-remote-http or ssh it started is left running (and seen as a user of the folder)."""
    proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env,
                            start_new_session=True)
    try:
        out, err = proc.communicate(data, timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except OSError:
            pass
        try:
            proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        raise
    return proc.returncode, out, err


def _git(repo, *args, timeout=30, env=None, stdin="", net=False):
    """(exit code, stdout, stderr) of one git call. Never raises: a timeout or a missing git is exit code 124. `net`:
    a network step, which also stops at its share of the budget."""
    repo = str(repo)
    for end in _DEADLINE[:2 if net else 1]:
        if end is not None:
            timeout = min(timeout, end - time.monotonic())
    if timeout <= 0:
        return 124, "", "the time budget is used up"
    full = {k: v for k, v in os.environ.items() if not k.startswith("GIT_") or k.startswith(KEPT_ENV)}
    full.update(GIT_TERMINAL_PROMPT="0", GIT_OPTIONAL_LOCKS="0", GIT_LITERAL_PATHSPECS="1", LC_ALL="C",
                GIT_AUTHOR_NAME="ah save", GIT_AUTHOR_EMAIL="ah-save@localhost",
                GIT_COMMITTER_NAME="ah save", GIT_COMMITTER_EMAIL="ah-save@localhost")
    full.update(env or {})
    try:
        if repo not in _HOOKS_OFF:   # hooks defined in git config (git 2.54+) ignore core.hooksPath: each is named off
            names = _run(["git", "-C", repo, "config", "--name-only", "--get-regexp", r"^hook\..*\.event$"],
                         timeout, full)[1]
            _HOOKS_OFF[repo] = [arg for name in sorted(set(names.decode("utf-8", "replace").splitlines()))
                                for arg in ("-c", "hook.%s.enabled=false" % name[5:-6])]
        code, out, err = _run([*GIT, *_HOOKS_OFF[repo], "-C", repo, *args], timeout, full,
                              stdin.encode("utf-8", "surrogateescape"))
    except (OSError, subprocess.SubprocessError) as error:
        return 124, "", type(error).__name__
    return code, out.decode("utf-8", "surrogateescape"), err.decode("utf-8", "replace").strip()


def _must(repo, *args, **kw) -> str:
    code, out, err = _git(repo, *args, **kw)
    if code != 0:
        raise SaveError("git %s failed: %s" % (args[0], ah_log_push.shown_url(err)[:200] or "exit %d" % code))
    return out


def _home(*parts) -> str:
    return str(Path.home().joinpath(".agent-harness", *parts))


def _mkdirs(path) -> None:
    mask = os.umask(0o077)   # every directory made here is 0700
    try:
        os.makedirs(path, exist_ok=True)
    finally:
        os.umask(mask)


def _read_json(path) -> dict:
    try:
        with open(path, "rb") as handle:
            data = json.loads(handle.read(4 * 1024 * 1024).decode("utf-8"))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _write_json(path, data) -> None:
    _mkdirs(os.path.dirname(path))
    part = "%s.%d.tmp" % (path, os.getpid())
    with os.fdopen(os.open(part, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), "w") as handle:
        json.dump(data, handle, indent=1, sort_keys=True)
    os.replace(part, path)


def _slug(text) -> str:
    """A name that is safe as one path component and inside a ref name."""
    return re.sub(r"\.\.+|\.lock$", "-", re.sub(r"[^A-Za-z0-9._-]+", "-", str(text))).strip(".-")[:80] or "x"


def _secret_name(rel) -> bool:
    rel = str(rel).lower()
    return any(fnmatch.fnmatchcase(rel if "/" in pattern else rel.rsplit("/", 1)[-1], pattern)
               for pattern in SECRET_NAMES)


@contextlib.contextmanager
def _scratch(f=None):
    """A new bare repository that borrows the checkout's objects (none without `f`). Network and bundle steps run in
    it, so the checkout's own config never applies to them and its refs are never touched."""
    path = tempfile.mkdtemp(prefix="ah-save-")
    try:
        _must(path, "init", "-q", "--bare")
        if f:
            with open(os.path.join(path, "objects", "info", "alternates"), "w", errors="surrogateescape") as handle:
                handle.write(os.path.join(f["common_dir"], "objects") + "\n")
            if os.path.isfile(os.path.join(f["common_dir"], "shallow")):
                shutil.copy(os.path.join(f["common_dir"], "shallow"), path)
        yield path
    finally:
        shutil.rmtree(path, ignore_errors=True)


def is_offhost(url) -> bool:
    """True for https://, ssh:// and user@host:path style URLs whose host is another machine. A plain path, file://,
    localhost, this host's own name, a remote helper (x::...) and a .bundle file are all False."""
    u = (url or "").strip()
    if not u or u.lower().endswith(".bundle") or re.match(r"[A-Za-z0-9_+.-]+::", u):
        return False
    found = re.match(r"(?:https?|ssh|git|git\+ssh|ssh\+git)://(?:[^@/]*@)?(\[[^\]]+\]|[^:/]+)", u, re.I)
    if not found and "://" not in u and not u.startswith(("/", ".", "~")):
        found = re.match(r"(?:[^@/:]+@)?(\[[^\]]+\]|[^:/]+):", u)   # scp-like host:path
    host = found.group(1).strip("[]").lower() if found else "localhost"
    try:
        ip = ipaddress.ip_address(host)
        if ip.is_loopback or ip.is_unspecified or ip.is_link_local:
            return False
    except ValueError:
        pass
    mine = {"localhost", socket.gethostname().lower(), socket.gethostname().lower().split(".")[0]}
    return host not in mine and host.split(".")[0] not in mine


def _real_remote(start, url):
    """The first off-host URL reached by following a local-path origin through at most 5 repositories, else None."""
    for _ in range(6):
        if not url or is_offhost(url):
            return url or None
        path = os.path.join(str(start), os.path.expanduser(url[7:] if url.startswith("file://") else url))
        if url.lower().endswith(".bundle") or not os.path.isdir(path):
            return None
        code, out, _err = _git(path, "config", "--get", "remote.origin.url")
        start, url = path, (out.strip() if code == 0 else "")
    return None


def facts(repo) -> dict:
    """What one checkout is and what it holds. Read only. A non-empty `errors` means the rest cannot be trusted."""
    repo = os.path.abspath(str(repo))
    f = {"toplevel": None, "git_dir": None, "common_dir": None, "linked_worktree": False, "head": None, "branch": None,
         "origin": None, "real_remote": None, "dirty": False, "untracked": 0, "stashes": [], "tips": {},
         "alternates": [], "worktrees": [], "errors": []}

    def ask(*args, quiet=()):
        code, out, err = _git(repo, *args)
        if (code != 0 and code not in quiet) or "ignoring broken ref" in err:
            f["errors"].append("git %s: %s" % (args[0], (err.splitlines() or ["exit %d" % code])[0][:200]))
        return out if code == 0 else ""

    where = ask("rev-parse", "--is-bare-repository", "--absolute-git-dir", "--git-common-dir").splitlines()
    if len(where) != 3:
        f["errors"] = f["errors"] or ["not a git checkout"]
        return f
    f["git_dir"], f["common_dir"] = os.path.realpath(where[1]), os.path.realpath(os.path.join(repo, where[2]))
    f["linked_worktree"] = f["git_dir"] != f["common_dir"]
    if where[0] != "true":
        f["toplevel"] = ask("rev-parse", "--show-toplevel").strip() or None
    f["head"] = ask("rev-parse", "-q", "--verify", "HEAD^{commit}", quiet=(1,)).strip() or None
    f["branch"] = (ask("symbolic-ref", "-q", "--short", "HEAD", quiet=(1,)).strip() or None) if f["head"] else None
    for line in ask("for-each-ref", "--format=%(objectname) %(refname)", "refs/heads", "refs/tags",
                    "refs/rescue").splitlines():   # refs/rescue: commits `ah worktree --rescue` saved locally
        f["tips"][line.partition(" ")[2][len("refs/"):]] = line.partition(" ")[0]
    stash = ask("for-each-ref", "--format=%(objectname)", "refs/stash").strip()
    if stash:   # the ref counts even when its reflog was expired
        listed = ask("rev-list", "-g", "refs/stash", "--").split()
        f["stashes"] = listed if stash in listed else [stash] + listed
    f["tips"].update(("stash/%d" % n, sha) for n, sha in enumerate(f["stashes"]))
    if f["head"] and not f["branch"]:
        f["tips"]["detached"] = f["head"]
    f["origin"] = ask("config", "--get", "remote.origin.url", quiet=(1,)).strip() or None
    f["real_remote"] = _real_remote(f["toplevel"] or repo, f["origin"])
    filters = [line.split("\t")[-1] for line in ask("config", "--show-scope", "--name-only", "--get-regexp",
                                                    r"^filter\..+\.(clean|smudge|process)$", quiet=(1,)).splitlines()
               if line.split("\t")[0] in ("local", "worktree")]
    if filters:   # git would run that program on the files: nothing more is asked of git here
        f["errors"].append("its own git config names a filter program (%s), which is never run" % filters[0])
    if f["toplevel"] and not f["errors"]:
        changes = ask("status", "--porcelain=v1", "-z", "--no-renames", "--untracked-files=all",
                      "--ignore-submodules=dirty").split("\0")   # a submodule is its own checkout, never entered
        f["untracked"] = sum(x.startswith("?? ") for x in changes)
        f["dirty"] = len(list(filter(None, changes))) > f["untracked"]
    objects = os.path.join(f["common_dir"], "objects")
    try:
        with open(os.path.join(objects, "info", "alternates"), "rb") as handle:
            lines = handle.read(256 * 1024).decode("utf-8", "surrogateescape").splitlines()
        f["alternates"] = [os.path.normpath(os.path.join(objects, x.strip())) for x in lines
                           if x.strip()[:1] not in ("", "#")]
    except FileNotFoundError:
        pass
    except OSError as error:
        f["errors"].append("alternates unreadable: %s" % type(error).__name__)
    if not f["linked_worktree"]:   # the linked worktrees that depend on this checkout (the main one is listed first)
        listed = [x[9:] for x in ask("worktree", "list", "--porcelain").splitlines() if x.startswith("worktree ")]
        f["worktrees"] = [p for p in listed[1:] if os.path.isdir(p)]
    return f


def unsaved_tips(repo, facts, remote_url):
    """(names in facts["tips"] not reachable from what `git ls-remote remote_url` reports, "known" | "unknown").
    "unknown" means ls-remote failed, and then every tip counts as unsaved."""
    tips = facts.get("tips") or {}
    with _scratch() as scratch:   # the checkout's own config (url.insteadOf, credential.helper) does not apply
        code, out, _err = _git(scratch, "ls-remote", "--", remote_url, timeout=NET_SECONDS, net=True)
    if code != 0:
        return sorted(tips), "unknown"
    remote = {line.split("\t")[0] for line in out.splitlines() if "\t" in line and HEX.fullmatch(line.split("\t")[0])}
    code, out, _err = _git(repo, "cat-file", "--batch-check", stdin="".join(sha + "\n" for sha in sorted(remote)))
    have = [x.split()[0] for x in out.splitlines() if x.split()[1:2] in (["commit"], ["tag"])] if code == 0 else []
    unsaved = []
    for name, sha in sorted(tips.items()):   # only remote commit ids that exist locally can vouch for a tip
        if sha not in remote:
            code, out, _err = _git(repo, "rev-list", "-1", "--stdin",
                                   stdin="".join("^%s\n" % x for x in have) + sha + "\n")
            if code != 0 or out.strip():
                unsaved.append(name)
    return unsaved, "known"


def _held_reason(top, rel, cache, seen):
    """None: put it in the snapshot (a regular file, a symlink, which git stores as its target's name, or one that is
    gone). "": a directory, which is a nested checkout or a submodule and is saved on its own. Anything else: why the
    file is held back. The content of a file up to SCAN_MAX is checked; the verdict is kept in `seen` and reused from
    `cache` while the file's size and times are the same."""
    try:
        info = os.lstat(os.path.join(top, rel))
    except FileNotFoundError:
        return None
    if stat.S_ISLNK(info.st_mode):
        return None
    if not stat.S_ISREG(info.st_mode):
        return "" if stat.S_ISDIR(info.st_mode) else "not a regular file"
    if _secret_name(rel):
        return "secret-shaped name"
    if info.st_size > MAX_FILE:
        return "over 20 MB"
    if info.st_size > SCAN_MAX:
        return None
    key = [info.st_size, info.st_mtime_ns, info.st_ctime_ns]
    old = cache.get(rel)
    if isinstance(old, list) and old[:3] == key:
        reason = old[3] if len(old) == 4 else None
    else:
        if _DEADLINE[0] is not None and time.monotonic() > _DEADLINE[0]:
            raise SaveError("the time budget ran out while files were checked for secret shapes")
        with open(os.path.join(top, rel), "rb") as handle:   # unreadable: the save is not ok and the checkout stays
            text = handle.read(SCAN_MAX).decode("utf-8", "replace")
        reason = "secret-shaped content" if redact.has_secret(text) else None
    seen[rel] = key + [reason]
    return reason


def _snapshot(repo, session, cache=None, seen=None):
    """(commit, tree, held_back) for the working tree, built in a temporary index. The commit is None when the tree is
    the same as HEAD's. Raises SaveError when git fails. `cache` and `seen`: see _held_reason."""
    cache, seen = cache or {}, {} if seen is None else seen
    top = _must(repo, "rev-parse", "--show-toplevel").strip()
    code, out, _err = _git(repo, "rev-parse", "-q", "--verify", "HEAD^{commit}")
    head = out.strip() if code == 0 else None   # None: no commit yet
    scratch = tempfile.mkdtemp(prefix="ah-save-")
    try:
        env = {"GIT_INDEX_FILE": os.path.join(scratch, "index")}
        real = os.path.join(top, _must(top, "rev-parse", "--git-path", "index").strip())
        if os.path.isfile(real):
            shutil.copy2(real, env["GIT_INDEX_FILE"])   # keeps the stat cache, so only changed files are hashed, and
            # the index's own timestamp: with a newer one git would not re-read a same-size edit made in that second
        elif head:
            _must(top, "read-tree", head, env=env)
        hidden = [x[2:] for x in _must(top, "ls-files", "-v", "-z", env=env).split("\0") if x[:1] in ("h", "S", "s")]
        hidden = "".join(x + "\0" for x in hidden if os.path.lexists(os.path.join(top, x)))
        for flag in ("--no-assume-unchanged", "--no-skip-worktree") if hidden else ():
            _must(top, "update-index", flag, "-z", "--stdin", env=env, stdin=hidden)   # hidden files are compared too
        changed = _must(top, "ls-files", "-z", "-m", "-d", "-o", "--exclude-standard", env=env)
        changed += (_must(top, "diff-index", "--cached", "--ignore-submodules=dirty", "--name-only", "-z", head,
                          env=env) if head
                    else _must(top, "ls-files", "-z", "--cached", env=env))   # staged paths are judged too
        take, held = [], []
        for rel in sorted(set(filter(None, changed.split("\0")))):
            reason = _held_reason(top, rel, cache, seen)
            if reason is None:
                take.append(rel)
            elif reason:
                held.append({"path": rel, "reason": reason})
        names = "".join(h["path"] + "\0" for h in held)   # a held file keeps HEAD's version in the snapshot, or none
        if held and head:
            _must(top, "reset", "-q", "--pathspec-from-file=-", "--pathspec-file-nul", head, env=env, stdin=names)
        elif held:
            _must(top, "update-index", "--force-remove", "-z", "--stdin", env=env, stdin=names)
        if take:
            _must(top, "update-index", "--add", "--remove", "--replace", "-z", "--stdin", env=env,
                  stdin="".join(t + "\0" for t in take))
        tree = _must(top, "write-tree", env=env).strip()
        if (tree == _must(top, "rev-parse", head + "^{tree}").strip() if head
                else not _must(top, "ls-files", "-z", "--cached", env=env)):
            return None, None, held
        day = time.strftime("%Y-%m-%dT00:00:00Z", time.gmtime())   # same tree on the same day: the same commit id
        commit = _must(top, "commit-tree", tree, *(["-p", head] if head else []), "-m",
                       "ah save: working tree of %s (session %s)" % (top, session),
                       env={"GIT_AUTHOR_DATE": day, "GIT_COMMITTER_DATE": day}).strip()
        return commit, tree, held
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


def snapshot(repo, session):
    """(commit id or None, held_back): a commit holding tracked changes and untracked files that are not ignored,
    parent HEAD. held_back is [{"path", "reason"}] for the files left out. Raises SaveError when git fails."""
    commit, _tree, held = _snapshot(repo, session)
    return commit, held


def rebuildable(path, ignored=False) -> bool:
    """True when the directory `path` is rebuildable output by its name: REBUILDABLE always, `target` beside a
    Cargo.toml or pom.xml, and `dist` or `build` only when the caller knows git ignores it inside a checkout."""
    name, parent = os.path.basename(path), os.path.dirname(path)
    return (name in REBUILDABLE or (ignored and name in ("dist", "build"))
            or (name == "target" and any(os.path.isfile(os.path.join(parent, x)) for x in ("Cargo.toml", "pom.xml"))))


def _unreadable(error):
    raise SaveError("unreadable directory %s" % error.filename)


def _tool_output(path) -> bool:
    """True for a directory a tool marked as its own output: a virtualenv (pyvenv.cfg), a cache (CACHEDIR.TAG), or one
    that ignores all of itself with a .gitignore of `*` (coverage's htmlcov and many caches write that)."""
    if any(os.path.isfile(os.path.join(path, name)) for name in ("pyvenv.cfg", "CACHEDIR.TAG")):
        return True
    try:
        with open(os.path.join(path, ".gitignore"), "rb") as handle:
            lines = [x.strip() for x in handle.read(4096).decode("utf-8", "replace").splitlines()]
    except OSError:
        return False
    return [x for x in lines if x and not x.startswith("#")] == ["*"]


def ignored_keepers(repo, big=None) -> list:
    """Relative paths of ignored regular files outside rebuildable directories and tool output: a deletion would lose
    them (.env, *.local, a local SQLite file, results). A file over 20 MB is never copied: it is added to `big`, or,
    without that list, raises SaveError. Raises SaveError when they cannot be listed."""
    top = _must(repo, "rev-parse", "--show-toplevel").strip()
    keep_going, big = big is not None, [] if big is None else big
    found = set()   # git lists a directory that holds only ignored files and may list its files as well
    for rel in filter(None, _must(top, "ls-files", "-z", "-o", "-i", "--exclude-standard", "--directory").split("\0")):
        parts = rel.rstrip("/").split("/")
        if any(rebuildable(os.path.join(top, *parts[:n])) or _tool_output(os.path.join(top, *parts[:n]))
               for n in range(1, len(parts))):
            continue
        files = [] if rel.endswith("/") else [os.path.join(top, rel)]
        for root, dirs, names in os.walk(os.path.join(top, rel), onerror=_unreadable) if rel.endswith("/") else ():
            if ".git" in dirs or ".git" in names or rebuildable(root.rstrip("/"), True) or _tool_output(root):
                dirs[:] = []   # a nested checkout (saved on its own), rebuildable or tool output
                continue
            files += [os.path.join(root, name) for name in names]
        infos = [(os.path.relpath(full, top), os.lstat(full)) for full in files[:MAX_KEEPERS + 1]]
        found.update(name for name, info in infos if stat.S_ISREG(info.st_mode) and info.st_size <= MAX_FILE)
        big += [name for name, info in infos if stat.S_ISREG(info.st_mode) and info.st_size > MAX_FILE]
        if len(files) > MAX_KEEPERS or len(found) > MAX_KEEPERS:
            raise SaveError("more than %d ignored files to hold" % MAX_KEEPERS)
    if big and not keep_going:
        raise SaveError(_too_big(big))
    return sorted(found)


def _too_big(big) -> str:
    return "ignored file %s is over 20 MB and is not copied (move it into keep/ or delete it)" % sorted(big)[0]


def _visibility(url):
    """True or False when gh says whether the GitHub repository is private (cached for 24 hours); None otherwise."""
    found = ah_log_push.GITHUB.match(url or "")
    if not found:
        return None
    slug = "%s/%s" % (found.group("owner"), found.group("repo"))
    cache = _home("state", "git-save", "private-%s.json" % hashlib.sha256(slug.lower().encode()).hexdigest()[:16])
    old = _read_json(cache)
    age = time.time() - old["at"] if isinstance(old.get("at"), (int, float)) else -1
    if old.get("repo") == slug and isinstance(old.get("private"), bool) and 0 <= age < 86400:
        return old["private"]
    try:
        left = 15 if _DEADLINE[1] is None else max(1, min(15, _DEADLINE[1] - time.monotonic()))
        done = subprocess.run(["gh", "api", "repos/" + slug, "--jq", ".private"], capture_output=True, text=True,
                              timeout=left, stdin=subprocess.DEVNULL)
        answer = done.stdout.strip() if done.returncode == 0 else ""
    except (OSError, subprocess.SubprocessError):
        answer = ""
    if answer in ("true", "false"):
        _write_json(cache, {"repo": slug, "private": answer == "true", "at": time.time()})
    return {"true": True, "false": False}.get(answer)


def _is_private(url) -> bool:
    """True only when gh says the GitHub repository is private; any failure counts as not private."""
    return _visibility(url) is True


def destination(facts) -> dict:
    """Where saved work goes: {"kind": "remote", "url", "why"} or {"kind": "bundle", "url": None, "why"}."""
    chosen = ah_local.get("rescue_remote", "")
    if chosen and _visibility(chosen) is False:   # gh says the chosen GitHub repository is public
        return {"kind": "bundle", "url": None, "why": "rescue_remote is a public repository"}
    if chosen:
        return {"kind": "remote", "url": chosen, "why": "rescue_remote"}
    real, mode = facts.get("real_remote"), ah_local.get("rescue_to_origin", "private")
    if real and mode != "never" and (mode == "always" or _is_private(real)):
        return {"kind": "remote", "url": real, "why": "the checkout's own remote (rescue_to_origin)"}
    return {"kind": "bundle", "url": None, "why": "no rescue_remote, and rescue_to_origin does not allow the remote"}


def _push(repo, url, prefix, want, force):
    """Push {name: commit} below `prefix`. Returns {ref: commit} only when ls-remote then shows every one of those
    refs with exactly that commit id; otherwise None. `repo` is a scratch repository that borrows the objects."""
    refs = {prefix + name: sha for name, sha in want.items()}
    specs = ["%s%s:%s" % ("+" if force else "", sha, ref) for ref, sha in refs.items()]
    if _git(repo, "push", "--no-verify", "--quiet", "--", url, *specs, timeout=NET_SECONDS, net=True)[0] != 0:
        return None
    code, out, _err = _git(repo, "ls-remote", "--", url, prefix + "*", timeout=NET_SECONDS, net=True)
    seen = {line.split("\t", 1)[1]: line.split("\t", 1)[0] for line in out.splitlines() if "\t" in line}
    return refs if code == 0 and all(seen.get(ref) == sha for ref, sha in refs.items()) else None


def _secret_in(repo, shas, known) -> str:
    """The first path, in the commits of `shas` that `known` lacks, whose name or content (files up to SCAN_MAX) is
    secret-shaped; "" when there is none. When git cannot list them or there is too much to read, that is the answer,
    so those commits go to the local bundle instead of a remote."""
    code, out, _err = _git(repo, "rev-list", "--objects", "--stdin",
                           stdin="".join(x + "\n" for x in shas) + "".join("^%s\n" % x for x in known))
    named = {}
    for line in out.splitlines() if code == 0 else ():
        sha, _space, rel = line.partition(" ")
        if rel:
            named.setdefault(sha, rel)
    code, out, _err = (_git(repo, "cat-file", "--batch-check=%(objectname) %(objecttype) %(objectsize)",
                            stdin="".join(x + "\n" for x in named)) if code == 0 and named else (code, "", ""))
    if code != 0:
        return "(git could not list what the commits hold)"
    blobs = [x.split() for x in out.splitlines() if x.split()[1:2] == ["blob"]]
    hit = next((named[sha] for sha, _kind, _size in blobs if _secret_name(named[sha])), None)
    small = [sha for sha, _kind, size in blobs if int(size) <= SCAN_MAX]
    if hit or not small:
        return hit or ""
    if sum(int(size) for _sha, _kind, size in blobs if int(size) <= SCAN_MAX) > SCAN_TOTAL:
        return "(more than %d MB of new files to check)" % (SCAN_TOTAL // 1048576)
    code, out, _err = _git(repo, "cat-file", "--batch", stdin="".join(x + "\n" for x in small))
    data, at = out.encode("utf-8", "surrogateescape"), 0
    for sha in small if code == 0 else ():
        end = data.index(b"\n", at)
        size = int(data[at:end].split()[2])
        if redact.has_secret(data[end + 1:end + 1 + size].decode("utf-8", "replace")):
            return named[sha]
        at = end + 2 + size
    return "" if code == 0 else "(git could not read what the commits hold)"


def _bundle(f, want, saved, path):
    """Write a bundle of {name: commit}, without the commits of `saved` (proven on the remote), at `path`. Returns
    {ref: commit} once `git bundle verify` passes and the bundle lists every ref with its id; else raises SaveError."""
    if (os.path.realpath(path) + os.sep).startswith(os.path.realpath(f["toplevel"] or f["git_dir"]) + os.sep):
        raise SaveError("the bundle would be written inside the checkout")
    refs = {("refs/" if name.startswith(("heads/", "tags/")) else "refs/heads/rescue/") + name: sha
            for name, sha in want.items()}
    _mkdirs(os.path.dirname(path))
    part = "%s.%d.tmp" % (path, os.getpid())
    try:
        with _scratch(f) as scratch:
            _must(scratch, "update-ref", "--stdin", stdin="".join("create %s %s\n" % x for x in refs.items()))
            _must(scratch, "bundle", "create", "-q", part, "--stdin", timeout=NET_SECONDS,
                  stdin="".join(ref + "\n" for ref in refs) + "".join("^%s\n" % sha for sha in saved))
            _must(scratch, "bundle", "verify", "-q", part, timeout=NET_SECONDS)
            listed = [x.split(" ", 1) for x in _must(scratch, "bundle", "list-heads", part).splitlines() if " " in x]
        got = {ref: sha for sha, ref in listed}
        for ref, sha in list(refs.items()):
            if got.get(ref) == sha:
                continue
            # git bundle leaves out a ref whose commit is already reachable from `saved` (proven on the remote):
            # that ref needs no bundle, so it is not a failure
            if ref not in got and any(_git(f["toplevel"] or f["git_dir"], "merge-base", "--is-ancestor", sha, s)[0] == 0 for s in saved):
                del refs[ref]
                continue
            raise SaveError("the bundle does not list every ref with its commit id")
        os.replace(part, path)
    finally:
        if os.path.lexists(part):
            os.unlink(part)
    return refs


def _real_dirs(base, rel) -> str:
    """Make base/rel one level at a time and return it. A level that is anything but a real directory (a symlink
    left there) raises SaveError, so no write ever leaves `base`."""
    _mkdirs(base)
    path = base
    for part in [""] + [x for x in rel.split("/") if x]:
        path = os.path.join(path, part) if part else path
        if part:
            try:
                os.mkdir(path, 0o700)
            except FileExistsError:
                pass
        if not stat.S_ISDIR(os.lstat(path).st_mode):
            raise SaveError("the held copy %s is not a real directory" % path)
    return path


def _hold(top, paths, dest) -> list:
    """Copy regular files that never go into a snapshot to `dest` (directories 0700, files 0600), keeping relative
    paths. Nothing is ever written through a symlink."""
    infos = {rel: os.lstat(os.path.join(top, rel)) for rel in paths}
    infos = {rel: i for rel, i in infos.items() if stat.S_ISREG(i.st_mode)}
    if sum(i.st_size for i in infos.values()) > HELD_MAX:
        raise SaveError("held files too large")
    for rel, info in infos.items():
        source = os.path.join(top, rel)
        target = os.path.join(_real_dirs(dest, os.path.dirname(rel)), os.path.basename(rel))
        if os.path.lexists(target):
            old = os.lstat(target)
            if stat.S_ISREG(old.st_mode) and (old.st_size, old.st_mtime_ns) == (info.st_size, info.st_mtime_ns):
                continue   # unchanged since the last copy
            if stat.S_ISDIR(old.st_mode):
                raise SaveError("the held copy %s is a directory" % target)
            os.unlink(target)   # a symlink goes, never what it points to
        with open(source, "rb") as src:
            with open(os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), "wb") as dst:
                shutil.copyfileobj(src, dst)
        os.utime(target, ns=(info.st_atime_ns, info.st_mtime_ns))
    return sorted(infos)


def _store(repo, f, tips, where, checked) -> dict:
    """Prove every tip saved: on the checkout's real remote already, pushed below refs/rescue/<where>/, or in a bundle
    at rescue/<where>.bundle. Unpushed commits that hold a secret-shaped file go to the bundle, never to a remote.
    `checked`: commits already found free of secret shapes."""
    unsaved = sorted(tips)
    if f["real_remote"]:
        unsaved = unsaved_tips(repo, dict(f, tips=tips), f["real_remote"])[0]
    want = {name: tips[name] for name in unsaved}
    out = {"where": "nothing", "url": None, "refs": {}, "bundle": None, "snapshot": tips.get("snapshot"),
           "checked": checked, "secret": None}
    if not want:
        return out
    saved, dest = [sha for name, sha in tips.items() if name not in want], destination(f)
    if dest["kind"] == "remote":   # the snapshot's own files were judged already: its parents are checked here
        look = sorted({f["head"] if name == "snapshot" else sha for name, sha in want.items()} - {None})
        out["secret"] = _secret_in(repo, look, saved + checked) or None
        out["checked"] = checked if out["secret"] else look
        with _scratch(f) as scratch:   # a forced update only inside refs/rescue/; plain branches are the one retry
            refs = None if out["secret"] else (
                _push(scratch, dest["url"], "refs/rescue/%s/" % where, want, True)
                or _push(scratch, dest["url"], "refs/heads/rescue/%s/" % where, want, False))
        if refs:
            return dict(out, where="remote", url=ah_log_push.shown_url(dest["url"]), refs=refs)
    path = _home("rescue", where + ".bundle")
    refs = _bundle(f, want, saved, path)
    origin = ah_log_push.shown_url(f["real_remote"] or f["origin"] or "")
    restore = ("git clone %s back && git -C back fetch %s 'refs/*:refs/rescued/*'" % (origin, path)
               if saved and origin else "git clone %s back" % path)   # leaving out commits gives prerequisites
    _write_json(path[:-len(".bundle")] + ".json", {
        "repo": f["toplevel"] or f["git_dir"], "made_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "refs": refs, "origin": origin, "restore": restore, "secret_in_commits": out["secret"]})
    return dict(out, where="bundle", refs=refs, bundle=path)


def _life(git_dir, bare=False):
    """The life token in the checkout's own git dir (for a linked worktree its .git/worktrees/<name>, for a bare
    repository the repository itself), written now when there is none. A checkout cloned or a worktree added again at
    the same path starts without one, so it is a new life. None when it cannot be read or written: no life is known.
    No token is written into a bare repository that lies inside another checkout's tree, where it would be a file of
    that checkout: such a bare repository has no life, so its copies are never continued."""
    path, parent = os.path.join(git_dir, LIFE), os.path.dirname(git_dir)
    while bare and parent != os.path.dirname(parent):
        if os.path.lexists(os.path.join(parent, ".git")):
            return None
        parent = os.path.dirname(parent)
    for _ in range(2):
        try:
            with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), "rb") as handle:
                text = handle.read(64).decode("ascii", "replace").strip()
            return text if re.fullmatch(r"[0-9a-f]{32}", text) else None
        except FileNotFoundError:
            pass
        except OSError:
            return None
        token = os.urandom(16).hex()
        try:
            with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), "w") as handle:
                handle.write(token + "\n")
            return token
        except FileExistsError:
            continue   # another save wrote one just now: read that
        except OSError:
            return None
    return None


def _continues(repo, saved, tips, life, recorded) -> bool:
    """True only with positive evidence that the copy saved last time is this checkout's own, so it may be brought up
    to date in place: this checkout's life token is the one recorded with that save, that save named commits (refs or
    a snapshot), this checkout still has its snapshot commit, and every other commit it saved is reachable from the
    tips now. A save that named no commit is no evidence. A checkout made again at the same path has a new token (or
    none), so it gets a new stamp and the copy of the one before is never changed, even when it holds those commits."""
    if not life or life != recorded or not saved.get("stamp"):
        return False
    snap, old = saved.get("snapshot"), sorted(set((saved.get("refs") or {}).values()) - {saved.get("snapshot")})
    if not snap and not old:
        return False
    if snap and _git(repo, "cat-file", "-e", "%s^{commit}" % snap)[0] != 0:
        return False
    code, out, _err = _git(repo, "rev-list", "-1", "--stdin", stdin="".join(x + "\n" for x in old)
                           + "".join("^%s\n" % x for x in tips.values())) if old else (0, "", "")
    return code == 0 and not out.strip()


def _held_already(top, keep, dest) -> bool:
    """True when every file to hold already has its copy in `dest` with the same size and time, so holding them there
    again would write nothing (_hold skips such a copy)."""
    for rel in keep if dest else ():
        try:
            info = os.lstat(os.path.join(top, rel))
            if not stat.S_ISREG(info.st_mode):
                continue
            old = os.lstat(os.path.join(dest, rel))
        except OSError:
            return False
        if not stat.S_ISREG(old.st_mode) or (old.st_size, old.st_mtime_ns) != (info.st_size, info.st_mtime_ns):
            return False
    return bool(dest)


def _stopped(mark, old) -> str:
    """The refusal for a checkout `ah reap` began to delete: where its proven copy is, what removing the mark does."""
    proof = _read_json(mark) or (old.get("saved") if isinstance(old.get("saved"), dict) else {})
    refs, copy = sorted(proof.get("refs") or {}), "named in ~/.agent-harness/logs/reap.jsonl"
    if proof.get("bundle"):
        copy = "the bundle %s" % proof["bundle"]
    elif refs:
        prefix = os.path.commonprefix(refs)
        copy = "the refs %s* on %s" % (prefix[:prefix.rfind("/") + 1], proof.get("url") or "the rescue remote")
    if proof.get("held_dir"):
        copy += " (held files: %s)" % proof["held_dir"]
    return ("ah reap stopped part way through deleting it; removing its ah-reaping mark lets a fresh copy be made "
            "beside its proven copy, which stays untouched: %s (the mark is %s)" % (copy, mark))


def note_reaping(f) -> None:
    """Record in the checkout's state file that `ah reap` begins to delete it, so no later save brings the proven copy
    up to date in place, even once the mark in its git dir has gone. Raises OSError when it cannot be written."""
    path = _state_file(f)
    _write_json(path, dict(_read_json(path), reaping=True))


def _measure(f, session, cache, seen):
    """(tips, snapshot commit, snapshot tree, files to hold, why they cannot all be held or None) of a checkout."""
    top, tips = f["toplevel"], dict(f["tips"])
    if any(not HEX.fullmatch(sha) for sha in tips.values()):
        raise SaveError("a ref has no commit id")
    commit, tree, held_back = _snapshot(top, session, cache, seen) if top else (None, None, [])
    big, problem = [], None
    keep = sorted({h["path"] for h in held_back} | set(ignored_keepers(top, big))) if top else []
    if big:
        problem = _too_big(big)
    elif os.path.isdir(os.path.join(f["common_dir"], "lfs")):
        problem = "it uses git-lfs, whose file contents this save cannot prove saved"
    return tips, commit, tree, keep, problem


def _state_file(f) -> str:
    return _home("state", "git-save", hashlib.sha256(os.fsencode(f["toplevel"] or f["git_dir"])).hexdigest() + ".json")


def save(repo, session, name, host=None, budget_s=120, fresh=False) -> dict:
    """Save what exists nowhere else and prove it. Returns {ok, where: "remote" | "bundle" | "nothing", url, refs,
    bundle, held, held_dir, reason, proof}; ok is True only when every unsaved thing is proven saved. `name` gets a
    short hash of the checkout's path and a stamp of this checkout's life, so no two checkouts share saved copies.
    An unchanged checkout is answered from its state file without a network call; `fresh=True` (use it before
    deleting) proves it again. `proof` is what unchanged() compares. Never raises."""
    res = {"ok": False, "where": "nothing", "url": None, "refs": {}, "bundle": None, "held": [], "held_dir": None,
           "reason": None, "proof": None}
    now = time.monotonic()
    _DEADLINE[:] = [now + budget_s, now + budget_s * NET_SHARE]
    try:
        f = facts(repo)
        if f["errors"]:
            raise SaveError(f["errors"][0])
        top, state_file = f["toplevel"], _state_file(f)
        old, seen = _read_json(state_file), {}
        if os.path.lexists(os.path.join(f["git_dir"], REAPING)):   # kept in the state file for after it is removed
            if old.get("reaping") is not True:
                with contextlib.suppress(OSError):   # the refusal below stands either way
                    _write_json(state_file, dict(old, reaping=True))
            raise SaveError(_stopped(os.path.join(f["git_dir"], REAPING), old))
        cache, life = old.get("scan") if isinstance(old.get("scan"), dict) else {}, _life(f["git_dir"], not top)
        try:
            tips, commit, tree, keep, problem = _measure(f, session, cache, seen)
        except SaveError:
            if seen:   # what was read before the time ran out is not read again
                _write_json(state_file, dict(old, scan=dict(cache, **seen)))
            raise
        mark, saved = {"tips": dict(tips), "snapshot_tree": tree}, old.get("saved")
        saved = saved if isinstance(saved, dict) else {}
        if commit:
            tips["snapshot"] = commit
        reaping = old.get("reaping") is True   # ah reap began to delete it: the proven copy is never updated
        renew = (fresh or reaping or not saved.get("stamp") or any(old.get(k) != v for k, v in mark.items())
                 or (life is not None and old.get("life") != life)   # a new life: a new stamp, recorded now
                 or (saved.get("bundle") and not os.path.isfile(saved["bundle"])))

        def same():
            return _continues(top or f["git_dir"], saved, tips, life, old.get("life"))

        held_at = _home("rescue", "held", saved["place"]) if isinstance(saved.get("place"), str) else None
        if not renew and keep and not _held_already(top, keep, held_at) and not same():
            renew = True   # the held files would change a copy that may be another life's: they get a new stamp
        if renew:
            stamp = (saved["stamp"] if not reaping and same()
                     else time.strftime("%Y%m%dT%H%M%SZ-", time.gmtime()) + os.urandom(2).hex())
            place = "%s/%s/%s-%s/%s" % (_slug(host or ah_log_push._host()), _slug(session), _slug(name),
                                        os.path.basename(state_file)[:8], stamp)
            checked = saved.get("checked") if saved.get("stamp") == stamp else []
            saved = dict(_store(top or f["git_dir"], f, tips, place, checked or []), stamp=stamp, place=place)
            _write_json(state_file, dict(mark, repo=top or f["git_dir"], at=time.time(), saved=saved, scan=seen,
                                         life=life))
        elif seen != cache:
            _write_json(state_file, dict(old, scan=seen))
        res.update({k: saved.get(k) for k in ("where", "url", "refs", "bundle")})
        res["proof"] = [mark["tips"], tree, keep]
        if keep:
            res["held_dir"] = _home("rescue", "held", saved["place"])
            res["held"] = _hold(top, keep, res["held_dir"])
        if problem:
            raise SaveError(problem)
        res["ok"] = True
    except Exception as error:   # noqa: BLE001  anything unexpected is a reason to keep the checkout, never to crash
        known = isinstance(error, (SaveError, OSError))
        res.update(ok=False, reason=str(error) if known and str(error) else "%s: %s" % (type(error).__name__, error))
    finally:
        _DEADLINE[:] = [None, None]
    return res


def unchanged(repo, session, proof) -> bool:
    """True when the checkout still holds exactly what save() proved (its result's `proof`): the same tips, the same
    working tree and the same files to hold. No network. `ah reap` asks this right before each deletion."""
    try:
        f = facts(repo)
        old = _read_json(_state_file(f))
        cache = old.get("scan") if isinstance(old.get("scan"), dict) else {}
        tips, _commit, tree, keep, problem = _measure(f, session, cache, {}) if not f["errors"] else ({}, 0, 0, 0, 1)
        return problem is None and proof is not None and [tips, tree, keep] == list(proof)
    except Exception:   # noqa: BLE001  any doubt: it may have changed
        return False
