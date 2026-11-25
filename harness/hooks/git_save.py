#!/usr/bin/env python3
"""Save whatever in one git checkout exists nowhere else, and prove it (docs/lifecycle.md).

`ah reap` deletes a checkout only on the strength of `save()["ok"]`; the Stop hook calls save() after every turn.
The proof is exact: a pushed ref counts only when `git ls-remote` shows that ref with that commit id; a bundle only
when `git bundle verify` passes, it lists every ref with its id and the file sits outside the checkout. Unknown means
keep: a git error, a timeout or any doubt gives ok False with the reason. Nothing here reads command text or blocks a
tool call, and the checkout's index, refs and working tree are never touched (a snapshot only adds objects). A nested
checkout or a submodule is its own checkout: it is skipped here, call save() on it separately.
Standard library only. Every git call has a timeout, no prompt, no pager, no optional locks and runs no hooks.
"""
from __future__ import annotations

import fnmatch
import hashlib
import ipaddress
import json
import os
import re
import shutil
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

GIT = ("git", "--no-pager", "-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false",
       "-c", "commit.gpgsign=false")
KEPT_ENV = ("GIT_CONFIG", "GIT_SSH", "GIT_ASKPASS", "GIT_CEILING")   # every other GIT_* variable is dropped
NET_SECONDS = 60
MAX_FILE = 20 * 1024 * 1024    # a larger file is never put in a snapshot and never held as an ignored keeper
HELD_MAX = 200 * 1024 * 1024   # more held bytes than this are not copied: the save is not ok and the checkout stays
MAX_KEEPERS = 5000             # more ignored files than this are not judged: the save is not ok and the checkout stays
HEX = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?")
SECRET_NAMES = (".env*", "*.pem", "*.key", "id_rsa*", "id_ed25519*", "*.p12", "*.pfx", ".netrc", ".npmrc", ".pypirc",
                "*credentials*.json", "*.tfvars", "auth.json", "*.keystore")
REBUILDABLE = frozenset(("node_modules", ".venv", "venv", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache",
                         ".next", ".nuxt", ".turbo", ".parcel-cache", ".gradle", ".tox"))
_DEADLINE = [None]   # set by save(): no git call outlives the caller's budget
_HOOKS_OFF: dict = {}


class SaveError(Exception):
    """Something could not be read or proven, so the checkout must be kept. The message is the reason."""


def _git(repo, *args, timeout=30, env=None, stdin=""):
    """(exit code, stdout, stderr) of one git call. Never raises: a timeout or a missing git is exit code 124."""
    repo = str(repo)
    if _DEADLINE[0] is not None:
        timeout = min(timeout, _DEADLINE[0] - time.monotonic())
        if timeout <= 0:
            return 124, "", "the time budget is used up"
    full = {k: v for k, v in os.environ.items() if not k.startswith("GIT_") or k.startswith(KEPT_ENV)}
    full.update(GIT_TERMINAL_PROMPT="0", GIT_OPTIONAL_LOCKS="0", GIT_LITERAL_PATHSPECS="1", LC_ALL="C",
                GIT_AUTHOR_NAME="ah save", GIT_AUTHOR_EMAIL="ah-save@localhost",
                GIT_COMMITTER_NAME="ah save", GIT_COMMITTER_EMAIL="ah-save@localhost")
    full.update(env or {})
    try:
        if repo not in _HOOKS_OFF:   # hooks defined in git config (git 2.54+) ignore core.hooksPath: each is named off
            names = subprocess.run(["git", "-C", repo, "config", "--name-only", "--get-regexp", r"^hook\..*\.event$"],
                                   capture_output=True, timeout=timeout, env=full, stdin=subprocess.DEVNULL).stdout
            _HOOKS_OFF[repo] = [arg for name in sorted(set(names.decode("utf-8", "replace").splitlines()))
                                for arg in ("-c", "hook.%s.enabled=false" % name[5:-6])]
        done = subprocess.run([*GIT, *_HOOKS_OFF[repo], "-C", repo, *args], capture_output=True, timeout=timeout,
                              env=full, input=stdin.encode("utf-8", "surrogateescape"))
    except (OSError, subprocess.SubprocessError) as error:
        return 124, "", type(error).__name__
    return (done.returncode, done.stdout.decode("utf-8", "surrogateescape"),
            done.stderr.decode("utf-8", "replace").strip())


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
        if code != 0 and code not in quiet:
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
    if ask("for-each-ref", "refs/stash"):
        f["stashes"] = ask("rev-list", "-g", "refs/stash", "--").split()
    f["tips"].update(("stash/%d" % n, sha) for n, sha in enumerate(f["stashes"]))
    if f["head"] and not f["branch"]:
        f["tips"]["detached"] = f["head"]
    f["origin"] = ask("config", "--get", "remote.origin.url", quiet=(1,)).strip() or None
    f["real_remote"] = _real_remote(f["toplevel"] or repo, f["origin"])
    if f["toplevel"]:
        changes = ask("status", "--porcelain=v1", "-z", "--no-renames", "--untracked-files=all").split("\0")
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
    code, out, _err = _git(repo, "ls-remote", "--", remote_url, timeout=NET_SECONDS)
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


def _held_reason(path):
    """None: put it in the snapshot (a regular file, or one that is gone). "": a directory, which is a nested checkout
    or a submodule and is saved on its own. Anything else: why the file is held back."""
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(info.st_mode):
        return "" if stat.S_ISDIR(info.st_mode) else "not a regular file"
    if any(fnmatch.fnmatchcase(os.path.basename(path).lower(), pattern) for pattern in SECRET_NAMES):
        return "secret-shaped name"
    return "over 20 MB" if info.st_size > MAX_FILE else None


def _snapshot(repo, session):
    """(commit, tree, held_back) for the working tree, built in a temporary index. The commit is None when the tree is
    the same as HEAD's. Raises SaveError when git fails."""
    top = _must(repo, "rev-parse", "--show-toplevel").strip()
    code, out, _err = _git(repo, "rev-parse", "-q", "--verify", "HEAD^{commit}")
    head = out.strip() if code == 0 else None   # None: no commit yet
    scratch = tempfile.mkdtemp(prefix="ah-save-")
    try:
        env = {"GIT_INDEX_FILE": os.path.join(scratch, "index")}
        real = os.path.join(top, _must(top, "rev-parse", "--git-path", "index").strip())
        if os.path.isfile(real):
            shutil.copyfile(real, env["GIT_INDEX_FILE"])   # keeps the stat cache, so only changed files are hashed
        elif head:
            _must(top, "read-tree", head, env=env)
        hidden = [x[2:] for x in _must(top, "ls-files", "-v", "-z", env=env).split("\0") if x[:1] in ("h", "S", "s")]
        hidden = "".join(x + "\0" for x in hidden if os.path.lexists(os.path.join(top, x)))
        for flag in ("--no-assume-unchanged", "--no-skip-worktree") if hidden else ():
            _must(top, "update-index", flag, "-z", "--stdin", env=env, stdin=hidden)   # hidden files are compared too
        changed = _must(top, "ls-files", "-z", "-m", "-d", "-o", "--exclude-standard", env=env)
        changed += (_must(top, "diff-index", "--cached", "--name-only", "-z", head, env=env) if head
                    else _must(top, "ls-files", "-z", "--cached", env=env))   # staged paths are judged too
        take, held = [], []
        for rel in sorted(set(filter(None, changed.split("\0")))):
            reason = _held_reason(os.path.join(top, rel))
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


def ignored_keepers(repo) -> list:
    """Relative paths of ignored regular files, at most 20 MB each, outside rebuildable directories: a deletion would
    lose them (.env, *.local, a local SQLite file). Raises SaveError when they cannot be listed."""
    top = _must(repo, "rev-parse", "--show-toplevel").strip()
    found = set()   # git lists a directory that holds only ignored files and may list its files as well
    for rel in filter(None, _must(top, "ls-files", "-z", "-o", "-i", "--exclude-standard", "--directory").split("\0")):
        parts = rel.rstrip("/").split("/")
        if any(rebuildable(os.path.join(top, *parts[:n])) for n in range(1, len(parts))):
            continue
        files = [] if rel.endswith("/") else [os.path.join(top, rel)]
        for root, dirs, names in os.walk(os.path.join(top, rel), onerror=_unreadable) if rel.endswith("/") else ():
            if ".git" in dirs or ".git" in names or rebuildable(root.rstrip("/"), True):
                dirs[:] = []   # a nested checkout (saved on its own) or rebuildable output
                continue
            files += [os.path.join(root, name) for name in names]
        infos = [(os.path.relpath(full, top), os.lstat(full)) for full in files[:MAX_KEEPERS + 1]]
        found.update(name for name, info in infos if stat.S_ISREG(info.st_mode) and info.st_size <= MAX_FILE)
        if len(files) > MAX_KEEPERS or len(found) > MAX_KEEPERS:
            raise SaveError("more than %d ignored files to hold" % MAX_KEEPERS)
    return sorted(found)


def _is_private(url) -> bool:
    """True only when gh says the GitHub repository is private (a yes or no is cached for 24 hours)."""
    found = ah_log_push.GITHUB.match(url or "")
    if not found:
        return False
    slug = "%s/%s" % (found.group("owner"), found.group("repo"))
    cache = _home("state", "git-save", "private-%s.json" % hashlib.sha256(slug.lower().encode()).hexdigest()[:16])
    old = _read_json(cache)
    age = time.time() - old["at"] if isinstance(old.get("at"), (int, float)) else -1
    if old.get("repo") == slug and isinstance(old.get("private"), bool) and 0 <= age < 86400:
        return old["private"]
    try:
        left = 15 if _DEADLINE[0] is None else max(1, min(15, _DEADLINE[0] - time.monotonic()))
        done = subprocess.run(["gh", "api", "repos/" + slug, "--jq", ".private"], capture_output=True, text=True,
                              timeout=left, stdin=subprocess.DEVNULL)
        answer = done.stdout.strip() if done.returncode == 0 else ""
    except (OSError, subprocess.SubprocessError):
        answer = ""
    if answer in ("true", "false"):
        _write_json(cache, {"repo": slug, "private": answer == "true", "at": time.time()})
    return answer == "true"


def destination(facts) -> dict:
    """Where saved work goes: {"kind": "remote", "url", "why"} or {"kind": "bundle", "url": None, "why"}."""
    chosen = ah_local.get("rescue_remote", "")
    if chosen:
        return {"kind": "remote", "url": chosen, "why": "rescue_remote"}
    real, mode = facts.get("real_remote"), ah_local.get("rescue_to_origin", "private")
    if real and mode != "never" and (mode == "always" or _is_private(real)):
        return {"kind": "remote", "url": real, "why": "the checkout's own remote (rescue_to_origin)"}
    return {"kind": "bundle", "url": None, "why": "no rescue_remote, and rescue_to_origin does not allow the remote"}


def _push(repo, url, prefix, want, force):
    """Push {name: commit} below `prefix`. Returns {ref: commit} only when ls-remote then shows every one of those
    refs with exactly that commit id; otherwise None."""
    refs = {prefix + name: sha for name, sha in want.items()}
    specs = ["%s%s:%s" % ("+" if force else "", sha, ref) for ref, sha in refs.items()]
    if _git(repo, "push", "--no-verify", "--quiet", "--", url, *specs, timeout=NET_SECONDS)[0] != 0:
        return None
    code, out, _err = _git(repo, "ls-remote", "--", url, prefix + "*", timeout=NET_SECONDS)
    seen = {line.split("\t", 1)[1]: line.split("\t", 1)[0] for line in out.splitlines() if "\t" in line}
    return refs if code == 0 and all(seen.get(ref) == sha for ref, sha in refs.items()) else None


def _bundle(f, want, saved, path):
    """Write a bundle of {name: commit}, without the commits of `saved` (proven on the remote), at `path`. Returns
    {ref: commit} once `git bundle verify` passes and the bundle lists every ref with its id; else raises SaveError."""
    if (os.path.realpath(path) + os.sep).startswith(os.path.realpath(f["toplevel"] or f["git_dir"]) + os.sep):
        raise SaveError("the bundle would be written inside the checkout")
    refs = {("refs/" if name.startswith(("heads/", "tags/")) else "refs/heads/rescue/") + name: sha
            for name, sha in want.items()}
    _mkdirs(os.path.dirname(path))
    scratch, part = tempfile.mkdtemp(prefix="ah-save-"), "%s.%d.tmp" % (path, os.getpid())
    try:   # a scratch bare repository that borrows the checkout's objects, so the checkout's refs are never touched
        env = {"GIT_ALTERNATE_OBJECT_DIRECTORIES": os.path.join(f["common_dir"], "objects")}
        _must(scratch, "init", "-q", "--bare")
        _must(scratch, "update-ref", "--stdin", env=env, stdin="".join("create %s %s\n" % x for x in refs.items()))
        _must(scratch, "bundle", "create", "-q", part, "--stdin", env=env, timeout=NET_SECONDS,
              stdin="".join(ref + "\n" for ref in refs) + "".join("^%s\n" % sha for sha in saved))
        _must(scratch, "bundle", "verify", "-q", part, env=env, timeout=NET_SECONDS)
        listed = [x.split(" ", 1) for x in _must(scratch, "bundle", "list-heads", part).splitlines() if " " in x]
        if any({ref: sha for sha, ref in listed}.get(ref) != sha for ref, sha in refs.items()):
            raise SaveError("the bundle does not list every ref with its commit id")
        os.replace(part, path)
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
        if os.path.lexists(part):
            os.unlink(part)
    return refs


def _hold(top, paths, dest) -> list:
    """Copy files that never go into a snapshot to `dest` (directories 0700, files 0600), keeping relative paths."""
    infos = {rel: os.lstat(os.path.join(top, rel)) for rel in paths}
    infos = {rel: i for rel, i in infos.items() if stat.S_ISREG(i.st_mode) or stat.S_ISLNK(i.st_mode)}
    if sum(i.st_size for i in infos.values()) > HELD_MAX:
        raise SaveError("held files too large")
    for rel, info in infos.items():
        source, target = os.path.join(top, rel), os.path.join(dest, rel)
        _mkdirs(os.path.dirname(target))
        if os.path.lexists(target):
            old = os.lstat(target)
            if stat.S_ISREG(info.st_mode) and (old.st_size, old.st_mtime_ns) == (info.st_size, info.st_mtime_ns):
                continue   # unchanged since the last copy
            os.unlink(target)
        if stat.S_ISLNK(info.st_mode):
            os.symlink(os.readlink(source), target)
            continue
        with open(source, "rb") as src:
            with open(os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as dst:
                shutil.copyfileobj(src, dst)
        os.utime(target, ns=(info.st_atime_ns, info.st_mtime_ns))
    return sorted(infos)


def _store(repo, f, tips, where) -> dict:
    """Prove every tip saved: on the checkout's real remote already, pushed to the rescue refs, or in a bundle."""
    unsaved = sorted(tips)
    if f["real_remote"]:
        unsaved = unsaved_tips(repo, dict(f, tips=tips), f["real_remote"])[0]
    want = {name: tips[name] for name in unsaved}
    if not want:
        return {"where": "nothing", "url": None, "refs": {}, "bundle": None}
    dest = destination(f)
    if dest["kind"] == "remote":   # a forced update only inside refs/rescue/; plain branches are the one retry
        refs = (_push(repo, dest["url"], "refs/rescue/%s/" % where, want, True)
                or _push(repo, dest["url"], "refs/heads/rescue/%s/" % where, want, False))
        if refs:
            return {"where": "remote", "url": ah_log_push.shown_url(dest["url"]), "refs": refs, "bundle": None}
    path = _home("rescue", where + ".bundle")
    refs = _bundle(f, want, [sha for name, sha in tips.items() if name not in want], path)
    _write_json(path[:-len(".bundle")] + ".json", {
        "repo": f["toplevel"] or f["git_dir"], "made_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "refs": refs, "origin": ah_log_push.shown_url(f["real_remote"] or f["origin"] or ""),
        "restore": "git clone " + path})
    return {"where": "bundle", "url": None, "refs": refs, "bundle": path}


def save(repo, session, name, host=None, budget_s=120, fresh=False) -> dict:
    """Save what exists nowhere else and prove it. Returns {ok, where: "remote" | "bundle" | "nothing", url, refs,
    bundle, held, held_dir, reason}; ok is True only when every unsaved thing is proven saved. `name` gets a short
    hash of the checkout's path, so two checkouts never share rescue refs. An unchanged checkout is answered from its
    state file without a network call; `fresh=True` (use it before deleting) proves it again. Never raises."""
    res = {"ok": False, "where": "nothing", "url": None, "refs": {}, "bundle": None, "held": [], "held_dir": None,
           "reason": None}
    _DEADLINE[0] = time.monotonic() + budget_s
    try:
        f = facts(repo)
        if f["errors"]:
            raise SaveError(f["errors"][0])
        top, tips = f["toplevel"], dict(f["tips"])
        if any(not HEX.fullmatch(sha) for sha in tips.values()):
            raise SaveError("a ref has no commit id")
        key = hashlib.sha256(os.fsencode(top or f["git_dir"])).hexdigest()
        where = "%s/%s/%s-%s" % (_slug(host or ah_log_push._host()), _slug(session), _slug(name), key[:8])
        commit, tree, held_back = _snapshot(top, session) if top else (None, None, [])
        state_file = _home("state", "git-save", key + ".json")
        mark, old = {"tips": dict(tips), "snapshot_tree": tree}, _read_json(state_file)
        if commit:
            tips["snapshot"] = commit
        saved = old.get("saved") if isinstance(old.get("saved"), dict) else {}
        if (fresh or not saved or any(old.get(k) != v for k, v in mark.items())
                or (saved.get("bundle") and not os.path.isfile(saved["bundle"]))):
            saved = _store(top or f["git_dir"], f, tips, where)
            _write_json(state_file, dict(mark, repo=top or f["git_dir"], at=time.time(), saved=saved))
        res.update({k: saved.get(k) for k in ("where", "url", "refs", "bundle")})
        if top:
            keep = sorted({h["path"] for h in held_back} | set(ignored_keepers(top)))
            res["held"] = _hold(top, keep, _home("rescue", "held", where))
            res["held_dir"] = _home("rescue", "held", where) if res["held"] else None
        res["ok"] = True
    except Exception as error:   # noqa: BLE001  anything unexpected is a reason to keep the checkout, never to crash
        known = isinstance(error, (SaveError, OSError))
        res.update(ok=False, reason=str(error) if known and str(error) else "%s: %s" % (type(error).__name__, error))
    finally:
        _DEADLINE[0] = None
    return res
