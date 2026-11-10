#!/usr/bin/env python3
"""Audited garbage collection of ~/.agent-harness/work (GoodQA #15565).

The work directory had reached 183 GiB on a Mac at 97% disk. This tool finds two kinds of reclaimable content and removes
them only from a plan that a dry run printed:

  worktree  the git worktree of a FINISHED agent: `<repo>/.claude/worktrees/agent-<id>` whose `.git` is a FILE pointing
            into `<repo>/.git/worktrees/` (relative gitdir paths are resolved against the worktree), when
              * its agent log has not been written for `--idle-hours` (default and minimum 3), no sub-agent transcript
                that names it was written within that time, and no process has its cwd inside it,
              * it is not locked (`git worktree lock`),
              * `git status` shows no changed or untracked file, no index entry hides changes, no submodule, and every
                IGNORED entry is a whole build or dependency folder (or .DS_Store / bytecode) that holds no nested
                repository, no Claude/Codex/harness folder and (outside dependency trees) no secret, key, database,
                log or transcript file, and
              * its HEAD is contained in a remote-tracking ref of a remote whose URL is on an allowed network host
                (github.com, t2-dev) AND that ref equals the live tip `git ls-remote` reports now. Local paths and
                file:// remotes are never proof; a remote that does not answer keeps the worktree.
            It is removed with `git worktree remove --force`, which leaves the branch and the repository alone.
  regen     a folder named like build output or dependencies (node_modules, .venv, venv, .next, .nuxt, .turbo, dist,
            build, coverage, __pycache__, .pytest_cache, .mypy_cache, .ruff_cache, .cache, target, .gradle,
            .svelte-kit, .output, .parcel-cache, .wrangler, .media-cache). Inside a git work tree only when git tracks
            nothing in it AND ignores it. Outside any repository only self-identifying folders: node_modules with a
            package.json beside it, .venv/venv holding pyvenv.cfg, __pycache__, .pytest_cache, .mypy_cache, .ruff_cache.
            Never when it holds a nested repository, a session record or (outside dependency trees) a secret or log,
            and never while a process has its cwd inside it or at its repository root.

It never descends into or removes: `.git`, `~/.claude`, session logs (`wals`, `projects`, `sessions`, `transcripts`,
`*.jsonl`), state or approval files (`state`, `.agent-harness/state`), or a worktree that holds work. Everything it
removes, skips or fails on in `apply` is appended to `~/.agent-harness/state/work-gc.jsonl`.

    work_gc.py plan  [--root DIR] [--idle-hours H] [--out plan.json]    dry run: lists candidates with sizes
    work_gc.py apply --plan plan.json [--root DIR] [--idle-hours H]     re-verifies every item, then removes it

`apply` takes only a plan file produced by `plan`. Its items carry an unkeyed sha256, which only detects accidental or
careless edits (anyone can recompute it); the protection is that apply re-verifies every item in full, right before
removing it, with a fresh process snapshot and the idle time given on ITS command line. It holds an exclusive lock so
two applies cannot run at once, and writes an intent row to the audit log before each removal and a result row after.
A process "uses" a folder when lsof names any path under it (any fd) or a command line (ps) contains one.

Known limit: `git status` runs the repository's configured filter drivers (clean/process); the repositories under the
work root are the agents' own clones, so they are trusted to that extent. Python 3.9+, stdlib only.
"""
from __future__ import annotations

import argparse
import contextlib
import fcntl
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

REGEN_NAMES = frozenset((
    "node_modules", ".next", "dist", "build", ".venv", "venv", "__pycache__", ".cache", "target", "coverage", ".turbo",
    ".nuxt", ".svelte-kit", ".output", ".pytest_cache", ".mypy_cache", ".ruff_cache", ".gradle", ".parcel-cache",
    ".wrangler", ".media-cache"))
# outside a git work tree a name proves nothing (dist, build, target may be hand-made); only these identify themselves
OUTSIDE_GIT_NAMES = frozenset(("node_modules", ".venv", "venv", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache"))
# third-party trees hold fixtures (keys, databases) that are part of a package: only the name-independent checks apply
DEPENDENCY_NAMES = frozenset(("node_modules", "venv", ".venv", "__pycache__", ".tox", ".eggs", ".gradle"))
PROTECTED_NAMES = frozenset((".git", "wals", "projects", "sessions", "transcripts", "state", ".claude"))
HARNESS_NAMES = frozenset((".claude", ".codex", ".agent-harness"))
NEVER_SEGMENTS = HARNESS_NAMES | frozenset(("wals", "projects", "sessions", "transcripts", "state", "logs"))
CONTENT_PROTECTED = HARNESS_NAMES | frozenset(("wals", "transcripts"))  # refused even inside dependency trees
SECRET_OR_RECORD = re.compile(
    r"(?:^\.env|^\.npmrc$|^\.netrc$|^id_|^credentials|^service-account.*\.json$"
    r"|\.(?:pem|key|p12|pfx|kdbx|db|sqlite|sqlite3|jsonl|log|jks|keystore|tfstate|ovpn|sql|sql\.gz)$)", re.I)
ALLOWED_HOSTS = ("github.com", "t2-dev")
MIN_IDLE_HOURS = 3.0
WALK_LIMIT = 3000000
MAX_DEPTH = 9
SCAN_SECONDS = 120.0
DU_TIMEOUT = 60
GIT_TIMEOUT = 30
LS_REMOTE_TIMEOUT = 20


class Refuse(Exception):
    """A folder or worktree must be kept; the message says why."""


def home() -> Path:
    return Path(os.environ.get("AH_HOME") or Path.home())


def work_root() -> Path:
    return home() / ".agent-harness" / "work"


def audit_path() -> Path:
    return home() / ".agent-harness" / "state" / "work-gc.jsonl"


def lock_path() -> Path:
    return home() / ".agent-harness" / "state" / "work-gc.lock"


# repository-selecting variables of the caller must never redirect git to another repository
GIT_ENV_DROP = ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_COMMON_DIR", "GIT_OBJECT_DIRECTORY",
                "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_NAMESPACE", "GIT_CEILING_DIRECTORIES")


def git_env(**extra) -> dict:
    env = dict(os.environ)
    for name in GIT_ENV_DROP:
        env.pop(name, None)
    env.update(GIT_OPTIONAL_LOCKS="0", GIT_TERMINAL_PROMPT="0", **extra)
    return env


def git(path, *args, timeout=GIT_TIMEOUT, ceiling=None, stdin=None):
    """Run git in `path` (plain -C, never cd). `ceiling` stops repository discovery from climbing above it."""
    env = git_env()
    if ceiling is not None:
        env["GIT_CEILING_DIRECTORIES"] = str(ceiling)
    done = subprocess.run(["git", "-C", str(path), "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", *args],
                          capture_output=True, text=True, timeout=timeout, env=env, input=stdin,
                          stdin=None if stdin is not None else subprocess.DEVNULL)
    return done.returncode, done.stdout


def disk_bytes(path: Path) -> int:
    try:
        done = subprocess.run(["du", "-sk", str(path)], capture_output=True, text=True, timeout=DU_TIMEOUT)
        return int(done.stdout.split()[0]) * 1024
    except (OSError, ValueError, IndexError, subprocess.TimeoutExpired):
        return -1


def lsof_paths():
    """Every absolute path lsof names for any process and any fd (cwd, txt, open files, mapped libraries).
    A failing, non-zero or empty lsof returns None: the process list is unreadable and nothing is removed."""
    try:
        done = subprocess.run(["lsof", "-n", "-Fn"], capture_output=True, text=True, errors="replace", timeout=120,
                              stdin=subprocess.DEVNULL)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if done.returncode != 0:
        return None
    lines = [ln[1:] for ln in done.stdout.splitlines() if ln.startswith("n/")]
    return lines or None


ARGV_PATH = re.compile(r"""(?:^|[\s='"])(/[^\s'"]+)""")


def argv_paths():
    """Absolute paths in every process command line (`ps -axo command=`): a program run from a folder, such as
    `node <dir>/node_modules/wrangler/cli.js`, need not have its cwd or an open file there. None when ps fails."""
    try:
        done = subprocess.run(["ps", "-axo", "command="], capture_output=True, text=True, errors="replace",
                              timeout=60, stdin=subprocess.DEVNULL)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if done.returncode != 0 or not done.stdout.strip():
        return None
    return [m.rstrip("/") or "/" for line in done.stdout.splitlines() for m in ARGV_PATH.findall(line)]


def in_use_paths():
    """ONE snapshot of every path a process uses (lsof, all fds) or names on its command line (ps). None when either
    list cannot be read, which keeps everything."""
    files = lsof_paths()
    if files is None:
        return None
    argv = argv_paths()
    if argv is None:
        return None
    return files + argv


def _under(used, path) -> bool:
    for target in {str(path).rstrip("/"), os.path.realpath(path)}:
        prefix = target + "/"
        if any(c == target or c.startswith(prefix) for c in used):
            return True
    return False


def repo_anchor(path: Path, root: Path):
    """The nearest folder at or above `path` (not above root) that contains `.git`, else None."""
    for p in [path, *path.parents]:
        if os.path.lexists(os.path.join(p, ".git")):
            return p
        if p == root or root not in p.parents:
            return None
    return None


def busy(path: Path, used, root: Path = None) -> bool:
    """A process uses a path inside `path` (cwd, open or executed file, command-line argument), or one at/under the
    repository root above it (a dev server run from the repo). `used` is None when the snapshot was unreadable."""
    if used is None:
        return True
    if _under(used, path):
        return True
    anchor = repo_anchor(path, root) if root is not None else None
    return anchor is not None and _under(used, anchor)


# ---------------------------------------------------------------- what an ignored or rebuildable folder may hold


def scan_folder(path, name) -> int:
    """Walk one folder (never following links, bounded) and raise Refuse for a nested repository (its commits may exist
    nowhere else), a bare-repository shape, a Claude/Codex/harness or session folder, any `.jsonl`, and, outside
    dependency trees, a secret, key, database, log or transcript file. Returns the number of entries seen."""
    dependency = name in DEPENDENCY_NAMES
    bad_dirs = CONTENT_PROTECTED if dependency else NEVER_SEGMENTS
    seen = 0

    def onerror(error):
        raise Refuse("could not be read completely (%s)" % error)

    for base, dirs, files in os.walk(path, onerror=onerror, followlinks=False):
        if "HEAD" in files and "objects" in dirs and "refs" in dirs:
            raise Refuse("holds a bare repository (%s)" % os.path.relpath(base, path))
        for d in dirs:
            low = d.casefold()
            if low == ".git":
                raise Refuse("holds a nested repository (%s)" % os.path.relpath(os.path.join(base, d), path))
            if low in bad_dirs:
                raise Refuse("holds a Claude, harness or session folder (%s)" % d)
        for f in files:
            low = f.casefold()
            if low == ".git":
                raise Refuse("holds a nested repository file (%s)" % os.path.relpath(os.path.join(base, f), path))
            if low.endswith(".jsonl") or (not dependency and SECRET_OR_RECORD.search(f)):
                raise Refuse("holds a secret, key, database, log or transcript file (%s)" % f)
        seen += len(dirs) + len(files)
        if seen > WALK_LIMIT:
            raise Refuse("too large to check (over %d entries)" % WALK_LIMIT)
    return seen


def regenerable_ignored(entry: str) -> bool:
    """True when a `git status --ignored` entry is rebuildable output: a whole ignored folder (trailing slash) whose own
    name is a build or dependency name, or a .DS_Store or __pycache__ bytecode file. Never with a session segment."""
    text = str(entry).replace("\\", "/")
    parts = [seg for seg in text.split("/") if seg]
    if not parts or ".." in parts or any(seg.casefold() in NEVER_SEGMENTS for seg in parts):
        return False
    if text.endswith("/"):
        return parts[-1] in REGEN_NAMES
    name = parts[-1]
    if name == ".DS_Store":
        return True
    return name.endswith((".pyc", ".pyo")) and len(parts) > 1 and parts[-2] == "__pycache__"


def check_regen_origin(path: Path, root: Path) -> str:
    """F1: inside a git work tree a folder is rebuildable only when git tracks nothing in it and ignores it; outside
    any repository only self-identifying folders are. Returns a reason or raises Refuse."""
    parent = path.parent
    code, top = git(parent, "rev-parse", "--show-toplevel", ceiling=root.parent)
    if code == 0 and top.strip():
        code, tracked = git(parent, "ls-files", "-z", "--", path.name, ceiling=root.parent)
        if code != 0 or tracked:
            raise Refuse("git tracks files in it")
        code, _ = git(parent, "check-ignore", "-q", path.name + "/", ceiling=root.parent)
        if code != 0:
            raise Refuse("its repository does not ignore it (untracked output may be unique)")
        return "untracked and ignored by its repository"
    for anc in [parent, *parent.parents]:  # git failed although a repository is here: refuse, never guess
        if os.path.lexists(os.path.join(anc, ".git")):
            raise Refuse("git could not inspect the repository around it")
        if anc == root or root not in anc.parents:
            break
    name = path.name
    if name not in OUTSIDE_GIT_NAMES:
        raise Refuse("outside git, %s is not self-identifying output" % name)
    if name == "node_modules":
        beside = parent / "package.json"
        if beside.is_symlink() or not beside.is_file():
            raise Refuse("outside git, node_modules without a package.json beside it")
    if name in (".venv", "venv"):
        cfg = path / "pyvenv.cfg"
        if cfg.is_symlink() or not cfg.is_file():
            raise Refuse("outside git, %s without pyvenv.cfg" % name)
    return "self-identifying folder outside git"


# ---------------------------------------------------------------- pushed proof


def remote_host(url) -> str:
    """The host of a network git URL (https, ssh, git+ssh or scp-like), else ''. Local paths and file:// give ''."""
    url = str(url or "").strip()
    m = re.match(r"^(?:https|ssh|git\+ssh)://(?:[^@/\s]+@)?([A-Za-z0-9.-]+)(?::\d+)?/\S+$", url, re.I)
    if not m and not url.startswith(("/", ".", "~")) and "://" not in url:
        m = re.match(r"^(?:[A-Za-z0-9._-]+@)?([A-Za-z0-9.-]+):\S+$", url)
    return m.group(1).casefold() if m else ""


def remote_host_allowed(url) -> bool:
    """Only https, ssh, git+ssh or scp-like URLs on an allowed host; never a transport helper (`<helper>::<address>`)."""
    if "::" in str(url or ""):
        return False
    return remote_host(url) in ALLOWED_HOSTS


def live_ls_remote(url):
    """{refname: sha} of the live heads of `url`, listed from outside any repository, or None when it did not answer."""
    if not remote_host_allowed(url):
        return None
    env = git_env(GIT_ASKPASS="/bin/true", GIT_SSH_COMMAND="ssh -oBatchMode=yes -oConnectTimeout=10")
    try:
        done = subprocess.run(["git", "-c", "protocol.ext.allow=never", "-c", "protocol.file.allow=never",
                               "ls-remote", "--heads", "--", url], cwd="/", capture_output=True, text=True,
                              timeout=LS_REMOTE_TIMEOUT, env=env, stdin=subprocess.DEVNULL)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if done.returncode != 0:
        return None
    return {ref: sha for sha, ref in (ln.split("\t", 1) for ln in done.stdout.splitlines() if "\t" in ln)}


# injection points (tests replace these; the defaults are the network-backed checks)
remote_allowed = remote_host_allowed
ls_remote = live_ls_remote


class Context:
    """Per-run facts shared by every verdict: remote checks, the ls-remote cache, sub-agent activity."""

    def __init__(self, root: Path, idle_hours: float, remote_allowed_fn=None, ls_remote_fn=None):
        self.root, self.idle_hours = Path(root), float(idle_hours)
        self.remote_allowed = remote_allowed_fn or remote_allowed
        self.ls_remote = ls_remote_fn or ls_remote
        self._listings, self._activity, self._url_locks = {}, {}, {}
        self._lock = threading.Lock()

    def listing(self, url):
        """The live listing of `url`, fetched once per run. Only that URL's own lock is held during the network call."""
        with self._lock:
            url_lock = self._url_locks.setdefault(url, threading.Lock())
        with url_lock:
            with self._lock:
                if url in self._listings:
                    return self._listings[url]
            try:
                live = self.ls_remote(url)
            except Exception:  # noqa: BLE001 - an unanswered listing keeps the worktree
                live = None
            with self._lock:
                self._listings[url] = live
            return live

    def subagent_written(self, session: str, worktree: Path):
        """Newest mtime of a sub-agent transcript whose meta names this worktree, else None (missing files = no info)."""
        with self._lock:
            if session not in self._activity:
                found = {}
                projects = home() / ".claude" / "projects"
                try:
                    metas = list(projects.glob("*/%s/subagents/*.meta.json" % session))
                except OSError:
                    metas = []
                for meta in metas:
                    try:
                        with open(meta, encoding="utf-8") as handle:
                            data = json.loads(handle.read(65536))
                        # worktreePath, inheritedWorktreePath (most metas), and any future *WorktreePath key
                        wheres = [v for k, v in data.items() if isinstance(k, str) and k.endswith("orktreePath")
                                  and isinstance(v, str) and v] if isinstance(data, dict) else []
                        if not wheres:
                            continue
                        transcript = meta.with_name(meta.name[:-len(".meta.json")] + ".jsonl")
                        mtime = transcript.stat().st_mtime
                    except (OSError, ValueError):
                        continue
                    for where in wheres:
                        key = os.path.realpath(where)
                        found[key] = max(found.get(key, 0.0), mtime)
                self._activity[session] = found
            return self._activity[session].get(os.path.realpath(worktree))


def pushed(path: Path, ctx: Context) -> str:
    """Reason HEAD is safely on a live remote branch, else raise Refuse."""
    code, head = git(path, "rev-parse", "--verify", "HEAD^{commit}")
    head = head.strip()
    if code != 0 or not head:
        raise Refuse("no HEAD")
    code, remotes = git(path, "remote", "-v")
    if code != 0:
        raise Refuse("cannot list remotes")
    urls = {}
    for line in remotes.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[2] == "(fetch)":
            urls.setdefault(parts[0], parts[1])
    candidates = [(name, url) for name, url in sorted(urls.items()) if ctx.remote_allowed(url)]
    if not candidates:
        raise Refuse("no remote on an allowed network host (%s); a local or file remote is no proof of a push"
                     % ", ".join(ALLOWED_HOSTS))
    unanswered = False
    for name, url in candidates:
        prefix = "refs/remotes/%s/" % name
        code, refs = git(path, "for-each-ref", "--contains", head, "--format=%(refname) %(objectname)", prefix)
        if code != 0:
            continue
        rows = [ln.split() for ln in refs.splitlines() if len(ln.split()) == 2]
        rows = [(ref, sha) for ref, sha in rows if ref.startswith(prefix) and ref != prefix + "HEAD"]
        if not rows:
            continue
        live = ctx.listing(url)
        if live is None:
            unanswered = True
            continue
        for ref, sha in rows:
            if live.get("refs/heads/" + ref[len(prefix):]) == sha:
                check_reflog_pushed(path, [ctx.listing(u) for _, u in candidates])
                return "pushed: %s equals the live tip on %s" % (ref, remote_host(url) or name)
    if unanswered:
        raise Refuse("cannot verify push: the remote did not answer ls-remote")
    raise Refuse("HEAD is on no live remote branch tip (unpushed, or a stale or hand-set tracking ref)")


def check_reflog_pushed(path: Path, listings) -> None:
    """Raise Refuse when the worktree's own HEAD reflog holds a commit that no live remote head contains: work an
    agent committed and then reset away exists only in this worktree's reflog, which `worktree remove` deletes."""
    code, reflog = git(path, "reflog", "show", "--format=%H", "HEAD")
    if code != 0:
        raise Refuse("cannot read the worktree's reflog")
    shas = sorted({ln.strip() for ln in reflog.splitlines() if re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", ln.strip())})
    if not shas:
        return
    live = sorted({sha for listing in listings if listing for sha in listing.values()
                   if re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", str(sha))})
    present = []
    if live:  # a live sha this clone lacks cannot be negated; leaving it out only lists more, never hides a commit
        code, out = git(path, "cat-file", "--batch-check=%(objectname) %(objecttype)", stdin="\n".join(live) + "\n")
        present = [ln.split()[0] for ln in out.splitlines() if ln.endswith(" commit")] if code == 0 else []
    code, extra = git(path, "rev-list", "--max-count=1", "--stdin",
                      stdin="".join("%s\n" % sha for sha in shas) + "".join("^%s\n" % sha for sha in present))
    if code != 0 or extra.strip():
        raise Refuse("the worktree's reflog holds a commit on no live remote branch (reset or rebased-away work)")


# ---------------------------------------------------------------- verdicts


def agent_log_idle_hours(worktree: Path, session: str):
    """Hours since the agent's own log was written; None when the log cannot be found (treated as not finished)."""
    candidate = home() / ".claude" / "wals" / session / ("%s.jsonl" % worktree.name)  # agent-<id>
    try:
        return (time.time() - candidate.stat().st_mtime) / 3600.0
    except OSError:
        return None


def session_of(path: Path, root: Path):
    try:
        return path.relative_to(root).parts[0]
    except (ValueError, IndexError):
        return None


def _repo_of(worktree: Path):
    """The main repository of an agent worktree, else None. Requires the shape `<repo>/.claude/worktrees/agent-*`, a
    `.git` FILE (a `.git` directory is a main checkout) whose gitdir, resolved against the worktree when relative,
    is `<repo>/.git/worktrees/<name>`."""
    wt = Path(worktree)
    if not (wt.name.startswith("agent-") and wt.parent.name == "worktrees" and wt.parent.parent.name == ".claude"):
        return None
    repo = wt.parent.parent.parent
    dotgit = wt / ".git"
    try:
        if dotgit.is_symlink() or not dotgit.is_file():
            return None
        common = repo / ".git"
        if common.is_symlink() or not common.is_dir():
            return None
        with open(dotgit, encoding="utf-8", errors="replace") as handle:
            line = handle.read(4096).splitlines()[0].strip()
    except (OSError, IndexError):
        return None
    if not line.startswith("gitdir:"):
        return None
    gitdir = Path(line[len("gitdir:"):].strip())
    if not gitdir.is_absolute():
        gitdir = wt / gitdir
    if os.path.dirname(os.path.realpath(gitdir)) != os.path.realpath(common / "worktrees"):
        return None
    return repo


def worktree_locked(path: Path):
    """True when `git worktree list --porcelain` marks this worktree locked; None when it cannot be told."""
    code, listing = git(path, "worktree", "list", "--porcelain")
    if code != 0:
        return None
    me, current, locked = os.path.realpath(path), None, False
    for line in listing.splitlines() + [""]:
        if line.startswith("worktree "):
            current, locked = os.path.realpath(line[len("worktree "):]), False
        elif line == "locked" or line.startswith("locked "):
            locked = True
        elif line == "" and current is not None:
            if current == me:
                return locked
            current = None
    return None


def check_worktree_contents(path: Path) -> None:
    """Raise Refuse unless removing the worktree loses no file: no change, no untracked file, no hidden index entry,
    no submodule, and every ignored entry is a build or dependency folder that holds nothing unique (F2)."""
    code, status = git(path, "status", "--porcelain=v1", "--untracked-files=all", "-z")
    if code != 0:
        raise Refuse("git status failed")
    if status:
        raise Refuse("changed or untracked files: %s" % status.split("\0")[0][:60])
    code, staged = git(path, "ls-files", "-s", "-z")
    if code != 0 or any(rec.startswith("160000 ") for rec in staged.split("\0")):
        raise Refuse("has submodules (their commits are not checked)")
    code, flagged = git(path, "ls-files", "-v", "-z")
    if code != 0 or any(len(rec) > 2 and (rec[0].islower() or rec[0] == "S") for rec in flagged.split("\0")):
        raise Refuse("an index entry is assume-unchanged or skip-worktree, so status cannot see its changes")
    code, ignored = git(path, "status", "--porcelain=v1", "--ignored=traditional", "--untracked-files=normal", "-z")
    if code != 0:
        raise Refuse("git status --ignored failed")
    for rec in ignored.split("\0"):
        if not rec:
            continue
        if not rec.startswith("!! ") or not regenerable_ignored(rec[3:]):
            raise Refuse("ignored entry is not rebuildable output and would be lost: %s" % rec[3:][:80])
        if rec.endswith("/"):
            rel = rec[3:].rstrip("/")
            try:
                scan_folder(path / rel, rel.rsplit("/", 1)[-1])
            except Refuse as why:
                raise Refuse("ignored folder %s/ %s" % (rel[:60], why))


def worktree_verdict(path: Path, root: Path, idle_hours: float, used, ctx: Context = None) -> tuple:
    """(ok, reason). ok only when removing the worktree loses nothing."""
    ctx = ctx or Context(root, idle_hours)
    try:
        if _repo_of(path) is None:
            raise Refuse("not an agent worktree: needs <repo>/.claude/worktrees/agent-* with a .git file into <repo>/.git/worktrees")
        session = session_of(path, root)
        idle = agent_log_idle_hours(path, session) if session else None
        if idle is None:
            raise Refuse("no agent log found: cannot tell whether the agent finished")
        if idle < idle_hours:
            raise Refuse("agent log written %.1f h ago (< %.1f h)" % (idle, idle_hours))
        written = ctx.subagent_written(session, path)
        if written is not None and (time.time() - written) / 3600.0 < idle_hours:
            raise Refuse("a sub-agent transcript naming this worktree was written %.1f h ago" % ((time.time() - written) / 3600.0))
        if busy(path, used, root):
            raise Refuse("a process uses a path inside it (or the process list was unreadable)")
        locked = worktree_locked(path)
        if locked is None:
            raise Refuse("cannot tell whether the worktree is locked")
        if locked:
            raise Refuse("the worktree is locked (git worktree lock)")
        check_worktree_contents(path)
        return True, "finished, clean, " + pushed(path, ctx)
    except Refuse as why:
        return False, str(why)


def enclosing_worktree(path: Path):
    for parent in path.parents:
        if parent.parent.name == "worktrees" and parent.parent.parent.name == ".claude" and parent.name.startswith("agent-"):
            return parent
    return None


def _protected_location(path: Path, root: Path) -> bool:
    try:
        parts = path.relative_to(root).parts
    except ValueError:
        return True
    for i, part in enumerate(parts[:-1]):
        low = part.casefold()
        if low == ".claude":
            if i + 1 < len(parts) and parts[i + 1] == "worktrees":
                continue
            return True
        if low in PROTECTED_NAMES:
            return True
    return False


def regen_verdict(path: Path, used, root: Path = None, idle_hours: float = MIN_IDLE_HOURS, ctx: Context = None) -> tuple:
    """(ok, reason) for a rebuildable-folder candidate; re-run in full by apply."""
    try:
        if path.name not in REGEN_NAMES:
            raise Refuse("not a rebuildable folder name")
        if path.is_symlink() or not path.is_dir():
            raise Refuse("not a real directory")
        if root is None:
            raise Refuse("no work root given")
        if _protected_location(path, root):
            raise Refuse("inside .git, a session-log, state or Claude folder")
        ctx = ctx or Context(root, idle_hours)
        owner = enclosing_worktree(path)
        if owner is not None:  # a live agent is probably using its own dependencies
            idle = agent_log_idle_hours(owner, session_of(owner, root) or "")
            if idle is None or idle < idle_hours:
                raise Refuse("its agent worktree is not finished (log idle %s h)" % ("?" if idle is None else "%.1f" % idle))
            written = ctx.subagent_written(session_of(owner, root) or "", owner)
            if written is not None and (time.time() - written) / 3600.0 < idle_hours:
                raise Refuse("a sub-agent working in its worktree wrote its transcript recently")
        else:
            try:
                changed = (time.time() - path.stat().st_mtime) / 3600.0
            except OSError:
                raise Refuse("cannot stat")
            if changed < idle_hours:
                raise Refuse("changed %.1f h ago (< %.1f h)" % (changed, idle_hours))
        if busy(path, used, root):
            raise Refuse("a process uses a path inside it or at its repository root (or the process list was unreadable)")
        origin = check_regen_origin(path, root)
        scan_folder(path, path.name)
        return True, "rebuildable folder (%s)" % origin
    except Refuse as why:
        return False, str(why)


# ---------------------------------------------------------------- plan and apply


def scan(root: Path, deadline: float, state: dict = None):
    """Yield (kind, path) candidates. Does not descend into candidates, .git or protected folders. Sets
    state['partial'] when the deadline cut the walk short."""
    stack = [(root, 0)]
    while stack:
        if time.monotonic() >= deadline:
            if state is not None:
                state["partial"] = True
            return
        base, depth = stack.pop()
        try:
            entries = sorted(os.scandir(base), key=lambda e: e.name)
        except OSError:
            continue
        for entry in entries:
            try:
                if entry.is_symlink() or not entry.is_dir(follow_symlinks=False):
                    continue
            except OSError:
                continue
            name, path = entry.name, Path(entry.path)
            if base.name == "worktrees" and base.parent.name == ".claude" and name.startswith("agent-"):
                yield "worktree", path
                stack.append((path, depth + 1))  # its rebuildable folders are judged too
                continue
            if name in REGEN_NAMES:
                yield "regen", path
                continue
            if name in PROTECTED_NAMES and not (name == ".claude"):
                continue
            if depth + 1 < MAX_DEPTH:
                stack.append((path, depth + 1))


def check_idle_hours(idle_hours) -> float:
    try:
        value = float(idle_hours)
    except (TypeError, ValueError):
        raise ValueError("idle hours must be a number")
    if not value >= MIN_IDLE_HOURS:
        raise ValueError("idle hours must be at least %.0f (got %s)" % (MIN_IDLE_HOURS, idle_hours))
    return value


def items_digest(items) -> str:
    return hashlib.sha256(json.dumps(items, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def seal(plan: dict) -> dict:
    """Record an unkeyed sha256 of the plan's items: apply refuses a plan edited by accident or by hand without
    recomputing it. It is not authentication; apply re-verifies every item regardless."""
    plan["items_sha256"] = items_digest(plan.get("items", []))
    return plan


def make_plan(root: Path, idle_hours: float, workers=8, remote_allowed=None, ls_remote=None) -> dict:
    idle_hours = check_idle_hours(idle_hours)
    root = Path(os.path.realpath(root))
    used = in_use_paths()  # ONE snapshot of every path a process uses, for the whole plan
    ctx = Context(root, idle_hours, remote_allowed, ls_remote)
    state = {"partial": False}
    found = list(scan(root, time.monotonic() + SCAN_SECONDS, state))
    items = []

    def judge(item):
        kind, path = item
        if kind == "worktree":
            ok, reason = worktree_verdict(path, root, idle_hours, used, ctx)
        else:
            ok, reason = regen_verdict(path, used, root, idle_hours, ctx)
        return {"kind": kind, "path": str(path), "ok": ok, "reason": reason,
                "bytes": disk_bytes(path) if ok else 0}

    with ThreadPoolExecutor(max_workers=workers) as pool:
        for row in pool.map(judge, found):
            items.append(row)
    # a regen folder inside a worktree that is itself removed is counted once, under the worktree
    removed = [Path(i["path"]) for i in items if i["kind"] == "worktree" and i["ok"]]
    for i in items:
        if i["kind"] == "regen" and i["ok"] and any(str(Path(i["path"])).startswith(str(w) + "/") for w in removed):
            i["ok"], i["reason"], i["bytes"] = False, "inside a worktree that is removed whole", 0
    return seal({"root": str(root), "at": time.time(), "idle_hours": idle_hours, "partial": state["partial"],
                 "items": items, "total_bytes": sum(i["bytes"] for i in items if i["ok"])})


def record(row: dict) -> None:
    path = audit_path()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(row) + "\n")


@contextlib.contextmanager
def exclusive_lock():
    path = lock_path()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(str(path), os.O_RDWR | os.O_CREAT, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raise RuntimeError("another work_gc apply is running (lock %s held)" % path)
        try:
            yield
        finally:
            fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


def remove_tree(path: Path) -> None:
    """shutil.rmtree that, once per folder inside `path`, adds u+w to a read-only folder and retries."""
    top = os.path.realpath(path)
    fixed = set()

    def onerror(func, failed, exc_info):
        error = exc_info[1]
        parent = os.path.dirname(failed)
        inside = parent == top or parent.startswith(top + "/")
        if isinstance(error, PermissionError) and func in (os.unlink, os.remove, os.rmdir) and inside \
                and parent not in fixed:
            fixed.add(parent)
            os.chmod(parent, stat.S_IMODE(os.lstat(parent).st_mode) | stat.S_IWUSR | stat.S_IXUSR | stat.S_IRUSR)
            func(failed)
            return
        raise error

    shutil.rmtree(str(path), onerror=onerror)


def path_in_root(path, root_real: str) -> bool:
    """True only for a normalized path with no symlink anywhere on it, strictly inside the (real) work root."""
    real = os.path.realpath(path)
    return real == str(path) and real.startswith(root_real.rstrip("/") + "/")


OUTSIDE_ROOT = "path is a symlink, not normalized, or outside the work root"


def _apply_one(item: dict, root: Path, root_real: str, idle: float, ctx: Context, row: dict) -> None:
    path = Path(item["path"])
    kind = item.get("kind")
    if not path_in_root(path, root_real):
        row.update(status="skipped", reason=OUTSIDE_ROOT)
        return
    if kind not in ("worktree", "regen"):
        row.update(status="skipped", reason="unknown kind")
        return
    used = in_use_paths()  # a fresh snapshot right before this item, not the one the plan or an earlier item saw
    if kind == "worktree":
        ok, reason = worktree_verdict(path, root, idle, used, ctx)
    else:
        ok, reason = regen_verdict(path, used, root, idle, ctx)
    row.update(reason=reason)
    if not ok:
        row["status"] = "skipped"
        return
    if not path_in_root(path, root_real):  # swapped for a symlink between the verdict and now
        row.update(status="skipped", reason=OUTSIDE_ROOT + " (changed after the check)")
        return
    record(dict(row, status="removing"))  # the intent row comes first: no removal is ever unrecorded
    if kind == "worktree":
        repo = _repo_of(path)
        if repo is None or not path_in_root(path, root_real):
            raise RuntimeError("the worktree changed after the check")
        code, _ = git(repo, "worktree", "remove", "--force", str(path), timeout=600)
        row["status"] = "removed" if code == 0 and not os.path.lexists(path) else "failed"
        if row["status"] == "failed":
            row["error"] = "git worktree remove exited %d%s" % (code, " but the folder is still there" if code == 0 else "")
    else:
        remove_tree(path)
        row["status"] = "removed" if not os.path.lexists(path) else "failed"


def apply_plan(plan: dict, root: Path, idle_hours: float = MIN_IDLE_HOURS, remote_allowed=None, ls_remote=None) -> list:
    """Re-verify and remove each ok item of a plan produced by make_plan. The idle time comes from the caller, never
    from the plan. Raises ValueError for a hand-edited plan or idle hours under the minimum, RuntimeError when another
    apply holds the lock. Returns result rows (every row is also appended to the audit log)."""
    idle = check_idle_hours(idle_hours)
    items = plan.get("items") if isinstance(plan, dict) else None
    if not isinstance(items, list) or plan.get("items_sha256") != items_digest(items):
        raise ValueError("the plan's items do not match its sha256: a hand-edited or foreign plan is refused")
    root = Path(os.path.realpath(root))
    if plan.get("root") and os.path.realpath(plan["root"]) != str(root):
        raise ValueError("the plan was made for %s, not %s" % (plan["root"], root))
    results = []
    with exclusive_lock():
        ctx = Context(root, idle, remote_allowed, ls_remote)
        root_real = os.path.realpath(root)
        for item in items:
            if not isinstance(item, dict) or not item.get("ok"):
                continue
            row = {"at": time.time(), "path": str(item.get("path")), "kind": str(item.get("kind")),
                   "bytes": item.get("bytes", 0) if isinstance(item.get("bytes", 0), int) else 0}
            try:
                _apply_one(item, root, root_real, idle, ctx, row)
                record(row)
            except Exception as error:  # noqa: BLE001 - one bad item must not stop the run or go unrecorded
                row.update(status="failed", error="%s: %s" % (type(error).__name__, error))
                try:
                    record(row)
                except Exception as audit_error:  # noqa: BLE001 - say so loudly, keep going
                    row["audit_error"] = "%s: %s" % (type(audit_error).__name__, audit_error)
                    print("work_gc: could not write the audit row for %s: %s" % (row["path"], audit_error),
                          file=sys.stderr)
            results.append(row)
    return results


def human(n: int) -> str:
    return "%.1f GiB" % (n / 2**30) if n >= 2**30 else "%.0f MiB" % (n / 2**20)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("plan")
    p.add_argument("--root")
    p.add_argument("--idle-hours", type=float, default=MIN_IDLE_HOURS)
    p.add_argument("--out")
    a = sub.add_parser("apply")
    a.add_argument("--plan", required=True)
    a.add_argument("--root")
    a.add_argument("--idle-hours", type=float, default=MIN_IDLE_HOURS)
    args = parser.parse_args(argv)
    root = Path(args.root) if args.root else work_root()
    try:
        check_idle_hours(args.idle_hours)
    except ValueError as error:
        print("work_gc: %s" % error, file=sys.stderr)
        return 2
    if args.cmd == "plan":
        plan = make_plan(root, args.idle_hours)
        if args.out:
            Path(args.out).write_text(json.dumps(plan, indent=1))
        for row in sorted(plan["items"], key=lambda r: -r["bytes"]):
            if row["ok"]:
                print("%10s  %-8s %s" % (human(row["bytes"]), row["kind"], row["path"]))
        kept = sum(1 for r in plan["items"] if not r["ok"] and r["kind"] == "worktree")
        print("reclaimable: %s in %d item(s); %d worktree(s) kept (not finished, dirty, unpushed or unverifiable)" % (
            human(plan["total_bytes"]), sum(1 for r in plan["items"] if r["ok"]), kept))
        if plan.get("partial"):
            print("WARNING: the scan stopped after %.0f s; the plan is partial (more may be reclaimable)" % SCAN_SECONDS)
        return 0
    try:
        plan = json.loads(Path(args.plan).read_text())
        results = apply_plan(plan, root, args.idle_hours)
    except (OSError, ValueError, RuntimeError) as error:
        print("work_gc: %s" % error, file=sys.stderr)
        return 2
    freed = sum(r["bytes"] for r in results if r["status"] == "removed")
    for r in results:
        detail = "" if r["status"] == "removed" else r.get("error") or r.get("reason", "")
        print("%-8s %-8s %s %s" % (r["status"], r["kind"], r["path"], detail))
    print("removed %s in %d item(s)" % (human(freed), sum(1 for r in results if r["status"] == "removed")))
    return 0 if not any(r["status"] == "failed" for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())
