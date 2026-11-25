#!/usr/bin/env python3
"""`ah reap`: remove what finished sessions left on disk, after saving what exists nowhere else (docs/lifecycle.md).

    ah reap scan [--json] [--loose DIR ...] [--check-remote]                                       read only
    ah reap run [--apply] [--idle-hours N] [--if-above PCT] [--session ID ...] [--path PATH ...]
    ah co <owner/repo | URL> [--ref REF] [--name NAME]                    a checkout in the session folder

The path is the owner: a folder directly under ~/.agent-harness/work belongs to the session it is named after, and
`--path` names one other folder exactly. Nothing here reads command text or blocks a tool call, and `run` changes
nothing without --apply. In a folder idle long enough that no process uses, `run --apply` removes rebuildable
directories (node_modules, .venv, target, ...), the session's temp directory, every git checkout `git_save.save`
proves saved (children first), and the docker containers and volumes tied to that session. It never removes loose
files, a folder with a .keep file, a keep/ directory or a checkout that holds one, the calling session's own folder,
a symlink, a docker image or an unlabelled container. Unknown means keep: a git error, an unreadable directory, an
unproven save or a process inside the folder keeps the data, and the reason is printed. Every deletion is a row in
~/.agent-harness/logs/reap.jsonl, written before the deletion starts. Exit codes: 0 done or nothing to do,
1 something failed, 3 refused. Standard library only.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ah_local  # noqa: E402
import ah_log_push  # noqa: E402
import git_save  # noqa: E402
import workdir  # noqa: E402
from git_save import _git  # noqa: E402  (the one git runner: a timeout, no prompt, no pager, no repository hooks)

BIG_FILE = 100 * 1024 * 1024   # a larger file outside a checkout is reported by scan and never deleted
WALK_MAX = 3000000             # more entries than this in one folder: what it holds is unknown, so it is kept
DEFAULT_HOURS, DONE_HOURS = 48, 1
PRESSURE_HOURS, PRESSURE_DROP = 6, 5   # --if-above: the idle hours that are enough, and how far under PCT to stop
SESSION_ENV = ("AH_SESSION", "CLAUDE_SESSION_ID", "CLAUDE_CODE_SESSION_ID")


def _inside(path, root) -> bool:
    return path == root or path.startswith(root.rstrip(os.sep) + os.sep)


def _human(size) -> str:
    for unit in ("B", "KB", "MB"):
        if size < 1024:
            return ("%d %s" if unit == "B" else "%.1f %s") % (size, unit)
        size /= 1024.0
    return "%.1f GB" % size


def _size(path) -> int:
    return workdir._activity(Path(path), Path(path), WALK_MAX)[1]


def _disk_used(path):
    """Percent in use of the volume that holds `path`, or None when that cannot be read."""
    try:
        usage = shutil.disk_usage(path)
        return round(100.0 * (usage.total - usage.free) / usage.total, 1)
    except (OSError, ZeroDivisionError):
        return None


def _idle_default():
    hours = ah_local.get("reap_idle_hours")
    return hours if isinstance(hours, (int, float)) and not isinstance(hours, bool) and hours >= 0 else DEFAULT_HOURS


def _session():
    return next((os.environ[key] for key in SESSION_ENV if os.environ.get(key)), None)


def _dirs(parent, links=False) -> list:
    """Directories directly in `parent`, sorted; with `links` also symlinks (they are only ever reported)."""
    try:
        with os.scandir(parent) as entries:
            return sorted(e.path for e in entries if e.is_dir(follow_symlinks=False) or (links and e.is_symlink()))
    except OSError:
        return []


# ---- who is using a folder ------------------------------------------------------------------------------------

def _processes(proc="/proc"):
    """{pid: (parent pid, [working directory and open files])} for every process this user may inspect, or None when
    that cannot be found out (no /proc and no working lsof)."""
    table, pid = {}, None
    if os.path.isdir(os.path.join(proc, "self", "fd")):
        for pid in filter(str.isdigit, os.listdir(proc)):
            base = os.path.join(proc, pid)
            try:
                with open(os.path.join(base, "stat"), "rb") as handle:   # "pid (name) state parent ..."
                    parent = int(handle.read(4096).rsplit(b")", 1)[1].split()[1])
                names = ["cwd"] + ["fd/" + fd for fd in os.listdir(os.path.join(base, "fd"))]
            except (OSError, ValueError, IndexError):
                continue   # it has exited, or it is another user's process
            table[int(pid)] = (parent, [os.path.realpath(os.path.join(base, name)) for name in names])
        return table
    try:
        done = subprocess.run(["lsof", "-nP", "-F", "pRn"], capture_output=True, timeout=60, stdin=subprocess.DEVNULL)
    except (OSError, subprocess.SubprocessError):
        return None
    for line in done.stdout.decode("utf-8", "replace").splitlines():
        if line[:1] == "p" and line[1:].isdigit():
            pid = int(line[1:])
            table[pid] = (0, [])
        elif pid is not None and line[:1] == "R" and line[1:].isdigit():
            table[pid] = (int(line[1:]), table[pid][1])
        elif pid is not None and line[:1] == "n":
            table[pid][1].append(line[1:])
    return table if os.getpid() in table else None   # a listing without this very process told us nothing


def _users(table, roots):
    """Pids with a working directory or an open file inside one of `roots`. This process, its parents and its children
    never count: a check that sees itself refuses everything. None when the process table is unknown."""
    if table is None:
        return None
    me = os.getpid()
    skip, kids, more, pid = {me}, {me}, {me}, me
    while pid in table and table[pid][0] not in skip:
        pid = table[pid][0]
        skip.add(pid)
    while more:
        more = {p for p, (parent, _paths) in table.items() if parent in kids} - kids
        kids |= more
    return sorted(pid for pid, (_parent, paths) in table.items() if pid not in skip and pid not in kids
                  and any(_inside(path, root) for path in paths for root in roots))


def _in_use(look, table):
    users = _users(table, [root for root in (look["real"], look["tmp"]) if root])
    if users is None:
        return "cannot tell whether a process is using it"
    return "in use by process %s" % ", ".join(str(pid) for pid in users[:5]) if users else None


# ---- what a folder holds --------------------------------------------------------------------------------------

def _rebuildable(path, checkout) -> bool:
    """True when the directory is rebuildable output that may go unseen. Inside a checkout git must track nothing in
    it, and `dist` or `build` must also be ignored there."""
    if checkout is None or not git_save.rebuildable(path, ignored=True):
        return git_save.rebuildable(path)
    rel, plain = os.path.relpath(path, checkout), {"GIT_LITERAL_PATHSPECS": "0"}   # check-ignore refuses that setting
    if os.path.basename(path) in ("dist", "build") and _git(checkout, "check-ignore", "-q", "--", rel, env=plain)[0]:
        return False
    code, out, _err = _git(checkout, "ls-files", "-z", "--", rel)
    return code == 0 and not out


def _survey(folder) -> dict:
    """One walk that never enters .git, keep/ or a rebuildable directory. Read only. `newest` is the latest change
    of a file (directories do not count: removing a rebuildable directory changes its parent)."""
    found = {"checkouts": [], "rebuildable": [], "keep": [], "big": [], "newest": 0.0, "problem": None}
    stack, seen = [(folder, None)], 0
    while stack and not found["problem"]:
        current, checkout = stack.pop()
        try:
            with os.scandir(current) as handle:
                entries = list(handle)
        except OSError as error:
            found["problem"] = "unreadable directory %s (%s)" % (current, type(error).__name__)
            break
        seen += len(entries)
        if seen > WALK_MAX:
            found["problem"] = "more than %d entries to look through" % WALK_MAX
        if any(entry.name == ".git" for entry in entries):
            checkout = current
            found["checkouts"].append(current)
        for entry in entries:
            try:
                info = entry.stat(follow_symlinks=False)
            except OSError:
                continue
            if not stat.S_ISDIR(info.st_mode):
                found["newest"] = max(found["newest"], info.st_mtime)
                if checkout is None and stat.S_ISREG(info.st_mode) and info.st_size > BIG_FILE:
                    found["big"].append({"path": entry.path, "bytes": info.st_size})
            elif entry.name == "keep":
                found["keep"].append(entry.path)
            elif entry.name != ".git" and _rebuildable(entry.path, checkout):
                found["rebuildable"].append(entry.path)
            elif entry.name != ".git":
                stack.append((entry.path, checkout))
    return found


def _look(path, loose=False) -> dict:
    """What one folder is and holds: owner, last use, size, checkouts, rebuildable directories. Read only."""
    name = os.path.basename(path)
    look = {"path": path, "real": os.path.realpath(path), "name": name, "loose": loose, "owner": None, "tmp": None,
            "skip": None}
    if os.path.islink(path) or not os.path.isdir(path):
        look["skip"] = "a symlink, which is never followed"
        return look
    wal = Path(look["real"], workdir.MARKER)   # a loose folder has no session log: only its own files count
    if not loose:   # the owner is the folder name when that is a session id, else unknown
        wal, look["owner"] = workdir._wal_for(name), name if workdir.SESSION_UUID.fullmatch(name) else None
        try:
            with open(os.path.join(path, workdir.MARKER), "rb") as handle:
                recorded = json.loads(handle.read(65536).decode("utf-8")).get("session_id")
            if isinstance(recorded, str) and workdir.safe_name(recorded) == name:
                look["owner"] = recorded
        except (OSError, ValueError, AttributeError):
            pass
        tmp = git_save._home("tmp", name[:8])   # the TMPDIR session_env.py gives a session
        twins = [other for other in os.listdir(os.path.dirname(path)) if other[:8] == name[:8]]
        if workdir.SESSION_UUID.fullmatch(name) and twins == [name] and os.path.isdir(tmp) and not os.path.islink(tmp):
            look["tmp"] = os.path.realpath(tmp)
    signs = workdir._transcripts(look["owner"]) if look["owner"] else []   # a live session keeps writing these
    look.update(_survey(look["real"]), wal=str(wal))
    last, size, complete = workdir._activity(Path(look["real"]), wal, WALK_MAX,
                                             signs + ([Path(look["tmp"])] if look["tmp"] else []))
    look.update(last=last, bytes=size, complete=complete, keep_file=os.path.lexists(os.path.join(path, workdir.KEEP)),
                done=not loose and (os.path.lexists(os.path.join(path, workdir.DONE)) or workdir._marked_done(wal)))
    return look


def _why_not(look, hours, own, named, table):
    """Why this folder is left alone, or None when it may be reduced (then look["need"] and look["why"] are set)."""
    if look["skip"]:
        return look["skip"]
    if workdir._protected(Path(look["path"])):
        return "a protected path"
    if look["keep_file"]:
        return "has a .keep file"
    if not look["loose"] and look["name"] == own and look["name"] not in named:
        return "the calling session's own folder (name it with --session to include it)"
    if look["problem"] or not look["complete"]:
        return look["problem"] or "too large or unreadable to tell when it was last used"
    look["need"] = min(hours, DONE_HOURS) if look["done"] else hours
    idle = (time.time() - look["last"]) / 3600.0
    if idle < look["need"]:
        return "used %.1f hours ago, needs %g idle hours" % (idle, look["need"])
    look["why"] = "%sidle %.1f hours" % ("marked done, " if look["done"] else "", idle)
    return _in_use(look, table)


def _recheck(look):
    """Asked again right before deleting: why the folder may no longer be reduced, or None. What this run itself
    changes (objects a save writes in .git, the parents of what it removed) does not count as use."""
    if os.path.lexists(os.path.join(look["path"], workdir.KEEP)):
        return "has a .keep file"
    fresh = _survey(look["real"])
    signs = [Path(look["wal"])] + (workdir._transcripts(look["owner"]) if look["owner"] else [])
    last = max([fresh["newest"]] + [workdir._mtime(sign) for sign in signs])
    if (time.time() - last) / 3600.0 < look["need"]:
        return "used again while it was being cleaned"
    return fresh["problem"] or _in_use(look, _processes())


def _borrowed(checkouts) -> dict:
    """{object directory: [checkouts that borrow from it through objects/info/alternates]}."""
    found = {}
    for repo in checkouts:
        objects = os.path.join(repo, ".git", "objects")
        try:
            with open(os.path.join(objects, "info", "alternates"), errors="surrogateescape") as handle:
                lines = [line.strip() for line in handle.read(262144).splitlines()]
        except OSError:
            continue   # nearly always: there is no such file
        for line in lines:
            if line[:1] not in ("", "#"):
                found.setdefault(os.path.realpath(os.path.join(objects, line)), []).append(repo)
    return found


def _order(repos, borrowed):
    """Children first: a nested checkout, a linked worktree and a borrower come before what they sit in or depend on.
    Returns (order, facts, before, outside, circle): before[p] is what must go before p may, outside[p] names a path
    outside this folder that depends on p, and circle holds checkouts whose dependencies never resolve."""
    facts = {repo: git_save.facts(repo) for repo in repos}
    before, outside = {repo: set() for repo in repos}, {}
    for repo, f in facts.items():
        before[repo].update(other for other in repos if other != repo and _inside(other, repo))
        if f["errors"] or f["linked_worktree"]:
            continue   # a linked worktree owns no object store: nothing can depend on it
        users = [(os.path.realpath(path), "is a linked worktree of it") for path in f["worktrees"]]
        users += [(path, "borrows its objects") for path in
                  borrowed.get(os.path.realpath(os.path.join(f["common_dir"], "objects")), ()) if os.path.isdir(path)]
        for user, how in users:
            if user in before:
                before[repo].update({user} - {repo})
            else:
                outside[repo] = "%s %s" % (user, how)
    order, left = [], dict(before)
    while left:
        ready = sorted(repo for repo in left if not left[repo] & left.keys())
        if not ready:
            break
        order += ready
        left = {repo: needs for repo, needs in left.items() if repo not in ready}
    return order + sorted(left), facts, before, outside, set(left)


def _summary(repo, f, check_remote=False) -> dict:
    """{"path", "state": "saved" | "unsaved" | "unknown", "why": [...], "text"} for one checkout. Read only. The
    remote is asked only with check_remote; without it the remote-tracking refs answer."""
    unsaved = ["changed files"] * f["dirty"] + ["%d untracked files" % f["untracked"]] * bool(f["untracked"])
    unsaved += ["%d stashes" % len(f["stashes"])] * bool(f["stashes"])
    unknown, tips, real = f["errors"][:1], f["tips"], f["real_remote"]
    if tips and not real:
        unsaved.append("no remote off this host")
    elif tips and check_remote:
        names, state = git_save.unsaved_tips(repo, f, real)
        unknown += ["the remote did not answer"] * (state == "unknown")
        unsaved += ["not on the remote: " + ", ".join(names[:5])] * bool(names and state == "known")
    elif tips and f["origin"] != real:
        unknown.append("its origin is a local path (--check-remote asks the real remote)")
    elif tips:
        code, out, _err = _git(repo, "rev-list", "-1", "--stdin", "--not", "--remotes",
                               stdin="".join(sha + "\n" for sha in sorted(set(tips.values()))))
        unknown += ["git could not compare it with its remote-tracking refs"] * (code != 0)
        unsaved += ["commits not on its remote-tracking refs"] * bool(code == 0 and out.strip())
    state = "unknown" if f["errors"] else "unsaved" if unsaved else "unknown" if unknown else "saved"
    return {"path": repo, "state": state, "why": unsaved + unknown,
            "text": ": ".join([state] + [", ".join(unsaved + unknown)] * bool(unsaved + unknown))}


def _docker(*args, timeout=30):
    """stdout of one docker call, or None when it fails or does not answer in time."""
    try:
        done = subprocess.run(["docker", *args], capture_output=True, text=True, timeout=timeout,
                              stdin=subprocess.DEVNULL)
    except (OSError, subprocess.SubprocessError):
        return None
    return done.stdout if done.returncode == 0 else None


def _docker_list(looks):
    """Containers and volumes as [{kind, id, name, session, folder, state}], or None when docker does not answer
    within 5 seconds. `folder` is the session folder a thing is tied to, by its ah.session label or by a bind mount
    below that folder; None means unlabelled, and an unlabelled thing is only ever reported."""
    ids = _docker("ps", "-aq", "--no-trunc", timeout=5)
    names = _docker("volume", "ls", "-q", timeout=5) if ids is not None else None
    try:
        containers = json.loads(_docker("inspect", *ids.split()) or "") if ids.split() else []
        volumes = json.loads(_docker("volume", "inspect", *names.split()) or "") if names.split() else []
    except (ValueError, AttributeError):
        return None
    looks = [look for look in looks if not look["skip"]]
    folders = {key: look["real"] for look in looks if not look["loose"] for key in (look["owner"], look["name"]) if key}

    def thing(kind, ident, name, labels, binds, state):
        label = (labels or {}).get("ah.session")
        folder = folders.get(label or "") or next((look["real"] for look in looks for bind in binds
                                                   if bind and _inside(os.path.realpath(bind), look["real"])), None)
        return {"kind": kind, "id": ident, "name": name, "session": label, "folder": folder, "state": state}

    return ([thing("container", c.get("Id"), str(c.get("Name") or "").lstrip("/"),
                   (c.get("Config") or {}).get("Labels"),
                   [m.get("Source") for m in c.get("Mounts") or [] if m.get("Type") == "bind"],
                   (c.get("State") or {}).get("Status")) for c in containers]
            + [thing("volume", v.get("Name"), v.get("Name"), v.get("Labels"), [], None) for v in volumes])


# ---- run ------------------------------------------------------------------------------------------------------

def _remove(path) -> None:
    """Delete a tree without following a symlink. Directories are made writable first (a read-only Go module cache
    stops a plain removal half way); files are never changed, because a file may be a hard link into a shared store."""
    own = {"follow_symlinks": False} if os.chmod in os.supports_follow_symlinks else {}
    stack = [path]
    while stack:
        current = stack.pop()
        mode = os.lstat(current).st_mode
        if stat.S_ISDIR(mode):
            if stat.S_IMODE(mode) & 0o700 != 0o700:
                os.chmod(current, stat.S_IMODE(mode) | 0o700, **own)
            stack.extend(_dirs(current))
    shutil.rmtree(path)


def _unproven(result, folder):
    """Why a save result does not allow the deletion, or None when it does."""
    if not result.get("ok"):
        return "not saved: %s" % (result.get("reason") or "no reason given")
    if any(result.get(key) and _inside(os.path.realpath(result[key]), folder) for key in ("bundle", "held_dir")):
        return "its saved copy would be inside the folder being removed"
    return None


class _Run:
    """One `ah reap run`: prints each decision and, with --apply, logs it and carries it out."""

    def __init__(self, apply):
        self.apply, self.failed, self.freed = apply, False, 0

    def note(self, action, kind, path, look, reason=None, size=None, saved=None) -> bool:
        """Print one line; on an --apply run also append the row to reap.jsonl. False: the row could not be written,
        and then nothing may be deleted."""
        shown = action if self.apply or action == "left" else "would " + {"removed": "remove", "kept": "keep"}[action]
        line = "  ".join(str(x) for x in (shown, kind, None if size is None else _human(size), path, reason) if x)
        print(line.encode("utf-8", "backslashreplace").decode("utf-8"))   # a path may hold bytes that are not text
        if not self.apply or action == "left":
            return True
        row = {"time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "host": ah_log_push._host(),
               "session": look["owner"] or (None if look["loose"] else look["name"]), "path": path, "bytes": size,
               "kind": kind, "action": action, "saved": saved, "reason": reason}
        try:
            log = git_save._home("logs", "reap.jsonl")
            git_save._mkdirs(os.path.dirname(log))
            with os.fdopen(os.open(log, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600), "a") as handle:
                handle.write(json.dumps(row, sort_keys=True) + "\n")
        except OSError as error:
            self.failed = True
            print("ah reap: cannot write the log (%s), so nothing is deleted" % type(error).__name__, file=sys.stderr)
            return False
        return True

    def remove(self, look, kind, path, saved=None, reason=None) -> bool:
        """Log one deletion, then do it. True when the tree is gone."""
        size = _size(path)
        if not self.note("removed", kind, path, look, reason or look["why"], size, saved) or not self.apply:
            return False
        try:
            _remove(path)
        except OSError as error:
            self.failed = True
            self.note("failed", kind, path, look, "partly removed: %s" % type(error).__name__)
            return False
        self.freed += size
        return True

    def reduce(self, look, borrowed, things) -> None:
        """Steps 1 to 6 for one eligible folder: rebuildable output, then checkouts (save, check again, delete), then
        the session's containers and volumes."""
        top, session = look["real"], "loose" if look["loose"] else look["name"]   # the names autosave.py saves under
        why = _recheck(look) if self.apply else None
        for path in [] if why else sorted(look["rebuildable"]) + [look["tmp"]] * bool(look["tmp"]):
            self.remove(look, "tmp" if path == look["tmp"] else "rebuildable", path)
        order, facts, before, outside, circle = ([], {}, {}, {}, ()) if why else _order(look["checkouts"], borrowed)
        saved, kept = {}, {}
        for repo in order:
            holds = next((path for path in look["keep"] if _inside(path, repo)), None)
            blocker = next((other for other in sorted(before[repo]) if other in kept), None)
            if facts[repo]["errors"]:
                kept[repo] = "git cannot read it: %s" % facts[repo]["errors"][0]
            elif os.path.realpath(facts[repo]["toplevel"] or "") != repo:
                kept[repo] = "git does not see a checkout of its own here"
            elif repo in circle:
                kept[repo] = "it and another checkout depend on each other in a circle"
            elif repo in outside:
                kept[repo] = outside[repo]
            elif holds:
                kept[repo] = "holds %s, which is never removed" % holds
            elif blocker:
                kept[repo] = "%s is kept, and it is inside this checkout or depends on it" % blocker
            elif self.apply:
                name = os.path.relpath(repo, top) if repo != top else look["name"] if look["loose"] else "top"
                saved[repo] = git_save.save(repo, session, name, fresh=True)   # fresh: proven now, not remembered
                if _unproven(saved[repo], top):
                    kept[repo] = _unproven(saved[repo], top)
            else:
                self.remove(look, "checkout", repo, reason="once its work is proven saved (now %s)"
                            % _summary(repo, facts[repo])["text"])
            if repo in kept:
                self.note("kept", "checkout", repo, look, kept[repo])
        why = why or (_recheck(look) if saved else None)   # the saves took time: still idle, still unused?
        if why:
            self.note("kept", "folder", top, look, why)
            return
        for repo in [repo for repo in order if repo in saved and repo not in kept]:
            proof = dict({key: saved[repo].get(key) for key in ("where", "url", "refs", "bundle", "held_dir")},
                         held=len(saved[repo].get("held") or ()))
            f = facts[repo]   # a removed linked worktree leaves an entry in its repository: drop it, as git would
            if (self.remove(look, "checkout", repo, proof) and f["linked_worktree"]
                    and os.path.dirname(f["git_dir"]) == os.path.join(f["common_dir"], "worktrees")):
                shutil.rmtree(f["git_dir"], ignore_errors=True)
        for thing in sorted((t for t in things or () if t["folder"] == top), key=lambda t: t["kind"]):
            plain = re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", str(thing["id"]))
            if plain and self.note("removed", thing["kind"], thing["name"], look, look["why"]) and self.apply:
                if thing["kind"] == "container":   # only this session's own: never an image, never a prune
                    _docker("stop", thing["id"], timeout=60)
                    gone = _docker("rm", "-v", thing["id"]) is not None
                else:
                    gone = _docker("volume", "rm", thing["id"]) is not None
                if not gone:
                    self.failed = True
                    self.note("failed", thing["kind"], thing["name"], look, "docker did not remove it")


def _run(args) -> int:
    root, mine = os.path.realpath(str(workdir.work_root())), os.path.realpath(git_save._home())
    home, folders, paths = os.path.realpath(str(Path.home())), _dirs(root, links=True), []
    named = {workdir.safe_name(session) for session in args.session}
    missing, refused = sorted(named - {os.path.basename(path) for path in folders}), None
    if args.apply and not getattr(shutil.rmtree, "avoids_symlink_attacks", False):
        refused = "this platform cannot delete a tree without following symlinks"
    elif args.if_above is not None and not PRESSURE_DROP < args.if_above <= 100:
        refused = "--if-above takes a percentage above %d and up to 100" % PRESSURE_DROP
    elif missing:
        refused = "no folder under %s for session %s" % (root, ", ".join(missing))
    for given in [] if refused else args.path:
        plain = os.path.abspath(os.path.expanduser(given))
        real = os.path.realpath(plain)
        paths.append(real)
        if (os.path.islink(plain) or not os.path.isdir(real) or workdir._protected(Path(real)) or _inside(real, mine)
                or _inside(home, real)):
            refused = ("--path %s must be a real directory, and not the home folder, a folder that holds it, or "
                       "anything under ~/.agent-harness, ~/.claude or ~/.codex (--session names a session)" % given)
    if refused:
        print("ah reap: " + refused, file=sys.stderr)
        return 3
    used = _disk_used(root) if args.if_above is not None else None
    if args.if_above is not None and (used is None or used < args.if_above):
        print("the disk is %s, under %g%%: nothing to do" % ("unreadable" if used is None else "%g%% full" % used,
                                                               args.if_above))
        return 0
    hours = args.idle_hours
    if hours is None:
        hours = PRESSURE_HOURS if args.if_above is not None else _idle_default()
    every = not (named or paths)
    chosen = [_look(path) for path in folders if every or os.path.basename(path) in named]
    chosen += [_look(path, loose=True) for path in paths]
    rest = [path for path in folders if not every and os.path.basename(path) not in named and not os.path.islink(path)]
    # who borrows objects is asked of the whole work root, two levels below the home folder and beside each --path
    near = [path for parent in [home] + [os.path.dirname(path) for path in paths]
            for first in _dirs(parent) for path in [first] + _dirs(first)]
    borrowed = _borrowed([repo for look in chosen for repo in look.get("checkouts", ())] + near
                         + [repo for path in rest for repo in _survey(os.path.realpath(path))["checkouts"]])
    table, things, run = _processes(), _docker_list(chosen), _Run(args.apply)
    own = workdir.safe_name(_session()) if _session() else None
    if args.if_above is not None:
        chosen.sort(key=lambda look: look.get("last") or 0)   # oldest first
    for look in chosen:
        if args.apply and args.if_above is not None and (_disk_used(root) or 0) <= args.if_above - PRESSURE_DROP:
            print("the disk is now %d points under %g%%: stopping" % (PRESSURE_DROP, args.if_above))
            break
        why = _why_not(look, hours, own, named, table)
        if why:
            run.note("left", "folder", look["path"], look, why)
        else:
            run.reduce(look, borrowed, things)
    print("freed %s" % _human(run.freed) if args.apply else "nothing was changed: this was a dry run (--apply does it)")
    return 1 if run.failed else 0


def _scan(args) -> int:
    root = os.path.realpath(str(workdir.work_root()))
    looks = [_look(path) for path in _dirs(root, links=True)]
    table, things, hours, now = _processes(), _docker_list(looks), _idle_default(), time.time()
    own = workdir.safe_name(_session()) if _session() else None

    def checkouts(found):
        return [_summary(repo, git_save.facts(repo), args.check_remote) for repo in sorted(found)]

    for look in [look for look in looks if not look["skip"]]:
        users = _users(table, [path for path in (look["real"], look["tmp"]) if path])
        look.update(idle_hours=round((now - look["last"]) / 3600.0, 1), in_use=users,
                    checkouts=checkouts(look["checkouts"]),
                    rebuildable_bytes=sum(_size(path) for path in look["rebuildable"]),
                    docker=[thing for thing in things or () if thing["folder"] == look["real"]])
        look["live"] = bool(users) or look["name"] == own or look["idle_hours"] < hours
    loose = []   # git checkouts at most two levels below each --loose DIR and not under the work root: report only
    for first in [path for given in args.loose for path in _dirs(os.path.realpath(os.path.expanduser(given)))]:
        inner = [first] if os.path.lexists(os.path.join(first, ".git")) else _dirs(first)
        loose += [path for path in inner if os.path.lexists(os.path.join(path, ".git")) and not _inside(path, root)]
    report = {"work_root": root, "disk_used_percent": _disk_used(root), "folders": looks, "loose": checkouts(loose),
              "docker_unlabelled": None if things is None else [thing for thing in things if not thing["folder"]]}
    if args.json:
        print(json.dumps(report, indent=1, sort_keys=True))
        return 0
    print("%s  (its disk is %s%% full)" % (root, report["disk_used_percent"]))
    for look in looks:
        if look["skip"]:
            print("%s  %s" % (look["name"], look["skip"]))
            continue
        marks = [".keep"] * look["keep_file"] + ["keep/"] * bool(look["keep"]) + ["done"] * look["done"]
        print("%s  owner %s  %s, idle %s h  %s%s, rebuildable %s%s" % (
            look["name"], look["owner"] or "unknown", "live" if look["live"] else "not live", look["idle_hours"],
            _human(look["bytes"]), "" if look["complete"] else "+", _human(look["rebuildable_bytes"]),
            "".join("  [%s]" % mark for mark in marks)))
        lines = ["checkout %s  %s" % (item["path"], item["text"]) for item in look["checkouts"]]
        lines += ["large file %s  %s (never deleted here)" % (big["path"], _human(big["bytes"])) for big in look["big"]]
        lines += ["%s %s  %s" % (item["kind"], item["name"], item["state"] or "") for item in look["docker"]]
        print("".join("    %s\n" % line for line in lines), end="")
    print("".join("loose checkout %s  %s\n" % (item["path"], item["text"]) for item in report["loose"]), end="")
    print("docker did not answer: containers and volumes are not listed\n" * (things is None), end="")
    for item in report["docker_unlabelled"] or ():
        print("unlabelled %s %s  %s (report only)" % (item["kind"], item["name"], item["state"] or ""))
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="ah reap", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="action", required=True)
    scan = sub.add_parser("scan", help="read only: what is under the work root, who owns it and what is unsaved")
    scan.add_argument("--json", action="store_true")
    scan.add_argument("--loose", nargs="+", action="extend", default=[], metavar="DIR",
                      help="also report git checkouts at most two levels below DIR")
    scan.add_argument("--check-remote", action="store_true", help="ask each checkout's remote what it has")
    run = sub.add_parser("run", help="print the plan; with --apply save unsaved work, then remove")
    run.add_argument("--apply", action="store_true")
    run.add_argument("--idle-hours", type=float, metavar="N", help="default: reap_idle_hours in local.json, else 48")
    run.add_argument("--if-above", type=float, metavar="PCT",
                     help="only when the disk is at least PCT%% full: oldest first, until it is 5 points under")
    run.add_argument("--session", nargs="+", action="extend", default=[], metavar="ID")
    run.add_argument("--path", nargs="+", action="extend", default=[], metavar="PATH",
                     help="one folder outside the work root, named exactly, treated as an ownerless folder")
    try:
        args = parser.parse_args(argv)
    except SystemExit as stop:
        return 0 if stop.code == 0 else 3
    return _scan(args) if args.action == "scan" else _run(args)


def co_main(argv=None) -> int:
    """`ah co <owner/repo | URL> [--ref REF] [--name NAME]`: a checkout at <session folder>/co/<name> whose origin is
    the real URL. A bare mirror in ~/.agent-harness/cache/git lends its objects only while cloning
    (--reference-if-able --dissociate), so the checkout depends on nothing else. Prints the path."""
    parser = argparse.ArgumentParser(prog="ah co", description=co_main.__doc__)
    parser.add_argument("repo")
    parser.add_argument("--ref")
    parser.add_argument("--name")
    try:
        args = parser.parse_args(argv)
    except SystemExit as stop:
        return 0 if stop.code == 0 else 3
    url = "https://github.com/%s.git" % args.repo if re.fullmatch(r"[\w.-]+/[\w.-]+", args.repo) else args.repo
    parts = [part for part in re.split(r"[/:]+", re.sub(r"\.git/?$", "", url.rstrip("/"))) if part]
    owner, repo = [re.sub(r"[^A-Za-z0-9._-]", "-", part).strip(".-") or "x" for part in (["x", "x"] + parts)[-2:]]
    session, name = _session(), args.name or repo
    if (not session or url.startswith("-") or not git_save.is_offhost(url) or (args.ref or "").startswith("-")
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", name)):
        print("ah co: needs a session (AH_SESSION), owner/repo or the URL of a remote (not a local path), and a "
              "plain --name", file=sys.stderr)
        return 3
    target = os.path.join(str(workdir.ensure_session_dir(session)), "co", name)
    if os.path.lexists(target):
        print("ah co: %s already exists (choose another --name)" % target, file=sys.stderr)
        return 3
    mirror = git_save._home("cache", "git", owner, repo + ".git")
    os.makedirs(os.path.dirname(target), exist_ok=True)
    git_save._mkdirs(os.path.dirname(mirror))
    if os.path.isdir(mirror):   # a mirror only saves download time: a failure here never stops the checkout
        _git(mirror, "fetch", "--quiet", "--prune", "origin", timeout=600)
    else:
        part = "%s.%d.tmp" % (mirror, os.getpid())
        if _git(os.path.dirname(mirror), "clone", "--quiet", "--mirror", "--", url, part, timeout=1800)[0] == 0:
            try:
                os.rename(part, mirror)
            except OSError:
                pass   # another session made it first
        shutil.rmtree(part, ignore_errors=True)
    code, _out, err = _git(os.path.dirname(target), "clone", "--quiet", "--reference-if-able", mirror, "--dissociate",
                           "--", url, target, timeout=1800)
    if code == 0 and args.ref and _git(target, "checkout", "--quiet", args.ref)[0] != 0:
        code, _out, err = _git(target, "fetch", "--quiet", "origin", args.ref, timeout=600)   # such as a PR head
        if code == 0:
            code, _out, err = _git(target, "checkout", "--quiet", "--detach", "FETCH_HEAD")
    if code != 0:
        print("ah co: %s%s" % (ah_log_push.shown_url(err)[:300] or "git failed", "; %s is on its default branch"
                               % target if os.path.isdir(target) else ""), file=sys.stderr)
        return 1
    print(target)
    return 0


if __name__ == "__main__":
    sys.exit(co_main(sys.argv[2:]) if sys.argv[1:2] == ["co"] else main(sys.argv[1:]))
