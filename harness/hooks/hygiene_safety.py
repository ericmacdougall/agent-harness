#!/usr/bin/env python3
"""Shared safety rules for copy_hygiene.py (test copies, reaper) and workspace_janitor.py (session release, TTL sweep).

ONE place for every question "may this folder be deleted?" so the two tools cannot drift apart again:

  recoverable()   a checkout holds nothing that exists only here: clean tree, no hidden (skip-worktree) edits, no stash,
                  LFS or submodule, no ignored file except the one regenerable list below, no kept path inside it, and
                  every local commit is on what the remote advertises RIGHT NOW (fresh ls-remote, not stale tracking refs).
  in_use_paths()  every path a process uses: cwd, root, exe, open files and memory maps (/proc/*/maps).
  service_refs()  every path a systemd unit or launchd plist names (via copy_hygiene.protected_scan, the one unit parser), plus
                  cron entries and docker or podman containers, resolved with realpath. Every probe fails CLOSED:
                  a probe that errors or times out raises ProbeError and the caller keeps everything.
  protected_name()  the one "protect_names" rule: matches the path AND the checkout's remote URLs.
  remove_tree()   removal that never crosses a mount point.
  simple_commands()  the one shell-command splitter used by the PreToolUse hooks.
"""
from __future__ import annotations

import fcntl
import glob
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import time

GB = 1024 ** 3
# THE regenerable list: ignored paths with one of these names may be deleted with their checkout. test-results and
# playwright-report are NOT here: click-test evidence lives there (an owner may add them in config if wanted).
REGENERABLE_IGNORED = ("node_modules", ".next", "dist", "build", "target", ".venv", "venv", "__pycache__",
                       ".pytest_cache", ".mypy_cache", ".ruff_cache", "coverage", ".turbo", ".cache", ".parcel-cache",
                       ".gradle", "DerivedData", ".nuxt", ".svelte-kit", "out")
# Dependency folders that may legitimately hold nested .git folders (git dependencies); any other ignored folder with a
# repository inside is kept because the repository may hold work.
NESTED_REPO_OK = frozenset(("node_modules", ".venv", "venv"))
GENV = dict(os.environ, GIT_OPTIONAL_LOCKS="0", GIT_TERMINAL_PROMPT="0",
            GIT_SSH_COMMAND="ssh -o BatchMode=yes -o ConnectTimeout=15")
GSAFE = ["-c", "core.fsmonitor=false", "-c", "gc.auto=0", "-c", "maintenance.auto=false"]
SHOW_PROPS = ("WorkingDirectory,RootDirectory,ExecStart,ExecStartPre,ExecStartPost,ExecStop,ExecStopPost,ExecReload,"
              "ExecCondition,Environment,EnvironmentFiles,ReadWritePaths,ReadOnlyPaths,BindPaths,BindReadOnlyPaths,"
              "FragmentPath,SourcePath,DropInPaths,Where,What")
PREFIXES = frozenset(("sudo", "command", "time", "env", "nice", "nohup", "exec", "builtin", "ionice", "timeout", "setsid",
                      "stdbuf", "chrt", "doas"))
ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
# options of each prefix command that take a separate value
PREFIX_VALUE_OPTS = {"sudo": {"-u", "-g", "-h", "-p", "-C", "-D", "-r", "-t", "-U"}, "env": {"-u", "-C", "-S"},
                     "nice": {"-n"}, "ionice": {"-c", "-n", "-p", "-P", "-u"}, "timeout": {"-s", "-k"},
                     "stdbuf": {"-i", "-o", "-e"}, "chrt": set(), "doas": {"-u", "-C"}, "time": {"-f", "-o"}}
ABS_PATH = re.compile(r"(?<![\w/.])/[A-Za-z0-9_.@+%~-][^\s\"'<>,;=)\]}\\|&`:]*")


class ProbeError(Exception):
    """a liveness probe failed: callers must keep everything rather than treat it as 'nothing found'."""


# ---------------------------------------------------------------- locations, config, audit
def home() -> str:
    return (os.environ.get("HARNESS_COPY_HYGIENE_HOME") or os.environ.get("HARNESS_JANITOR_HOME")
            or os.path.expanduser("~"))


def ah(*p: str) -> str:
    return os.path.join(home(), ".agent-harness", *p)


def state_dir() -> str:
    return ah("state")


def allowed_roots() -> list:
    """The only trees any delete path may live in."""
    return [os.path.realpath(ah(n)) for n in ("work", "checkouts", "test-copies")]


def within_allowed(path: str, strictly_inside: bool = True) -> bool:
    rp = os.path.realpath(os.path.expanduser(path))
    for r in allowed_roots():
        if rp == r and not strictly_inside:
            return True
        if rp.startswith(r + os.sep):
            return True
    return False


def safe_key(key: str) -> str:
    k = re.sub(r"[^A-Za-z0-9._-]+", "-", str(key)).strip("-.")
    if not k or set(k) <= {"."}:
        raise ValueError("unusable key: %r" % (key,))
    return k[:80]


def alert(kind: str, detail: dict) -> None:
    """Append one row to the single audit/alert log; never raises."""
    try:
        os.makedirs(state_dir(), exist_ok=True)
        row = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "kind": kind}
        row.update(detail)
        with open(os.path.join(state_dir(), "copy-hygiene-alerts.jsonl"), "a") as f:
            f.write(json.dumps(row) + "\n")
    except OSError:
        pass


# A partial-clone mirror must not download while it is only being inspected: GIT_NO_LAZY_FETCH is honoured by newer
# git; git 2.43 ignores it, so also allow no transport at all (a missing object then just reads as absent).
NO_FETCH_ENV = {"GIT_NO_LAZY_FETCH": "1", "GIT_ALLOW_PROTOCOL": "none-allowed"}


def alert_daily(kind: str, key: str, detail: dict) -> None:
    """alert(), but at most once per UTC day per (kind, key): a standing condition must not add rows every run."""
    try:
        os.makedirs(state_dir(), exist_ok=True)
        path = os.path.join(state_dir(), "alert-daily.json")
        try:
            with open(path) as f:
                seen = json.load(f)
            if not isinstance(seen, dict):
                seen = {}
        except (OSError, ValueError):
            seen = {}
        day, k = time.strftime("%Y-%m-%d", time.gmtime()), kind + ":" + key
        if seen.get(k) == day:
            return
        seen = {a: b for a, b in seen.items() if b == day}
        seen[k] = day
        tmp = path + ".tmp%d" % os.getpid()
        with open(tmp, "w") as f:
            json.dump(seen, f)
        os.replace(tmp, path)
    except OSError:
        pass
    alert(kind, detail)


def git(cwd: str, *args: str, t: int = 120, inp: "str | None" = None, offline: bool = False) -> "tuple[int, str, str]":
    """(rc, stdout, stderr); rc -1 on timeout or a missing git. offline=True: never lazy-fetch a missing object."""
    try:
        r = subprocess.run(["git", "-C", cwd] + GSAFE + list(args), capture_output=True, text=True, timeout=t,
                           env=dict(GENV, **NO_FETCH_ENV) if offline else GENV, errors="replace", input=inp)
        return r.returncode, r.stdout, r.stderr
    except Exception as e:  # noqa: BLE001
        return -1, "", str(e)


def probe(cmd: list, t: int = 60) -> "tuple[int, str, str]":
    """(rc, stdout, stderr); rc 127 when the tool is missing, -1 on timeout or any other failure."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=t, errors="replace")
        return r.returncode, r.stdout, r.stderr
    except FileNotFoundError:
        return 127, "", "not installed"
    except Exception as e:  # noqa: BLE001
        return -1, "", str(e)


def lock_nonblocking(path: str):
    """Open and exclusively lock path (a lock file); None when somebody holds it. Close the file to release."""
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        fh = open(path, "a")
    except OSError:
        return None
    try:
        fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return fh
    except OSError:
        fh.close()
        return None


# ---------------------------------------------------------------- command analysis
def strip_prefixes(words: list) -> list:
    """Drop VAR=x, sudo/env/timeout/nice/... and their own options and values, leaving the real command."""
    while words:
        w = words[0]
        name = os.path.basename(w)
        if ASSIGN.match(w):
            words = words[1:]
        elif name in PREFIXES:
            words = words[1:]
            vopts = PREFIX_VALUE_OPTS.get(name, set())
            while words and (words[0].startswith("-") or ASSIGN.match(words[0])):
                skip = 2 if words[0] in vopts else 1
                words = words[skip:]
            if name == "timeout" and words and re.match(r"^[0-9.]+[smhd]?$", words[0]):
                words = words[1:]
            if name == "chrt" and words and re.match(r"^[0-9]+$", words[0]):
                words = words[1:]
        else:
            break
    return words


def simple_commands(cmd: str) -> list:
    """argv lists of the simple commands in a shell line (quote-aware enough for policy; never raises)."""
    out = []
    for m in re.finditer(r"\b(?:ba|z|da)?sh\s+(?:-\w+\s+)*-c\s+(?:'([^']*)'|\"([^\"]*)\")", cmd):
        out.extend(simple_commands(m.group(1) or m.group(2) or ""))      # `bash -c '...'` keeps its quoted &&/; intact
    for seg in re.split(r"\|\||&&|[;|&\n]|\$\(|`|\(|\)", cmd):
        seg = seg.strip()
        if not seg:
            continue
        try:
            words = shlex.split(seg, comments=True)
        except ValueError:
            words = seg.split()
        words = strip_prefixes(words)
        if words:
            out.append(words)
            if os.path.basename(words[0]) in ("sh", "bash", "zsh", "dash") and "-c" in words[1:-1]:
                out.extend(simple_commands(words[words.index("-c") + 1]))
    return out


# ---------------------------------------------------------------- in use
def mounts_under(path: str) -> list:
    out = []
    path = os.path.realpath(path)
    try:
        with open("/proc/self/mountinfo") as f:
            for l in f:
                mp = l.split()[4].replace("\\040", " ")
                if mp == path or mp.startswith(path.rstrip("/") + "/"):
                    out.append(mp)
    except OSError:
        pass
    return out


def _ls(d: str) -> list:
    try:
        return os.listdir(d)
    except OSError:
        return []


def _norm(t: str) -> str:
    return t[:-len(" (deleted)")] if t.endswith(" (deleted)") else t


def in_use_paths() -> set:
    """Paths any process uses: cwd, root, exe, open files, memory-mapped files (a process can close a file it mapped)."""
    out = set()
    for p in glob.glob("/proc/[0-9]*"):
        for link in ["cwd", "root", "exe"] + ["fd/" + f for f in _ls(p + "/fd")]:
            try:
                t = os.readlink(os.path.join(p, link))
            except OSError:
                continue
            if t.startswith("/"):
                out.add(_norm(t))
        try:
            with open(p + "/maps", errors="replace") as fh:
                for line in fh:
                    parts = line.split(None, 5)
                    if len(parts) == 6 and parts[5].startswith("/"):
                        out.add(_norm(parts[5].rstrip("\n")))
        except OSError:
            pass
    if not out and sys.platform == "darwin":
        rc, o, _ = probe(["lsof", "-Fn", "-u", str(os.getuid())], 120)
        for l in o.splitlines():
            if l.startswith("n/"):
                out.add(l[1:])
    if not out:
        raise ProbeError("no open files or working folders seen (process scan failed)")
    return out


def is_used(path: str, used: set) -> bool:
    rp = os.path.realpath(path)
    for cand in {path.rstrip("/"), rp}:
        pre = cand + "/"
        if any(u == cand or u.startswith(pre) for u in used):
            return True
    return False


# ---------------------------------------------------------------- service references
def _unit_names(out: str) -> list:
    names = []
    for l in out.splitlines():
        for tok in l.split():
            if tok in ("●", "*", "○", "×"):
                continue
            if "@." not in tok and re.match(r"^[\w:.@\\-]+\.(service|socket|timer|mount|automount|path|target|slice|scope|swap)$", tok):
                names.append(tok)
            break
    return sorted(set(names))


def _systemd_texts() -> list:
    texts = []
    for scope in ([], ["--user"]):
        names = []
        for sub in (["list-unit-files"], ["list-units", "--all"]):
            rc, o, err = probe(["systemctl"] + scope + sub + ["--no-legend", "--plain", "--no-pager"], 60)
            if rc == 127:
                return texts                      # no systemd on this host (unit FILES are still read by the caller)
            if rc != 0:
                if scope:                         # no user bus for this account: its unit files are read from disk
                    names = None
                    break
                raise ProbeError("systemctl %s failed: %s" % (" ".join(sub), (err or "")[-120:].strip()))
            names += _unit_names(o)
        if not names:
            continue
        names = sorted(set(names))
        for i in range(0, len(names), 100):
            rc, o, err = probe(["systemctl"] + scope + ["show", "--no-pager", "-p", SHOW_PROPS, "--"] + names[i:i + 100], 120)
            if rc != 0:
                raise ProbeError("systemctl show failed (rc %s): %s" % (rc, (err or "")[-120:].strip()))
            texts.append(o)
    return texts


def service_refs() -> set:
    h = home()
    texts = []
    rc, cron, err = probe(["crontab", "-l"])
    if rc not in (0, 127) and "no crontab" not in err:
        raise ProbeError("crontab -l failed")
    texts.append(cron)
    texts += _systemd_texts()
    for g in ["/etc/cron*/*", "/etc/crontab", "/var/spool/cron/crontabs/*",
              h + "/.config/environment.d/*", h + "/.config/containers/systemd/**", "/etc/containers/systemd/**",
              h + "/.profile", h + "/.bashrc", h + "/.zshrc"]:
        for f in glob.glob(g, recursive=True):
            try:
                if os.path.isfile(f):
                    with open(f, "rb") as fh:
                        texts.append(fh.read(262144).decode("utf-8", "replace"))
            except OSError:
                pass
    fmt = ("{{range .Mounts}}{{.Source}} {{end}}{{range $k,$v := .Config.Labels}}{{$v}} {{end}}{{.Config.WorkingDir}} "
           "{{.Path}} {{range .Args}}{{.}} {{end}}")
    for tool in ("docker", "podman"):
        rc, ids, _ = probe([tool, "ps", "-aq"])
        if rc == 127:
            continue
        if rc != 0:
            raise ProbeError("%s ps failed" % tool)
        if ids.split():
            rc, o, _ = probe([tool, "inspect", "-f", fmt] + ids.split(), 120)
            if rc != 0:
                raise ProbeError("%s inspect failed" % tool)
            texts.append(o)
    refs = set()
    # systemd units and launchd plists: ONE parser, copy_hygiene's protected-path scan (it carries the bypass fixes:
    # %h/~ expansion, User= homes, drop-ins, EnvironmentFile, symlinked units). Imported here because copy_hygiene
    # imports this module. An unreadable unit fails closed like every other probe.
    try:
        import copy_hygiene
        prot, unit_errors = copy_hygiene.protected_scan()
    except Exception as e:      # noqa: BLE001
        raise ProbeError("service unit scan failed: %s" % type(e).__name__)
    if unit_errors:
        raise ProbeError("%d service unit file(s) could not be read" % unit_errors)
    for _k_, (orig, _src) in prot.items():
        for x in {orig, os.path.realpath(orig)}:
            refs.add(x)
            if os.path.isfile(x):
                refs.add(os.path.dirname(x))
    for t in texts:
        t = t.replace("${HOME}", h).replace("$HOME", h).replace("%h", h).replace("~/", h + "/")
        for m in ABS_PATH.findall(t):
            m = os.path.normpath(m.rstrip("/."))
            if m in ("/", ""):
                continue
            for x in {m, os.path.realpath(m)}:
                refs.add(x)
                if os.path.isfile(x):
                    refs.add(os.path.dirname(x))
    for d in (h, h + "/bin", h + "/.local/bin", h + "/.config", "/usr/local/bin"):  # tools symlinked from a work folder
        for e in _ls(d):
            p = os.path.join(d, e)
            if os.path.islink(p):
                refs.add(os.path.realpath(p))
                refs.add(os.path.dirname(os.path.realpath(p)))
    refs.discard(h)
    refs.discard(os.path.realpath(h))
    refs.discard("/")
    return refs


def protected_name(path: str, cfg: dict) -> str:
    """'' or why `path` is protected by a configured name (cfg["protect_names"], lower case). Matches the path (and its
    realpath) and, for a checkout or bare mirror, every remote URL, because a clone can be named anything. A repository
    whose URLs cannot be read counts as protected (fail closed)."""
    names = [n for n in (cfg.get("protect_names") or []) if n]
    if not names:
        return ""
    for text in {path.lower(), os.path.realpath(path).lower()}:
        for n in names:
            if n in text:
                return "protected name %r" % n
    if os.path.exists(os.path.join(path, ".git")) or os.path.isfile(os.path.join(path, "HEAD")):
        rc, out, _ = git(path, "config", "--get-regexp", r"^remote\..*url$")
        if rc not in (0, 1):                      # 1 = no remote configured
            return "protected: cannot read the remote URLs to check protect_names"
        low = out.lower()
        for n in names:
            if n in low:
                return "protected name %r in a remote URL" % n
    return ""


def referenced(path: str, refs: set) -> bool:
    rp = os.path.realpath(path)
    for cand in {path.rstrip("/"), rp}:
        pre = cand + "/"
        if any(r == cand or r.startswith(pre) for r in refs):
            return True
    return False


def busy(path: str, used: set, refs: set) -> str:
    if is_used(path, used):
        return "a process has files open, maps them or works inside"
    if referenced(path, refs):
        return "referenced by a systemd unit, cron job, container or launchd plist"
    return ""


# ---------------------------------------------------------------- recoverability
def _has_nested_repo(path: str) -> bool:
    for dp, dn, fn in os.walk(path):
        if ".git" in dn or ".git" in fn:
            return True
    return False


def ignored_problem(repo: str, status_out: str) -> str:
    """'' when every ignored entry is regenerable build output, else a description of the first one that is not."""
    for line in status_out.splitlines():
        if not line.startswith("!! "):
            continue
        entry = line[3:].strip().strip('"')
        name = entry.rstrip("/").split("/")[-1]
        if name not in REGENERABLE_IGNORED:
            return "ignored files that may be evidence (%s)" % entry[:80]
        full = os.path.join(repo, entry)
        if name not in NESTED_REPO_OK and os.path.isdir(full) and _has_nested_repo(full):
            return "ignored folder holds a nested repository (%s)" % entry[:80]
    return ""


def recoverable(repo: str, deadline: "float | None" = None) -> "tuple[bool, str]":
    """True when deleting the checkout loses nothing: see the module docstring."""
    def left() -> int:
        return 120 if deadline is None else max(5, min(120, int(deadline - time.time())))
    if deadline is not None and time.time() > deadline:
        return False, "time budget exhausted"
    rc, st, _ = git(repo, "status", "--porcelain", "--untracked-files=all", "--ignored=matching",
                    "--ignore-submodules=none", t=300)
    if rc != 0:
        return False, "git status failed"
    if any(l and not l.startswith("!! ") for l in st.splitlines()):
        return False, "uncommitted or untracked changes"
    why = ignored_problem(repo, st)
    if why:
        return False, why
    rc, gd, _ = git(repo, "rev-parse", "--absolute-git-dir")
    gd = gd.strip()
    if rc != 0 or not gd:
        return False, "cannot find the git directory"
    if any(os.path.exists(os.path.join(gd, x)) for x in ("rebase-merge", "rebase-apply", "MERGE_HEAD", "CHERRY_PICK_HEAD",
                                                       "REVERT_HEAD", "BISECT_LOG")):
        return False, "rebase or merge in progress"
    rc, hidden, _ = git(repo, "ls-files", "-v", t=300)
    if rc != 0 or any(l[:1] == "S" or l[:1].islower() for l in hidden.splitlines()):
        return False, "skip-worktree / assume-unchanged files (edits git status does not show)"
    rc, common, _ = git(repo, "rev-parse", "--git-common-dir")
    common = os.path.realpath(os.path.join(repo, common.strip())) if rc == 0 else gd
    if (os.path.isdir(os.path.join(common, "lfs")) or os.path.exists(os.path.join(repo, ".gitmodules"))
            or "/modules/" in gd or os.path.isdir(os.path.join(gd, "modules"))):
        return False, "LFS objects or submodules (not verified)"
    rc, stash, _ = git(repo, "stash", "list")
    if rc != 0 or stash.strip():
        return False, "has a stash"
    linked = os.path.isfile(os.path.join(repo, ".git"))
    if not linked:
        for w in _ls(os.path.join(gd, "worktrees")):
            try:
                with open(os.path.join(gd, "worktrees", w, "gitdir")) as fh:
                    if os.path.exists(fh.read().strip()):
                        return False, "other linked worktrees use this repository"
            except OSError:
                continue
    rc, remotes, _ = git(repo, "remote")
    names = remotes.split()
    if rc != 0 or not names:
        return False, "no remote"
    advertised = set()
    for name in names:
        rc, url, _ = git(repo, "remote", "get-url", name)
        rc2, adv, _ = git(repo, "ls-remote", url.strip(), t=left()) if rc == 0 and url.strip() else (1, "", "")
        if rc2 != 0:
            return False, "ls-remote failed (cannot prove the commits are on the remote)"
        advertised |= {l.split()[0] for l in adv.splitlines() if l.strip()}
    rc, present, _ = git(repo, "cat-file", "--batch-check=%(objectname) %(objecttype)", inp="\n".join(sorted(advertised)), t=120,
                      offline=True)
    have = "".join("^%s\n" % l.split()[0] for l in present.splitlines() if l.endswith(" commit"))
    rc, n, _ = git(repo, "rev-list", "--count", "--stdin", "HEAD", inp=have, t=300, offline=True)
    if rc != 0 or n.strip() != "0":
        return False, "HEAD is on no remote ref"
    if not linked:
        rc, n, _ = git(repo, "rev-list", "--count", "--stdin", "--branches", "--tags", inp=have, t=300, offline=True)
        if rc != 0 or n.strip() != "0":
            return False, "a local branch has commits on no remote"
    return True, ""


def find_repos(root: str) -> list:
    """Every checkout (a folder with .git) under root, innermost first; does not descend into .git or regenerable folders."""
    out = []
    for dp, dn, fn in os.walk(root):
        if ".git" in dn or ".git" in fn:
            out.append(dp)
        dn[:] = [d for d in dn if d != ".git" and d not in REGENERABLE_IGNORED]
    return sorted(out, key=lambda p: -p.count("/"))


# ---------------------------------------------------------------- activity, size, removal
def newest_activity(path: str) -> float:
    """Newest mtime OR ctime anywhere in the tree (ctime survives cp -a / rsync -a / tar -x, so a fresh copy is never old)."""
    best = 0.0
    for dp, dn, fn in os.walk(path):
        dn[:] = [d for d in dn if d not in REGENERABLE_IGNORED and not (d == "objects" and dp.endswith("/.git"))]
        for f in fn + [""]:
            try:
                st = os.lstat(os.path.join(dp, f) if f else dp)
                best = max(best, st.st_mtime, st.st_ctime)
            except OSError:
                pass
    return best


def du(path: str) -> int:
    total = 0
    for dp, dn, fn in os.walk(path):
        for f in fn + dn:
            try:
                total += os.lstat(os.path.join(dp, f)).st_blocks * 512
            except OSError:
                pass
    return total


def remove_tree(path: str) -> "tuple[bool, str]":
    """rmtree that refuses (and removes nothing) when a mount point or another device is inside."""
    try:
        if os.path.islink(path):
            os.unlink(path)
            return True, ""
        if mounts_under(path):
            return False, "mount point inside"
        dev = os.lstat(path).st_dev
        for dp, dn, fn in os.walk(path):
            for d in dn:
                try:
                    if os.lstat(os.path.join(dp, d)).st_dev != dev:
                        return False, "another filesystem inside"
                except OSError:
                    pass
        shutil.rmtree(path)
        return True, ""
    except OSError as e:
        return False, "%s: %s" % (type(e).__name__, str(e)[:160])


def remove_checkout(repo: str) -> "tuple[bool, str]":
    """Linked worktree: plain `git worktree remove` (no --force). Standalone clone: remove_tree."""
    if mounts_under(repo):
        return False, "mount point inside"
    if os.path.isfile(os.path.join(repo, ".git")):
        rc, common, _ = git(repo, "rev-parse", "--path-format=absolute", "--git-common-dir")
        if rc != 0:
            return False, "cannot find the main repository"
        common = common.strip()
        main = os.path.dirname(common) if os.path.basename(common) == ".git" else common
        rc, _, err = git(main, "worktree", "remove", repo)
        return rc == 0, err.strip()[-200:]
    return remove_tree(repo)
