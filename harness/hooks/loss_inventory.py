#!/usr/bin/env python3
"""Loss-class inventory for a host that is about to be decommissioned (goodqa#14565, PL-03).

Single-file, stdlib-only. Counts and paths only: it never reads file contents or prints secrets
(the one read is the 16-byte SQLite magic header of a ``.db`` file; git status/crontab output is
reduced to a count and a hash).

Subcommands
  scan   --root DIR [--root DIR ...] [--json] [--max-seconds N] [--min-db-bytes N] [--exclude NAME]
         [--cross-devices] [--allow-symlink-target PATH] [--no-save]
         Classes (rows keyed by path; branch rows are REPO::branch):
           unpushed_branch      local branch/detached HEAD whose tip is in no OFF-HOST remote-tracking ref
           no_remote_repo       git repo (incl. bare) with no remote, or only same-host remotes
                                (local path, file://, localhost, this hostname)
           local_tag            tag whose commit is in no off-host remote-tracking ref
           git_stash            repo has stash entries
           dirty_worktree       work tree with uncommitted/untracked entries (count only)
           systemd_user_unit    .service/.socket/.path/.mount/.automount in ~/.config/systemd/user
                                and ~/.local/share/systemd/user
           timer                .timer in the same directories
           crontab              user crontab has active lines (count only)
           state_db_outside_git sqlite/db >= --min-db-bytes not tracked by git
         Git state comes from LOCAL refs only and never fetches, so it can be stale.
         The result is saved to $HOME/.agent-harness/state/loss-inventory/last-scan.json.
  decide --row PATH --decision moved|rebuildable|accepted-loss --ticket REF
         Append to $HOME/.agent-harness/state/loss-inventory/decisions.jsonl. PATH must be a row of
         the last scan. A decision on a git/crontab row is voided by any change of its fingerprint
         (tips, stash, status hash, crontab hash); on a DB or unit only a "moved" decision is voided.
  report [--json] [--max-age HOURS] [--allow-partial-roots]
         Print undecided rows and problems. Exit 1 if any row is undecided OR the saved scan cannot
         prove nothing is left: wrong schema/missing keys, older than --max-age (default 24 h), roots
         do not include $HOME, partial (--max-seconds), scan errors, skipped other-filesystem dirs,
         or symlinks not followed whose target is outside the scanned roots. Exit 2 if no saved
         scan, else 0. Excluded names block until --ack-excludes; built-in pruned names are listed in the output.

NOT covered (known limits): system units (/etc/systemd/system), other users' crontabs and homes,
anything outside the --root dirs, remotes addressed by this host's LAN IP (only loopback, hostname and
resolved own addresses are recognised), gitignored files and plain (non-git) files, linked worktrees
whose main repo is outside the roots, refs/notes and other custom refs, git objects outside refs (reflog-only commits), rewritten
remotes (url.insteadOf), and remote-side state (we never contact a remote).

Safety: symlinks are never followed; the walk does not cross filesystems unless --cross-devices;
node_modules, .git internals, virtualenvs and caches are skipped; every git call has a timeout,
runs with optional locks off, fsmonitor disabled and signature display off. git status is skipped
(with a blocking error) for a repo whose config defines a clean/process filter, because that would
run a command from the repo. A failing repo becomes an entry in
"errors", not a crash.
"""
import argparse
import getpass
import hashlib
import ipaddress
import json
import os
import re
import socket
import stat
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone

SCHEMA = 2
CLASSES = ("unpushed_branch", "no_remote_repo", "systemd_user_unit", "timer", "state_db_outside_git",
           "git_stash", "local_tag", "dirty_worktree", "crontab")
UNIT_EXTS = (".service", ".socket", ".path", ".mount", ".automount")
REQUIRED_KEYS = ("schema", "min_db_bytes", "host", "scanned_at", "roots", "classes", "rows", "partial", "errors_total",
                 "skipped_mounts_total", "skipped_symlinks_total", "excludes", "prune")
DECISIONS = ("moved", "rebuildable", "accepted-loss")
DB_EXTS = (".sqlite", ".sqlite3", ".db")
SQLITE_MAGIC = b"SQLite format 3\x00"
PRUNE = {
    ".git", "node_modules", ".venv", "venv", "__pycache__", ".tox", ".mypy_cache",
    ".pytest_cache", ".cache", ".npm", ".pnpm-store", ".yarn", ".cargo", ".rustup",
    ".gradle", ".m2", "site-packages", ".Trash", "Cache", "Caches",
}
MAX_ERRORS = 200
GIT_TIMEOUT = 30
DIRTY_STAT_CAP = 5000
DEFAULT_MIN_DB = 1000000


def state_dir():
    return os.path.join(os.path.expanduser("~"), ".agent-harness", "state", "loss-inventory")


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class Budget:
    def __init__(self, seconds):
        self.deadline = time.monotonic() + seconds if seconds and seconds > 0 else None
        self.exceeded = False

    def left(self):
        return None if self.deadline is None else self.deadline - time.monotonic()

    def over(self):
        if self.deadline is not None and time.monotonic() >= self.deadline:
            self.exceeded = True
        return self.exceeded


class Scan:
    def __init__(self, args):
        self.min_db = args.min_db_bytes
        self.budget = Budget(args.max_seconds)
        self.extra_prune = set(args.exclude or [])
        self.prune = PRUNE | self.extra_prune
        self.cross = args.cross_devices
        self.no_crontab = args.no_crontab
        self.symlink_allow = [os.path.realpath(os.path.expanduser(x)) for x in (args.allow_symlink_target or [])]
        self.roots_real = []
        self.rows = []
        self.errors = []
        self.errors_total = 0
        self.dirs = 0
        self.repos = 0
        self.now = time.time()
        self.seen_common = set()
        self.skipped_mounts = []
        self.skipped_symlinks = []
        self.skipped_symlinks_total = 0
        self.acked_symlinks = []
        self.local_names = local_host_names()

    def err(self, path, what):
        self.errors_total += 1
        if len(self.errors) < MAX_ERRORS:
            self.errors.append({"path": path, "error": str(what)[:200]})

    def row(self, cls, path, mtime, size, fp=None, count=None):
        age = None if mtime is None else round(max(0.0, self.now - mtime) / 86400.0, 1)
        r = {"class": cls, "path": path, "age_days": age, "bytes": size, "decision": None,
             "fp": fp}  # fp: tip sha / hash / size:mtime; a decision is void when it changes
        if count is not None:
            r["count"] = count  # number of entries (stash entries, dirty paths, cron lines); never contents
        self.rows.append(r)

    # ---- git (local refs only, never fetch) ----
    def git(self, repo, *argv):
        left = self.budget.left()
        timeout = GIT_TIMEOUT if left is None else max(1.0, min(GIT_TIMEOUT, left))
        env = os.environ.copy()
        for k in ("GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_COMMON_DIR"):
            env.pop(k, None)
        env.update(GIT_TERMINAL_PROMPT="0", GIT_OPTIONAL_LOCKS="0", GIT_LITERAL_PATHSPECS="1")  # optional locks off: status never writes the index
        # fsmonitor=false: a scanned repo's config must not be able to run a command
        cmd = ["git", "-C", repo, "-c", "core.fsmonitor=false", "-c", "log.showSignature=false"] + list(argv)
        try:
            p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout,
                               env=env, stdin=subprocess.DEVNULL)
        except subprocess.TimeoutExpired:
            raise RuntimeError("git %s timed out" % argv[0])
        except OSError as e:
            raise RuntimeError("git not runnable: %s" % e)
        return p.returncode, p.stdout.decode("utf-8", "surrogateescape"), p.stderr.decode("utf-8", "replace")

    def contained_in(self, repo, sha, *namespaces):
        """True if some ref under the namespaces contains commit sha (for-each-ref --contains)."""
        rc, out, er = self.git(repo, "for-each-ref", "--count=1", "--format=%(refname)",
                               "--contains", sha, *namespaces)
        if rc != 0:
            raise RuntimeError("for-each-ref --contains failed: %s" % er.strip()[:120])
        return bool(out.strip())

    def offhost_remotes(self, repo):
        """Names of remotes whose URL is not this host (URLs are never stored or printed)."""
        rc, out, er = self.git(repo, "remote")
        if rc != 0:
            raise RuntimeError("git remote failed: %s" % er.strip()[:120])
        names = [n for n in out.split("\n") if n.strip()]
        good = []
        for n in names:
            urls = []
            for key in ("url", "pushurl"):
                rc, o, _ = self.git(repo, "config", "--get-all", "remote.%s.%s" % (n, key))
                if rc == 0:
                    urls += [u for u in o.split("\n") if u.strip()]
            if urls and not any(url_is_local(u, self.local_names) for u in urls):
                good.append(n)
        if any("/" in n for n in names):
            # tracking refs of "a/b" live under refs/remotes/a/: they cannot be told apart from remote "a"
            self.err(repo, "remote name contains '/'; cannot attribute tracking refs, repo treated as having no off-host remote")
            good = []
        return names, good

    def any_not_in_remotes(self, repo, kind, offhost):
        """Fast path: one rev-list says whether any local branch/tag has a commit no off-host remote has."""
        if any(c in n for n in offhost for c in "*?["):
            return True
        rc, out, _ = self.git(repo, "rev-list", "--max-count=1", kind, "--not",
                              *["--remotes=%s" % n for n in offhost])
        return rc != 0 or bool(out.strip())

    def analyze_repo(self, repo):
        """Branch/remote/stash checks run once per common git dir (linked worktrees, submodules and
        bare repos with worktrees share refs); detached-HEAD and dirty checks run per work tree."""
        self.repos += 1
        try:
            rc, out, er = self.git(repo, "rev-parse", "--git-common-dir", "--is-bare-repository")
            lines = out.split("\n")
            if rc != 0 or len(lines) < 2:
                raise RuntimeError("git rev-parse failed: %s" % er.strip()[:120])
            common = os.path.realpath(os.path.join(repo, lines[0].strip()))
            bare = lines[1].strip() == "true"
            names, offhost = self.offhost_remotes(repo)
            ns = ["refs/remotes/%s" % n for n in offhost]
            if common not in self.seen_common:
                self.seen_common.add(common)
                self.first_visit(repo, common, offhost, ns)
            if offhost and not self.budget.over():
                self.check_detached(repo, ns)
            if not bare and not self.budget.over():
                self.check_dirty(repo)
        except RuntimeError as e:
            self.err(repo, e)

    def first_visit(self, repo, common, offhost, ns):
        rc, refs, er = self.git(repo, "for-each-ref", "--format=%(refname:short)\t%(objectname)\t%(committerdate:unix)",
                                "refs/heads")
        if rc != 0:
            raise RuntimeError("for-each-ref failed: %s" % er.strip()[:120])
        if not offhost:
            try:
                mtime = os.lstat(common).st_mtime
            except OSError:
                mtime = None
            # fingerprint = every local branch tip + HEAD, so a commit anywhere voids a decision
            rc2, head, _ = self.git(repo, "rev-parse", "--verify", "-q", "HEAD")
            rc3, allrefs, _ = self.git(repo, "for-each-ref", "--format=%(refname)%(objectname)")  # every ref: tags, stash, notes
            tips = allrefs if rc3 == 0 else "?"
            fp = hashlib.sha256((tips + "\nHEAD:" + (head.strip() if rc2 == 0 else "")).encode("utf-8", "replace")).hexdigest()[:16]
            self.row("no_remote_repo", repo, mtime, self.pack_bytes(common), fp)
        else:
            if self.any_not_in_remotes(repo, "--branches", offhost):
                for line in refs.splitlines():
                    parts = line.split("\t")
                    if len(parts) != 3 or self.budget.over():
                        continue
                    name, sha, ct = parts
                    if not self.contained_in(repo, sha, *ns):
                        self.row("unpushed_branch", "%s::%s" % (repo, name), float(ct) if ct.isdigit() else None, None, sha)
            if self.any_not_in_remotes(repo, "--tags", offhost):
                rc, tags, er = self.git(repo, "for-each-ref", "--format=%(refname:short)\t%(objectname)", "refs/tags")
                if rc != 0:
                    raise RuntimeError("for-each-ref tags failed: %s" % er.strip()[:120])
                for line in tags.splitlines():
                    parts = line.split("\t")
                    if len(parts) != 2 or self.budget.over():
                        continue
                    tname, tsha = parts
                    if not self.contained_in(repo, tsha, *ns):
                        self.row("local_tag", "%s::tag:%s" % (repo, tname), None, None, tsha)
        rc, sha, _ = self.git(repo, "rev-parse", "--verify", "-q", "refs/stash")
        if rc == 0 and sha.strip():
            rc, cnt, _ = self.git(repo, "rev-list", "-g", "--count", "refs/stash")
            rc2, ct, _ = self.git(repo, "log", "-1", "--format=%ct", "refs/stash")
            self.row("git_stash", "%s::stash" % repo, float(ct.strip()) if ct.strip().isdigit() else None, None,
                     sha.strip(), int(cnt.strip()) if cnt.strip().isdigit() else None)

    def check_detached(self, repo, ns):
        rc, _, _ = self.git(repo, "symbolic-ref", "-q", "HEAD")
        if rc != 1:
            return
        rc, sha, _ = self.git(repo, "rev-parse", "--verify", "-q", "HEAD")
        sha = sha.strip()
        if rc == 0 and sha and not self.contained_in(repo, sha, *(ns + ["refs/heads", "refs/tags"])):
            rc, ct, _ = self.git(repo, "log", "-1", "--format=%ct", sha)
            ct = ct.strip()
            self.row("unpushed_branch", "%s::(detached HEAD)" % repo, float(ct) if ct.isdigit() else None, None, sha)

    def check_dirty(self, repo):
        """Count of changed/untracked entries only (git status --porcelain, no index write)."""
        # a clean/process filter would make status run a command from the repo's config: skip, fail closed
        # only the repo's own config (local + worktree): global/system filters such as git-lfs are
        # configured on every host and are not repo-defined commands
        pat = r"^filter\..*\.(clean|process)$"
        rc, flt, _ = self.git(repo, "config", "--local", "--includes", "--get-regexp", pat)
        rcw, wt, _ = self.git(repo, "config", "--local", "--get", "extensions.worktreeConfig")
        if rcw == 0 and wt.strip().lower() in ("true", "yes", "on", "1"):
            rc2, flt2, _ = self.git(repo, "config", "--worktree", "--includes", "--get-regexp", pat)
            if rc2 == 0:
                flt += flt2
                rc = 0
        if rc == 0 and flt.strip():
            raise RuntimeError("repo config defines a clean/process filter; git status skipped "
                               "(it would run a repo-defined command); dirty state not inventoried")
        # explicit flags: user/repo config (status.showUntrackedFiles=no) must not hide files
        rc, out, er = self.git(repo, "status", "--porcelain", "-z", "--untracked-files=all", "--ignore-submodules=all")
        if rc != 0:
            raise RuntimeError("git status failed: %s" % er.strip()[:120])
        fields = out.split("\0")  # -z: no path quoting; a rename/copy record is followed by its source path
        paths, i = [], 0
        while i < len(fields):
            f = fields[i]
            i += 1
            if len(f) < 4:
                continue
            if f[0] in "RC" or f[1] in "RC":
                i += 1
            paths.append(f[3:])
        if paths:
            h = hashlib.sha256(out.encode("utf-8", "replace"))
            for pth in paths[:DIRTY_STAT_CAP]:  # content changes under the same path change size:mtime
                try:
                    st = os.lstat(os.path.join(repo, pth))
                    h.update(("%d:%d" % (st.st_size, st.st_mtime_ns)).encode())
                except OSError:
                    h.update(b"-")
            self.row("dirty_worktree", "%s::dirty" % repo, self.now, None, h.hexdigest()[:16], len(paths))

    def tracked(self, repo_root, path):
        """True if path is tracked by git (so it lives in the repo, not only on this disk)."""
        try:
            rc, _, _ = self.git(repo_root, "ls-files", "--error-unmatch", "--", os.path.relpath(path, repo_root))
        except RuntimeError as e:
            self.err(path, e)
            return False
        return rc == 0

    @staticmethod
    def pack_bytes(gitpath):
        total = 0
        try:
            with os.scandir(os.path.join(gitpath, "objects", "pack")) as it:
                for e in it:
                    if e.name.endswith(".pack"):
                        total += e.stat(follow_symlinks=False).st_size
        except OSError:
            return None
        return total

    # ---- systemd user units and crontab ----
    def scan_units(self):
        home = os.path.expanduser("~")
        for d in (os.path.join(home, ".config", "systemd", "user"),
                  os.path.join(home, ".local", "share", "systemd", "user")):
            try:
                with os.scandir(d) as it:
                    entries = sorted(it, key=lambda e: e.name)
            except FileNotFoundError:
                continue
            except OSError as e:
                self.err(d, e)
                continue
            for e in entries:
                cls = "timer" if e.name.endswith(".timer") else "systemd_user_unit" if e.name.endswith(UNIT_EXTS) else None
                if not cls:
                    continue
                try:
                    st = e.stat(follow_symlinks=False)
                except OSError as ex:
                    self.err(e.path, ex)
                    continue
                if e.is_dir(follow_symlinks=False):
                    continue
                self.row(cls, e.path, st.st_mtime, st.st_size, "%d:%d" % (st.st_size, st.st_mtime))

    def scan_crontab(self):
        """User crontab: count of active lines only; contents are hashed and discarded."""
        if self.no_crontab:
            return
        try:
            p = subprocess.run(["crontab", "-l"], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               timeout=10, stdin=subprocess.DEVNULL)
        except FileNotFoundError:
            self.err("crontab", "crontab binary not found (use --no-crontab if this host has no cron)")
            return
        except (OSError, subprocess.TimeoutExpired) as e:
            self.err("crontab", e)
            return
        if p.returncode != 0:
            if b"no crontab" not in p.stderr.lower():  # only this message means "empty"
                self.err("crontab", "crontab -l failed: %s" % p.stderr.decode("utf-8", "replace").strip()[:100])
            return
        text = p.stdout.decode("utf-8", "replace")
        n = len([l for l in text.split("\n") if l.strip() and not l.strip().startswith("#")])
        if n:
            self.row("crontab", "crontab:%s" % getpass.getuser(), self.now, None,
                     hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()[:16], n)

    # ---- tree walk ----
    def is_sqlite(self, path, name):
        if name.endswith((".sqlite", ".sqlite3")):
            return True
        try:  # .db: header magic only, no other content; O_NONBLOCK so a FIFO cannot hang us
            fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0))
        except OSError:
            return False
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                return False
            return os.read(fd, 16) == SQLITE_MAGIC
        except OSError:
            return False
        finally:
            os.close(fd)

    def inside(self, target, prefixes):
        return any(target == r or target.startswith(r.rstrip("/") + "/") for r in prefixes)

    def walked(self, target):
        """target is inside a scanned root AND no pruned directory name lies on the way to it."""
        for r in self.roots_real:
            if target == r or target.startswith(r.rstrip("/") + "/"):
                rel = os.path.relpath(target, r)
                if not any(part in self.prune for part in rel.split(os.sep)):
                    return True
        return False

    def note_symlink(self, path, force=False):
        """A symlink we did not follow. Blocks report unless its target is inside a scanned root
        (it is then inventoried through the real path) or under --allow-symlink-target."""
        target = os.path.realpath(path)
        if not force and self.walked(target):
            return
        if not force and self.inside(target, self.symlink_allow):
            if len(self.acked_symlinks) < MAX_ERRORS:
                self.acked_symlinks.append({"path": path, "target": target})
            return
        self.skipped_symlinks_total += 1
        if len(self.skipped_symlinks) < MAX_ERRORS:
            self.skipped_symlinks.append({"path": path, "target": target})

    def is_own_git_dir(self, d):
        """A HEAD/objects/refs look-alike inside an enclosing repo is not a bare repo."""
        try:
            rc, out, _ = self.git(d, "rev-parse", "--git-dir")
        except RuntimeError:
            return False
        return rc == 0 and os.path.realpath(os.path.join(d, out.strip())) == os.path.realpath(d)

    def walk(self, root):
        try:
            dev = os.lstat(root).st_dev
        except OSError as e:
            self.err(root, e)
            return
        stack = [(root, None)]
        while stack:
            if self.budget.over():
                return
            cur, repo_root = stack.pop()
            try:
                with os.scandir(cur) as it:
                    entries = list(it)
            except OSError as e:
                self.err(cur, e)
                continue
            self.dirs += 1
            names = {e.name: e for e in entries}
            # bare repository: HEAD + objects + refs; inventory it, do not descend
            if (all(n in names for n in ("HEAD", "objects", "refs")) and ".git" not in names
                    and self.is_own_git_dir(cur)):
                self.analyze_repo(cur)  # bare repository: inventory it
                if repo_root is None:
                    continue  # standalone bare repo: nothing else to find inside
                # inside an enclosing work tree (git accepts any HEAD/objects/refs dir as bare): keep walking
            g = names.get(".git")
            if g is not None:
                try:
                    if g.is_symlink():
                        self.note_symlink(g.path, force=True)  # repo not analysed: always blocks
                    elif g.is_dir(follow_symlinks=False) or g.is_file(follow_symlinks=False):
                        self.analyze_repo(cur)
                        repo_root = cur
                except OSError as e:
                    self.err(cur, e)
            for e in entries:
                try:
                    if e.is_symlink():
                        if e.name in self.prune or e.name == ".git":
                            continue
                        if e.is_dir():  # follows the link only to learn it is a directory
                            self.note_symlink(e.path)
                        elif e.name.endswith(DB_EXTS) and os.path.exists(e.path):
                            self.note_symlink(e.path)
                        continue
                    if e.is_dir(follow_symlinks=False):
                        if e.name in self.prune:
                            continue
                        if not self.cross and e.stat(follow_symlinks=False).st_dev != dev:
                            self.skipped_mounts.append(e.path)
                            continue
                        stack.append((e.path, repo_root))
                    elif e.name.endswith(DB_EXTS) and e.is_file(follow_symlinks=False):
                        st = e.stat(follow_symlinks=False)
                        if (st.st_size >= self.min_db and self.is_sqlite(e.path, e.name)
                                and not (repo_root and self.tracked(repo_root, e.path))):
                            self.row("state_db_outside_git", e.path, st.st_mtime, st.st_size,
                                     "%d:%d" % (st.st_size, st.st_mtime))
                except OSError as ex:
                    self.err(e.path, ex)


def local_host_names():
    names = {"localhost", "::1"}
    for n in (socket.gethostname(), socket.getfqdn()):
        if n:
            names.add(n.lower())
            names.add(n.lower().split(".")[0])
    try:  # this machine's own addresses
        for info in socket.getaddrinfo(socket.gethostname(), None):
            names.add(info[4][0].lower())
    except OSError:
        pass
    return names


def url_is_local(url, local_names):
    """True if a remote URL points at this machine (a path, file://, localhost or our own hostname)."""
    u = re.sub(r"^[A-Za-z0-9_+.-]+::", "", url.strip())  # remote helpers: gcrypt::/path, ext::...
    if url.strip() != u and not u.startswith(("http://", "https://", "ssh://", "git://")):
        return True  # helper with a bare address: cannot prove it is off-host, so count as local
    if not u or u == "." or u.startswith(("/", "./", "../", "~", "file:")):
        return True
    m = re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://(?:[^@/]*@)?(\[[^\]]+\]|[^:/]+)", u)
    if not m:
        m = re.match(r"^(?:[^@/:]+@)?(\[[^\]]+\]|[^:/]+):", u)  # scp-like host:path
    if not m:
        return True  # plain relative path
    host = m.group(1).strip("[]").lower()
    try:
        ip = ipaddress.ip_address(host)
        if ip.is_loopback or ip.is_unspecified or ip.is_link_local:
            return True
    except ValueError:
        pass
    return host in local_names or host.split(".")[0] in local_names


# decisions on these classes are voided by ANY change of the row fingerprint: the content behind a
# branch/tree/stash/crontab can change under the same path
GUARDED = {"unpushed_branch", "no_remote_repo", "git_stash", "local_tag", "dirty_worktree", "crontab"}


def load_decisions():
    """Latest decision per path (file order wins). Malformed or undecodable lines are skipped."""
    out = {}
    try:
        with open(os.path.join(state_dir(), "decisions.jsonl"), "rb") as f:
            for raw in f:
                try:
                    d = json.loads(raw.decode("utf-8"))
                except ValueError:
                    continue
                if isinstance(d, dict) and isinstance(d.get("path"), str) and d.get("decision") in DECISIONS:
                    out[d["path"]] = d
    except FileNotFoundError:
        pass
    return out


def merge_decisions(rows):
    """Apply recorded decisions unless the row changed since it was decided (fingerprint)."""
    dec = load_decisions()
    for r in rows:
        d = dec.get(r["path"])
        stale = False
        if d is not None:
            if r["class"] in GUARDED:
                stale = r.get("fp") is None or d.get("fp") != r.get("fp")  # unknown fingerprint: fail closed
            else:  # live DBs/units: only a "moved" claim depends on content
                stale = d["decision"] == "moved" and d.get("fp") is not None and r.get("fp") is not None and d["fp"] != r["fp"]
        r["decision"] = d["decision"] if d is not None and not stale else None
        r["decision_stale"] = True if stale else None
    return rows


def ensure_state_dir():
    d = state_dir()
    os.makedirs(d, mode=0o700, exist_ok=True)
    os.chmod(d, 0o700)
    return d


def write_private(path, text):
    ensure_state_dir()
    fd, tmp = tempfile.mkstemp(prefix=".tmp-", dir=os.path.dirname(path))  # O_EXCL, mode 0600
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def cmd_scan(args):
    roots = [os.path.abspath(os.path.expanduser(r)) for r in args.root]
    for a in args.allow_symlink_target or []:
        if os.path.realpath(os.path.expanduser(a)) == "/":
            print("error: --allow-symlink-target / would silence every symlink", file=sys.stderr)
            return 2
    s = Scan(args)
    s.roots_real = [os.path.realpath(r) for r in roots]
    s.scan_units()
    s.scan_crontab()
    for r in roots:
        s.walk(r)
    uniq = {}
    for r in s.rows:  # overlapping roots must not double-count
        uniq[(r["class"], r["path"])] = r
    s.rows = sorted(uniq.values(), key=lambda r: (r["class"], r["path"]))
    merge_decisions(s.rows)
    classes = dict((c, 0) for c in CLASSES)
    for r in s.rows:
        classes[r["class"]] += 1
    result = {
        "schema": SCHEMA, "host": socket.gethostname(), "scanned_at": now_iso(), "roots": roots,
        "classes": classes, "rows": s.rows,
        "partial": s.budget.exceeded,
        "partial_reason": "max-seconds budget exceeded" if s.budget.exceeded else None,
        "dirs_scanned": s.dirs, "repos_scanned": s.repos,
        "errors": s.errors, "errors_total": s.errors_total,
        "skipped_mounts": s.skipped_mounts[:MAX_ERRORS], "skipped_mounts_total": len(s.skipped_mounts),
        "skipped_symlinks": s.skipped_symlinks, "skipped_symlinks_total": s.skipped_symlinks_total,
        "symlink_allow": s.symlink_allow, "acked_symlinks": s.acked_symlinks,
        "excludes": sorted(s.extra_prune), "prune": sorted(PRUNE),
        "min_db_bytes": s.min_db, "no_crontab": bool(s.no_crontab),
        "note": "git state comes from local refs only (never fetched); remote-tracking refs may be stale",
    }
    if not args.no_save:
        write_private(os.path.join(state_dir(), "last-scan.json"), json.dumps(result, indent=1))
    if args.json:
        print(json.dumps(result, indent=1))
    else:
        print("host=%s partial=%s dirs=%d repos=%d errors=%d" % (
            result["host"], result["partial"], s.dirs, s.repos, s.errors_total))
        for c in CLASSES:
            print("%-22s %d" % (c, classes[c]))
    return 0


STATE_MAX_BYTES = 64 * 1024 * 1024  # a dev2 scan is ~250 bytes per row; this allows ~250k rows


def load_last():
    """The saved scan, or None when it is missing, oversized or malformed. Every caller treats None as
    "no usable scan" and exits 2, so a damaged file can never read as zero losses."""
    path = os.path.join(state_dir(), "last-scan.json")
    try:
        with open(path, "rb") as f:
            raw = f.read(STATE_MAX_BYTES + 1)  # input-ok: the tool's own 0600 state file; oversize is rejected below
    except OSError:
        return None
    if len(raw) > STATE_MAX_BYTES:
        print("error: %s is larger than %d bytes; refusing to load it" % (path, STATE_MAX_BYTES), file=sys.stderr)
        return None
    try:
        d = json.loads(raw.decode("utf-8"))  # input-ok: bounded by the read above
    except ValueError:
        print("error: %s is not valid JSON" % path, file=sys.stderr)
        return None
    if not isinstance(d, dict) or not isinstance(d.get("rows"), list):
        print("error: %s does not hold a saved scan" % path, file=sys.stderr)
        return None
    d["rows"] = [r for r in d["rows"] if isinstance(r, dict) and isinstance(r.get("path"), str) and r.get("class")]
    return d


def cmd_decide(args):
    if args.decision not in DECISIONS:
        print("error: decision must be one of %s" % ", ".join(DECISIONS), file=sys.stderr)
        return 2
    ticket = (args.ticket or "").strip()
    if not ticket or len(ticket) > 200 or any(ord(c) < 32 or c.isspace() for c in ticket):
        print("error: --ticket is required (no whitespace/control characters, max 200 chars)", file=sys.stderr)
        return 2
    last = load_last()
    if last is None:
        print("error: no saved scan; run scan first", file=sys.stderr)
        return 2
    path = args.row if args.row in {r["path"] for r in last["rows"]} else os.path.abspath(args.row)
    match = [r for r in last["rows"] if r["path"] == path]
    if not match:
        print("error: %s is not a row of the last scan" % args.row, file=sys.stderr)
        return 2
    entry = {"ts": now_iso(), "path": path, "class": match[0]["class"], "decision": args.decision,
             "ticket": ticket, "by": args.by or getpass.getuser(), "fp": match[0].get("fp")}
    ensure_state_dir()
    fd = os.open(os.path.join(state_dir(), "decisions.jsonl"), os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    try:
        os.write(fd, (json.dumps(entry) + "\n").encode("utf-8"))  # one write: atomic append
        os.fsync(fd)
    finally:
        os.close(fd)
    print(json.dumps(entry))
    return 0


def roots_cover_home(roots):
    home = os.path.realpath(os.path.expanduser("~"))
    for r in roots:
        r = os.path.realpath(r).rstrip("/")
        if home == r or home.startswith(r + "/") or r == "":
            return True
    return False


def cmd_report(args):
    last = load_last()
    if last is None:
        print("error: no saved scan; run scan first", file=sys.stderr)
        return 2
    problems = []  # each one means "this scan cannot prove nothing is left"
    missing = [k for k in REQUIRED_KEYS if k not in last]
    if missing:
        problems.append("INCOMPLETE\tsaved scan is incomplete or not written by this tool (missing: %s)" % ",".join(missing))
    elif last.get("schema") != SCHEMA:
        problems.append("INCOMPLETE\tsaved scan has schema %r, expected %d; rescan" % (last.get("schema"), SCHEMA))
    try:
        age_h = (datetime.now(timezone.utc) - datetime.strptime(last.get("scanned_at", ""), "%Y-%m-%dT%H:%M:%SZ")
                 .replace(tzinfo=timezone.utc)).total_seconds() / 3600.0
    except (ValueError, TypeError):
        age_h = None
        problems.append("INCOMPLETE\tscanned_at missing or unparseable")
    if age_h is not None and age_h > args.max_age:
        problems.append("STALE\tscan is %.1f h old, older than --max-age %g h; rescan" % (age_h, args.max_age))
    roots = last.get("roots") or []
    if not args.allow_partial_roots and not roots_cover_home(roots):
        problems.append("ROOTS\tscanned roots do not include $HOME; rescan with --root ~ (or --allow-partial-roots)")
    if args.expect_host and last.get("host") != args.expect_host:
        problems.append("HOST\tscan was taken on %r, expected %r" % (last.get("host"), args.expect_host))
    mdb = last.get("min_db_bytes")
    if not isinstance(mdb, int) or isinstance(mdb, bool) or mdb > DEFAULT_MIN_DB:
        problems.append("DB_THRESHOLD\tscan skipped databases below %s bytes (default %d); rescan with the default" % (last.get("min_db_bytes"), DEFAULT_MIN_DB))
    if last.get("excludes") and not args.ack_excludes:
        problems.append("EXCLUDES\tdirectory names excluded from the scan (%s): anything under them was not inventoried; review and pass --ack-excludes" % ",".join(last["excludes"]))
    if last.get("no_crontab"):
        problems.append("NO_CRONTAB\tcrontab was not checked (--no-crontab)")
    undecided = [r for r in merge_decisions(last["rows"]) if r.get("decision") is None]
    if last.get("partial"):
        problems.append("PARTIAL\tscan hit its --max-seconds budget; some of the tree was not scanned")
    errors = last.get("errors") or []
    if last.get("errors_total", len(errors)) > 0:
        problems.append("ERRORS\t%d scan errors" % last.get("errors_total", len(errors)))
    if last.get("skipped_mounts_total", 0) > 0:
        problems.append("SKIPPED_MOUNTS\t%d other-filesystem dirs not scanned; rescan with --cross-devices" % last["skipped_mounts_total"])
    if last.get("skipped_symlinks_total", 0) > 0:
        problems.append("SKIPPED_SYMLINKS\t%d symlinks not followed whose target is outside the scanned roots; scan the target as a --root or use --allow-symlink-target" % last["skipped_symlinks_total"])
    if args.json:
        print(json.dumps({"scanned_at": last.get("scanned_at"), "roots": roots, "problems": problems,
                          "partial": bool(last.get("partial")), "errors_total": last.get("errors_total"),
                          "errors": errors, "skipped_mounts": last.get("skipped_mounts", []),
                          "skipped_symlinks": last.get("skipped_symlinks", []),
                          "symlink_allow": last.get("symlink_allow", []), "acked_symlinks": last.get("acked_symlinks", []),
                          "excludes": last.get("excludes", []),
                          "prune": last.get("prune", []), "undecided": undecided}, indent=1))
    else:
        print("last scan %s (incomplete)" % last.get("scanned_at") if problems else "last scan %s" % last.get("scanned_at"))
        print("HOST\t%s\tMIN_DB_BYTES\t%s" % (last.get("host"), last.get("min_db_bytes")))
        print("ROOTS\t%s" % ",".join(roots))
        for r in undecided:
            print("%s\t%s\tage_days=%s\tbytes=%s%s" % (r["class"], r["path"], r.get("age_days"), r.get("bytes"),
                                                       "\t(decision stale: changed since decided)" if r.get("decision_stale") else ""))
        for pr in problems:
            print(pr)
        for e in errors:
            print("ERROR\t%s\t%s" % (e["path"], e["error"]))
        for m in last.get("skipped_mounts", []):
            print("SKIPPED_MOUNT\t%s" % m)
        if last.get("symlink_allow"):
            print("SYMLINK_ALLOW\t%s" % ",".join(last["symlink_allow"]))
        for sl in last.get("acked_symlinks", []):
            print("ACKED_SYMLINK\t%s -> %s" % (sl["path"], sl["target"]))
        for sl in last.get("skipped_symlinks", []):
            print("SKIPPED_SYMLINK\t%s -> %s" % (sl["path"], sl["target"]))
        if last.get("excludes"):
            print("EXCLUDED_DIR_NAMES\t%s (anything under these names anywhere was not inventoried)" % ",".join(last["excludes"]))
        print("PRUNED_DIR_NAMES\t%s (never inventoried)" % ",".join(last.get("prune", [])))
        print("%d undecided, %d problems" % (len(undecided), len(problems)))
    return 1 if (undecided or problems) else 0


def main(argv=None):
    try:  # non-UTF-8 file names must not crash text output
        sys.stdout.reconfigure(errors="backslashreplace")
    except (AttributeError, ValueError):
        pass
    p = argparse.ArgumentParser(prog="loss_inventory.py", description=__doc__.split("\n")[0])
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan")
    s.add_argument("--root", action="append", required=True)
    s.add_argument("--json", action="store_true")
    s.add_argument("--max-seconds", type=float, default=900, help="time budget, 0 = unlimited (default 900)")
    s.add_argument("--min-db-bytes", type=int, default=DEFAULT_MIN_DB)
    s.add_argument("--exclude", action="append", help="extra directory name to skip (reported)")
    s.add_argument("--cross-devices", action="store_true")
    s.add_argument("--allow-symlink-target", action="append", help="acknowledge symlinks whose target is under this path (reported)")
    s.add_argument("--no-crontab", action="store_true", help="host has no cron (reported)")
    s.add_argument("--no-save", action="store_true")
    d = sub.add_parser("decide")
    d.add_argument("--row", required=True)
    d.add_argument("--decision", required=True)
    d.add_argument("--ticket", required=True)
    d.add_argument("--by")
    r = sub.add_parser("report")
    r.add_argument("--json", action="store_true")
    r.add_argument("--max-age", type=float, default=24, help="max scan age in hours (default 24)")
    r.add_argument("--ack-excludes", action="store_true", help="acknowledge the scan's --exclude names (they are printed)")
    r.add_argument("--expect-host", help="fail unless the saved scan was taken on this host")
    r.add_argument("--allow-partial-roots", action="store_true", help="do not require $HOME under the scanned roots")
    args = p.parse_args(argv)
    return {"scan": cmd_scan, "decide": cmd_decide, "report": cmd_report}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
