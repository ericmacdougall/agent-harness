#!/usr/bin/env python3
"""Loss-class inventory for a host that is about to be decommissioned (goodqa#14565, PL-03).

Single-file, stdlib-only. Counts and paths only: it never reads file contents
(the one exception is the 16-byte SQLite magic header of a ``.db`` file, used
to avoid listing non-database files) and never prints secrets.

Subcommands
  scan   --root DIR [--root DIR ...] [--json] [--max-seconds N] [--min-db-bytes N]
         Walk the roots and classify what would be lost with the host:
           unpushed_branch      local branch (or detached HEAD) whose tip is in no
                                remote-tracking ref (LOCAL refs only; never fetches,
                                so it can be stale versus the real remote)
           no_remote_repo       git work tree with no remote at all
           systemd_user_unit    *.service in $HOME/.config/systemd/user
           timer                *.timer in $HOME/.config/systemd/user
           state_db_outside_git sqlite/db file >= --min-db-bytes outside any git work tree
         The result is saved to $HOME/.agent-harness/state/loss-inventory/last-scan.json.
  decide --row PATH --decision moved|rebuildable|accepted-loss --ticket REF
         Append a decision to $HOME/.agent-harness/state/loss-inventory/decisions.jsonl.
         PATH must be a row of the last saved scan.
  report [--json]
         Print rows of the last saved scan that have no decision. Exit 1 if any remain
         or the saved scan was partial (a partial scan cannot prove nothing is left),
         exit 2 if there is no saved scan, otherwise 0.

Safety: symlinks are never followed (a symlinked directory is not entered, a symlinked
file is not sized through); the walk does not cross filesystems unless --cross-devices;
node_modules, .git internals, virtualenvs and caches are skipped; every git call has a
timeout and a failing repo becomes an entry in "errors", not a crash.
"""
import argparse
import getpass
import json
import os
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone

CLASSES = ("unpushed_branch", "no_remote_repo", "systemd_user_unit", "timer", "state_db_outside_git")
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
        self.prune = PRUNE | set(args.exclude or [])
        self.cross = args.cross_devices
        self.rows = []
        self.errors = []
        self.errors_total = 0
        self.dirs = 0
        self.repos = 0
        self.now = time.time()

    def err(self, path, what):
        self.errors_total += 1
        if len(self.errors) < MAX_ERRORS:
            self.errors.append({"path": path, "error": str(what)[:200]})

    def row(self, cls, path, mtime, size):
        age = None if mtime is None else round(max(0.0, self.now - mtime) / 86400.0, 1)
        self.rows.append({"class": cls, "path": path, "age_days": age, "bytes": size, "decision": None})

    # ---- git (local refs only, never fetch) ----
    def git(self, repo, *argv):
        left = self.budget.left()
        timeout = GIT_TIMEOUT if left is None else max(1.0, min(GIT_TIMEOUT, left))
        env = dict(os.environ, GIT_TERMINAL_PROMPT="0", GIT_OPTIONAL_LOCKS="0")
        try:
            p = subprocess.run(["git", "-C", repo] + list(argv), stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, timeout=timeout, env=env, stdin=subprocess.DEVNULL)
        except subprocess.TimeoutExpired:
            raise RuntimeError("git %s timed out" % argv[0])
        except OSError as e:
            raise RuntimeError("git not runnable: %s" % e)
        return p.returncode, p.stdout.decode("utf-8", "replace"), p.stderr.decode("utf-8", "replace")

    def contained_in(self, repo, sha, *namespaces):
        """True if some ref under the namespaces contains commit sha (for-each-ref --contains)."""
        rc, out, er = self.git(repo, "for-each-ref", "--count=1", "--format=%(refname)",
                               "--contains", sha, *namespaces)
        if rc != 0:
            raise RuntimeError("for-each-ref --contains failed: %s" % er.strip()[:120])
        return bool(out.strip())

    def analyze_repo(self, repo, gitpath, linked):
        self.repos += 1
        try:
            rc, out, er = self.git(repo, "remote")
            if rc != 0:
                raise RuntimeError("git remote failed: %s" % er.strip()[:120])
            if not out.strip():
                try:
                    st = os.lstat(gitpath)
                    mtime = st.st_mtime
                except OSError:
                    mtime = None
                self.row("no_remote_repo", repo, mtime, self.pack_bytes(gitpath))
                return
            if not linked:  # linked worktrees share refs with their main repo
                rc, out, er = self.git(repo, "for-each-ref", "--format=%(refname:short)\t%(objectname)\t%(committerdate:unix)",
                                       "refs/heads")
                if rc != 0:
                    raise RuntimeError("for-each-ref failed: %s" % er.strip()[:120])
                for line in out.splitlines():
                    parts = line.split("\t")
                    if len(parts) != 3 or self.budget.over():
                        continue
                    name, sha, ct = parts
                    if not self.contained_in(repo, sha, "refs/remotes"):
                        self.row("unpushed_branch", "%s::%s" % (repo, name), float(ct) if ct.isdigit() else None, None)
            if self.budget.over():
                return
            rc, _, _ = self.git(repo, "symbolic-ref", "-q", "HEAD")
            if rc == 1:  # detached HEAD
                rc, sha, _ = self.git(repo, "rev-parse", "--verify", "-q", "HEAD")
                sha = sha.strip()
                if rc == 0 and sha and not self.contained_in(repo, sha, "refs/remotes", "refs/heads", "refs/tags"):
                    rc, ct, _ = self.git(repo, "log", "-1", "--format=%ct", sha)
                    ct = ct.strip()
                    self.row("unpushed_branch", "%s::(detached HEAD)" % repo,
                             float(ct) if ct.isdigit() else None, None)
        except RuntimeError as e:
            self.err(repo, e)

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

    # ---- systemd user units ----
    def scan_units(self):
        d = os.path.join(os.path.expanduser("~"), ".config", "systemd", "user")
        try:
            with os.scandir(d) as it:
                entries = sorted(it, key=lambda e: e.name)
        except FileNotFoundError:
            return
        except OSError as e:
            self.err(d, e)
            return
        for e in entries:
            cls = "systemd_user_unit" if e.name.endswith(".service") else "timer" if e.name.endswith(".timer") else None
            if not cls:
                continue
            try:
                st = e.stat(follow_symlinks=False)
            except OSError as ex:
                self.err(e.path, ex)
                continue
            if e.is_dir(follow_symlinks=False):
                continue
            self.row(cls, e.path, st.st_mtime, st.st_size)

    # ---- tree walk ----
    def is_sqlite(self, path, name):
        if name.endswith((".sqlite", ".sqlite3")):
            return True
        try:  # .db: header magic only, no other content
            with open(path, "rb") as f:
                return f.read(16) == SQLITE_MAGIC
        except OSError:
            return False

    def walk(self, root):
        try:
            dev = os.lstat(root).st_dev
        except OSError as e:
            self.err(root, e)
            return
        stack = [(root, False)]
        while stack:
            if self.budget.over():
                return
            cur, in_repo = stack.pop()
            try:
                with os.scandir(cur) as it:
                    entries = list(it)
            except OSError as e:
                self.err(cur, e)
                continue
            self.dirs += 1
            names = {e.name: e for e in entries}
            # bare repository: HEAD + objects + refs; nothing to inventory, do not descend
            if all(n in names for n in ("HEAD", "objects", "refs")) and ".git" not in names:
                continue
            g = names.get(".git")
            if g is not None:
                try:
                    if g.is_dir(follow_symlinks=False):
                        self.analyze_repo(cur, g.path, False)
                        in_repo = True
                    elif g.is_file(follow_symlinks=False):
                        self.analyze_repo(cur, g.path, True)
                        in_repo = True
                except OSError as e:
                    self.err(cur, e)
            for e in entries:
                try:
                    if e.is_symlink():
                        continue
                    if e.is_dir(follow_symlinks=False):
                        if e.name in self.prune:
                            continue
                        if not self.cross and e.stat(follow_symlinks=False).st_dev != dev:
                            continue
                        stack.append((e.path, in_repo))
                    elif not in_repo and e.name.endswith(DB_EXTS) and e.is_file(follow_symlinks=False):
                        st = e.stat(follow_symlinks=False)
                        if st.st_size >= self.min_db and self.is_sqlite(e.path, e.name):
                            self.row("state_db_outside_git", e.path, st.st_mtime, st.st_size)
                except OSError as ex:
                    self.err(e.path, ex)


def load_decisions():
    """Latest decision per path (file order wins). Malformed lines are skipped."""
    out = {}
    try:
        with open(os.path.join(state_dir(), "decisions.jsonl"), encoding="utf-8") as f:
            for line in f:
                try:
                    d = json.loads(line)
                except ValueError:
                    continue
                if isinstance(d, dict) and isinstance(d.get("path"), str) and d.get("decision") in DECISIONS:
                    out[d["path"]] = d
    except FileNotFoundError:
        pass
    return out


def merge_decisions(rows):
    dec = load_decisions()
    for r in rows:
        d = dec.get(r["path"])
        r["decision"] = d["decision"] if d else None
    return rows


def write_private(path, text):
    os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
    tmp = "%s.%d.tmp" % (path, os.getpid())
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(text)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)


def cmd_scan(args):
    roots = [os.path.abspath(os.path.expanduser(r)) for r in args.root]
    s = Scan(args)
    s.scan_units()
    for r in roots:
        s.walk(r)
    s.rows.sort(key=lambda r: (r["class"], r["path"]))
    merge_decisions(s.rows)
    classes = dict((c, 0) for c in CLASSES)
    for r in s.rows:
        classes[r["class"]] += 1
    result = {
        "host": socket.gethostname(), "scanned_at": now_iso(), "roots": roots,
        "classes": classes, "rows": s.rows,
        "partial": s.budget.exceeded,
        "partial_reason": "max-seconds budget exceeded" if s.budget.exceeded else None,
        "dirs_scanned": s.dirs, "repos_scanned": s.repos,
        "errors": s.errors, "errors_total": s.errors_total,
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


def load_last():
    try:
        with open(os.path.join(state_dir(), "last-scan.json"), encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


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
             "ticket": ticket, "by": args.by or getpass.getuser()}
    os.makedirs(state_dir(), mode=0o700, exist_ok=True)
    fd = os.open(os.path.join(state_dir(), "decisions.jsonl"), os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    try:
        os.write(fd, (json.dumps(entry) + "\n").encode("utf-8"))  # one write: atomic append
        os.fsync(fd)
    finally:
        os.close(fd)
    print(json.dumps(entry))
    return 0


def cmd_report(args):
    last = load_last()
    if last is None:
        print("error: no saved scan; run scan first", file=sys.stderr)
        return 2
    undecided = [r for r in merge_decisions(last["rows"]) if r["decision"] is None]
    partial = bool(last.get("partial"))
    if args.json:
        print(json.dumps({"scanned_at": last.get("scanned_at"), "partial": partial,
                          "undecided": undecided}, indent=1))
    else:
        print("last scan %s%s" % (last.get("scanned_at"), " (PARTIAL: some of the tree was not scanned)" if partial else ""))
        for r in undecided:
            print("%s\t%s\tage_days=%s\tbytes=%s" % (r["class"], r["path"], r["age_days"], r["bytes"]))
        print("%d undecided" % len(undecided))
    return 1 if (undecided or partial) else 0


def main(argv=None):
    p = argparse.ArgumentParser(prog="loss_inventory.py", description=__doc__.split("\n")[0])
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan")
    s.add_argument("--root", action="append", required=True)
    s.add_argument("--json", action="store_true")
    s.add_argument("--max-seconds", type=float, default=900, help="time budget, 0 = unlimited (default 900)")
    s.add_argument("--min-db-bytes", type=int, default=1000000)
    s.add_argument("--exclude", action="append", help="extra directory name to skip")
    s.add_argument("--cross-devices", action="store_true")
    s.add_argument("--no-save", action="store_true")
    d = sub.add_parser("decide")
    d.add_argument("--row", required=True)
    d.add_argument("--decision", required=True)
    d.add_argument("--ticket", required=True)
    d.add_argument("--by")
    r = sub.add_parser("report")
    r.add_argument("--json", action="store_true")
    args = p.parse_args(argv)
    return {"scan": cmd_scan, "decide": cmd_decide, "report": cmd_report}[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
