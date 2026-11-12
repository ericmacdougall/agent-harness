"""`ah install-files`: install MERGED hook files on a remote host through one audited command (goodqa#15742).

The 2026-11-11 t2-dev install of command_guard.py was blocked as a remote `cp` and then done with `scp`, a second route
around a guard. This command is the sanctioned route:

  * the bytes come only from a commit proven to be an ancestor of the canonical harness repository's main, fetched into a
    FRESH repository this tool owns (never one the caller names); the commit, the trees on the path and the blob are
    re-hashed here before use; names only from the installer's HOOKS tuple at that commit;
  * the host gets a constant remote program (REMOTE_SCRIPT, text never built from caller input) run as one shell-quoted
    command through ssh: stage and verify every file (nothing live changes), then rename them in a fixed order with
    command_guard.py LAST, read the shas back and compare the host's own self-test with its baseline; anything worse rolls
    every file back (guard first);
  * an audit row on the Mac before the first remote write and after the run, one on the host; an unknown outcome is never
    reported as installed or refused; a host with an unfinished run refuses new runs until it is resumed or rolled back.

Threat model: careless or hurried agents, not one that edits this module or the audit file.
"""
from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import shlex
import shutil
import subprocess
import time
import uuid
from pathlib import Path

HOSTS = ("t2-dev", "ah-mac-mini")
CANONICAL_URL = "https://github.com/ericmacdougall/agent-harness.git"
ALLOW_FILE = False  # tests only: lets the fetch read a local bare repository standing in for the canonical URL
REMOTE_PREFIX = ""  # tests only: a `HOME=... ` assignment so a real ssh-to-localhost run uses a disposable home
MAX_FILES = 20
MAX_BLOB = 4 * 1024 * 1024
NAME_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]*")
REF_RE = re.compile(r"[0-9a-f]{40}")
TICKET_RE = re.compile(r"GoodQA [A-Za-z0-9_-]+#[0-9]+")
RUN_RE = re.compile(r"ins-[0-9a-f]{12}")
SSH_TIMEOUT = 120
SELFTEST_TIMEOUT = 300
HOST_AUDIT = ".agent-harness/install-audit.jsonl"
FIRST = ("doctor.py", "ah.py")  # no special order beyond: command_guard.py is always last


class InstallError(Exception):
    def __init__(self, code, message, exit_code=2, data=None):
        super().__init__(message)
        self.code, self.exit_code, self.data = code, exit_code, data or {}


def refuse(message, code="refused", exit_code=2, data=None):
    raise InstallError(code, message, exit_code, data)


# ----------------------------------------------------------------------------- the constant remote program
# Runs on the host as `python3 -I -c SCRIPT OP JSON`, file bytes on stdin for `stage`. Python 3.9 compatible, standard
# library only. Every path is built from the fixed hooks directory and a name matched against NAME_RE; it never reads a
# path from the caller.
REMOTE_SCRIPT = r'''
import hashlib, json, os, re, shutil, stat, subprocess, sys, time, uuid
NAME = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]*")
HOOKS = os.path.expanduser("~/.claude/hooks")
STATE = os.path.join(HOOKS, ".ah-install")
LOCK = os.path.join(STATE, "lock")
BACKUPS = os.path.join(STATE, "backups")
STALE = 1800
out = {}

def sha(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

def kind(path):
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return "absent"
    if stat.S_ISLNK(st.st_mode):
        return "symlink"
    if stat.S_ISREG(st.st_mode):
        return "file"
    return "other"

def need(name):
    if not isinstance(name, str) or not NAME.fullmatch(name) or name.startswith(".."):
        raise SystemExit("bad name")
    return name

def live(name):
    return os.path.join(HOOKS, need(name))

def temp(name):
    return os.path.join(HOOKS, "." + need(name) + ".ah-install-tmp")

def mkdir_private(path):
    try:
        os.mkdir(path, 0o700)
    except FileExistsError:
        pass
    if kind(path) != "other" or os.path.islink(path):
        raise SystemExit("not a plain directory: " + os.path.basename(path))

def fsync_dir(path):
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)

def write_exclusive(path, data, mode):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)

def replace_with(name, data, mode):
    t = temp(name)
    if kind(t) == "file":
        os.unlink(t)
    elif kind(t) != "absent":
        raise SystemExit("temporary name is not a regular file: " + name)
    write_exclusive(t, data, 0o600)
    os.chmod(t, mode)
    return t

def selftest():
    guard = os.path.join(HOOKS, "command_guard.py")
    res = {"guard": {}, "doctor": None}
    probes = {"allow": "ls -la",
              "deny_wal": "rm -rf ~/.claude/wals",
              "deny_hooks_copy": 'ssh t2-dev "cp x ~/.claude/hooks/command_guard.py"'}
    for key, cmd in probes.items():
        try:
            p = subprocess.run([sys.executable, "-I", guard, "check", cmd], capture_output=True, text=True, timeout=60,
                               cwd=os.path.expanduser("~"))
            data = json.loads((p.stdout or "").strip().splitlines()[-1])
            rule = re.search(r"\[([A-Za-z0-9_/-]+)\]", data.get("message") or "")
            res["guard"][key] = {"exit": p.returncode, "verdict": str(data.get("verdict")), "rule": rule.group(1) if rule else ""}
        except Exception as e:
            res["guard"][key] = {"exit": None, "verdict": "error:" + type(e).__name__, "rule": ""}
    doctor = os.path.join(HOOKS, "doctor.py")
    if os.path.exists(doctor):
        try:
            p = subprocess.run([sys.executable, "-I", doctor, "check", "--json", "--no-canary"], capture_output=True, text=True,
                               timeout=120, cwd=os.path.expanduser("~"))
            if "unrecognized arguments" in (p.stderr or ""):
                res["doctor"] = {"flags": False, "failing": None}
            else:
                data = json.loads(p.stdout)
                items = data if isinstance(data, list) else data.get("findings") or data.get("checks") or []
                failing = sorted(str(i.get("id") or "?") for i in items
                                 if isinstance(i, dict) and str(i.get("state", "WIRED")) not in ("WIRED", "PENDING"))
                res["doctor"] = {"flags": True, "failing": failing, "exit": p.returncode}
        except subprocess.TimeoutExpired:
            res["doctor"] = {"flags": True, "failing": None, "timeout": True}
        except Exception as e:
            res["doctor"] = {"flags": True, "failing": None, "error": type(e).__name__}
    return res

op = sys.argv[1]
args = json.loads(sys.argv[2]) if len(sys.argv) > 2 else {}
if op == "probe":
    items = {}
    for name in args["names"]:
        p = live(name)
        k = kind(p)
        items[name] = {"kind": k, "sha": sha(p) if k == "file" else None,
                       "mode": stat.S_IMODE(os.lstat(p).st_mode) if k == "file" else None,
                       "temp": kind(temp(name))}
    out["files"] = items
    out["lock"] = kind(LOCK)
    out["list"] = sorted((n, os.lstat(os.path.join(HOOKS, n)).st_size, os.lstat(os.path.join(HOOKS, n)).st_mtime_ns,
                          os.lstat(os.path.join(HOOKS, n)).st_ino) for n in os.listdir(HOOKS)) if args.get("list") else None
elif op == "lock":
    mkdir_private(STATE)
    stale = False
    if kind(LOCK) != "absent":
        age = time.time() - os.lstat(LOCK).st_mtime
        if age < STALE:
            raise SystemExit("locked by another run")
        os.rename(LOCK, LOCK + ".stale-" + uuid.uuid4().hex[:8])
        stale = True
    os.mkdir(LOCK, 0o700)
    write_exclusive(os.path.join(LOCK, "run"), args["run"].encode(), 0o600)
    out["stale_taken_over"] = stale
elif op == "unlock":
    try:
        if open(os.path.join(LOCK, "run")).read() == args["run"]:
            shutil.rmtree(LOCK)
            out["released"] = True
        else:
            out["released"] = False
    except FileNotFoundError:
        out["released"] = False
elif op == "stage":
    name = need(args["name"])
    if not re.fullmatch(r"ins-[0-9a-f]{12}", args["run"]):
        raise SystemExit("bad run id")
    data = sys.stdin.buffer.read()
    if hashlib.sha256(data).hexdigest() != args["sha256"]:
        raise SystemExit("uploaded bytes differ from the expected sha256")
    p = live(name)
    k = kind(p)
    if k not in ("absent", "file"):
        raise SystemExit("target is a " + k)
    mkdir_private(STATE)
    mkdir_private(BACKUPS)
    bdir = os.path.join(BACKUPS, args["run"])
    mkdir_private(bdir)
    if k == "file":
        with open(p, "rb") as f:
            old = f.read()
        b = os.path.join(bdir, name)
        if kind(b) == "file":
            if sha(b) != hashlib.sha256(old).hexdigest():
                raise SystemExit("backup name already holds different bytes")  # an earlier part of this run: reuse only if equal
        elif kind(b) != "absent":
            raise SystemExit("backup name is not a regular file")
        else:
            write_exclusive(b, old, 0o600)
        out["old_sha"] = hashlib.sha256(old).hexdigest()
        out["backup_sha"] = sha(b)
        out["mode"] = stat.S_IMODE(os.lstat(p).st_mode)
    else:
        out["old_sha"] = None
    mode = out.get("mode", 0o644)
    t = replace_with(name, data, mode)
    out["temp_sha"] = sha(t)
elif op == "commit":
    out["live"] = {}
    for name in args["names"]:
        t, p = temp(name), live(name)
        if kind(t) != "file":
            raise SystemExit("no staged file for " + name)
        os.replace(t, p)
    fsync_dir(HOOKS)
    for name in args["names"]:
        out["live"][name] = sha(live(name))
elif op == "restore":
    out["live"] = {}
    for item in args["items"]:
        name = need(item["name"])
        if item.get("remove_if_sha"):
            p = live(name)
            if kind(p) == "file" and sha(p) == item["remove_if_sha"]:
                os.unlink(p)
            out["live"][name] = None
            continue
        data = sys.stdin.buffer.read(item["size"])
        if hashlib.sha256(data).hexdigest() != item["sha256"]:
            raise SystemExit("restore bytes differ from the recorded old sha256")
        t = replace_with(name, data, item["mode"])
        os.replace(t, live(name))
    fsync_dir(HOOKS)
    for item in args["items"]:
        if not item.get("remove_if_sha"):
            out["live"][item["name"]] = sha(live(item["name"]))
elif op == "read_backup":
    import base64
    if not re.fullmatch(r"ins-[0-9a-f]{12}", args["run"]):
        raise SystemExit("bad run id")
    b = os.path.join(BACKUPS, args["run"], need(args["name"]))
    if kind(b) == "file":
        with open(b, "rb") as f:
            out["b64"] = base64.b64encode(f.read(5 * 1024 * 1024)).decode()
    else:
        out["b64"] = None
elif op == "selftest":
    out = selftest()
elif op == "audit":
    d = os.path.expanduser("~/.agent-harness")
    try:
        os.mkdir(d, 0o700)
    except FileExistsError:
        pass
    fd = os.open(os.path.join(d, "install-audit.jsonl"), os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        os.write(fd, (json.dumps(args["row"], separators=(",", ":")) + "\n").encode())
        os.fsync(fd)
    finally:
        os.close(fd)
elif op == "prune":
    if kind(BACKUPS) == "other":
        runs = sorted(os.listdir(BACKUPS), key=lambda n: os.lstat(os.path.join(BACKUPS, n)).st_mtime)
        for old in runs[:-10]:
            if re.fullmatch(r"ins-[0-9a-f]{12}", old):
                shutil.rmtree(os.path.join(BACKUPS, old))
elif op == "cleanup":
    for name in args["names"]:
        t = temp(name)
        if kind(t) == "file":
            os.unlink(t)
else:
    raise SystemExit("unknown operation")
print(json.dumps(out))
'''
SCRIPT_SHA256 = hashlib.sha256(REMOTE_SCRIPT.encode()).hexdigest()


# ----------------------------------------------------------------------------- remote calls
def ssh_argv(host, op, args):
    """One command string, every argument shell-quoted, passed after `--` so a host can never be read as an option."""
    command = "%spython3 -I -c %s %s %s" % (REMOTE_PREFIX, shlex.quote(REMOTE_SCRIPT), shlex.quote(op), shlex.quote(json.dumps(args)))
    return ["ssh", "-o", "BatchMode=yes", "-o", "ClearAllForwardings=yes", "-o", "ConnectTimeout=10", "--", host, command]


class Remote:
    def __init__(self, host, runner):
        self.host, self.runner, self.started = host, runner, False

    def call(self, op, args=None, data=None, timeout=SSH_TIMEOUT, write=False):
        """Run one remote operation. After the first WRITE operation has started, any failure is `unknown`: a killed ssh
        client does not stop the remote command."""
        if write:
            self.started = True
        try:
            done = self.runner(ssh_argv(self.host, op, args or {}), input=data, capture_output=True, timeout=timeout)
        except (OSError, subprocess.SubprocessError) as error:
            raise InstallError("lost", "no answer from %s for %s (%s)" % (self.host, op, type(error).__name__), 5 if self.started else 2,
                               {"unknown": self.started})
        text = done.stdout.decode() if isinstance(done.stdout, bytes) else done.stdout
        if done.returncode != 0:
            err = done.stderr.decode() if isinstance(done.stderr, bytes) else (done.stderr or "")
            raise InstallError("remote_failed", "%s failed on %s: %s" % (op, self.host, err.strip().splitlines()[-1][:200] if err.strip() else "exit %s" % done.returncode),
                               2, {"unknown": False})
        try:
            return json.loads(text.strip().splitlines()[-1]) if text.strip() else {}
        except (ValueError, IndexError):
            raise InstallError("lost", "unreadable answer from %s for %s" % (self.host, op), 5 if self.started else 2, {"unknown": self.started})


# ----------------------------------------------------------------------------- input and source proof
def check_inputs(host, ref, files, ticket, dry_run, resume, rollback, force_files):
    if host not in HOSTS:
        refuse("--host must be one of %s" % ", ".join(HOSTS))
    if resume and rollback:
        refuse("--resume and --rollback cannot be combined")
    for label, run in (("--resume", resume), ("--rollback", rollback)):
        if run is not None:
            if not isinstance(run, str) or not RUN_RE.fullmatch(run):
                refuse("%s takes a run id like ins-0123456789ab" % label)
            if files or ref:
                refuse("%s takes the run id only: no --file or --from-ref" % label)
    if force_files and not rollback:
        refuse("--force-file is accepted only with --rollback")
    if ticket is None:
        if not dry_run:
            refuse("--ticket GoodQA project#N is required for a real run, a resume and a rollback")
    elif not isinstance(ticket, str) or not TICKET_RE.fullmatch(ticket):
        refuse("--ticket must look like GoodQA project#123")
    if resume or rollback:
        return
    if not isinstance(ref, str) or not REF_RE.fullmatch(ref):
        refuse("--from-ref must be a full 40-hex lowercase commit sha")
    if not files or len(files) > MAX_FILES:
        refuse("between 1 and %d --file names are required" % MAX_FILES)
    if len(set(files)) != len(files):
        refuse("a --file name is repeated")
    for name in files:
        if not isinstance(name, str) or not NAME_RE.fullmatch(name) or name.startswith(".") or ".." in name:
            refuse("--file must be a bare file name (letters, digits, _ - . only, no slash or dot segment, no leading dot)")


def git_env(home):
    env = {k: os.environ[k] for k in ("PATH", "LANG", "LC_ALL", "TMPDIR") if k in os.environ}
    env["PATH"] = os.pathsep.join(p for p in env.get("PATH", "").split(os.pathsep) if p.startswith("/")) or "/usr/bin:/bin"
    env.update(HOME=str(home), GIT_CONFIG_GLOBAL="/dev/null", GIT_CONFIG_NOSYSTEM="1", GIT_TERMINAL_PROMPT="0",
               GIT_NO_REPLACE_OBJECTS="1", GIT_OPTIONAL_LOCKS="0", GIT_ASKPASS="/bin/true", LC_ALL="C")
    return env


def git(repo, args, home, timeout=300, data=None, check=True):
    argv = ["git", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", "-c", "core.commitGraph=false",
            "-c", "protocol.allow=never", "-c", "protocol.https.allow=always"]
    if ALLOW_FILE:
        argv += ["-c", "protocol.file.allow=always"]
    argv += ["-C", str(repo)] + list(args)
    done = subprocess.run(argv, capture_output=True, timeout=timeout, env=git_env(home), input=data)
    if check and done.returncode != 0:
        raise InstallError("git_failed", "git %s failed" % (args[0] if args else ""), 2)
    return done


def verified_object(repo, home, kind_, oid):
    """Bytes of one object, re-hashed here: git does not hash-check an object on a plain read."""
    if not re.fullmatch(r"[0-9a-f]{40}", oid):
        refuse("the repository uses an object format other than sha1")
    body = git(repo, ["cat-file", kind_, oid], home).stdout
    if hashlib.sha1(("%s %d\0" % (kind_, len(body))).encode() + body).hexdigest() != oid:
        refuse("the %s object %s does not hash to its own id" % (kind_, oid[:12]))
    return body


def tree_entries(body):
    out, i = {}, 0
    while i < len(body):
        sp = body.index(b" ", i)
        nul = body.index(b"\0", sp)
        mode, name = body[i:sp].decode(), body[sp + 1:nul].decode("utf-8", "surrogateescape")
        out[name] = (mode, body[nul + 1:nul + 21].hex())
        i = nul + 21
    return out


def fetch_source(ref, names, home):
    """Fetch the canonical main into a FRESH repository, prove REF is merged, return {name: (bytes, blob id)} and the list of
    HOOKS names at REF. The fresh repository is deleted afterwards."""
    root = Path(home) / ".agent-harness" / "install-cache"
    root.mkdir(mode=0o700, parents=True, exist_ok=True)
    if root.is_symlink() or root.stat().st_uid != os.getuid():
        refuse("the install cache directory is a symlink or belongs to another user")
    for old in root.iterdir():  # leftovers of an earlier run older than an hour, by the fixed name pattern only
        if re.fullmatch(r"run-[0-9a-f]{12}", old.name) and old.is_dir() and not old.is_symlink() and time.time() - old.stat().st_mtime > 3600:
            shutil.rmtree(old)
    repo = root / ("run-" + uuid.uuid4().hex[:12])
    os.mkdir(repo, 0o700)
    try:
        git(repo, ["init", "-q", "--bare"], home)
        for key, value in (("transfer.fsckObjects", "true"), ("fetch.fsckObjects", "true"), ("receive.fsckObjects", "true")):
            git(repo, ["config", key, value], home)
        try:
            git(repo, ["fetch", "-q", "--no-tags", "--no-write-fetch-head", CANONICAL_URL, "+refs/heads/main:refs/heads/main"], home, timeout=600)
        except (InstallError, subprocess.SubprocessError):
            refuse("could not fetch main of the canonical harness repository (the merged-code proof needs it)", "fetch_failed")
        _hook("after_fetch", repo=repo)
        for forbidden in ("info/grafts", "shallow"):
            if (repo / forbidden).exists():
                refuse("the fetched repository has a %s file" % forbidden)
        if git(repo, ["for-each-ref", "refs/replace"], home).stdout.strip():
            refuse("the fetched repository has replace refs")
        main = git(repo, ["rev-parse", "--verify", "refs/heads/main"], home).stdout.decode().strip()
        if git(repo, ["cat-file", "-e", ref + "^{commit}"], home, check=False).returncode != 0:
            refuse("--from-ref is not a commit of the canonical main history")
        if git(repo, ["merge-base", "--is-ancestor", ref, main], home, check=False).returncode != 0:
            refuse("--from-ref is not an ancestor of the canonical main (unmerged code is not installed)")
        commit = verified_object(repo, home, "commit", ref)
        tree_id = re.match(rb"tree ([0-9a-f]{40})\n", commit)
        if not tree_id:
            refuse("the commit has no tree line")
        node = tree_entries(verified_object(repo, home, "tree", tree_id.group(1).decode()))

        def blob_at(path):
            cur = node
            parts = path.split("/")
            for part in parts[:-1]:
                if part not in cur or cur[part][0] != "40000":
                    refuse("%s is not in the commit" % path)
                cur = tree_entries(verified_object(repo, home, "tree", cur[part][1]))
            if parts[-1] not in cur:
                refuse("%s is not in the commit" % path)
            mode, oid = cur[parts[-1]]
            if mode not in ("100644", "100755"):
                refuse("%s is not a regular file in the commit (mode %s)" % (path, mode))
            return verified_object(repo, home, "blob", oid), oid, mode

        install_py = blob_at("install.py")[0]
        listed = None
        for stmt in ast.parse(install_py.decode()).body:
            if isinstance(stmt, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "HOOKS" for t in stmt.targets):
                listed = [str(x) for x in ast.literal_eval(stmt.value)]
        if not listed:
            refuse("install.py at that commit has no HOOKS tuple")
        out = {}
        for name in names:
            if name not in listed:
                refuse("%s is not in the installer's HOOKS list at that commit" % name)
            data, oid, mode = blob_at("harness/hooks/" + name)
            if len(data) > MAX_BLOB:
                refuse("%s is larger than %d bytes" % (name, MAX_BLOB))
            out[name] = (data, oid, mode)
        return out, listed, main
    finally:
        shutil.rmtree(repo, ignore_errors=True)


HOOK = None


def _hook(event, **info):
    if HOOK:
        HOOK(event, **info)


# ----------------------------------------------------------------------------- audit
def audit_path(home):
    return Path(home) / ".agent-harness" / "install-audit.jsonl"


def audit(home, row):
    path = audit_path(home)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    row = dict(row, at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), by="ah")
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        os.fchmod(fd, 0o600)
        os.write(fd, (json.dumps(row, ensure_ascii=False, separators=(",", ":")) + "\n").encode())
        os.fsync(fd)
    finally:
        os.close(fd)


def audit_rows(home):
    rows = []
    try:
        for line in open(audit_path(home), errors="replace"):
            try:
                row = json.loads(line)
            except ValueError:
                continue
            if isinstance(row, dict):
                rows.append(row)
    except OSError:
        pass
    return rows


def unfinished_runs(home, host):
    """Runs on this host whose start row has no definite result (missing or unknown)."""
    starts, done = {}, {}
    for row in audit_rows(home):
        if row.get("host") != host or not row.get("run"):
            continue
        if row.get("event") == "start" and row.get("kind") in ("install", "resume", "rollback"):
            starts[row["run"]] = row
        elif row.get("event") == "result":
            done[row["run"]] = row.get("result")
    return [r for r in starts if done.get(r) in (None, "unknown")]


def sha256(data):
    return hashlib.sha256(data).hexdigest()


# ----------------------------------------------------------------------------- the self-test comparison
def selftest_worse(before, after):
    """None when `after` is no worse than `before`, else the reason."""
    for key, was in (before.get("guard") or {}).items():
        now = (after.get("guard") or {}).get(key)
        if now is None or now.get("exit") != was.get("exit") or now.get("verdict") != was.get("verdict") or now.get("rule") != was.get("rule"):
            return "the guard probe %s changed (%s -> %s)" % (key, was.get("verdict"), (now or {}).get("verdict"))
    d0, d1 = before.get("doctor") or {}, after.get("doctor") or {}
    if d1.get("flags") is False and d0.get("flags") is not False:
        return "doctor no longer accepts its flags"
    if d0.get("failing") is not None:
        if d1.get("failing") is None:
            return "doctor could not run after the install"
        new = sorted(set(d1["failing"]) - set(d0["failing"]))
        if new:
            return "new failing doctor checks: %s" % ", ".join(new[:10])
    return None


def selftest_ok_to_start(result):
    guard = result.get("guard") or {}
    if not guard or any(v.get("exit") is None for v in guard.values()):
        return False
    return True


# ----------------------------------------------------------------------------- the run
def new_run_id():
    return "ins-" + uuid.uuid4().hex[:12]


def order(names):
    """Fixed install order: everything else first, command_guard.py LAST."""
    rest = [n for n in names if n != "command_guard.py"]
    return rest + (["command_guard.py"] if "command_guard.py" in names else [])


def post_comment(ticket, text, poster):
    if not ticket:
        return None
    try:
        if poster:
            poster(ticket, text)
        else:
            subprocess.run(["python3", str(Path(__file__).resolve().parent / "ah.py"), "ticket", "comment", ticket, "--body", text],
                           capture_output=True, timeout=60)
        return True
    except Exception:  # noqa: BLE001 - a failed comment is reported, never fatal
        return False


def finish(home, run, host, result, exit_code, extra, ticket, poster, kind_):
    """Write the result row, post the one ticket comment and return (exit 0) or raise (any other exit)."""
    row = dict({"event": "result", "run": run, "host": host, "kind": kind_, "result": result}, **extra)
    out = dict({"ok": exit_code == 0, "run": run, "host": host, "result": result, "exit_code": exit_code}, **extra)
    try:
        audit(home, row)
    except OSError:
        out["audit_warning"] = "the result row could not be written on this machine"
    summary = {n: {"old": v.get("old_sha"), "new": v.get("new_sha")} for n, v in (extra.get("files") or {}).items()}
    out["ticket_comment"] = post_comment(ticket, "ah install-files %s on %s: %s (run %s) ref %s files %s" % (
        kind_, host, result, run, extra.get("ref"), json.dumps(summary)[:1500]), poster)
    if exit_code != 0:
        raise InstallError(result, "%s on %s (run %s)%s" % (result, host, run, ": " + str(extra["reason"]) if extra.get("reason") else ""), exit_code, out)
    return out


def start_row(home, run):
    rows = [r for r in audit_rows(home) if r.get("run") == run and r.get("event") == "start" and r.get("kind") in ("install", "resume")]
    return rows[0] if rows else None


def results_of(home, run):
    return [r.get("result") for r in audit_rows(home) if r.get("run") == run and r.get("event") == "result"]


def install_files(host, ref, files, ticket, dry_run=False, home=None, session="", agent="", runner=subprocess.run, poster=None):
    check_inputs(host, ref, files, ticket, dry_run, None, None, ())
    return _run(host, ref, list(files), ticket, dry_run, Path(home or Path.home()), session, agent, runner, poster, None, None, "install")


def resume(run_id, ticket, home=None, session="", agent="", runner=subprocess.run, poster=None):
    home = Path(home or Path.home())
    if not isinstance(run_id, str) or not RUN_RE.fullmatch(run_id):
        refuse("--resume takes a run id like ins-0123456789ab")
    row = start_row(home, run_id)
    if row is None:
        refuse("no such run on this machine: %s" % run_id)
    if ("installed" in results_of(home, run_id)) or ("rolled_back" in results_of(home, run_id)) or ("restored" in results_of(home, run_id)):
        refuse("run %s already finished" % run_id)
    check_inputs(row["host"], None, None, ticket, False, run_id, None, ())
    return _run(row["host"], row["ref"], sorted(row["files"], key=lambda n: n), ticket, False, home, session, agent, runner, poster, run_id,
                row.get("baseline"), "resume")


def _plan_for(names, sources, state, run):
    plan = {}
    for name in names:
        data, oid, mode = sources[name]
        new, old = sha256(data), state[name]["sha"]
        plan[name] = {"action": "already_current" if old == new else ("new" if old is None else "replaced"), "old_sha": old, "new_sha": new,
                      "blob": oid, "mode": state[name]["mode"] if state[name]["mode"] is not None else 0o644,
                      "backup": ".ah-install/backups/%s/%s" % (run, name) if old and old != new else None}
    return plan


def _run(host, ref, files, ticket, dry_run, home, session, agent, runner, poster, resume_of, baseline, kind_):
    sources, listed, main = fetch_source(ref, files, home)
    remote = Remote(host, runner)
    run = resume_of or new_run_id()
    names = order(files)
    if not dry_run:
        busy = [r for r in unfinished_runs(home, host) if r != resume_of]
        if busy:
            refuse("host %s has an unfinished run (%s): resume it with --resume or undo it with --rollback first" % (host, busy[0]), "unfinished_run")
    probe = remote.call("probe", {"names": names, "list": dry_run})
    state = probe["files"]
    for name, item in state.items():
        if item["kind"] not in ("absent", "file"):
            refuse("the live target %s on %s is a %s" % (name, host, item["kind"]))
        if item["temp"] not in ("absent", "file"):
            refuse("the temporary name for %s on %s is not a regular file" % (name, host))
    before = baseline if baseline is not None else remote.call("selftest", timeout=SELFTEST_TIMEOUT)
    if not selftest_ok_to_start(before):
        refuse("the host self-test cannot run on %s; nothing was changed" % host, "selftest_unavailable")
    plan = _plan_for(names, sources, state, run)
    if dry_run:
        try:
            audit(home, {"event": "result", "run": run, "host": host, "kind": "dry_run", "result": "dry_run", "ref": ref, "files": plan})
        except OSError:
            pass
        return {"ok": True, "run": run, "host": host, "result": "dry_run", "exit_code": 0, "ref": ref, "main": main, "files": plan,
                "selftest_baseline": before, "listing": probe.get("list")}
    # a resume: files the interrupted run already installed keep THEIR original plan entry (old sha, backup) so a failing
    # self-test can still roll them back, and the self-test after is compared with the ORIGINAL baseline
    orig = (start_row(home, resume_of) or {}).get("files", {}) if resume_of else {}
    for name in names:
        prior = orig.get(name) or {}
        if resume_of and plan[name]["action"] == "already_current" and prior.get("action") in ("new", "replaced") and prior.get("new_sha") == plan[name]["new_sha"]:
            plan[name] = dict(prior, resumed_already_applied=True)
    applied = [n for n in names if plan[n]["action"] in ("new", "replaced")]
    todo = [n for n in applied if not plan[n].get("resumed_already_applied")]
    start = {"event": "start", "kind": kind_, "run": run, "host": host, "url": CANONICAL_URL, "main": main, "ref": ref, "files": plan,
             "baseline": before, "script_sha256": SCRIPT_SHA256, "session": session or None, "agent": agent or None, "ticket": ticket}
    try:
        audit(home, start)  # fail closed: nothing is written remotely when this row cannot be written and fsynced
    except OSError:
        raise InstallError("audit_failed", "could not write the audit row; nothing was changed", 3, {"ok": False})
    if not applied:
        return finish(home, run, host, "already_current", 0, {"ref": ref, "files": plan}, ticket, poster, kind_)
    if resume_of and not todo:
        remote.started = True  # everything is already live from the interrupted run: only the after-test remains
    locked = False
    try:
        remote.call("lock", {"run": run})
        locked = True
        for name in todo:  # phase 1: stage and verify every file; nothing live changes
            data = sources[name][0]
            got = remote.call("stage", {"name": name, "sha256": plan[name]["new_sha"], "run": run}, data=data)
            if got.get("temp_sha") != plan[name]["new_sha"]:
                raise InstallError("stage_mismatch", "the staged %s differs from the blob" % name, 2)
            if plan[name]["old_sha"] is not None:
                if got.get("old_sha") != plan[name]["old_sha"] or got.get("backup_sha") != plan[name]["old_sha"]:
                    raise InstallError("backup_mismatch", "the backup of %s does not match the live file" % name, 2)
                _keep_mac_copy(home, remote, run, name, plan[name]["old_sha"])
        _hook("after_stage", run=run, host=host)
        if todo:
            done = remote.call("commit", {"names": todo, "run": run}, write=True)  # phase 2: guard last
            wrong = [n for n in todo if done["live"].get(n) != plan[n]["new_sha"]]
            if wrong:
                raise InstallError("readback_mismatch", "read-back sha differs for %s" % ", ".join(wrong), 2)
        _hook("after_commit", run=run, host=host)
        after = remote.call("selftest", timeout=SELFTEST_TIMEOUT)
        why = selftest_worse(before, after)
        if why:
            raise InstallError("selftest_worse", why, 4)
    except InstallError as error:
        if remote.started and error.code == "lost":
            return finish(home, run, host, "unknown", 5, {"ref": ref, "files": plan, "reason": "%s; check %s before retrying" % (error, host)}, ticket, poster, kind_)
        if remote.started:
            return _roll_back(home, run, host, plan, applied, remote, error, ticket, poster, kind_, ref)
        try:
            remote.call("cleanup", {"names": todo})
        except InstallError:
            pass
        return finish(home, run, host, "refused", 2, {"ref": ref, "files": plan, "reason": str(error)[:300]}, ticket, poster, kind_)
    finally:
        if locked:
            try:
                remote.call("unlock", {"run": run})
            except InstallError:
                pass
    for op, args in (("prune", {}), ("audit", {"row": {"event": "result", "run": run, "kind": kind_, "files": {n: {"old": plan[n]["old_sha"], "new": plan[n]["new_sha"]} for n in todo},
                                                       "script_sha256": SCRIPT_SHA256, "agent": agent or None}})):
        try:
            remote.call(op, args)
        except InstallError:
            pass
    return finish(home, run, host, "installed", 0, {"ref": ref, "files": plan, "selftest_after": after}, ticket, poster, kind_)


def _keep_mac_copy(home, remote, run, name, old_sha):
    data = _read_backup(remote, run, name)
    if data is None or sha256(data) != old_sha:
        raise InstallError("backup_mismatch", "the host backup of %s could not be read back with the recorded sha256" % name, 2)
    folder = Path(home) / ".agent-harness" / "install-backups" / run
    folder.mkdir(mode=0o700, parents=True, exist_ok=True)
    target = folder / name
    if target.exists() or target.is_symlink():
        if target.is_symlink() or not target.is_file() or sha256(target.read_bytes()) != old_sha:
            raise InstallError("backup_mismatch", "the local copy of %s differs" % name, 2)
        return
    fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)


def _read_backup(remote, run, name):
    try:
        got = remote.call("read_backup", {"run": run, "name": name})
    except InstallError:
        return None
    import base64
    return base64.b64decode(got["b64"]) if got.get("b64") is not None else None


def _restore_items(home, remote, run, plan, names, current):
    """Restore items for `names`, guard FIRST, plus the concatenated old bytes. Raises InstallError when a backup is unusable."""
    items, payload = [], b""
    for name in (["command_guard.py"] if "command_guard.py" in names else []) + [n for n in reversed(names) if n != "command_guard.py"]:
        old = plan[name]["old_sha"]
        if old is None:
            items.append({"name": name, "remove_if_sha": plan[name]["new_sha"]})
            continue
        data = _read_backup(remote, run, name)
        if data is None or sha256(data) != old:
            mac = Path(home) / ".agent-harness" / "install-backups" / run / name
            data = mac.read_bytes() if mac.is_file() and not mac.is_symlink() else None
        if data is None or sha256(data) != old:
            raise InstallError("backup_mismatch", "no usable backup of %s (host and local copies are missing or differ)" % name, 2)
        items.append({"name": name, "size": len(data), "sha256": old, "mode": plan[name].get("mode", 0o644)})
        payload += data
    return items, payload


def _roll_back(home, run, host, plan, todo, remote, cause, ticket, poster, kind_, ref):
    """Automatic rollback: every changed file back from its backup, guard FIRST, then the self-test again. An interrupted or
    impossible rollback is `unknown` ("rollback incomplete")."""
    try:
        items, payload = _restore_items(home, remote, run, plan, todo, None)
        got = remote.call("restore", {"items": items}, data=payload, write=True)
        again = remote.call("selftest", timeout=SELFTEST_TIMEOUT)
    except InstallError as error:
        return finish(home, run, host, "unknown", 5, {"ref": ref, "files": plan, "reason": "rollback incomplete: %s; check %s" % (error, host)}, ticket, poster, kind_)
    bad = [i["name"] for i in items if not i.get("remove_if_sha") and got["live"].get(i["name"]) != plan[i["name"]]["old_sha"]]
    if bad:
        return finish(home, run, host, "unknown", 5, {"ref": ref, "files": plan, "reason": "rollback incomplete: read-back differs for %s; check %s" % (", ".join(bad), host)}, ticket, poster, kind_)
    return finish(home, run, host, "rolled_back", 4, {"ref": ref, "files": plan, "reason": str(cause)[:300], "selftest_after_rollback": again}, ticket, poster, kind_)


def rollback(run_id, ticket, force_files=(), home=None, session="", agent="", runner=subprocess.run, poster=None):
    home = Path(home or Path.home())
    if not isinstance(run_id, str) or not RUN_RE.fullmatch(run_id):
        refuse("--rollback takes a run id like ins-0123456789ab")
    row = start_row(home, run_id)
    if row is None:
        refuse("no such run on this machine: %s" % run_id)
    host = row["host"]
    check_inputs(host, None, None, ticket, False, None, run_id, tuple(force_files))
    for name in force_files:
        if name not in row["files"]:
            refuse("--force-file %s is not a file of run %s" % (name, run_id))
    if "rolled_back" in results_of(home, run_id) or "restored" in results_of(home, run_id):
        refuse("run %s was already rolled back" % run_id)
    busy = [r for r in unfinished_runs(home, host) if r != run_id]
    if busy:
        refuse("host %s has another unfinished run (%s)" % (host, busy[0]), "unfinished_run")
    plan = row["files"]
    names = order([n for n in plan if plan[n]["action"] in ("new", "replaced")])
    remote = Remote(host, runner)
    state = remote.call("probe", {"names": names})["files"]
    to_restore, notes = [], {}
    for name in names:
        live_sha = state[name]["sha"]
        if live_sha == plan[name]["old_sha"]:
            notes[name] = "already at the old sha"
            continue
        if live_sha != plan[name]["new_sha"] and name not in force_files:
            later = [r["run"] for r in audit_rows(home) if r.get("event") == "start" and r.get("host") == host and r.get("run") != run_id
                     and name in (r.get("files") or {}) and (r["files"][name] or {}).get("new_sha") == live_sha]
            refuse("%s on %s no longer holds run %s's new bytes%s (use --force-file %s to restore anyway)" % (
                name, host, run_id, " (a later run %s installed it)" % later[0] if later else "", name), "live_changed")
        to_restore.append(name)
    start = {"event": "start", "kind": "rollback", "run": run_id, "host": host, "files": {n: plan[n] for n in to_restore}, "forced": sorted(force_files),
             "script_sha256": SCRIPT_SHA256, "session": session or None, "agent": agent or None, "ticket": ticket}
    try:
        audit(home, start)
    except OSError:
        raise InstallError("audit_failed", "could not write the audit row; nothing was changed", 3, {"ok": False})
    locked = False
    try:
        remote.call("lock", {"run": run_id})
        locked = True
        items, payload = _restore_items(home, remote, run_id, plan, to_restore, None) if to_restore else ([], b"")
        got = remote.call("restore", {"items": items}, data=payload, write=True) if items else {"live": {}}
        after = remote.call("selftest", timeout=SELFTEST_TIMEOUT)
    except InstallError as error:
        if remote.started:
            return finish(home, run_id, host, "unknown", 5, {"files": plan, "reason": "rollback incomplete: %s; check %s" % (error, host)}, ticket, poster, "rollback")
        return finish(home, run_id, host, "refused", 2, {"files": plan, "reason": str(error)[:300]}, ticket, poster, "rollback")
    finally:
        if locked:
            try:
                remote.call("unlock", {"run": run_id})
            except InstallError:
                pass
    bad = [i["name"] for i in items if not i.get("remove_if_sha") and got["live"].get(i["name"]) != plan[i["name"]]["old_sha"]]
    if bad:
        return finish(home, run_id, host, "unknown", 5, {"files": plan, "reason": "rollback incomplete: read-back differs for %s; check %s" % (", ".join(bad), host)}, ticket, poster, "rollback")
    why = selftest_worse(row.get("baseline") or {}, after)
    extra = {"files": plan, "restored": to_restore, "notes": notes, "selftest_after": after}
    if why:
        extra["selftest_note"] = why  # a rollback is never blocked by the self-test: the difference is reported, not refused
    return finish(home, run_id, host, "restored", 0, extra, ticket, poster, "rollback")


