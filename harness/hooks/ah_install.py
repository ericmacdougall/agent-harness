"""`ah install-files`: install MERGED hook files on a remote host through one audited command (goodqa#15742).

The 2026-11-11 t2-dev install of command_guard.py was blocked as a remote `cp` and then done with `scp`, a second route
around a guard. This command is the sanctioned route:

  * the bytes come only from a commit proven to be an ancestor of the canonical harness repository's main, fetched into a
    FRESH repository this tool owns (never one the caller names); the commit, the trees on the path and the blob are
    re-hashed here before use; names only from the installer's HOOKS tuple at that commit;
  * the host gets a constant remote program (REMOTE_SCRIPT, text never built from caller input) run as one shell-quoted
    command through ssh: stage and verify every file (nothing live changes), then rename them in a fixed order with
    command_guard.py LAST, read the shas back and compare the host's own self-test with its baseline; anything worse rolls
    every file back (guard first). Worse: a guard probe changed, a doctor check newly failing, or a hook wired before
    and not wired after. A hook row that the baseline manifest did not declare and that settings.json does not register
    (doctor MISSING) is not worse: this command never edits settings.json, so the result lists it as `unregistered` and
    it does not run until install.py's settings merge registers it (goodqa#15754 AC-10);
  * an audit row on the Mac before the first remote write and after the run, one on the host; an unknown outcome is never
    reported as installed or refused; a host with an unfinished run refuses new runs until it is resumed or rolled back.

This machine (goodqa#15913): `--host local` (~/.claude/hooks) and `--host local-codex` (~/.codex/agent-harness, names from
install_codex.py's DELIVERY_HELPERS at the commit) run the SAME constant program as a local subprocess, with no shell and no
ssh, an allowlisted environment and a fixed root token (never a path), so every step above is unchanged. A local real run,
resume or rollback runs WHOLE in its own session (ah.main -> run_in_own_session), so a caller whose process group is killed
after the commit never skips the self-test verdict or the automatic rollback; each program step also starts in its own
session (detached_run). Every local writer (a run, a resume, a rollback) holds an exclusive flock on
~/.agent-harness/install-locks/TARGET.lock from before its first probe to its end, and every program step it starts
inherits that descriptor, so the lock stays held while the run's session OR any step it started still lives; another
writer of that target refuses with exit 7 (still_running) until the kernel drops the lock with its last holder, so a
recovery never races a live writer. A kill that ends that session leaves the run unfinished; once its last step has
exited, `--resume RUN` applies the verdict and rolls back. The host-side audit
row is skipped there: that file is the caller's own audit file, which already holds the start and result rows; so the ticket
comment is the only record off the machine, and a local run whose comment is not confirmed as posted exits 6. `--host local` also reports the
Codex copies that differ from the bytes it installed, so the Codex home is never silently left behind; local-codex refuses
a CODEX_HOME that points elsewhere. Every target's self-test also runs the registered hook entry (command_guard_hook.py) on
two sub-agent payloads, which must both be blocked with their exact rules after any install.

Rename invariant: files change one os.replace at a time, every other file first and command_guard.py LAST on install, and
command_guard.py FIRST on restore; at every instant each hook file is either its old or its new complete bytes, so a session
that runs the hook in the window gets the old guard's verdict, the new guard's verdict, or, when a mix of old and new modules
makes the analyser crash, command_guard_hook.py's fail-closed fallback.

Threat model: careless or hurried agents, not one that edits this module or the audit file.
"""
from __future__ import annotations

import ast
import contextlib
import errno
import fcntl
import hashlib
import json
import os
import re
import shlex
import shutil
import stat
import subprocess
import sys
import time
import uuid
from pathlib import Path

HOSTS = ("t2-dev", "ah-mac-mini")
LOCAL_TARGETS = {"local": "claude", "local-codex": "codex"}  # this machine, by a fixed root token the program maps to a fixed directory
LOCAL_ENV_KEYS = ("PATH", "LANG", "LC_ALL", "TMPDIR", "USER", "LOGNAME", "SHELL")  # plus HOME; nothing else of the caller's environment
NAME_LISTS = {"claude": ("install.py", "HOOKS"), "codex": ("install_codex.py", "DELIVERY_HELPERS")}
CODEX_DIR = (".codex", "agent-harness")
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
SELFTEST_TIMEOUT = 330  # clearly above the remote TOTAL_DEADLINE (200 s) plus python and ssh start-up, so a local timeout is a lost link, not a slow self-test
HOST_AUDIT = ".agent-harness/install-audit.jsonl"
FIRST = ("doctor.py", "ah.py")  # no special order beyond: command_guard.py is always last


class InstallError(Exception):
    def __init__(self, code, message, exit_code=2, data=None):
        super().__init__(message)
        self.code, self.exit_code, self.data = code, exit_code, data or {}


def refuse(message, code="refused", exit_code=2, data=None):
    raise InstallError(code, message, exit_code, data)


# ----------------------------------------------------------------------------- the constant remote program
# Runs on the host as `python3 -I -c SCRIPT OP JSON [ROOT]`, file bytes on stdin for `stage`. Python 3.9 compatible, standard
# library only. Every path is built from a fixed hooks directory and a name matched against NAME_RE; it never reads a
# path from the caller. ROOT is a token from ROOTS (absent over ssh: claude).
REMOTE_SCRIPT = r'''
import hashlib, json, os, re, shutil, stat, subprocess, sys, tempfile, time, uuid
NAME = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]*")
ROOTS = {"claude": "~/.claude/hooks", "codex": "~/.codex/agent-harness"}
ROOT = sys.argv[3] if len(sys.argv) > 3 else "claude"
if ROOT not in ROOTS:
    raise SystemExit("bad root")
HOOKS = os.path.expanduser(ROOTS[ROOT])
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
    st = os.lstat(path)
    if not stat.S_ISDIR(st.st_mode):
        raise SystemExit("not a plain directory: " + os.path.basename(path))

def fsync_dir(path):
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)

def write_exclusive(path, data, mode, final=None):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        os.write(fd, data)
        if final is not None:
            os.fchmod(fd, final)
        os.fsync(fd)
    finally:
        os.close(fd)

def replace_with(name, data, mode):
    t = temp(name)
    if kind(t) == "file":
        os.unlink(t)
    elif kind(t) != "absent":
        raise SystemExit("temporary name is not a regular file: " + name)
    write_exclusive(t, data, 0o600, mode)
    return t

PROBE_TIMEOUT, DOCTOR_TIMEOUT, TOTAL_DEADLINE = 60, 120, 200  # the whole self-test ends inside TOTAL_DEADLINE seconds, always
# Through the REGISTERED entry (command_guard_hook.py hook), as a sub-agent payload (no transcript, so never main). The WAL
# path does not exist, so no delete approval can cover it and the probe can never consume one. Data only, never executed.
HOOK_PROBES = {"hook_deny_wal": "rm -rf ~/.claude/wals/.ah-install-selftest-absent",
               "hook_subagent_local": "python3 -I ~/.claude/hooks/ah.py install-files --host local --from-ref "
                                      + "0" * 40 + ' --file ah.py --ticket "GoodQA selftest#1"'}
# goodqa#15913 M2: main's own recovery form, sent AS MAIN (no agent_id; a disposable Claude home whose projects folder holds
# this session's transcript, caller_identity's proof). The run id is never looked up: the probe only asks the guard.
MAIN_PROBE = 'python3 -I ~/.claude/hooks/ah.py install-files --host local --rollback ins-000000000000 --ticket "GoodQA selftest#1"'

def selftest():
    guard = os.path.join(HOOKS, "command_guard.py")
    res = {"guard": {}, "hook": {}, "doctor": None}
    deadline = time.time() + TOTAL_DEADLINE
    probes = {"allow": "ls -la",
              "deny_wal": "rm -rf ~/.claude/wals",
              "deny_hooks_copy": 'ssh t2-dev "cp x ~/.claude/hooks/command_guard.py"'}
    for key, cmd in probes.items():
        if deadline - time.time() <= 0.5:
            res["guard"][key] = {"exit": None, "verdict": "error:deadline", "rule": ""}
            continue
        try:
            p = subprocess.run([sys.executable, "-I", guard, "check", cmd], capture_output=True, text=True,
                               timeout=max(0.5, min(PROBE_TIMEOUT, deadline - time.time())), cwd=os.path.expanduser("~"))
            data = json.loads((p.stdout or "").strip().splitlines()[-1])
            rule = re.search(r"\[([A-Za-z0-9_/-]+)\]", data.get("message") or "")
            res["guard"][key] = {"exit": p.returncode, "verdict": str(data.get("verdict")), "rule": rule.group(1) if rule else ""}
        except Exception as e:
            res["guard"][key] = {"exit": None, "verdict": "error:" + type(e).__name__, "rule": ""}
    entry = os.path.join(HOOKS, "command_guard_hook.py")
    for key, cmd in HOOK_PROBES.items():
        if deadline - time.time() <= 0.5:
            res["hook"][key] = {"exit": None, "rule": "", "error": "deadline"}
            continue
        payload = json.dumps({"session_id": "ah-install-selftest", "agent_id": "ah-install-selftest", "hook_event_name": "PreToolUse",
                              "tool_name": "Bash", "tool_input": {"command": cmd}, "cwd": os.path.expanduser("~")})
        try:
            p = subprocess.run(["python3", entry, "hook"], input=payload, capture_output=True, text=True,  # the registered form
                               timeout=max(0.5, min(PROBE_TIMEOUT, deadline - time.time())), cwd=os.path.expanduser("~"))
            rule = re.search(r"\[([A-Za-z0-9_/-]+)\]", p.stderr or "")
            res["hook"][key] = {"exit": p.returncode, "rule": rule.group(1) if rule else ""}
        except Exception as e:
            res["hook"][key] = {"exit": None, "rule": "", "error": type(e).__name__}
    # compared with the baseline, never absolute (selftest_worse): a caller that cannot prove main is refused before and after
    if deadline - time.time() <= 0.5:
        res["hook"]["hook_main_recovery"] = {"exit": None, "rule": "", "error": "deadline"}
    else:
        claude_dir = tempfile.mkdtemp(prefix="ah-install-selftest-")
        try:
            sid = str(uuid.uuid4())
            os.makedirs(os.path.join(claude_dir, "projects", "selftest"), 0o700)
            transcript = os.path.join(claude_dir, "projects", "selftest", sid + ".jsonl")
            write_exclusive(transcript, b"", 0o600)
            payload = json.dumps({"session_id": sid, "transcript_path": transcript, "hook_event_name": "PreToolUse", "tool_name": "Bash",
                                  "tool_input": {"command": MAIN_PROBE}, "cwd": os.path.expanduser("~")})
            p = subprocess.run(["python3", entry, "hook"], input=payload, capture_output=True, text=True,
                               env=dict(os.environ, CLAUDE_CONFIG_DIR=claude_dir),
                               timeout=max(0.5, min(PROBE_TIMEOUT, deadline - time.time())), cwd=os.path.expanduser("~"))
            rule = re.search(r"\[([A-Za-z0-9_/-]+)\]", p.stderr or "")
            res["hook"]["hook_main_recovery"] = {"exit": p.returncode, "rule": rule.group(1) if rule else ""}
        except Exception as e:
            res["hook"]["hook_main_recovery"] = {"exit": None, "rule": "", "error": type(e).__name__}
        finally:
            shutil.rmtree(claude_dir, ignore_errors=True)
    doctor = os.path.join(HOOKS, "doctor.py")
    if os.path.exists(doctor) and deadline - time.time() <= 0.5:
        res["doctor"] = {"flags": True, "failing": None, "timeout": True}
    elif os.path.exists(doctor):
        try:
            p = subprocess.run([sys.executable, "-I", doctor, "check", "--json", "--no-canary"], capture_output=True, text=True,
                               timeout=max(0.5, min(DOCTOR_TIMEOUT, deadline - time.time())), cwd=os.path.expanduser("~"))
            if "unrecognized arguments" in (p.stderr or ""):
                res["doctor"] = {"flags": False, "failing": None}
            else:
                data = json.loads(p.stdout)
                items = data if isinstance(data, list) else data.get("findings") or data.get("checks") or []
                failing = sorted(str(i.get("id") or "?") for i in items
                                 if isinstance(i, dict) and str(i.get("state", "WIRED")) not in ("WIRED", "PENDING"))
                res["doctor"] = {"flags": True, "failing": failing, "exit": p.returncode}
                ids = [str(i.get("id") or "?") for i in items if isinstance(i, dict)]
                # past the bound, or with ids that collide when cut, record nothing: the comparison then keeps the
                # strict rule (a partial map could let a wired row past the bound pass as newly declared)
                if len(ids) <= 400 and all(len(x) <= 80 for x in ids) and len(set(ids)) == len(ids):
                    res["doctor"]["states"] = {str(i.get("id") or "?"): str(i.get("state", "WIRED"))[:20]
                                               for i in items if isinstance(i, dict)}
        except subprocess.TimeoutExpired:
            res["doctor"] = {"flags": True, "failing": None, "timeout": True}
        except Exception as e:
            res["doctor"] = {"flags": True, "failing": None, "error": type(e).__name__}
    return res

def check_hooks():
    for path in (os.path.dirname(HOOKS), HOOKS):  # ~/.claude or ~/.codex first: a linked parent would redirect every write too
        try:
            st = os.lstat(path)
        except FileNotFoundError:
            raise SystemExit("the hooks directory does not exist")
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid():
            raise SystemExit(("the hooks directory" if path == HOOKS else "the hooks directory's parent (~/" + os.path.basename(path) + ")")
                             + " is a symlink, not a directory or owned by another user")

def touch_lock(run):
    try:
        if open(os.path.join(LOCK, "run")).read() == run:
            os.utime(LOCK)
    except OSError:
        pass

op = sys.argv[1]
args = json.loads(sys.argv[2]) if len(sys.argv) > 2 else {}
check_hooks()
if op == "probe":
    out["hooks_realpath"] = os.path.realpath(HOOKS)
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
        try:
            holder = open(os.path.join(LOCK, "run")).read()
        except OSError:
            holder = ""
        if holder == args["run"]:  # the same run (a resume after an interruption) takes its own lock back
            os.utime(LOCK)
            out["stale_taken_over"] = False
            print(json.dumps(out))
            sys.exit(0)
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
    touch_lock(args["run"])
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
    touch_lock(args["run"])
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
    touch_lock(args.get("run", ""))
    for item in args["items"]:
        name = need(item["name"])
        if item.get("remove_if_sha"):
            p = live(name)
            if kind(p) == "file" and sha(p) == item["remove_if_sha"]:
                os.unlink(p)
            out["live"][name] = sha(p) if kind(p) == "file" else None  # the REAL state after: a file that was not removed shows its sha
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
    if os.path.isdir(BACKUPS) and not os.path.islink(BACKUPS):
        runs = sorted((n for n in os.listdir(BACKUPS) if re.fullmatch(r"ins-[0-9a-f]{12}", n)),
                      key=lambda n: os.lstat(os.path.join(BACKUPS, n)).st_mtime)
        for old in runs[:-10]:
            shutil.rmtree(os.path.join(BACKUPS, old))
    if os.path.isdir(STATE) and not os.path.islink(STATE):
        for n in os.listdir(STATE):
            if re.fullmatch(r"lock\.stale-[0-9a-f]{8}", n) and os.path.isdir(os.path.join(STATE, n)) and not os.path.islink(os.path.join(STATE, n)):
                shutil.rmtree(os.path.join(STATE, n))
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


def local_argv(root, op, args):
    """The same constant program on this machine (goodqa#15913): an argv list, no shell, no ssh; `root` is a ROOTS token."""
    return [sys.executable, "-I", "-c", REMOTE_SCRIPT, op, json.dumps(args), root]


def local_env(home):
    """An allowlisted environment whose HOME is the caller's home: the caller's AH_*, guard switches or PYTHON* settings
    never reach the program or its self-test."""
    env = {k: os.environ[k] for k in LOCAL_ENV_KEYS if k in os.environ}
    env["PATH"] = os.pathsep.join(p for p in env.get("PATH", "").split(os.pathsep) if p.startswith("/")) or "/usr/bin:/bin"
    env["HOME"] = str(home)
    return env


def detached_run(argv, input=None, capture_output=True, timeout=None, env=None, pass_fds=()):
    """The local transport (goodqa#15913). The program starts in its OWN session, so a caller that is killed with its
    process group never stops it between two renames or inside a rollback; and, like a
    killed ssh client, a caller-side timeout leaves it running to its end instead of killing it. The call is then reported
    as lost (unknown after the first write). `pass_fds` carries the run's writer lock into the program, so the lock is held
    until the program exits even when its caller is gone. Not covered: a kill that walks the process tree by parent id."""
    proc = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env,
                            start_new_session=True, close_fds=True, pass_fds=tuple(pass_fds))
    try:
        out, err = proc.communicate(input, timeout=timeout)
    except subprocess.TimeoutExpired:
        for stream in (proc.stdin, proc.stdout, proc.stderr):
            try:
                stream.close()  # the program's final print then fails harmlessly; every rename has happened by then
            except OSError:
                pass
        raise
    return subprocess.CompletedProcess(argv, proc.returncode, out, err)


IN_SESSION_ENV = "AH_INSTALL_IN_SESSION"  # set on the copy that already runs in its own session: it never starts another
AH_PY = os.path.join(os.path.dirname(os.path.abspath(__file__)), "ah.py")
SESSION_DIR = (".agent-harness", "install-sessions")
STILL_RUNNING_EXIT = 7  # a writer of this target (a run's session, or a program step it started) still holds the writer lock
LOCK_DIR = (".agent-harness", "install-locks")


def in_own_session():
    """This process is the copy that runs in its own session: the marker AND it leads its own session. An inherited
    marker alone (for example from a settings environment) is not trusted."""
    return os.environ.get(IN_SESSION_ENV) == "1" and os.getsid(0) == os.getpid()


@contextlib.contextmanager
def writer_lock(home, host):
    """goodqa#15913 F2: the exclusive writer lock of a local target, held for the whole of a run, a resume or a rollback.
    It is an flock on ~/.agent-harness/install-locks/HOST.lock, taken without waiting; it yields the descriptor for every
    program step to inherit (Remote keep_fds -> detached_run pass_fds), so the lock stays held while this process OR any
    step it started still lives, and the kernel drops it when the last of them exits: no pid or start-time bookkeeping.
    A writer that cannot take it refuses with still_running (exit 7) before it reads anything, so a recovery never acts on
    a probe that a live step can still change. A fleet host yields no descriptor (its program runs over ssh)."""
    if host not in LOCAL_TARGETS:
        yield ()
        return
    folder = Path(home).joinpath(*LOCK_DIR)
    path = folder / (host + ".lock")
    try:
        folder.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd = os.open(str(path), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    except OSError as error:
        refuse("could not open the writer lock %s (%s); nothing was changed" % (path, type(error).__name__))
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            if error.errno not in (errno.EWOULDBLOCK, errno.EAGAIN):
                refuse("could not take the writer lock %s (%s); nothing was changed" % (path, type(error).__name__))
            refuse("another install-files writer on %s still holds %s: a run's own session, or a program step it started, is "
                   "still working. Wait for that run's result row in ~/.agent-harness/install-audit.jsonl, or for the holder "
                   "to exit (`lsof` on the lock file names it), then retry; nothing was changed" % (host, path),
                   "still_running", STILL_RUNNING_EXIT)
        yield (fd,)
    finally:
        os.close(fd)


def own_session_target(args, home):
    """The local target of an install-files command line that must run in its own session: a real run, a --resume or a
    --rollback on this machine (goodqa#15913 N1). None for a dry run, a fleet host, a run id this machine does not know
    and the copy that already runs in its own session."""
    if in_own_session() or getattr(args, "dry_run", False):
        return None
    return target_of(args, home)


def target_of(args, home):
    """The local target a command line acts on: --host for a new run, the run's own start row for --resume/--rollback."""
    run_id = getattr(args, "resume", None) or getattr(args, "rollback", None)
    if run_id:
        try:
            host = (start_row(Path(home), run_id) or {}).get("host") if isinstance(run_id, str) and RUN_RE.fullmatch(run_id) else None
        except (OSError, ValueError):
            host = None  # the run itself refuses with the real reason
    else:
        host = getattr(args, "host", None)
    return host if host in LOCAL_TARGETS else None


def run_in_own_session(argv, home, launcher=None):
    """Run this install-files command line again in a NEW session and wait for it, relaying its stdout, stderr and exit
    status. The whole run (lock, renames, the self-test verdict, the automatic rollback, the result row and the ticket
    comment) then lives in that session, so a kill of the caller's process group no longer stops it after the commit;
    the run's output stays in ~/.agent-harness/install-sessions/ until the caller has relayed it. A run ended by a signal
    is exit 5 (unknown). Not covered: a kill that ends that session too, or walks the process tree (the run is then
    unfinished and `--resume RUN` applies the verdict)."""
    stem, fds = None, []
    try:
        folder = Path(home).joinpath(*SESSION_DIR)
        folder.mkdir(mode=0o700, parents=True, exist_ok=True)
        stem = str(folder / ("%s-%d-%s" % (time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()), os.getpid(), uuid.uuid4().hex[:6])))
        for ext in (".out", ".err"):
            fds.append(os.open(stem + ext, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600))
        child = subprocess.Popen(launcher or [sys.executable, "-I", AH_PY] + list(argv), stdin=subprocess.DEVNULL, stdout=fds[0],
                                 stderr=fds[1], start_new_session=True, close_fds=True, env=dict(os.environ, **{IN_SESSION_ENV: "1"}))
    except OSError as error:  # nothing has run: refuse, never fall back to a run in the caller's session
        sys.stdout.write(json.dumps({"ok": False, "code": "session_failed", "message": "could not start the run in its own session "
                                     "(%s); nothing was changed" % type(error).__name__}) + "\n")
        return 2
    finally:
        for fd in fds:
            os.close(fd)
    sys.stderr.write("install-files: the run is in its own session (pid %d) and continues if this call's process group is "
                     "killed; a --resume or --rollback refuses (exit 7) until it and every program step it started have "
                     "ended; its output: %s.out\n" % (child.pid, stem))
    sys.stderr.flush()
    code = child.wait()
    for ext, stream in ((".out", sys.stdout), (".err", sys.stderr)):
        try:
            with open(stem + ext, errors="replace") as fh:
                stream.write(fh.read())
            stream.flush()
            os.unlink(stem + ext)
        except OSError:
            pass
    return code if code >= 0 else 5


class Remote:
    def __init__(self, host, runner, home=None, keep_fds=()):
        self.root = LOCAL_TARGETS.get(host)  # None: a fleet host, over ssh
        self.host, self.started = host, False
        self.runner = runner or (detached_run if self.root else subprocess.run)
        self.home = home
        self.keep_fds = tuple(keep_fds)  # the writer lock: every local program step inherits it (goodqa#15913 F2)
        if self.root and (not sys.executable or home is None):
            refuse("the local target needs this python's own executable and the caller's home")

    def call(self, op, args=None, data=None, timeout=SSH_TIMEOUT, write=False):
        """Run one remote operation. After the first WRITE operation has started, any failure is `unknown`: a killed ssh
        client does not stop the remote command, and a local program killed at its timeout may have stopped part way."""
        if write:
            self.started = True
        try:
            if self.root:
                inherit = {"pass_fds": self.keep_fds} if self.keep_fds else {}
                done = self.runner(local_argv(self.root, op, args or {}), input=data, capture_output=True, timeout=timeout,
                                   env=local_env(self.home), **inherit)
            else:
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
def check_inputs(host, ref, files, ticket, dry_run, resume, rollback, force_files, allow_older=False):
    if not isinstance(host, str) or (host not in HOSTS and host not in LOCAL_TARGETS):
        refuse("--host must be one of %s" % ", ".join(HOSTS + tuple(LOCAL_TARGETS)))
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
    if allow_older and (resume or rollback):
        refuse("--allow-older is accepted only with a new install")
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


def fetch_source(ref, names, home, allow_older=False, target="claude"):
    """Fetch the canonical main into a FRESH repository, prove REF is merged, return {name: (bytes, blob id)} and the list of
    names at REF that the target's installer ships (NAME_LISTS: install.py HOOKS, or install_codex.py DELIVERY_HELPERS for
    the Codex harness directory). The fresh repository is deleted afterwards."""
    list_file, list_name = NAME_LISTS[target]
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

        install_py = blob_at(list_file)[0]
        listed = None
        for stmt in ast.parse(install_py.decode()).body:
            if isinstance(stmt, ast.Assign) and any(isinstance(t, ast.Name) and t.id == list_name for t in stmt.targets):
                try:
                    listed = [str(x) for x in ast.literal_eval(stmt.value)]
                except (ValueError, SyntaxError, TypeError):
                    refuse("the %s tuple in %s at that commit is not a plain literal" % (list_name, list_file))
        if not listed:
            refuse("%s at that commit has no %s tuple" % (list_file, list_name))
        out = {}
        for name in names:
            if name not in listed:
                refuse("%s is not in the installer's %s list at that commit" % (name, list_name))
            if not allow_older:
                newer = git(repo, ["log", "--format=%H", "%s..%s" % (ref, main), "--", "harness/hooks/" + name], home).stdout.decode().split()
                if newer:
                    refuse("%s has %d newer merged version(s) on main (latest commit %s): installing this ref would DOWNGRADE it; use a newer "
                           "--from-ref, or --allow-older (audited) if that is intended" % (name, len(newer), newer[0][:12]), "older_ref")
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
        with open(audit_path(home), errors="replace") as fh:
            for line in fh:
                try:
                    row = json.loads(line)
                except ValueError:
                    continue
                if isinstance(row, dict):
                    rows.append(row)
    except OSError:
        pass
    return rows


CLEARING = ("installed", "rolled_back", "restored", "already_current", "refused")  # definite results; attempt_refused and unknown never clear


def unfinished_runs(home, host):
    """Runs on this host with an install or a rollback ATTEMPT that has no definite result. Only a definite result clears an
    attempt: installed, rolled_back, restored, already_current, or `refused` of a NEW install (nothing live changed). A resume
    or rollback that fails records `attempt_refused`, which does NOT clear: the host is still in the state the earlier
    attempt left it in."""
    opened = {}
    for row in audit_rows(home):
        if row.get("host") != host or not row.get("run"):
            continue
        run, kind_ = row["run"], row.get("kind")
        if row.get("event") == "start" and kind_ in ("install", "resume", "rollback"):
            opened[(run, "rollback" if kind_ == "rollback" else "install")] = True
        elif row.get("event") == "result" and row.get("result") in CLEARING:
            if kind_ == "rollback" or row.get("result") == "restored":
                opened[(run, "rollback")] = False
            if row.get("result") == "restored" or kind_ != "rollback":
                opened[(run, "install")] = False
    return sorted({run for (run, _which), is_open in opened.items() if is_open})


def sha256(data):
    return hashlib.sha256(data).hexdigest()


# ----------------------------------------------------------------------------- the self-test comparison
UNREGISTERED = "MISSING"  # doctor's state for a declared, required hook that settings.json does not register
NOT_REGISTERED_BEFORE = ("PENDING",)  # doctor's state for a declared, not yet required row: never registered either


def _states(result):
    states = (result.get("doctor") or {}).get("states")
    return states if isinstance(states, dict) else None


def newly_declared_unregistered(before, after):
    """Doctor ids the baseline manifest did not declare (or declared `pending`, so not registered then either) and that
    are declared but unregistered after the install
    (goodqa#15754 AC-10: install-files ships a manifest that adds hook rows, and never edits settings.json, so those rows
    are MISSING until main registers them). They are reported, not a regression. Empty when either side has no states
    (an older baseline): the strict rule applies."""
    s0, s1 = _states(before), _states(after)
    if s0 is None or s1 is None:
        return []
    return sorted(i for i, state in s1.items()
                  if state == UNREGISTERED and (i not in s0 or s0[i] in NOT_REGISTERED_BEFORE))


HOOK_RULES = {"hook_deny_wal": "log_delete/log-delete", "hook_subagent_local": "log_delete/install-files"}


def selftest_worse(before, after):
    """None when `after` is no worse than `before`, else the reason. The hook-entry probes are ABSOLUTE (goodqa#15913): after
    any install the registered entry must block both with exactly these rules, whatever the baseline did (a host whose old
    guard lacks the install-files rule must take command_guard.py in the same run). The rule label, not only exit 2, is
    required: a missing or unreadable entry also exits 2, from python itself. The main recovery probe (M2) is RELATIVE: allowed
    before and not allowed after is worse; a baseline without it, or one that already refused it, is never compared."""
    for key, rule in HOOK_RULES.items():
        now = (after.get("hook") or {}).get(key) or {}
        if now.get("exit") != 2 or now.get("rule") != rule:
            return ("the hook entry probe %s did not block with %s (exit %s, rule %s): install command_guard.py and "
                    "command_guard_hook.py from one merged commit" % (key, rule, now.get("exit"), now.get("rule") or "-"))
    was = (before.get("hook") or {}).get("hook_main_recovery") or {}
    now = (after.get("hook") or {}).get("hook_main_recovery") or {}
    if was.get("exit") == 0 and now.get("exit") != 0:
        return ("the hook entry probe hook_main_recovery (main's --rollback form) was allowed before the install and is not "
                "now (exit %s, rule %s): main could no longer recover this host" % (now.get("exit"), now.get("rule") or "-"))
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
        s0, s1 = _states(before), _states(after)
        if s0 is not None and s1 is not None:
            # a hook wired before the install must still be declared and wired after it (a renamed or dropped row of a
            # wired hook is a regression, not a new row)
            lost = sorted(i for i, state in s0.items() if state == "WIRED" and s1.get(i) != "WIRED")
            if lost:
                return "doctor checks no longer wired: %s" % ", ".join(lost[:10])
        new = sorted(set(d1["failing"]) - set(d0["failing"]) - set(newly_declared_unregistered(before, after)))
        if new:
            return "new failing doctor checks: %s" % ", ".join(new[:10])
    return None


def selftest_ok_to_start(result):
    """The baseline must be able to run AND the host's guard must already deny the foundational probe: a guard that fails
    open before the install would let any replacement pass the comparison."""
    guard = result.get("guard") or {}
    if not guard or any(v.get("exit") is None for v in guard.values()):
        return False
    return (guard.get("deny_wal") or {}).get("verdict") == "block" and (guard.get("allow") or {}).get("verdict") == "allow"


# ----------------------------------------------------------------------------- the run
def new_run_id():
    return "ins-" + uuid.uuid4().hex[:12]


def order(names):
    """Fixed install order: everything else first, command_guard.py LAST."""
    rest = [n for n in names if n != "command_guard.py"]
    return rest + (["command_guard.py"] if "command_guard.py" in names else [])


def comment_state(ticket, text, poster):
    """How the one ticket comment ended: "posted" only when it was confirmed. An injected poster: "posted" unless it raised
    or returned False. `ah ticket comment`: its JSON reply must say ok true and comment "posted"; a zero exit with comment
    "pending" (spooled), "parked" or "dead", a "duplicate" (no delivery state), or an unreadable reply is not delivery
    (goodqa#15913 F1). None without a ticket."""
    if not ticket:
        return None
    try:
        if poster:
            return "failed" if poster(ticket, text) is False else "posted"
        done = subprocess.run([sys.executable, "-I", AH_PY, "ticket", "comment", ticket, "--body", text],
                              capture_output=True, timeout=60)
        if done.returncode != 0:
            return "failed"
        reply = json.loads(done.stdout)
    except Exception:  # noqa: BLE001 - a failed comment is reported (and exits 6 locally), never a traceback
        return "failed"
    if not isinstance(reply, dict) or reply.get("ok") is not True:
        return "unconfirmed"
    state = reply.get("comment") or reply.get("result")
    return state if state in ("posted", "pending", "parked", "dead", "duplicate") else "unconfirmed"


def post_comment(ticket, text, poster):
    """True only when the comment's delivery was confirmed (see comment_state); None without a ticket."""
    state = comment_state(ticket, text, poster)
    return None if state is None else state == "posted"


COMMENT_FAILED_EXIT = 6


def finish(home, run, host, result, exit_code, extra, ticket, poster, kind_):
    """Write the result row, post the one ticket comment and return (exit 0) or raise (any other exit). A resume or a rollback that
    is refused is recorded as `attempt_refused`: it must not clear an unfinished run (the host may still be half installed).
    A local target keeps no host-side audit copy, so its ticket comment is the only record off this machine: when that
    comment fails, a run that would exit 0 exits 6 (`comment_failed`; the result row still holds the real result)."""
    if result == "refused" and kind_ in ("resume", "rollback"):
        result = "attempt_refused"
    row = dict({"event": "result", "run": run, "host": host, "kind": kind_, "result": result}, **extra)
    out = dict({"ok": exit_code == 0, "run": run, "host": host, "result": result, "exit_code": exit_code}, **extra)
    try:
        audit(home, row)
    except OSError:
        out["audit_warning"] = "the result row could not be written on this machine"
    summary = {n: {"old": v.get("old_sha"), "new": v.get("new_sha")} for n, v in (extra.get("files") or {}).items()}
    state = comment_state(ticket, "ah install-files %s on %s: %s (run %s) ref %s files %s" % (
        kind_, host, result, run, extra.get("ref"), json.dumps(summary)[:1500])
        + ("; " + str(extra["note"])[:500] if extra.get("note") else ""), poster)
    out["ticket_comment"] = None if state is None else state == "posted"
    if out["ticket_comment"] is False:
        out["comment_failed"] = True
        out["ticket_comment_state"] = state
        if host in LOCAL_TARGETS and exit_code == 0:
            exit_code = COMMENT_FAILED_EXIT
            out.update(ok=False, exit_code=exit_code, reason="the ticket comment for run %s was not confirmed as posted (%s): check "
                       "the ticket and post it by hand if it is missing (the result row on this machine says %s)" % (run, state, result))
    if exit_code == COMMENT_FAILED_EXIT:
        raise InstallError("comment_failed", "%s on %s (run %s): %s" % (result, host, run, out["reason"]), exit_code, out)
    if exit_code != 0:
        raise InstallError(result, "%s on %s (run %s)%s" % (result, host, run, ": " + str(extra["reason"]) if extra.get("reason") else ""), exit_code, out)
    return out


def start_row(home, run):
    rows = [r for r in audit_rows(home) if r.get("run") == run and r.get("event") == "start" and r.get("kind") in ("install", "resume")]
    return rows[0] if rows else None


def results_of(home, run):
    return [r.get("result") for r in audit_rows(home) if r.get("run") == run and r.get("event") == "result"]


def install_files(host, ref, files, ticket, dry_run=False, home=None, session="", agent="", runner=None, poster=None, allow_older=False):
    check_inputs(host, ref, files, ticket, dry_run, None, None, (), allow_older)
    home = Path(home or Path.home())
    with (contextlib.nullcontext(()) if dry_run else writer_lock(home, host)) as keep_fds:  # a dry run writes nothing
        return _run(host, ref, list(files), ticket, dry_run, home, session, agent, runner, poster, None, None, "install", allow_older,
                    keep_fds)


def resume(run_id, ticket, home=None, session="", agent="", runner=None, poster=None):
    home = Path(home or Path.home())
    if not isinstance(run_id, str) or not RUN_RE.fullmatch(run_id):
        refuse("--resume takes a run id like ins-0123456789ab")
    row = start_row(home, run_id)
    if row is None:
        refuse("no such run on this machine: %s" % run_id)
    with writer_lock(home, row["host"]) as keep_fds:  # F2: no live writer of this target; only now read its results and files
        if ("installed" in results_of(home, run_id)) or ("rolled_back" in results_of(home, run_id)) or ("restored" in results_of(home, run_id)):
            refuse("run %s already finished" % run_id)
        check_inputs(row["host"], None, None, ticket, False, run_id, None, ())
        return _run(row["host"], row["ref"], sorted(row["files"], key=lambda n: n), ticket, False, home, session, agent, runner, poster,
                    run_id, row.get("baseline"), "resume", False, keep_fds)


def _plan_for(names, sources, state, run):
    plan = {}
    for name in names:
        data, oid, mode = sources[name]
        new, old = sha256(data), state[name]["sha"]
        plan[name] = {"action": "already_current" if old == new else ("new" if old is None else "replaced"), "old_sha": old, "new_sha": new,
                      "blob": oid, "mode": state[name]["mode"] if state[name]["mode"] is not None else 0o644,
                      "backup": ".ah-install/backups/%s/%s" % (run, name) if old and old != new else None}
    return plan


def codex_differs(home, plan, unchecked=None):
    """`--host local`: names of this run whose Codex harness copy exists and differs from the bytes just installed. Read only;
    a missing Codex directory, a missing copy or a symlink is not listed. A copy (or the directory) that cannot be read, or
    that goes away or changes type while it is read, is never fatal and is never followed or waited on: its name goes into
    `unchecked` (goodqa#15913 r5 F1). lstat, not is_dir/is_file: newer Pythons answer False for a permission error there,
    which would hide an unreadable copy."""
    unchecked = [] if unchecked is None else unchecked
    folder, out = Path(home).joinpath(*CODEX_DIR), []
    try:
        if not stat.S_ISDIR(folder.lstat().st_mode):
            return []  # a symlink or a file is not listed
    except (FileNotFoundError, NotADirectoryError):
        return []
    except OSError:
        unchecked.append("~/" + "/".join(CODEX_DIR))
        return []
    for name, item in plan.items():
        path = folder / name
        try:
            if not stat.S_ISREG(path.lstat().st_mode):
                continue  # a symlink is not listed
        except (FileNotFoundError, NotADirectoryError):
            continue
        except OSError:
            unchecked.append(name)
            continue
        try:
            digest = _regular_file_sha(path)
        except OSError:
            digest = None
        if digest is None:
            unchecked.append(name)  # unreadable, or removed or swapped for a link or a FIFO after the lstat
        elif digest != item["new_sha"]:
            out.append(name)
    return sorted(out)


def _regular_file_sha(path):
    """sha256 of a regular file, or None when the path is not one (a FIFO or device swapped in after a lookup). Opened
    without following a symlink (OSError) and without blocking on a FIFO; hashed in chunks, so a huge file costs no memory."""
    fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return None
        digest = hashlib.sha256()
        for chunk in iter(lambda: os.read(fd, 1 << 20), b""):
            digest.update(chunk)
        return digest.hexdigest()
    finally:
        os.close(fd)


def codex_home_elsewhere(home):
    """CODEX_HOME when it is set and names a directory other than ~/.codex, else None: Codex then loads its harness from
    there, not from the ~/.codex/agent-harness that local-codex writes and the drift report reads."""
    value = os.environ.get("CODEX_HOME") or ""
    if not value or os.path.realpath(os.path.expanduser(value)) == os.path.realpath(str(Path(home) / CODEX_DIR[0])):
        return None
    return value


def _add_note(extra, note):
    extra["note"] = (str(extra["note"]) + "; " + note) if extra.get("note") else note


def _with_codex_note(home, remote, plan, extra):
    """The Codex drift report for `--host local`. It runs after the files are live and before finish(), so it must never
    raise: a failure is reported as "could not be checked" and the real result is still recorded (goodqa#15913 r5 F1)."""
    if remote.root != "claude":
        return extra
    unchecked = []
    try:
        differs = codex_differs(home, plan, unchecked)
        if differs:
            extra["codex_differs"] = differs
            _add_note(extra, "the Codex harness copies of %s on this machine differ from the installed bytes; install them with "
                             "--host local-codex" % ", ".join(differs[:10]))
        elsewhere = codex_home_elsewhere(home)
        if elsewhere:
            extra["codex_home"] = elsewhere[:300]
            _add_note(extra, "CODEX_HOME is set to %s: Codex loads its harness from there, and this drift report read ~/%s "
                             "instead" % (elsewhere[:200], "/".join(CODEX_DIR)))
    except Exception as error:  # noqa: BLE001 - a drift report never stops the real result from being recorded
        unchecked.append("(%s)" % type(error).__name__)
    if unchecked:
        extra["codex_unchecked"] = unchecked[:20]
        _add_note(extra, "the Codex drift could not be checked for %s (unreadable, or removed while it was read)"
                  % ", ".join(unchecked[:10]))
    return extra


def _run(host, ref, files, ticket, dry_run, home, session, agent, runner, poster, resume_of, baseline, kind_, allow_older=False, keep_fds=()):
    root = LOCAL_TARGETS.get(host)
    if root == "codex" and not Path(home).joinpath(*CODEX_DIR).is_dir():
        refuse("the Codex harness directory ~/%s does not exist on this machine; nothing was changed" % "/".join(CODEX_DIR))
    if root == "codex" and kind_ == "install" and codex_home_elsewhere(home):
        refuse("CODEX_HOME is set to %s, so Codex does not load ~/%s, which local-codex writes; nothing was changed"
               % (codex_home_elsewhere(home)[:200], "/".join(CODEX_DIR)))
    sources, listed, main = fetch_source(ref, files, home, allow_older or bool(resume_of), root or "claude")
    remote = Remote(host, runner, home, keep_fds)
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
             "baseline": before, "script_sha256": SCRIPT_SHA256, "session": session or None, "agent": agent or None, "ticket": ticket,
             "allow_older": bool(allow_older)}
    try:
        audit(home, start)  # fail closed: nothing is written remotely when this row cannot be written and fsynced
    except OSError:
        raise InstallError("audit_failed", "could not write the audit row; nothing was changed", 3, {"ok": False})
    if not applied:
        return finish(home, run, host, "already_current", 0, _with_codex_note(home, remote, plan, {"ref": ref, "files": plan}), ticket, poster, kind_)
    if resume_of:
        remote.started = True  # the interrupted run may have reached its commit: a failure is never a clean refusal, it is unknown or a rollback
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
        try:
            after = remote.call("selftest", timeout=SELFTEST_TIMEOUT)
        except InstallError as error:
            if error.code != "lost":
                raise
            # the self-test we started did not answer in time: that is a bad sign, not a lost link to ignore; try to roll back
            # (guard first); if ssh is really gone the rollback itself reports unknown
            raise InstallError("selftest_worse", "the after-install self-test did not answer in time", 4)
        why = selftest_worse(before, after)
        if why:
            raise InstallError("selftest_worse", why, 4)
    except Exception as error:  # noqa: BLE001 - an unexpected failure after the first live write must not leave a bare traceback
        if not isinstance(error, InstallError):
            error = InstallError("unexpected", "%s: %s" % (type(error).__name__, str(error)[:120]), 5 if remote.started else 2)
        if remote.started and error.code in ("lost", "unexpected"):
            return finish(home, run, host, "unknown", 5, {"ref": ref, "files": plan, "reason": "%s; check %s before retrying" % (error, host)}, ticket, poster, kind_)
        if not locked:  # the lock was never taken (held by another run, or no answer): touch nothing on the host, not even a rollback
            note = "; a lock may remain on %s until it is stale (30 minutes)" % host if error.code == "lost" else ""
            return finish(home, run, host, "refused", 2, {"ref": ref, "files": plan, "reason": (str(error)[:300] + note)}, ticket, poster, kind_)
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
        if op == "audit" and remote.root:
            continue  # this machine: the host audit file IS the caller's audit file, which already holds the start and result rows
        try:
            remote.call(op, args)
        except InstallError:
            pass
    extra = {"ref": ref, "files": plan, "selftest_after": after}
    unregistered = newly_declared_unregistered(before, after)
    if unregistered:
        # installed, but these hooks do not run until settings.json registers them (install.py's merge): never "live"
        extra["unregistered"] = unregistered
        extra["registration_needed"] = True
        extra["note"] = ("hooks declared by the new manifest but not registered in settings.json on %s (they do not run "
                         "until registered): %s" % (host, ", ".join(unregistered[:10])))
    return finish(home, run, host, "installed", 0, _with_codex_note(home, remote, plan, extra), ticket, poster, kind_)


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
    bad = [i["name"] for i in items if got["live"].get(i["name"]) != (None if i.get("remove_if_sha") else plan[i["name"]]["old_sha"])]
    if bad:
        return finish(home, run, host, "unknown", 5, {"ref": ref, "files": plan, "reason": "rollback incomplete: read-back differs for %s; check %s" % (", ".join(bad), host)}, ticket, poster, kind_)
    return finish(home, run, host, "rolled_back", 4, {"ref": ref, "files": plan, "reason": str(cause)[:300], "selftest_after_rollback": again}, ticket, poster, kind_)


def rollback(run_id, ticket, force_files=(), home=None, session="", agent="", runner=None, poster=None):
    home = Path(home or Path.home())
    if not isinstance(run_id, str) or not RUN_RE.fullmatch(run_id):
        refuse("--rollback takes a run id like ins-0123456789ab")
    row = start_row(home, run_id)
    if row is None:
        refuse("no such run on this machine: %s" % run_id)
    with writer_lock(home, row["host"]) as keep_fds:  # F2: no live writer of this target; only now read the audit and probe
        return _rollback(row, run_id, ticket, force_files, home, session, agent, runner, poster, keep_fds)


def _rollback(row, run_id, ticket, force_files, home, session, agent, runner, poster, keep_fds):
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
    remote = Remote(host, runner, home, keep_fds)
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
    items, payload = _restore_items(home, remote, run_id, plan, to_restore, None) if to_restore else ([], b"")  # a plain refusal BEFORE the start row: unusable backups must not open an attempt
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
        got = remote.call("restore", {"items": items}, data=payload, write=True) if items else {"live": {}}
        try:  # NEG-28: a commit step killed part way leaves the unrenamed temps holding this run's new bytes; remove them all
            remote.call("cleanup", {"names": sorted(plan)})
        except InstallError:
            pass  # best effort: the restore above already decided the live bytes
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
    bad = [i["name"] for i in items if got["live"].get(i["name"]) != (None if i.get("remove_if_sha") else plan[i["name"]]["old_sha"])]
    if bad:
        return finish(home, run_id, host, "unknown", 5, {"files": plan, "reason": "rollback incomplete: read-back differs for %s; check %s" % (", ".join(bad), host)}, ticket, poster, "rollback")
    why = selftest_worse(row.get("baseline") or {}, after)
    extra = {"files": plan, "restored": to_restore, "notes": notes, "selftest_after": after}
    if why:
        extra["selftest_note"] = why  # a rollback is never blocked by the self-test: the difference is reported, not refused
    return finish(home, run_id, host, "restored", 0, extra, ticket, poster, "rollback")


