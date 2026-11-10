#!/usr/bin/env python3
"""codex_owner: run long-lived Codex (GPT) owners on the ChatGPT subscription, with a two-way message channel.

Commands:
  start NAME --dir DIR --brief FILE [--ticket T] [--stream S] [--model M] [--effort E] [--max-auto-turns N]
        [--add-dir D ...] [--session ID] [--strict-vet]
  send NAME --from user|main --text TEXT        queue a message for the owner (read at its next turn; TEXT - = stdin)
  status [NAME] [--json]                        owner table (harness=openai)
  log NAME [-n N]                               the owner's last N replies (outbox)
  stop NAME                                     stop after the current turn
  restart NAME                                  stop after the current turn, then start again on the same thread
  vet [--strict-vet]                            check the Codex hooks the way every owner turn does

State lives in $CODEX_OWNER_HOME (default ~/.agent-harness/codex-owners)/NAME/ (status.json, inbox/, outbox.jsonl,
turns/*.jsonl, supervisor.log, supervisor.lock). Each turn is `codex exec` (first) or `codex exec resume <thread>`;
the owner ends every turn with a STATUS line:
  STATUS: WORKING   -> the supervisor resumes it with "continue" (bounded by --max-auto-turns between messages)
  STATUS: WAITING|BLOCKED|DONE -> the supervisor idles and polls the inbox ($CODEX_OWNER_POLL_SECS, default 30 s)

Hook vetting: Codex silently skips user hooks that are not trusted in config.toml, so the supervisor passes
--dangerously-bypass-hook-trust, but only after vet_hooks() passes for that turn: every hooks.json command must run
a python file in <codex home>/agent-harness, and the files, that directory, hooks.json and the codex home must be
owned by this user and not group- or world-writable. --strict-vet (or CODEX_OWNER_STRICT_VET=1) also compares each
hook file's sha256 with install-manifest.json written by install_codex.py. A failed vet never runs the turn and
leaves the owner BLOCKED. Owners run `-s workspace-write`, and no writable directory may contain the codex home.

Configuration (environment, with the values main used as defaults): CODEX_OWNER_HOME, CODEX_OWNER_BIN,
CODEX_OWNER_SESSION (WAL dir ~/.claude/wals/<session>, work dir ~/.agent-harness/work/<session>),
CODEX_OWNER_POLL_SECS, CODEX_OWNER_ERROR_BACKOFF, CODEX_OWNER_STRICT_VET, CODEX_HOME.
No API keys: the CLI's own signed-in subscription auth is used; OPENAI_API_KEY, CODEX_API_KEY and OPENAI_BASE_URL are
removed from the child env. Python 3.9+ standard library only.
"""
import argparse
import errno
import fcntl
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import time
import uuid
from pathlib import Path

DEFAULT_CODEX = "/Applications/ChatGPT.app/Contents/Resources/codex-cli/bin/codex"
DEFAULT_SESSION = "baab765b-d85c-46b4-b7b9-588eb912c770"
CONTINUE = ("Continue your plan from where you stopped. Do the next concrete step, commit and push green steps, "
            "post checkpoints on the ticket, and end with a STATUS line.")
STRIPPED_ENV = ("OPENAI_API_KEY", "CODEX_API_KEY", "OPENAI_BASE_URL")
STATUSES = ("WORKING", "WAITING", "BLOCKED", "DONE")
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
TOKEN_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")  # model, effort, thread id: never an option
MAX_TEXT = 20000            # characters in one message
MAX_INBOX_BYTES = 256 * 1024  # one inbox file (20000 chars of \\uXXXX pairs fit)
MAX_STATUS_BYTES = 4 * 1024 * 1024
MAX_HOOKS_BYTES = 1024 * 1024
MAX_HOOK_FILE_BYTES = 16 * 1024 * 1024
UNSAFE_BITS = stat.S_IWGRP | stat.S_IWOTH


class StatusError(Exception):
    """status.json exists but cannot be trusted; never overwritten automatically."""


def root():
    return Path(os.environ.get("CODEX_OWNER_HOME") or (Path.home() / ".agent-harness" / "codex-owners"))


def codex_bin():
    return os.environ.get("CODEX_OWNER_BIN") or DEFAULT_CODEX


def session():
    return os.environ.get("CODEX_OWNER_SESSION") or DEFAULT_SESSION


def codex_home():
    return Path(os.environ.get("CODEX_HOME") or (Path.home() / ".codex"))


def _float_env(name, default):
    try:
        value = float(os.environ.get(name, default))
    except ValueError:
        return default
    return value if value >= 0 else default


def poll_secs():
    return _float_env("CODEX_OWNER_POLL_SECS", 30.0)


def error_backoff():
    return _float_env("CODEX_OWNER_ERROR_BACKOFF", 60.0)


def strict_env():
    return os.environ.get("CODEX_OWNER_STRICT_VET") == "1"


def now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def valid_name(name):
    return isinstance(name, str) and bool(NAME_RE.match(name))


def odir(name):
    if not valid_name(name):
        sys.exit("bad owner name %r: use letters, digits, '-' and '_' (no dots or path separators)" % (name,))
    return root() / name


def log_line(name, text):
    """Supervisor log; callers pass reasons and paths, never message bodies or environment values."""
    try:
        with open(odir(name) / "supervisor.log", "a") as f:
            f.write("%s %s\n" % (now(), text))
    except OSError:
        pass


def read_capped(path, limit):
    """Read a regular file without following a final symlink; raise OSError when it is not one or too large."""
    fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise OSError(errno.EINVAL, "not a regular file")
        if st.st_size > limit:
            raise OSError(errno.EFBIG, "file over the %d byte cap" % limit)
        chunks, total = [], 0
        while True:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            total += len(chunk)
            if total > limit:
                raise OSError(errno.EFBIG, "file over the %d byte cap" % limit)
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)


def load(name):
    """None when there is no status.json; StatusError when it exists but is unreadable or not an object."""
    p = odir(name) / "status.json"
    if not os.path.lexists(str(p)):
        return None
    try:
        data = json.loads(read_capped(p, MAX_STATUS_BYTES).decode("utf-8"))
    except (OSError, ValueError) as e:
        raise StatusError("%s is corrupt or unreadable (%s)" % (p, e))
    if not isinstance(data, dict):
        raise StatusError("%s does not hold a JSON object" % p)
    return data


def save(name, st):
    d = odir(name)
    tmp = d / ("status.json.%d.tmp" % os.getpid())
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(json.dumps(st, indent=1))
    os.replace(str(tmp), str(d / "status.json"))


def append(path, rec):
    with open(path, "a") as f:
        f.write(json.dumps(rec) + "\n")


def _reject(name, path, why):
    log_line(name, "inbox: rejected %s (%s)" % (path.name, why))
    try:
        os.rename(str(path), str(path) + ".rejected")
    except OSError:
        pass


def take_inbox(name):
    """Deliver each queued message once: only regular files under the size cap holding a well-formed message.
    Delivered files become *.read, anything else *.rejected, so nothing is retried forever."""
    d = odir(name) / "inbox"
    msgs = []
    try:
        entries = sorted(os.listdir(str(d)))
    except OSError:
        return msgs
    for entry in entries:
        if not entry.endswith(".json"):
            continue
        p = d / entry
        try:
            m = json.loads(read_capped(p, MAX_INBOX_BYTES).decode("utf-8"))
        except OSError as e:
            _reject(name, p, "unreadable: %s" % (e.strerror or e))
            continue
        except ValueError:
            _reject(name, p, "malformed JSON")
            continue
        if not (isinstance(m, dict) and m.get("from") in ("user", "main") and isinstance(m.get("text"), str)
                and m["text"].strip() and len(m["text"]) <= MAX_TEXT and isinstance(m.get("at", ""), str)):
            _reject(name, p, "not a valid message")
            continue
        try:
            os.rename(str(p), str(p) + ".read")
        except OSError:
            continue  # consumed by someone else; never deliver twice
        msgs.append({"at": str(m.get("at", ""))[:40], "from": m["from"], "text": m["text"]})
    return msgs


def parse_status(text):
    for line in reversed((text or "").strip().splitlines()):
        line = line.strip().upper()
        if line.startswith("STATUS:"):
            rest = line.split(":", 1)[1].strip()
            word = rest.split()[0] if rest else ""
            return word if word in STATUSES else "WORKING"
    return "WORKING"


def _lstat(path):
    return os.lstat(str(path))


def _unsafe(path, want_dir):
    """Reason string when path is not a user-owned, non-symlink file/dir without group/other write; else None."""
    try:
        s = _lstat(path)
    except OSError:
        return "missing %s %s" % ("directory" if want_dir else "hook file", path)
    if stat.S_ISLNK(s.st_mode):
        return "symlink not allowed: %s" % path
    if want_dir and not stat.S_ISDIR(s.st_mode):
        return "not a directory: %s" % path
    if not want_dir and not stat.S_ISREG(s.st_mode):
        return "not a regular file: %s" % path
    if s.st_uid != os.getuid():
        return "not owned by this user: %s" % path
    if s.st_mode & UNSAFE_BITS:
        return "group- or world-writable: %s" % path
    return None


def hook_command_re(home):
    """`python3 <home>/agent-harness/<name>.py[ hook][ || exit 2]`, the forms install_codex.py registers."""
    return re.compile(r"^python3 (" + re.escape(str(home / "agent-harness")) + r"/[a-z_]+\.py)( hook)?( \|\| exit 2)?$")


def _sha256_file(path):
    return hashlib.sha256(read_capped(path, MAX_HOOK_FILE_BYTES)).hexdigest()


def load_manifest(hdir):
    """{file name: sha256} from install-manifest.json, or a reason string."""
    path = hdir / "install-manifest.json"
    bad = _unsafe(path, False)
    if bad:
        return "install manifest: " + bad.replace("hook file", "file")
    try:
        data = json.loads(read_capped(path, MAX_HOOKS_BYTES).decode("utf-8"))
    except (OSError, ValueError) as e:
        return "install manifest unreadable: %s" % e
    files = data.get("files") if isinstance(data, dict) else None
    if not isinstance(files, dict):
        return "install manifest has no files object"
    return files


def vet_hooks(strict=False):
    """Return (ok, reason). Hooks are only force-trusted when every Codex hook command is one of ours, each file and
    its directory are user-owned and not writable by others, and (strict) each file matches the install manifest."""
    home = codex_home()
    path = home / "hooks.json"
    hdir = home / "agent-harness"
    for p, is_dir in ((home, True), (path, False), (hdir, True)):
        bad = _unsafe(p, is_dir)
        if bad:
            return False, bad.replace("hook file", "file")
    try:
        data = json.loads(read_capped(path, MAX_HOOKS_BYTES).decode("utf-8"))
    except (OSError, ValueError) as e:
        return False, "hooks.json unreadable: %s" % e
    cmds = []

    def walk(x):
        if isinstance(x, dict):
            for k, v in x.items():
                if k == "command":
                    cmds.append(v)
                else:
                    walk(v)
        elif isinstance(x, list):
            for v in x:
                walk(v)
    walk(data)
    if not cmds:
        return False, "no hook commands"
    pattern = hook_command_re(home)
    manifest = load_manifest(hdir) if strict else None
    if isinstance(manifest, str):
        return False, manifest
    drift, files = [], set()
    for c in cmds:
        m = pattern.match(c) if isinstance(c, str) else None
        if not m:
            return False, "unexpected hook command: %r" % (c if isinstance(c, str) else type(c).__name__)
        f = Path(m.group(1))
        files.add(f)
        bad = _unsafe(f, False)
        if bad:
            return False, bad
    for f in sorted(files):
        try:
            digest = _sha256_file(f)
        except OSError as e:
            return False, "hook file unreadable: %s (%s)" % (f, e)
        if strict and manifest.get(f.name) != digest:
            return False, "strict vet: %s differs from the install manifest (re-run install_codex.py --apply)" % f.name
        ref = Path.home() / ".claude" / "hooks" / f.name
        try:
            if _sha256_file(ref) != digest:
                drift.append(f.name)
        except OSError:
            drift.append(f.name)
    msg = "%d hook commands vetted%s" % (len(cmds), " (strict)" if strict else "")
    if drift:
        msg += "; WARNING stale vs ~/.claude/hooks: %s (re-run install_codex.py)" % ",".join(sorted(set(drift)))
    return True, msg


def _inside(child, parent):
    try:
        child.relative_to(parent)
        return True
    except ValueError:
        return False


def turn_dirs(name, st):
    return (Path(st.get("wal_dir") or (Path.home() / ".claude" / "wals" / session())),
            Path(st.get("work_dir") or (Path.home() / ".agent-harness" / "work" / session())))


def check_state(name, st):
    """status.json sits in a directory the owner can write, so every field that reaches argv is checked per turn."""
    for key in ("model", "effort"):
        if not (isinstance(st.get(key), str) and TOKEN_RE.match(st[key])):
            return "invalid %s in status.json" % key
    if st.get("thread") is not None and not (isinstance(st["thread"], str) and TOKEN_RE.match(st["thread"])):
        return "invalid thread in status.json"
    extras = st.get("add_dirs", [])
    if not isinstance(extras, list) or not all(isinstance(x, str) for x in extras):
        return "invalid add_dirs in status.json"
    if not isinstance(st.get("dir"), str) or not st["dir"]:
        return "invalid dir in status.json"
    home = Path(os.path.realpath(str(codex_home())))
    wal_dir, work_dir = turn_dirs(name, st)
    for w in [st["dir"], str(wal_dir), str(work_dir), str(odir(name))] + extras:
        real = Path(os.path.realpath(w))
        if _inside(home, real) or _inside(real, home):
            return "writable dir %s would expose the codex home %s" % (w, home)
    return None


def block(name, st, turn, why):
    st.update(state="blocked", last_status="BLOCKED", last_reply=why, child_pid=None)
    save(name, st)
    append(odir(name) / "outbox.jsonl", {"at": now(), "turn": turn, "rc": -1, "status": "BLOCKED", "text": why})
    log_line(name, why)
    return "BLOCKED", -1


def run_turn(name, st, prompt):
    d = odir(name)
    turn = st.get("turns", 0) + 1
    bad = check_state(name, st)
    if bad:
        return block(name, st, turn, "refusing turn: " + bad)
    strict = bool(st.get("strict_vet")) or strict_env()
    ok, why = vet_hooks(strict)
    st["hooks_vetted"], st["hooks_vet_reason"] = ok, why
    if not ok:
        # Never run an owner turn without the harness guards.
        return block(name, st, turn, "harness hooks failed vetting: " + why)
    wal_dir, work_dir = turn_dirs(name, st)
    out = d / "turns" / ("%04d.jsonl" % turn)
    base = [codex_bin(), "exec"]
    common = ["--json", "--skip-git-repo-check", "-m", st["model"], "-c", 'model_reasoning_effort="%s"' % st["effort"],
              "-s", "workspace-write", "-c", "sandbox_workspace_write.network_access=true",
              "--add-dir", str(wal_dir), "--add-dir", str(work_dir), "--add-dir", str(d)]
    for extra in st.get("add_dirs", []):
        common += ["--add-dir", extra]
    common += ["--dangerously-bypass-hook-trust"]  # only reached after a passing vet
    if st.get("thread"):
        cmd = base + ["resume"] + common + [st["thread"], "-"]
    else:
        cmd = base + common + ["-C", st["dir"], "-"]
    env = {k: v for k, v in os.environ.items() if k not in STRIPPED_ENV}
    st.update(state="running", turn_started=now(), turns=turn)
    save(name, st)
    last, usage = "", None
    with open(out, "w") as f, open(d / "supervisor.log", "a") as errlog:
        try:
            p = subprocess.Popen(cmd, cwd=st["dir"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                 stderr=errlog, env=env, text=True)
        except OSError as e:
            log_line(name, "cannot launch codex: %s" % e)
            rc = 127
        else:
            st["child_pid"] = p.pid
            save(name, st)
            try:
                p.stdin.write(prompt)
                p.stdin.close()
            except BrokenPipeError:
                pass
            for line in p.stdout:
                f.write(line)
                try:
                    ev = json.loads(line)
                except ValueError:
                    continue
                if not isinstance(ev, dict):
                    continue
                if ev.get("type") == "thread.started":
                    st["thread"] = ev.get("thread_id")
                    save(name, st)
                elif ev.get("type") == "item.completed":
                    it = ev.get("item") if isinstance(ev.get("item"), dict) else {}
                    if it.get("type") == "agent_message" and isinstance(it.get("text"), str):
                        last = it["text"]
                    st["last_activity"] = now()
                    st["last_item"] = it.get("type")
                    save(name, st)
                elif ev.get("type") == "turn.completed":
                    usage = ev.get("usage")
            rc = p.wait()
    status = parse_status(last) if rc == 0 else "ERROR"
    append(d / "outbox.jsonl", {"at": now(), "turn": turn, "rc": rc, "status": status, "text": last, "usage": usage})
    st.update(state="idle", child_pid=None, last_reply=last[-2000:], last_status=status, last_rc=rc, turn_ended=now())
    save(name, st)
    return status, rc


def acquire_lock(name):
    """An exclusive flock held for the supervisor's life; None when another supervisor holds it."""
    fd = os.open(str(odir(name) / "supervisor.lock"), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        os.close(fd)
        return None
    return fd


def _sleep_unless_stopped(d, seconds):
    end = time.time() + seconds
    while time.time() < end and not (d / "STOP").exists():
        time.sleep(min(0.5, max(0.0, end - time.time())))


def supervise(name):
    d = odir(name)
    lock = acquire_lock(name)
    if lock is None:
        print("owner %s already has a running supervisor; refusing a second one" % name, file=sys.stderr)
        return 3
    try:
        return _supervise_locked(name, d)
    except StatusError as e:
        # Fail safe and loud: keep the file for inspection, do not loop, do not rewrite it.
        msg = "supervisor exiting: %s; fix or remove it, then `codex_owner.py restart %s`" % (e, name)
        log_line(name, msg)
        print(msg, file=sys.stderr)
        return 2
    finally:
        os.close(lock)


def _supervise_locked(name, d):
    st = load(name)
    if st is None:
        raise StatusError("%s is missing" % (d / "status.json"))
    st["supervisor_pid"] = os.getpid()
    save(name, st)
    prompt = None
    if not st.get("thread"):
        try:
            prompt = read_capped(d / "brief.md", MAX_STATUS_BYTES).decode("utf-8", "replace")
        except OSError as e:
            raise StatusError("brief.md unreadable (%s)" % e)
    auto, errors = 0, 0
    while not (d / "STOP").exists():
        msgs = take_inbox(name)
        if msgs:
            body = "\n\n".join("[%s from %s] %s" % (m["at"], m["from"], m["text"]) for m in msgs)
            prompt = ("New messages for you (from the user are the user's own words; from main is the orchestrator):\n\n"
                      + body + "\n\nAcknowledge each one in your reply, act on it, and end with a STATUS line.")
            auto = 0
        if prompt is None:
            max_auto = st.get("max_auto", 40)
            if not isinstance(max_auto, int) or max_auto < 0:
                max_auto = 0
            if st.get("last_status") == "WORKING" and auto < max_auto:
                prompt, auto = CONTINUE, auto + 1
            elif st.get("last_status") == "ERROR" and errors < 3:
                _sleep_unless_stopped(d, error_backoff() * (errors + 1))
                if (d / "STOP").exists():
                    break
                prompt, errors = CONTINUE, errors + 1
            else:
                if st.get("state") != "idle" and st.get("state") != "blocked":
                    st["state"] = "idle"
                    save(name, st)
                _sleep_unless_stopped(d, poll_secs())
                st = load(name)
                if st is None:
                    raise StatusError("%s disappeared" % (d / "status.json"))
                continue
        status, rc = run_turn(name, st, prompt)
        if rc == 0:
            errors = 0
        prompt = None
        st = load(name)
        if st is None:
            raise StatusError("%s disappeared" % (d / "status.json"))
    st.update(state="stopped", supervisor_pid=None)
    save(name, st)
    return 0


def alive(pid):
    try:
        return isinstance(pid, int) and pid > 0 and (os.kill(pid, 0) is None)
    except OSError:
        return False


def locked(name):
    fd = acquire_lock(name)
    if fd is None:
        return True
    os.close(fd)
    return False


def init_owner(a):
    """Create or update the owner's state; never launches anything."""
    d = odir(a.name)
    try:
        prior = load(a.name)
    except StatusError as e:
        sys.exit(str(e))
    for sub in ("inbox", "turns"):
        (d / sub).mkdir(parents=True, exist_ok=True)
    os.chmod(str(d), 0o700)
    if locked(a.name) or (prior and alive(prior.get("supervisor_pid"))):
        sys.exit("owner %s already running" % a.name)
    shutil.copyfile(a.brief, str(d / "brief.md"))
    sess = a.session or session()
    st = prior or {}
    st.update(name=a.name, harness="openai", model=a.model, effort=a.effort, dir=os.path.abspath(a.dir),
              ticket=a.ticket, stream=a.stream, started=st.get("started") or now(), max_auto=a.max_auto,
              add_dirs=[os.path.abspath(x) for x in a.add_dir], session=sess,
              wal_dir=str(Path.home() / ".claude" / "wals" / sess),
              work_dir=str(Path.home() / ".agent-harness" / "work" / sess), strict_vet=bool(a.strict_vet))
    st.setdefault("turns", 0)
    bad = check_state(a.name, st)
    if bad:
        sys.exit("refusing to start: " + bad)
    save(a.name, st)
    try:
        (d / "STOP").unlink()
    except FileNotFoundError:
        pass
    return d


def spawn(name):
    d = odir(name)
    with open(d / "supervisor.log", "a") as log:
        return subprocess.Popen([sys.executable, os.path.abspath(__file__), "_run", name], stdout=log, stderr=log,
                                stdin=subprocess.DEVNULL, start_new_session=True)


def cmd_start(a):
    d = init_owner(a)
    p = spawn(a.name)
    print("STARTED %s pid=%d dir=%s" % (a.name, p.pid, d))


def cmd_send(a):
    d = odir(a.name)
    try:
        if not load(a.name):
            sys.exit("no such owner")
    except StatusError as e:
        sys.exit(str(e))
    if a.text == "-":
        text = sys.stdin.read(MAX_TEXT + 1)
    else:
        text = a.text
    if not text.strip() or len(text) > MAX_TEXT:
        sys.exit("empty or too long (limit %d characters)" % MAX_TEXT)
    mid = "%s-%s" % (time.strftime("%Y%m%dT%H%M%S"), uuid.uuid4().hex[:6])
    tmp = d / "inbox" / (mid + ".tmp")
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(json.dumps({"id": mid, "at": now(), "from": a.sender, "text": text}))
    os.replace(str(tmp), str(d / "inbox" / (mid + ".json")))
    print("QUEUED %s %s" % (a.name, mid))


def cmd_status(a):
    rows = []
    if a.name:
        odir(a.name)
        names = [a.name]
    else:
        base = root()
        names = sorted(p.name for p in base.glob("*") if valid_name(p.name) and (p / "status.json").exists()) \
            if base.is_dir() else []
    for n in names:
        try:
            st = load(n) or {"name": n, "state": "missing"}
        except StatusError as e:
            st = {"name": n, "state": "CORRUPT", "error": str(e)}
        st["supervisor_alive"] = alive(st.get("supervisor_pid"))
        try:
            st["pending_inbox"] = len([e for e in os.listdir(str(odir(n) / "inbox")) if e.endswith(".json")])
        except OSError:
            st["pending_inbox"] = 0
        rows.append(st)
    if a.json:
        print(json.dumps(rows, indent=1))
        return
    for st in rows:
        print("%-16s %-7s %-10s sup=%s turns=%s status=%s last=%s ticket=%s" % (
            st.get("name"), st.get("harness"), st.get("state"), "up" if st["supervisor_alive"] else "DOWN",
            st.get("turns"), st.get("last_status"), st.get("last_activity") or st.get("turn_ended"), st.get("ticket")))
        if st.get("error"):
            print("    " + st["error"])
        reply = st.get("last_reply")
        if isinstance(reply, str) and reply.strip():
            print("    " + reply.strip().splitlines()[-1][:200])


def cmd_log(a):
    p = odir(a.name) / "outbox.jsonl"
    try:
        lines = read_capped(p, 64 * 1024 * 1024).decode("utf-8", "replace").splitlines()[-a.n:]
    except OSError:
        lines = []
    for l in lines:
        try:
            r = json.loads(l)
            print("--- turn %s %s rc=%s %s\n%s" % (r["turn"], r["at"], r["rc"], r["status"], str(r["text"])[-4000:]))
        except (ValueError, KeyError, TypeError):
            print("--- (malformed outbox line skipped)")


def cmd_restart(a):
    """Stop after the current turn, wait for the supervisor to exit, then start it again on the same thread."""
    d = odir(a.name)
    try:
        st = load(a.name) or {}
    except StatusError as e:
        sys.exit(str(e))
    (d / "STOP").write_text(now())
    while locked(a.name):
        time.sleep(min(10.0, max(0.1, poll_secs())))
    (d / "STOP").unlink()
    p = spawn(a.name)
    print("RESTARTED %s pid=%d thread=%s" % (a.name, p.pid, st.get("thread")))


def cmd_vet(a):
    ok, why = vet_hooks(bool(a.strict_vet) or strict_env())
    print(("OK " if ok else "FAIL ") + why)
    sys.exit(0 if ok else 1)


def cmd_stop(a):
    d = odir(a.name)
    if not d.is_dir():
        sys.exit("no such owner")
    (d / "STOP").write_text(now())
    print("STOP requested for %s (takes effect after the current turn)" % a.name)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sp = ap.add_subparsers(dest="cmd", required=True)
    s = sp.add_parser("start"); s.add_argument("name"); s.add_argument("--dir", required=True)
    s.add_argument("--brief", required=True); s.add_argument("--ticket", default=""); s.add_argument("--stream", default="")
    s.add_argument("--model", default="gpt-6.1-sol"); s.add_argument("--effort", default="high")
    s.add_argument("--max-auto-turns", "--max-auto", dest="max_auto", type=int, default=40)
    s.add_argument("--add-dir", action="append", default=[])
    s.add_argument("--session", default="", help="session id for the WAL and work dirs (default $CODEX_OWNER_SESSION)")
    s.add_argument("--strict-vet", action="store_true", help="also compare hook files with install-manifest.json")
    s.set_defaults(f=cmd_start)
    s = sp.add_parser("send"); s.add_argument("name"); s.add_argument("--from", dest="sender", choices=["user", "main"], required=True)
    s.add_argument("--text", required=True); s.set_defaults(f=cmd_send)
    s = sp.add_parser("status"); s.add_argument("name", nargs="?"); s.add_argument("--json", action="store_true"); s.set_defaults(f=cmd_status)
    s = sp.add_parser("log"); s.add_argument("name"); s.add_argument("-n", type=int, default=3); s.set_defaults(f=cmd_log)
    s = sp.add_parser("stop"); s.add_argument("name"); s.set_defaults(f=cmd_stop)
    s = sp.add_parser("restart"); s.add_argument("name"); s.set_defaults(f=cmd_restart)
    s = sp.add_parser("vet"); s.add_argument("--strict-vet", action="store_true"); s.set_defaults(f=cmd_vet)
    s = sp.add_parser("_run"); s.add_argument("name"); s.set_defaults(f=lambda a: sys.exit(supervise(a.name)))
    a = ap.parse_args(argv)
    r = root()
    r.mkdir(parents=True, exist_ok=True)
    a.f(a)


if __name__ == "__main__":
    main()
