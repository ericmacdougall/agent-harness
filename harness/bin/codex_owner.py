#!/usr/bin/env python3
"""codex_owner: run long-lived Codex (GPT) owners on the ChatGPT subscription, with a two-way message channel.

Commands:
  start NAME --dir DIR --brief FILE [--ticket T] [--stream S] [--model M] [--effort E] [--max-auto-turns N]
        [--add-dir D ...] [--session ID] [--strict-vet | --no-strict-vet] [--no-yolo] [--env NAME ...]
        [--allow-secret-env NAME ...]
  send NAME --from user|main --text TEXT        queue a signed message for the owner (TEXT - = stdin)
  status [NAME] [--json]                        owner table (harness=openai)
  log NAME [-n N]                               the owner's last N replies (outbox)
  stop NAME                                     stop after the current turn
  restart NAME                                  stop after the current turn, then start again on the same thread
  vet [--dir DIR] [--strict-vet | --no-strict-vet]   check the Codex hooks the way every owner turn does

Layout under $CODEX_OWNER_HOME (default ~/.agent-harness/codex-owners):
  NAME/            display and mailbox: status.json (output only, never read back), inbox/, outbox.jsonl, turns/,
                   supervisor.log, brief.md
  .control/NAME/   supervisor-owned: config.json (written by `start`, read only when a supervisor starts),
                   state.json (thread, turns), STOP, supervisor.lock, nonces.json
  .key             HMAC key for inbox messages (0600, created at first use)

Each turn is `codex exec` (first) or `codex exec resume <thread>`; the owner ends every turn with a STATUS line:
  STATUS: WORKING   -> the supervisor resumes it with "continue" (bounded by --max-auto-turns between verified messages)
  STATUS: WAITING|BLOCKED|DONE -> the supervisor idles and polls the inbox ($CODEX_OWNER_POLL_SECS, default 30 s)

Yolo mode (the default; the user: "codex owners should run with yolo mode but still obey the harness"): every turn
runs --dangerously-bypass-approvals-and-sandbox (no Codex sandbox, no approval prompts) and
--dangerously-bypass-hook-trust (Codex otherwise skips untrusted user hooks silently, so no guard would run). Both
flags are added only after vet_hooks() passes for that turn; a failed vet starts no child and leaves the owner
BLOCKED. `codex exec resume` accepts neither -s nor --add-dir, so resumes never carry them. --no-yolo runs the first
turn with `-s workspace-write` and the owner's own WAL and work dirs plus allowlisted --add-dir entries (inside DIR
or those per-owner dirs; never $HOME, dot-dirs or ~/Library), and resumes with no sandbox flags.

The vet: every hooks.json command must be `python3 <codex home>/agent-harness/<name>.py[ hook][ || exit 2]`, the
`python3` found on the child's fixed PATH must be a root- or user-owned file nobody else can write, the codex home,
hooks.json, the harness dir and each hook file must be user-owned, single-linked, non-symlink and not group- or
world-writable, config.toml must hold no hook tables, no plugin may carry command hooks (and only openai-* plugin
caches may carry hooks at all), and the owner's DIR (and its parents) may hold no project hooks (.codex/hooks.json,
.codex/hooks/, .codex/config.toml with hooks). Strict vet (the default when <codex home>/agent-harness/
install-manifest.json exists; --no-strict-vet or CODEX_OWNER_STRICT_VET=0 opts out with a warning every turn) also
checks every manifest file's sha256 and link count and refuses .py files the manifest does not list. A yolo owner can
write anywhere, hooks included, so after every turn the supervisor compares a fingerprint of hooks.json, the manifest
and every harness .py/.json file and re-runs the vet; a change marks the owner BLOCKED ("hooks changed during the
turn"), logs an ALERT and refuses further turns until `restart`. The guards still run on every command during the
turn: this catches tampering after the fact only.

Messages: `send` signs {id, from, text, ts, nonce} with HMAC-SHA256 under .key. The supervisor delivers only verified,
unseen nonces; anything else is renamed *.rejected and counted (inbox_forgery_attempts), and only a verified message
resets the auto-turn bound. In yolo mode an owner that reads .key can still forge: the key is a speed bump, and
decisions attributed to the user are re-verified through provenance on main's side.

Environment: the child gets an allowlist only (HOME, a fixed PATH, LANG, LC_*, TERM, TMPDIR, USER, LOGNAME, SHELL,
CODEX_HOME) plus names given with --env; names that look like secrets need --allow-secret-env NAME (logged), and
OPENAI_*, ANTHROPIC_* and CODEX_API_KEY never pass. Configuration: CODEX_OWNER_HOME, CODEX_OWNER_BIN,
CODEX_OWNER_SESSION, CODEX_OWNER_POLL_SECS, CODEX_OWNER_ERROR_BACKOFF, CODEX_OWNER_STRICT_VET, CODEX_HOME.
Signals: SIGTERM/SIGINT/SIGHUP stop the supervisor and terminate the running codex child (TERM, then KILL after 5 s).
SIGKILL of the supervisor cannot be handled: the child then runs to the end of its turn with the vet already passed.
Python 3.9+ standard library only.
"""
import argparse
import errno
import fcntl
import hashlib
import hmac
import json
import os
import re
import secrets
import shutil
import signal
import stat
import subprocess
import sys
import threading
import time
from pathlib import Path

DEFAULT_CODEX = "/Applications/ChatGPT.app/Contents/Resources/codex-cli/bin/codex"
DEFAULT_SESSION = "baab765b-d85c-46b4-b7b9-588eb912c770"
CONTINUE = ("Continue your plan from where you stopped. Do the next concrete step, commit and push green steps, "
            "post checkpoints on the ticket, and end with a STATUS line.")
STATUSES = ("WORKING", "WAITING", "BLOCKED", "DONE")
NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,63}")
TOKEN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")  # model, effort, thread id: never an option
ENV_NAME_RE = re.compile(r"[A-Z_][A-Z0-9_]{0,63}")
ENV_ALLOW = ("HOME", "LANG", "TERM", "TMPDIR", "USER", "LOGNAME", "SHELL", "CODEX_HOME")
ENV_NEVER = re.compile(r"(OPENAI_.*|ANTHROPIC_.*|CODEX_API_KEY)")
ENV_SECRETISH = re.compile(r".*(KEY|SECRET|TOKEN|PASSW|AUTH|CREDENTIAL|COOKIE|SESSION|PRIVATE).*")
SAFE_PATH = "/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin:~/.local/bin"
MAX_TEXT = 20000
MAX_INBOX_BYTES = 256 * 1024
MAX_STATE_BYTES = 4 * 1024 * 1024
MAX_HOOKS_BYTES = 1024 * 1024
MAX_HOOK_FILE_BYTES = 16 * 1024 * 1024
MAX_JSON_NODES = 20000
MAX_MSG_AGE = 30 * 86400
MAX_NONCES = 5000
UNSAFE_BITS = stat.S_IWGRP | stat.S_IWOTH
YOLO_FLAG = "--dangerously-bypass-approvals-and-sandbox"
TRUST_FLAG = "--dangerously-bypass-hook-trust"


class StateError(Exception):
    """A supervisor input file exists but cannot be trusted; never overwritten automatically."""


# ---------------------------------------------------------------- configuration

def root():
    return Path(os.environ.get("CODEX_OWNER_HOME") or (Path.home() / ".agent-harness" / "codex-owners"))


def codex_bin():
    return os.environ.get("CODEX_OWNER_BIN") or DEFAULT_CODEX


def session():
    return os.environ.get("CODEX_OWNER_SESSION") or DEFAULT_SESSION


def codex_home(home=None):
    """The Codex home, the one rule shared with install_codex.py: $CODEX_HOME when it is set and the target is the
    current user's home, else <home>/.codex."""
    base = Path(home) if home is not None else Path.home()
    env = os.environ.get("CODEX_HOME")
    if env and os.path.realpath(str(base)) == os.path.realpath(str(Path.home())):
        return Path(env)
    return base / ".codex"


def safe_path():
    return SAFE_PATH.replace("~", str(Path.home()))


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
    """True/False when CODEX_OWNER_STRICT_VET is 1/0, else None (decided by the manifest)."""
    return {"1": True, "0": False}.get(os.environ.get("CODEX_OWNER_STRICT_VET", ""))


def strict_mode(choice=None):
    """(strict, warning or None). An explicit choice wins, then the env, then: strict when the manifest exists."""
    manifest = codex_home() / "agent-harness" / "install-manifest.json"
    if choice is None:
        choice = strict_env()
    if choice is True:
        return True, None
    if choice is False:
        return False, ("WARNING strict hook vet is OFF (--no-strict-vet or CODEX_OWNER_STRICT_VET=0): a yolo owner can "
                       "rewrite the harness files and only the post-turn fingerprint would notice")
    if os.path.lexists(str(manifest)):
        return True, None
    return False, ("WARNING no %s: running the non-strict hook vet; re-run install_codex.py --apply so hook edits are "
                   "detected against the install manifest" % manifest)


def now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def valid_name(name):
    return isinstance(name, str) and bool(NAME_RE.fullmatch(name))


def odir(name):
    if not valid_name(name):
        sys.exit("bad owner name %r: use letters, digits, '-' and '_' (no dots or path separators)" % (name,))
    return root() / name


def cdir(name):
    odir(name)
    return root() / ".control" / name


def log_line(name, text):
    """Supervisor log; callers pass reasons and paths, never message bodies or environment values."""
    try:
        with open(odir(name) / "supervisor.log", "a") as f:
            f.write("%s %s\n" % (now(), text))
    except OSError:
        pass


# ---------------------------------------------------------------- files

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


def read_json(path, limit=MAX_STATE_BYTES, missing=None):
    """JSON object from path; `missing` when absent; StateError when present but unusable."""
    if not os.path.lexists(str(path)):
        return missing
    try:
        data = json.loads(read_capped(path, limit).decode("utf-8"))
    except (OSError, ValueError, RecursionError) as e:
        raise StateError("%s is corrupt or unreadable (%s)" % (path, e))
    if not isinstance(data, dict):
        raise StateError("%s does not hold a JSON object" % path)
    return data


def write_json(path, data):
    tmp = path.parent / ("%s.%d.tmp" % (path.name, os.getpid()))
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(json.dumps(data, indent=1))
    os.replace(str(tmp), str(path))


def append(path, rec):
    with open(path, "a") as f:
        f.write(json.dumps(rec) + "\n")


def _lstat(path):
    return os.lstat(str(path))


def _sha256_file(path):
    return hashlib.sha256(read_capped(path, MAX_HOOK_FILE_BYTES)).hexdigest()


def _unsafe(path, want_dir, label="file"):
    """Reason string when path is not a user-owned, non-symlink, single-linked file/dir without group/other write."""
    try:
        s = _lstat(path)
    except OSError:
        return "missing %s %s" % ("directory" if want_dir else label, path)
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
    if not want_dir and s.st_nlink != 1:
        return "hard-linked (%d links): %s" % (s.st_nlink, path)
    return None


# ---------------------------------------------------------------- vet

def hook_command_re(home):
    """`python3 <home>/agent-harness/<name>.py[ hook][ || exit 2]`, the forms install_codex.py registers."""
    return re.compile(r"python3 (" + re.escape(str(home / "agent-harness")) + r"/[a-z_]+\.py)( hook)?( \|\| exit 2)?")


def _json_strings_under(data, key):
    """Every value stored under `key` anywhere in data; iterative and node-bounded (no RecursionError)."""
    found, stack, nodes = [], [data], 0
    while stack:
        x = stack.pop()
        nodes += 1
        if nodes > MAX_JSON_NODES:
            raise ValueError("JSON has more than %d nodes" % MAX_JSON_NODES)
        if isinstance(x, dict):
            for k, v in x.items():
                if k == key:
                    found.append(v)
                else:
                    stack.append(v)
        elif isinstance(x, list):
            stack.extend(x)
    return found


def _load_json_bytes(raw, label):
    try:
        return json.loads(raw.decode("utf-8"))
    except (ValueError, RecursionError) as e:
        raise ValueError("%s unreadable: %s" % (label, type(e).__name__ if isinstance(e, RecursionError) else e))


def check_interpreter():
    """The python3 Codex will run for the hooks: found on the child's fixed PATH, owned by root or this user, and not
    writable by anyone else (file and directory)."""
    found = shutil.which("python3", path=safe_path())
    if not found:
        return "python3 not found on the fixed PATH %s" % safe_path()
    real = os.path.realpath(found)
    for p in (real, os.path.dirname(real)):
        try:
            s = os.stat(p)
        except OSError:
            return "python3 unresolvable: %s" % real
        if s.st_uid not in (0, os.getuid()) or s.st_mode & UNSAFE_BITS:
            return "python3 at %s is writable by others or owned by another user" % p
    return None


TOML_HOOK_TABLE = re.compile(r"^\s*\[\[?\s*\"?hooks\"?\s*(\]|\.(?!\s*\"?state\"?\s*[\].]))", re.M)
TOML_HOOK_KEY = re.compile(r"^\s*\"?hooks\"?\s*(=|\.(?!\s*\"?state\b))", re.M)
TOML_TABLE = re.compile(r"^\s*\[", re.M)


def toml_has_hooks(text):
    """True when TOML text defines hooks: a [hooks] or [hooks.<event>] table, [[hooks...]], or a root-level
    `hooks = ...` / `hooks.<event> = ...` before the first table. The [hooks.state."..."] trust entries are not hooks,
    and a `hooks` key inside another table (a feature flag) is not one either."""
    first = TOML_TABLE.search(text)
    head = text[:first.start()] if first else text
    return bool(TOML_HOOK_TABLE.search(text) or TOML_HOOK_KEY.search(head))


def check_user_config(home):
    conf = home / "config.toml"
    if not os.path.lexists(str(conf)):
        return None
    try:
        text = read_capped(conf, MAX_HOOKS_BYTES).decode("utf-8", "replace")
    except OSError as e:
        return "config.toml unreadable: %s" % e
    if toml_has_hooks(text):
        return "config.toml defines hooks; only ~/.codex/hooks.json hooks are vetted, so remove them"
    return None


def check_plugins(home):
    """Plugin hooks are force-trusted by the bypass flag too: no plugin may carry command hooks, and only the
    vendor caches (plugins/cache/openai-*) may carry hooks at all."""
    base = home / "plugins"
    if not base.is_dir():
        return None
    seen = 0
    for dirpath, dirnames, filenames in os.walk(str(base), followlinks=False):
        depth = len(Path(dirpath).relative_to(base).parts)
        if depth >= 7:
            dirnames[:] = []
        rel = Path(dirpath).relative_to(base).parts
        vendor = len(rel) >= 2 and rel[0] == "cache" and rel[1].startswith("openai-")
        if "hooks" in dirnames and not vendor:
            return "plugin hooks directory %s" % (Path(dirpath) / "hooks")
        for fn in filenames:
            if fn not in ("plugin.json", "hooks.json"):
                continue
            seen += 1
            if seen > 2000:
                return "too many plugin manifests to vet under %s" % base
            p = Path(dirpath) / fn
            try:
                data = _load_json_bytes(read_capped(p, MAX_HOOKS_BYTES), str(p))
                hooks = data.get("hooks") if (fn == "plugin.json" and isinstance(data, dict)) else data
                if not hooks:
                    continue
                if not vendor:
                    return "plugin hooks in %s" % p
                types = _json_strings_under(hooks, "type")
                if "command" in types or _json_strings_under(hooks, "command"):
                    return "plugin command hook in %s" % p
            except (OSError, ValueError) as e:
                return "plugin manifest unreadable: %s (%s)" % (p, e)
    return None


def check_project(project_dir, home):
    """Project-local hooks (which the owner could author) in DIR or any parent; the codex home itself is skipped."""
    if not project_dir:
        return None
    home_real = os.path.realpath(str(home))
    cur = Path(os.path.realpath(str(project_dir)))
    for d in [cur] + list(cur.parents):
        dot = d / ".codex"
        if os.path.realpath(str(dot)) == home_real or not os.path.lexists(str(dot)):
            continue
        if os.path.lexists(str(dot / "hooks.json")) or os.path.lexists(str(dot / "hooks")):
            return "project-local hooks in %s" % dot
        conf = dot / "config.toml"
        if os.path.lexists(str(conf)):
            try:
                if toml_has_hooks(read_capped(conf, MAX_HOOKS_BYTES).decode("utf-8", "replace")):
                    return "project-local hooks table in %s" % conf
            except OSError as e:
                return "project config unreadable: %s (%s)" % (conf, e)
    return None


def load_manifest(hdir):
    """{file name: sha256} from install-manifest.json, or a reason string."""
    path = hdir / "install-manifest.json"
    bad = _unsafe(path, False)
    if bad:
        return "install manifest: %s; re-run install_codex.py --apply" % bad
    try:
        data = _load_json_bytes(read_capped(path, MAX_HOOKS_BYTES), "install manifest")
    except (OSError, ValueError) as e:
        return "install manifest unreadable (%s); re-run install_codex.py --apply" % e
    files = data.get("files") if isinstance(data, dict) else None
    if not isinstance(files, dict) or not all(isinstance(k, str) and "/" not in k and isinstance(v, str)
                                              for k, v in files.items()):
        return "install manifest has no valid files object; re-run install_codex.py --apply"
    return files


def vet_hooks(strict=False, project_dir=None):
    """Return (ok, reason). See the module docstring for the rules."""
    home = codex_home()
    path = home / "hooks.json"
    hdir = home / "agent-harness"
    for p, is_dir in ((home, True), (path, False), (hdir, True)):
        bad = _unsafe(p, is_dir)
        if bad:
            return False, bad
    try:
        data = _load_json_bytes(read_capped(path, MAX_HOOKS_BYTES), "hooks.json")
        cmds = _json_strings_under(data, "command")
    except (OSError, ValueError) as e:
        return False, "hooks.json unreadable: %s" % e
    if not cmds:
        return False, "no hook commands"
    pattern = hook_command_re(home)
    files = set()
    for c in cmds:
        m = pattern.fullmatch(c) if isinstance(c, str) else None
        if not m:
            return False, "unexpected hook command: %r" % (c[:200] if isinstance(c, str) else type(c).__name__)
        files.add(Path(m.group(1)))
    for f in sorted(files):
        bad = _unsafe(f, False, "hook file")
        if bad:
            return False, bad
    for check in (check_interpreter, lambda: check_user_config(home), lambda: check_plugins(home),
                  lambda: check_project(project_dir, home)):
        bad = check()
        if bad:
            return False, bad
    if strict:
        manifest = load_manifest(hdir)
        if isinstance(manifest, str):
            return False, manifest
        for name in sorted(manifest):
            f = hdir / name
            bad = _unsafe(f, False)
            if bad:
                return False, "strict vet: " + bad
            try:
                if _sha256_file(f) != manifest[name]:
                    return False, ("strict vet: %s differs from the install manifest (re-run install_codex.py --apply)"
                                   % name)
            except OSError as e:
                return False, "strict vet: %s unreadable (%s)" % (name, e)
        for f in files:
            if f.name not in manifest:
                return False, "strict vet: hook file %s is not in the install manifest" % f.name
        try:
            extra = sorted(e for e in os.listdir(str(hdir)) if e.endswith(".py") and e not in manifest)
        except OSError as e:
            return False, "strict vet: cannot list %s (%s)" % (hdir, e)
        if extra:
            return False, "strict vet: unexpected .py files not in the install manifest: %s" % ",".join(extra[:10])
    drift = []
    for f in sorted(files):
        ref = Path.home() / ".claude" / "hooks" / f.name
        try:
            if _sha256_file(ref) != _sha256_file(f):
                drift.append(f.name)
        except OSError:
            drift.append(f.name)
    msg = "%d hook commands vetted%s" % (len(cmds), " (strict)" if strict else "")
    if drift:
        msg += "; WARNING stale vs ~/.claude/hooks: %s (re-run install_codex.py)" % ",".join(sorted(set(drift)))
    return True, msg


def hook_fingerprint():
    """{path: digest-ish} for hooks.json, the manifest and every top-level .py/.json in the harness dir. Never raises."""
    home = codex_home()
    hdir = home / "agent-harness"
    paths = [home / "hooks.json", hdir / "install-manifest.json"]
    try:
        paths += sorted(hdir / e for e in os.listdir(str(hdir)) if e.endswith((".py", ".json")))
    except OSError:
        paths.append(hdir)
    out = {}
    for p in paths:
        try:
            s = _lstat(p)
            if stat.S_ISLNK(s.st_mode):
                out[str(p)] = "symlink:" + os.readlink(str(p))
            elif not stat.S_ISREG(s.st_mode):
                out[str(p)] = "not-a-file"
            else:
                out[str(p)] = "%s:%o:%d:%d" % (_sha256_file(p), s.st_mode, s.st_uid, s.st_nlink)
        except FileNotFoundError:
            out[str(p)] = "missing"
        except OSError as e:
            out[str(p)] = "unreadable:%s" % (e.strerror or e)
    return out


# ---------------------------------------------------------------- config validation

def _inside(child, parent):
    try:
        Path(child).relative_to(parent)
        return True
    except ValueError:
        return False


def forbidden_dir(path):
    """Reason when a writable dir is $HOME, /, a dot-dir or ~/Library under $HOME, or exposes the codex home."""
    real = Path(os.path.realpath(str(path)))
    home = Path(os.path.realpath(str(Path.home())))
    chome = Path(os.path.realpath(str(codex_home())))
    if real == home or real == Path("/"):
        return "%s is the home or root directory" % path
    if _inside(chome, real) or _inside(real, chome):
        return "%s would expose the codex home %s" % (path, chome)
    if _inside(real, home):
        first = real.relative_to(home).parts[0]
        if first.startswith(".") or first == "Library":
            return "%s is inside %s" % (path, home / first)
    return None


def owner_dirs(name, sess):
    """Each owner's own WAL and work directories (never the session-wide ones)."""
    return (Path.home() / ".claude" / "wals" / sess / ("codex-" + name),
            Path.home() / ".agent-harness" / "work" / sess / ("codex-" + name))


def validate_config(cfg):
    """None when cfg is safe to run, else a reason. Called by `start` and again when a supervisor loads it."""
    if not valid_name(cfg.get("name")):
        return "invalid name"
    for key in ("model", "effort"):
        if not (isinstance(cfg.get(key), str) and TOKEN_RE.fullmatch(cfg[key])):
            return "invalid %s" % key
    if not isinstance(cfg.get("dir"), str) or not os.path.isabs(cfg["dir"]):
        return "invalid dir"
    if not isinstance(cfg.get("max_auto"), int) or isinstance(cfg["max_auto"], bool) or not 0 <= cfg["max_auto"] <= 1000:
        return "max_auto must be an integer from 0 to 1000"
    if cfg.get("strict_vet") not in (None, True, False) or not isinstance(cfg.get("yolo"), bool):
        return "invalid strict_vet or yolo"
    for key in ("add_dirs", "env", "secret_env"):
        if not isinstance(cfg.get(key), list) or not all(isinstance(x, str) for x in cfg[key]):
            return "invalid %s" % key
    for key in ("wal_dir", "work_dir"):
        if not isinstance(cfg.get(key), str) or not os.path.isabs(cfg[key]):
            return "invalid %s" % key
    for n in cfg["env"]:
        if not ENV_NAME_RE.fullmatch(n) or n == "PATH":
            return "invalid --env name %r" % n
        if ENV_NEVER.fullmatch(n):
            return "--env %s is never passed to an owner" % n
        if ENV_SECRETISH.fullmatch(n) and n not in cfg["secret_env"]:
            return "--env %s looks like a secret; pass --allow-secret-env %s to allow it explicitly" % (n, n)
    if not cfg["yolo"]:
        bad = forbidden_dir(cfg["dir"])
        if bad:
            return "dir: " + bad
        roots = [os.path.realpath(x) for x in (cfg["dir"], cfg["wal_dir"], cfg["work_dir"])]
        for extra in cfg["add_dirs"]:
            real = os.path.realpath(extra)
            if not any(_inside(real, r) for r in roots):
                return "--add-dir %s is outside the repo and the owner's own WAL/work dirs" % extra
            bad = forbidden_dir(extra) if not any(_inside(real, r) for r in roots[1:]) else None
            if bad:
                return "--add-dir: " + bad
    return None


# ---------------------------------------------------------------- inbox

def key_path():
    return root() / ".key"


def load_key(create=False):
    p = key_path()
    if create and not os.path.lexists(str(p)):
        root().mkdir(parents=True, exist_ok=True)
        try:
            fd = os.open(str(p), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write(secrets.token_hex(32))
        except FileExistsError:
            pass
    try:
        s = _lstat(p)
        if not stat.S_ISREG(s.st_mode) or s.st_uid != os.getuid() or s.st_mode & 0o077:
            raise StateError("%s must be a 0600 file owned by this user" % p)
        key = read_capped(p, 1024).strip()
    except OSError as e:
        raise StateError("message key unreadable (%s)" % e)
    if len(key) < 32:
        raise StateError("message key %s is too short" % p)
    return key


def sign(key, msg):
    body = json.dumps({k: msg[k] for k in ("id", "from", "text", "ts", "nonce")}, sort_keys=True,
                      separators=(",", ":"), ensure_ascii=True)
    return hmac.new(key, body.encode(), hashlib.sha256).hexdigest()


class Inbox:
    """Delivers each verified message once. Unverified files are renamed *.rejected and counted."""

    def __init__(self, name, key, nonces):
        self.name, self.key = name, key
        self.nonces = list(nonces)[-MAX_NONCES:]
        self.seen = set(self.nonces)
        self.rejected = 0
        self.forgeries = 0

    def _reject(self, path, why, forgery=False):
        self.rejected += 1
        self.forgeries += bool(forgery)
        log_line(self.name, "inbox: rejected %s (%s)" % (path.name, why))
        try:
            os.rename(str(path), str(path) + ".rejected")
        except OSError:
            pass

    def take(self):
        d = odir(self.name) / "inbox"
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
                self._reject(p, "unreadable: %s" % (e.strerror or e))
                continue
            except (ValueError, RecursionError):
                self._reject(p, "malformed JSON")
                continue
            if not (isinstance(m, dict) and m.get("from") in ("user", "main") and isinstance(m.get("text"), str)
                    and m["text"].strip() and len(m["text"]) <= MAX_TEXT and isinstance(m.get("id"), str)
                    and isinstance(m.get("nonce"), str) and isinstance(m.get("ts"), int)
                    and isinstance(m.get("mac"), str)):
                self._reject(p, "not a signed message", forgery=True)
                continue
            if not hmac.compare_digest(sign(self.key, m), m["mac"]):
                self._reject(p, "bad signature", forgery=True)
                continue
            age = time.time() - m["ts"]
            if m["nonce"] in self.seen or age > MAX_MSG_AGE or age < -300:
                self._reject(p, "replayed or stale", forgery=True)
                continue
            try:
                os.rename(str(p), str(p) + ".read")
            except OSError:
                continue
            self.seen.add(m["nonce"])
            self.nonces.append(m["nonce"])
            msgs.append({"at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(m["ts"])), "from": m["from"],
                         "text": m["text"], "id": m["id"]})
        if msgs:
            self.nonces = self.nonces[-MAX_NONCES:]
            write_json(cdir(self.name) / "nonces.json", {"nonces": self.nonces})
        return msgs


def parse_status(text):
    for line in reversed((text or "").strip().splitlines()):
        line = line.strip().upper()
        if line.startswith("STATUS:"):
            rest = line.split(":", 1)[1].strip()
            word = rest.split()[0] if rest else ""
            return word if word in STATUSES else "WORKING"
    return "WORKING"


# ---------------------------------------------------------------- turns

def build_argv(cfg, thread):
    """argv for one vetted turn. `codex exec resume` rejects -s and --add-dir, so resumes never carry them."""
    flags = ["--json", "--skip-git-repo-check", "-m", cfg["model"], "-c", 'model_reasoning_effort="%s"' % cfg["effort"]]
    if cfg["yolo"]:
        flags.append(YOLO_FLAG)
    elif not thread:
        flags += ["-s", "workspace-write", "-c", "sandbox_workspace_write.network_access=true",
                  "--add-dir", cfg["wal_dir"], "--add-dir", cfg["work_dir"]]
        for extra in cfg["add_dirs"]:
            flags += ["--add-dir", extra]
    flags.append(TRUST_FLAG)
    if thread:
        return [codex_bin(), "exec", "resume"] + flags + [thread, "-"]
    return [codex_bin(), "exec"] + flags + ["-C", cfg["dir"], "-"]


def child_env(cfg):
    env = {k: os.environ[k] for k in ENV_ALLOW if k in os.environ}
    env.update({k: v for k, v in os.environ.items() if k.startswith("LC_")})
    for n in cfg["env"]:
        if n in os.environ and not ENV_NEVER.fullmatch(n):
            env[n] = os.environ[n]
    env["PATH"] = safe_path()
    return env


class Supervisor:
    def __init__(self, name):
        self.name = name
        self.d = odir(name)
        self.c = cdir(name)
        self.stop = threading.Event()
        self.child = None
        self.lock_fd = None
        self.lock_id = None
        self.alert = None

    # -- control
    def acquire(self):
        self.c.mkdir(parents=True, exist_ok=True)
        os.chmod(str(self.c), 0o700)
        fd = os.open(str(self.c / "supervisor.lock"), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            os.close(fd)
            return False
        s = os.fstat(fd)
        self.lock_fd, self.lock_id = fd, (s.st_dev, s.st_ino)
        return True

    def lock_intact(self):
        try:
            s = os.lstat(str(self.c / "supervisor.lock"))
        except OSError:
            return False
        return (s.st_dev, s.st_ino) == self.lock_id

    def kill_child(self, why):
        p = self.child
        if p is None or p.poll() is not None:
            return
        log_line(self.name, "terminating codex child pid %d (%s)" % (p.pid, why))
        try:
            os.killpg(p.pid, signal.SIGTERM)
        except OSError:
            pass

        def reaper():
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(p.pid, signal.SIGKILL)
                except OSError:
                    pass
        threading.Thread(target=reaper, daemon=True).start()

    def watch(self):
        """Latches STOP (an owner deleting the file later cannot undo it) and the lock inode check."""
        while not self.stop.is_set():
            if (self.c / "STOP").exists():
                log_line(self.name, "STOP seen; stopping after the current turn")
                self.stop.set()
            elif not self.lock_intact():
                log_line(self.name, "ALERT supervisor.lock was replaced or removed; stopping and terminating the turn")
                self.stop.set()
                self.kill_child("lock replaced")
            time.sleep(0.2)

    def on_signal(self, signum, _frame):
        self.stop.set()
        self.kill_child("signal %d" % signum)

    # -- state
    def publish(self, **fields):
        self.status.update(fields)
        self.status.update(inbox_rejected=self.inbox.rejected, inbox_forgery_attempts=self.inbox.forgeries,
                           alert=self.alert, yolo=self.cfg["yolo"])
        try:
            write_json(self.d / "status.json", self.status)
        except OSError as e:
            log_line(self.name, "cannot write status.json (%s)" % e)

    def save_state(self):
        write_json(self.c / "state.json", {"thread": self.thread, "turns": self.turns, "last_status": self.last_status})

    def block(self, why):
        self.last_status = "BLOCKED"
        self.save_state()
        append(self.d / "outbox.jsonl", {"at": now(), "turn": self.turns + 1, "rc": -1, "status": "BLOCKED",
                                         "text": why})
        log_line(self.name, why)
        self.publish(state="blocked", last_status="BLOCKED", last_reply=why, child_pid=None)
        return "BLOCKED", -1

    def raise_alert(self, reason, detail):
        self.alert = {"at": now(), "reason": reason, "detail": detail[:20]}
        log_line(self.name, "ALERT %s: %s" % (reason, json.dumps(detail[:20])))
        return self.block("%s: %s" % (reason, ", ".join(detail[:5])))

    def run_turn(self, prompt):
        if self.alert:
            return self.block("refusing turn: unresolved alert (%s); inspect the hooks, then `codex_owner.py restart %s`"
                              % (self.alert["reason"], self.name))
        strict, warning = strict_mode(self.cfg["strict_vet"])
        if warning:
            log_line(self.name, warning)
        ok, why = vet_hooks(strict, self.cfg["dir"])
        self.publish(hooks_vetted=ok, hooks_vet_reason=why, vet_warning=warning, strict_vet=strict)
        if not ok:
            # Never run an owner turn without the harness guards: no child, and so neither bypass flag.
            return self.block("harness hooks failed vetting: " + why)
        before = hook_fingerprint()
        turn = self.turns + 1
        cmd = build_argv(self.cfg, self.thread)
        self.turns = turn
        self.save_state()
        self.publish(state="running", turn_started=now(), turns=turn)
        last, usage, rc = "", None, None
        with open(self.d / "turns" / ("%04d.jsonl" % turn), "w") as f, open(self.d / "supervisor.log", "a") as err:
            try:
                self.child = subprocess.Popen(cmd, cwd=self.cfg["dir"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                              stderr=err, env=child_env(self.cfg), text=True, start_new_session=True)
            except OSError as e:
                log_line(self.name, "cannot launch codex: %s" % e)
                rc = 127
            if rc is None:
                p = self.child
                self.publish(child_pid=p.pid)
                try:
                    p.stdin.write(prompt)
                    p.stdin.close()
                except BrokenPipeError:
                    pass
                for line in p.stdout:
                    f.write(line)
                    try:
                        ev = json.loads(line)
                    except (ValueError, RecursionError):
                        continue
                    if not isinstance(ev, dict):
                        continue
                    if ev.get("type") == "thread.started" and not self.thread:
                        tid = ev.get("thread_id")
                        if isinstance(tid, str) and TOKEN_RE.fullmatch(tid):
                            self.thread = tid
                            self.save_state()
                            self.publish(thread=tid)
                    elif ev.get("type") == "item.completed":
                        it = ev.get("item") if isinstance(ev.get("item"), dict) else {}
                        if it.get("type") == "agent_message" and isinstance(it.get("text"), str):
                            last = it["text"]
                        self.publish(last_activity=now(), last_item=it.get("type"))
                    elif ev.get("type") == "turn.completed":
                        usage = ev.get("usage")
                rc = p.wait()
        self.child = None
        status = parse_status(last) if rc == 0 else "ERROR"
        append(self.d / "outbox.jsonl", {"at": now(), "turn": turn, "rc": rc, "status": status, "text": last,
                                         "usage": usage})
        self.last_status = status
        self.save_state()
        self.publish(state="idle", child_pid=None, last_reply=last[-2000:], last_status=status, last_rc=rc,
                     turn_ended=now())
        after = hook_fingerprint()
        changed = sorted(k for k in set(before) | set(after) if before.get(k) != after.get(k))
        if changed:
            return self.raise_alert("hooks changed during the turn", changed)
        ok, why = vet_hooks(strict, self.cfg["dir"])
        if not ok:
            return self.raise_alert("hooks changed during the turn", [why])
        return status, rc

    # -- main loop
    def run(self):
        if not self.acquire():
            print("owner %s already has a running supervisor; refusing a second one" % self.name, file=sys.stderr)
            return 3
        try:
            return self._run()
        except StateError as e:
            msg = "supervisor exiting: %s; fix or remove it, then `codex_owner.py start %s ...`" % (e, self.name)
            log_line(self.name, msg)
            print(msg, file=sys.stderr)
            return 2
        finally:
            self.kill_child("supervisor exiting")
            os.close(self.lock_fd)

    def _run(self):
        cfg = read_json(self.c / "config.json")
        if cfg is None:
            raise StateError("%s is missing (run `start`)" % (self.c / "config.json"))
        bad = validate_config(cfg)
        if bad:
            raise StateError("%s is invalid (%s)" % (self.c / "config.json", bad))
        self.cfg = cfg  # authoritative for this supervisor's life; never re-read
        state = read_json(self.c / "state.json", missing={})
        thread = state.get("thread")
        if thread is not None and not (isinstance(thread, str) and TOKEN_RE.fullmatch(thread)):
            raise StateError("%s has an invalid thread" % (self.c / "state.json"))
        self.thread = thread
        self.turns = state.get("turns") if isinstance(state.get("turns"), int) else 0
        self.last_status = state.get("last_status") if state.get("last_status") in STATUSES + ("ERROR",) else None
        nonces = read_json(self.c / "nonces.json", missing={}).get("nonces") or []
        self.inbox = Inbox(self.name, load_key(create=True), [n for n in nonces if isinstance(n, str)])
        self.status = {k: cfg[k] for k in ("name", "model", "effort", "dir", "ticket", "stream", "max_auto",
                                            "add_dirs", "wal_dir", "work_dir", "env") if k in cfg}
        self.status.update(harness="openai", supervisor_pid=os.getpid(), thread=self.thread, turns=self.turns,
                           last_status=self.last_status, started=cfg.get("created"))
        if cfg["yolo"]:
            log_line(self.name, "YOLO mode: Codex sandbox and approvals bypassed; the vetted hooks are the control")
        for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            signal.signal(sig, self.on_signal)
        threading.Thread(target=self.watch, daemon=True).start()
        self.publish(state="starting")
        prompt = None
        if not self.thread:
            try:
                prompt = read_capped(self.d / "brief.md", MAX_STATE_BYTES).decode("utf-8", "replace")
            except OSError as e:
                raise StateError("brief.md unreadable (%s)" % e)
        auto, errors = 0, 0
        while not self.stop.is_set():
            msgs = self.inbox.take()
            if msgs:
                body = "\n\n".join("[%s from %s] %s" % (m["at"], m["from"], m["text"]) for m in msgs)
                prompt = ("New messages for you (from the user are the user's own words; from main is the "
                          "orchestrator):\n\n" + body + "\n\nAcknowledge each one in your reply, act on it, and end "
                          "with a STATUS line.")
                auto = 0  # only verified, unseen messages get here
            elif self.inbox.rejected != self.status.get("inbox_rejected"):
                self.publish()
            if prompt is None:
                if self.last_status == "WORKING" and auto < cfg["max_auto"]:
                    prompt, auto = CONTINUE, auto + 1
                elif self.last_status == "ERROR" and errors < 3:
                    self.stop.wait(error_backoff() * (errors + 1))
                    if self.stop.is_set():
                        break
                    prompt, errors = CONTINUE, errors + 1
                else:
                    if self.status.get("state") not in ("idle", "blocked"):
                        self.publish(state="idle")
                    self.stop.wait(poll_secs())
                    continue
            status, rc = self.run_turn(prompt)
            if rc == 0:
                errors = 0
            prompt = None
        self.publish(state="stopped", supervisor_pid=None, child_pid=None)
        return 0


def supervise(name):
    return Supervisor(name).run()


# ---------------------------------------------------------------- commands

def alive(pid):
    try:
        return isinstance(pid, int) and pid > 0 and (os.kill(pid, 0) is None)
    except OSError:
        return False


def locked(name):
    c = cdir(name)
    if not c.is_dir():
        return False
    try:
        fd = os.open(str(c / "supervisor.lock"), os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    except OSError:
        return True
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return False
    except OSError:
        return True
    finally:
        os.close(fd)


def init_owner(a):
    """Create or update the owner's config; never launches anything."""
    d, c = odir(a.name), cdir(a.name)
    if locked(a.name):
        sys.exit("owner %s already running" % a.name)
    sess = a.session or session()
    wal_dir, work_dir = owner_dirs(a.name, sess)
    cfg = {"name": a.name, "harness": "openai", "model": a.model, "effort": a.effort, "dir": os.path.abspath(a.dir),
           "ticket": a.ticket, "stream": a.stream, "max_auto": a.max_auto,
           "add_dirs": [os.path.abspath(x) for x in a.add_dir], "session": sess, "wal_dir": str(wal_dir),
           "work_dir": str(work_dir), "strict_vet": a.strict_vet, "yolo": not a.no_yolo, "env": list(a.env),
           "secret_env": list(a.allow_secret_env), "created": now()}
    bad = validate_config(cfg)
    if bad:
        sys.exit("refusing to start: " + bad)
    bad = check_project(cfg["dir"], codex_home())
    if bad:
        sys.exit("refusing to start: " + bad)
    for sub in (d / "inbox", d / "turns", c, wal_dir, work_dir):
        sub.mkdir(parents=True, exist_ok=True)
    for p in (d, c, root() / ".control", wal_dir, work_dir):
        os.chmod(str(p), 0o700)
    shutil.copyfile(a.brief, str(d / "brief.md"))
    try:
        state = read_json(c / "state.json")
    except StateError as e:
        sys.exit(str(e))
    if state is None:
        # One-time adoption of an owner started by the earlier supervisor: keep its thread.
        try:
            legacy = read_json(d / "status.json") or {}
        except StateError:
            legacy = {}
        thread = legacy.get("thread")
        state = {"thread": thread if isinstance(thread, str) and TOKEN_RE.fullmatch(thread) else None,
                 "turns": legacy.get("turns") if isinstance(legacy.get("turns"), int) else 0, "last_status": None}
        write_json(c / "state.json", state)
    write_json(c / "config.json", cfg)
    for n in cfg["secret_env"]:
        log_line(a.name, "secret-looking env name allowed by the operator: %s" % n)
    try:
        (c / "STOP").unlink()
    except FileNotFoundError:
        pass
    load_key(create=True)
    return d


def spawn(name):
    d = odir(name)
    with open(d / "supervisor.log", "a") as log:
        return subprocess.Popen([sys.executable, os.path.abspath(__file__), "_run", name], stdout=log, stderr=log,
                                stdin=subprocess.DEVNULL, start_new_session=True)


def cmd_start(a):
    d = init_owner(a)
    p = spawn(a.name)
    print("STARTED %s pid=%d dir=%s yolo=%s" % (a.name, p.pid, d, not a.no_yolo))


def cmd_send(a):
    d = odir(a.name)
    if not (cdir(a.name) / "config.json").is_file():
        sys.exit("no such owner")
    text = sys.stdin.read(MAX_TEXT + 1) if a.text == "-" else a.text
    if not text.strip() or len(text) > MAX_TEXT:
        sys.exit("empty or too long (limit %d characters)" % MAX_TEXT)
    try:
        key = load_key(create=True)
    except StateError as e:
        sys.exit(str(e))
    mid = "%s-%s" % (time.strftime("%Y%m%dT%H%M%S"), secrets.token_hex(3))
    msg = {"id": mid, "from": a.sender, "text": text, "ts": int(time.time()), "nonce": secrets.token_hex(16)}
    msg["mac"] = sign(key, msg)
    tmp = d / "inbox" / (mid + ".tmp")
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(json.dumps(msg))
    os.replace(str(tmp), str(d / "inbox" / (mid + ".json")))
    print("QUEUED %s %s" % (a.name, mid))


def cmd_status(a):
    rows = []
    if a.name:
        odir(a.name)
        names = [a.name]
    else:
        base = root() / ".control"
        names = sorted(p.name for p in base.iterdir() if valid_name(p.name)) if base.is_dir() else []
    for n in names:
        try:
            st = read_json(odir(n) / "status.json") or {"name": n, "state": "new"}
        except StateError as e:
            st = {"name": n, "state": "CORRUPT", "error": str(e)}
        st["supervisor_alive"] = locked(n)
        try:
            st["pending_inbox"] = len([e for e in os.listdir(str(odir(n) / "inbox")) if e.endswith(".json")])
        except OSError:
            st["pending_inbox"] = 0
        rows.append(st)
    if a.json:
        print(json.dumps(rows, indent=1))
        return
    for st in rows:
        print("%-16s %-7s %-10s sup=%s yolo=%s turns=%s status=%s last=%s ticket=%s" % (
            st.get("name"), st.get("harness"), st.get("state"), "up" if st["supervisor_alive"] else "DOWN",
            st.get("yolo"), st.get("turns"), st.get("last_status"), st.get("last_activity") or st.get("turn_ended"),
            st.get("ticket")))
        if st.get("alert"):
            print("    ALERT " + json.dumps(st["alert"])[:300])
        if st.get("inbox_forgery_attempts"):
            print("    inbox forgery attempts: %s" % st["inbox_forgery_attempts"])
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
    """Stop after the current turn, wait for the supervisor to exit, then start it again from config.json."""
    c = cdir(a.name)
    if not (c / "config.json").is_file():
        sys.exit("no config for %s: use `start` (it adopts an earlier owner's thread)" % a.name)
    (c / "STOP").write_text(now())
    while locked(a.name):
        time.sleep(min(10.0, max(0.1, poll_secs())))
    (c / "STOP").unlink()
    p = spawn(a.name)
    print("RESTARTED %s pid=%d" % (a.name, p.pid))


def cmd_vet(a):
    strict, warning = strict_mode(a.strict_vet)
    if warning:
        print(warning, file=sys.stderr)
    ok, why = vet_hooks(strict, a.dir)
    print(("OK " if ok else "FAIL ") + why)
    sys.exit(0 if ok else 1)


def cmd_stop(a):
    c = cdir(a.name)
    if not c.is_dir():
        sys.exit("no such owner")
    (c / "STOP").write_text(now())
    print("STOP requested for %s (takes effect after the current turn)" % a.name)


def _strict_flags(p):
    g = p.add_mutually_exclusive_group()
    g.add_argument("--strict-vet", dest="strict_vet", action="store_const", const=True, default=None,
                   help="always compare harness files with install-manifest.json")
    g.add_argument("--no-strict-vet", dest="strict_vet", action="store_const", const=False,
                   help="opt out of the strict vet (a loud warning every turn)")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sp = ap.add_subparsers(dest="cmd", required=True)
    s = sp.add_parser("start"); s.add_argument("name"); s.add_argument("--dir", required=True)
    s.add_argument("--brief", required=True); s.add_argument("--ticket", default=""); s.add_argument("--stream", default="")
    s.add_argument("--model", default="gpt-6.1-sol"); s.add_argument("--effort", default="high")
    s.add_argument("--max-auto-turns", "--max-auto", dest="max_auto", type=int, default=40)
    s.add_argument("--add-dir", action="append", default=[])
    s.add_argument("--session", default="", help="session id for the owner's WAL and work dirs")
    s.add_argument("--no-yolo", action="store_true", help="first turn in -s workspace-write instead of yolo mode")
    s.add_argument("--env", action="append", default=[], help="pass this environment variable to the owner")
    s.add_argument("--allow-secret-env", action="append", default=[], help="allow a secret-looking --env name")
    _strict_flags(s)
    s.set_defaults(f=cmd_start)
    s = sp.add_parser("send"); s.add_argument("name"); s.add_argument("--from", dest="sender", choices=["user", "main"], required=True)
    s.add_argument("--text", required=True); s.set_defaults(f=cmd_send)
    s = sp.add_parser("status"); s.add_argument("name", nargs="?"); s.add_argument("--json", action="store_true"); s.set_defaults(f=cmd_status)
    s = sp.add_parser("log"); s.add_argument("name"); s.add_argument("-n", type=int, default=3); s.set_defaults(f=cmd_log)
    s = sp.add_parser("stop"); s.add_argument("name"); s.set_defaults(f=cmd_stop)
    s = sp.add_parser("restart"); s.add_argument("name"); s.set_defaults(f=cmd_restart)
    s = sp.add_parser("vet"); s.add_argument("--dir", default=None); _strict_flags(s); s.set_defaults(f=cmd_vet)
    s = sp.add_parser("_run"); s.add_argument("name"); s.set_defaults(f=lambda a: sys.exit(supervise(a.name)))
    a = ap.parse_args(argv)
    root().mkdir(parents=True, exist_ok=True)
    a.f(a)


if __name__ == "__main__":
    main()
