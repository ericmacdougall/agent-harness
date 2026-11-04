"""Python front door for the Go port (plan 3.6, GoodQA #35674).

A ported helper calls dispatch() from its `if __name__ == "__main__":` block before running its own main.
It decides, with exactly the rules of internal/impl (driven by the same parity/switchfile/cases.json),
whether the Go binary serves this switch group, and if so execs it with the canonical grammar:

    harness --host H --config-dir <dir of the helper> --entry py:<abs helper path> <sub> *argv

Missing, invalid or unsafe state runs Python. A pin that cannot be honoured, or a dispatch that would
bounce back across a hop, is refused: hook surfaces exit 2 (Codex and Claude let a tool call through on
exit 1), CLI surfaces exit 1. Any unexpected error inside dispatch (a failed exec, an I/O error while
hashing) is refused the same way, never surfaced as a traceback exit 1. Nothing imports this module at
import time of a helper, so importing helpers never execs.
"""

import hashlib
import json
import os
import re
import stat
import sys

GO, PYTHON, REFUSE = "go", "python", "refuse"
PIN_ENV = "AGENT_HARNESS_IMPL_PIN"
DISPATCH_ENV = "AGENT_HARNESS_DISPATCHED"
MAX_FILE = 64 << 10
GROUPS = ("wal", "policy", "spec", "watch", "review", "rescue", "delivery", "install")
HEX_SHA = re.compile(r"[0-9a-f]{64}")
PIN = re.compile(r"([a-z]+):(go|python):([0-9a-f]{64}|-)")


def default_file():
    return os.path.join(os.path.expanduser("~"), ".agent-harness", "impl.json")


def _owner(info):
    return info.st_uid == os.geteuid()


def _reject_constant(name):
    raise ValueError(f"non-standard JSON constant {name}")  # NaN/Infinity: Go's encoding/json rejects them


def _open_regular(path):
    # O_NONBLOCK: a FIFO swapped in after lstat must not hang the hook (a hook timeout is fail-open).
    return os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)


def _safe_ancestors(path):
    """Every directory above path is owned by us or root and not group/other-writable unless sticky."""
    current = os.path.dirname(path)
    while True:
        try:
            info = os.stat(current)
        except OSError:
            return False
        mode = stat.S_IMODE(info.st_mode)
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid not in (0, os.geteuid())
                or (mode & 0o022 and not mode & stat.S_ISVTX)):
            return False
        parent = os.path.dirname(current)
        if parent == current:
            return True
        current = parent


def _load(path):
    """Return (data, state); state is "" or missing, unsafe, invalid."""
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return None, "missing"
    except OSError:
        return None, "unsafe"
    if not stat.S_ISREG(info.st_mode) or not _owner(info) or stat.S_IMODE(info.st_mode) & 0o077:
        return None, "unsafe"
    try:
        fd = _open_regular(path)
    except OSError:
        return None, "unsafe"
    with os.fdopen(fd, "rb") as handle:
        opened = os.fstat(handle.fileno())
        if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
            return None, "unsafe"
        raw = handle.read(MAX_FILE + 1)
    if len(raw) > MAX_FILE:
        return None, "invalid"
    try:
        data = json.loads(raw.decode("utf-8"), parse_constant=_reject_constant)
    except (ValueError, UnicodeDecodeError):
        return None, "invalid"
    if (not isinstance(data, dict) or data.get("schema") != 1 or type(data.get("schema")) is not int
            or not isinstance(data.get("groups"), dict) or not isinstance(data.get("hosts"), dict)):
        return None, "invalid"
    for group, value in data["groups"].items():
        if group not in GROUPS or value not in (GO, PYTHON):
            return None, "invalid"
    for entry in data["hosts"].values():
        if (not isinstance(entry, dict) or not isinstance(entry.get("binary"), str)
                or not os.path.isabs(entry["binary"]) or not isinstance(entry.get("sha256"), str)
                or not HEX_SHA.fullmatch(entry["sha256"])):
            return None, "invalid"
    return data, ""


def _verified_binary(data, host, launcher):
    """Return (binary, sha256, why); why is "", host or binary."""
    entry = data["hosts"].get(host)
    if entry is None:
        return None, None, "host"
    binary = entry["binary"]
    if binary != launcher:  # exact: normpath and filepath.Clean disagree on a leading "//"
        return None, None, "binary"
    try:
        info = os.lstat(binary)
        mode = stat.S_IMODE(info.st_mode)
        if (not stat.S_ISREG(info.st_mode) or not _owner(info) or mode & 0o022 or not mode & stat.S_IXUSR
                or not _safe_ancestors(binary)):
            return None, None, "binary"
        fd = _open_regular(binary)
    except OSError:
        return None, None, "binary"
    digest = hashlib.sha256()
    with os.fdopen(fd, "rb") as handle:
        opened = os.fstat(handle.fileno())
        if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
            return None, None, "binary"
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return binary, digest.hexdigest(), ""


def resolve(group, host, launcher, path=None, environ=None):
    """Return (impl, reason, binary, sha256) with the internal/impl rules."""
    environ = os.environ if environ is None else environ
    decision = _resolve(group, host, launcher, path or default_file(), environ)
    if decision[0] == GO and environ.get(DISPATCH_ENV):
        return REFUSE, "loop", None, None
    return decision


def _resolve(group, host, launcher, path, environ):
    data, state = _load(path)
    pin = environ.get(PIN_ENV)
    if pin:
        match = PIN.fullmatch(pin)
        if not match:
            return REFUSE, "pin", None, None
        if match.group(1) == group:
            if match.group(2) == PYTHON:
                return PYTHON, "pin", None, None
            if state:
                return REFUSE, "pin", None, None
            binary, actual, why = _verified_binary(data, host, launcher)
            if why or actual != match.group(3):
                return REFUSE, "pin", None, None
            return GO, "pin", binary, actual
    if state:
        return PYTHON, state, None, None
    if data["groups"].get(group) != GO:
        return PYTHON, "group", None, None
    binary, actual, why = _verified_binary(data, host, launcher)
    if why:
        return PYTHON, why, None, None
    if actual != data["hosts"][host]["sha256"]:
        return PYTHON, "sha", None, None
    return GO, "", binary, actual


def dispatch(group, host, launcher, helper, sub, argv, *, hook=False, on_fallback=None):
    """Exec Go when it serves this group; return normally to run Python; exit on refusal or error."""
    try:
        _dispatch(group, host, launcher, helper, sub, argv, hook, on_fallback)
    except SystemExit:
        raise
    except BaseException as error:  # noqa: BLE001 - a hook must never fail open on exit 1
        print(f"agent-harness: front door failed for {group} ({type(error).__name__}); "
              + ("refusing the action (fail-closed)" if hook else "aborting"), file=sys.stderr)
        sys.exit(2 if hook else 1)


def _dispatch(group, host, launcher, helper, sub, argv, hook, on_fallback):
    impl, reason, binary, _ = resolve(group, host, launcher)
    if impl == REFUSE:
        print(f"agent-harness: refusing to dispatch {group} ({reason}): "
              + ("harness dispatch loop" if reason == "loop" else "implementation pin cannot be honoured"),
              file=sys.stderr)
        sys.exit(2 if hook else 1)
    if impl == PYTHON:
        if reason not in ("group", "missing") and on_fallback is not None:
            on_fallback(reason)
        return
    helper = os.path.abspath(helper)
    env = dict(os.environ)
    env[DISPATCH_ENV] = "py->go"
    os.execve(binary, [binary, "--host", host, "--config-dir", os.path.dirname(helper),
                       "--entry", "py:" + helper, sub, *argv], env)
