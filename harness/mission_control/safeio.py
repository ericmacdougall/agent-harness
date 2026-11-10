"""The only ways Mission Control touches the outside world (GoodQA #15585 AC-8).

`Runner.run` executes a subprocess only when its argv matches one of a small set of read-only shapes.
`Reader` opens files only under configured roots, after resolving the real path, refusing symlinks and
credential locations. Everything else raises `Refused`. Tests patch these two classes to prove that.
"""

from __future__ import annotations

import os
import re
import shutil
import stat
import subprocess
from pathlib import Path

TICKET_RE = re.compile(r"^(?:GoodQA )?[a-z0-9][a-z0-9-]{0,39}#[0-9]{1,7}$")
LOGIN_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$")
CURSOR_RE = re.compile(r"^[A-Za-z0-9._:=-]{0,128}$")
SESSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{7,63}$")
SAFE_ENV = ("PATH", "HOME", "USER", "LOGNAME", "LANG", "LC_ALL", "TMPDIR", "SSH_AUTH_SOCK", "GH_CONFIG_DIR",
            "XDG_CONFIG_HOME")
SECRET_ENV = re.compile(r"(?i)(TOKEN|KEY|SECRET|PASSWORD|PASSWD|CREDENTIAL|COOKIE|AUTH)")
DENY_PARTS = (".ssh", ".gnupg", "Keychains", ".kimi-code", ".aws", ".netrc", ".docker", ".kube")
DENY_NAMES = ("auth.json", "credentials", "credentials.json", ".netrc", "id_rsa", "id_ed25519", "secret")


class Refused(PermissionError):
    pass


def scrubbed_env(extra: dict | None = None) -> dict:
    """A minimal environment: no variable whose name suggests a credential reaches a child."""
    env = {k: v for k, v in os.environ.items() if k in SAFE_ENV and not SECRET_ENV.search(k)}
    env.setdefault("PATH", "/usr/bin:/bin:/usr/sbin:/sbin:/opt/homebrew/bin:/usr/local/bin")
    for key, value in (extra or {}).items():
        if SECRET_ENV.search(key):
            raise Refused(f"refusing to pass {key} to a child process")
        env[key] = value
    return env


class Runner:
    """Allowlisted, read-only subprocess runner with timeouts and output caps."""

    def __init__(self, *, python: str, ah: str, gh: str | None = None, ssh: str = "/usr/bin/ssh",
                 codex: str | None = None, remote_host: str = "t2-dev", fabric_bin: str | None = None):
        self.python, self.ah = python, ah
        self.gh = gh or shutil.which("gh") or "/opt/homebrew/bin/gh"
        self.ssh, self.codex, self.remote_host, self.fabric_bin = ssh, codex, remote_host, fabric_bin

    # Each shape returns the argv or raises Refused. Arguments are validated before they are placed.
    def argv(self, kind: str, *args) -> list[str]:
        if kind == "ah-owners" and not args:
            return [self.python, "-I", self.ah, "owners"]
        if kind == "ah-sessions" and not args:
            return [self.python, "-I", self.ah, "sessions"]
        if kind == "ah-ticket-comments" and len(args) == 1 and TICKET_RE.match(str(args[0])):
            return [self.python, "-I", self.ah, "ticket", "comments", str(args[0])]
        if kind == "provenance-asks" and len(args) == 1 and SESSION_RE.match(str(args[0])):
            # read-only: the open asks of one session, as data (the "Needs you" list)
            return [self.python, "-I", str(Path(self.ah).with_name("provenance.py")), "asks", "--session", str(args[0]),
                    "--json", "--items"]
        if kind == "gh-user" and not args:
            return [self.gh, "api", "user", "--method", "GET"]
        if kind == "gh-events" and len(args) == 1 and LOGIN_RE.match(str(args[0])):
            return [self.gh, "api", "--method", "GET", f"/users/{args[0]}/events?per_page=30"]
        if kind == "remote-wal-probe" and not args:
            # one fixed read command: the newest WAL lines modified in the last 2 minutes, at most 64 KiB
            script = ("find ~/.claude/wals -maxdepth 2 -name '*.jsonl' -mmin -2 -type f 2>/dev/null | head -50 | "
                      "while read f; do printf '%s\\t' \"$f\"; tail -n 3 \"$f\" | tr '\\n' '\\036'; echo; done | "
                      "head -c 65536")
            return [self.ssh, "-o", "BatchMode=yes", "-o", "ConnectTimeout=5", "-a", "-x", "-T",
                    self.remote_host, script]
        if kind == "fabric-export" and len(args) == 1 and self.fabric_bin and CURSOR_RE.match(str(args[0])):
            return [self.ssh, "-o", "BatchMode=yes", "-o", "ConnectTimeout=5", "-a", "-x", "-T", self.remote_host,
                    f"{self.fabric_bin} control export --since {args[0] or '0'}"]
        if kind == "codex-login-status" and not args and self.codex:
            return [self.codex, "login", "status"]
        if kind == "codex-pool-status" and not args:
            return [self.python, "-I", str(Path(self.ah).with_name("codex_pool.py")), "status"]
        raise Refused(f"subprocess shape {kind!r} with {len(args)} argument(s) is not allowlisted")

    def run(self, kind: str, *args, timeout: float = 20.0, limit: int = 4 * 1024 * 1024) -> tuple[int, str]:
        argv = self.argv(kind, *args)
        try:
            proc = subprocess.run(argv, capture_output=True, timeout=timeout, env=scrubbed_env(),
                                  stdin=subprocess.DEVNULL, cwd="/")
        except subprocess.TimeoutExpired:
            return 124, ""
        except OSError as exc:
            return 127, str(exc)[:200]
        return proc.returncode, proc.stdout[:limit].decode("utf-8", "replace")


def credential_path(path: Path) -> bool:
    parts = set(path.parts)
    if any(part in parts for part in DENY_PARTS):
        return True
    name = path.name.lower()
    return name in DENY_NAMES or name.endswith((".pem", ".key", ".p12", ".keychain", ".keychain-db"))


class Reader:
    """File reads confined to roots; realpath inside a root, no symlinks, no credential paths."""

    def __init__(self, roots):
        self.roots = [Path(os.path.realpath(r)) for r in roots]

    def check(self, path) -> Path:
        raw = Path(path)
        try:
            info = os.lstat(raw)
        except OSError as exc:
            raise Refused(f"cannot stat {raw.name}") from exc
        if stat.S_ISLNK(info.st_mode):
            raise Refused(f"{raw.name} is a symlink")
        if not stat.S_ISREG(info.st_mode):
            raise Refused(f"{raw.name} is not a regular file")
        real = Path(os.path.realpath(raw))
        if credential_path(real):
            raise Refused(f"{raw.name} is a credential location")
        if not any(real == root or root in real.parents for root in self.roots):
            raise Refused(f"{raw.name} is outside the readable roots")
        return real

    def open(self, path):
        real = self.check(path)
        fd = os.open(real, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        return os.fdopen(fd, "rb")

    def read(self, path, limit: int) -> bytes:
        with self.open(path) as handle:
            return handle.read(limit)
