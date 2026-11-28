#!/usr/bin/env python3
"""`ah doctor`: prove on this host that the boundary denies what it claims, and check the install (docs/doctor.md).

    ah doctor [--json] [--role worker|reviewer|supervisor|all|none] [--no-probes] [--strict] [--codex]

`--no-probes` (the same as `--role none`) runs the checks only: nothing is created or written anywhere, which is how
to run doctor on a real host without the probe files in ~/.agent-harness/work and $HOME.

Every sandbox probe has three parts. The control proves the target is real outside the sandbox (the file exists and
this user can read it; the folder is writable). The denial runs the same operation inside the role's sandbox and must
fail. The twin runs the nearest allowed operation in the same sandbox invocation and must succeed. PROVEN = control
ok, denial refused, twin ok. FAILED = the denial went through, or the twin was refused (a boundary that blocks
everything proves nothing). UNPROVEN = the control could not be set up (target absent, mechanism missing).

The probe sandbox is built from the role's lists in sandbox_base.json (ah_sandbox.role_lists): Seatbelt through
/usr/bin/sandbox-exec on macOS, bubblewrap on Linux; with --codex and the Codex CLI present the same probes also run
under the real `codex sandbox -P ah-<role>`. The real Claude Code enforcement is proven by tests/e2e_combined.py,
which costs a model call. No probe prints file content: reads go to /dev/null and only exit codes are kept. Doctor
writes nothing except its own probe directory under $TMPDIR (removed at the end) and short-lived probe files it
removes at once; it never runs a hook script and never reads command text.

Exit 0 when nothing FAILED (UNPROVEN is a warning unless --strict), 1 on any FAILED, 2 when a config file cannot be
read. Standard library only, Python 3.9.
"""
from __future__ import annotations

import argparse
import calendar
import pwd
import hashlib
import json
import os
import re
import secrets
import shlex
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ah_sandbox  # noqa: E402
import ah_switch  # noqa: E402

STATUSES = ("PROVEN", "OK", "FAILED", "UNPROVEN", "SKIPPED")
SCHEMA = "ah-doctor/1"
DISK_LIMIT = 70            # the reaper's timer acts above this many percent used (docs/lifecycle.md)
BACKUP_MAX_AGE = 24 * 3600
MIN_PYTHON = (3, 9)
SHIM_MARK = b"agent-harness switch shim"   # the same mark install.py writes into harness/bin/harness
DEFAULT_PREFIX = "com.agent-harness."
BASH_EVENTS = ("PreToolUse", "PostToolUse", "PostToolUseFailure", "PermissionDenied")
FLAVOR_FILES = {"claude": (".claude/settings.json", ".claude/hooks"), "codex": (".codex/hooks.json", ".codex/agent-harness")}
GITHUB = re.compile(r"^(?:https://(?:[^/@\s]+@)?github\.com/|git@github\.com:|ssh://git@github\.com/)"
                    r"(?P<owner>[\w.-]+)/(?P<repo>[\w.-]+?)(?:\.git)?/?$")   # the ah_log_push.GITHUB rule
TRUST_KEY = re.compile(r'^\s*\[hooks\.state\."((?:[^"\\]|\\.)*)"\]\s*$')
TRUST_HASH = re.compile(r'^\s*trusted_hash\s*=\s*"([^"]*)"\s*$')
APP_CODEX = "/Applications/ChatGPT.app/Contents/Resources/codex-cli/CodexCLI.app/Contents/MacOS/codex"
SECRET_WALK = 500
# Names that look like a credential (the doctor's coverage check, `secrets-readable`); matched on file names only.
CREDENTIAL_NAME = re.compile(r"(?i)(token|secret|credential|passw|api[-_]?key|auth\.json$|\.env$|^\.env\b|\.pem$|"
                             r"\.key$|-keys?$|^id_(rsa|dsa|ecdsa|ed25519)$|netrc$|pgpass$|\.p12$|\.pfx$|\.keystore$)")
CREDENTIAL_SCAN = 4000      # directory entries looked at, at most
RULESET_REPOS = 20          # active repositories checked for the merge rule, at most
RULESET_ACTIVE_DAYS = 30
GIT_ENV = {"GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1", "GIT_TERMINAL_PROMPT": "0"}


class ConfigError(Exception):
    """A config file exists but cannot be read or parsed (exit 2)."""


def result(rid, status, summary, **detail) -> dict:
    return {"id": rid, "status": status, "summary": summary, "detail": detail}


def parse_iso(text) -> float:
    return float(calendar.timegm(time.strptime(text, "%Y-%m-%dT%H:%M:%SZ")))


def default_runner(argv, env=None, cwd=None, timeout=60):
    """(returncode, stdout, stderr); 127 when the program cannot start, 124 on a timeout."""
    try:
        done = subprocess.run(argv, env=env, cwd=cwd, stdin=subprocess.DEVNULL, capture_output=True, text=True,
                              timeout=timeout, check=False)
        return done.returncode, done.stdout, done.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "timed out"
    except (OSError, subprocess.SubprocessError) as error:
        return 127, "", f"{error.__class__.__name__}"


def read_json_file(path: Path):
    """The parsed file, None when absent; ConfigError when present but unreadable or not JSON."""
    try:
        with open(path, "rb") as handle:
            raw = handle.read(8 * 1024 * 1024)
    except FileNotFoundError:
        return None
    except OSError as error:
        raise ConfigError(f"{path}: {error.__class__.__name__}")
    try:
        return json.loads(raw.decode("utf-8"))
    except ValueError:
        raise ConfigError(f"{path}: not valid JSON")


def tail(text, limit=160) -> str:
    return re.sub(r"\s+", " ", str(text or "")).strip()[-limit:]


# ----------------------------------------------------------------------------- the probe mechanism
def _sb(path) -> str:
    return '"' + str(path).replace("\\", "\\\\").replace('"', '\\"') + '"'


def real(path) -> str:
    """Seatbelt and bwrap see resolved paths (/var is /private/var on macOS)."""
    return os.path.realpath(str(path))


def seatbelt_profile(spec) -> str:
    """(allow default), deny reads of deny_read, deny every write, then allow the writable roots, then deny the
    records again (later rules win)."""
    lines = ["(version 1)", "(allow default)"]
    lines += [f"(deny file-read* (subpath {_sb(real(p))}))" for p in spec["deny_read"]]
    lines.append("(deny file-write*)")
    allow = ['(subpath "/dev")'] + [f"(subpath {_sb(real(p))})" for p in spec["allow_write"]]
    lines.append("(allow file-write* " + " ".join(allow) + ")")
    lines += [f"(deny file-write* (subpath {_sb(real(p))}))" for p in spec["deny_write"]]
    lines += [f"(deny file-read* (subpath {_sb(real(p))}))" for p in spec["deny_read"]]
    return "\n".join(lines) + "\n"


def bwrap_argv(bwrap, spec, script) -> list:
    """Read-only root, the writable roots bound read-write, the records bound read-only again, denied directories
    hidden under an empty tmpfs and denied files under /dev/null."""
    argv = [bwrap, "--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc", "--unshare-user", "--die-with-parent"]
    for path in spec["allow_write"]:
        if os.path.exists(path):
            argv += ["--bind", real(path), real(path)]
    for path in spec["deny_write"]:
        if os.path.exists(path):
            argv += ["--ro-bind", real(path), real(path)]
    for path in spec["deny_read"]:
        if os.path.isdir(path):
            argv += ["--tmpfs", real(path)]
        elif os.path.exists(path):
            argv += ["--ro-bind", "/dev/null", real(path)]
    return argv + ["--", "/bin/sh", "-c", script]


class Mechanism:
    """Wraps a probe script in the host's sandbox for one probe spec; `name` is None when none is available."""

    def __init__(self, ctx):
        self.ctx, self.name, self.path = ctx, None, None
        if ctx.system == "darwin":
            self.path = ctx.which("sandbox-exec")
            self.name = "sandbox-exec" if self.path else None
        elif ctx.system == "linux":
            self.path = ctx.which("bwrap")
            if self.path and ctx.runner([self.path, "--ro-bind", "/", "/", "--unshare-user", "--", "/bin/true"],
                                        env=ctx.env(), timeout=20)[0] == 0:
                self.name = "bwrap"

    def argv(self, spec, script, cwd):
        if self.name == "sandbox-exec":
            return [self.path, "-p", seatbelt_profile(spec), "/bin/sh", "-c", script]
        return bwrap_argv(self.path, spec, script)


class CodexMechanism:
    """The real Codex enforcement: `codex sandbox -P ah-<role> -C <project> -- /bin/sh -c SCRIPT` (Codex 0.171)."""

    def __init__(self, ctx, role):
        self.ctx, self.role = ctx, role
        self.path = ctx.which("codex") or (APP_CODEX if ctx.system == "darwin" and os.access(APP_CODEX, os.X_OK)
                                           else None)
        self.name = "codex" if self.path else None

    def argv(self, spec, script, cwd):
        return [self.path, "sandbox", "-P", f"ah-{self.role}", "-C", str(cwd), "--", "/bin/sh", "-c", script]


# ----------------------------------------------------------------------------- context
class Ctx:
    def __init__(self, home, runner, system, which, disk_usage, managed_dir, tmp_root, now, environ):
        self.home = Path(home)
        self.runner = runner
        self.system = system
        self.which = which
        self.disk_usage = disk_usage
        self.managed_dir = Path(managed_dir) if managed_dir else ah_sandbox.managed_target(system).parent.parent
        self.tmp_root = tmp_root
        self.now = now
        self.environ = environ
        self.config_errors = []
        self.local = {}

    def env(self, **extra) -> dict:
        env = dict(self.environ)
        env["HOME"] = str(self.home)
        env.update(extra)
        return env


# ----------------------------------------------------------------------------- probes
class Probe:
    """One probe run: `steps` are (label, shell) pairs; labels starting with d are denials, t twins."""

    def __init__(self, rid, mech, spec, cwd, env):
        self.rid, self.mech, self.spec, self.cwd, self.env = rid, mech, spec, cwd, env
        self.steps, self.cleanup = [], []

    def add(self, label, shell):
        self.steps.append((label, shell))

    def run(self, ctx):
        # each step in its own subshell: a failed redirection on a special builtin (`: >> f`) ends a POSIX shell
        script = "\n".join(f'( {shell} ) >/dev/null 2>&1; echo "{label}=$?"' for label, shell in self.steps) + "\n"
        try:
            code, out, err = ctx.runner(self.mech.argv(self.spec, script, self.cwd), env=self.env, cwd=str(self.cwd),
                                        timeout=120)
        finally:
            for path in self.cleanup:
                _remove(path)
        codes = dict(re.findall(r"^([dt][A-Za-z0-9_]*)=(\d+)$", out or "", re.M))
        return code, codes, err


def _remove(path):
    try:
        if os.path.lexists(path) and not os.path.isdir(path):
            os.unlink(path)
    except OSError:
        pass


def first_file(path: Path):
    """The path itself when it is a regular file, else the first regular file found under it (sorted, bounded)."""
    try:
        info = os.lstat(path)
    except OSError:
        return None
    if stat.S_ISREG(info.st_mode):
        return path
    if not stat.S_ISDIR(info.st_mode):
        return None
    seen = 0
    for root, dirs, files in os.walk(path):
        dirs.sort()
        for name in sorted(files):
            seen += 1
            candidate = Path(root) / name
            try:
                if stat.S_ISREG(os.lstat(candidate).st_mode):
                    return candidate
            except OSError:
                pass
            if seen > SECRET_WALK:
                return None
        if seen > SECRET_WALK:
            return None
    return None


def readable(path: Path) -> bool:
    """Control for a read denial: this user can read one byte outside the sandbox (the byte is discarded)."""
    try:
        with open(path, "rb") as handle:
            handle.read(1)
        return True
    except OSError:
        return False


def verdict(rid, mech, code, codes, err, denials, twins, proven_text, **detail) -> dict:
    missing = [label for label in denials + twins if label not in codes]
    if missing:
        return result(rid, "UNPROVEN", f"the sandbox did not run the probe ({mech.name} exit {code}): {tail(err)}",
                      mechanism=mech.name, **detail)
    leaked = [label for label in denials if codes[label] == "0"]
    refused = [label for label in twins if codes[label] != "0"]
    if leaked:
        names = [detail.get("targets", {}).get(label, label) for label in leaked]
        return result(rid, "FAILED", "denial leaked: " + ", ".join(names), mechanism=mech.name, leaked=names, **detail)
    if refused:
        return result(rid, "FAILED", "twin refused (the boundary blocks the allowed operation too): "
                      + ", ".join(detail.get("targets", {}).get(label, label) for label in refused),
                      mechanism=mech.name, **detail)
    return result(rid, "PROVEN", proven_text, mechanism=mech.name, **detail)


class ProbeSet:
    """The probe directory: base/ (not writable), base/project (a git repository, writable except for reviewers),
    base/tmp (the session temp directory), base/standin (copies standing in for approvals.jsonl and roles.json)."""

    def __init__(self, ctx):
        self.ctx = ctx
        self.base = Path(tempfile.mkdtemp(prefix="ah-doctor-", dir=str(ctx.tmp_root) if ctx.tmp_root else None))
        self.project = self.base / "project"
        self.tmp = self.base / "tmp"
        self.standin = self.base / "standin"
        for path in (self.project, self.tmp, self.standin):
            path.mkdir(mode=0o700)
        (self.project / "README").write_text("ah doctor probe project\n")
        # The project is a repository before any sandbox runs, as a real checkout is: Codex keeps .git/hooks and
        # .git/config read-only inside a workspace root, so `git init` there is refused by design (docs/sandbox.md).
        ctx.runner(["git", "init", "-q", str(self.project)], env=ctx.env(**GIT_ENV), cwd=str(self.base), timeout=60)
        for name in ("approvals.jsonl", "roles.json"):
            (self.standin / name).write_text("")

    def close(self):
        for root, dirs, files in os.walk(self.base):
            for name in dirs:
                try:
                    os.chmod(os.path.join(root, name), 0o700)
                except OSError:
                    pass
        shutil.rmtree(self.base, ignore_errors=True)

    def spec(self, role, lists, standins=False) -> dict:
        allow = list(lists["allow_write"]) + [str(self.tmp)]
        if not lists["project_read_only"]:
            allow.append(str(self.project))
        deny_write = list(lists["deny_write"])
        if standins:
            ah = self.ctx.home / ".agent-harness"
            swap = {str(ah / "approvals.jsonl"): str(self.standin / "approvals.jsonl"),
                    str(ah / "roles.json"): str(self.standin / "roles.json")}
            allow = [swap.get(p, p) for p in allow]
            deny_write = [swap.get(p, p) for p in deny_write]
        return {"deny_read": list(lists["deny_read"]), "allow_write": allow, "deny_write": deny_write}

    def env(self):
        return self.ctx.env(TMPDIR=str(self.tmp), **GIT_ENV)

    def twin(self, probe, lists, label="t0"):
        """The reviewer's twin is a read inside the project; the others write inside it."""
        if lists["project_read_only"]:
            probe.add(label, f"head -c1 {shlex.quote(str(self.project / 'README'))}")
        else:
            path = self.project / f".ah-doctor-twin-{secrets.token_hex(4)}"
            probe.add(label, f"echo ok > {shlex.quote(str(path))}")
            probe.cleanup.append(str(path))


def probe_secrets(ps, mech, role, lists, prefix):
    rid = f"{prefix}.{role}.secrets"
    probe = Probe(rid, mech, ps.spec(role, lists), ps.project, ps.env())
    targets, skipped = {}, []
    for entry in lists["deny_read"]:
        found = first_file(Path(entry))
        if found is None or not readable(found):
            skipped.append(entry)
            continue
        label = f"d{len(targets)}"
        targets[label] = str(found)
        probe.add(label, f"head -c1 {shlex.quote(str(found))}")
    if not targets:
        return result(rid, "UNPROVEN", "no secret file exists and is readable here, so the denial cannot be shown",
                      skipped=skipped)
    probe.add("t0", f"head -c1 {shlex.quote(str(ps.project / 'README'))}")
    code, codes, err = probe.run(ps.ctx)
    targets["t0"] = str(ps.project / "README")
    return verdict(rid, mech, code, codes, err, [k for k in targets if k.startswith("d")], ["t0"],
                   f"{len(targets) - 1} secret file(s) unreadable in the sandbox; the project file read",
                   targets=targets, skipped=skipped)


def probe_records(ps, mech, role, lists, prefix):
    rid = f"{prefix}.{role}.records"
    probe = Probe(rid, mech, ps.spec(role, lists), ps.project, ps.env())
    targets, skipped = {}, []
    for entry in lists["deny_write"]:
        path = Path(entry)
        if path.is_symlink() or not path.exists():
            skipped.append(entry)            # never created by the probe (a missing OFF stays missing)
            continue
        label = f"d{len(targets)}"
        if path.is_dir():
            if not os.access(path, os.W_OK | os.X_OK):
                skipped.append(entry)
                continue
            target = path / f".ah-doctor-probe-{secrets.token_hex(4)}"
            probe.add(label, f"(umask 077; : > {shlex.quote(str(target))})")
            probe.cleanup.append(str(target))
        else:
            if not os.access(path, os.W_OK):
                skipped.append(entry)
                continue
            target = path
            probe.add(label, f": >> {shlex.quote(str(path))}")     # opened for append, nothing written
        targets[label] = str(target)
    if not targets:
        return result(rid, "UNPROVEN", "no record folder or file exists here, so the denial cannot be shown",
                      skipped=skipped)
    work = ps.ctx.home / ".agent-harness" / "work"
    if lists["project_read_only"] or not work.is_dir():
        ps.twin(probe, lists)
        targets["t0"] = str(ps.project)
    else:
        twin = work / f".ah-doctor-probe-{secrets.token_hex(4)}"
        probe.add("t0", f"echo ok > {shlex.quote(str(twin))}")
        probe.cleanup.append(str(twin))
        targets["t0"] = str(twin)
    code, codes, err = probe.run(ps.ctx)
    return verdict(rid, mech, code, codes, err, [k for k in targets if k.startswith("d")], ["t0"],
                   f"{len(targets) - 1} record path(s) unwritable in the sandbox; the allowed write went through",
                   targets=targets, skipped=skipped)


def probe_write_scope(ps, mech, role, lists, prefix):
    rid = f"{prefix}.{role}.write-scope"
    outside = ps.ctx.home / f"ah-doctor-outside-{secrets.token_hex(4)}"
    try:   # control: this user can write there outside the sandbox
        fd = os.open(str(outside), os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        os.close(fd)
        os.unlink(outside)
    except OSError:
        return result(rid, "UNPROVEN", f"cannot write {outside.parent} outside the sandbox either")
    probe = Probe(rid, mech, ps.spec(role, lists), ps.project, ps.env())
    target = ps.ctx.home / f"ah-doctor-outside-{secrets.token_hex(4)}"
    probe.add("d0", f"echo no > {shlex.quote(str(target))}")
    probe.cleanup.append(str(target))
    targets = {"d0": str(target)}
    if lists["project_read_only"]:
        ps.twin(probe, lists)
        targets["t0"] = "read inside the project"
        text = "a write outside every writable root was refused; reading the project worked"
    else:
        name = f"twin-{secrets.token_hex(4)}"
        probe.add("t0", f"echo ok > {name} && {{ [ -d .git ] || git init -q . ; }} && git add {name} && "
                        "git -c user.name=ah-doctor -c user.email=doctor@invalid -c commit.gpgsign=false "
                        "-c core.hooksPath=/dev/null commit -qm probe")
        targets["t0"] = "write, git init and git commit inside the project"
        text = "a write outside the project and every writable root was refused; git commit inside it worked"
    code, codes, err = probe.run(ps.ctx)
    return verdict(rid, mech, code, codes, err, ["d0"], ["t0"], text, targets=targets)


def probe_git_hooks(ps, mech, role, lists, prefix):
    """Codex: .git/hooks and .git/config stay read-only in a workspace root, so a planted hook cannot run later in the
    owner's own git; a commit still works (the twin)."""
    rid = f"{prefix}.{role}.git-hooks"
    probe = Probe(rid, mech, ps.spec(role, lists), ps.project, ps.env())
    hook = ps.project / ".git" / "hooks" / f"ah-doctor-{secrets.token_hex(4)}"
    probe.add("d0", f"echo x > {shlex.quote(str(hook))}")
    probe.add("d1", f"echo '# ah doctor' >> {shlex.quote(str(ps.project / '.git' / 'config'))}")
    probe.cleanup.append(str(hook))
    name = f"hooks-twin-{secrets.token_hex(4)}"
    probe.add("t0", f"echo ok > {name} && git add {name} && git -c user.name=ah-doctor -c user.email=doctor@invalid "
                    "-c commit.gpgsign=false -c core.hooksPath=/dev/null commit -qm probe")
    code, codes, err = probe.run(ps.ctx)
    return verdict(rid, mech, code, codes, err, ["d0", "d1"], ["t0"], ".git/hooks and .git/config are read-only; "
                   "git commit works", targets={"d0": ".git/hooks/<new file>", "d1": "append to .git/config",
                                                "t0": "git commit inside the project"})


def probe_read_only(ps, mech, role, lists, prefix):
    rid = f"{prefix}.{role}.read-only"
    probe = Probe(rid, mech, ps.spec(role, lists), ps.project, ps.env())
    target = ps.project / f".ah-doctor-probe-{secrets.token_hex(4)}"
    probe.add("d0", f"echo no > {shlex.quote(str(target))}")
    probe.cleanup.append(str(target))
    probe.add("t0", f"head -c1 {shlex.quote(str(ps.project / 'README'))}")
    code, codes, err = probe.run(ps.ctx)
    return verdict(rid, mech, code, codes, err, ["d0"], ["t0"], "a write inside the project was refused; reading it "
                   "worked", targets={"d0": str(target), "t0": str(ps.project / "README")})


def probe_approvals(ps, mech, role, lists, prefix):
    """Stand-ins in the probe directory take the place of approvals.jsonl and roles.json in the profile."""
    rid = f"{prefix}.{role}.approvals"
    probe = Probe(rid, mech, ps.spec(role, lists, standins=True), ps.project, ps.env())
    approvals, roles = ps.standin / "approvals.jsonl", ps.standin / "roles.json"
    if role == "supervisor":
        probe.add("d0", f"echo x >> {shlex.quote(str(roles))}")
        probe.add("t0", f"echo x >> {shlex.quote(str(approvals))}")
        targets = {"d0": "append to roles.json (stand-in)", "t0": "append to approvals.jsonl (stand-in)"}
        text = "the supervisor appends to approvals.jsonl; roles.json stays unwritable"
    else:
        probe.add("d0", f"echo x >> {shlex.quote(str(approvals))}")
        ps.twin(probe, lists)
        targets = {"d0": "append to approvals.jsonl (stand-in)", "t0": "write inside the project"}
        text = "the approvals log is unwritable for this role; the project write went through"
    code, codes, err = probe.run(ps.ctx)
    for path in (approvals, roles):
        path.write_text("")
    return verdict(rid, mech, code, codes, err, ["d0"], ["t0"], text, targets=targets)


def probe_network(ps, mech, role, lists, prefix, codex_config_text):
    rid = f"{prefix}.{role}.network"
    if not re.search(r"(?m)^\s*network_proxy\s*=\s*true\s*$", codex_config_text or ""):
        return result(rid, "UNPROVEN", "features.network_proxy is off: Codex does not enforce the domain list")
    curl = ps.ctx.which("curl")
    if not curl:
        return result(rid, "UNPROVEN", "curl is not installed")

    def fetch(url):
        return f"{shlex.quote(curl)} -sS -o /dev/null --max-time 15 {url}"
    controls = [ps.ctx.runner(["/bin/sh", "-c", fetch(u)], env=ps.ctx.env(), timeout=30)[0] for u in
                ("https://example.com", "https://github.com")]
    if any(controls):
        return result(rid, "UNPROVEN", "example.com or github.com does not answer outside the sandbox")
    probe = Probe(rid, mech, ps.spec(role, lists), ps.project, ps.env())
    probe.add("d0", fetch("https://example.com"))
    probe.add("t0", fetch("https://github.com"))
    code, codes, err = probe.run(ps.ctx)
    return verdict(rid, mech, code, codes, err, ["d0"], ["t0"], "example.com refused; github.com reached",
                   targets={"d0": "https://example.com", "t0": "https://github.com"})


def role_probes(ctx, ps, role, mech, prefix, codex_text=None) -> list:
    lists = ah_sandbox.role_lists(role, ctx.home, ctx.local)
    if mech.name is None:
        why = "no sandbox mechanism on this host (sandbox-exec or a working bwrap)" if prefix == "probe" else \
            "the Codex CLI is not installed"
        return [result(f"{prefix}.{role}.{name}", "UNPROVEN", why) for name in
                ("secrets", "records", "write-scope")]
    out = [probe_secrets(ps, mech, role, lists, prefix), probe_records(ps, mech, role, lists, prefix),
           probe_write_scope(ps, mech, role, lists, prefix)]
    if role == "reviewer":
        out.append(probe_read_only(ps, mech, role, lists, prefix))
    elif prefix == "probe":
        out.append(probe_approvals(ps, mech, role, lists, prefix))
    if prefix == "codex":
        if role != "reviewer":
            out.append(probe_git_hooks(ps, mech, role, lists, prefix))
        out.append(probe_network(ps, mech, role, lists, prefix, codex_text))
    return out


def codex_probes(ctx, ps, roles) -> list:
    codex_home = Path(ctx.environ.get("CODEX_HOME") or ctx.home / ".codex")
    try:
        text = (codex_home / "config.toml").read_text(encoding="utf-8")  # input-ok: the owner's own Codex config
    except FileNotFoundError:
        text = ""
    except OSError as error:
        ctx.config_errors.append(f"{codex_home / 'config.toml'}: {error.__class__.__name__}")
        text = ""
    out = []
    for role in roles:
        mech = CodexMechanism(ctx, role)
        if mech.name and f"[permissions.ah-{role}]" not in text:
            out.append(result(f"codex.{role}.profile", "UNPROVEN",
                              f"the ah-{role} profile is not in {codex_home / 'config.toml'} (install_codex.py)"))
            continue
        out += role_probes(ctx, ps, role, mech, "codex", text)
    return out


# ----------------------------------------------------------------------------- checks
def _labels(ctx) -> list:
    prefix = ah_sandbox._get(ctx.local, "launchd_label_prefix", DEFAULT_PREFIX)
    if not re.fullmatch(r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.", prefix or ""):
        prefix = DEFAULT_PREFIX
    out = []
    for label in ah_switch.MAC_LABELS:   # computed when ah_switch was imported: its prefix may be another home's
        suffix = label.rsplit(".", 1)[-1]   # the job names have no dot (ahd, log-backup, mission-control, floor)
        for name in (label, prefix + suffix, DEFAULT_PREFIX + suffix):
            if name not in out:          # one at a time: the three spellings are often the same label
                out.append(name)
    return out


def check_switch(ctx) -> dict:
    off = ah_switch.is_off(ctx.home)
    info = ah_switch.flag_info(ctx.home) or {}
    if ctx.system == "darwin":
        domain = f"gui/{os.getuid()}"
        loaded = [label for label in _labels(ctx)
                  if ctx.runner(["launchctl", "print", f"{domain}/{label}"], env=ctx.env(), timeout=15)[0] == 0]
    elif ctx.system == "linux":
        loaded = [unit for unit in ah_switch.LINUX_UNITS
                  if ctx.runner(["systemctl", "--user", "is-active", "--quiet", unit], env=ctx.env(), timeout=15)[0] == 0]
    else:
        return result("switch", "SKIPPED", f"no job check on {ctx.system}", off=off)
    since = f" since {info.get('at')}" if info.get("at") else ""
    by = f" by {info.get('by')}" if info.get("by") else ""
    if off and loaded:
        return result("switch", "FAILED", f"OFF{since} but {len(loaded)} harness job(s) still run: "
                      + ", ".join(loaded) + " (harness off stops them)", off=True, loaded=loaded)
    if off:
        return result("switch", "OK", f"OFF{since}{by}; no harness job loaded", off=True, loaded=[])
    return result("switch", "OK", "ON; harness jobs loaded: " + (", ".join(loaded) or "none"), off=False, loaded=loaded)


def check_files(ctx, flavor) -> dict:
    rid = f"files.{flavor}"
    if not (ctx.home / FLAVOR_FILES[flavor][1]).is_dir():
        return result(rid, "SKIPPED", f"{flavor} flavor not installed")
    snap = ah_switch.latest_snapshot(ctx.home, flavor)
    if not snap:
        return result(rid, "UNPROVEN", "no release snapshot to compare with (installed by an installer without "
                      "releases)")
    bad = []
    for rel, meta in sorted(snap["files"].items()):
        try:
            with open(ctx.home / rel, "rb") as handle:
                digest = hashlib.sha256(handle.read()).hexdigest()  # input-ok: an installed file the release snapshot names
        except OSError:
            digest = None
        if digest != (meta or {}).get("sha256"):
            bad.append(rel)
    if bad:
        return result(rid, "FAILED", f"{len(bad)} installed file(s) differ from release {snap.get('release')}: "
                      + ", ".join(bad[:5]) + (" ..." if len(bad) > 5 else ""), changed=bad)
    return result(rid, "OK", f"{len(snap['files'])} file(s) match release {snap.get('release')}")


def matcher_matches(matcher, tool="Bash") -> bool:
    """Claude Code's rule: empty, missing or * is every tool; letters, digits, _ - | , is a list of names; anything
    else is an unanchored regular expression. An invalid expression counts as matching (reported, not assumed)."""
    if matcher is None or str(matcher).strip() in ("", "*"):
        return True
    text = str(matcher)
    if re.fullmatch(r"[A-Za-z0-9_|,\- ]+", text):
        return tool in [part.strip() for part in re.split(r"[|,]", text)]
    try:
        return re.search(text, tool) is not None
    except re.error:
        return True


def managed_script(handler, hooks_dir: str):
    """(script name, via launcher) when the handler runs a Python file from hooks_dir; None otherwise."""
    if not isinstance(handler, dict) or handler.get("type", "command") != "command":
        return None
    toks = ah_switch.handler_tokens(handler)
    if not toks or not re.fullmatch(r"python[0-9.]*", os.path.basename(toks[0])):
        return None
    i = 1
    while i < len(toks) and toks[i].startswith("-"):
        i += 1
    if i >= len(toks):
        return None
    path = os.path.normpath(os.path.expanduser(toks[i]))
    # real paths on both sides: the installer writes the resolved home (/private/tmp/... for a home under /tmp)
    if os.path.realpath(os.path.dirname(path)) != os.path.realpath(hooks_dir):
        return None
    if os.path.basename(path) == ah_switch.LAUNCHER:
        return (toks[i + 1] if i + 1 < len(toks) else "", True)
    return (os.path.basename(path), False)


def handlers(doc):
    hooks = doc.get("hooks") if isinstance(doc, dict) else None
    for event, groups in (hooks or {}).items() if isinstance(hooks, dict) else ():
        for gi, group in enumerate(groups if isinstance(groups, list) else ()):
            if not isinstance(group, dict):
                continue
            for hi, handler in enumerate(group.get("hooks") if isinstance(group.get("hooks"), list) else ()):
                yield event, gi, hi, group.get("matcher"), handler


def check_wiring(ctx, flavor) -> dict:
    rid = f"wiring.{flavor}"
    settings_rel, hooks_rel = FLAVOR_FILES[flavor]
    path = ctx.home / settings_rel
    try:
        doc = read_json_file(path)
    except ConfigError as error:
        ctx.config_errors.append(str(error))
        return result(rid, "FAILED", f"cannot read {error}")
    if doc is None:
        return result(rid, "SKIPPED", f"{settings_rel} absent")
    hooks_dir = str(ctx.home / hooks_rel)
    problems, count, users_on_bash = [], 0, 0
    for event, _gi, _hi, matcher, handler in handlers(doc):
        found = managed_script(handler, hooks_dir)
        on_bash = event in BASH_EVENTS and matcher_matches(matcher)
        if not found:
            users_on_bash += on_bash
            continue
        count += 1
        script, via_launcher = found
        if not via_launcher:
            problems.append(f"{script} on {event} is wired directly, not through the launcher (no off switch)")
        if not script or not (Path(hooks_dir) / script).is_file():
            problems.append(f"{event} names {script or 'no script'}, which is not installed")
        if on_bash:
            problems.append(f"{script} on {event} matches Bash (a hook process per shell call)")
    snap = ah_switch.latest_snapshot(ctx.home, flavor)
    spec = snap.get("settings") if snap else None
    if isinstance(spec, dict) and isinstance(doc, dict):
        current = doc.get("hooks") if isinstance(doc.get("hooks"), dict) else {}
        if ah_switch.managed_wiring(current, spec) != ah_switch.managed_wiring(spec.get("groups") or {}, spec):
            problems.append(f"live wiring differs from release {snap.get('release')} (install.py --apply restores it)")
    note = f"; {users_on_bash} handler(s) of your own match Bash" if users_on_bash else ""
    if problems:
        return result(rid, "FAILED", "; ".join(problems[:4]) + (" ..." if len(problems) > 4 else ""),
                      problems=problems, handlers=count)
    return result(rid, "OK", f"{count} harness handler(s), all through the launcher, none on Bash{note}",
                  handlers=count)


IMPORT_SCRIPT = ("import importlib, json, sys\nsys.path.insert(0, sys.argv[1])\nbad = {}\n"
                 "for name in sys.argv[2:]:\n    try:\n        importlib.import_module(name)\n"
                 "    except BaseException as error:\n        bad[name] = type(error).__name__\n"
                 "print(json.dumps(bad))\n")


def check_imports(ctx, cwd) -> dict:
    python = ctx.which("python3")
    if not python:
        return result("imports", "FAILED", "python3 is not on PATH; no hook can run")
    bad, total = {}, 0
    for flavor in FLAVOR_FILES:
        folder = ctx.home / FLAVOR_FILES[flavor][1]
        names = sorted(p.stem for p in folder.glob("*.py")) if folder.is_dir() else []
        if not names:
            continue
        total += len(names)
        code, out, err = ctx.runner([python, "-I", "-c", IMPORT_SCRIPT, str(folder), *names], env=ctx.env(),
                                    cwd=str(cwd), timeout=300)
        try:
            found = json.loads((out or "").strip().splitlines()[-1])
        except (ValueError, IndexError):
            found = {"(import run)": f"exit {code}: {tail(err, 80)}"}
        bad.update({f"{flavor}:{k}": v for k, v in (found if isinstance(found, dict) else {}).items()})
    if not total:
        return result("imports", "SKIPPED", "no installed hook modules")
    if bad:
        return result("imports", "FAILED", f"{len(bad)} installed module(s) do not import under {python}: "
                      + ", ".join(f"{k} ({v})" for k, v in sorted(bad.items())[:5]), failed=bad)
    return result("imports", "OK", f"{total} installed module(s) import under {python} -I")


def snake(event) -> str:
    return re.sub(r"(?<!^)(?=[A-Z])", "_", event).lower()


def codex_trust_hash(event, handler) -> str:
    """Codex 0.171's trust hash of one handler (p2 2.3, reproduced against a live config.toml)."""
    body = {"event_name": snake(event), "hooks": [{"type": handler.get("type", "command"),
                                                   "command": handler.get("command"),
                                                   "timeout": handler.get("timeout", 600),
                                                   "async": bool(handler.get("async", False))}]}
    return "sha256:" + hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def trusted_hashes(text) -> dict:
    out, key = {}, None
    for line in (text or "").splitlines():
        found = TRUST_KEY.match(line)
        if found:
            key = found.group(1).replace('\\"', '"').replace("\\\\", "\\")
            continue
        found = TRUST_HASH.match(line)
        if found and key is not None:
            out[key] = found.group(1)
            key = None
        elif line.strip().startswith("["):
            key = None
    return out


def check_codex_trust(ctx) -> dict:
    hooks_json = ctx.home / FLAVOR_FILES["codex"][0]
    try:
        doc = read_json_file(hooks_json)
    except ConfigError as error:
        ctx.config_errors.append(str(error))
        return result("codex-trust", "FAILED", f"cannot read {error}")
    if doc is None:
        return result("codex-trust", "SKIPPED", "Codex hooks not installed")
    config = Path(ctx.environ.get("CODEX_HOME") or ctx.home / ".codex") / "config.toml"
    try:
        trusted = trusted_hashes(config.read_text(encoding="utf-8"))  # input-ok: the owner's own Codex config
    except FileNotFoundError:
        trusted = {}
    except OSError as error:
        ctx.config_errors.append(f"{config}: {error.__class__.__name__}")
        return result("codex-trust", "FAILED", f"cannot read {config}")
    hooks_dir = str(ctx.home / FLAVOR_FILES["codex"][1])
    stale, total = [], 0
    for event, gi, hi, _matcher, handler in handlers(doc):
        found = managed_script(handler, hooks_dir)
        if not found:
            continue
        total += 1
        if trusted.get(f"{hooks_json}:{snake(event)}:{gi}:{hi}") != codex_trust_hash(event, handler):
            stale.append(f"{event}:{found[0]}")
    if stale:
        return result("codex-trust", "UNPROVEN", f"{len(stale)} of {total} Codex handler(s) are not trusted at their "
                      "current definition, so Codex skips them: review in /hooks", stale=stale)
    return result("codex-trust", "OK", f"{total} Codex handler(s) trusted at their current definition")


def check_shim(ctx) -> dict:
    path = ctx.which("harness")
    if not path:
        return result("shim", "UNPROVEN", "`harness` is not on PATH (add ~/.agent-harness/bin)")
    try:
        with open(path, "rb") as handle:
            head = handle.read(4096)
    except OSError:
        head = b""
    if SHIM_MARK in head:
        return result("shim", "OK", f"`harness` is the switch shim ({path})")
    return result("shim", "FAILED", f"name collision: `harness` on PATH is {path}, not the switch shim", path=path)


def check_python(ctx) -> dict:
    python = ctx.which("python3")
    if not python:
        return result("python", "FAILED", "python3 is not on PATH")
    code, out, _err = ctx.runner([python, "-I", "-c", "import sys; print('%d.%d.%d' % sys.version_info[:3])"],
                                 env=ctx.env(), timeout=30)
    found = re.match(r"^(\d+)\.(\d+)", (out or "").strip())
    if code != 0 or not found:
        return result("python", "FAILED", f"{python} does not run")
    version = (int(found.group(1)), int(found.group(2)))
    if version < MIN_PYTHON:
        return result("python", "FAILED", f"{python} is {out.strip()}; hooks need 3.9 or newer")
    return result("python", "OK", f"{python} is {out.strip()}")


def account_home() -> str:
    """This account's own home directory (the password database), whatever $HOME says."""
    try:
        return os.path.realpath(pwd.getpwuid(os.getuid()).pw_dir)
    except (KeyError, OSError):
        return ""


def check_gh(ctx) -> dict:
    gh = ctx.which("gh")
    if not gh:
        return result("gh", "FAILED", "gh is not installed (reviews, the merge rule and saves use it)")
    if ctx.runner([gh, "auth", "status"], env=ctx.env(), timeout=30)[0] != 0:
        if ctx.system == "darwin" and real(ctx.home) != account_home():
            # macOS keeps gh's token in the login keychain, and the keychain search follows $HOME: a temporary
            # home cannot reach it, so this says nothing about the account (the release 1001 e2e).
            return result("gh", "UNPROVEN", f"gh is not authenticated under {ctx.home}, which is not this account's "
                          "home; the login keychain follows $HOME, so the real login cannot be seen from here")
        return result("gh", "FAILED", "gh is not authenticated (gh auth login)")
    return result("gh", "OK", "gh is installed and authenticated")


def _covered(path: str, denied) -> bool:
    return any(path == d or path.startswith(d.rstrip("/") + "/") for d in denied)


def check_secrets_readable(ctx) -> dict:
    """The credential-shaped files in $HOME's dot files and ~/.config (two levels) that no role's deny list covers:
    the secrets probe only proves the paths that are listed, so this lists what is left readable."""
    denied = [real(p) for p in ah_sandbox.role_lists("worker", ctx.home, ctx.local)["deny_read"]]
    found, seen = [], 0
    roots = [(ctx.home, 1, True), (ctx.home / ".config", 2, False)]
    for root, depth, dot_only in roots:
        stack = [(root, 0)]
        while stack and seen < CREDENTIAL_SCAN:
            folder, level = stack.pop()
            try:
                names = sorted(os.listdir(folder))
            except OSError:
                continue
            for name in names:
                seen += 1
                if seen > CREDENTIAL_SCAN:
                    break
                if dot_only and level == 0 and not name.startswith("."):
                    continue
                path = os.path.join(str(folder), name)
                full = real(path)
                if _covered(full, denied) or name in (".Trash", "Library"):
                    continue
                if CREDENTIAL_NAME.search(name):
                    try:
                        if os.access(path, os.R_OK):
                            found.append(str(Path("~") / os.path.relpath(path, str(ctx.home))))
                    except OSError:
                        pass
                    continue
                if level + 1 < depth and os.path.isdir(path) and not os.path.islink(path):
                    stack.append((Path(path), level + 1))
    if found:
        shown = ", ".join(found[:8]) + (f" (+{len(found) - 8} more)" if len(found) > 8 else "")
        return result("secrets-readable", "FAILED", f"{len(found)} credential-shaped file(s) no role denies: {shown}; "
                      "add them to local.json sandbox_extra_deny_read", paths=found[:50])
    return result("secrets-readable", "OK", f"no credential-shaped file outside the deny list ({seen} entries looked at)")


def _pushed_at(repo) -> float:
    try:
        return parse_iso(str(repo.get("pushedAt") or ""))
    except ValueError:
        return 0.0


def check_rulesets(ctx) -> dict:
    """Release 1001 unregisters the merge gate hook; the harness-merge-rule ruleset on GitHub is the gate now. Lists
    the account's active repositories (admin, not archived, pushed within RULESET_ACTIVE_DAYS) without it."""
    gh = ctx.which("gh")
    if not gh:
        return result("rulesets", "UNPROVEN", "gh is not installed; cannot list repositories without the merge rule")
    code, out, err = ctx.runner([gh, "repo", "list", "--no-archived", "--limit", "100", "--json",
                                 "nameWithOwner,pushedAt,viewerPermission"], env=ctx.env(), timeout=60)
    try:
        repos = json.loads(out) if code == 0 else None
    except ValueError:
        repos = None
    if not isinstance(repos, list):
        return result("rulesets", "UNPROVEN", f"cannot list this account's repositories with gh ({tail(err) or code})")
    cutoff = ctx.now - RULESET_ACTIVE_DAYS * 86400
    active = [r["nameWithOwner"] for r in repos if isinstance(r, dict) and isinstance(r.get("nameWithOwner"), str)
              and r.get("viewerPermission") == "ADMIN" and _pushed_at(r) >= cutoff]
    active = active[:RULESET_REPOS]
    missing, unknown = [], []
    for slug in active:
        code, out, _err = ctx.runner([gh, "api", f"repos/{slug}/rulesets"], env=ctx.env(), timeout=30)
        try:
            names = [x.get("name") for x in json.loads(out)] if code == 0 else None
        except (ValueError, AttributeError, TypeError):
            names = None
        if names is None:
            unknown.append(slug)
        elif "harness-merge-rule" not in names:
            missing.append(slug)
    if missing:
        return result("rulesets", "FAILED", f"{len(missing)} active repositor{'y has' if len(missing) == 1 else 'ies have'}"
                      " no harness-merge-rule, and release 1001 has no merge hook: " + ", ".join(missing[:8])
                      + f" (run `ah repo protect {missing[0]}` for each)", missing=missing, unknown=unknown)
    if unknown:
        return result("rulesets", "UNPROVEN", "could not read the rulesets of " + ", ".join(unknown[:8]),
                      unknown=unknown)
    return result("rulesets", "OK", f"{len(active)} active repositor{'y has' if len(active) == 1 else 'ies have'} the "
                  "merge rule" if active else "no active repository of this account to protect")


def check_mechanism(ctx, mech) -> dict:
    if mech.name:
        return result("mechanism", "OK", f"{mech.name} is available ({mech.path})")
    want = "sandbox-exec" if ctx.system == "darwin" else "bubblewrap (bwrap) with user namespaces"
    return result("mechanism", "UNPROVEN", f"{want} is not available, so no boundary can be proven here")


def check_backup(ctx) -> dict:
    try:
        import log_backup  # noqa: PLC0415
    except Exception as error:   # a partial install: report, do not crash
        return result("backup", "UNPROVEN", f"log_backup does not import ({error.__class__.__name__})")
    state = log_backup.classify(ctx.home, now=ctx.now, max_age=BACKUP_MAX_AGE)
    if state["state"] == "fresh":
        return result("backup", "OK", f"last successful log backup {log_backup.human_age(state['age'])} ago")
    if state["state"] == "stale":
        return result("backup", "FAILED", f"last successful log backup {log_backup.human_age(state['age'])} ago "
                      "(limit 24 h); see ~/.agent-harness/logs/log-backup.log")
    installed = list((ctx.home / "Library" / "LaunchAgents").glob("*log-backup*.plist")) + \
        list((ctx.home / ".config" / "systemd" / "user").glob("log-backup.*"))
    if not installed:
        return result("backup", "UNPROVEN", "log backup is not installed on this host")
    return result("backup", "FAILED", "log backup is installed but has no valid success marker "
                  f"({state['state']})")


def check_rescue(ctx) -> dict:
    remote = ah_sandbox._get(ctx.local, "rescue_remote", "")
    if not remote:
        return result("rescue-remote", "OK", "no rescue_remote: saved work goes to verified bundles on this host")
    found = GITHUB.match(remote)
    if not found:
        return result("rescue-remote", "UNPROVEN", "rescue_remote is not a GitHub URL; its visibility is unknown")
    gh = ctx.which("gh")
    slug = f"{found.group('owner')}/{found.group('repo')}"
    if not gh:
        return result("rescue-remote", "UNPROVEN", f"gh is not installed; cannot see whether {slug} is private")
    code, out, _err = ctx.runner([gh, "repo", "view", slug, "--json", "visibility", "--jq", ".visibility"],
                                 env=ctx.env(), timeout=30)
    visibility = (out or "").strip().upper()
    if code == 0 and visibility == "PUBLIC":
        return result("rescue-remote", "FAILED", f"rescue_remote {slug} is PUBLIC (saves fall back to bundles)")
    if code == 0 and visibility in ("PRIVATE", "INTERNAL"):
        return result("rescue-remote", "OK", f"rescue_remote {slug} is {visibility.lower()}")
    return result("rescue-remote", "UNPROVEN", f"cannot read the visibility of {slug}")


def check_disk(ctx) -> dict:
    try:
        total, used, _free = ctx.disk_usage(str(ctx.home))
        percent = round(100.0 * used / total, 1)
    except (OSError, ZeroDivisionError, TypeError, ValueError):
        return result("disk", "UNPROVEN", "cannot read the disk usage of the home volume")
    if percent > DISK_LIMIT:
        return result("disk", "FAILED", f"{percent}% used, above the reaper's {DISK_LIMIT}% (ah reap run --apply "
                      f"--if-above {DISK_LIMIT})", percent=percent)
    return result("disk", "OK", f"{percent}% used (reaper acts above {DISK_LIMIT}%)", percent=percent)


def check_managed(ctx) -> dict:
    path = ctx.managed_dir / "managed-settings.d" / ah_sandbox.MANAGED_NAME
    try:
        doc = read_json_file(path)
    except ConfigError as error:
        ctx.config_errors.append(str(error))
        return result("managed", "FAILED", f"cannot read {error}")
    role = ah_sandbox.sandbox_role(ctx.home, ctx.local)
    if doc is None:
        return result("managed", "OK", f"no managed drop-in at {path}: the boundary applies only to sessions "
                      "launched with --settings")
    if doc != ah_sandbox.managed_settings(role, ctx.home, ctx.local):
        return result("managed", "FAILED", f"{path} differs from `ah sandbox show --flavor managed --role {role}`")
    return result("managed", "OK", f"managed drop-in equals the {role} settings ({path})")


def check_sandbox_files(ctx) -> dict:
    found, bad = 0, []
    for role in ah_sandbox.ROLES:
        path = ah_sandbox.installed_path(ctx.home, role)
        try:
            doc = read_json_file(path)
        except ConfigError as error:
            ctx.config_errors.append(str(error))
            bad.append(role)
            continue
        if doc is None:
            continue
        found += 1
        if doc != ah_sandbox.claude_settings(role, ctx.home, ctx.local):
            bad.append(role)
    if bad:
        return result("sandbox-files", "FAILED", "generated sandbox file(s) out of date: " + ", ".join(bad)
                      + " (install.py --apply rewrites them)", roles=bad)
    if not found:
        return result("sandbox-files", "SKIPPED", "no generated sandbox files under ~/.agent-harness/sandbox")
    return result("sandbox-files", "OK", f"{found} generated sandbox file(s) equal `ah sandbox show`")


def check_local(ctx) -> dict:
    path = ctx.home / ".agent-harness" / "local.json"
    try:
        doc = read_json_file(path)
    except ConfigError as error:
        ctx.config_errors.append(str(error))
        return result("local", "FAILED", f"cannot read {error}")
    if doc is None:
        return result("local", "OK", "no local.json (every key at its default)")
    if not isinstance(doc, dict):
        ctx.config_errors.append(f"{path}: not a JSON object")
        return result("local", "FAILED", f"{path} is not a JSON object")
    ctx.local = doc
    return result("local", "OK", f"local.json parses; sandbox_role {ah_sandbox.sandbox_role(ctx.home, doc)}")


# ----------------------------------------------------------------------------- run
def run(home=None, roles=ah_sandbox.ROLES, codex=False, strict=False, runner=None, system=None, which=None,
        disk_usage=None, managed_dir=None, tmp_root=None, now=None, environ=None) -> dict:
    system = ah_switch.system_name(system)
    environ = dict(os.environ if environ is None else environ)
    ctx = Ctx(Path(home).expanduser() if home else Path(environ.get("HOME") or os.path.expanduser("~")),
              runner or default_runner, system, which or (lambda n: shutil.which(n, path=environ.get("PATH"))),
              disk_usage or shutil.disk_usage, managed_dir, tmp_root, time.time() if now is None else now, environ)
    results = [check_local(ctx)]
    ps = ProbeSet(ctx)
    try:
        mech = Mechanism(ctx)
        results += [check_switch(ctx), check_files(ctx, "claude"), check_files(ctx, "codex"),
                    check_wiring(ctx, "claude"), check_wiring(ctx, "codex"), check_imports(ctx, ps.tmp),
                    check_codex_trust(ctx), check_shim(ctx), check_python(ctx), check_gh(ctx), check_rulesets(ctx),
                    check_mechanism(ctx, mech), check_backup(ctx), check_rescue(ctx), check_disk(ctx),
                    check_managed(ctx), check_sandbox_files(ctx), check_secrets_readable(ctx)]
        for role in roles:
            results += role_probes(ctx, ps, role, mech, "probe")
        if codex:
            results += codex_probes(ctx, ps, roles)
    finally:
        ps.close()
    counts = {}
    for item in results:
        counts[item["status"]] = counts.get(item["status"], 0) + 1
    if ctx.config_errors:
        code = 2
    elif counts.get("FAILED") or (strict and counts.get("UNPROVEN")):
        code = 1
    else:
        code = 0
    return {"schema": SCHEMA, "host": socket.gethostname().split(".")[0], "system": system, "home": str(ctx.home),
            "roles": list(roles), "codex": bool(codex), "strict": bool(strict), "exit": code, "counts": counts,
            "config_errors": ctx.config_errors, "results": results}


def text_report(report) -> str:
    lines = [f"{r['status']:<9}{r['id']:<28} {r['summary']}" for r in report["results"]]
    counts = ", ".join(f"{report['counts'][s]} {s}" for s in STATUSES if report["counts"].get(s))
    lines.append(f"ah doctor: {counts}; exit {report['exit']}"
                 + ("; unreadable: " + "; ".join(report["config_errors"]) if report["config_errors"] else ""))
    return "\n".join(lines) + "\n"


def main(argv=None, runner=None, system=None, which=None, disk_usage=None, tmp_root=None) -> int:
    parser = argparse.ArgumentParser(prog="ah doctor", description="Prove this host's boundary and check the "
                                     "install (docs/doctor.md).")
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--role", default="all", help="worker, reviewer, supervisor, all (default) or none")
    parser.add_argument("--no-probes", action="store_true",
                        help="the checks only: no probe file is created anywhere (for a real host); same as --role none")
    parser.add_argument("--strict", action="store_true", help="UNPROVEN counts as a failure")
    parser.add_argument("--codex", action="store_true", help="also run the probes under the real `codex sandbox`")
    parser.add_argument("--home", help="the home to check (tests; default $HOME)")
    parser.add_argument("--managed-dir", help="the managed-settings directory (default the system one)")
    try:
        args = parser.parse_args(list(sys.argv[1:] if argv is None else argv))
    except SystemExit as stop:
        return int(stop.code or 0)
    if args.role not in ("all", "none") and args.role not in ah_sandbox.ROLES:
        print(f"ah doctor: --role is one of {', '.join(ah_sandbox.ROLES)}, all or none", file=sys.stderr)
        return 2
    if args.no_probes or args.role == "none":
        roles = ()
        if args.codex:
            print("ah doctor: --codex runs probes; it does not go with --no-probes", file=sys.stderr)
            return 2
    else:
        roles = ah_sandbox.ROLES if args.role == "all" else (args.role,)
    report = run(home=args.home, roles=roles, codex=args.codex, strict=args.strict, runner=runner, system=system,
                 which=which, disk_usage=disk_usage, managed_dir=args.managed_dir, tmp_root=tmp_root)
    sys.stdout.write(json.dumps(report, indent=2, sort_keys=True) + "\n" if args.json else text_report(report))
    return report["exit"]


if __name__ == "__main__":
    sys.exit(main())
