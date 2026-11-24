#!/usr/bin/env python3
"""Refresh existing harness files from a pinned, canonically merged release."""

import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import runpy
import shlex
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tarfile
import tempfile
import time


ORIGIN = "https://github.com/ericmacdougall/agent-harness.git"
GIT = "/usr/bin/git"
SSH = "/usr/bin/ssh"
INSTALLERS = ("install.py", "install_codex.py")
SETTINGS = (".claude/CLAUDE.md", ".claude/settings.json", ".codex/AGENTS.md",
            ".codex/hooks.json", ".codex/config.toml", ".codex/hooks.state", ".codex/hooks.state.json")
LOCAL_PROFILES = tuple(f"{folder}/{name}.local.json"
                       for folder in (".claude/hooks", ".codex/agent-harness")
                       for name in ("commit_policy", "spec_policy"))
BACKUPS = (".claude/agent-harness-backups", ".codex/agent-harness/backups")
HOOK_PATHS = (".claude/hooks/ah.py", ".codex/agent-harness/ah.py")
MAX_ARCHIVE = 64 * 1024 * 1024
MIN_FREE = 512 * 1024 * 1024
MAX_LOG = 65536
INSTALL_TIMEOUT = 80
SSH_TIMEOUT = 185
REF = re.compile(r"[a-f0-9]{40}")
HASH = re.compile(r"[a-f0-9]{64}")
HOST = re.compile(r"[A-Za-z0-9][A-Za-z0-9.-]{0,127}")
TOKEN = re.compile(r"repair-[a-z0-9_]{8}")


class RepairError(ValueError):
    """An incomplete or refused repair."""


def require(condition, message):
    if not condition:
        raise RepairError(message)


def digest(path):
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as source:
        item = os.fstat(source.fileno())
        require(stat.S_ISREG(item.st_mode), f"Expected a regular file: {path.name}")
        return hashlib.file_digest(source, "sha256").hexdigest()


def snapshot(paths):
    result = {}
    for path in paths:
        try:
            info = path.lstat()
        except FileNotFoundError:
            result[str(path)] = None
            continue
        require(stat.S_ISREG(info.st_mode), f"Protected or installed path is not a regular file: {path.name}")
        result[str(path)] = [info.st_dev, info.st_ino, stat.S_IMODE(info.st_mode), digest(path)]
    return result


def private_dir(path):
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid() and not info.st_mode & 0o077,
            f"Expected a private non-symlink directory: {path}")
    return path


def work_dir(home):
    require(os.geteuid() != 0 and home.is_absolute() and home.resolve() == home,
            "Run under the existing non-root harness account.")
    return private_dir(private_dir(home / ".agent-harness") / "work")


def ensure_space(path):
    free = shutil.disk_usage(path).free
    require(free >= MIN_FREE, "Insufficient free space: repair requires at least 512 MiB before staging or applying.")
    return free


@contextmanager
def host_lock(work, name):
    # A stable inode keeps overlapping attempts and a surviving SSH worker apart.
    fd = os.open(work / name, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        info = os.fstat(fd)
        require(stat.S_ISREG(info.st_mode) and info.st_uid == os.geteuid()
                and info.st_nlink == 1 and not info.st_mode & 0o077,
                "Unsafe repair lock file.")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise RepairError("Another repair still holds the host lock. Reconcile its result first.") from error
        yield
    finally:
        os.close(fd)


def git(args, *, cwd, timeout=40, file_limit=None):
    env = {name: value for name, value in os.environ.items() if not name.startswith("GIT_")}
    env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull, GIT_TERMINAL_PROMPT="0")
    def limit_output():
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        resource.setrlimit(resource.RLIMIT_FSIZE, (file_limit, file_limit))
    return subprocess.run([GIT, *args], cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                          stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=timeout, check=True,
                          preexec_fn=limit_output if file_limit is not None else None).stdout


def canonical_archive(ref, stage):
    ensure_space(stage)
    # Reuse one blob-filtered canonical object store, not another complete clone
    # per repair. Each run still gets a fresh archive and two fresh extractions.
    with host_lock(stage.parent, "repair-source.lock"):
        repo = stage.parent / "repair-source.git"
        if not repo.exists():
            repo.mkdir(mode=0o700)
            git(["init", "--quiet", "--bare"], cwd=repo)
        private_dir(repo)
        git(["fetch", "--quiet", "--filter=blob:none", "--no-tags", ORIGIN,
             "+refs/heads/main:refs/remotes/canonical/main"], cwd=repo)
        main = git(["rev-parse", "refs/remotes/canonical/main"], cwd=repo).decode().strip()
        try:
            require(git(["cat-file", "-t", ref], cwd=repo).strip() == b"commit", "Select an exact commit.")
            git(["merge-base", "--is-ancestor", ref, main], cwd=repo)
        except subprocess.CalledProcessError as error:
            raise RepairError("The selected commit is outside canonical main history.") from error
        git(["archive", "--format=tar", f"--output={stage / 'release.tar'}", ref], cwd=repo,
            file_limit=MAX_ARCHIVE)
    require(0 < (stage / "release.tar").stat().st_size <= MAX_ARCHIVE, "Canonical release archive is too large.")
    return main


def receive_archive(source, path, size):
    require(0 < size <= MAX_ARCHIVE, "Invalid archive size.")
    with path.open("xb") as dest:
        remaining = size
        while remaining:
            chunk = source.read(min(remaining, 1024 * 1024))
            require(chunk, "Incomplete release archive.")
            dest.write(chunk)
            remaining -= len(chunk)
        require(not source.read(1), "Release archive contains unexpected trailing bytes.")


def extraction(archive, target, expected):
    require(HASH.fullmatch(expected) and digest(archive) == expected, "Release archive digest mismatch.")
    target.mkdir(mode=0o700)
    with tarfile.open(archive, "r:") as bundle:
        members = bundle.getmembers()
        require(len({Path(item.name) for item in members}) == len(members), "Duplicate release archive entry.")
        for item in members:
            path = Path(item.name)
            require(path.parts and not path.is_absolute() and ".." not in path.parts and (item.isdir() or item.isreg()),
                    "Unexpected member in release archive.")
            destination = target / path
            if item.isdir():
                destination.mkdir(mode=0o700, parents=True, exist_ok=True)
            else:
                destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                with destination.open("xb") as output, bundle.extractfile(item) as entry:
                    shutil.copyfileobj(entry, output)


def inventory(source, home):
    # Read the manifests from the verified release. Keep installer ownership and source mapping aligned.
    sys.path.insert(0, str(source))
    old_install = sys.modules.pop("install", None)
    try:
        claude = runpy.run_path(str(source / "install.py"))
        codex = runpy.run_path(str(source / "install_codex.py"))
    finally:
        sys.path.pop(0)
        sys.modules.pop("install", None)
        if old_install is not None:
            sys.modules["install"] = old_install
    mappings = {}
    directories = {"agents": "AGENTS", "hooks": "HOOKS", "tools": "TOOLS", "skills": "SKILLS"}
    for folder, names in directories.items():
        for name in claude[names]:
            mappings[home / ".claude" / folder / name] = source / "harness" / folder / name
    for folder, names in (("agents", "AGENTS"), ("skills/agent-harness", "SKILL_FILES")):
        for name in codex[names]:
            mappings[home / ".codex" / folder / name] = source / "codex" / folder / name
    codex_data = home / ".codex/agent-harness"
    for name in (*codex["DELIVERY_HELPERS"], "ops_watch.py"):
        mappings[codex_data / name] = source / "harness/hooks" / name
    mappings[codex_data / "wal.py"] = source / "codex/hooks/wal.py"
    mappings[codex_data / "watch-tests.py"] = source / "harness/tools/watch-tests.py"
    return mappings


def run_logged(argv, logfile, timeout, *, cwd=None, stdin=subprocess.DEVNULL, stderr=subprocess.STDOUT):
    # Drain child output without allowing it to grow private logs past the cap.
    import selectors

    with logfile.open("xb") as log, subprocess.Popen(
        argv, cwd=cwd, stdin=stdin, stdout=subprocess.PIPE, stderr=stderr,
        start_new_session=True,
    ) as process, selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ)
        deadline = time.monotonic() + timeout
        written = 0
        try:
            while True:
                remaining = deadline - time.monotonic()
                require(remaining > 0 and selector.select(remaining), "Command did not finish before its timeout.")
                chunk = os.read(process.stdout.fileno(), 8192)
                if not chunk:
                    break
                kept = chunk[:max(0, MAX_LOG - written)]
                log.write(kept)
                written += len(kept)
            require(process.wait(timeout=max(0.01, deadline - time.monotonic())) == 0, "Command failed.")
        except BaseException:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            raise
    return logfile.read_text(encoding="utf-8", errors="replace")


def bounded_install(source, name, logfile, apply, home):
    argv = [sys.executable, "-EsB", name, "--hooks-only", "--home", str(home)]
    if apply:
        argv.append("--apply")
    return run_logged(argv, logfile, INSTALL_TIMEOUT, cwd=source)


def backup_paths(home):
    return {str(path) for folder in BACKUPS for path in (home / folder).glob("*") if path.is_dir()}


def host_worker(phase, expected, token, size, source, home):
    work = work_dir(home)
    checking = phase == "check"
    require(checking or phase == "apply", "Invalid host phase.")
    require(token == "-" if checking else TOKEN.fullmatch(token), "Invalid host stage.")
    stage = private_dir(Path(tempfile.mkdtemp(prefix="repair-", dir=work))) if checking else private_dir(work / token)
    reply = {"stage": stage.name, "status": "failed", "backups": [], "git_backstop": "unconfirmed",
             "log_dir": str(stage)}
    old_backups = backup_paths(home)
    try:
        with host_lock(work, "repair-apply.lock"):
            free = ensure_space(work)
            (stage / f"{phase}-runtime.json").write_text(json.dumps({
                "python": sys.executable, "python_version": sys.version.split()[0],
                "free_bytes": free, "minimum_free_bytes": MIN_FREE,
                "archive_bytes": size if checking else (stage / "release.tar").stat().st_size,
            }))
            require(all((home / path).is_file() for path in HOOK_PATHS), "Both harness editions must already exist.")
            archive = stage / "release.tar"
            if checking:
                receive_archive(source, archive, size)
            else:
                require(size == 0 and not source.read(1), "Unexpected apply payload.")
            files = stage / f"source-{phase}"
            extraction(archive, files, expected)
            mappings = inventory(files, home)
            required = {path: digest(payload) for path, payload in mappings.items()}
            settings = [home / path for path in SETTINGS]
            # Existing personalized profiles are immutable. The stock installers may migrate a missing one.
            settings.extend(home / path for path in LOCAL_PROFILES if os.path.lexists(home / path))
            before = {"files": snapshot(mappings), "settings": snapshot(settings)}
            record = stage / "preview.json"
            if not checking:
                require(json.loads(record.read_text()) == before, "The installation changed after preview. Reconcile first.")
            for name in INSTALLERS:
                log = bounded_install(files, name, stage / f"{phase}-{name}.log", apply=not checking, home=home)
                version = re.search(r"commit-msg backstop inactive: (?:git )+(?:version )?([0-9.]+) lacks", log)
                if version:
                    reply["git_backstop"] = f"inactive (Git {version[1]}; requires 2.54+)"
                elif "commit-msg backstop inactive" in log:
                    reply["git_backstop"] = "inactive"
                elif "register git hook." in log or "registered git hook." in log:
                    if not reply["git_backstop"].startswith("inactive"):
                        reply["git_backstop"] = "available"
            require(snapshot(settings) == before["settings"], "Instructions or settings changed unexpectedly.")
            if checking:
                require(snapshot(mappings) == before["files"], "Managed files changed during preview.")
                with record.open("x") as receipt:
                    json.dump(before, receipt)
            else:
                require(all(digest(path) == checksum for path, checksum in required.items()),
                        "An installer-owned file differs from the verified release.")
            reply["status"] = "ok"
    except (OSError, ValueError, tarfile.TarError, subprocess.SubprocessError, KeyError) as error:
        detail = str(error) if isinstance(error, RepairError) else type(error).__name__
        (stage / f"{phase}-failure.log").write_text(detail[:500] + "\n", encoding="utf-8")
    reply["backups"] = sorted(backup_paths(home) - old_backups)
    return reply


def report(label, reply):
    print(f"{label}: {reply['status']}. Logs: {reply['log_dir']}. Git backstop: {reply['git_backstop']}.")
    if reply["status"] == "ok":
        print(f"{label} agent hook registration: unchanged (hooks-only); enrollment and trust were not granted.")
    for path in reply["backups"]:
        print(f"{label} backup: {path}")


def sequence(options, stage, local, remote):
    archive = stage / "release.tar"
    try:
        local_check = local("check", archive)
        report("Local preflight", local_check)
        require(local_check["status"] == "ok", "Local preflight failed.")
        remote_check = remote("check", archive)
        report(f"{options.host} preflight", remote_check)
        require(remote_check["status"] == "ok", "Remote preflight failed.")
    except RepairError as error:
        raise RepairError("Repair stopped during preflight. Neither installer applied any changes.") from error
    if not options.apply:
        print("Preview complete. No installers applied changes.")
        return
    try:
        remote_apply = remote("apply", remote_check["stage"])
    except RepairError as error:
        raise RepairError(
            f"Remote apply outcome is uncertain. Local apply did not start. Reconcile {remote_check['log_dir']} before retrying."
        ) from error
    report(f"{options.host} apply", remote_apply)
    require(remote_apply["status"] == "ok", "Remote apply reported failure and may be partial. Local apply did not start.")
    try:
        local_apply = local("apply", local_check["stage"])
        report("Local apply", local_apply)
        require(local_apply["status"] == "ok", "Local apply reported failure.")
    except RepairError as error:
        raise RepairError(f"Repair stopped during local apply. The remote already applied. Local state may be partial; inspect {local_check['log_dir']}.") from error
    print("Both installations match the verified release. Existing instructions and settings were preserved.")


def remote_client(host, worker_code, expected, stage):
    def invoke(phase, payload):
        checking = phase == "check"
        token = "-" if checking else payload
        size = payload.stat().st_size if checking else 0
        # The SSH target must already have a trusted host key. The worker independently checks its hostname.
        argv = ["-IB", "-c", worker_code, "--worker", phase, expected, token, str(size), host.split(".")[0]]
        command = (
            "for py in /usr/bin/python3 /usr/bin/python3.15 /usr/bin/python3.14 /usr/bin/python3.13 "
            "/usr/bin/python3.12 /usr/bin/python3.11 /opt/homebrew/bin/python3.15 "
            "/opt/homebrew/bin/python3.14 /opt/homebrew/bin/python3.13 /opt/homebrew/bin/python3.12 "
            "/opt/homebrew/bin/python3.11 /usr/local/bin/python3; do "
            'if "$py" -I -c "import sys; sys.exit(sys.version_info < (3, 11))" 2>/dev/null; then '
            'exec "$py" ' + shlex.join(argv) + "; fi; done; exit 2"
        )
        try:
            with (payload if checking else Path(os.devnull)).open("rb") as data:
                output = run_logged(
                    [SSH, "-T", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", "-o",
                     "StrictHostKeyChecking=yes", "-o", "ClearAllForwardings=yes", host, command],
                    stage / f"remote-{phase}.log", SSH_TIMEOUT, stdin=data, stderr=subprocess.DEVNULL,
                )
            require(len(output.encode()) < MAX_LOG, "Oversized remote repair response.")
            reply = json.loads(output)
            require(type(reply) is dict and reply.keys() == {"stage", "status", "backups", "git_backstop", "log_dir"}
                    and TOKEN.fullmatch(reply["stage"]) and reply["status"] in ("ok", "failed")
                    and (checking or reply["stage"] == token)
                    and type(reply["backups"]) is list and len(reply["backups"]) <= 8
                    and good_absolute(reply["log_dir"]) and Path(reply["log_dir"]).name == reply["stage"]
                    and all(good_absolute(path) for path in reply["backups"])
                    and re.fullmatch(r"available|unconfirmed|inactive(?: \(Git [0-9.]+; requires 2\.54\+\))?",
                                     reply["git_backstop"]),
                    "Unverified remote repair response.")
            return reply
        except (OSError, ValueError, subprocess.SubprocessError, TypeError) as error:
            raise RepairError("Could not confirm the remote worker's result.") from error

    return invoke


def good_absolute(path):
    return type(path) is str and 0 < len(path) <= 512 and path.startswith("/") and path.isprintable()


def main():
    os.umask(0o077)
    if sys.argv[1:2] == ["--worker"]:
        _, phase, expected, token, size, host = sys.argv[1:]
        require(socket.gethostname().split(".")[0].casefold() == host.casefold(), "Worker host name mismatch.")
        print(json.dumps(host_worker(phase, expected, token, int(size), sys.stdin.buffer, Path.home())))
        return
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ref", required=True, help="exact reviewed canonical main commit")
    parser.add_argument("--host", default="t2-dev", help="trusted SSH hostname (default: t2-dev)")
    parser.add_argument("--python", type=Path, help="absolute local Python 3.11+ interpreter")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="preview only (default)")
    mode.add_argument("--apply", action="store_true", help="apply after both host previews pass")
    options = parser.parse_args()
    require(REF.fullmatch(options.ref) and HOST.fullmatch(options.host), "Supply a full commit SHA and a trusted SSH host.")
    require(options.python is None or options.python.is_absolute(), "Use an absolute --python path.")
    home = Path.home()
    stage = Path(tempfile.mkdtemp(prefix="harness-repair-", dir=work_dir(home)))
    print(f"Repair staging: {stage}", flush=True)
    main_ref = canonical_archive(options.ref, stage)
    print(f"Selected release {options.ref}; verified against canonical main {main_ref}.", flush=True)
    expected = digest(stage / "release.tar")

    def local(phase, payload):
        checking = phase == "check"
        try:
            with (payload if checking else Path(os.devnull)).open("rb") as data:
                return host_worker(phase, expected, "-" if checking else payload,
                                   payload.stat().st_size if checking else 0, data, home)
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            raise RepairError("Could not confirm the local worker's result.") from error

    sequence(options, stage, local, remote_client(options.host, Path(__file__).read_text(), expected, stage))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        detail = str(error) if isinstance(error, RepairError) else type(error).__name__
        print(f"Harness repair stopped: {detail}", file=sys.stderr)
        sys.exit(2)
