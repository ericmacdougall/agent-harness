"""Install Harness Mission Control, the local realtime fleet dashboard (GoodQA #15585, docs/mission-control.md).

The server and its web assets are copied from harness/mission_control/ to ~/.agent-harness/mission-control/app/
(staged, then swapped in by rename; the previous copy is kept as app.prev for rollback). On macOS the LaunchAgent
com.agent-harness.mission-control is (re)registered through the installed `server.py install-launchd --apply`, so
it always points at the installed copy, never at a checkout or worktree.

Like netwatch, this step never fails the harness install: it reports one status line. `--no-mission-control`
opts out and is remembered; where installed it stops the LaunchAgent (files and chat data stay). The LaunchAgent
belongs to the real user, so with a non-default --home (tests, staging a home) the service is never touched and
the files are only copied when --mission-control asks for them.
"""

from __future__ import annotations

import json
import os
import secrets
import shutil
import stat
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SOURCE = ROOT / "harness" / "mission_control"
STATE_FILE = "mission-control-state.json"
LABEL = "com.agent-harness.mission-control"
SKIP_DIRS = {"__pycache__", "tests"}
SKIP_SUFFIXES = {".pyc", ".pyo"}
MAX_FILE = 8 << 20  # the vendored three.js module is the largest file, well under this


def mc_root(home: Path) -> Path:
    return home / ".agent-harness" / "mission-control"


def app_dir(home: Path) -> Path:
    return mc_root(home) / "app"


def real_home() -> Path:
    """The account's home from the password database: a LaunchAgent belongs to the real user, not to $HOME."""
    try:
        import pwd
        return Path(pwd.getpwuid(os.getuid()).pw_dir).resolve()
    except (ImportError, KeyError):
        return Path.home().resolve()


def read_state(path: Path):
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0)
    try:
        fd = os.open(path, flags)
    except OSError:
        return None
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return None
        return json.loads(os.read(fd, 4096).decode())
    except (OSError, ValueError):
        return None
    finally:
        os.close(fd)


def real_dir(path: Path) -> None:
    """Create path (0700) if missing; refuse a symlink or a non-directory."""
    try:
        path.mkdir(mode=0o700)
    except FileExistsError:
        pass
    if path.is_symlink() or not path.is_dir():
        raise OSError(f"{path} must be a real directory, not a link")


def choice(home: Path, flag) -> bool:
    """--mission-control/--no-mission-control win; otherwise the saved choice; otherwise on."""
    if flag is not None:
        return bool(flag)
    state = read_state(home / ".agent-harness" / STATE_FILE)
    return not (isinstance(state, dict) and state.get("enabled") is False)


def save_choice(home: Path, enabled: bool) -> None:
    directory = home / ".agent-harness"
    real_dir(directory)
    temporary = directory / f".{STATE_FILE}.{secrets.token_hex(4)}"
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "w") as handle:
        json.dump({"schema": 1, "enabled": enabled}, handle)
        handle.write("\n")
    os.replace(temporary, directory / STATE_FILE)


def source_files(source: Path = SOURCE) -> list[Path]:
    """Every regular file the app needs, relative to source; a symlink in the checkout is refused, not followed."""
    files = []
    for dirpath, dirnames, filenames in os.walk(source, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS and not d.startswith("."))
        for name in sorted(filenames):
            path = Path(dirpath) / name
            if name.startswith(".") or path.suffix in SKIP_SUFFIXES:
                continue
            if path.is_symlink() or not path.is_file():
                raise OSError(f"refusing a non-regular source file: {path.relative_to(source)}")
            if path.stat().st_size > MAX_FILE:
                raise OSError(f"source file too large: {path.relative_to(source)}")
            files.append(path.relative_to(source))
    if Path("server.py") not in files or Path("web/index.html") not in files:
        raise OSError("harness/mission_control is incomplete (server.py or web/index.html missing)")
    return files


def install_app(home: Path, source: Path = SOURCE) -> int:
    """Copy the app into a staged directory, then swap it in by rename. Returns the file count."""
    files = source_files(source)
    for directory in (home / ".agent-harness", mc_root(home)):
        real_dir(directory)
    root = mc_root(home)
    staged = root / f".app-{secrets.token_hex(6)}"
    staged.mkdir(mode=0o700)
    try:
        for relative in files:
            target = staged / relative
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            data = (source / relative).read_bytes()
            fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
        app, previous = app_dir(home), root / "app.prev"
        for path in (app, previous):
            if path.is_symlink():
                raise OSError(f"{path} is a symlink; inspect it before installing")
        if previous.exists():
            shutil.rmtree(previous)  # only the copy this installer made one install ago
        if app.exists():
            os.rename(app, previous)
        os.rename(staged, app)
    except BaseException:
        shutil.rmtree(staged, ignore_errors=True)
        raise
    return len(files)


def default_runner(argv: list[str]):
    return subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=120, check=False)


def service_argv(home: Path, verb: str, python: str = "/usr/bin/python3") -> list[str]:
    """The installed server's own launchd command; /usr/bin/python3 survives Homebrew upgrades."""
    argv = [python, str(app_dir(home) / "server.py"), verb, "--apply"]
    if verb == "install-launchd":
        argv += ["--python", python]
    return argv


def run_service(home: Path, verb: str, run) -> str:
    try:
        result = run(service_argv(home, verb))
    except (OSError, subprocess.TimeoutExpired) as error:
        return f"{verb} failed ({error.__class__.__name__})"
    code = getattr(result, "returncode", 1)
    if code:
        tail = (getattr(result, "stderr", "") or getattr(result, "stdout", "") or "").strip()[-200:]
        return f"{verb} failed (exit {code}): {tail}"
    return "ok"


def status(home: Path, apply: bool, flag=None, *, run=None, system: str | None = None,
           source: Path = SOURCE) -> str:
    """One status line; never raises."""
    try:
        home = home.expanduser().resolve()
        system = system or sys.platform
        is_real = home == real_home()
        enabled = choice(home, flag)
        if apply and flag is not None:
            save_choice(home, enabled)
        plist = home / "Library" / "LaunchAgents" / f"{LABEL}.plist"
        if not enabled:
            if not apply:
                return "mission control: would stay off (--no-mission-control remembered)"
            if is_real and system == "darwin" and plist.exists() and (app_dir(home) / "server.py").is_file():
                result = run_service(home, "uninstall-launchd", run or default_runner)
                return f"mission control: off; LaunchAgent stopped ({result}); files and chat data kept"
            return "mission control: off (remembered)"
        if not is_real and flag is None:
            return "mission control: skipped (non-default --home; pass --mission-control to copy the files)"
        files = source_files(source)
        service = is_real and system == "darwin"
        if not apply:
            return (f"mission control: would copy {len(files)} files to {app_dir(home)}"
                    + (f" and register the {LABEL} LaunchAgent" if service else ""))
        count = install_app(home, source)
        line = f"mission control: {count} files in {app_dir(home)}"
        if service:
            result = run_service(home, "install-launchd", run or default_runner)
            line += f"; LaunchAgent {LABEL}: {result}"
            if result == "ok":
                line += f"; open it with `python3 {app_dir(home) / 'server.py'} open`"
        elif is_real:
            line += f"; no launchd on {system}: run `python3 {app_dir(home) / 'server.py'} serve` yourself"
        return line
    except Exception as error:  # noqa: BLE001 - an optional component never fails the harness install
        return f"mission control: skipped ({error.__class__.__name__}: {str(error)[:160]})"
