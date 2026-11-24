"""Install the transcript archive backfill scheduler (GoodQA #16650): launchd on macOS, a systemd user timer on Linux.

Files written (each atomically, only when the bytes differ; a differing file is first saved as NAME.bak-STAMP):
  macOS: ~/Library/LaunchAgents/com.ericmacdougall.transcripts-backfill.plist (every 1800 s, Nice 10)
  Linux: ~/.config/systemd/user/transcripts-backfill.service and .timer (every 30 min, Nice=10)
Both run `~/.claude/hooks/transcripts.py backfill --budget-seconds 1500`, which install.py ships with the hooks.

Opt-in, because the backfill uploads redacted transcripts to private GitHub repos: `install.py --transcripts-backfill`
installs it and remembers the choice; `--no-transcripts-backfill` remembers the opposite and stops the job (files and
archived chunks stay). With no flag the remembered choice wins; with none, it is kept up to date only where its unit
file is already installed. The scheduler is (re)loaded only when a unit file changed or the job was never enabled,
and never for a non-default --home (the job belongs to the real user). Failures come back as one status line and
never fail the harness install. A symlinked destination or parent directory is refused.
"""

from __future__ import annotations

import json
import os
import platform
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from xml.sax.saxutils import escape

ROOT = Path(__file__).resolve().parent
LABEL = "com.ericmacdougall.transcripts-backfill"
UNITS = ("transcripts-backfill.service", "transcripts-backfill.timer")
CHOICE_FILE = "transcripts-backfill-choice.json"
STATE_FILE = "transcripts-backfill.scheduler"  # enabled | disabled: what the installer last succeeded in doing


class InstallRefused(Exception):
    pass


def real_home() -> Path:
    try:
        import pwd
        return Path(pwd.getpwuid(os.getuid()).pw_dir).resolve()
    except (ImportError, KeyError):
        return Path.home().resolve()


def unit_paths(home: Path, system: str) -> list[Path]:
    if system == "Darwin":
        return [home / "Library" / "LaunchAgents" / f"{LABEL}.plist"]
    return [home / ".config" / "systemd" / "user" / name for name in UNITS]


def component_installed(home: Path) -> bool:
    return any(p.is_file() for s in ("Darwin", "Linux") for p in unit_paths(home, s))


def desired_files(home: Path, system: str) -> list[tuple[Path, bytes, int, bool]]:
    """[(destination, bytes, mode, is_unit)] for this platform."""
    sched = ROOT / "harness" / "schedulers"
    if system == "Darwin":
        plist = (sched / f"{LABEL}.plist").read_text().replace("@HOME@", escape(str(home)))
        return [(unit_paths(home, system)[0], plist.encode(), 0o644, True)]
    return [(path, (sched / path.name).read_bytes(), 0o644, True) for path in unit_paths(home, system)]


def _read_small(path: Path, limit: int = 4096):
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    except OSError:
        return None
    try:
        return os.read(fd, limit).decode("utf-8", "replace")
    except OSError:
        return None
    finally:
        os.close(fd)


def read_choice(home: Path):
    text = _read_small(home / ".agent-harness" / CHOICE_FILE)
    try:
        value = json.loads(text).get("enabled") if text else None
    except (ValueError, AttributeError):
        return None
    return value if isinstance(value, bool) else None


def choice(home: Path, flag) -> bool:
    if flag is not None:
        return flag
    home = home.expanduser().resolve()
    remembered = read_choice(home)
    return remembered if remembered is not None else component_installed(home)


def save_choice(home: Path, enabled: bool) -> None:
    directory = home / ".agent-harness"
    if directory.is_symlink():
        raise InstallRefused(f"refusing a symlinked directory: {directory}")
    directory.mkdir(parents=True, exist_ok=True)
    write_atomic(directory / CHOICE_FILE, (json.dumps({"schema": 1, "enabled": enabled}) + "\n").encode(), 0o600)


def read_state(home: Path):
    text = (_read_small(home / ".agent-harness" / "logs" / STATE_FILE, 64) or "").strip()
    return text if text in ("enabled", "disabled") else None


def write_state(home: Path, value: str) -> None:
    write_atomic(home / ".agent-harness" / "logs" / STATE_FILE, (value + "\n").encode(), 0o600)


def check_path(path: Path, home: Path) -> None:
    for part in [path, *path.parents]:
        if part == home.parent:
            break
        if part.is_symlink():
            raise InstallRefused(f"refusing a symlinked path component: {part}")
    if path.exists() and not path.is_file():
        raise InstallRefused(f"destination is not a regular file: {path}")


def write_atomic(path: Path, data: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".{path.name}.tmp.{os.getpid()}")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
        os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def default_runner(argv: list[str]) -> int:
    return subprocess.run(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=60, check=False).returncode


def safe_run(run, argv: list[str]) -> int:
    try:
        return run(argv)
    except (OSError, subprocess.SubprocessError):
        return 127


def reload_scheduler(system: str, home: Path, uid: int, run) -> str:
    if system == "Darwin":
        domain = f"gui/{uid}"
        safe_run(run, ["launchctl", "enable", f"{domain}/{LABEL}"])
        safe_run(run, ["launchctl", "bootout", f"{domain}/{LABEL}"])  # fails harmlessly when not loaded
        code = safe_run(run, ["launchctl", "bootstrap", domain, str(unit_paths(home, system)[0])])
        return "loaded" if code == 0 else f"launchctl bootstrap failed (exit {code})"
    if safe_run(run, ["systemctl", "--user", "daemon-reload"]) != 0:
        return "systemctl --user daemon-reload failed (is a user session or linger active?)"
    code = safe_run(run, ["systemctl", "--user", "enable", "--now", "transcripts-backfill.timer"])
    return "enabled" if code == 0 else f"systemctl enable failed (exit {code})"


def disable_scheduler(system: str, uid: int, run) -> str:
    if system == "Darwin":
        off = safe_run(run, ["launchctl", "disable", f"gui/{uid}/{LABEL}"])
        code = safe_run(run, ["launchctl", "bootout", f"gui/{uid}/{LABEL}"])
        if off != 0:
            return f"launchctl disable failed (exit {off})"
        return "stopped" if code in (0, 3, 113) else f"launchctl bootout failed (exit {code})"
    code = safe_run(run, ["systemctl", "--user", "disable", "--now", "transcripts-backfill.timer"])
    return "stopped" if code == 0 else f"systemctl disable failed (exit {code})"


def status(home: Path, apply: bool, system: str | None = None, run=None, uid: int | None = None,
           activate: bool | None = None, enabled: bool | None = None) -> str:
    try:
        home = home.expanduser().resolve()
        system = system or platform.system()
        if system not in ("Darwin", "Linux"):
            return f"transcripts backfill: skipped (unsupported platform {system})"
        enabled = choice(home, None) if enabled is None else enabled
        activate = (home == real_home()) if activate is None else activate
        uid = os.getuid() if uid is None else uid
        run = run or default_runner
        state = read_state(home)
        if not enabled:
            if not component_installed(home):
                return "transcripts backfill: not installed (pass --transcripts-backfill to install it); nothing changed"
            if not activate or state == "disabled":
                return "transcripts backfill: disabled by choice; scheduler not touched"
            if not apply:
                return "transcripts backfill: disabled by choice; would stop the scheduler job (files stay)"
            result = disable_scheduler(system, uid, run)
            if result == "stopped":
                write_state(home, "disabled")
            return f"transcripts backfill: disabled by choice, scheduler {result}; files and archived chunks stay"
        files = desired_files(home, system)
        changed = []
        for path, data, _mode, _unit in files:
            check_path(path, home)
            if not path.exists() or path.read_bytes() != data:
                changed.append(path)
        reload = bool(changed) or state != "enabled"
        names = ", ".join(p.name for p in changed) or "no file changes"
        if not apply:
            if reload and activate:
                return f"transcripts backfill: would install {names}; would (re)load and enable the scheduler"
            return f"transcripts backfill: would install {names} (scheduler not touched)" if changed else \
                "transcripts backfill: up to date (would change nothing)"
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + f"-{os.getpid()}"
        for path, data, mode, _unit in files:
            if path in changed:
                if path.exists():
                    write_atomic(path.with_name(f"{path.name}.bak-{stamp}"), path.read_bytes(), 0o600)
                write_atomic(path, data, mode)
        if not activate:
            return "transcripts backfill: files written; scheduler not loaded (non-default --home)"
        if not reload:
            return "transcripts backfill: up to date (no scheduler reload)"
        result = reload_scheduler(system, home, uid, run)
        if result in ("loaded", "enabled"):
            write_state(home, "enabled")
        return f"transcripts backfill: installed, scheduler {result}"
    except (InstallRefused, OSError, subprocess.SubprocessError) as error:
        return f"transcripts backfill: skipped ({error.__class__.__name__}: {error})"
