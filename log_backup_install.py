"""Install the scheduled agent log backup (GoodQA #14471): script, excludes, and the launchd or systemd units.

Files written (each atomically, only when the bytes differ; a differing hand-installed file is first saved as
NAME.bak-STAMP):
  ~/.agent-harness/bin/log-backup.sh, log-backup.excludes and log-backup.work-excludes
  macOS: ~/Library/LaunchAgents/com.ericmacdougall.log-backup.plist (label unchanged, so no second job appears)
  Linux: ~/.config/systemd/user/log-backup.service and log-backup.timer

The scheduler is (re)loaded only when a unit file changed, never while a backup run holds the lock, and never
when the installer targets a non-default --home (the job belongs to the real user). A failure here is returned as
one status line and never fails the harness install. A symlinked destination or parent directory is refused.

Opt-in: encryption at rest is not part of this component (GoodQA #14522), so a host that does not have it yet does
not get it from a routine install. `--log-backup` installs it and remembers the choice; `--no-log-backup` remembers
the opposite and, when the component is installed, stops its scheduler job (files and remote copies stay). With no
flag, the remembered choice wins; with none, the component is kept up to date only where it is already installed
(log-backup.excludes next to the script is the marker, so a hand-installed copy alone does not count).
"""

from __future__ import annotations

import json
import os
import platform
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from xml.sax.saxutils import escape

ROOT = Path(__file__).resolve().parent
LABEL = "com.ericmacdougall.log-backup"


class InstallRefused(Exception):
    pass


def real_home() -> Path:
    try:
        import pwd
        return Path(pwd.getpwuid(os.getuid()).pw_dir).resolve()
    except (ImportError, KeyError):
        return Path.home().resolve()


CHOICE_FILE = "log-backup-choice.json"
STATE_FILE = "log-backup.scheduler"      # what the installer last SUCCEEDED in doing to the scheduler: enabled | disabled
PENDING_FILE = "log-backup.reload-pending"   # an enable/disable that was deferred, failed or raised and must be retried


def logs_dir(home: Path) -> Path:
    return home / ".agent-harness" / "logs"


def read_scheduler_state(home: Path):
    """'enabled', 'disabled' or None (unknown: never set, unreadable, or anything else). Never follows a link."""
    try:
        fd = os.open(logs_dir(home) / STATE_FILE, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    except OSError:
        return None
    try:
        text = os.read(fd, 64).decode("utf-8", "replace").strip()
    except OSError:
        return None
    finally:
        os.close(fd)
    return text if text in ("enabled", "disabled") else None


def write_scheduler_state(home: Path, value: str) -> None:
    logs_dir(home).mkdir(parents=True, exist_ok=True)
    write_atomic(logs_dir(home) / STATE_FILE, (value + "\n").encode(), 0o600)


def component_installed(home: Path) -> bool:
    return (home / ".agent-harness" / "bin" / "log-backup.excludes").is_file()


def read_choice(home: Path):
    """True or False when a choice was remembered, else None. Never follows a link, never raises."""
    path = home / ".agent-harness" / CHOICE_FILE
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
    except OSError:
        return None
    try:
        data = json.loads(os.read(fd, 4096).decode("utf-8", "replace"))
    except (OSError, ValueError):
        return None
    finally:
        os.close(fd)
    value = data.get("enabled") if isinstance(data, dict) else None
    return value if isinstance(value, bool) else None


def choice(home: Path, flag) -> bool:
    """--log-backup/--no-log-backup win; else the remembered choice; else on only where the component already is."""
    if flag is not None:
        return flag
    remembered = read_choice(home.expanduser().resolve())
    return remembered if remembered is not None else component_installed(home.expanduser().resolve())


def save_choice(home: Path, enabled: bool) -> None:
    directory = home / ".agent-harness"
    if directory.is_symlink():
        raise InstallRefused(f"refusing a symlinked directory: {directory}")
    directory.mkdir(parents=True, exist_ok=True)
    write_atomic(directory / CHOICE_FILE, (json.dumps({"schema": 1, "enabled": enabled}) + "\n").encode(), 0o600)


def desired_files(home: Path, system: str) -> list[tuple[Path, bytes, int, bool]]:
    """[(destination, bytes, mode, is_unit)] for this platform."""
    bin_dir = home / ".agent-harness" / "bin"
    out = [(bin_dir / "log-backup.sh", (ROOT / "harness" / "bin" / "log-backup.sh").read_bytes(), 0o755, False),
           (bin_dir / "log-backup.excludes", (ROOT / "harness" / "bin" / "log-backup.excludes").read_bytes(), 0o644, False),
           (bin_dir / "log-backup.work-excludes", (ROOT / "harness" / "bin" / "log-backup.work-excludes").read_bytes(), 0o644, False)]
    sched = ROOT / "harness" / "schedulers"
    if system == "Darwin":
        plist = (sched / f"{LABEL}.plist").read_text().replace("@HOME@", escape(str(home)))
        out.append((home / "Library" / "LaunchAgents" / f"{LABEL}.plist", plist.encode(), 0o644, True))
    else:
        unit_dir = home / ".config" / "systemd" / "user"
        for name in ("log-backup.service", "log-backup.timer"):
            out.append((unit_dir / name, (sched / name).read_bytes(), 0o644, True))
    return out


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
        os.replace(tmp, path)  # a running bash script keeps its old inode; the next run sees the new one
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def backup_run_active(home: Path) -> bool:
    logs = home / ".agent-harness" / "logs"
    for name, limit in (("log-backup.transcripts.lock.d", 3600), ("log-backup.bulk.lock.d", 21600)):
        # The hand-installed script's locks: young means its run is going (an unreadable time counts as live).
        legacy = logs / name
        if legacy.is_dir():
            try:
                age = time.time() - legacy.stat().st_mtime
            except OSError:
                return True
            if -limit < age < limit:
                return True
    lock = logs / "log-backup.lock.d"
    pid_file = lock / "pid"
    if lock.is_dir() and not pid_file.exists():
        # The older hand-installed script uses the same lock directory without a pid: treat a young one as a run in
        # progress, so a scheduler reload never kills it.
        try:
            return time.time() - lock.stat().st_mtime < 86400
        except OSError:
            return False
    try:
        pid = int(pid_file.read_text().strip())
        if pid <= 1:
            return False
        if time.time() - lock.stat().st_mtime >= 86400:
            return False  # as in the script: a lock over a day old may carry a recycled pid
        os.kill(pid, 0)
    except (OSError, ValueError):
        return False
    return is_backup_process(pid)


def is_backup_process(pid: int) -> bool:
    """The pid runs `<shell> <path>/log-backup.sh`, as the script itself requires of a lock holder."""
    try:
        done = subprocess.run(["ps", "-p", str(pid), "-o", "args="], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                              timeout=10, check=False)
    except (OSError, subprocess.SubprocessError):
        return False
    args = done.stdout.decode("utf-8", "replace").strip()
    first, _, rest = args.partition(" ")
    if not rest or os.path.basename(first) not in ("sh", "bash", "dash", "zsh"):
        return False
    return not rest.startswith("-") and rest.endswith("log-backup.sh")


def default_runner(argv: list[str]) -> int:
    return subprocess.run(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=60, check=False).returncode


def safe_run(run, argv: list[str]) -> int:
    """A runner that raises (timeout, missing launchctl or systemctl) counts as a failed command, never as success."""
    try:
        return run(argv)
    except (OSError, subprocess.SubprocessError):
        return 127


def disable_scheduler(system: str, home: Path, uid: int, run) -> str:
    if system == "Darwin":
        # `disable` is the persistent part: it survives logout and reboot, so RunAtLoad cannot bring the job back from
        # the plist that stays in ~/Library/LaunchAgents. `bootout` then stops the loaded instance.
        off = safe_run(run, ["launchctl", "disable", f"gui/{uid}/{LABEL}"])
        code = safe_run(run, ["launchctl", "bootout", f"gui/{uid}/{LABEL}"])
        if off != 0:
            return f"launchctl disable failed (exit {off}); the job may return at the next login"
        return "stopped" if code in (0, 3, 113) else f"launchctl bootout failed (exit {code})"  # 3/113: not loaded
    code = safe_run(run, ["systemctl", "--user", "disable", "--now", "log-backup.timer"])
    return "stopped" if code == 0 else f"systemctl disable failed (exit {code})"


def reload_scheduler(system: str, home: Path, uid: int, run) -> str:
    run = lambda argv, _run=run: safe_run(_run, argv)  # noqa: E731
    if system == "Darwin":
        domain = f"gui/{uid}"
        plist = str(home / "Library" / "LaunchAgents" / f"{LABEL}.plist")
        run(["launchctl", "enable", f"{domain}/{LABEL}"])  # undo an earlier --no-log-backup, or bootstrap is refused
        run(["launchctl", "bootout", f"{domain}/{LABEL}"])  # fails harmlessly when not loaded
        code = run(["launchctl", "bootstrap", domain, plist])
        return "loaded" if code == 0 else f"launchctl bootstrap failed (exit {code})"
    if run(["systemctl", "--user", "daemon-reload"]) != 0:
        return "systemctl --user daemon-reload failed (is a user session or linger active?)"
    code = run(["systemctl", "--user", "enable", "--now", "log-backup.timer"])
    run(["systemctl", "--user", "restart", "log-backup.timer"])
    return "enabled" if code == 0 else f"systemctl enable failed (exit {code})"


def status(home: Path, apply: bool, system: str | None = None, run=None, uid: int | None = None,
           activate: bool | None = None, enabled: bool | None = None) -> str:
    try:
        home = home.expanduser().resolve()
        system = system or platform.system()
        if system not in ("Darwin", "Linux"):
            return f"log backup: skipped (unsupported platform {system})"
        if enabled is None:
            enabled = choice(home, None)
        if not enabled:
            if not component_installed(home):
                return "log backup: not installed on this host (pass --log-backup to install it); nothing changed"
            if not apply:
                return "log backup: disabled by choice; would stop the scheduler job (files stay)"
            if activate is None:
                activate = home == real_home()
            if not activate:
                return "log backup: disabled by choice (non-default --home); scheduler not touched"
            if read_scheduler_state(home) == "disabled" and not (logs_dir(home) / PENDING_FILE).exists():
                return "log backup: disabled by choice; scheduler already stopped; nothing changed"
            pending = logs_dir(home) / PENDING_FILE
            pending.parent.mkdir(parents=True, exist_ok=True)
            if backup_run_active(home):
                pending.write_text("disable deferred\n")
                return "log backup: disabled by choice; scheduler stop deferred while a backup runs; re-run install"
            pending.write_text("disable started\n")  # stays if the stop fails or raises
            result = disable_scheduler(system, home, os.getuid() if uid is None else uid, run or default_runner)
            if result == "stopped":
                write_scheduler_state(home, "disabled")
                try:
                    pending.unlink()
                except OSError:
                    pass
            return f"log backup: disabled by choice, scheduler {result}; files and remote copies stay"
        files = desired_files(home, system)
        changed, units_changed = [], False
        for path, data, _mode, is_unit in files:
            check_path(path, home)
            if not path.exists() or path.read_bytes() != data:
                changed.append(path)
                units_changed = units_changed or is_unit
        if not apply:
            return "log backup: would install " + (", ".join(p.name for p in changed) if changed else "nothing (up to date)")
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + f"-{os.getpid()}"
        for path, data, mode, _unit in files:
            if path not in changed:
                continue
            if path.exists():
                write_atomic(path.with_name(f"{path.name}.bak-{stamp}"), path.read_bytes(), 0o600)
            write_atomic(path, data, mode)
        if activate is None:
            activate = home == real_home()
        pending = logs_dir(home) / PENDING_FILE
        if activate and not units_changed and (pending.exists() or read_scheduler_state(home) != "enabled"):
            # An earlier enable/disable was deferred or failed, or the job was last switched off (or never known to be
            # on): the files being unchanged says nothing about the scheduler, so enable it now.
            units_changed = True
        if not units_changed:
            return "log backup: up to date (no scheduler reload)" if not changed else \
                "log backup: script updated (scheduler untouched)"
        if not activate:
            return "log backup: files written; scheduler not loaded (non-default --home)"
        pending.parent.mkdir(parents=True, exist_ok=True)
        if backup_run_active(home):
            pending.write_text("reload deferred\n")
            return "log backup: units written; scheduler reload deferred while a backup runs; re-run install to finish it"
        pending.write_text("reload started\n")  # stays if the reload fails or raises; the next install finishes it
        result = reload_scheduler(system, home, os.getuid() if uid is None else uid, run or default_runner)
        if result in ("loaded", "enabled"):
            write_scheduler_state(home, "enabled")
            try:
                pending.unlink()
            except OSError:
                pass
        return f"log backup: installed, scheduler {result}"
    except (InstallRefused, OSError, subprocess.SubprocessError) as error:
        return f"log backup: skipped ({error.__class__.__name__}: {error})"
