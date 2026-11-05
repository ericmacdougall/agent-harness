"""Install the scheduled agent log backup (GoodQA #14471): script, excludes, and the launchd or systemd units.

Files written (each atomically, only when the bytes differ; a differing hand-installed file is first saved as
NAME.bak-STAMP):
  ~/.agent-harness/bin/log-backup.sh and log-backup.excludes
  macOS: ~/Library/LaunchAgents/com.ericmacdougall.log-backup.plist (label unchanged, so no second job appears)
  Linux: ~/.config/systemd/user/log-backup.service and log-backup.timer

The scheduler is (re)loaded only when a unit file changed, never while a backup run holds the lock, and never
when the installer targets a non-default --home (the job belongs to the real user). A failure here is returned as
one status line and never fails the harness install. A symlinked destination or parent directory is refused.
"""

from __future__ import annotations

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
        os.kill(pid, 0)
        return True
    except (OSError, ValueError):
        return False


def default_runner(argv: list[str]) -> int:
    return subprocess.run(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=60, check=False).returncode


def reload_scheduler(system: str, home: Path, uid: int, run) -> str:
    if system == "Darwin":
        domain = f"gui/{uid}"
        plist = str(home / "Library" / "LaunchAgents" / f"{LABEL}.plist")
        run(["launchctl", "bootout", f"{domain}/{LABEL}"])  # fails harmlessly when not loaded
        code = run(["launchctl", "bootstrap", domain, plist])
        return "loaded" if code == 0 else f"launchctl bootstrap failed (exit {code})"
    if run(["systemctl", "--user", "daemon-reload"]) != 0:
        return "systemctl --user daemon-reload failed (is a user session or linger active?)"
    code = run(["systemctl", "--user", "enable", "--now", "log-backup.timer"])
    run(["systemctl", "--user", "restart", "log-backup.timer"])
    return "enabled" if code == 0 else f"systemctl enable failed (exit {code})"


def status(home: Path, apply: bool, system: str | None = None, run=None, uid: int | None = None,
           activate: bool | None = None) -> str:
    try:
        home = home.expanduser().resolve()
        system = system or platform.system()
        if system not in ("Darwin", "Linux"):
            return f"log backup: skipped (unsupported platform {system})"
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
        pending = home / ".agent-harness" / "logs" / "log-backup.reload-pending"
        if pending.exists() and not units_changed and activate:
            units_changed = True  # an earlier reload was deferred or failed: finish it now
        if not units_changed:
            return "log backup: up to date (no scheduler reload)" if not changed else \
                "log backup: script updated (scheduler untouched)"
        if not activate:
            return "log backup: files written; scheduler not loaded (non-default --home)"
        pending.parent.mkdir(parents=True, exist_ok=True)
        if backup_run_active(home):
            pending.write_text("reload deferred\n")
            return "log backup: units written; scheduler reload deferred while a backup runs; re-run install to finish it"
        result = reload_scheduler(system, home, os.getuid() if uid is None else uid, run or default_runner)
        if result in ("loaded", "enabled"):
            try:
                pending.unlink()
            except OSError:
                pass
        else:
            pending.write_text("reload failed\n")
        return f"log backup: installed, scheduler {result}"
    except (InstallRefused, OSError, subprocess.SubprocessError) as error:
        return f"log backup: skipped ({error.__class__.__name__}: {error})"
