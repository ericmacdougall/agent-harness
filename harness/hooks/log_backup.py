#!/usr/bin/env python3
"""Agent log backup companion (GoodQA #14471): freshness check, SessionStart alert, status and restore.

The backup itself is harness/bin/log-backup.sh (copy only, scheduled by launchd or systemd). It writes
~/.agent-harness/logs/log-backup.last-ok only after every source copied cleanly. A run skipped because of a held
lock writes log-backup.last-skip instead, which this tool never treats as success.

  check          exit 0 fresh, 1 stale, 2 missing or invalid (a future timestamp is invalid)
  session-start  SessionStart hook: prints an alert only when the backup is not fresh; always exits 0
  status         last success, last run, last skip and lock holder
  restore        copy one backed-up source from the remote into an empty scratch directory and compare it

The remote is selected exactly as the script does (LOG_BACKUP_REMOTE, else the first of lessons-dropbox: or
dropbox: that `rclone listremotes` names), so a crypt overlay remote added later is honoured by both.
Nothing here prints rclone configuration or runs a remote delete, sync, purge or move.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

MAX_AGE_SECONDS = 3600
FUTURE_TOLERANCE_SECONDS = 300
LAST_OK = "log-backup.last-ok"
LAST_SKIP = "log-backup.last-skip"
LAST_RUN = "log-backup.last-run"
LOCK_DIR = "log-backup.lock.d"
REMOTE_CANDIDATES = ("lessons-dropbox", "dropbox")
MAX_STAMP_BYTES = 256
HASH_BLOCK = 1 << 20


def logs_dir(home: Path) -> Path:
    return home / ".agent-harness" / "logs"


def read_small(path: Path) -> str | None:
    """Text of a small regular file, or None. Never follows a symlink, never reads more than MAX_STAMP_BYTES."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_NONBLOCK", 0))
    except OSError:
        return None
    try:
        import stat
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return None
        return os.read(fd, MAX_STAMP_BYTES).decode("utf-8", "replace")
    except OSError:
        return None
    finally:
        os.close(fd)


def parse_stamp(text: str | None) -> float | None:
    """Epoch seconds from a leading ISO-8601 UTC stamp such as 2026-11-04T23:49:19Z, else None."""
    if not text:
        return None
    word = text.strip().split()[0] if text.strip() else ""
    try:
        return datetime.strptime(word, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp()
    except ValueError:
        return None


def classify(home: Path, now: float | None = None, max_age: int = MAX_AGE_SECONDS) -> dict:
    """{'state': fresh|stale|missing|invalid, 'age': seconds or None, ...}. Only last-ok can make a backup fresh."""
    now = time.time() if now is None else now
    text = read_small(logs_dir(home) / LAST_OK)
    if text is None:
        return {"state": "missing", "age": None}
    stamp = parse_stamp(text)
    if stamp is None:
        return {"state": "invalid", "age": None}
    age = now - stamp
    if age < -FUTURE_TOLERANCE_SECONDS:
        return {"state": "invalid", "age": age}
    age = max(age, 0.0)
    return {"state": "fresh" if age <= max_age else "stale", "age": age}


def printable(text: str) -> str:
    """Control characters stripped: state files are untrusted when shown on a terminal."""
    return "".join(c if c.isprintable() or c == " " else "?" for c in text.strip())


def human_age(seconds: float | None) -> str:
    if seconds is None:
        return "unknown"
    seconds = int(seconds)
    hours, rest = divmod(seconds, 3600)
    return f"{hours}h{rest // 60:02d}m" if hours else f"{rest // 60}m{rest % 60:02d}s"


def alert_text(result: dict, max_age: int = MAX_AGE_SECONDS) -> str:
    if result["state"] == "missing":
        return ("LOG BACKUP ALERT: no successful agent log backup has ever completed on this host "
                f"({LAST_OK} is missing). Check ~/.agent-harness/logs/log-backup.log and the scheduler.")
    if result["state"] == "invalid":
        return ("LOG BACKUP ALERT: the backup success marker is unreadable or dated in the future; "
                "treat the logs as NOT backed up. See ~/.agent-harness/logs/log-backup.log.")
    return (f"LOG BACKUP ALERT: the last successful agent log backup was {human_age(result['age'])} ago "
            f"(limit {max_age // 60} min). Do not delete or prune Claude/Codex logs until "
            "`python3 ~/.claude/hooks/log_backup.py status` shows a fresh backup.")


def run_note(home: Path) -> str:
    """Say so when a backup run is in progress: a long run does not hide a stale backup, it explains it."""
    lock = logs_dir(home) / LOCK_DIR
    if "held by pid" not in lock_holder(home):
        return ""
    try:
        since = max(0, int(time.time() - lock.stat().st_mtime))
    except OSError:
        return ""
    return f" A backup run has held the lock for {human_age(since)} and has not finished."


def cmd_check(args) -> int:
    result = classify(args.home, max_age=args.max_age)
    if args.json:
        print(json.dumps(result))
    else:
        print("fresh" if result["state"] == "fresh" else alert_text(result, args.max_age) + run_note(args.home))
    return {"fresh": 0, "stale": 1}.get(result["state"], 2)


def cmd_session_start(args) -> int:
    try:
        try:
            sys.stdin.read(65536)  # the hook payload is not needed; drain a bounded amount
        except (OSError, ValueError):
            pass
        result = classify(args.home, max_age=args.max_age)
        if result["state"] != "fresh":
            text = alert_text(result, args.max_age) + run_note(args.home)
            print(json.dumps({"hookSpecificOutput": {"hookEventName": "SessionStart", "additionalContext": text},
                              "systemMessage": text}))
    except Exception:  # noqa: BLE001 - a status hook must never break a session
        pass
    return 0


def lock_holder(home: Path) -> str:
    lock = logs_dir(home) / LOCK_DIR
    if not lock.is_dir():
        return "none"
    pid = (read_small(lock / "pid") or "").strip()
    if not pid.isdigit():
        return "held (pid unknown)"
    try:
        os.kill(int(pid), 0)
        return f"held by pid {pid}"
    except ProcessLookupError:
        return f"stale (pid {pid} is gone)"
    except PermissionError:
        return f"held by pid {pid}"


def cmd_status(args) -> int:
    result = classify(args.home, max_age=args.max_age)
    logs = logs_dir(args.home)
    print(f"last success : {printable(read_small(logs / LAST_OK) or 'never')} (age {human_age(result['age'])}, {result['state']})")
    print(f"last run     : {printable(read_small(logs / LAST_RUN) or 'never')}")
    print(f"last skipped : {printable(read_small(logs / LAST_SKIP) or 'never')} (a skipped run is not a backup)")
    print(f"lock         : {lock_holder(args.home)}")
    return 0 if result["state"] == "fresh" else 1


# ---- restore -------------------------------------------------------------------------------------------------

class RestoreError(Exception):
    pass


def inside(path: str, root: str) -> bool:
    """True when path is root or below it. Compared case-insensitively: APFS and HFS+ volumes usually are."""
    path, root = os.path.normcase(path), os.path.normcase(root)
    if sys.platform == "darwin":
        path, root = path.lower(), root.lower()
    try:
        return os.path.commonpath([path, root]) == root
    except ValueError:
        return False


def has_symlink_component(path: Path) -> bool:
    """A symlink anywhere in the path, except root-owned system ones such as macOS /tmp and /var."""
    for part in [path, *path.parents]:
        try:
            if part.is_symlink() and os.lstat(part).st_uid != 0:
                return True
        except OSError:
            return True
    return False


def validate_into(into: str, home: Path) -> Path:
    """The target must be absolute, free of `..` and symlinks, empty or absent, and outside every live tree
    (~/.claude, ~/.codex, ~/.agent-harness: the last holds other sessions' work, which is itself a backup source)."""
    raw = Path(into)
    if not raw.is_absolute():
        raise RestoreError("--into must be an absolute path")
    if ".." in raw.parts:
        raise RestoreError("--into must not contain '..'")
    if has_symlink_component(raw):
        raise RestoreError("--into must not be, or sit below, a symlink")
    real = os.path.realpath(raw)
    for live in (home / ".claude", home / ".codex", home / ".agent-harness"):
        if inside(real, os.path.realpath(live)):
            raise RestoreError(f"refusing to restore inside the live tree {live}")
    if raw.exists() and (not raw.is_dir() or any(raw.iterdir())):
        raise RestoreError("--into must be an empty directory")
    return Path(real)


def validate_src(src: str) -> str:
    parts = Path(src).parts if src else ()
    if (not parts or src.startswith("/") or src.startswith("-")
            or any(part in (".", "..") or not re.fullmatch(r"[A-Za-z0-9._@=+,-][A-Za-z0-9._ @=+,-]*", part) for part in parts)):
        raise RestoreError("--src must be a relative path such as .claude/projects")
    return "/".join(parts)


def validate_host(host: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9._-]*", host) or ".." in host:
        raise RestoreError("--host may contain only letters, digits, '.', '_' and '-'")
    return host


def list_remotes(rclone: str) -> dict[str, str]:
    """{name: type} from `rclone listremotes --long` (names and types only; never configuration)."""
    try:
        done = subprocess.run([rclone, "listremotes", "--long", "--ask-password=false"], stdin=subprocess.DEVNULL, env=clean_env(),
                              stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=60, check=False)
    except (OSError, subprocess.SubprocessError) as error:
        raise RestoreError(f"cannot run {rclone} ({error.__class__.__name__})")
    out = {}
    for line in done.stdout.decode("utf-8", "replace").splitlines():
        words = line.split()
        if words and words[0].endswith(":"):
            out[words[0][:-1]] = words[1] if len(words) > 1 else ""
    return out


def resolve_base(rclone: str, environ=os.environ) -> str:
    """Same selection rules as log-backup.sh: an explicit NAME:path must name a configured remote."""
    base = environ.get("LOG_BACKUP_REMOTE", "")
    if base.startswith("/"):
        if environ.get("LOG_BACKUP_ALLOW_LOCAL") == "1":
            return base
        raise RestoreError("LOG_BACKUP_REMOTE must be NAME:path")
    remotes = list_remotes(rclone)
    if base:
        if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]*:[A-Za-z0-9_./-]*", base) or ".." in base:
            raise RestoreError("LOG_BACKUP_REMOTE is not a plain NAME:path")
        if remotes.get(base.split(":", 1)[0]) not in ("dropbox", "crypt"):
            raise RestoreError("LOG_BACKUP_REMOTE must name a configured dropbox or crypt remote")
        return base
    for name in REMOTE_CANDIDATES:
        if remotes.get(name) in ("dropbox", "crypt"):
            return f"{name}:Backups/agent-logs"
    raise RestoreError("no usable rclone remote (expected lessons-dropbox: or dropbox:); set LOG_BACKUP_REMOTE")


def clean_env() -> dict:
    """Inherited RCLONE_* options (other than the config path) must not redirect or reconfigure a restore."""
    return {k: v for k, v in os.environ.items() if not k.startswith("RCLONE_") or k == "RCLONE_CONFIG"}


def run_rclone(argv: list[str], timeout: int) -> tuple[int, bytes]:
    try:
        done = subprocess.run(argv, env=clean_env(), stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=timeout, check=False)
    except (OSError, subprocess.SubprocessError) as error:
        raise RestoreError(f"rclone failed to run ({error.__class__.__name__})")
    return done.returncode, done.stdout[:64 * 1024 * 1024]


def sha256_of(path: str, limit: int | None = None) -> str:
    digest, left = hashlib.sha256(), limit
    with open(path, "rb") as handle:
        while left is None or left > 0:
            block = handle.read(HASH_BLOCK if left is None else min(HASH_BLOCK, left))
            if not block:
                break
            digest.update(block)
            if left is not None:
                left -= len(block)
    return digest.hexdigest()


def compare_to_live(restored_root: Path, live_root: Path, single: bool) -> dict:
    """Classify each restored file against the live copy: identical, grown (a byte prefix of a longer live file),
    differing, or no-live (the live file is gone; nothing to compare)."""
    out = {"identical": 0, "grown": 0, "differing": [], "no_live": 0, "files": 0}
    files = [restored_root] if single else [
        Path(root) / name for root, _dirs, names in os.walk(restored_root) for name in names]
    for path in sorted(files):
        if path.is_symlink() or not path.is_file():
            continue
        out["files"] += 1
        rel = path.name if single else os.path.relpath(path, restored_root)
        live = live_root if single else live_root / rel
        if live.is_symlink() or not live.is_file():
            out["no_live"] += 1
            continue
        size, live_size = path.stat().st_size, live.stat().st_size
        if size == live_size and sha256_of(str(path)) == sha256_of(str(live)):
            out["identical"] += 1
        elif size < live_size and sha256_of(str(path)) == sha256_of(str(live), size):
            out["grown"] += 1
        else:
            out["differing"].append(rel)
    out["differing"] = out["differing"][:50]
    return out


def cmd_restore(args) -> int:
    home = args.home
    try:
        src = validate_src(args.src)
        host = validate_host(args.host)
        into = validate_into(args.into, home)
        base = resolve_base(args.rclone)
        remote = f"{base}/{host}/{src}"
        code, stat_out = run_rclone([args.rclone, "lsjson", "--stat", "--", remote], args.timeout)
        if code != 0:
            raise RestoreError("the backed-up source was not found on the remote (or the remote is unreachable)")
        try:
            is_dir = bool(json.loads(stat_out.decode("utf-8"))["IsDir"])
        except (ValueError, KeyError, TypeError):
            raise RestoreError("unexpected rclone lsjson output")
        try:
            into.mkdir(mode=0o700, parents=True, exist_ok=True)
        except OSError as error:
            raise RestoreError(f"cannot create --into ({error.__class__.__name__})")
        if any(into.iterdir()):
            raise RestoreError("--into must be an empty directory")
        target = into / src
        target.parent.mkdir(parents=True, exist_ok=True)
        code, _ = run_rclone([args.rclone, "copyto", "--", remote, str(target)], args.timeout)
        if code != 0:
            raise RestoreError(f"rclone copyto failed (exit {code})")
        # Remote and restored copy must agree by checksum (rclone check, source side only).
        if is_dir:
            check = [args.rclone, "check", "--one-way", "--download", "--", remote, str(target)]
        else:
            check = [args.rclone, "check", "--one-way", "--download", "--include", "/" + target.name, "--",
                     remote.rsplit("/", 1)[0], str(target.parent)]
        code, _ = run_rclone(check, args.timeout)
        if code != 0:
            raise RestoreError(f"restored files do not match the remote (rclone check exit {code})")
        report = compare_to_live(target, home / src, single=not is_dir)
    except RestoreError as error:
        print(f"restore: {error}", file=sys.stderr)
        return 2
    print(json.dumps({"restored_into": str(into), "src": src, **report}))
    if report["files"] == 0:
        print("restore: nothing was restored", file=sys.stderr)
        return 1
    if report["differing"]:
        print("restore: restored files differ from the live copies", file=sys.stderr)
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--home", type=Path, default=Path(os.path.expanduser("~")), help=argparse.SUPPRESS)
    sub = parser.add_subparsers(dest="action", required=True)
    for name, handler in (("check", cmd_check), ("session-start", cmd_session_start), ("status", cmd_status)):
        cmd = sub.add_parser(name)
        cmd.add_argument("--max-age", type=int, default=MAX_AGE_SECONDS, help="seconds before stale (default 3600)")
        if name == "check":
            cmd.add_argument("--json", action="store_true")
        cmd.set_defaults(func=handler)
    restore = sub.add_parser("restore", help="restore one source from the remote into an empty scratch directory")
    restore.add_argument("--src", required=True, help="source relative to HOME, e.g. .claude/projects")
    restore.add_argument("--into", required=True, help="empty scratch directory (never a live tree)")
    restore.add_argument("--host", default=os.environ.get("LOG_BACKUP_HOST") or os.uname().nodename.split(".")[0])
    restore.add_argument("--rclone", default=os.environ.get("LOG_BACKUP_RCLONE", "rclone"))
    restore.add_argument("--timeout", type=int, default=3600)
    restore.set_defaults(func=cmd_restore)
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
