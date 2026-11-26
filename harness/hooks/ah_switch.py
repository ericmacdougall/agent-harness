#!/usr/bin/env python3
"""The harness OFF/ON switch and the release floor (docs/off-switch.md).

  off [--reason TEXT] [--keep-services]  create ~/.agent-harness/OFF (every hook launcher exits 0 at once, running
                                    sessions too), move the harness instruction blocks out of ~/.claude/CLAUDE.md and
                                    ~/.codex/AGENTS.md into ~/.agent-harness/off-stash/, and stop the harness
                                    LaunchAgents (Linux: systemd user units) and remember which. Off means off:
                                    only --keep-services leaves the background jobs running.
  on                                put the stashed blocks back exactly, start the services `off` stopped, remove the
                                    flag last.
  status [--json]                   one line (or JSON): on or off, since when, by whom, what is stashed, the floor.
  floor-check                       report (never repair) that an installer that predates the floor (an old checkout's
                                    install.py) overwrote the installed release. Nothing rewrites settings.json except
                                    an explicit install.py --apply; `--repair` was removed in release 1001.

No guard, approval, WAL note or ticket is needed for any of these. Every run appends one line to
~/.agent-harness/logs/switch.log. Standard library only, Python 3.9, no imports from sibling modules.
"""
from __future__ import annotations

import argparse
import getpass
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
import time
from pathlib import Path

FLAVORS = {
    "claude": {"instructions": ".claude/CLAUDE.md", "start": "<!-- agent-harness:start -->",
               "end": "<!-- agent-harness:end -->", "settings": ".claude/settings.json",
               "hooks_dir": ".claude/hooks", "backups": ".claude/agent-harness-backups"},
    "codex": {"instructions": ".codex/AGENTS.md", "start": "<!-- agent-harness-codex:start -->",
              "end": "<!-- agent-harness-codex:end -->", "settings": ".codex/hooks.json",
              "hooks_dir": ".codex/agent-harness", "backups": ".codex/agent-harness/backups"},
}
LAUNCHER = "ah_hook.py"
INSTALL_STATE = "install-state.json"
FLOOR_LABEL = "com.agent-harness.floor"
FLOOR_UNIT = "agent-harness-floor"
# What the installers register on a host (log_backup_install, backup_watch, ops_watch, mission_control_install), and
# the floor watcher releases before 1001 installed (stopped while OFF wherever one is left). netwatch is a separate
# network monitor and stays.


def _label_prefix():
    """~/.agent-harness/local.json `launchd_label_prefix` (read inline: no sibling imports here; ah_local.label_prefix
    is the same rule)."""
    try:
        path = os.environ.get("AH_LOCAL_CONFIG") or os.path.join(os.path.expanduser("~"), ".agent-harness", "local.json")
        with open(os.path.expanduser(path), "rb") as handle:
            value = json.loads(handle.read(262144).decode("utf-8")).get("launchd_label_prefix")
        if isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.", value):
            return value
    except (OSError, ValueError, AttributeError):
        pass
    return "com.agent-harness."


MAC_LABELS = tuple(_label_prefix() + n for n in ("log-backup", "backup-watch", "ops-watch")) + (
    "com.agent-harness.mission-control", FLOOR_LABEL)
LINUX_UNITS = ("log-backup.timer", "backup-watch.timer", "ops-watch.timer", FLOOR_UNIT + ".path")
REMOVED_IN = 1001  # the release that removed `floor-check --repair` and the floor watcher
PENDING_SECONDS = 900  # an install that marked itself pending this recently is reported in progress, not as drift
KEEP_RELEASES = 2


# ----------------------------------------------------------------------------- small helpers
def home_dir(home=None) -> Path:
    return Path(home).expanduser() if home is not None else Path(os.environ.get("HOME") or os.path.expanduser("~"))


def ah_dir(home) -> Path:
    return home_dir(home) / ".agent-harness"


def now_iso(now=None) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() if now is None else now))


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def private_dir(path: Path) -> Path:
    if path.is_symlink():
        raise OSError(f"{path} is a symlink; refusing to write through it")
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    return path


def read_json(path: Path):
    try:
        with open(path, "rb") as handle:
            data = handle.read(8 * 1024 * 1024)
        return json.loads(data.decode("utf-8"))
    except (OSError, ValueError):
        return None


def read_text(path: Path):
    try:
        # input-ok: the harness's own release and install files, read by the user's switch command
        return path.read_bytes().decode("utf-8")
    except FileNotFoundError:
        return None


def write_atomic(path: Path, data: bytes, mode=None) -> None:
    """Replace path in one rename; a symlinked file is written through to its target (dotfile managers keep working)."""
    if path.is_symlink():
        path = path.resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    if mode is None:
        try:
            mode = stat.S_IMODE(path.stat().st_mode)
        except FileNotFoundError:
            mode = 0o600
    tmp = f".{path.name}.{secrets.token_hex(6)}.tmp"
    directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600,
                     dir_fd=directory)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
                os.fchmod(handle.fileno(), mode)
            os.replace(tmp, path.name, src_dir_fd=directory, dst_dir_fd=directory)
        except BaseException:
            try:
                os.unlink(tmp, dir_fd=directory)
            except FileNotFoundError:
                pass
            raise
    finally:
        os.close(directory)


def write_json(path: Path, data) -> None:
    write_atomic(path, (json.dumps(data, indent=2, sort_keys=True) + "\n").encode(), 0o600)


def log_line(home, name: str, text: str) -> None:
    """One line per run; a log failure never fails the switch."""
    try:
        logs = private_dir(ah_dir(home) / "logs")
        line = now_iso() + " " + re.sub(r"[\r\n\t]+", " ", text)[:600] + "\n"
        fd = os.open(logs / name, os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            os.write(fd, line.encode("utf-8", "replace"))
        finally:
            os.close(fd)
    except OSError:
        pass


def clean(text, limit=200) -> str:
    return re.sub(r"\s+", " ", str(text or "")).strip()[:limit]


# ----------------------------------------------------------------------------- the flag
def flag_path(home=None) -> Path:
    return ah_dir(home) / "OFF"


def is_off(home=None) -> bool:
    return os.path.exists(flag_path(home))


def flag_info(home=None):
    path = flag_path(home)
    if not os.path.exists(path):
        return None
    data = read_json(path)
    return data if isinstance(data, dict) else {}


# ----------------------------------------------------------------------------- instruction blocks
def marker_lines(lines, start, end):
    """Marker lines outside fenced Markdown examples (the same rule as install.markdown_marker_lines)."""
    starts, ends, fence = [], [], None
    for i, line in enumerate(lines):
        plain = line.rstrip("\r\n")
        opening = re.match(r"^ {0,3}(`{3,}|~{3,})", plain)
        if opening:
            run = opening.group(1)
            if fence is None:
                fence = (run[0], len(run))
            elif run[0] == fence[0] and len(run) >= fence[1] and not plain[opening.end():].strip():
                fence = None
            continue
        if fence is None:
            if plain == start:
                starts.append(i)
            elif plain == end:
                ends.append(i)
    return starts, ends


class Malformed(ValueError):
    pass


def split_block(text: str, start: str, end: str):
    """(text without the block, lead, block, offset) or None when there is no block. `lead` is one blank line before
    the block, removed with it so the file does not keep an empty gap; text[:offset] + lead + block + text[offset:]
    is the original, byte for byte."""
    lines = text.splitlines(keepends=True)
    starts, ends = marker_lines(lines, start, end)
    if not starts and not ends:
        return None
    if len(starts) != 1 or len(ends) != 1 or starts[0] >= ends[0]:
        raise Malformed("malformed harness markers; resolve them by hand")
    s, e = starts[0], ends[0]
    lead = ""
    if s > 0 and lines[s - 1].strip() == "":
        lead, s0 = lines[s - 1], s - 1
    else:
        s0 = s
    block = "".join(lines[s:e + 1])
    before = "".join(lines[:s0])
    return before + "".join(lines[e + 1:]), lead, block, len(before)


def stash_path(home, flavor) -> Path:
    return ah_dir(home) / "off-stash" / f"{flavor}.json"


def plan_stash(home, flavor, text: str, block=None):
    """What the instructions file should hold while OFF and the stash record to save. `block` replaces the stashed
    block text (an installer running while OFF hands its new block here, so `on` restores the current version)."""
    spec = FLAVORS[flavor]
    found = split_block(text, spec["start"], spec["end"])
    existing = read_json(stash_path(home, flavor))
    fresh = None
    if found:
        new_text, lead, old_block, offset = found
        fresh = {"lead": lead, "block": old_block, "offset": offset, "prefix_sha256": sha256(new_text[:offset].encode())}
    else:
        new_text = text
    if isinstance(existing, dict) and existing.get("block"):
        record = dict(existing)  # keep what the user had when they switched off, and where it was
        offset = record.get("offset")
        if not (isinstance(offset, int) and 0 <= offset <= len(new_text)
                and record.get("prefix_sha256") == sha256(new_text[:offset].encode())):
            record.update({k: v for k, v in fresh.items() if k != "block"} if fresh else
                          {"lead": "", "offset": None, "prefix_sha256": None})
    elif fresh:
        record = fresh
    elif block is not None:
        record = {"lead": "", "block": block, "offset": None, "prefix_sha256": None}
    else:
        return text, None
    if block is not None:
        record["block"] = block
    record.update(path=str(home_dir(home) / spec["instructions"]), flavor=flavor, at=now_iso())
    return new_text, record


def save_stash(home, flavor, record) -> None:
    private_dir(ah_dir(home) / "off-stash")
    write_json(stash_path(home, flavor), record)


def stash_block(home, flavor) -> str:
    spec = FLAVORS[flavor]
    path = home_dir(home) / spec["instructions"]
    text = read_text(path)
    if text is None:
        return "stashed earlier" if stash_path(home, flavor).exists() else "absent"
    try:
        new_text, record = plan_stash(home, flavor, text)
    except Malformed as error:
        return f"left in place ({error})"
    if record is None:
        return "absent"
    save_stash(home, flavor, record)  # the stash first: a crash after it loses nothing
    if new_text != text:
        write_atomic(path, new_text.encode("utf-8"))
        return "stashed"
    return "stashed earlier"


def restore_block(home, flavor) -> str:
    spath = stash_path(home, flavor)
    record = read_json(spath)
    if not isinstance(record, dict) or not record.get("block"):
        return "nothing stashed"
    spec = FLAVORS[flavor]
    path = home_dir(home) / spec["instructions"]
    text = read_text(path) or ""
    try:
        present = split_block(text, spec["start"], spec["end"]) is not None
    except Malformed:
        present = True
    if present:
        os.unlink(spath)
        return "already present"
    offset, prefix = record.get("offset"), record.get("prefix_sha256")
    block, lead = record["block"], record.get("lead") or ""
    if isinstance(offset, int) and 0 <= offset <= len(text) and prefix == sha256(text[:offset].encode()):
        new_text = text[:offset] + lead + block + text[offset:]
        how = "restored"
    else:  # the file changed while off: append, never rewrite the user's text
        base = text if not text or text.endswith("\n") else text + "\n"
        new_text = base + ("\n" if base.strip() else "") + block
        how = "restored at the end (the file changed while off)"
    write_atomic(path, new_text.encode("utf-8"))
    os.unlink(spath)
    return how


# ----------------------------------------------------------------------------- services
def default_run(argv) -> int:
    try:
        return subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True, timeout=30, check=False).returncode
    except (OSError, subprocess.SubprocessError):
        return 127


def system_name(system=None) -> str:
    system = system or sys.platform
    return "darwin" if system == "darwin" else "linux" if system.startswith("linux") else system


def services_path(home) -> Path:
    return ah_dir(home) / "off-stash" / "services.json"


def stop_services(home, run=None, system=None) -> list:
    run = run or default_run
    home = home_dir(home)
    stopped = read_json(services_path(home))
    stopped = stopped if isinstance(stopped, list) else []
    known = {item.get("name") for item in stopped if isinstance(item, dict)}
    system = system_name(system)
    if system == "darwin":
        domain = f"gui/{os.getuid()}"
        for label in MAC_LABELS:
            plist = home / "Library" / "LaunchAgents" / f"{label}.plist"
            if label in known or not plist.exists() or run(["launchctl", "print", f"{domain}/{label}"]) != 0:
                continue
            run(["launchctl", "disable", f"{domain}/{label}"])  # or the next login loads it again while off
            if run(["launchctl", "bootout", f"{domain}/{label}"]) in (0, 3, 113):
                stopped.append({"kind": "launchd", "name": label, "plist": str(plist)})
    elif system == "linux":
        units = home / ".config" / "systemd" / "user"
        for unit in LINUX_UNITS:
            # only a unit file the harness wrote under this home: a test or staged home never stops the real user's jobs
            if unit in known or not (units / unit).exists() \
                    or run(["systemctl", "--user", "is-active", "--quiet", unit]) != 0:
                continue
            enabled = run(["systemctl", "--user", "is-enabled", "--quiet", unit]) == 0
            if run(["systemctl", "--user", "disable" if enabled else "stop", *(["--now"] if enabled else []), unit]) == 0:
                stopped.append({"kind": "systemd", "name": unit, "enabled": enabled})
    if stopped:
        private_dir(ah_dir(home) / "off-stash")
        write_json(services_path(home), stopped)
    return [item["name"] for item in stopped]


def start_services(home, run=None, system=None) -> tuple:
    run = run or default_run
    path = services_path(home)
    stopped = read_json(path)
    if not isinstance(stopped, list):
        return [], []
    started, failed = [], []
    domain = f"gui/{os.getuid()}"
    for item in stopped:
        if not isinstance(item, dict):
            continue
        name = str(item.get("name"))
        if item.get("kind") == "launchd":
            run(["launchctl", "enable", f"{domain}/{name}"])
            ok = run(["launchctl", "bootstrap", domain, str(item.get("plist"))]) in (0, 5, 37)  # 5/37: already loaded
        elif item.get("kind") == "systemd":
            argv = ["systemctl", "--user", "enable", "--now", name] if item.get("enabled") else \
                ["systemctl", "--user", "start", name]
            ok = run(argv) == 0
        else:
            ok = False
        (started if ok else failed).append(name)
    remaining = [item for item in stopped if isinstance(item, dict) and item.get("name") in failed]
    if remaining:
        write_json(path, remaining)
    else:
        os.unlink(path)
    return started, failed


# ----------------------------------------------------------------------------- off / on / status
def switch_off(home=None, reason="", services=True, run=None, system=None) -> dict:
    """Off means off: the flag first, then the instruction blocks, then (unless services=False) the background jobs."""
    home = home_dir(home)
    private_dir(ah_dir(home))
    flag = flag_path(home)
    was_off = flag.exists()
    if not was_off:  # first, so every hook is silent before anything else changes
        write_json(flag, {"by": getpass.getuser(), "at": now_iso(), "reason": clean(reason),
                          "host": socket.gethostname().split(".")[0], "pid": os.getppid()})
    blocks = {}
    for flavor in FLAVORS:
        try:
            blocks[flavor] = stash_block(home, flavor)
        except OSError as error:
            blocks[flavor] = f"error: {error.__class__.__name__}"
    stopped = stop_services(home, run, system) if services else []
    result = {"off": True, "was_off": was_off, "blocks": blocks, "services_stopped": stopped}
    log_line(home, "switch.log", f"off by {getpass.getuser()} reason={clean(reason)!r} was_off={was_off} "
                                 + " ".join(f"{k}={v}" for k, v in blocks.items())
                                 + (f" services={','.join(stopped) or 'none'}" if services else ""))
    return result


def switch_on(home=None, run=None, system=None) -> dict:
    home = home_dir(home)
    blocks, errors = {}, []
    for flavor in FLAVORS:
        try:
            blocks[flavor] = restore_block(home, flavor)
        except OSError as error:
            blocks[flavor] = f"error: {error.__class__.__name__}"
            errors.append(flavor)
    started, failed = start_services(home, run, system)
    flag = flag_path(home)
    was_off = flag.exists()
    if was_off and not errors:
        os.unlink(flag)  # last: until here every hook stayed silent
    result = {"off": flag.exists(), "was_off": was_off, "blocks": blocks, "services_started": started,
              "services_failed": failed}
    log_line(home, "switch.log", f"on by {getpass.getuser()} was_off={was_off} "
                                 + " ".join(f"{k}={v}" for k, v in blocks.items())
                                 + f" services={','.join(started) or 'none'}" + (f" failed={','.join(failed)}" if failed else ""))
    return result


def status(home=None) -> dict:
    home = home_dir(home)
    state = read_json(ah_dir(home) / INSTALL_STATE)
    floor = read_json(ah_dir(home) / "floor.json")
    services = read_json(services_path(home))
    return {"off": is_off(home), "flag": flag_info(home),
            "stashed": [f for f in FLAVORS if stash_path(home, f).exists()],
            "services_stopped": [i.get("name") for i in services if isinstance(i, dict)] if isinstance(services, list) else [],
            "installed": (state or {}).get("flavors", {}) if isinstance(state, dict) else {},
            "floor": (floor or {}).get("flavors", {}) if isinstance(floor, dict) else {}}


def status_line(data: dict) -> str:
    floor = ", ".join(f"{k} {v.get('release')}" for k, v in sorted(data["floor"].items()) if isinstance(v, dict))
    tail = f" (floor: {floor})" if floor else ""
    if not data["off"]:
        return "harness: ON" + tail
    flag = data.get("flag") or {}
    bits = [f"since {flag.get('at', '?')}", f"by {flag.get('by', '?')}"]
    if flag.get("reason"):
        bits.append(f"reason: {flag['reason']}")
    extra = []
    if data["stashed"]:
        extra.append("instructions stashed: " + ", ".join(data["stashed"]))
    if data["services_stopped"]:
        extra.append("services stopped: " + ", ".join(data["services_stopped"]))
    return "harness: OFF " + " ".join(bits) + ("; " + "; ".join(extra) if extra else "") + tail + "; turn on: harness on"


# ----------------------------------------------------------------------------- install state, floor, snapshots
def read_state(home) -> dict:
    data = read_json(ah_dir(home) / INSTALL_STATE)
    return data if isinstance(data, dict) else {}


def update_state(home, change) -> dict:
    """Read, change and atomically rewrite install-state.json, keeping every key this change does not touch."""
    private_dir(ah_dir(home))
    state = read_state(home)
    state.setdefault("schema", 1)
    change(state)
    write_json(ah_dir(home) / INSTALL_STATE, state)
    return state


def mark_pending(home, flavor, release) -> None:
    update_state(home, lambda s: s.setdefault("pending", {}).__setitem__(flavor, {"release": release, "at": time.time()}))


def clear_pending(home, flavor) -> None:
    def change(state):
        pending = state.get("pending")
        if isinstance(pending, dict):
            pending.pop(flavor, None)
            if not pending:
                state.pop("pending")
    update_state(home, change)


def read_release(root) -> int:
    """harness/RELEASE of a checkout: one integer. A checkout without it predates the floor (release 0)."""
    try:
        # input-ok: the harness's own release and install files, read by the user's switch command
        return int((Path(root) / "harness" / "RELEASE").read_text().strip())
    except (OSError, ValueError):
        return 0


def source_commit(root) -> str:
    try:
        done = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"], capture_output=True, text=True, timeout=10)
        return done.stdout.strip() if done.returncode == 0 and re.fullmatch(r"[0-9a-f]{40}", done.stdout.strip()) else "unknown"
    except (OSError, subprocess.SubprocessError):
        return "unknown"


def floor_of(home, flavor):
    floor = read_json(ah_dir(home) / "floor.json")
    entry = ((floor or {}).get("flavors") or {}).get(flavor) if isinstance(floor, dict) else None
    return entry if isinstance(entry, dict) and isinstance(entry.get("release"), int) else None


def downgrade_refusal(home, flavor, release, allow=False):
    """One line when installing `release` would go below this host's floor; None when it may proceed."""
    entry = floor_of(home, flavor)
    if entry is None or release >= entry["release"] or allow:
        return None
    return (f"refusing to install release {release}: this host is at release {entry['release']} "
            f"(commit {str(entry.get('commit', '?'))[:12]}); this checkout is older. Use an up-to-date checkout, "
            "or pass --allow-downgrade to do it on purpose")


def newest_backup(home, flavor):
    root = home_dir(home) / FLAVORS[flavor]["backups"]
    try:
        names = [n for n in os.listdir(root) if re.fullmatch(r"\d{8}T\d{6}\d*Z-[0-9a-f]+", n)]
    except OSError:
        return None
    return max(names) if names else None


def write_snapshot(home, flavor, release, commit, files, settings_spec=None, instructions_spec=None) -> Path:
    """Copy the installed managed files (absolute paths under home) into releases/<release>/<flavor>/."""
    home = home_dir(home)
    rel_root = private_dir(ah_dir(home) / "releases" / str(int(release)))
    tmp = rel_root / f".tmp-{flavor}-{secrets.token_hex(4)}"
    os.mkdir(tmp, 0o700)
    try:
        manifest = {"release": int(release), "commit": commit, "flavor": flavor, "at": now_iso(), "files": {},
                    "settings": settings_spec, "instructions": instructions_spec}
        for path in files:
            path = Path(path)
            rel = path.relative_to(home).as_posix()
            # input-ok: the harness's own release and install files, read by the user's switch command
            data = path.read_bytes()
            target = tmp / "files" / rel
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            target.write_bytes(data)
            os.chmod(target, 0o600)
            manifest["files"][rel] = {"sha256": sha256(data), "mode": stat.S_IMODE(path.stat().st_mode)}
        write_json(tmp / "manifest.json", manifest)
        final = rel_root / flavor
        old = None
        if final.exists():
            old = rel_root / f".old-{flavor}-{secrets.token_hex(4)}"
            os.rename(final, old)
        os.rename(tmp, final)
        if old:
            shutil.rmtree(old, ignore_errors=True)
        return final
    except BaseException:
        shutil.rmtree(tmp, ignore_errors=True)
        raise


def read_snapshot(home, flavor, release):
    manifest = read_json(ah_dir(home) / "releases" / str(int(release)) / flavor / "manifest.json")
    return manifest if isinstance(manifest, dict) and isinstance(manifest.get("files"), dict) else None


def latest_snapshot(home, flavor):
    root = ah_dir(home) / "releases"
    try:
        releases = sorted((int(n) for n in os.listdir(root) if n.isdigit()), reverse=True)
    except OSError:
        return None
    for release in releases:
        snap = read_snapshot(home, flavor, release)
        if snap:
            return snap
    return None


def prune_releases(home, keep=KEEP_RELEASES) -> None:
    root = ah_dir(home) / "releases"
    floor = read_json(ah_dir(home) / "floor.json")
    pinned = {str(v.get("release")) for v in ((floor or {}).get("flavors") or {}).values() if isinstance(v, dict)} \
        if isinstance(floor, dict) else set()
    try:
        names = sorted((n for n in os.listdir(root) if n.isdigit()), key=int, reverse=True)
    except OSError:
        return
    for name in names[keep:]:
        path = root / name
        if name not in pinned and path.is_dir() and not path.is_symlink():
            shutil.rmtree(path, ignore_errors=True)


def record_install(home, flavor, release, commit, files, settings_spec=None, instructions_spec=None, backup=None) -> None:
    """After a successful install: snapshot, install state, then the floor (so a watcher never sees a floor without
    its snapshot), then keep the newest two releases."""
    home = home_dir(home)
    write_snapshot(home, flavor, release, commit, files, settings_spec, instructions_spec)

    def change(state):
        state.setdefault("flavors", {})[flavor] = {"release": int(release), "commit": commit, "backup": backup,
                                                  "at": now_iso()}
        releases = [v.get("release") for v in state["flavors"].values() if isinstance(v, dict)]
        state["release"] = max(r for r in releases if isinstance(r, int))
        state["commit"] = commit
        pending = state.get("pending")
        if isinstance(pending, dict):
            pending.pop(flavor, None)
            if not pending:
                state.pop("pending")
    update_state(home, change)
    floor = read_json(ah_dir(home) / "floor.json")
    floor = floor if isinstance(floor, dict) else {}
    floor.setdefault("schema", 1)
    floor.setdefault("flavors", {})[flavor] = {"release": int(release), "commit": commit, "at": now_iso()}
    floor["release"] = max(v["release"] for v in floor["flavors"].values())
    write_json(ah_dir(home) / "floor.json", floor)
    prune_releases(home)


# ----------------------------------------------------------------------------- hook wiring (report only)
def handler_tokens(handler) -> list:
    command = str(handler.get("command", ""))
    args = handler.get("args")
    if isinstance(args, list) and args:
        return [command, *[str(a) for a in args]]
    try:
        return shlex.split(command)
    except ValueError:
        return [command]


def is_managed_handler(handler, hooks_dir: str, names) -> bool:
    """A handler that runs a harness script from hooks_dir, directly (old installers) or through the launcher."""
    if not isinstance(handler, dict) or handler.get("type", "command") != "command":
        return False
    toks = handler_tokens(handler)
    if not toks or not re.fullmatch(r"python[0-9.]*", os.path.basename(toks[0])):
        return False
    i = 1
    while i < len(toks) and toks[i].startswith("-"):
        i += 1
    if i >= len(toks):
        return False
    path = os.path.normpath(os.path.expanduser(toks[i]))
    if os.path.dirname(path) != os.path.normpath(hooks_dir):
        return False
    name = os.path.basename(path)
    if name == LAUNCHER:
        return i + 1 < len(toks) and toks[i + 1] in names
    return name in names


def uses_launcher(handler, hooks_dir) -> bool:
    toks = handler_tokens(handler)
    return len(toks) > 1 and os.path.normpath(os.path.expanduser(toks[1])) == os.path.normpath(
        os.path.join(hooks_dir, LAUNCHER))


def managed_wiring(hooks, spec) -> list:
    """[(event, matcher, handler JSON)] for every harness handler in a hooks object, in file order. Read only: the floor
    check compares it with the snapshot's groups and never writes it back."""
    names, hooks_dir = set(spec.get("names") or ()), spec["hooks_dir"]
    out = []
    for event in sorted(hooks) if isinstance(hooks, dict) else ():
        for group in hooks[event] if isinstance(hooks[event], list) else ():
            if not isinstance(group, dict) or not isinstance(group.get("hooks"), list):
                continue
            for handler in group["hooks"]:
                if is_managed_handler(handler, hooks_dir, names):
                    out.append((event, group.get("matcher"), json.dumps(handler, sort_keys=True)))
    return out


def wiring_problems(hooks, spec) -> list:
    names, hooks_dir = set(spec.get("names") or ()), spec["hooks_dir"]
    direct = launcher = 0
    for groups in (hooks or {}).values() if isinstance(hooks, dict) else ():
        for group in groups if isinstance(groups, list) else ():
            for handler in (group.get("hooks") or []) if isinstance(group, dict) else ():
                if is_managed_handler(handler, hooks_dir, names):
                    if uses_launcher(handler, hooks_dir):
                        launcher += 1
                    else:
                        direct += 1
    out = []
    if direct:
        out.append(f"{direct} hook(s) wired directly, not through the launcher (an old installer's wiring)")
    if not launcher and spec.get("groups"):
        out.append("launcher wiring missing")
    return out


# ----------------------------------------------------------------------------- floor-check (report only)
def check_flavor(home, flavor, entry, state, now=None) -> dict:
    """What differs from the floor release. Writes nothing: the fix is `install.py --apply` from a current checkout."""
    now = time.time() if now is None else now
    home = home_dir(home)
    release = entry["release"]
    snap = read_snapshot(home, flavor, release)
    if not snap:
        return {"state": "no_snapshot", "release": release}
    fstate = (state.get("flavors") or {}).get(flavor) if isinstance(state.get("flavors"), dict) else None
    fstate = fstate if isinstance(fstate, dict) else {}
    pending = (state.get("pending") or {}).get(flavor) if isinstance(state.get("pending"), dict) else None
    if isinstance(pending, dict) and now - float(pending.get("at") or 0) < PENDING_SECONDS \
            and int(pending.get("release") or 0) >= release:
        return {"state": "install_in_progress", "release": release}
    installed = fstate.get("release")
    if isinstance(installed, int) and installed > release:
        return {"state": "newer_install", "release": release, "installed": installed}
    signals = []
    if not isinstance(installed, int):
        signals.append("install state has no release (an installer that predates the floor ran)")
    elif installed < release:
        signals.append(f"install state says release {installed}, below the floor {release}")
    backup = newest_backup(home, flavor)
    if backup and backup > str(fstate.get("backup") or ""):
        signals.append(f"an installer that does not record its release ran (backup {backup})")
    changed = []
    for rel, meta in sorted(snap["files"].items()):
        try:
            # input-ok: the harness's own release and install files, read by the user's switch command
            current = sha256((home / rel).read_bytes())
        except OSError:
            current = None
        if current != meta.get("sha256"):
            changed.append(rel)
    problems = []
    settings_spec = snap.get("settings")
    if isinstance(settings_spec, dict):
        settings_doc = read_json(home / settings_spec["path"])
        settings_doc = settings_doc if isinstance(settings_doc, dict) else {}
        current_hooks = settings_doc.get("hooks", {})
        if managed_wiring(current_hooks, settings_spec) != managed_wiring(settings_spec.get("groups") or {}, settings_spec):
            problems.extend(wiring_problems(current_hooks, settings_spec) or ["hook wiring differs from the floor"])
    ispec = snap.get("instructions")
    text = read_text(home / FLAVORS[flavor]["instructions"])
    if text is not None:
        try:
            found = split_block(text, FLAVORS[flavor]["start"], FLAVORS[flavor]["end"])
        except Malformed:
            found = None
        if found and is_off(home):
            problems.append("harness instructions present while OFF")
        elif found and signals and isinstance(ispec, dict) and ispec.get("block") and found[2] != ispec["block"]:
            problems.append("instructions block differs from the floor release")
    if changed and signals:
        problems.append(f"{len(changed)} managed file(s) differ from release {release}")
    result = {"state": "drift" if problems else "ok", "release": release, "problems": problems, "signals": signals,
              "changed_files": changed}
    if changed and not signals:
        result["note"] = f"{len(changed)} file(s) differ from the snapshot without an old-installer sign (hand edits?); left alone"
    return result


def floor_check(home=None, now=None) -> dict:
    home = home_dir(home)
    floor = read_json(ah_dir(home) / "floor.json")
    if not isinstance(floor, dict) or not isinstance(floor.get("flavors"), dict):
        return {"ok": True, "state": "no_floor", "flavors": {}}
    state = read_state(home)
    out = {}
    for flavor, entry in sorted(floor["flavors"].items()):
        if flavor in FLAVORS and isinstance(entry, dict) and isinstance(entry.get("release"), int):
            try:
                out[flavor] = check_flavor(home, flavor, entry, state, now)
            except (OSError, ValueError, KeyError) as error:
                out[flavor] = {"state": "error", "error": f"{error.__class__.__name__}: {clean(error)}"}
    bad = [f for f, r in out.items() if r["state"] in ("drift", "error")]
    return {"ok": not bad, "off": is_off(home), "flavors": out}


def floor_line(result) -> str:
    if result.get("state") == "no_floor":
        return "floor: none recorded (no install with a release yet)"
    parts = []
    for flavor, r in result["flavors"].items():
        text = f"{flavor} {r.get('release')}: {r['state']}"
        if r.get("problems"):
            text += " (" + "; ".join(r["problems"]) + ")"
        if r.get("note"):
            text += f" [{r['note']}]"
        parts.append(text)
    tail = "" if result["ok"] else "; fix: run install.py --apply from an up-to-date checkout"
    return "floor: " + ("; ".join(parts) or "nothing to check") + tail


# ----------------------------------------------------------------------------- the retired floor watcher
def floor_watch_units(home, system=None) -> list:
    """The files the floor watcher of releases before 1001 was installed as. Only its removal is left."""
    home = home_dir(home)
    if system_name(system) == "darwin":
        return [home / "Library" / "LaunchAgents" / f"{FLOOR_LABEL}.plist"]
    units = home / ".config" / "systemd" / "user"
    return [units / f"{FLOOR_UNIT}.path", units / f"{FLOOR_UNIT}.service"]


def remove_floor_watch(home, run=None, system=None) -> str:
    """Stop and delete an old release's floor watcher (it rewrote settings.json). Nothing installs it any more."""
    run = run or default_run
    home = home_dir(home)
    system = system_name(system)
    units = floor_watch_units(home, system) if system in ("darwin", "linux") else []
    if not any(path.exists() for path in units):
        return "floor watcher: not installed"
    if system == "darwin":
        run(["launchctl", "bootout", f"gui/{os.getuid()}/{FLOOR_LABEL}"])
    else:
        run(["systemctl", "--user", "disable", "--now", f"{FLOOR_UNIT}.path"])
    for path in units:
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
    if system == "linux":
        run(["systemctl", "--user", "daemon-reload"])
    return f"floor watcher: removed (release {REMOVED_IN} no longer runs it)"


# ----------------------------------------------------------------------------- CLI
def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="harness", description="Agent Harness off switch and release floor "
                                                             "(docs/off-switch.md)")
    ap.add_argument("--home", help=argparse.SUPPRESS)
    sub = ap.add_subparsers(dest="cmd", required=True)
    off = sub.add_parser("off", help="turn the harness off now (hooks silent, instructions stashed, background jobs "
                                     "stopped)")
    off.add_argument("--reason", default="")
    off.add_argument("--keep-services", dest="keep_services", action="store_true",
                     help="leave the harness LaunchAgents / systemd user units running")
    off.add_argument("--services", action="store_true", help=argparse.SUPPRESS)  # the default since 1001; a no-op
    off.add_argument("--json", action="store_true")
    on = sub.add_parser("on", help="turn it back on")
    on.add_argument("--json", action="store_true")
    st = sub.add_parser("status", help="on or off, and the floor")
    st.add_argument("--json", action="store_true")
    fc = sub.add_parser("floor-check", help="report an old installer's overwrite (read only)")
    fc.add_argument("--repair", action="store_true", help=argparse.SUPPRESS)  # removed in 1001: fails loudly
    fc.add_argument("--json", action="store_true")
    fc.add_argument("--quiet", action="store_true", help="print nothing unless something was found")
    args = ap.parse_args(argv)
    home = home_dir(args.home)
    if args.cmd == "off":
        result = switch_off(home, args.reason, services=not args.keep_services)
        print(json.dumps(result, indent=2) if args.json else status_line(status(home)))
        return 0
    if args.cmd == "on":
        result = switch_on(home)
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print(status_line(status(home)) + (f"; could not restart: {', '.join(result['services_failed'])}"
                                               if result["services_failed"] else ""))
        return 0 if not result["off"] else 1
    if args.cmd == "status":
        data = status(home)
        print(json.dumps(data, indent=2) if args.json else status_line(data))
        return 0
    if args.repair:
        print(f"harness floor-check: --repair was removed in release {REMOVED_IN}: nothing rewrites settings.json "
              "except an explicit install.py --apply; run that from an up-to-date checkout", file=sys.stderr)
        return 2
    result = floor_check(home)
    if args.json:
        print(json.dumps(result, indent=2))
    elif not args.quiet or any(r["state"] in ("drift", "error") for r in result.get("flavors", {}).values()):
        print(floor_line(result))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
