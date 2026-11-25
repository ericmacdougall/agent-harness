#!/usr/bin/env python3
"""The harness OFF/ON switch and the release floor (docs/off-switch.md).

  off [--reason TEXT] [--services]  create ~/.agent-harness/OFF (every hook launcher exits 0 at once, running sessions
                                    too), move the harness instruction blocks out of ~/.claude/CLAUDE.md and
                                    ~/.codex/AGENTS.md into ~/.agent-harness/off-stash/, and with --services stop the
                                    harness LaunchAgents (Linux: systemd user units) and remember which.
  on                                put the stashed blocks back exactly, start the services `off` stopped, remove the
                                    flag last.
  status [--json]                   one line (or JSON): on or off, since when, by whom, what is stashed, the floor.
  floor-check [--repair]            notice that an installer that predates the floor (an old checkout's install.py)
                                    overwrote the installed release, and with --repair put the floor snapshot back.

No guard, approval, WAL note or ticket is needed for any of these. Every run appends one line to
~/.agent-harness/logs/switch.log (floor repairs: logs/floor.log). Standard library only, Python 3.9, no imports from
sibling modules: the floor LaunchAgent runs it with `python3 -I`.
"""
from __future__ import annotations

import argparse
import copy
import getpass
import hashlib
import json
import os
import plistlib
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
# What the installers register on a host (install.py --services/ahd, log_backup_install, backup_watch, ops_watch,
# mission_control_install, ahc_install, and the floor watcher below). netwatch is a separate network monitor and stays.
MAC_LABELS = ("com.ericmacdougall.ahd", "com.ericmacdougall.log-backup", "com.ericmacdougall.backup-watch",
              "com.ericmacdougall.ops-watch", "com.agent-harness.mission-control", FLOOR_LABEL)
LINUX_UNITS = ("ahd.service", "log-backup.timer", "backup-watch.timer", "ops-watch.timer", "ahc-core.service",
               "ahc-review.service", FLOOR_UNIT + ".path")
PENDING_SECONDS = 900  # an install that marked itself pending this recently is never "repaired" underneath
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
        for unit in LINUX_UNITS:
            if unit in known or run(["systemctl", "--user", "is-active", "--quiet", unit]) != 0:
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
def switch_off(home=None, reason="", services=False, run=None, system=None) -> dict:
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


# ----------------------------------------------------------------------------- hook wiring (floor repair)
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


def repaired_hooks(hooks: dict, spec: dict) -> dict:
    """The hooks object with every managed handler removed and the snapshot's managed groups appended per event:
    the same result the installer's merge gives, so a repaired file matches a fresh install."""
    names, hooks_dir, wanted = set(spec.get("names") or ()), spec["hooks_dir"], spec.get("groups") or {}
    out = copy.deepcopy(hooks) if isinstance(hooks, dict) else {}
    for event in sorted(set(out) | set(wanted)):
        entries = out.get(event, [])
        if not isinstance(entries, list):
            continue
        preserved = []
        for group in entries:
            if not isinstance(group, dict) or not isinstance(group.get("hooks"), list):
                preserved.append(group)
                continue
            remaining = [h for h in group["hooks"] if not is_managed_handler(h, hooks_dir, names)]
            if remaining == group["hooks"]:
                preserved.append(group)
            elif remaining:
                preserved.append({**group, "hooks": remaining})
        preserved.extend(copy.deepcopy(wanted.get(event, [])))
        if preserved:
            out[event] = preserved
        elif entries:
            del out[event]
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


# ----------------------------------------------------------------------------- floor-check
def check_flavor(home, flavor, entry, state, repair=False, now=None) -> dict:
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
            current = sha256((home / rel).read_bytes())
        except OSError:
            current = None
        if current != meta.get("sha256"):
            changed.append(rel)
    problems = []
    settings_spec, new_hooks, settings_doc = snap.get("settings"), None, None
    if isinstance(settings_spec, dict):
        settings_doc = read_json(home / settings_spec["path"])
        settings_doc = settings_doc if isinstance(settings_doc, dict) else {}
        current_hooks = settings_doc.get("hooks", {})
        new_hooks = repaired_hooks(current_hooks, settings_spec)
        if json.dumps(new_hooks, sort_keys=True) != json.dumps(current_hooks if isinstance(current_hooks, dict) else {},
                                                                sort_keys=True):
            problems.extend(wiring_problems(current_hooks, settings_spec) or ["hook wiring differs from the floor"])
        else:
            new_hooks = None
    off = is_off(home)
    block_fix = None
    ispec = snap.get("instructions")
    ipath = home / FLAVORS[flavor]["instructions"]
    text = read_text(ipath)
    if text is not None:
        try:
            found = split_block(text, FLAVORS[flavor]["start"], FLAVORS[flavor]["end"])
        except Malformed:
            found = None
        if found and off:
            problems.append("harness instructions present while OFF")
            block_fix = "stash"
        elif found and signals and isinstance(ispec, dict) and ispec.get("block") and found[2] != ispec["block"]:
            problems.append("instructions block differs from the floor release")
            block_fix = "replace"
    if changed and signals:
        problems.append(f"{len(changed)} managed file(s) differ from release {release}")
    result = {"state": "drift" if problems else "ok", "release": release, "problems": problems, "signals": signals,
              "changed_files": changed}
    if changed and not signals:
        result["note"] = f"{len(changed)} file(s) differ from the snapshot without an old-installer sign (hand edits?); left alone"
    if not (repair and problems):
        return result
    fixed = []
    if changed and signals:
        root = ah_dir(home) / "releases" / str(release) / flavor / "files"
        for rel in changed:
            meta = snap["files"][rel]
            write_atomic(home / rel, (root / rel).read_bytes(), int(meta.get("mode") or 0o600))
        fixed.append(f"{len(changed)} file(s)")
    if new_hooks is not None:
        settings_doc["hooks"] = new_hooks
        write_atomic(home / settings_spec["path"], (json.dumps(settings_doc, indent=2) + "\n").encode())
        fixed.append("hook wiring")
    if block_fix == "stash":
        stash_block(home, flavor)
        fixed.append("instructions stashed (OFF)")
    elif block_fix == "replace":
        new_text, lead, _old, offset = split_block(text, FLAVORS[flavor]["start"], FLAVORS[flavor]["end"])
        write_atomic(ipath, (new_text[:offset] + lead + ispec["block"] + new_text[offset:]).encode("utf-8"))
        fixed.append("instructions block")

    def change(state_):
        flavors = state_.setdefault("flavors", {})
        prior = flavors.get(flavor) if isinstance(flavors.get(flavor), dict) else {}
        flavors[flavor] = {**prior, "release": release, "commit": entry.get("commit") or snap.get("commit"),
                           "backup": backup or prior.get("backup"), "repaired_at": now_iso()}
        state_["release"] = max(v.get("release", 0) for v in flavors.values() if isinstance(v, dict))
    update_state(home, change)
    result.update(state="repaired", fixed=fixed)
    log_line(home, "floor.log", f"repaired {flavor} to release {release}: {', '.join(fixed)}; why: "
                                + "; ".join(signals + problems))
    return result


def floor_check(home=None, repair=False, now=None) -> dict:
    home = home_dir(home)
    floor = read_json(ah_dir(home) / "floor.json")
    if not isinstance(floor, dict) or not isinstance(floor.get("flavors"), dict):
        return {"ok": True, "state": "no_floor", "flavors": {}}
    state = read_state(home)
    out = {}
    for flavor, entry in sorted(floor["flavors"].items()):
        if flavor in FLAVORS and isinstance(entry, dict) and isinstance(entry.get("release"), int):
            try:
                out[flavor] = check_flavor(home, flavor, entry, state, repair, now)
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
    tail = "" if result["ok"] else "; repair: harness floor-check --repair"
    return "floor: " + ("; ".join(parts) or "nothing to check") + tail


# ----------------------------------------------------------------------------- the floor watcher service
def floor_watch_units(home, system=None) -> list:
    """[(path, bytes)] for the watcher that runs `floor-check --repair` when the installed tree changes."""
    home = home_dir(home)
    script = home / ".claude" / "hooks" / "ah_switch.py"
    watched = [home / ".claude" / "hooks", home / ".claude" / "settings.json", ah_dir(home) / INSTALL_STATE]
    if (home / ".codex" / "agent-harness").is_dir():
        watched += [home / ".codex" / "agent-harness", home / ".codex" / "hooks.json"]
    if system_name(system) == "darwin":
        plist = {"Label": FLOOR_LABEL,
                 "ProgramArguments": ["/usr/bin/python3", "-I", str(script), "floor-check", "--repair", "--quiet"],
                 "WatchPaths": [str(p) for p in watched], "ThrottleInterval": 30, "RunAtLoad": True,
                 "Nice": 10, "LowPriorityIO": True, "StandardOutPath": "/dev/null",
                 "StandardErrorPath": str(ah_dir(home) / "logs" / "floor.err")}
        return [(home / "Library" / "LaunchAgents" / f"{FLOOR_LABEL}.plist", plistlib.dumps(plist))]
    units = home / ".config" / "systemd" / "user"
    path_unit = ("[Unit]\nDescription=agent harness release floor watcher (docs/off-switch.md)\n\n[Path]\n"
                 + "".join(f"PathChanged={p}\n" for p in watched)
                 + f"Unit={FLOOR_UNIT}.service\nTriggerLimitIntervalSec=30\nTriggerLimitBurst=1\n\n"
                   "[Install]\nWantedBy=default.target\n")
    service = ("[Unit]\nDescription=agent harness release floor check (docs/off-switch.md)\n\n[Service]\nType=oneshot\n"
               f"ExecStart=/usr/bin/env python3 -I {shlex.quote(str(script))} floor-check --repair --quiet\nNice=10\n")
    return [(units / f"{FLOOR_UNIT}.path", path_unit.encode()), (units / f"{FLOOR_UNIT}.service", service.encode())]


def install_floor_watch(home, run=None, system=None) -> str:
    run = run or default_run
    home = home_dir(home)
    system = system_name(system)
    if system not in ("darwin", "linux"):
        return f"floor watcher: not available on {system}"
    private_dir(ah_dir(home) / "logs")
    for path, data in floor_watch_units(home, system):
        write_atomic(path, data, 0o644)
    if system == "darwin":
        domain = f"gui/{os.getuid()}"
        plist = str(floor_watch_units(home, system)[0][0])
        run(["launchctl", "enable", f"{domain}/{FLOOR_LABEL}"])
        run(["launchctl", "bootout", f"{domain}/{FLOOR_LABEL}"])  # not loaded is fine; reload picks up new paths
        code = run(["launchctl", "bootstrap", domain, plist])
        return f"floor watcher: {FLOOR_LABEL} " + ("loaded" if code == 0 else f"bootstrap failed (exit {code})")
    if run(["systemctl", "--user", "daemon-reload"]) != 0:
        return "floor watcher: systemctl --user daemon-reload failed (no user session?); units written, not started"
    code = run(["systemctl", "--user", "enable", "--now", f"{FLOOR_UNIT}.path"])
    return f"floor watcher: {FLOOR_UNIT}.path " + ("enabled" if code == 0 else f"enable failed (exit {code})")


def remove_floor_watch(home, run=None, system=None) -> str:
    run = run or default_run
    home = home_dir(home)
    system = system_name(system)
    units = floor_watch_units(home, system) if system in ("darwin", "linux") else []
    if not any(path.exists() for path, _ in units):
        return "floor watcher: not installed"
    if system == "darwin":
        run(["launchctl", "bootout", f"gui/{os.getuid()}/{FLOOR_LABEL}"])
    else:
        run(["systemctl", "--user", "disable", "--now", f"{FLOOR_UNIT}.path"])
    for path, _ in units:
        try:
            os.unlink(path)
        except FileNotFoundError:
            pass
    if system == "linux":
        run(["systemctl", "--user", "daemon-reload"])
    return "floor watcher: removed"


# ----------------------------------------------------------------------------- CLI
def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="harness", description="Agent Harness off switch and release floor "
                                                             "(docs/off-switch.md)")
    ap.add_argument("--home", help=argparse.SUPPRESS)
    sub = ap.add_subparsers(dest="cmd", required=True)
    off = sub.add_parser("off", help="turn the harness off now (hooks silent, instructions stashed)")
    off.add_argument("--reason", default="")
    off.add_argument("--services", action="store_true", help="also stop the harness LaunchAgents / systemd user units")
    off.add_argument("--json", action="store_true")
    on = sub.add_parser("on", help="turn it back on")
    on.add_argument("--json", action="store_true")
    st = sub.add_parser("status", help="on or off, and the floor")
    st.add_argument("--json", action="store_true")
    fc = sub.add_parser("floor-check", help="detect (and with --repair undo) an old installer's overwrite")
    fc.add_argument("--repair", action="store_true")
    fc.add_argument("--json", action="store_true")
    fc.add_argument("--quiet", action="store_true", help="print nothing unless something was found")
    args = ap.parse_args(argv)
    home = home_dir(args.home)
    if args.cmd == "off":
        result = switch_off(home, args.reason, args.services)
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
    result = floor_check(home, repair=args.repair)
    if args.json:
        print(json.dumps(result, indent=2))
    elif not args.quiet or any(r["state"] in ("drift", "repaired", "error") for r in result.get("flavors", {}).values()):
        print(floor_line(result))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
