"""Install or upgrade netwatch, the local network and orphaned-process monitor.

netwatch (https://github.com/ericmacdougall/netwatch) is a separate,
public Go binary. The harness installs one pinned release: the version and
the SHA-256 of every platform archive are recorded in harness/netwatch.json,
and an archive whose digest differs is refused. The binary goes to
~/.agent-harness/bin/ and registers its own per-user service (LaunchAgent,
systemd --user unit or logon Scheduled Task) with `netwatch install`; no
root or administrator rights are used.

A failure here never fails the harness install: it is reported as one
status line. `--no-netwatch` opts out and is remembered.

The service belongs to the real user, so it is only (re)registered when the
installer targets the real home directory: `netwatch install` writes the
LaunchAgent, unit or task of whoever runs it, whatever --home says. With a
non-default --home (as in tests) netwatch is skipped unless --netwatch asks
for the binary, and the service is still left alone.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import platform
import re
import secrets
import stat
import subprocess
import sys
import tarfile
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PIN_FILE = ROOT / "harness" / "netwatch.json"
STATE_FILE = "netwatch-state.json"
OPT_OUT_ENV = "AGENT_HARNESS_NETWATCH"  # "0" skips netwatch for one run
MAX_ARCHIVE = 64 << 20
MAX_BINARY = 64 << 20


def platform_key(system: str | None = None, machine: str | None = None) -> str | None:
    """Release key such as "darwin_arm64", or None for an unsupported platform."""
    system = (system or sys.platform).lower()
    machine = (machine or platform.machine()).lower()
    os_name = {"darwin": "darwin", "linux": "linux", "win32": "windows", "windows": "windows"}.get(system)
    arch = {"arm64": "arm64", "aarch64": "arm64", "x86_64": "amd64", "amd64": "amd64"}.get(machine)
    if not os_name or not arch:
        return None
    return f"{os_name}_{arch}"


def load_pin(path: Path = PIN_FILE) -> dict:
    pin = json.loads(path.read_text())
    if not isinstance(pin, dict) or not str(pin.get("version", "")).startswith("v"):
        raise ValueError(f"{path}: missing version")
    assets = pin.get("assets")
    if not isinstance(assets, dict) or not assets:
        raise ValueError(f"{path}: missing assets")
    for key, asset in assets.items():
        for field in ("sha256", "binary_sha256"):
            digest = asset.get(field, "") if isinstance(asset, dict) else ""
            if not re.fullmatch(r"[0-9a-f]{64}", digest):
                raise ValueError(f"{path}: asset {key} needs a lowercase hex {field}")
    return pin


def binary_path(home: Path, key: str) -> Path:
    name = "netwatch.exe" if key.startswith("windows_") else "netwatch"
    return home / ".agent-harness" / "bin" / name


def archive_name(version: str, key: str) -> str:
    return f"netwatch_{version}_{key}" + (".zip" if key.startswith("windows_") else ".tar.gz")


def choice(home: Path, flag: bool | None) -> bool:
    """--netwatch/--no-netwatch win (and are saved); otherwise the saved choice; otherwise on."""
    if flag is not None:
        return flag
    if os.environ.get(OPT_OUT_ENV) == "0":
        return False
    state = read_state(home / ".agent-harness" / STATE_FILE)
    return not (isinstance(state, dict) and state.get("enabled") is False)


def read_state(path: Path):
    """Read the small state file without following links or blocking on a FIFO."""
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
    """Create path (0700) if missing; refuse a symlink or non-directory."""
    try:
        path.mkdir(mode=0o700)
    except FileExistsError:
        pass
    if path.is_symlink() or not path.is_dir():
        raise OSError(f"{path} must be a real directory, not a link")


def save_choice(home: Path, enabled: bool) -> None:
    directory = home / ".agent-harness"
    real_dir(directory)
    temporary = directory / f".{STATE_FILE}.{secrets.token_hex(4)}"
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "w") as handle:
        json.dump({"schema": 1, "enabled": enabled}, handle)
        handle.write("\n")
    os.replace(temporary, directory / STATE_FILE)


def fetch(url: str, timeout: float = 60) -> bytes:
    if not url.startswith("https://"):
        raise ValueError("refusing a non-HTTPS download")
    with urllib.request.urlopen(url, timeout=timeout) as response:  # noqa: S310 (https only)
        data = response.read(MAX_ARCHIVE + 1)
    if len(data) > MAX_ARCHIVE:
        raise ValueError("archive is larger than expected")
    return data


def extract_binary(archive: bytes, version: str, key: str) -> bytes:
    """Return the netwatch binary from a release archive.

    Only the one expected member is read, so a hostile archive cannot write
    anywhere (no path traversal, links or extra files are ever extracted).
    """
    member = f"netwatch_{version}_{key}/" + ("netwatch.exe" if key.startswith("windows_") else "netwatch")
    if key.startswith("windows_"):
        with zipfile.ZipFile(io.BytesIO(archive)) as zf:
            info = zf.getinfo(member)
            if info.is_dir() or info.file_size > MAX_BINARY:
                raise ValueError(f"unexpected archive member {member}")
            return zf.read(info)
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tf:
        info = tf.getmember(member)
        if not info.isreg() or info.size > MAX_BINARY:
            raise ValueError(f"unexpected archive member {member}")
        handle = tf.extractfile(info)
        if handle is None:
            raise ValueError(f"unreadable archive member {member}")
        return handle.read()


def file_sha256(path: Path) -> str | None:
    try:
        if path.is_symlink() or not path.is_file():
            return None
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


def version_tuple(version: str | None):
    m = re.fullmatch(r"v(\d+)\.(\d+)\.(\d+)", version or "")
    return tuple(int(x) for x in m.groups()) if m else None


def installed_version(binary: Path, run=subprocess.run) -> str | None:
    if not binary.is_file():
        return None
    try:
        result = run([str(binary), "version"], capture_output=True, text=True, timeout=20)
    except (OSError, subprocess.SubprocessError):
        return None
    out = result.stdout.strip()
    return out.removeprefix("netwatch ") if result.returncode == 0 and out.startswith("netwatch ") else None


def place_binary(binary: Path, data: bytes) -> None:
    """Atomically replace the binary. A running Windows executable cannot be
    overwritten but can be renamed, so the old one is moved aside first."""
    real_dir(binary.parent.parent)
    real_dir(binary.parent)
    for old in binary.parent.glob(f"{binary.name}.old-*"):  # left by a Windows upgrade
        try:
            old.unlink()
        except OSError:
            pass  # still running; removed next time
    temporary = binary.with_name(f".{binary.name}.{secrets.token_hex(4)}")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o755)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
        try:
            os.replace(temporary, binary)
        except PermissionError:
            if os.name != "nt" or not binary.exists():
                raise
            aside = binary.with_name(f"{binary.name}.old-{secrets.token_hex(4)}")
            os.replace(binary, aside)
            try:
                os.replace(temporary, binary)
            except OSError:
                os.replace(aside, binary)  # put the working binary back
                raise
    finally:
        if temporary.exists():
            temporary.unlink()


# Exact `netwatch status` first lines for a running service, per platform:
# macOS "loaded, state running, pid 123" (launchd also says "state not
# running"), Linux "netwatch.service active/running (...)", Windows
# "Scheduled Task netwatch: Running".
RUNNING = re.compile(r"(state running, pid \d+$)|( active/running )|(: Running$)")


def real_home() -> Path:
    """The account's home from the password database, not $HOME: launchd and
    systemd --user domains are per user, so a HOME override must not count."""
    try:
        import pwd
        return Path(pwd.getpwuid(os.getuid()).pw_dir).resolve()
    except (ImportError, KeyError):
        return Path.home().resolve()


def status(home: Path, apply: bool, enabled: bool = True, *, pin_path: Path = PIN_FILE,
           key: str | None = None, run=subprocess.run, download=fetch,
           register: bool | None = None) -> str:
    """Install or upgrade netwatch and return one status line.

    register defaults to whether home is the real home directory.
    """
    if not enabled:
        return "netwatch: skipped (opted out; rerun with --netwatch to install)"
    home = home.expanduser().resolve()
    if register is None:
        register = home == real_home()
    key = key or platform_key()
    try:
        pin = load_pin(pin_path)
    except (OSError, ValueError) as error:
        return f"netwatch: skipped (pin file unreadable: {error})"
    version = pin["version"]
    asset = pin["assets"].get(key or "")
    if asset is None:
        return f"netwatch: skipped (no {version} release for this platform)"
    binary = binary_path(home, key)
    if not apply:
        service = "and register its per-user service" if register else "(service left alone: non-default home)"
        return f"netwatch: would install {version} ({key}) at {binary} {service}"
    try:
        current_digest = file_sha256(binary)
        changed = current_digest != asset["binary_sha256"]
        if changed:
            # Never run an unverified binary: its own version output is not
            # evidence, so any binary that differs from the pin is replaced.
            name = archive_name(version, key)
            url = f"https://github.com/{pin['repo']}/releases/download/{version}/{name}"
            archive = download(url)
            digest = hashlib.sha256(archive).hexdigest()
            if digest != asset["sha256"]:
                return f"netwatch: not installed ({name} sha256 {digest[:12]}... does not match the pin)"
            data = extract_binary(archive, version, key)
            if hashlib.sha256(data).hexdigest() != asset["binary_sha256"]:
                return f"netwatch: not installed (binary in {name} does not match the pinned binary_sha256)"
            place_binary(binary, data)
            if installed_version(binary, run) != version:
                return f"netwatch: installed binary at {binary} does not report {version}; service not registered"
        action = f"installed {version}" if changed else f"{version} up to date"
        if not register:
            return f"netwatch: {action} at {binary}; service not registered (non-default home)"
        if not changed:
            # Re-registering would restart the service and drop a custom
            # --config or --log-dir, so leave a running service alone.
            st = run([str(binary), "status"], capture_output=True, text=True, timeout=60)
            first = st.stdout.splitlines()[0].strip() if st.stdout else ""
            if st.returncode == 0 and RUNNING.search(first):
                return f"netwatch: {action} at {binary}; service running"
        result = run([str(binary), "install"], capture_output=True, text=True, timeout=180)
    except Exception as error:  # noqa: BLE001 - never fail the harness install
        return f"netwatch: not installed ({error.__class__.__name__}: {error})"
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip().splitlines()[:1]
        return f"netwatch: {version} at {binary}; service registration failed ({detail[0] if detail else result.returncode})"
    return f"netwatch: {action} at {binary}; per-user service registered"
