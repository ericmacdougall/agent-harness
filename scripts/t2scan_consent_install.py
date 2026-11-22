#!/usr/bin/env python3
"""Protected Linux half of operator-run T2Scan consent provisioning."""

import base64
import fcntl
import grp
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import socket
import stat
import subprocess
import sys


HOST = "t2-dev"
ACCOUNT = "agent-harness-consent"
CLIENTS = "agent-harness-consent-client"
NAME = "t2scan-astra-consent"
CONFIG = Path("/etc/agent-harness") / NAME
STATE = Path("/var/lib") / f"agent-harness-{NAME}"
BIN = Path("/usr/lib/agent-harness/t2scan_consent.py")
SYSTEMD = Path("/etc/systemd/system")
SOCKET = f"{NAME}.socket"
SERVICE = f"{NAME}.service"
TARGETS = {"verifier": BIN, "socket": SYSTEMD / SOCKET, "service": SYSTEMD / SERVICE}
KEY = Path("/etc/ssh/ssh_host_ed25519_key.pub")
MAX_REQUEST = 65536


class Refusal(ValueError):
    """Provisioning cannot be confirmed."""


def require(condition, message):
    if not condition:
        raise Refusal(message)


def command(*args):
    return subprocess.run(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          timeout=25, check=True).stdout


def paths_are_protected(path):
    for folder in (*reversed(path.parents), path):
        info = folder.lstat()
        require(info.st_uid == 0 and stat.S_ISDIR(info.st_mode) and not info.st_mode & 0o022,
                "A system path is not protected.")


def make_root_dir(path):
    paths_are_protected(path.parent)
    path.mkdir(mode=0o755, exist_ok=True)
    paths_are_protected(path)


def new_file(path, data):
    paths_are_protected(path.parent)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
    with os.fdopen(fd, "wb") as output:
        output.write(data)
        output.flush()
        os.fsync(output.fileno())


def enc(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def target_fingerprint():
    return command("/usr/bin/ssh-keygen", "-l", "-E", "sha256", "-f", str(KEY)).decode("ascii").split()[1]


def target_identity(issuer, fingerprint, expected_uid):
    require(os.geteuid() == 0 and socket.gethostname().split(".")[0] == HOST, "Unexpected operator host.")
    require(re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,63}", issuer), "Invalid issuer.")
    require(re.fullmatch(r"SHA256:[A-Za-z0-9+/]{43}", fingerprint) and fingerprint == target_fingerprint(),
            "Target SSH host key does not match.")
    uid = int(os.environ.get("SUDO_UID", "0"))
    require(uid > 0 and uid == expected_uid, "Target execution UID does not match.")
    return {"issuer": issuer, "host_label": HOST, "ssh_ed25519_fingerprint": fingerprint, "peer_uid": uid}


def root_file(path):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
            and not info.st_mode & 0o022, "An existing installation file is not protected.")
    return path.read_bytes()


def no_conflicts():
    for path in (*TARGETS.values(), CONFIG, STATE):
        require(not os.path.lexists(path), "Existing consent installation or state needs reconciliation.")
    for folder in (BIN.parent.parent, CONFIG.parent.parent, STATE.parent, SYSTEMD):
        paths_are_protected(folder)
    for folder in (BIN.parent, CONFIG.parent):
        if os.path.lexists(folder):
            paths_are_protected(folder)


def decode_payload(payload):
    require(type(payload) is dict and payload.keys() == TARGETS.keys() | {"public_key", "ref", "signer_sha256"},
            "Unexpected setup payload.")
    require(re.fullmatch(r"[a-f0-9]{40}", payload["ref"]) and
            re.fullmatch(r"[a-f0-9]{64}", payload["signer_sha256"]), "Unpinned release or signer.")
    assets = {name: base64.b64decode(payload[name], validate=True) for name in (*TARGETS, "public_key")}
    require(all(0 < len(content) <= 32768 for content in assets.values()), "Unexpected setup asset size.")
    key = assets["public_key"]
    require(len(key) <= 512 and re.fullmatch(
        rb"-----BEGIN PUBLIC KEY-----\n[A-Za-z0-9+/=\n]+-----END PUBLIC KEY-----\n?", key), "Invalid signer public key.")
    return assets


def lookup(get, name):
    try:
        return get(name)
    except KeyError:
        return None


def create_accounts(peer):
    existing = [lookup(grp.getgrnam, group) for group in (ACCOUNT, CLIENTS)]
    require(not any(existing) and lookup(pwd.getpwnam, ACCOUNT) is None,
            "Dedicated consent group or account already exists. Reconcile first.")
    command("/usr/sbin/groupadd", "--system", ACCOUNT)
    command("/usr/sbin/groupadd", "--system", CLIENTS)
    command("/usr/sbin/useradd", "--system", "--no-create-home", "--gid", ACCOUNT,
            "--home-dir", str(STATE), "--shell", "/usr/sbin/nologin", ACCOUNT)
    command("/usr/sbin/usermod", "--append", "--groups", CLIENTS, peer)
    return pwd.getpwnam(ACCOUNT)


def systemctl(*args):
    command("/usr/bin/systemctl", *args)


def disable():
    # Disable first to block socket reactivation while stopping the service.
    try:
        systemctl("disable", "--now", SOCKET)
    finally:
        systemctl("stop", SERVICE)


def peer_probe(peer):
    address = Path("/run/agent-harness") / SOCKET.replace(".socket", ".sock")
    info = address.lstat()
    require(stat.S_ISSOCK(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o660
            and info.st_gid == grp.getgrnam(CLIENTS).gr_gid, "Installed socket identity differs.")
    source = '''
import socket, struct, sys
with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
    connection.settimeout(4)
    connection.connect(sys.argv[1])
    _, uid, _ = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    if uid != 0:
        raise SystemExit(2)
    connection.sendall(b'{"action":"check"}\\n')
    connection.shutdown(socket.SHUT_WR)
    with connection.makefile("rb") as reply:
        if reply.read(128) != b'{"decision":"denied"}\\n':
            raise SystemExit(2)
'''
    command("/usr/sbin/runuser", "-u", peer, "--", "/usr/bin/python3", "-I", "-c", source, str(address))


def install(config, payload, verify_key):
    no_conflicts()
    assets = decode_payload(payload)
    verify_key(assets["public_key"])
    peer = pwd.getpwuid(config["peer_uid"]).pw_name
    owner = create_accounts(peer)
    make_root_dir(BIN.parent)
    make_root_dir(CONFIG.parent)
    make_root_dir(CONFIG)
    for name, path in TARGETS.items():
        new_file(path, assets[name])
    new_file(CONFIG / "settings.json", enc(config))
    new_file(CONFIG / "issuer.pem", assets["public_key"])
    record = {"ref": payload["ref"], "signer_sha256": payload["signer_sha256"],
              "public_key_sha256": sha(assets["public_key"]),
              "asset_sha256": {name: sha(assets[name]) for name in TARGETS}}
    new_file(CONFIG / "release.json", enc(record))
    STATE.mkdir(mode=0o700)
    os.chown(STATE, owner.pw_uid, owner.pw_gid)
    command("/usr/sbin/runuser", "-u", ACCOUNT, "--", "/usr/bin/python3", "-I", str(BIN), "initialize-state")
    try:
        systemctl("daemon-reload")
        systemctl("enable", "--now", SOCKET)
        peer_probe(peer)
        systemctl("is-active", "--quiet", SERVICE)
        require(all(root_file(path) == assets[name] for name, path in TARGETS.items())
                and root_file(CONFIG / "settings.json") == enc(config)
                and root_file(CONFIG / "issuer.pem") == assets["public_key"],
                "Released broker files differ after installation.")
    except (OSError, ValueError, subprocess.SubprocessError):
        disable()
        raise
    return record


def rollback(config, ref):
    paths_are_protected(CONFIG)
    require(root_file(CONFIG / "settings.json") == enc(config), "Configured issuer or target differs.")
    record = json.loads(root_file(CONFIG / "release.json"))
    require(record["ref"] == ref and record["public_key_sha256"] == sha(root_file(CONFIG / "issuer.pem")),
            "Installed release or issuer differs.")
    disable()


def run(phase, config, payload, verify_key):
    if phase == "check":
        require(payload is None, "Preview cannot receive enrollment material.")
        no_conflicts()
        require(not any(lookup(grp.getgrnam, name) for name in (ACCOUNT, CLIENTS))
                and lookup(pwd.getpwnam, ACCOUNT) is None, "Dedicated consent account already exists.")
        for command_path in ("/usr/sbin/runuser", "/usr/bin/openssl", "/usr/bin/systemctl"):
            require(os.access(command_path, os.X_OK), "A provisioning prerequisite is unavailable.")
    elif phase == "install":
        return install(config, payload, verify_key)
    elif phase == "rollback":
        require(type(payload) is str and re.fullmatch(r"[a-f0-9]{40}", payload), "Invalid rollback release.")
        rollback(config, payload)
    else:
        raise Refusal("Unknown operation.")
    return {}


def worker(verify_key):
    os.umask(0o022)
    raw = sys.stdin.buffer.read(MAX_REQUEST + 1)
    require(len(raw) <= MAX_REQUEST, "Setup request is over the limit.")
    request = json.loads(raw)
    require(type(request) is dict and request.keys() == {"phase", "issuer", "fingerprint", "uid", "payload"},
            "Unexpected setup request.")
    config = target_identity(request["issuer"], request["fingerprint"], request["uid"])
    phase = request["phase"]
    if phase == "check":
        result = run(phase, config, request["payload"], verify_key)
    else:
        lock = os.open("/run/agent-harness-t2scan-provision.lock",
                       os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            info = os.fstat(lock)
            require(stat.S_ISREG(info.st_mode) and info.st_uid == 0 and info.st_nlink == 1
                    and not info.st_mode & 0o077, "Unsafe setup lock.")
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            result = run(phase, config, request["payload"], verify_key)
        finally:
            os.close(lock)
    print(json.dumps({"status": phase, "result": result}))
