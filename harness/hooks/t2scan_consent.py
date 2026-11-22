#!/usr/bin/env python3
"""Narrow, opt-in portable consent broker for a named T2Scan direct-Astra batch."""

from __future__ import annotations

import base64
import binascii
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import sqlite3
import stat
import struct
import subprocess
import sys
import tempfile
import time


SOCKET_PATH = Path("/run/agent-harness/t2scan-astra-consent.sock")
CONFIG_DIR = Path("/etc/agent-harness/t2scan-astra-consent")
STATE_DIR = Path("/var/lib/agent-harness-t2scan-astra-consent")
SSH_PUBLIC_KEY = Path("/etc/ssh/ssh_host_ed25519_key.pub")
OPENSSL = "/usr/bin/openssl"
SCHEMA = "agent-harness.t2scan.astra-direct.v1"
MODEL = "gpt-6-astra"
DOMAIN = b"Agent Harness T2Scan Astra direct approval v1\x00"
ROLES = {"executive-synthesis", "assurance-synthesis", "delivery-synthesis"}
CLAIMS = {"schema", "issuer", "audience", "provider", "model", "mode", "project_id", "run_id",
          "created_at", "expires_at", "assignments"}
ITEM_KEYS = {"assignment", "work_item_id", "task_key", "packet_sha256", "nonce"}
SCOPE_KEYS = (ITEM_KEYS - {"nonce"}) | {"project_id", "run_id", "model"}
REQUEST_KEYS = SCOPE_KEYS | {"action", "challenge_b64", "signature_b64"}
ID = re.compile(r"[a-z0-9][a-z0-9.-]{0,63}")
HOST_LABEL = re.compile(r"[a-z0-9][a-z0-9.-]{0,23}")
HOST_FINGERPRINT = re.compile(r"SHA256:[A-Za-z0-9+/]{43}")
HEX = re.compile(r"[a-f0-9]{64}")
# DER SubjectPublicKeyInfo prefix for an uncompressed P-256 public key.
P256_SPKI = bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d03010703420004")
MAX_LIFETIME = 900
MAX_CHALLENGE = 4096
MAX_SIGNATURE = 72
MAX_REQUEST = 8192
SECONDS_PER_READ = 1.0


def require(value):
    if not value:
        raise ValueError("Invalid portable consent")


def matches(pattern, value):
    return type(value) is str and re.fullmatch(pattern, value) is not None


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def unique_object(pairs):
    result = dict(pairs)
    require(len(result) == len(pairs))
    return result


def object_json(raw, limit):
    require(0 < len(raw) <= limit)
    value = json.loads(raw.decode("ascii"), object_pairs_hook=unique_object)
    require(type(value) is dict)
    return value


def field_bytes(value, limit):
    require(type(value) is str and 0 < len(value) <= (limit + 2) // 3 * 4)
    raw = base64.b64decode(value, validate=True)
    require(len(raw) <= limit and base64.b64encode(raw).decode("ascii") == value)
    return raw


def public_key_format(pem):
    pattern = rb"-----BEGIN PUBLIC KEY-----\n([A-Za-z0-9+/=\n]+)-----END PUBLIC KEY-----\n?"
    match = re.fullmatch(pattern, pem)
    require(match)
    spki = base64.b64decode(match.group(1).replace(b"\n", b""), validate=True)
    require(len(spki) == len(P256_SPKI) + 64 and spki.startswith(P256_SPKI))


def validate_challenge(raw, issuer, audience):
    claim = object_json(raw, MAX_CHALLENGE)
    require(claim.keys() == CLAIMS and canonical(claim) == raw)
    require(claim["schema"] == SCHEMA and claim["issuer"] == issuer and claim["audience"] == audience)
    require(claim["provider"] == "codex" and claim["model"] == MODEL and claim["mode"] == "direct")
    project, run = claim["project_id"], claim["run_id"]
    require(matches(r"prj_[A-Za-z0-9_-]{4,64}", project) and matches(r"run_[A-Za-z0-9_-]{4,64}", run))
    start, end = claim["created_at"], claim["expires_at"]
    require(type(start) is int and type(end) is int and 0 < start < (1 << 53) and 0 < end - start <= MAX_LIFETIME)
    items = claim["assignments"]
    require(type(items) is list and len(items) == 3)
    for item in items:
        require(type(item) is dict and item.keys() == ITEM_KEYS)
        work = item["work_item_id"]
        require(matches(r"wrk_[A-Za-z0-9_-]{4,64}", work))
        require(type(item["assignment"]) is str and item["assignment"] in ROLES)
        task = "t2scan-audit-" + sha(canonical([project, run, work]))[:32] + "-astra-direct"
        require(item["task_key"] == task and matches(HEX, item["packet_sha256"]) and matches(HEX, item["nonce"]))
    work_ids = [item["work_item_id"] for item in items]
    require(work_ids == sorted(set(work_ids)))
    require({item["assignment"] for item in items} == ROLES and len({item["nonce"] for item in items}) == 3)
    return claim


def connect_state(path):
    # An absent replay ledger must fail closed. Do not silently create state at startup or dispatch.
    db = sqlite3.connect(path.as_uri() + "?mode=rw", uri=True, isolation_level=None, timeout=1)
    try:
        db.execute("PRAGMA synchronous = FULL")
    except sqlite3.Error:
        db.close()
        raise
    return db


def initialize_state(path):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    os.close(fd)
    with closing(connect_state(path)) as db:
        db.executescript("""
            BEGIN IMMEDIATE;
            CREATE TABLE claimed (nonce TEXT PRIMARY KEY, challenge TEXT NOT NULL);
            CREATE TABLE revoked (challenge TEXT PRIMARY KEY);
            COMMIT;
        """)


class Verifier:
    def __init__(self, *, issuer, audience, peer_uid, public_key, state, clock=time.time):
        require(matches(ID, issuer) and matches(ID, audience))
        require(type(peer_uid) is int and 0 < peer_uid < (1 << 31))
        public_key_format(public_key)
        self.issuer = issuer
        self.audience = audience
        self.peer_uid = peer_uid
        self.public_key = public_key
        self.state = state
        self.clock = clock

    def verify_signature(self, raw, signature):
        require(8 <= len(signature) <= MAX_SIGNATURE)
        # Keep the trusted key snapshot and detached signature in anonymous descriptors.
        with tempfile.TemporaryFile() as detached, tempfile.TemporaryFile() as public_key:
            detached.write(signature)
            detached.seek(0)
            public_key.write(self.public_key)
            public_key.seek(0)
            signature_fd, key_fd = detached.fileno(), public_key.fileno()
            result = subprocess.run(
                [OPENSSL, "dgst", "-sha256", "-verify", f"/dev/fd/{key_fd}", "-signature", f"/dev/fd/{signature_fd}"],
                input=DOMAIN + raw, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                pass_fds=(key_fd, signature_fd), timeout=2,
                env={"PATH": "/usr/bin:/bin", "LC_ALL": "C", "OPENSSL_CONF": "/dev/null"},
            )
        require(result.returncode == 0)

    def decide(self, request, *, peer_uid):
        try:
            if request.get("action") == "revoke":
                require(peer_uid == 0 and request.keys() == {"action", "challenge_sha256"})
                digest = request["challenge_sha256"]
                require(matches(HEX, digest))
                with closing(connect_state(self.state)) as db, db:
                    db.execute("BEGIN IMMEDIATE")
                    db.execute("INSERT OR IGNORE INTO revoked VALUES (?)", (digest,))
                return True
            require(peer_uid == self.peer_uid and request.keys() == REQUEST_KEYS)
            action = request["action"]
            require(action in ("check", "consume"))
            raw = field_bytes(request["challenge_b64"], MAX_CHALLENGE)
            signature = field_bytes(request["signature_b64"], MAX_SIGNATURE)
            claim = validate_challenge(raw, self.issuer, self.audience)
            require(all(request[name] == claim[name] for name in ("project_id", "run_id", "model")))
            item = next((candidate for candidate in claim["assignments"]
                         if all(request[key] == candidate[key] for key in ITEM_KEYS - {"nonce"})), None)
            require(item)
            self.fresh(claim)
            self.verify_signature(raw, signature)
            with closing(connect_state(self.state)) as db, db:
                # Revocation and one-use claim linearize here. Recheck freshness after the lock.
                db.execute("BEGIN IMMEDIATE")
                self.fresh(claim)
                digest, nonce = sha(raw), item["nonce"]
                require(db.execute("SELECT 1 FROM revoked WHERE challenge = ?", (digest,)).fetchone() is None)
                require(db.execute("SELECT 1 FROM claimed WHERE nonce = ?", (nonce,)).fetchone() is None)
                if action == "consume":
                    db.execute("INSERT INTO claimed VALUES (?, ?)", (nonce, digest))
            return True
        except (ValueError, OSError, binascii.Error, OverflowError, RecursionError, sqlite3.Error,
                subprocess.SubprocessError):
            return False

    def fresh(self, claim):
        require(claim["created_at"] <= self.clock() < claim["expires_at"])


def protected(path, owner, *, directory=False, private=False):
    """Require an unredirected, non-writable-by-others ancestor chain."""
    require(path.is_absolute())
    for ancestor in reversed(path.parents):
        info = ancestor.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid in {0, owner} and not info.st_mode & 0o022)
    info = path.lstat()
    kind = stat.S_ISDIR if directory else stat.S_ISREG
    forbidden = 0o077 if private else 0o022
    require(info.st_uid == owner and kind(info.st_mode) and not info.st_mode & forbidden)
    require(directory or info.st_nlink == 1)
    return info


def protected_read(path, limit):
    info = protected(path, 0)
    require(0 < info.st_size <= limit)
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as source:
        current = os.fstat(source.fileno())
        require((current.st_dev, current.st_ino) == (info.st_dev, info.st_ino))
        data = source.read(limit + 1)
    require(0 < len(data) <= limit)
    return data


def ssh_fingerprint(data):
    tokens = data.split()
    require(len(tokens) >= 2 and tokens[0] == b"ssh-ed25519")
    value = field_bytes(tokens[1].decode("ascii"), 51)
    require(len(value) == 51 and value.startswith(b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20"))
    return "SHA256:" + base64.b64encode(hashlib.sha256(value).digest()).decode("ascii").rstrip("=")


def derive_audience(label, fingerprint, peer_uid):
    require(matches(HOST_LABEL, label) and matches(HOST_FINGERPRINT, fingerprint))
    require(type(peer_uid) is int and 0 < peer_uid < (1 << 31))
    field_bytes(fingerprint.removeprefix("SHA256:") + "=", 32)
    return label + "-" + sha(canonical([fingerprint, peer_uid]))[:32]


def load_verifier():
    config = object_json(protected_read(CONFIG_DIR / "settings.json", 1024), 1024)
    require(config.keys() == {"issuer", "host_label", "ssh_ed25519_fingerprint", "peer_uid"})
    fingerprint = config["ssh_ed25519_fingerprint"]
    label, peer_uid = config["host_label"], config["peer_uid"]
    audience = derive_audience(label, fingerprint, peer_uid)
    require(fingerprint == ssh_fingerprint(protected_read(SSH_PUBLIC_KEY, 1024)))
    uid = os.geteuid()
    require(uid != 0 and uid != peer_uid)
    protected(STATE_DIR, uid, directory=True, private=True)
    state = STATE_DIR / "state.sqlite3"
    protected(state, uid, private=True)
    with closing(connect_state(state)) as db:
        db.execute("SELECT nonce FROM claimed LIMIT 1").fetchone()
        db.execute("SELECT challenge FROM revoked LIMIT 1").fetchone()
    issuer_key = protected_read(CONFIG_DIR / "issuer.pem", 512)
    return Verifier(issuer=config["issuer"], audience=audience, peer_uid=peer_uid, public_key=issuer_key, state=state)


def socket_listener():
    require(sys.platform == "linux" and os.environ.get("LISTEN_PID") == str(os.getpid()))
    require(os.environ.get("LISTEN_FDS") == "1")
    for ancestor in reversed(SOCKET_PATH.parents):
        protected(ancestor, 0, directory=True)
    info = SOCKET_PATH.lstat()
    require(stat.S_ISSOCK(info.st_mode) and info.st_uid == 0)
    listener = socket.socket(fileno=3)
    require(listener.family == socket.AF_UNIX and listener.type == socket.SOCK_STREAM)
    require(listener.getsockopt(socket.SOL_SOCKET, socket.SO_ACCEPTCONN) == 1)
    require(listener.getsockname() == str(SOCKET_PATH))
    return listener


def receive(client):
    deadline = time.monotonic() + SECONDS_PER_READ
    raw = bytearray()
    while len(raw) < MAX_REQUEST:
        remaining = deadline - time.monotonic()
        require(remaining > 0)
        client.settimeout(remaining)
        chunk = client.recv(MAX_REQUEST - len(raw))
        require(chunk)
        raw.extend(chunk)
        if b"\n" in raw:
            require(raw.count(b"\n") == 1 and raw.endswith(b"\n"))
            remaining = deadline - time.monotonic()
            require(remaining > 0)
            client.settimeout(remaining)
            require(client.recv(1) == b"")
            return object_json(bytes(raw[:-1]), MAX_REQUEST - 1)
    raise ValueError("Invalid portable consent frame")


def handle(client, verifier):
    allowed = False
    try:
        credentials = client.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
        _, peer_uid, _ = struct.unpack("3i", credentials)
        if peer_uid in (0, verifier.peer_uid):
            allowed = verifier.decide(receive(client), peer_uid=peer_uid)
    except (OSError, ValueError, RecursionError):
        pass
    try:
        client.settimeout(SECONDS_PER_READ)
        client.sendall(b'{"decision":"allowed"}\n' if allowed else b'{"decision":"denied"}\n')
    except OSError:
        pass


def main():
    mode = sys.argv[1:]
    if mode == ["serve"]:
        verifier = load_verifier()
        with socket_listener() as listener:
            while True:
                client, _ = listener.accept()
                with client:
                    handle(client, verifier)
    if mode == ["initialize-state"]:
        require(os.geteuid() != 0)
        protected(STATE_DIR, os.geteuid(), directory=True, private=True)
        initialize_state(STATE_DIR / "state.sqlite3")
        return
    raise ValueError("Invalid portable consent service mode")


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, binascii.Error, sqlite3.Error):
        print("T2Scan portable consent service refused to start or stopped.", file=sys.stderr)
        sys.exit(2)
