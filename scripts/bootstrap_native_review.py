#!/usr/bin/env python3
"""Install a human-reviewed immutable native-review candidate on two hosts.

Default checks installed files and retains a private recovery cache. A
separately reviewed release.json pins this
program, the Git candidate, payload hashes and both hosts' predecessor hashes.
This utility does not review, approve, authorize or merge a pull request.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

REPOSITORY = "https://github.com/ericmacdougall/agent-harness.git"
FILES = ("native_pr_review.py", "native_pr_dispatch.py", "spec_flow.py", "merge_gate.py", "caller_identity.py", "ticket_adapters.py")
EDITIONS = (".claude/hooks", ".codex/agent-harness")
HOSTS = ("local", "t2-dev")
MAX_MESSAGE = 8 * 1024 * 1024

# The remote program is fixed source. Its only input is bounded JSON data.
# It is also executed locally in disposable subprocesses in the test suite.
AGENT_SOURCE = r'''
import base64, hashlib, json, os, re, stat, sys
from pathlib import Path

FILES = ("native_pr_review.py", "native_pr_dispatch.py", "spec_flow.py", "merge_gate.py", "caller_identity.py", "ticket_adapters.py")
EDITIONS = (".claude/hooks", ".codex/agent-harness")
def digest(data):
    return hashlib.sha256(data).hexdigest()
def secure_parents(path):
    for item in (path,) + tuple(path.parents):
        if item.is_symlink():
            raise ValueError("symlink directory refused")
        if item.exists():
            info = item.stat()
            if not stat.S_ISDIR(info.st_mode):
                raise ValueError("non-directory parent refused")
            # Root-owned system ancestors are trusted; other local users and
            # writable directories cannot participate in an atomic update.
            if info.st_uid not in (0, os.getuid()) or info.st_mode & 0o022:
                raise ValueError("untrusted directory ownership or writable mode")
def private_dir(path):
    # Refuse symlink parents, including the user home.
    secure_parents(path)
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.stat().st_uid != os.getuid() or path.stat().st_mode & 0o077:
        raise ValueError("journal directory must be private and owned")
def read_file(path, expected_mode=0o600):
    secure_parents(path.parent)
    try:
        fd = os.open(str(path), os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return None
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > 1024 * 1024:
            raise ValueError("non-regular or oversized file refused")
        if info.st_uid != os.getuid():
            raise ValueError("foreign owned file refused")
        mode = info.st_mode & 0o7777
        if mode not in (0o600, 0o644, 0o700, 0o755) or (expected_mode is not None and mode != expected_mode):
            raise ValueError("unsafe or unexpected file mode")
        return stream.read()
def atomic(path, data, mode=0o600):
    # Exclusive temporary name prevents following pre-existing links.
    temp = path.with_name(path.name + ".bootstrap-" + str(os.getpid()))
    fd = os.open(str(temp), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            os.fchmod(stream.fileno(), mode)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(str(temp), str(path))
        directory = os.open(str(path.parent), os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if temp.exists():
            temp.unlink()
def run_agent(request):
    if set(request) != {"phase", "transaction", "expected", "payloads"}:
        raise ValueError("unexpected request fields")
    phase = request["phase"]
    transaction = request["transaction"]
    if not re.fullmatch(r"[0-9a-f]{64}", transaction):
        raise ValueError("invalid transaction")
    if phase not in ("check", "prepare", "apply-check", "apply", "verify", "finalize", "rollback-check", "rollback-prepare", "rollback", "rollback-verify", "rollback-finalize"):
        raise ValueError("unknown phase")
    expected = request["expected"]
    payloads = request["payloads"]
    if set(expected) != set(EDITIONS) or set(payloads) != set(FILES):
        raise ValueError("closed payload set required")
    decoded = {}
    for name in FILES:
        decoded[name] = base64.b64decode(payloads[name], validate=True)
        if len(decoded[name]) > 1024 * 1024:
            raise ValueError("oversized payload")
    home = Path.home()
    entries = []
    for edition in EDITIONS:
        if set(expected[edition]) != set(FILES):
            raise ValueError("closed predecessor set required")
        directory = home / edition
        secure_parents(directory)
        if not directory.is_dir():
            raise ValueError("existing installed edition required")
        for name in FILES:
            old = expected[edition][name]
            if old is not None:
                if not isinstance(old, dict) or set(old) != {"sha256", "mode"} or not isinstance(old["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", old["sha256"]) or type(old["mode"]) is not int or old["mode"] not in (0o600, 0o644, 0o700, 0o755):
                    raise ValueError("invalid predecessor hash or mode")
            entries.append((directory / name, edition, name, old))
    root = home / ".agent-harness/work/native-review-bootstrap"
    active_path = root / "active.json"
    state_dir = root / transaction
    state_path = state_dir / "journal.json"
    def current(path):
        value = read_file(path, expected_mode=None)
        return None if value is None else {"sha256": digest(value), "mode": path.stat().st_mode & 0o7777}
    def installed(name):
        return {"sha256": digest(decoded[name]), "mode": 0o600}
    def require_old():
        for path, edition, name, old in entries:
            if current(path) != old:
                raise ValueError("installed predecessor drift: " + edition + "/" + name)
    def require_backups():
        for index, (path, edition, name, old) in enumerate(entries):
            backup = read_file(state_dir / (str(index) + ".backup"))
            if old is None:
                if backup is not None:
                    raise ValueError("unexpected backup for absent predecessor")
            elif backup is None or digest(backup) != old["sha256"]:
                raise ValueError("backup missing or digest mismatch")
    if phase == "check":
        active = read_file(active_path)
        if active is not None:
            active = json.loads(active)
            if active["transaction"] != transaction and active["state"] not in ("verified", "rolled-back"):
                raise ValueError("another target transaction requires recovery")
        require_old()
        return {"phase": "checked", "transaction": transaction, "files": len(entries)}
    private_dir(root)
    private_dir(state_dir)
    lock = root / "target-lock"
    # A crash retains the lock. Human investigation is required before retry.
    lock.mkdir(mode=0o700)
    try:
        active = read_file(active_path)
        if active is not None:
            active = json.loads(active)
            if active["transaction"] != transaction and active["state"] not in ("verified", "rolled-back"):
                raise ValueError("another target transaction requires recovery")
        binding = digest(json.dumps({"expected": expected, "payloads": payloads}, sort_keys=True).encode())
        if phase == "prepare":
            if state_path.exists():
                raise ValueError("transaction already prepared; inspect journal")
            require_old()
            atomic(active_path, json.dumps({"transaction": transaction, "state": "prepared"}).encode())
            if os.statvfs(str(state_dir)).f_bavail * os.statvfs(str(state_dir)).f_frsize < 16 * 1024 * 1024:
                raise ValueError("insufficient space for verified backups")
            for index, (path, edition, name, old) in enumerate(entries):
                value = read_file(path, expected_mode=None)
                if current(path) != old:
                    raise ValueError("predecessor changed during prepare")
                if value is not None:
                    backup = state_dir / (str(index) + ".backup")
                    if backup.exists() or backup.is_symlink():
                        raise ValueError("backup already exists")
                    atomic(backup, value)
                    if digest(read_file(backup)) != old["sha256"]:
                        raise ValueError("backup readback failed")
            journal = {"binding": binding, "phase": "prepared", "completed": []}
            atomic(state_path, json.dumps(journal, sort_keys=True).encode())
            return {"phase": "prepared", "transaction": transaction}
        raw = read_file(state_path)
        if raw is None:
            if phase in ("rollback-check", "rollback-prepare", "rollback", "rollback-verify", "rollback-finalize"):
                # No journal means no apply was authorized on this host. Exact
                # predecessors still must prove the host remained untouched.
                require_old()
                if phase == "rollback-check":
                    return {"phase": "rollback-checked", "transaction": transaction}
                if phase in ("rollback-verify", "rollback-finalize"):
                    if active is None or active["transaction"] != transaction or active["state"] != "rolled-back-pending":
                        raise ValueError("rollback reservation required")
                    if phase == "rollback-finalize":
                        atomic(active_path, json.dumps({"transaction": transaction, "state": "rolled-back"}).encode())
                    return {"phase": "rollback-verified" if phase == "rollback-verify" else "rollback-finalized", "transaction": transaction}
                atomic(active_path, json.dumps({"transaction": transaction, "state": "rolling-back"}).encode())
                if phase == "rollback-prepare":
                    return {"phase": "rollback-prepared", "transaction": transaction}
                require_old()
                atomic(active_path, json.dumps({"transaction": transaction, "state": "rolled-back-pending"}).encode())
                return {"phase": "rolled-back", "transaction": transaction}
            raise ValueError("prepared journal required")
        journal = json.loads(raw)
        if journal["binding"] != binding:
            raise ValueError("journal binding changed")
        if active is None or active["transaction"] != transaction:
            raise ValueError("target transaction guard mismatch")
        if phase in ("verify", "finalize"):
            for path, edition, name, old in entries:
                if current(path) != installed(name):
                    raise ValueError("installed readback mismatch")
            if journal["phase"] != "applied":
                raise ValueError("incomplete transaction")
            if phase == "finalize" and active["state"] != "verified-pending":
                raise ValueError("both-host verification phase required")
            atomic(active_path, json.dumps({"transaction": transaction, "state": "verified" if phase == "finalize" else "verified-pending"}).encode())
            return {"phase": "finalized" if phase == "finalize" else "verified", "transaction": transaction}
        if phase in ("rollback-verify", "rollback-finalize"):
            if journal["phase"] != "rolled-back" or active["state"] != "rolled-back-pending":
                raise ValueError("rollback reservation required")
            require_old()
            if phase == "rollback-finalize":
                atomic(active_path, json.dumps({"transaction": transaction, "state": "rolled-back"}).encode())
            return {"phase": "rollback-verified" if phase == "rollback-verify" else "rollback-finalized", "transaction": transaction}
        if phase in ("apply-check", "apply"):
            if journal["phase"] != "prepared":
                raise ValueError("apply requires untouched prepared journal")
            require_old()
            require_backups()
            if phase == "apply-check":
                return {"phase": "apply-checked", "transaction": transaction}
            journal["phase"] = "applying"
            atomic(state_path, json.dumps(journal, sort_keys=True).encode())
            for index, (path, edition, name, old) in enumerate(entries):
                if current(path) != old:
                    raise ValueError("predecessor changed during apply")
                atomic(path, decoded[name])
                if current(path) != installed(name):
                    raise ValueError("payload readback failed")
                journal["completed"].append(index)
                atomic(state_path, json.dumps(journal, sort_keys=True).encode())
            journal["phase"] = "applied"
            atomic(state_path, json.dumps(journal, sort_keys=True).encode())
            return {"phase": "applied", "transaction": transaction}
        # Rollback is explicit. Preflight every current byte and backup before writing.
        if journal["phase"] not in ("prepared", "applying", "applied", "rolling-back", "rolled-back"):
            raise ValueError("rollback state refused")
        require_backups()
        for index, (path, edition, name, old) in enumerate(entries):
            if current(path) not in (old, installed(name)):
                raise ValueError("rollback refuses changed installed bytes")
        if phase == "rollback-check":
            return {"phase": "rollback-checked", "transaction": transaction}
        # Reserve the common target set before any restore, including recovery
        # from a previously verified install. A failure retains this reservation.
        atomic(active_path, json.dumps({"transaction": transaction, "state": "rolling-back"}).encode())
        if phase == "rollback-prepare":
            return {"phase": "rollback-prepared", "transaction": transaction}
        journal["phase"] = "rolling-back"
        atomic(state_path, json.dumps(journal, sort_keys=True).encode())
        for index, (path, edition, name, old) in enumerate(entries):
            observed = current(path)
            if observed == old:
                continue
            if observed != installed(name):
                raise ValueError("rollback drift during restore")
            if old is None:
                path.unlink()
                directory = os.open(str(path.parent), os.O_RDONLY)
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
            else:
                backup = read_file(state_dir / (str(index) + ".backup"))
                if backup is None or digest(backup) != old["sha256"]:
                    raise ValueError("backup changed during rollback")
                atomic(path, backup, mode=old["mode"])
            if current(path) != old:
                raise ValueError("rollback readback mismatch")
        journal["phase"] = "rolled-back"
        atomic(state_path, json.dumps(journal, sort_keys=True).encode())
        atomic(active_path, json.dumps({"transaction": transaction, "state": "rolled-back-pending"}).encode())
        return {"phase": "rolled-back", "transaction": transaction}
    finally:
        lock.rmdir()
'''


def sha(data):
    return hashlib.sha256(data).hexdigest()


def validate_manifest(raw, program=None):
    manifest = json.loads(raw)
    if set(manifest) != {"version", "repository", "candidate", "bootstrap_sha256", "payloads", "hosts", "qualification"}:
        raise ValueError("release manifest fields differ from closed schema")
    if manifest["version"] != 1 or manifest["repository"] != REPOSITORY:
        raise ValueError("unsupported release or repository")
    if not re.fullmatch(r"[0-9a-f]{40}", manifest["candidate"]):
        raise ValueError("full Git commit required")
    if program is not None and sha(program) != manifest["bootstrap_sha256"]:
        raise ValueError("bootstrap program digest mismatch")
    if set(manifest["payloads"]) != set(FILES) or set(manifest["hosts"]) != set(HOSTS):
        raise ValueError("closed release payload and host sets required")
    if set(manifest["qualification"]) != {"spec_core_sha256", "acceptance_report_sha256", "adversarial_report_sha256", "tests_evidence_sha256"}:
        raise ValueError("closed qualification digest set required")
    for digest in [manifest["bootstrap_sha256"]] + list(manifest["payloads"].values()) + list(manifest["qualification"].values()):
        if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError("invalid release digest")
    for host in HOSTS:
        editions = manifest["hosts"][host]
        if set(editions) != set(EDITIONS):
            raise ValueError("both installed editions required")
        for edition in EDITIONS:
            if set(editions[edition]) != set(FILES):
                raise ValueError("closed predecessor file set required")
            for old in editions[edition].values():
                if old is not None:
                    if not isinstance(old, dict) or set(old) != {"sha256", "mode"} or not isinstance(old["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", old["sha256"]) or type(old["mode"]) is not int or old["mode"] not in (0o600, 0o644, 0o700, 0o755):
                        raise ValueError("invalid predecessor hash or mode")
    return manifest


def git(*arguments, cwd=None):
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    env.update(GIT_TERMINAL_PROMPT="0", GIT_CONFIG_NOSYSTEM="1")
    # Ignore user global Git aliases, filters and credential helpers.
    env["GIT_CONFIG_GLOBAL"] = os.devnull
    return subprocess.run(["git", *arguments], cwd=cwd, env=env, check=True,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE).stdout


def load_payloads(manifest, checkout):
    candidate = manifest["candidate"]
    if git("rev-parse", candidate + "^{commit}", cwd=checkout).decode().strip() != candidate:
        raise ValueError("candidate commit mismatch")
    payloads = {}
    for name in FILES:
        path = "harness/hooks/" + name
        listing = git("ls-tree", candidate, "--", path, cwd=checkout).decode().split()
        if len(listing) != 4 or listing[0] != "100644" or listing[1] != "blob":
            raise ValueError("candidate requires regular source payload: " + name)
        data = git("show", candidate + ":" + path, cwd=checkout)
        if len(data) > 1024 * 1024 or sha(data) != manifest["payloads"][name]:
            raise ValueError("candidate payload digest mismatch: " + name)
        compile(data, name, "exec")
        payloads[name] = base64.b64encode(data).decode("ascii")
    return payloads


def cached_payloads(manifest, payloads=None, home=None):
    """Persist/read immutable reviewed bytes for recovery without GitHub.

    The fixed host agent supplies its conservative file helpers. Candidate
    payloads are always data and are never executed by the cache.
    """
    helpers = {}
    exec(AGENT_SOURCE, helpers)
    read_file = helpers["read_file"]
    atomic = helpers["atomic"]
    private_dir = helpers["private_dir"]
    encoded_manifest = json.dumps(manifest, sort_keys=True).encode()
    transaction = sha(encoded_manifest)
    directory = (Path.home() if home is None else home) / ".agent-harness/work/native-review-bootstrap-cache" / transaction
    if payloads is not None:
        private_dir(directory.parent)
        private_dir(directory)
    elif not directory.is_dir():
        raise ValueError("offline recovery cache missing")
    else:
        private_dir(directory.parent)
        private_dir(directory)
    record = directory / "release.json"
    if payloads is not None:
        if set(payloads) != set(FILES):
            raise ValueError("closed cache payload set required")
        # Validate the entire proposed cache before creating any records.
        for name in FILES:
            value = base64.b64decode(payloads[name], validate=True)
            if len(value) > 1024 * 1024 or sha(value) != manifest["payloads"][name]:
                raise ValueError("cache proposed payload digest mismatch")
        for name in FILES:
            path = directory / name
            value = base64.b64decode(payloads[name], validate=True)
            existing = read_file(path)
            if existing is not None and existing != value:
                raise ValueError("existing recovery cache changed")
            if existing is None:
                atomic(path, value)
        existing = read_file(record)
        if existing is not None and existing != encoded_manifest:
            raise ValueError("existing recovery manifest changed")
        if existing is None:
            atomic(record, encoded_manifest)
    if read_file(record) != encoded_manifest:
        raise ValueError("offline recovery manifest mismatch")
    result = {}
    for name in FILES:
        value = read_file(directory / name)
        if value is None or sha(value) != manifest["payloads"][name]:
            raise ValueError("offline recovery payload missing or digest mismatch")
        result[name] = base64.b64encode(value).decode("ascii")
    return result


def release_payloads(manifest, rollback=False):
    if rollback:
        # Emergency restore must not depend on Git, GitHub or syntax compilation.
        return cached_payloads(manifest)
    work = Path.home() / ".agent-harness/work/native-review-bootstrap-source"
    helpers = {}
    exec(AGENT_SOURCE, helpers)
    helpers["private_dir"](work)
    with tempfile.TemporaryDirectory(prefix="source-", dir=work) as checkout:
        git("init", "--bare", checkout)
        git("-C", checkout, "fetch", "--depth=1", "--no-tags", REPOSITORY, manifest["candidate"])
        payloads = load_payloads(manifest, checkout)
    return cached_payloads(manifest, payloads)


def invoke(host, request):
    data = json.dumps(request, sort_keys=True).encode()
    if len(data) > MAX_MESSAGE:
        raise ValueError("request exceeds size limit")
    # Only constant source is executable; all release data is base64 JSON.
    program = AGENT_SOURCE + "\ntry:\n    request = json.loads(base64.b64decode(" + repr(base64.b64encode(data).decode()) + "))\n    print(json.dumps(run_agent(request), sort_keys=True))\nexcept Exception as exc:\n    print(json.dumps({'error': str(exc)}))\n    sys.exit(1)\n"
    command = [sys.executable, "-"] if host == "local" else [
        "ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=15", "t2-dev", "python3 -"]
    result = subprocess.run(command, input=program.encode(), stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=120)
    if len(result.stdout) > 65536 or result.returncode:
        raise RuntimeError(host + " failed or outcome unknown; preserve journals and inspect before retry")
    response = json.loads(result.stdout)
    if response.get("transaction") != request["transaction"]:
        raise RuntimeError("host transaction readback mismatch")
    expected_phase = {"check": "checked", "prepare": "prepared", "apply-check": "apply-checked",
                      "apply": "applied", "verify": "verified", "finalize": "finalized", "rollback-check": "rollback-checked",
                      "rollback-prepare": "rollback-prepared", "rollback": "rolled-back", "rollback-verify": "rollback-verified", "rollback-finalize": "rollback-finalized"}[request["phase"]]
    if response.get("phase") != expected_phase:
        raise RuntimeError("host phase readback mismatch")
    return response


def transact(manifest, payloads, mode, runner=invoke):
    transaction = sha(json.dumps(manifest, sort_keys=True).encode())
    def phase(name):
        for host in HOSTS:
            result = runner(host, {"phase": name, "transaction": transaction,
                                  "expected": manifest["hosts"][host], "payloads": payloads})
            print(json.dumps({"host": host, **result}, sort_keys=True))
    if mode == "rollback":
        phase("rollback-check")
        phase("rollback-prepare")
        phase("rollback")
        phase("rollback-verify")
        phase("rollback-finalize")
    else:
        phase("check")
        if mode == "apply":
            phase("prepare")
            phase("apply-check")
            phase("apply")
            phase("verify")
            phase("finalize")
    return transaction


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=Path(__file__).with_name("release.json"))
    parser.add_argument("--manifest-sha256", required=True, help="reviewed SHA-256 of exact release.json bytes")
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--check", action="store_true", help="read-only predecessor and source check (default)")
    modes.add_argument("--apply", action="store_true", help="human-authorized install of reviewed pinned candidate")
    modes.add_argument("--rollback", action="store_true", help="explicit guarded restore of this exact transaction")
    args = parser.parse_args()
    raw = args.manifest.read_bytes()
    if len(raw) > 65536:
        raise ValueError("oversized manifest")
    if not re.fullmatch(r"[0-9a-f]{64}", args.manifest_sha256) or sha(raw) != args.manifest_sha256:
        raise ValueError("reviewed manifest digest mismatch")
    manifest = validate_manifest(raw, Path(__file__).read_bytes())
    payloads = release_payloads(manifest, rollback=args.rollback)
    mode = "rollback" if args.rollback else "apply" if args.apply else "check"
    transaction = transact(manifest, payloads, mode)
    print("Transaction " + transaction + " " + mode + " completed. Fresh independent PR review and normal merge gates remain required.")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print("STOP: " + str(exc), file=sys.stderr)
        sys.exit(1)
