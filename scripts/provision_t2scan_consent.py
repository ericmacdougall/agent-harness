#!/usr/bin/env python3
"""Prepare one T2Scan named Astra batch through the macOS operator signer."""

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import stat
import subprocess
import sys
import tempfile
import time


ORIGIN = "https://github.com/ericmacdougall/agent-harness.git"
HOST = "t2-dev"
HOST_LABEL = HOST
SOURCES = {
    "verifier": "harness/hooks/t2scan_consent.py",
    "socket": "harness/schedulers/t2scan-astra-consent.socket",
    "service": "harness/schedulers/t2scan-astra-consent.service",
    "worker": "scripts/t2scan_consent_install.py",
    "signer": "scripts/t2scan_astra_operator.swift",
    "proposal": "scripts/t2scan_astra_challenge.py",
    "controller": "scripts/provision_t2scan_consent.py",
}
DIGEST = re.compile(r"[a-f0-9]{40}")
FINGERPRINT = re.compile(r"SHA256:[A-Za-z0-9+/]{43}")
SIGNING_DOMAIN = b"Agent Harness T2Scan Astra direct approval v1\x00"


class Refusal(ValueError):
    """Setup or authorization cannot continue."""


def require(condition, message):
    if not condition:
        raise Refusal(message)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def base64str(data):
    return base64.b64encode(data).decode("ascii")


def execute(args, *, input=None, timeout=40, tty=False):
    result = subprocess.run(args, input=input, stdout=subprocess.PIPE,
                            stderr=None if tty else subprocess.DEVNULL,
                            timeout=timeout, check=True)
    return result.stdout


def private(path):
    info = path.lstat()
    require(path.is_absolute() and path.resolve() == path and stat.S_ISDIR(info.st_mode)
            and info.st_uid == os.geteuid() and not info.st_mode & 0o077,
            "Use a private non-symlink operator directory.")
    return path


def pinned_release(ref, stage):
    repo = stage / "verified"
    repo.mkdir(mode=0o700)
    env = {name: item for name, item in os.environ.items() if not name.startswith("GIT_")}
    env.update(GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull, GIT_TERMINAL_PROMPT="0")

    def git(*args):
        return subprocess.run(["/usr/bin/git", *args], cwd=repo, env=env, stdin=subprocess.DEVNULL,
                              stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=40, check=True).stdout

    git("init", "--quiet")
    git("fetch", "--quiet", "--no-tags", ORIGIN, "+refs/heads/main:refs/remotes/verified/main")
    require(git("cat-file", "-t", ref).strip() == b"commit", "Use an exact canonical main commit.")
    git("merge-base", "--is-ancestor", ref, "refs/remotes/verified/main")
    result = {name: git("show", f"{ref}:{path}") for name, path in SOURCES.items()}
    require(result["controller"] == Path(__file__).read_bytes(), "Run the provisioning command from the reviewed release.")
    return result


def known_host_pin(stage, fingerprint):
    host_db = Path.home() / ".ssh" / "known_hosts"
    matches = execute(["/usr/bin/ssh-keygen", "-F", HOST, "-f", str(host_db)]).decode("ascii").splitlines()
    keys = set()
    for line in matches:
        words = line.split()
        if len(words) >= 3 and words[1] == "ssh-ed25519":
            blob = base64.b64decode(words[2], validate=True)
            pin = "SHA256:" + base64str(hashlib.sha256(blob).digest()).rstrip("=")
            if pin == fingerprint:
                keys.add(words[2])
    require(len(keys) == 1, "Independently verified host key is missing from known_hosts.")
    path = stage / "known_hosts"
    path.write_text(f"{HOST} ssh-ed25519 {keys.pop()}\n", encoding="ascii")
    return path


def ssh(known, code, *, input=None):
    return execute([
        "/usr/bin/ssh", "-T", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes",
        "-o", f"UserKnownHostsFile={known}", "-o", "GlobalKnownHostsFile=/dev/null", "-o", f"HostKeyAlias={HOST}",
        "-o", "HostKeyAlgorithms=ssh-ed25519", "-o", "ClearAllForwardings=yes", "-o",
        "KnownHostsCommand=none", "-o", "VerifyHostKeyDNS=no", "-o", "UpdateHostKeys=no",
        "-o", "PermitLocalCommand=no", "-o", "ConnectTimeout=8", HOST, code,
    ], input=input, timeout=125)


def remote_factory(known, assets, options, uid):
    # The reviewed verifier source supplies the shared P-256 input check for the root receiver.
    proof_source = repr(assets["verifier"])
    worker_source = assets["worker"].decode("utf-8")
    hashes = {name: sha(assets[name]) for name in ("verifier", "socket", "service")}
    source = worker_source + f"\nproof = {{'__name__': 't2scan_consent'}}\nexec(compile({proof_source}, 'verified consent', 'exec'), proof)\n"
    source += (f"try:\n    worker(proof['public_key_format'], {options.ref!r}, {hashes!r})\n"
               "except Exception:\n    print('T2Scan consent provisioning refused.', file=sys.stderr)\n    sys.exit(2)\n")
    shell = shlex.join(["/usr/bin/sudo", "-n", "/usr/bin/python3", "-I", "-c", source])

    def invoke(phase, payload):
        request = json.dumps(dict(phase=phase, issuer=options.issuer, fingerprint=options.fingerprint,
                                  uid=uid, payload=payload), separators=(",", ":")).encode("ascii")
        try:
            reply = json.loads(ssh(known, shell, input=request))
            require(type(reply) is dict and reply.keys() == {"status", "result"}
                    and reply["status"] == phase and type(reply["result"]) is dict,
                    "Unverified remote consent provisioning response.")
            if phase == "install":
                expected = dict(ref=options.ref, signer_sha256=payload["signer_sha256"],
                                public_key_sha256=sha(base64.b64decode(payload["public_key"], validate=True)),
                                asset_sha256=hashes)
                require(reply["result"] == expected, "Install response does not bind these exact assets and issuer.")
            return reply["result"]
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            raise Refusal(f"Remote {phase} failed or was unconfirmed. Preserve all existing issuer and replay state.") from error

    return invoke


def activate(remote, enroll, sign):
    remote("check", None)
    enrollment = enroll()
    remote("install", enrollment)
    sign()


def prepare_proposal(options, stage, assets, audience):
    source = stage / "release"
    (source / "scripts").mkdir(parents=True)
    (source / "harness/hooks").mkdir(parents=True)
    for name in ("proposal", "verifier"):
        (source / SOURCES[name]).write_bytes(assets[name])
    fd = os.open(options.manifest, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as scope:
        require(stat.S_ISREG(os.fstat(fd).st_mode), "Expected a regular assignment manifest.")
        contents = scope.read(4097)
    require(0 < len(contents) <= 4096, "Assignment manifest has invalid size.")
    pinned_manifest = stage / "scoped-assignments.json"
    pinned_manifest.write_bytes(contents)
    pinned_manifest.chmod(0o400)
    args = [sys.executable, "-IB", str(source / SOURCES["proposal"]), "--issuer", options.issuer,
            "--audience", audience, "--project", options.project, "--run", options.run,
            "--manifest", str(pinned_manifest), "--out"]
    execute([*args, str(stage / "unsigned-preview.json")])
    return args, sha(contents)


def output_bundle(options, stage, proposal, signer, signer_sha):
    challenge, signature = stage / "challenge.json", stage / "signature.der"
    require(sha(signer.read_bytes()) == signer_sha, "Reviewed signer executable changed after enrollment.")
    arguments, manifest_sha = proposal
    require(sha((stage / "scoped-assignments.json").read_bytes()) == manifest_sha,
            "Validated audit scope changed before signing.")
    execute([*arguments, str(challenge)])
    execute([str(signer), "sign", str(challenge), str(stage / "enrollment.json"), str(signature)],
            timeout=900, tty=True)
    signed = challenge.read_bytes()
    value = json.loads(signed)
    der = signature.read_bytes()
    require(8 <= len(der) <= 72 and int(time.time()) < value["expires_at"], "Detached signature expired or is malformed.")
    public_key = stage / "issuer.pem"
    execute(["/usr/bin/openssl", "dgst", "-sha256", "-verify", str(public_key), "-signature", str(signature)],
            input=SIGNING_DOMAIN + signed)
    proof = json.dumps({"challenge_b64": base64str(signed), "signature_b64": base64str(der)})
    directory = stage / "portable-consent"
    directory.mkdir(mode=0o700)
    assignment_exports = []
    for item in value["assignments"]:
        capsule = directory / f"{item['task_key']}.json"
        fd = os.open(capsule, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "w", encoding="ascii") as output:
            output.write(proof)
        fields = {key: item[key] for key in ("assignment", "work_item_id", "task_key", "packet_sha256")}
        assignment_exports.append(dict(fields, capsule=str(capsule.relative_to(stage))))
    binding = {name: value[name] for name in (
        "project_id", "run_id", "provider", "model", "mode", "issuer", "audience", "created_at", "expires_at"
    )}
    receipt = dict(
        binding, schema="agent-harness.t2scan.astra-approval-export.v1", release_ref=options.ref,
        signer_sha256=signer_sha, public_key_sha256=sha(public_key.read_bytes()), assignments=assignment_exports,
        challenge={"path": challenge.name, "sha256": sha(signed)},
        signature={"path": signature.name, "sha256": sha(der)},
    )
    result = stage / "approval-export.json"
    with tempfile.NamedTemporaryFile(dir=stage, delete=False, mode="w", encoding="utf-8") as pending:
        json.dump(receipt, pending, sort_keys=True)
        pending.flush()
        os.fsync(pending.fileno())
    os.replace(pending.name, result)
    print(f"Signed exact T2Scan batch for {options.run}. Private handoff record: {result}")


def parse():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check", action="store_true", help="read-only preflight (default)")
    mode.add_argument("--apply", action="store_true", help="enroll, provision, and sign the named audit")
    mode.add_argument("--rollback", action="store_true", help="stop and disable the installed socket, preserving state")
    parser.add_argument("--ref", required=True, help="reviewed merged Agent Harness commit")
    parser.add_argument("--issuer", required=True)
    parser.add_argument("--fingerprint", required=True, help="independently verified t2-dev Ed25519 SSH fingerprint")
    parser.add_argument("--project")
    parser.add_argument("--run")
    parser.add_argument("--manifest", type=Path)
    return parser.parse_args()


def main():
    os.umask(0o077)
    options = parse()
    require(sys.platform == "darwin" and os.geteuid() != 0, "Run from the macOS operator account.")
    require(DIGEST.fullmatch(options.ref) and FINGERPRINT.fullmatch(options.fingerprint)
            and re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,63}", options.issuer), "Invalid release or operator pin.")
    require(options.rollback or options.project and options.run and options.manifest, "A named audit and manifest are required.")
    if options.apply or options.rollback:
        require(os.isatty(0) and os.isatty(1), "Use a local interactive operator terminal.")
    work = private(private(Path.home() / ".agent-harness") / "work")
    stage = Path(tempfile.mkdtemp(prefix="t2scan-consent-", dir=work))
    print(f"Private operator work directory: {stage}", flush=True)
    assets = pinned_release(options.ref, stage)
    known = known_host_pin(stage, options.fingerprint)
    identity = ssh(known, "/usr/bin/id -u").decode("ascii").strip()
    require(re.fullmatch(r"[1-9][0-9]{0,9}", identity), "Unexpected execution UID.")
    uid = int(identity)
    remote = remote_factory(known, assets, options, uid)
    expected = json.dumps([options.fingerprint, uid], ensure_ascii=True, separators=(",", ":")).encode("ascii")
    audience = HOST_LABEL + "-" + sha(expected)[:32]
    if options.rollback:
        remote("rollback", options.ref)
        print("Broker disabled. Issuer, audit records and replay state retained on t2-dev.")
        return
    proposal = prepare_proposal(options, stage, assets, audience)
    if not options.apply:
        remote("check", None)
        print(f"Verified release and target {audience}. Preflight left broker files and state untouched.")
        return

    signer_source, signer = stage / "signer.swift", stage / "t2scan-astra-operator"
    signer_source.write_bytes(assets["signer"])
    signer_sha = None

    def enroll():
        nonlocal signer_sha
        execute(["/usr/bin/swiftc", "-parse-as-library", str(signer_source), "-o", str(signer)],
                timeout=90, tty=True)
        signer_sha = sha(signer.read_bytes())
        print(f"T2Scan signer SHA-256 {signer_sha} from reviewed {options.ref}. Target {audience}.", flush=True)
        public_key = execute([str(signer), "enroll", str(stage / "enrollment.json"), options.issuer, audience],
                             timeout=900, tty=True)
        (stage / "issuer.pem").write_bytes(public_key)
        return dict({name: base64str(assets[name]) for name in ("verifier", "socket", "service")},
                    ref=options.ref, signer_sha256=signer_sha, public_key=base64str(public_key))

    activate(remote, enroll, lambda: output_bundle(options, stage, proposal, signer, signer_sha))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        message = str(error) if isinstance(error, Refusal) else "T2Scan setup failed or was cancelled. Inspect the private operator work directory."
        print(message, file=sys.stderr)
        sys.exit(2)
