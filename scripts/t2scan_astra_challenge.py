#!/usr/bin/env python3
"""Prepare an unsigned, exact-scope T2Scan operator challenge."""

import argparse
import os
from pathlib import Path
import secrets
import stat
import sys
import time


sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "harness" / "hooks"))
import t2scan_consent as protocol  # noqa: E402


def create_challenge(*, issuer, audience, project, run, manifest, lifetime):
    protocol.require(protocol.matches(protocol.ID, issuer) and protocol.matches(protocol.ID, audience))
    protocol.require(0 < lifetime <= protocol.MAX_LIFETIME)
    protocol.require(manifest.keys() == {"assignments"})
    entries = manifest["assignments"]
    protocol.require(type(entries) is list and len(entries) == 3)
    items = []
    for entry in entries:
        protocol.require(type(entry) is dict and entry.keys() == {"assignment", "work_item_id", "packet_sha256"})
        work = entry["work_item_id"]
        protocol.require(protocol.matches(r"wrk_[A-Za-z0-9_-]{4,64}", work))
        task_digest = protocol.sha(protocol.canonical([project, run, work]))[:32]
        items.append({**entry, "task_key": f"t2scan-audit-{task_digest}-astra-direct", "nonce": secrets.token_hex(32)})
    now = int(time.time())
    raw = protocol.canonical({
        "schema": protocol.SCHEMA,
        "issuer": issuer,
        "audience": audience,
        "provider": "codex",
        "model": protocol.MODEL,
        "mode": "direct",
        "project_id": project,
        "run_id": run,
        "created_at": now,
        "expires_at": now + lifetime,
        "assignments": sorted(items, key=lambda item: item["work_item_id"]),
    })
    protocol.validate_challenge(raw, issuer, audience)
    return raw


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--issuer", required=True)
    parser.add_argument("--audience", required=True)
    parser.add_argument("--project", required=True)
    parser.add_argument("--run", required=True)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--out", required=True, type=Path)
    parser.add_argument("--lifetime", type=int, default=protocol.MAX_LIFETIME)
    args = parser.parse_args()
    try:
        fd = os.open(args.manifest, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as source:
            protocol.require(stat.S_ISREG(os.fstat(fd).st_mode))
            manifest = protocol.object_json(source.read(protocol.MAX_CHALLENGE + 1), protocol.MAX_CHALLENGE)
        raw = create_challenge(issuer=args.issuer, audience=args.audience, project=args.project,
                               run=args.run, manifest=manifest, lifetime=args.lifetime)
        fd = os.open(args.out, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as output:
            output.write(raw)
    except (OSError, ValueError, RecursionError):
        parser.exit(2, "T2Scan challenge refused.\n")


if __name__ == "__main__":
    main()
