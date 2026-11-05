#!/usr/bin/env python3
"""Local pre-push leak gate (no CI).

    python3 scripts/leak_gate.py --range origin/main..HEAD

Refuses to run on a dirty working tree (the tree scan reads files on disk, so uncommitted edits
could hide a committed leak). Runs scripts/leak_scan.py on the tree and on the added lines of the
commits in --range, then gitleaks if installed. The personal denylist is REQUIRED: without it the
generic rules cannot catch owner, org or customer names, so a missing or empty denylist is exit 2,
unless --no-denylist is passed explicitly. gitleaks must match a pinned SHA-256
(--gitleaks-sha256 or AGENT_HARNESS_GITLEAKS_SHA256); the hashed bytes are copied to a private
directory and that copy is run, so the binary cannot be swapped between check and use. A missing
gitleaks is reported as SKIPPED unless --require-gitleaks. Matched values are never printed.

Exit codes: 0 pass, 1 findings, 2 gate misconfigured or unable to run (never a pass).
"""
from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent


def run_scan(repo: Path, rev_range: str, deny_args: list[str]) -> int:
    base = [sys.executable, str(HERE / "leak_scan.py"), "--repo", str(repo), *deny_args]
    codes = [subprocess.run(base).returncode,
             subprocess.run(base + ["--history", "--range", rev_range]).returncode]
    return 2 if 2 in codes else max(codes)


def run_gitleaks(repo: Path, rev_range: str, pin: str | None, required: bool) -> int:
    exe = shutil.which("gitleaks")
    if not exe:
        print("gitleaks: SKIPPED (binary not found)" + (" -- required" if required else ""))
        return 2 if required else 0
    if not pin:
        print("gitleaks: refused, no pinned SHA-256 supplied", file=sys.stderr)
        return 2
    data = Path(exe).read_bytes()  # read once: the bytes hashed are the bytes run
    if hashlib.sha256(data).hexdigest() != pin.lower():
        print("gitleaks: refused, binary does not match pinned SHA-256", file=sys.stderr)
        return 2
    with tempfile.TemporaryDirectory(prefix="leakgate-") as private:
        os.chmod(private, 0o700)
        copy = Path(private) / "gitleaks"
        copy.write_bytes(data)
        copy.chmod(stat.S_IRWXU)
        return subprocess.run([str(copy), "git", "--redact", "--no-banner", "--exit-code", "1",
                               "--log-opts", rev_range, str(repo)]).returncode


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--repo", default=".")
    p.add_argument("--range", dest="rev_range", required=True, help="commits being pushed, e.g. origin/main..HEAD")
    p.add_argument("--denylist", type=Path)
    p.add_argument("--no-denylist", action="store_true", help="explicitly run on the generic rules alone")
    p.add_argument("--gitleaks-sha256", default=os.environ.get("AGENT_HARNESS_GITLEAKS_SHA256"))
    p.add_argument("--require-gitleaks", action="store_true")
    a = p.parse_args(argv)
    repo = Path(a.repo).resolve()
    dirty = subprocess.run(["git", "-C", str(repo), "status", "--porcelain"], capture_output=True, text=True)
    if dirty.returncode or dirty.stdout.strip():
        print("leak gate: refused, working tree is dirty or not a git repository", file=sys.stderr)
        return 2
    deny_args = [] if a.no_denylist else ["--require-denylist"]
    if a.denylist and not a.no_denylist:
        deny_args += ["--denylist", str(a.denylist)]
    rc = run_scan(repo, a.rev_range, deny_args)
    grc = run_gitleaks(repo, a.rev_range, a.gitleaks_sha256, a.require_gitleaks)
    if rc == 0 and grc == 0:
        print("leak gate: PASS" + (" (generic rules only: --no-denylist)" if a.no_denylist else ""))
        return 0
    print("leak gate: FAIL")
    return 2 if 2 in (rc, grc) else 1


if __name__ == "__main__":
    sys.exit(main())
