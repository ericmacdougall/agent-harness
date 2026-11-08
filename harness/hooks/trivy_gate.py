#!/usr/bin/env python3
"""Pinned Trivy dependency and misconfiguration scan of one reviewed commit (goodqa#15295).

    python3 trivy_gate.py --repo <worktree> [--rev HEAD] (--trivy-sha256 <hex> [--trivy <path>] | --trivy-image <ref@sha256:...>)

Trivy (Apache-2.0, Aqua Security) is used only as an external pinned artifact; none of its code or rules is
copied here. Two runners, both pinned:
  * a local binary whose SHA-256 must match --trivy-sha256; the hashed bytes are copied into a private
    directory and that copy is run, so the binary cannot be swapped between the check and the run;
  * a container image named by digest (repo@sha256:<64 hex>); a tag alone is refused.

What is scanned is exactly the commit: `git archive <rev>` extracted into a private directory with links that
leave it refused, so ignored, untracked and uncommitted files are never part of the result. Trivy runs with
`--scanners vuln,misconfig --severity HIGH,CRITICAL --format json` and an empty private ignore file, so a
repository .trivyignore cannot quietly suppress anything.

Accepted risks live in the tracked file .agent-harness/trivy-ignore.json, reviewed with the code:
    {"ignores": [{"id": "CVE-2026-0001", "statement": "why this is acceptable", "expired_at": "2026-12-31"}]}
Every entry needs an id, a statement and an expired_at no more than 366 days ahead. An entry past its date no
longer suppresses and is listed as expired. An optional "package" narrows the entry to one package name.

Output names only the finding id, package, installed and fixed version, severity, target path and rule title.
Code excerpts, matches and secret fields from the report are never printed.

Exit codes: 0 clean, 1 findings, 2 unable to scan (missing or unpinned Trivy, a failed run, a database that
could not be fetched, an unreadable report, a bad ignore file, or nothing scannable). 2 is never a pass.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile

IGNORE_PATH = ".agent-harness/trivy-ignore.json"
MAX_IGNORE_DAYS = 366
DEFAULT_TIMEOUT = 900
MAX_LINES = 200
DIGEST_REF = re.compile(r"^[a-z0-9][a-z0-9._/:-]*@sha256:[0-9a-f]{64}$")
SHA256 = re.compile(r"^[0-9a-fA-F]{64}$")
# Files Trivy reads for dependency (vuln) or configuration (misconfig) findings. A commit with none of them is
# reported as NOTHING_SCANNED, never as clean.
LOCKFILES = frozenset({
    "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock", "requirements.txt",
    "Pipfile.lock", "poetry.lock", "uv.lock", "pdm.lock", "go.mod", "go.sum", "Cargo.lock", "Gemfile.lock",
    "composer.lock", "pom.xml", "gradle.lockfile", "packages.lock.json", "mix.lock", "pubspec.lock",
    "Podfile.lock", "Package.resolved", "conan.lock",
})
CONFIG_NAMES = frozenset({"Dockerfile", "Containerfile", "Chart.yaml"})
CONFIG_SUFFIXES = (".dockerfile", ".tf", ".tf.json")
SEVERITIES = ("HIGH", "CRITICAL")


class GateError(Exception):
    """The scan could not be completed; always exit 2."""


def clean(value, limit=160):
    text = "" if value is None else str(value)
    text = "".join(char if char.isprintable() else " " for char in text).strip()
    return text[:limit]


def scan_targets(names):
    found = []
    for name in names:
        base = PurePosixPath(name).name
        if base in LOCKFILES or base in CONFIG_NAMES or base.endswith(CONFIG_SUFFIXES) or base.startswith("Dockerfile."):
            found.append(name)
    return found


def export_commit(repo, rev, destination):
    """Extract exactly `rev` into `destination`; returns the tracked file names."""
    archive = subprocess.run(["git", "-C", str(repo), "archive", "--format=tar", rev], capture_output=True,
                             timeout=300)
    if archive.returncode:
        raise GateError(f"git archive {clean(rev, 80)} failed")
    names = []
    root = Path(destination).resolve()
    with tarfile.open(fileobj=io.BytesIO(archive.stdout)) as bundle:
        for member in bundle.getmembers():
            path = PurePosixPath(member.name)
            if path.is_absolute() or ".." in path.parts:
                raise GateError("archive member escapes the scan directory")
            if member.issym() or member.islnk():
                target = (root / path.parent / member.linkname).resolve() if member.issym() else (root / member.linkname).resolve()
                if root != target and root not in target.parents:
                    raise GateError(f"link leaves the scan directory: {clean(member.name)}")
            if not (member.isfile() or member.isdir() or member.issym() or member.islnk()):
                raise GateError(f"unsupported archive member: {clean(member.name)}")
            member.mode &= 0o755
            if member.isfile():
                names.append(member.name)
        bundle.extractall(root)
    return names


def load_ignores(source_dir, today):
    path = Path(source_dir) / IGNORE_PATH
    if not path.exists():
        return [], []
    if path.is_symlink() or not path.is_file():
        raise GateError(f"{IGNORE_PATH} must be a regular file")
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        raise GateError(f"{IGNORE_PATH} is not valid JSON") from None
    entries = data.get("ignores") if isinstance(data, dict) else None
    if not isinstance(entries, list):
        raise GateError(f'{IGNORE_PATH} needs an "ignores" list')
    active, expired = [], []
    for number, entry in enumerate(entries, 1):
        if not isinstance(entry, dict):
            raise GateError(f"{IGNORE_PATH} entry {number} is not an object")
        ident, statement, until = entry.get("id"), entry.get("statement"), entry.get("expired_at")
        if not isinstance(ident, str) or not ident.strip():
            raise GateError(f"{IGNORE_PATH} entry {number} has no id")
        if not isinstance(statement, str) or not statement.strip():
            raise GateError(f"{IGNORE_PATH} entry {number} ({clean(ident, 40)}) has no statement")
        try:
            expiry = dt.date.fromisoformat(until) if isinstance(until, str) else None
        except ValueError:
            expiry = None
        if expiry is None:
            raise GateError(f"{IGNORE_PATH} entry {number} ({clean(ident, 40)}) needs expired_at as YYYY-MM-DD")
        if (expiry - today).days > MAX_IGNORE_DAYS:
            raise GateError(f"{IGNORE_PATH} entry {number} ({clean(ident, 40)}) expires more than "
                            f"{MAX_IGNORE_DAYS} days ahead")
        package = entry.get("package")
        if package is not None and not isinstance(package, str):
            raise GateError(f"{IGNORE_PATH} entry {number} ({clean(ident, 40)}) has a non-text package")
        record = {"id": ident.strip(), "package": package, "expired_at": expiry.isoformat()}
        (active if expiry >= today else expired).append(record)
    return active, expired


def findings_from(report):
    if not isinstance(report, dict) or not isinstance(report.get("Results", []), list):
        raise GateError("Trivy report has no Results list")
    found = []
    for result in report.get("Results") or []:
        if not isinstance(result, dict):
            raise GateError("Trivy report has a malformed result")
        target = clean(result.get("Target"))
        for vuln in result.get("Vulnerabilities") or []:
            if isinstance(vuln, dict) and str(vuln.get("Severity", "")).upper() in SEVERITIES:
                found.append({"kind": "vuln", "id": clean(vuln.get("VulnerabilityID"), 64),
                              "package": clean(vuln.get("PkgName"), 120),
                              "installed": clean(vuln.get("InstalledVersion"), 64),
                              "fixed": clean(vuln.get("FixedVersion"), 64),
                              "severity": clean(vuln.get("Severity"), 16).upper(), "target": target})
        for misconfig in result.get("Misconfigurations") or []:
            if (isinstance(misconfig, dict) and misconfig.get("Status", "FAIL") == "FAIL"
                    and str(misconfig.get("Severity", "")).upper() in SEVERITIES):
                found.append({"kind": "misconfig", "id": clean(misconfig.get("AVDID") or misconfig.get("ID"), 64),
                              "package": "", "title": clean(misconfig.get("Title"), 120),
                              "severity": clean(misconfig.get("Severity"), 16).upper(), "target": target})
    return found


def suppressed(finding, ignores):
    return any(entry["id"] in (finding["id"],) and (entry["package"] is None or entry["package"] == finding["package"])
               for entry in ignores)


def trivy_args(target, output, ignorefile):
    return ["fs", "--scanners", "vuln,misconfig", "--severity", ",".join(SEVERITIES), "--format", "json",
            "--output", output, "--exit-code", "0", "--ignorefile", ignorefile, "--quiet", target]


def run_binary(binary, pin, private, source, timeout):
    if not pin or not SHA256.match(pin):
        raise GateError("refused: no pinned SHA-256 for the trivy binary (--trivy-sha256)")
    exe = binary or shutil.which("trivy")
    if not exe or not Path(exe).is_file():
        raise GateError("trivy binary not found")
    data = Path(exe).read_bytes()  # read once: the bytes hashed are the bytes run
    if hashlib.sha256(data).hexdigest() != pin.lower():
        raise GateError("refused: trivy binary does not match the pinned SHA-256")
    copy = private / "bin" / "trivy"
    copy.parent.mkdir(mode=0o700)
    copy.write_bytes(data)
    copy.chmod(stat.S_IRWXU)
    ignorefile, output = private / "empty.trivyignore", private / "out" / "report.json"
    ignorefile.write_text("")
    command = [str(copy), *trivy_args(str(source), str(output), str(ignorefile))]
    return command, output, private


def run_image(image, private, source):
    if not image or not DIGEST_REF.match(image):
        raise GateError("refused: --trivy-image must be pinned by digest (name@sha256:<64 hex>)")
    if not shutil.which("docker"):
        raise GateError("docker not found for --trivy-image")
    (private / "empty.trivyignore").write_text("")
    output = private / "out" / "report.json"
    command = ["docker", "run", "--rm", "-v", f"{source}:/src:ro", "-v", f"{private / 'out'}:/out",
               "-v", f"{private / 'empty.trivyignore'}:/ignore/empty.trivyignore:ro", image,
               *trivy_args("/src", "/out/report.json", "/ignore/empty.trivyignore")]
    return command, output, private


def scan(repo, *, rev="HEAD", binary=None, sha256=None, image=None, today=None, timeout=DEFAULT_TIMEOUT):
    """Return (exit_code, lines). Never raises for an ordinary scan failure: that is exit 2."""
    lines = []
    today = today or dt.date.today()
    try:
        if bool(image) == bool(sha256):
            raise GateError("choose exactly one runner: --trivy-sha256 (binary) or --trivy-image (digest)")
        with tempfile.TemporaryDirectory(prefix="trivygate-") as private_name:
            private = Path(private_name)
            os.chmod(private, 0o700)
            source = private / "src"
            source.mkdir(mode=0o700)
            (private / "out").mkdir(mode=0o700)
            os.chmod(private / "out", 0o777 if image else 0o700)  # the container user writes the report
            names = export_commit(Path(repo), rev, source)
            targets = scan_targets(names)
            if not targets:
                raise GateError("NOTHING_SCANNED: the commit has no lockfile, manifest or scannable config; "
                                "this is not a clean result, drop --scan trivy for this repository")
            active, expired = load_ignores(source, today)
            if image:
                command, output, _ = run_image(image, private, source)
            else:
                command, output, _ = run_binary(binary, sha256, private, source, timeout)
            try:
                completed = subprocess.run(command, cwd=private, stdin=subprocess.DEVNULL, capture_output=True,
                                           timeout=timeout)
            except subprocess.TimeoutExpired:
                raise GateError(f"trivy did not finish within {timeout} seconds") from None
            if completed.returncode:
                raise GateError(f"trivy exited {completed.returncode} (database unavailable or scan error); "
                                "not a pass")
            try:
                report = json.loads(output.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                raise GateError("trivy wrote no readable JSON report") from None
            found = findings_from(report)
        lines.append(f"trivy: scanned {len(targets)} target file(s) at {clean(rev, 40)}")
        for entry in expired:
            lines.append(f"trivy: ignore entry {clean(entry['id'], 64)} expired {entry['expired_at']} "
                         "and no longer suppresses")
        blocking = []
        for finding in found:
            if suppressed(finding, active):
                package = f" {finding['package']}" if finding["package"] else ""
                lines.append(f"trivy: ignored {finding['id']}{package} in {finding['target']} "
                             "(accepted in " + IGNORE_PATH + ")")
            else:
                blocking.append(finding)
        for finding in blocking[:MAX_LINES]:
            if finding["kind"] == "vuln":
                fixed = f", fixed in {finding['fixed']}" if finding["fixed"] else ", no fix yet"
                lines.append(f"trivy: {finding['severity']} {finding['id']} {finding['package']} "
                             f"{finding['installed']}{fixed} ({finding['target']})")
            else:
                lines.append(f"trivy: {finding['severity']} {finding['id']} {finding['title']} ({finding['target']})")
        if len(blocking) > MAX_LINES:
            lines.append(f"trivy: {len(blocking) - MAX_LINES} more finding(s) not shown")
        if blocking:
            lines.append(f"trivy: FAIL, {len(blocking)} HIGH/CRITICAL finding(s)")
            return 1, lines
        lines.append("trivy: PASS, no unaccepted HIGH/CRITICAL findings")
        return 0, lines
    except GateError as error:
        lines.append(f"trivy: {error}")
        return 2, lines
    except (OSError, subprocess.SubprocessError, tarfile.TarError) as error:
        lines.append(f"trivy: scan failed ({type(error).__name__}); not a pass")
        return 2, lines


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--repo", default=".")
    parser.add_argument("--rev", default="HEAD")
    parser.add_argument("--trivy", help="trivy binary path (default: trivy on PATH)")
    parser.add_argument("--trivy-sha256", default=os.environ.get("AGENT_HARNESS_TRIVY_SHA256"))
    parser.add_argument("--trivy-image", default=os.environ.get("AGENT_HARNESS_TRIVY_IMAGE"))
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    args = parser.parse_args(argv)
    code, lines = scan(args.repo, rev=args.rev, binary=args.trivy, sha256=args.trivy_sha256,
                       image=args.trivy_image, timeout=args.timeout)
    print("\n".join(lines))
    return code


if __name__ == "__main__":
    sys.exit(main())
