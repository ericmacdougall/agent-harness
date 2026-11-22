"""Normalize only the local package versions in the pinned public release lock."""

import hashlib
from pathlib import Path
import sys
import tomllib


RELEASE_VERSION = "0.169.0"
LOCAL_PACKAGE_COUNT = 173
ORIGINAL_SHA256 = "56e04c89b25a6efa1fa6f1cf02934e92451933c8ebda57a5153207ba9ea9fb9e"
NORMALIZED_SHA256 = "200de438778a44c55d452b8931f5293ec3d7bda66c48717605b202764a4d3f7a"


def parse_packages(raw):
    return tomllib.loads(raw.decode("utf-8"))["package"]


def verify_workspace_members(root, expected_names):
    workspace_path = root / "Cargo.toml"
    workspace = tomllib.loads(workspace_path.read_text(encoding="utf-8"))["workspace"]
    if workspace["package"]["version"] != RELEASE_VERSION:
        raise ValueError("Unexpected workspace version")
    names = set()
    for path in root.rglob("Cargo.toml"):
        if path == workspace_path:
            continue
        package = tomllib.loads(path.read_text(encoding="utf-8")).get("package", {})
        name = package.get("name")
        if name in expected_names:
            if name in names or package.get("version") != {"workspace": True}:
                raise ValueError("Unverified inherited workspace version")
            names.add(name)
    if names != expected_names:
        raise ValueError("Missing workspace package manifest")
    return names


def normalize_workspace_versions(raw, names):
    packages = parse_packages(raw)
    identities = {(p["name"], p["version"], p.get("source")) for p in packages}
    local = [p for p in packages if "source" not in p]
    if len(identities) != len(packages) or len(local) != len(names) or {p["name"] for p in local} != names:
        raise ValueError("Unexpected locked workspace packages")
    for p in packages:
        if p["name"] in names and ("source" in p or p["version"] != "0.0.0"):
            raise ValueError("Conflicting locked workspace identity")
        for edge in p.get("dependencies", []):
            name, separator, _ = edge.partition(" ")
            if separator and name in names:
                raise ValueError("Qualified workspace dependency edge")

    marker = b"\n[[package]]\n"
    header, *blocks = raw.split(marker)
    for i, (block, p) in enumerate(zip(blocks, packages, strict=True)):
        if p["name"] in names:
            prefix = f'name = "{p["name"]}"\nversion = "0.0.0"\n'.encode("ascii")
            if not block.startswith(prefix):
                raise ValueError("Noncanonical workspace lock block")
            replacement = f'name = "{p["name"]}"\nversion = "{RELEASE_VERSION}"\n'.encode("ascii")
            blocks[i] = replacement + block[len(prefix):]
    return marker.join([header, *blocks])


def normalize_pinned_file(root):
    lock = root / "Cargo.lock"
    raw = lock.read_bytes()
    if hashlib.sha256(raw).hexdigest() != ORIGINAL_SHA256:
        raise ValueError("Original lock digest mismatch")
    names = {p["name"] for p in parse_packages(raw) if "source" not in p}
    if len(names) != LOCAL_PACKAGE_COUNT:
        raise ValueError("Unexpected workspace package count")
    repaired = normalize_workspace_versions(raw, verify_workspace_members(root, names))
    if hashlib.sha256(repaired).hexdigest() != NORMALIZED_SHA256:
        raise ValueError("Normalized lock digest mismatch")
    lock.write_bytes(repaired)


if __name__ == "__main__":
    try:
        (root,) = sys.argv[1:]
        normalize_pinned_file(Path(root))
    except (OSError, TypeError, ValueError, KeyError):
        raise SystemExit("The pinned Cargo lockfile normalization could not be verified.") from None
    print(f"upstream_cargo_lock_sha256={ORIGINAL_SHA256}")
    print(f"effective_cargo_lock_sha256={NORMALIZED_SHA256}")
