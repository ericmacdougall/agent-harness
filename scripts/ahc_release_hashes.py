#!/usr/bin/env python3
"""Write or check harness/hooks/ahc_release.json, the v5 release's entry-point hash list (goodqa#16049, AC-11).

The list names every ahc_*.py module the ahc CLI, the journal facade, the W16 CLI and both role units load. It is a
data file, not an entry point, so it never lists itself (L-r4-1). Regenerate it as the last step of any change to
those modules: `python3 scripts/ahc_release_hashes.py --write`; tests.test_ahc_migrate checks it with --check.
"""
import hashlib
import json
import sys
from pathlib import Path

HOOKS = Path(__file__).resolve().parents[1] / "harness" / "hooks"
LIST = HOOKS / "ahc_release.json"


def current():
    """The ahc modules install.py ships (an uninstalled module such as ahc_scan.py is not an entry point)."""
    sys.path.insert(0, str(HOOKS.parents[1]))
    import install  # noqa: PLC0415
    names = sorted(n for n in install.HOOKS if n.startswith("ahc_") and n.endswith(".py"))
    return {n: hashlib.sha256((HOOKS / n).read_bytes()).hexdigest() for n in names}


def helpers():
    """The legacy helper scripts the daemon may launch (ahc_guard.HELPER_SCRIPTS), bound by hash (r9 AC-13)."""
    sys.path.insert(0, str(HOOKS))
    import ahc_guard  # noqa: PLC0415
    return {n: hashlib.sha256((HOOKS / f).read_bytes()).hexdigest() for n, f in ahc_guard.HELPER_SCRIPTS.items()}


def main(argv):
    want = {"files": current(), "helpers": helpers(),
            "note": "v5 entry-point and legacy-helper sha256 list; regenerate with scripts/ahc_release_hashes.py"}
    if "--write" in argv:
        LIST.write_text(json.dumps(want, indent=1, sort_keys=True) + "\n")
        return 0
    have = json.loads(LIST.read_text())
    for part in ("files", "helpers"):
        if have.get(part) != want[part]:
            print("ahc_release.json is stale (%s): %s" % (part, sorted(
                k for k in set(have.get(part, {})) | set(want[part]) if have.get(part, {}).get(k) != want[part].get(k))))
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
