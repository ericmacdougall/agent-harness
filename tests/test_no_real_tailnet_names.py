"""Committed files must not carry a real Tailscale MagicDNS name (device + tailnet id); this repo is public.

Fixtures use the reserved tailnet id `tail1234` (e.g. `box.tail1234.ts.net`). Bare `*.ts.net` examples without a
tailnet id are fine. Main's decision on goodqa#15585 after a real name reached pushed history in 22ebf7d.
"""
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
FIXTURE_TAILNETS = {"tail1234"}
TAILNET_NAME = re.compile(r"(?i)\b(tail[0-9a-z]{3,})\.ts\.net\b")


def real_tailnet_names(text: str) -> list[str]:
    return sorted({m.group(0) for m in TAILNET_NAME.finditer(text) if m.group(1).lower() not in FIXTURE_TAILNETS})


def tracked_files() -> list[Path]:
    out = subprocess.run(["git", "-C", str(REPO), "ls-files", "-z"], capture_output=True, timeout=30)
    if out.returncode != 0:
        return []
    return [REPO / name for name in out.stdout.decode("utf-8", "replace").split("\0") if name]


class NoRealTailnetNames(unittest.TestCase):
    def test_the_detector_catches_a_real_looking_name_and_spares_fixtures(self):
        self.assertEqual(real_tailnet_names("host = 'my-laptop.tailabc123.ts.net'"), ["tailabc123.ts.net"])
        self.assertEqual(real_tailnet_names("box.tail1234.ts.net and NAME.ts.net and evil.ts.net"), [])
        with tempfile.TemporaryDirectory() as tmp:
            planted = Path(tmp) / "x.py"
            planted.write_text("URL = 'https://Some-Mac.TAILF00D99.ts.net/'\n")
            self.assertTrue(real_tailnet_names(planted.read_text()))

    def test_no_tracked_file_contains_a_real_tailnet_name(self):
        files = tracked_files()
        if not files:
            self.skipTest("not a git checkout (no tracked file list); the scan needs one")
        found = {}
        for path in files:
            try:
                if path.is_symlink() or not path.is_file() or path.stat().st_size > 2_000_000:
                    continue
                names = real_tailnet_names(path.read_text(encoding="utf-8", errors="replace"))
            except OSError:
                continue
            if names:
                found[str(path.relative_to(REPO))] = names
        self.assertEqual(found, {}, "real Tailscale names in committed files; use box.tail1234.ts.net in fixtures")


if __name__ == "__main__":
    unittest.main()
