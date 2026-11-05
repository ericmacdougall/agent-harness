"""Fake `gh` executable for tests/live_merge_gate.py: answers with the FakeGh scenario named in $HOME/scenario.
Never talks to GitHub and never merges (FakeGh raises if asked to)."""

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_merge_gate import SCENARIOS, FakeGh  # noqa: E402

home = Path(os.environ["HOME"])
scenario = (home / "scenario").read_text().strip()
counter = home / "prviews"
gh = FakeGh(SCENARIOS[scenario])
try:
    gh.pr_views = int(counter.read_text())
except (OSError, ValueError):
    gh.pr_views = 0
try:
    rc, out, err = gh(sys.argv[1:], 8)
finally:
    counter.write_text(str(gh.pr_views))
sys.stdout.write(out)
sys.stderr.write(err)
sys.exit(rc)
