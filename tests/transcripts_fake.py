"""A stand-in for harness/hooks/transcripts.py (GoodQA #16650), used through TRANSCRIPTS_BIN.

It follows the core writer's CLI contract only:
  sync --checkpoint C [--budget-seconds N] [--background]
  check [--max-age-min N] [--json]   exit 0 ok, 1 stale, 2 failed/cap/held/disk-low, 3 never-ok
Every call appends its argv as one JSON line to FAKE_TRANSCRIPTS_LOG. The behaviour comes from the environment:
  FAKE_SYNC_SLEEP   seconds the sync sleeps (also with --background: a script that fails to detach)
  FAKE_SYNC_RC      the sync exit code
  FAKE_CHECK_JSON   what `check --json` prints
  FAKE_CHECK_RC     the check exit code
  FAKE_CHECK_SLEEP  seconds the check sleeps
  FAKE_ARGV_RC      exit code of any other subcommand (for the ah passthrough)
"""
import os
from pathlib import Path

SCRIPT = r'''#!/usr/bin/env python3
import json, os, sys, time
log = os.environ.get("FAKE_TRANSCRIPTS_LOG")
if log:
    with open(log, "a") as handle:
        handle.write(json.dumps(sys.argv[1:]) + "\n")
command = sys.argv[1] if len(sys.argv) > 1 else ""
if command == "sync":
    time.sleep(float(os.environ.get("FAKE_SYNC_SLEEP", "0")))
    sys.exit(int(os.environ.get("FAKE_SYNC_RC", "0")))
if command == "check":
    time.sleep(float(os.environ.get("FAKE_CHECK_SLEEP", "0")))
    sys.stdout.write(os.environ.get("FAKE_CHECK_JSON", "{}") + "\n")
    sys.exit(int(os.environ.get("FAKE_CHECK_RC", "0")))
sys.stdout.write("fake transcripts " + " ".join(sys.argv[1:]) + "\n")
sys.exit(int(os.environ.get("FAKE_ARGV_RC", "0")))
'''


def write_fake(directory, name="transcripts.py") -> Path:
    path = Path(directory) / name
    path.write_text(SCRIPT)
    os.chmod(path, 0o755)
    return path


def now_iso():
    from datetime import datetime, timezone  # noqa: PLC0415
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def read_log(path):
    import json  # noqa: PLC0415
    try:
        return [json.loads(line) for line in Path(path).read_text().splitlines() if line.strip()]
    except FileNotFoundError:
        return []


def wait_for_log(path, count=1, timeout=5.0):
    import time  # noqa: PLC0415
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        rows = read_log(path)
        if len(rows) >= count:
            return rows
        time.sleep(0.05)
    return read_log(path)
