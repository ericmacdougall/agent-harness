#!/usr/bin/env python3
"""PreToolUse hook for the lane factory (GoodQA goodqa#15946): stamp a plain `ah lane <command>` call so the command
can prove who called it.

It stamps only for main (proven by `caller_identity.is_main`) running a plain `ah.py lane <command>` with no shell
syntax, or for a sub-agent's own `checkpoint` (the stamp carries the payload's agent id). It prints nothing, never
blocks and fails open: any error means no stamp, and a missing stamp makes the `ah lane` command refuse.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

LIMIT = 1 << 20


def main() -> int:
    try:
        raw = sys.stdin.read(LIMIT + 1)
        if len(raw) > LIMIT:
            return 0
        payload = json.loads(raw)
        from lane import auth  # noqa: PLC0415
        auth.stamp_command(payload)
    except Exception:  # noqa: BLE001 - fail open: no stamp, the command refuses
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
