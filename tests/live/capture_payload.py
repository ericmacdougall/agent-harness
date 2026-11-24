#!/usr/bin/env python3
"""AC-7 live kit helper: append one hook payload, as Claude Code sent it, to a private file in the kit's disposable
folder. Always exits 0 with no output, so it never changes a tool call. Usage: capture_payload.py EVENT OUT_FILE."""
import json
import os
import sys


def main() -> int:
    try:
        event, out = sys.argv[1], sys.argv[2]
        payload = json.loads(sys.stdin.read(1 << 20) or "{}")
        fd = os.open(out, os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            os.write(fd, (json.dumps({"event": event, "payload": payload}) + "\n").encode("utf-8"))
        finally:
            os.close(fd)
    except Exception:  # noqa: BLE001 -- a capture failure must never affect the session
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
