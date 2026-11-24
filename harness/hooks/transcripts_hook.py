#!/usr/bin/env python3
"""Claude Code SessionStart hook: start a detached transcript archive sync (GoodQA #16650, spec AC-8).

SessionStart `source` maps to a checkpoint: startup is a project start (`start`); resume, compact and clear are a
recovery (`recovery`). The hook spawns `transcripts.py sync --checkpoint <c> --background` from its own directory
(TRANSCRIPTS_BIN overrides the path, for tests) in a new session with no inherited pipes, and returns at once. It
prints nothing, never blocks and always exits 0: a missing tool, bad input or a failed spawn only means no sync.
"""
import json
import os
import subprocess
import sys
from pathlib import Path

RECOVERY_SOURCES = frozenset({"resume", "compact", "clear"})


def checkpoint_for(source) -> str:
    return "recovery" if source in RECOVERY_SOURCES else "start"


def tool_path() -> Path:
    override = os.environ.get("TRANSCRIPTS_BIN")
    return Path(override) if override else Path(__file__).resolve().with_name("transcripts.py")


def spawn_sync(checkpoint: str) -> bool:
    """Start `sync --checkpoint <checkpoint> --background` detached; True when a process was started. Never raises."""
    try:
        script = tool_path()
        if not script.is_file():
            return False
        argv = ([sys.executable, str(script)] if script.suffix == ".py" else [str(script)])
        subprocess.Popen(argv + ["sync", "--checkpoint", checkpoint, "--background"], stdin=subprocess.DEVNULL,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True, close_fds=True)
        return True
    except Exception:  # noqa: BLE001 - a session must never fail because the archive could not start
        return False


def read_source() -> str:
    try:
        if sys.stdin is None or sys.stdin.isatty():
            return ""
        data = json.loads(sys.stdin.read(1 << 20) or "{}")
        return str(data.get("source") or "") if isinstance(data, dict) else ""
    except Exception:  # noqa: BLE001
        return ""


def main(argv=None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if args[:1] in (["session-start"], []):
        spawn_sync(checkpoint_for(read_source()))
    return 0


if __name__ == "__main__":
    try:
        main()
    except BaseException:  # noqa: BLE001 - always exit 0
        pass
    sys.exit(0)
