#!/usr/bin/env python3
"""Shared per-turn Stop block counter (GoodQA goodqa#15754 spec delta M6).

`stop_hook_active` is one flag for every Stop hook: when one hook blocks, the next Stop arrives with it set and every
other hook skips its own check. A hook that calls allow(session, turn, hook) instead blocks at most `per_hook` times
per user turn whatever the other hooks did, and all callers together at most `total` times per turn, so the turn always
ends. State: ~/.agent-harness/state/stop-blocks/<session>.json (0600), the newest turn only. Fails open (returns
False) on any error: a broken counter never traps the agent. Adoption by dropped_gate and mission_gate is a follow-up.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path


def _path(session: str) -> Path:
    home = Path(os.environ.get("AH_HOME") or Path.home())
    safe = re.sub(r"[^A-Za-z0-9._-]", "_", session or "unknown")[:120]
    return home / ".agent-harness" / "state" / "stop-blocks" / f"{safe}.json"


def allow(session: str, turn: str, hook: str, per_hook: int = 1, total: int = 3) -> bool:
    try:
        path = _path(session)
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        try:
            state = json.loads(path.read_text())
        except (OSError, ValueError):
            state = {}
        if not isinstance(state, dict) or state.get("turn") != turn:
            state = {"turn": turn, "hooks": {}}
        hooks = state.setdefault("hooks", {})
        if hooks.get(hook, 0) >= per_hook or sum(hooks.values()) >= total:
            return False
        hooks[hook] = hooks.get(hook, 0) + 1
        tmp = path.with_suffix(f".{os.getpid()}.tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            json.dump(state, fh)
        os.replace(tmp, path)
        return True
    except Exception:  # noqa: BLE001 - fail open
        return False
