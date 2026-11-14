"""Which Claude session Mission Control follows, and whether it may write against it (goodqa#15961).

`ah owners` with no --session follows the newest main WAL, Codex sessions included, so the dashboard silently
switched to whichever session wrote last. This module picks the session on purpose and never guesses:

- a config/flag pin (MC_HOME/config.json "session" or `serve --session`), validated as a Claude session;
- else the mission goal ledger's `mission_session`, read from `ah goals --json` only when its state is "ok";
- else the last good pin, kept in memory for display only.

Session-scoped writes (requirement archive/restore, ask approvals) are allowed only when this tick's
pin comes from an agreeing config pin or an ok ledger (plan Revision 2, D1/D2). Pure: no writes, no subprocesses.
"""
from __future__ import annotations

import os
import re
import stat
from pathlib import Path

UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")


def codex_root_for(wals_root: Path) -> Path:
    """`~/.claude/wals` -> `~/.agent-harness/codex-wals` (the same home)."""
    return Path(wals_root).parent.parent / ".agent-harness" / "codex-wals"


def claude_session_ok(session, wals_root: Path, codex_root: Path | None = None) -> bool:
    """A lowercase UUID whose `<wals_root>/<id>/main.jsonl` is a regular file reached without symlinks, and which is
    not a Codex session (R4, R5). Codex sessions can also have a `~/.claude/wals/<id>/main.jsonl` (review A-4 found
    two on this Mac), so an id present under the Codex WAL root is refused as well."""
    if not isinstance(session, str) or not UUID_RE.fullmatch(session):
        return False
    if os.path.lexists(Path(codex_root or codex_root_for(wals_root)) / session):
        return False
    try:
        folder = os.lstat(wals_root / session)
        main = os.lstat(wals_root / session / "main.jsonl")
    except OSError:
        return False
    return stat.S_ISDIR(folder.st_mode) and stat.S_ISREG(main.st_mode)


def resolve(*, config_pin, ledger: dict | None, wals_root: Path, last_good: str = "") -> dict:
    """-> {display, write, source, reason, warnings}. `display` is what the reads follow (may be ''), `write` is the
    session a session-scoped write may use ('' = refuse, with `write_error` naming why)."""
    warnings = []
    ledger = ledger if isinstance(ledger, dict) else {}
    ledger_state = str(ledger.get("state") or "")
    mission = ledger.get("mission_session")
    ledger_session = ""
    if ledger_state == "ok":
        if claude_session_ok(mission, wals_root):
            ledger_session = mission
        elif mission:
            warnings.append("the mission ledger names a session that is not a Claude session on this Mac; refused")
    elif ledger_state:
        warnings.append(f"the mission ledger is {ledger_state[:20]}; its session is not used")
    pin = ""
    if config_pin not in (None, ""):
        if claude_session_ok(config_pin, wals_root):
            pin = config_pin
        else:
            warnings.append("the configured session pin is not a Claude session on this Mac; ignored")
    if pin:
        if ledger_session and ledger_session != pin:
            warnings.append(f"the configured pin {pin[:8]} differs from the mission ledger's {ledger_session[:8]}; "
                            "writes are refused until they agree")
            return {"display": pin, "write": "", "write_error": "pin_mismatch", "source": "config",
                    "reason": "pinned by config (differs from the mission ledger)", "warnings": warnings}
        return {"display": pin, "write": pin, "write_error": "", "source": "config", "reason": "pinned by config",
                "warnings": warnings}
    if ledger_session:
        return {"display": ledger_session, "write": ledger_session, "write_error": "", "source": "ledger",
                "reason": "the mission ledger's session", "warnings": warnings}
    if last_good and claude_session_ok(last_good, wals_root):
        return {"display": last_good, "write": "", "write_error": "unpinned", "source": "kept",
                "reason": "last good pin kept for display; writes refused until the ledger reads ok", "warnings": warnings}
    return {"display": "", "write": "", "write_error": "unpinned", "source": "",
            "reason": "no session pinned yet: waiting for the mission ledger", "warnings": warnings}


def write_check(pin: dict, shown) -> tuple[int, dict] | None:
    """None when a session-scoped write may proceed against pin['write']; else the (409, body) refusal. `shown` is the
    session the page displayed when the user acted (R6): a pin that moved since then is a conflict, never a write."""
    if not pin.get("write"):
        code = pin.get("write_error") or "unpinned"
        return 409, {"error": code, "message": pin.get("reason") or "Mission Control has no writable session"}
    if shown != pin["write"]:   # a page that sent no session (or an old one) never writes
        return 409, {"error": "session_changed",
                     "message": "the session changed since this page loaded; reload and act again"}
    return None
