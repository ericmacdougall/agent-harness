"""Who is calling a hook, and one-shot stamps that only the main agent's hook writes (goodqa#15253).

A payload without agent_id does not prove that main is calling: Codex hook payloads never carry agent_id
(#134 red-team B7). is_main() needs positive evidence instead. The payload has no agent_id and no agent_type, its
session_id is a Claude session id, and its transcript_path is the regular file
<claude home>/projects/<project>/<session_id>.jsonl. A sub-agent transcript is under .../<session_id>/subagents/,
and a Codex rollout is under ~/.codex, so neither qualifies.

Limit: a sub-agent that launches its own `claude -p` starts a new main session with its own transcript; that call is
main here. Threat model, as for the other gates: careless agents, not one that edits the hooks or the stamp files.

Stamps: a PreToolUse hook that has proven main records a stamp for one purpose and key. The process the command
starts takes it (single use, at most STAMP_TTL_SECONDS old). A command no main hook saw, such as one in a copied
script, a script file or a sub-agent's shell, finds no stamp.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import time
import uuid
from pathlib import Path

SESSION_ID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
STAMP_TTL_SECONDS = 600
STAMP_DIR = "main-stamps"


def claude_home(home=None) -> Path:
    if home:
        return Path(home)
    configured = os.environ.get("CLAUDE_CONFIG_DIR")
    return Path(configured) if configured else Path.home() / ".claude"


def is_main(payload, claude_dir=None) -> bool:
    """True only for a Claude Code main-agent payload, proven by its own transcript path (see module doc)."""
    if not isinstance(payload, dict) or payload.get("agent_id") or payload.get("agent_type"):
        return False
    session, path = payload.get("session_id"), payload.get("transcript_path")
    if not isinstance(session, str) or not SESSION_ID.match(session) or not isinstance(path, str) or "\x00" in path:
        return False
    try:
        projects = os.path.realpath(str(claude_home(claude_dir) / "projects"))
        real = Path(os.path.realpath(path))
        return (real.name == session + ".jsonl" and str(real.parent.parent) == projects and real.is_file()
                and not real.is_symlink())
    except (OSError, ValueError):
        return False


def stamp_dir(home=None) -> Path:
    return Path(home or Path.home()) / ".agent-harness" / "state" / STAMP_DIR


def stamp_key(purpose: str, parts) -> str:
    text = "|".join([purpose] + [str(p).strip().lower() for p in parts])
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()[:40]


def put_stamp(purpose: str, parts, session: str = "", home=None, now=None) -> None:
    folder = stamp_dir(home)
    folder.mkdir(parents=True, exist_ok=True, mode=0o700)
    key = stamp_key(purpose, parts)
    tmp = folder / ("%s.%s.tmp" % (key, uuid.uuid4().hex[:8]))
    tmp.write_text(json.dumps({"purpose": purpose, "session": str(session)[:80], "ts": now or time.time()}),
                   encoding="utf-8")
    os.chmod(str(tmp), 0o600)
    os.replace(str(tmp), str(folder / (key + ".json")))


def take_stamp(purpose: str, parts, home=None, now=None):
    """The stamp record (consumed) or None: missing, already used, expired or unreadable."""
    folder = stamp_dir(home)
    path = folder / (stamp_key(purpose, parts) + ".json")
    claimed = folder / (path.stem + ".%s.claimed" % uuid.uuid4().hex[:8])
    try:
        if path.is_symlink():
            return None
        os.rename(str(path), str(claimed))  # atomic: of two takers only one wins
    except OSError:
        return None
    try:
        with open(str(claimed), "rb") as handle:
            data = json.loads(handle.read(4096).decode("utf-8"))
    except (OSError, ValueError):
        data = None
    finally:
        try:
            os.unlink(str(claimed))
        except OSError:
            pass
    if not isinstance(data, dict) or data.get("purpose") != purpose:
        return None
    try:
        if (now or time.time()) - float(data["ts"]) > STAMP_TTL_SECONDS:
            return None
    except (KeyError, TypeError, ValueError):
        return None
    return data
