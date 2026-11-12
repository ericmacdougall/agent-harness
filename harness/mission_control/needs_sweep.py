"""The "Needs you" sweeper (GoodQA #15585): keeps the list the user sees current and honest.

One sweep takes the asks ledger of main's session (open, blocked and recently resolved asks) and decides, per ask:

    cleared   settled, so hidden: resolved in a session WAL, the ticket named by its own `[ticket:ref]` tag closed,
              its owner gone and reassigned, or the same words as an older ask of the same WAL that is in plain view.
              Listed under "cleared recently" with the reason and the evidence.
    stale     past its `until` (or TTL_S with no activity). Moved to the Stale section; still answerable; never hidden.
    flagged   its source does not trace. Shown as untraceable, never as a valid ask.
    active    everything else.

It writes only under MC_HOME/needs: the per-session state, an append-only audit log (one row per transition, never
one per sweep) and a heartbeat that ops_watch reads. It never writes a WAL, a chat record or an answer: hiding a
settled ask is the whole of its authority. Sweeps are serialized by a file lock, so two at once are safe.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import stat
import time
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path

import mc_chat

TTL_S = 72 * 3600                 # an open ask with no activity for this long is stale
SWEEP_EVERY_S = 300
HEARTBEAT_STALE_S = 3 * SWEEP_EVERY_S
CLEARED_KEEP_S = 7 * 86400        # "cleared recently"
CLEARED_SHOWN = 50
TICKET_LOOKUPS_PER_SWEEP = 8
TICKET_RECHECK_S = 30 * 60        # a ticket state, open or closed, is looked up again after this long (a reopen restores its asks)
AUDIT_MAX_BYTES = 4 * 1024 * 1024
ASK_RE = re.compile(r"^[A-Za-z0-9_-]{1,40}$")
SESSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{7,63}$")
# Only the ask's own tag names its ticket. A ticket merely mentioned in the text ("goodqa#14000 was closed by
# mistake; may I reopen it?") is never a reason to hide the ask.
TICKET_TAG_RE = re.compile(r"^\s*\[ticket:([a-z][a-z0-9-]{1,30}#\d{2,7})\]")  # it must open the note
AGENT_RE = re.compile(r"^agent-([A-Za-z0-9]{1,64})$")
# Provenance could not finish the check (it ran out of time or hit its own error). That is "not checked this
# sweep", never "untraceable": the ask stays listed, but its source was never verified, so the page shows it as
# answerable by reply only (no Approve or Deny, no digest) and /api/approve refuses it. too-many-sources is not
# here: it is a caller error (wal_note.CALLER_ERROR_CODES), a source that can never resolve, so it stays flagged.
UNCHECKED_RE = re.compile(r"^(scan-timeout|internal)\b")


def unchecked(row: dict) -> bool:
    return bool(UNCHECKED_RE.match(str(row.get("problem", ""))))


def needs_dir(root: Path) -> Path:
    path = Path(root) / "needs"
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.is_symlink():
        raise mc_chat.ChatError("unsafe-path", "needs is a symlink")
    os.chmod(path, 0o700)
    return path


@contextmanager
def _lock(folder: Path):
    fd = os.open(folder / ".lock", os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise mc_chat.ChatError("unsafe-path", "sweep lock is not a regular file")
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def _epoch(value) -> float | None:
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp()
    except (TypeError, ValueError):
        return None


def _clip(text, limit: int) -> str:
    text = mc_chat._redact(" ".join(str(text or "").split()))
    return text if len(text) <= limit else text[:limit - 1] + "…"


def _days(seconds: float) -> str:
    return f"{int(seconds // 86400)} d" if seconds >= 86400 else f"{int(seconds // 3600)} h"


def _text_key(row: dict) -> str:
    """Two asks are duplicates when their text and reason read the same, whatever the spacing or case."""
    body = " ".join(str(row.get("note", "")).split()).lower() + "\n" + " ".join(str(row.get("reason", "")).split()).lower()
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def _tickets(folder: Path) -> dict:
    data = mc_chat.read_json(folder / "tickets.json")
    return data if isinstance(data, dict) else {}


def _ticket_state(ref: str, cache: dict, lookup, budget: list, now: float) -> str | None:
    known = cache.get(ref)
    if isinstance(known, dict) and 0 <= now - known.get("at", 0) < TICKET_RECHECK_S:
        return known.get("state")
    if lookup is None or budget[0] <= 0:
        return None  # no fresh answer: unknown, which never hides an ask
    budget[0] -= 1
    try:
        state = lookup(ref)
    except Exception:  # noqa: BLE001 - a failed lookup decides nothing
        state = None
    if state in ("open", "closed"):
        cache[ref] = {"state": state, "at": now}
        return state
    return None  # unknown: never a reason to hide an ask


def _gone_owners(owners) -> dict:
    """agent id -> evidence, for owners that are gone AND whose stream was reassigned (a recorded disposition in
    force). A dropped owner with no such record keeps its asks in view."""
    out = {}
    for row in owners or ():
        if not isinstance(row, dict):
            continue
        disposition = row.get("disposition") if isinstance(row.get("disposition"), dict) else {}
        state = str(row.get("state", ""))
        gone = state.upper().startswith(("DROPPED", "SILENT")) or state in ("done", "handoff", "superseded", "returned")
        if gone and disposition.get("kind") == "reassigned" and disposition.get("live") is True:
            agent = str(row.get("agent_id", ""))
            if agent:
                out[agent] = ("owner:%s reassigned %s" % (agent[:40], _clip(disposition.get("ref") or "", 40))).strip()
    return out


def _decide(data: dict, owners, ticket_status, activity: dict, cache: dict, now: float) -> dict:
    """ask id -> {"state", "reason", "evidence"} for every ask in this ledger read."""
    out: dict[str, dict] = {}
    rows = [r for r in data.get("items") or [] if isinstance(r, dict) and ASK_RE.match(str(r.get("id", "")))]
    for row in data.get("resolved") or []:
        if isinstance(row, dict) and ASK_RE.match(str(row.get("id", ""))):
            by = str(row.get("resolved_by") or "")
            out[row["id"]] = {"state": "cleared", "reason": "resolved", "when": _epoch(row.get("resolved_at")),
                              "evidence": "wal:" + by if ASK_RE.match(by) else "wal:ask_resolved"}
    for row in data.get("blocked") or []:
        if isinstance(row, dict) and ASK_RE.match(str(row.get("id", ""))) and row["id"] not in out:
            if unchecked(row):
                rows.append(row)  # judged like any open ask below
                continue
            out[row["id"]] = {"state": "flagged", "evidence": "provenance",
                              "reason": "no traceable source: " + _clip(row.get("problem") or "source does not resolve", 160)}
    gone = _gone_owners(owners)
    budget = [TICKET_LOOKUPS_PER_SWEEP]
    absorbing: dict[tuple, str] = {}  # (owner WAL, text) -> the oldest ACTIVE ask with those words
    for row in sorted(rows, key=lambda r: (str(r.get("at", "")), r["id"])):
        ident = row["id"]
        if ident in out:
            continue
        agent = AGENT_RE.match(str(row.get("owner", "")))
        ticket = TICKET_TAG_RE.match(str(row.get("note", "")))
        asked = _epoch(row.get("at")) or now
        last = max(asked, activity.get(ident) or 0)
        until = _epoch(row.get("until")) if row.get("until") else None
        stale, why = (now >= until, "past its until time") if until is not None \
            else (now - last >= TTL_S, f"no activity for {_days(now - last)}")
        key = (str(row.get("owner", "")), _text_key(row))
        if agent and agent.group(1) in gone:
            out[ident] = {"state": "cleared", "reason": "owner-reassigned", "evidence": gone[agent.group(1)]}
        elif ticket and _ticket_state(ticket.group(1), cache, ticket_status, budget, now) == "closed":
            out[ident] = {"state": "cleared", "reason": "ticket-closed", "evidence": "ticket:" + ticket.group(1)}
        elif key in absorbing:
            # Same words, same WAL, and the older copy is in plain view (active): the user still sees and can
            # answer the question. A stale copy, or one another agent registered, never absorbs an ask.
            out[ident] = {"state": "cleared", "reason": "duplicate", "evidence": "ask:" + absorbing[key]}
        elif stale:
            out[ident] = {"state": "stale", "reason": why, "evidence": "age"}
        else:
            absorbing[key] = ident
            out[ident] = {"state": "active", "reason": "", "evidence": ""}
    return out


def sweep(root: Path, session: str, data: dict, *, owners=(), ticket_status=None, activity: dict | None = None,
          now: float | None = None) -> dict:
    """Run one sweep over a ledger read and return the view: {"status": {ask id: {state, reason, evidence}},
    "cleared": [rows, newest first], "swept_at": epoch}. Writes state, audit rows for transitions and the heartbeat."""
    if not isinstance(session, str) or not SESSION_RE.match(session):
        raise mc_chat.ChatError("bad-session", "the sweep needs main's session id")
    now = time.time() if now is None else now
    data = data if isinstance(data, dict) else {}
    folder = needs_dir(root)
    texts = {str(r.get("id")): r for key in ("items", "blocked", "resolved") for r in data.get(key) or []
             if isinstance(r, dict)}
    with _lock(folder):
        cache = _tickets(folder)
        decided = _decide(data, owners, ticket_status, activity or {}, cache, now)
        state_path = folder / (session + ".json")
        previous = mc_chat.read_json(state_path, limit=4 * 1024 * 1024)
        asks = previous.get("asks") if isinstance(previous, dict) and isinstance(previous.get("asks"), dict) else {}
        rows = []
        for ident, verdict in decided.items():
            when = verdict.pop("when", None)  # a resolved ask is listed at the time it was resolved, not noticed
            before = asks.get(ident) if isinstance(asks.get(ident), dict) else {}
            changed = (before.get("state"), before.get("reason") if verdict["state"] == "cleared" else None) != \
                      (verdict["state"], verdict["reason"] if verdict["state"] == "cleared" else None)
            if not changed:
                verdict = dict(verdict, at=before.get("at", now))
            else:
                verdict = dict(verdict, at=min(now, when) if when else now)
                action = verdict["state"] if verdict["state"] != "active" else ("restored" if before else None)
                if action:
                    rows.append({"at": mc_chat.now_iso(now), "session": session, "ask_id": ident, "action": action,
                                 "reason": verdict["reason"] or "its reason no longer holds",
                                 "evidence": verdict["evidence"] or str(before.get("evidence", "")),
                                 "text": _clip(texts.get(ident, {}).get("note"), 200)})
            asks[ident] = dict(verdict, text=_clip(texts.get(ident, {}).get("note"), 200) or before.get("text", ""))
        # asks that left the ledger entirely (older than its history window) age out of the state file
        for ident in [k for k, v in asks.items() if k not in decided and now - (v.get("at") or 0) > CLEARED_KEEP_S]:
            del asks[ident]
        _append_audit(folder, rows)  # also creates the log, so a first sweep leaves all three files
        mc_chat.write_json(state_path, {"session": session, "swept_at": now, "asks": asks})
        mc_chat.write_json(folder / "tickets.json", cache)
        counts = {name: sum(1 for v in decided.values() if v["state"] == name)
                  for name in ("active", "stale", "flagged", "cleared")}
        mc_chat.write_json(folder / "heartbeat.json", {"at": now, "session": session, **counts})
    cleared = sorted(({"id": k, "reason": v["reason"], "evidence": v["evidence"], "at": mc_chat.now_iso(v["at"]),
                       "text": v.get("text", "")} for k, v in asks.items()
                      if v.get("state") == "cleared" and now - (v.get("at") or 0) <= CLEARED_KEEP_S),
                     key=lambda row: row["at"], reverse=True)[:CLEARED_SHOWN]
    return {"status": {k: {"state": v["state"], "reason": v["reason"], "evidence": v["evidence"]}
                       for k, v in decided.items()},
            "cleared": cleared, "swept_at": now}


def _append_audit(folder: Path, rows: list[dict]) -> None:
    """Append-only, one JSON line per transition. Past AUDIT_MAX_BYTES the log rolls once to audit.jsonl.1."""
    path = folder / "audit.jsonl"
    try:
        if os.lstat(path).st_size > AUDIT_MAX_BYTES:
            os.replace(path, folder / "audit.jsonl.1")
    except FileNotFoundError:
        pass
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise mc_chat.ChatError("unsafe-path", "audit log is not a regular file")
        os.write(fd, "".join(json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n" for row in rows).encode("utf-8"))
        os.fsync(fd)
    finally:
        os.close(fd)


def heartbeat_age(root: Path, now: float | None = None) -> float | None:
    """Seconds since the last completed sweep, or None when no sweeper has ever run in this home."""
    beat = mc_chat.read_json(Path(root) / "needs" / "heartbeat.json")
    at = beat.get("at") if isinstance(beat, dict) else None
    if not isinstance(at, (int, float)) or isinstance(at, bool):
        return None
    return max(0.0, (time.time() if now is None else now) - at)
