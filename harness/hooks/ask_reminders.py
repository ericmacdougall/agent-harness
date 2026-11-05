"""Bounded, escalating reminders for open user asks (GoodQA goodqa#14791, NEVER-LOSE.md P16 / I16).

An open ask (a WAL `ask` entry with no `ask_resolved` naming it) is re-surfaced at fixed stages after it was
opened: at once, +30 min, +2 h, then every 4 h. Each (ask id, stage) fires once, never after the ask is resolved,
and the owner keeps working while it waits. This module is pure: the daemon and the prompt hook call `due()` and
record what they sent through `ah`.
"""
from __future__ import annotations

import json
from pathlib import Path

STAGES_S = (0, 30 * 60, 2 * 3600)   # then every REPEAT_S
REPEAT_S = 4 * 3600
MAX_REPEATS = 42                   # a week of 4-hourly reminders, then only the digest carries it


def stage_at(opened: float, now: float) -> int | None:
    """The highest stage due at `now` for an ask opened at `opened` (0-based), or None before stage 0."""
    age = now - opened
    if age < 0:
        return None
    stage = sum(1 for s in STAGES_S if age >= s) - 1
    if age >= STAGES_S[-1]:
        stage += min(MAX_REPEATS, int((age - STAGES_S[-1]) // REPEAT_S))
    return stage


def due(asks: list, now: float, sent: dict) -> list:
    """asks: [{"id", "opened", "note", "session"}] open asks; sent: {ask id: highest stage already sent}.
    Returns the reminders to send now: [{"id", "stage", "age_s", "note", "session"}], at most one per ask."""
    out = []
    for a in asks:
        stage = stage_at(float(a.get("opened") or 0), now)
        if stage is None or stage <= int(sent.get(a["id"], -1)):
            continue
        out.append({"id": a["id"], "stage": stage, "age_s": int(now - float(a.get("opened") or 0)),
                    "note": str(a.get("note") or "")[:160], "session": a.get("session")})
    return out


def open_asks(wal_path: Path, parse_ts) -> list:
    """Open asks of one session main WAL: `ask` entries with no later `ask_resolved` whose ref names them."""
    asks, resolved = {}, set()
    try:
        with open(wal_path, "rb") as fh:
            for raw in fh:
                try:
                    rec = json.loads(raw)
                except ValueError:
                    continue
                if not isinstance(rec, dict):
                    continue
                if rec.get("event") == "ask" and isinstance(rec.get("id"), str):
                    asks[rec["id"]] = {"id": rec["id"], "opened": parse_ts(rec.get("at")) or 0.0,
                                       "note": rec.get("note") or "", "session": wal_path.parent.name}
                elif rec.get("event") == "ask_resolved" and isinstance(rec.get("ref"), str):
                    resolved.add(rec["ref"])
    except OSError:
        return []
    return [a for k, a in asks.items() if k not in resolved]


def render(reminders: list) -> str:
    """One line per due ask for the prompt context, the console and the digest; never the full question."""
    if not reminders:
        return ""
    parts = []
    for r in sorted(reminders, key=lambda x: -x["age_s"]):
        h, m = divmod(r["age_s"] // 60, 60)
        parts.append(f"[ask:{r['id']}] open {h}h{m:02d}m (reminder {r['stage'] + 1}): {r['note'][:80]}")
    return ("OPEN ASKS awaiting the user (goodqa#14791 P16; answer with the ask id, owners keep working): "
            + "; ".join(parts))
