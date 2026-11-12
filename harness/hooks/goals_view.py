#!/usr/bin/env python3
"""Per-goal status from the mission goal ledger (GoodQA goodqa#15754): the one entry point for "what's left".

Why: on 2026-11-12 main answered "whats left" from `ah status --since 24h`. That report drops every row older than its
window, so three goals proven live two to five days earlier (prod move w16dc0f5dd6b, leads w53ff16565a1, self-update
wa6c1d52d985) read as not done. The ledger (~/.agent-harness/mission/goals.json, mission_coverage.py) holds the goals;
this module reads each goal's attached evidence with NO time window, plus rows tagged `--goal <id>` in the mission
session's WALs, and states what the records prove:

  DONE_LIVE      a passing live test, and no deploy attached after it
  LIVE_UNTESTED  a deploy with no passing live test at or after it
  VERIFIED       a passing test that is not a live test
  FAILING        the newest attached test is a FAIL (a FAIL row never counts as proof)
  IN_PROGRESS    no proof yet, an owner holds it (signed ops-watch owner snapshot)
  UNKNOWN        no proof and no known owner. Never "not started": the records do not say that.
  DEFERRED / RETIRED   from the ledger status

A test row's verdict: an explicit `result` field (wal_note --result) or `REALLY_TESTED <id> PASS|FAIL:` in the note;
otherwise FAIL when the note says FAIL/FAILED/FALSIFIED/"NOT installed"/"code only", else UNSTATED (legacy, counts).
A missing, unreadable or tampered ledger is an error (exit 2), never "nothing left". Output text is at most 4 KB.
Stdlib only; read-only.
"""
from __future__ import annotations

import json
import re
import time
from pathlib import Path

import mission_coverage as mc
import safe_input

TEXT_LIMIT = 4096
NOTE_CAP = 160
TAG_SCAN_BYTES = 64 << 20   # per WAL file
TAG_SCAN_SECONDS = 4.0      # whole scan; a hook calls this with a 10 s budget
RESULT_RE = re.compile(r"^\s*REALLY_TESTED\s+[A-Za-z0-9._-]+\s*:?\s*\b(PASS|FAIL)\b")
RT_RE = re.compile(r"^\s*REALLY_TESTED\s+([A-Za-z0-9._-]+)")
LEGACY_FAIL = re.compile(r"\b(?:FAIL(?:ED|S|ING)?|FALSIFIED|NOT installed)\b|\bcode only\b")
TAG_RE = re.compile(rb'"goal":\s*"([a-z0-9][a-z0-9_-]{0,63})"')
COUNTED = ("PASS", "UNSTATED")
ORDER = {"FAILING": 0, "UNKNOWN": 1, "LIVE_UNTESTED": 2, "IN_PROGRESS": 3, "VERIFIED": 4, "DEFERRED": 5,
         "DONE_LIVE": 6, "RETIRED": 7}


def _redact(text: str) -> str:
    try:
        import redact  # noqa: PLC0415
        return redact.redact(text)
    except Exception:  # noqa: BLE001 - without the redactor the note is still capped
        return text


def excerpt(text, cap: int = NOTE_CAP) -> str:
    return _redact(re.sub(r"\s+", " ", str(text or "")).strip())[:cap]


def verdict(rec: dict) -> str:
    """DEPLOY, PASS, FAIL or UNSTATED (a legacy REALLY_TESTED row without a stated result); '' for anything else."""
    if rec.get("event") == "deploy":
        return "DEPLOY"
    note = str(rec.get("note") or "")
    if not RT_RE.match(note):
        return ""
    stated = str(rec.get("result") or "").upper()
    if stated in ("PASS", "FAIL"):
        return stated
    m = RESULT_RE.match(note)
    if m:
        return m.group(1)
    return "FAIL" if LEGACY_FAIL.search(note) else "UNSTATED"


def tagged_rows(home: Path, session: str, goal_ids, as_of=None, budget_s: float = TAG_SCAN_SECONDS) -> dict:
    """{goal id: [(wal name, record)]} for every evidence row of `session` that carries `goal: <id>` (wal_note --goal).
    Whole files, no time window; bounded per file and in total time (a partial scan says so)."""
    out, partial = {g: [] for g in goal_ids}, False
    if not mc.SESSION_RE.match(session or ""):
        return {"rows": out, "partial": False}
    folder = mc.claude_dir() / "wals" / session
    if not folder.is_dir() or folder.is_symlink():
        return {"rows": out, "partial": False}
    started = time.monotonic()
    for path in sorted(folder.glob("*.jsonl")):
        if time.monotonic() - started > budget_s:
            partial = True
            break
        if path.is_symlink() or not mc.WAL_NAME_RE.match(path.name):
            continue
        try:
            raw_all = safe_input.read_bounded(path, TAG_SCAN_BYTES)
        except (OSError, safe_input.InputRejected):
            partial = True
            continue
        if b'"goal"' not in raw_all:
            continue
        for raw in raw_all.splitlines():
            m = TAG_RE.search(raw)
            if not m or m.group(1).decode() not in out:
                continue
            try:
                rec = json.loads(raw)
            except ValueError:
                continue
            if not isinstance(rec, dict) or rec.get("goal") != m.group(1).decode() or not verdict(rec):
                continue
            if as_of is not None and mc.parse_ts(rec.get("at")) > as_of:
                continue
            out[rec["goal"]].append((path.name, rec))
    return {"rows": out, "partial": partial}


def _item(home: Path, now: float, session: str, wal: str, rec, kind: str, wid: str, by: str) -> dict:
    if rec is None:
        return {"id": wid, "kind": kind, "verdict": "MISSING", "at": None, "age_s": None, "wal": wal, "by": by,
                "note": "attached id not found in its WAL"}
    at = mc.parse_ts(rec.get("at"))
    v = verdict(rec)
    if kind == "deploy" and v != "DEPLOY":
        v = "MISSING"
    return {"id": wid, "kind": kind, "verdict": v or "MISSING", "at": mc.iso(at) if at else None,
            "age_s": int(now - at) if at else None, "wal": wal, "by": by, "_at": at,
            "check": (RT_RE.match(str(rec.get("note") or "")) or [None, None])[1],
            "note": excerpt(rec.get("note"))}


def evidence_state(items: list) -> str:
    tests = [i for i in items if i["kind"] in ("test", "live_test") and i["verdict"] in ("PASS", "FAIL", "UNSTATED")]
    deploys = [i for i in items if i["kind"] == "deploy" and i["verdict"] == "DEPLOY"]
    if tests:
        newest = max(tests, key=lambda i: i.get("_at") or 0)
        if newest["verdict"] == "FAIL":
            return "FAILING"
    live = [i for i in tests if i["kind"] == "live_test" and i["verdict"] in COUNTED]
    last_deploy = max((i.get("_at") or 0 for i in deploys), default=None)
    last_live = max((i.get("_at") or 0 for i in live), default=None)
    if last_live is not None and (last_deploy is None or last_deploy <= last_live):
        return "DONE_LIVE"
    if last_deploy is not None:
        return "LIVE_UNTESTED"
    if any(i["verdict"] in COUNTED for i in tests):
        return "VERIFIED"
    return ""


def goals_report(home: Path, now=None, as_of=None, session=None, owner_rows=None, scan_budget_s=TAG_SCAN_SECONDS) -> dict:
    """The per-goal report. `as_of` (epoch) ignores evidence written after it (the status lint's calibration replays
    an old answer against what the records held then). owner_rows: an `ah owners` row list; default the signed
    ops-watch snapshot when fresh, else no owner data (said so)."""
    now = time.time() if now is None else now
    audit = mc.verify_audit(home)
    loaded = mc.load_goals(home)
    base = {"generated": mc.iso(now), "as_of": mc.iso(as_of) if as_of else None, "goals": [], "warnings": []}
    if loaded["state"] == "absent":
        return dict(base, state="absent", error=f"no goal ledger at {mc.goals_path(home)}: goal status is UNKNOWN; "
                                                "do not answer from memory (main seeds it with mission_coverage.py)")
    if loaded["state"] == "error":
        return dict(base, state="error", error=f"goal ledger unreadable: {loaded.get('error')}")
    if not audit.get("ok"):
        return dict(base, state="tampered", error=f"goal ledger fails its audit chain: {audit.get('problem')}")
    mission = loaded.get("mission_session") or ""
    session = (session or mission or mc.main_session(home) or "").lower()
    goals = [g for g in loaded["goals"]]
    tagged = tagged_rows(home, session, [g["id"] for g in goals], as_of=as_of, budget_s=scan_budget_s)
    if tagged["partial"]:
        base["warnings"].append("tag scan was partial (time or size bound); attached evidence is complete")
    owners_note = ""
    if owner_rows is None:
        snap = mc.load_owner_snapshot(home, session, now) if session else None
        owner_rows = snap.get("rows") if snap else None
        owners_note = "" if snap else "no fresh owner snapshot (run ah owners for live owners)"
    if owners_note:
        base["warnings"].append(owners_note)
    out = []
    for g in goals:
        items, seen = [], set()
        for r in g.get("evidence") or []:
            wal, rec = mc.find_wal_row(home, r["session"], r["id"], r["wal"])
            if rec is not None and as_of is not None and mc.parse_ts(rec.get("at")) > as_of:
                continue
            items.append(_item(home, now, r["session"], r["wal"], rec, r["kind"], r["id"], r.get("by") or "?"))
            seen.add(r["id"])
        for wal, rec in tagged["rows"].get(g["id"], []):
            wid = rec.get("id")
            if wid in seen:
                continue
            seen.add(wid)
            v = verdict(rec)
            kind = "deploy" if v == "DEPLOY" else ("live_test" if rec.get("live") is True else "test")
            items.append(_item(home, now, session, wal, rec, kind, str(wid or "?"), "tag"))
        status = g.get("status", "active")
        state = evidence_state(items)
        key = mc.ticket_key(g.get("ticket"))
        holders = []
        if owner_rows:
            holders = sorted({r.get("agent_id") for r in owner_rows if isinstance(r, dict) and mc._matches(r, g, key)
                              and mc.live_owner(r)} - {None})
        if status == "retired":
            state = "RETIRED"
        elif status == "deferred" and state != "DONE_LIVE":
            state = "DEFERRED"
        elif not state:
            state = "IN_PROGRESS" if holders else "UNKNOWN"
        items.sort(key=lambda i: -(i.get("_at") or 0))
        for i in items:
            i.pop("_at", None)
        deferral = g.get("deferral") or {}
        out.append({"id": g["id"], "title": excerpt(g.get("title"), 120), "ticket": key or "",
                    "ledger_status": status, "state": state, "priority": g.get("priority", 3),
                    "target": excerpt((g.get("target") or {}).get("text"), 200) or None,
                    "target_source": bool((g.get("target") or {}).get("source")),
                    "aliases": list(g.get("aliases") or []), "owners": holders,
                    "deferral": {k: deferral.get(k) for k in ("by", "ref", "until")} if deferral else None,
                    "missing": [i["id"] for i in items if i["verdict"] == "MISSING"],
                    "evidence": items})
    out.sort(key=lambda r: (ORDER.get(r["state"], 9), r["priority"], r["id"]))
    return dict(base, state="ok", session=session, mission_session=mission, goals=out)


def fmt_age(seconds) -> str:
    if seconds is None:
        return "?"
    s = int(seconds)
    return f"{s // 86400}d{(s % 86400) // 3600}h" if s >= 86400 else f"{s // 3600}h{(s % 3600) // 60:02d}m" \
        if s >= 3600 else f"{s // 60}m"


def goals_text(doc: dict, limit: int = TEXT_LIMIT) -> str:
    """Readable report, at most `limit` bytes (UTF-8). Evidence lines shrink first, then goals are cut with a note."""
    if doc.get("state") != "ok":
        return f"GOALS UNAVAILABLE ({doc.get('state')}): {excerpt(doc.get('error'), 400)}"
    head = (f"Goals from the mission ledger ({len(doc['goals'])} goals, evidence of any age"
            + (f", as of {doc['as_of']}" if doc.get("as_of") else "") + "). Report these states; UNKNOWN means "
            "no record either way, never 'not started'. FAIL rows never count.")

    def block(g, per_goal: int, note_cap: int) -> list:
        bits = [f"{g['state']:<13} {g['id']}" + (f" ({g['ticket']})" if g["ticket"] else "") + f": {g['title']}"]
        if g.get("target"):
            bits.append(f"    target: {g['target'][:note_cap]}")
        if g.get("owners"):
            bits.append("    owner: " + ", ".join(a[:17] for a in g["owners"][:3]))
        if g.get("deferral"):
            d = g["deferral"]
            bits.append(f"    deferred: {d.get('by')} {d.get('ref') or ''} until {d.get('until') or '?'}")
        for i in g["evidence"][:per_goal]:
            bits.append(f"    {i['id']} {i['verdict']:<8} {i['kind']:<9} {fmt_age(i['age_s']):>6} ago  "
                        f"{(i['note'] or '')[:note_cap]}")
        if len(g["evidence"]) > per_goal:
            bits.append(f"    (+{len(g['evidence']) - per_goal} more: ah goals --json)")
        return bits

    warn = ["warning: " + w for w in doc.get("warnings") or []]
    for per_goal, note_cap in ((3, 110), (2, 80), (1, 60), (1, 30), (0, 0)):
        lines = [head]
        for g in doc["goals"]:
            lines += block(g, per_goal, note_cap)
        lines += warn
        text = "\n".join(lines)
        if len(text.encode()) <= limit:
            return text
    tail = "\n(truncated at 4 KB; ah goals --json has every goal)"
    return text.encode()[:limit - len(tail.encode())].decode("utf-8", "ignore") + tail
