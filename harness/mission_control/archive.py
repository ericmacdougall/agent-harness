"""The archive rule for asks and requirements (GoodQA goodqa#15920).

One pure, deterministic rule decides whether an item is live or archived and says why. It reads data only; it
never deletes, writes or calls anything, and the caller keeps every record. Same rows and same clock give the
same answer, whatever order the rows arrive in.

First match wins:

    R1  terminal state      the row's own state is resolved, closed, done, superseded, expired, declined or
                            withdrawn; an ask carries resolved_at; or the sweeper cleared it as resolved or
                            because its owner was reassigned.
    R2  proven or closed    the newest deploy or live-test evidence is PASS, or the linked ticket is closed.
                            FAIL, UNSTATED and unknown never archive. A reopened ticket restores the item.
    R3  superseded          a newer row of the same session (same owner for asks) has the same words.
    R4  expired             an ask is past its own `until`; a requirement is older than REQUIREMENT_TTL_S and
                            has no owner, ticket or evidence (the number is an ASSUMPTION, tunable).

Everything else is live. An ask that is only quiet for ASK_STALE_S stays live and is marked stale: it is still
answerable and never hidden.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone

REQUIREMENT_TTL_S = 30 * 86400
ASK_STALE_S = 72 * 3600
TEXT_MAX = 2000
TERMINAL_STATES = frozenset({"resolved", "closed", "done", "superseded", "expired", "declined", "withdrawn"})
PROOF_KINDS = frozenset({"deploy", "live_test", "really_tested"})
CLEARED_RULES = {"resolved": "R1", "owner-reassigned": "R1", "ticket-closed": "R2", "duplicate": "R3", "expired": "R4"}
RULE_TITLES = {
    "R1": "terminal state", "R2": "proven or closed", "R3": "superseded", "R4": "expired", "live": "open",
}


def _epoch(value):
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        return _parse_iso(value)
    except (ValueError, OverflowError, OSError):
        return None


def _parse_iso(value: str):
    parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.timestamp()


def _text(value, limit: int = TEXT_MAX) -> str:
    if isinstance(value, str):
        text = value
    elif value is None or isinstance(value, (dict, list)):
        text = ""
    else:
        text = str(value)
    text = " ".join(text.split())
    return text if len(text) <= limit else text[:limit - 1] + "…"


def _key(row: dict) -> str:
    return " ".join(str(row.get("text") or "").split()).lower()


def _evidence(value) -> list[dict]:
    if isinstance(value, dict):
        return [value]
    if isinstance(value, list):
        return [v for v in value if isinstance(v, dict)]
    return []


def _proof(evidence: list[dict]):
    """The newest deploy or live-test record: (verdict upper-case, id), or None."""
    proofs = [e for e in evidence if str(e.get("kind", "")).lower() in PROOF_KINDS]
    if not proofs:
        return None
    # newest by `at`, then later in the list; deterministic for any input order of equal stamps
    best = max(enumerate(proofs), key=lambda p: (_epoch(p[1].get("at")) or 0.0, json.dumps(p[1], sort_keys=True, default=str)))[1]
    return str(best.get("verdict") or "").upper(), _text(best.get("id"), 80)


def _normalise(row: dict, kind: str) -> dict:
    text = row.get("text") if kind != "ask" else (row.get("note") if row.get("note") is not None else row.get("text"))
    state = row.get("state")
    out = {
        "id": _text(row.get("id"), 80), "kind": kind, "text": _text(text), "at": _text(row.get("at"), 40),
        "state": _text(state, 40).lower() if isinstance(state, str) else "",
        "session": _text(row.get("session"), 80), "owner": _text(row.get("owner"), 80),
        "ticket": row.get("ticket") if isinstance(row.get("ticket"), str) else "",
        "source": _text(row.get("source"), 400), "until": _text(row.get("until"), 40),
        "resolved_at": _text(row.get("resolved_at"), 40), "resolution": _text(row.get("resolution"), 300),
        "decision": _text(row.get("decision"), 40), "resolved_by": _text(row.get("resolved_by"), 80),
        "reason_in": _text(row.get("reason"), 300), "evidence_in": _text(row.get("evidence"), 200)
        if isinstance(row.get("evidence"), str) else "",
        "evidence": _evidence(row.get("evidence")),
        "full_len": len(text) if isinstance(text, str) else 0,
    }
    return out


def _decide(row: dict, now: float, newest_with_words: dict, ticket_closed):
    kind = row["kind"]
    at = _epoch(row["at"])
    age = max(0.0, now - at) if at is not None else None
    # R1
    if kind == "cleared":
        rule = CLEARED_RULES.get(row["reason_in"])
        if rule:
            return "archived", rule, f"cleared by the sweeper: {row['reason_in']}", row["evidence_in"], {}
    if row["state"] in TERMINAL_STATES:
        return "archived", "R1", f"state is {row['state']}", row["resolved_by"] and "wal:" + row["resolved_by"] or "", {}
    if kind == "ask" and row["resolved_at"]:
        how = row["resolution"] or row["decision"] or "resolved in a session WAL"
        return "archived", "R1", f"resolved: {how}", "wal:" + (row["resolved_by"] or "ask_resolved"), {}
    # R2
    proof = _proof(row["evidence"])
    if proof and proof[0] == "PASS":
        return "archived", "R2", "deploy or live test passed", proof[1], {}
    if row["ticket"] and ticket_closed is not None:
        try:
            closed = ticket_closed(row["ticket"])
        except Exception:  # noqa: BLE001 - a failed lookup decides nothing
            closed = None
        if closed is True:
            return "archived", "R2", f"ticket {row['ticket']} is closed", "ticket:" + row["ticket"], {}
    # R3
    newest = newest_with_words.get(_group(row))
    if newest is not None and newest is not row and newest["id"] != row["id"]:
        return "archived", "R3", f"superseded by newer {kind} {newest['id']} with the same words", f"{kind}:{newest['id']}", {}
    # R4
    extra: dict = {}
    if kind == "ask":
        until = _epoch(row["until"]) if row["until"] else None
        if until is not None and now >= until:
            return "archived", "R4", "past its own until time", "until:" + row["until"], {}
        if age is not None and age >= ASK_STALE_S:
            extra["stale"] = True
    elif kind == "requirement":
        guarded = bool(row["owner"] or row["ticket"] or row["evidence"] or row["evidence_in"])
        if age is not None and not guarded:
            if age > REQUIREMENT_TTL_S:
                return "archived", "R4", f"older than {REQUIREMENT_TTL_S // 86400} d with no owner, ticket or evidence", "age", {}
            extra["expires_in_s"] = int(REQUIREMENT_TTL_S - age)
    return "live", "live", "open: nothing has resolved, superseded or expired it", "", extra


def _group(row: dict):
    if row["kind"] == "cleared":
        return None
    words = _key(row)
    return (row["kind"], row["session"] if row["kind"] == "requirement" else row["owner"], words) if words else None


def classify_all(items, kind: str, now: float, ticket_closed=None) -> list[dict]:
    """Classify rows of one kind ("requirement", "ask" or "cleared"). Returns new dicts, newest first, one per id,
    each with bucket, rule, reason and evidence_ref. Bad rows are skipped, never raised on."""
    rows: dict[str, dict] = {}
    for raw in items if isinstance(items, (list, tuple)) else ():
        if not isinstance(raw, dict) or not isinstance(raw.get("id"), str) or not raw["id"].strip():
            continue
        row = _normalise(raw, kind)
        held = rows.get(row["id"])
        order = (_epoch(row["at"]) or 0.0, json.dumps(raw, sort_keys=True, default=str))
        if held is None or order > held["_order"]:
            row["_order"] = order
            rows[row["id"]] = row
    newest: dict = {}
    for row in rows.values():
        group = _group(row)
        if group is None:
            continue
        top = newest.get(group)
        if top is None or (_epoch(row["at"]) or 0.0, row["id"]) > (_epoch(top["at"]) or 0.0, top["id"]):
            newest[group] = row
    out = []
    for row in rows.values():
        bucket, rule, reason, ref, extra = _decide(row, now, newest, ticket_closed)
        done = {k: v for k, v in row.items() if k not in ("_order", "evidence_in", "reason_in", "evidence")}
        done["ask_reason"] = row["reason_in"] if kind == "ask" else ""
        done.update(bucket=bucket, rule=rule, rule_title=RULE_TITLES[rule], reason=reason, evidence_ref=ref, **extra)
        done["has_evidence"] = bool(row["evidence"] or row["evidence_in"])
        out.append(done)
    out.sort(key=lambda r: (-(_epoch(r["at"]) or 0.0), r["id"]))
    return out


def summary(rows) -> dict:
    counts = {"live": 0, "archived": 0, "rules": {}}
    for row in rows:
        counts[row["bucket"]] += 1
        counts["rules"][row["rule"]] = counts["rules"].get(row["rule"], 0) + 1
    return counts
