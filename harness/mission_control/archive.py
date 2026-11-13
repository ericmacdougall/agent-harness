"""The archive rule for asks and requirements (GoodQA goodqa#15920, spec v2).

One pure, deterministic rule decides whether an item is live or archived and says why. It reads data only: it never
deletes, writes or calls anything, and the caller keeps every record. Same rows and same clock give the same answer,
whatever order the rows arrive in.

First match wins:

    M   manual              the user archived or restored this item from the page (an `overrides` row). A restore keeps
                            it live whatever the automatic rules would say. Written by req_actions.py, never here.
    R1  terminal state      the row's own state is resolved, closed, done, superseded, expired, declined or withdrawn;
                            an ask carries resolved_at; the sweeper cleared it as resolved or because its owner was
                            reassigned.
    R2  done live           a deploy and a live test, bound to the same ticket or commit, where the newest of each
                            (sorted by time) is not FAIL / is PASS and the test is not older than the deploy. A local
                            REALLY_TESTED pass, a lone deploy, or an unbound pair never archives. A closed ticket
                            (from the sweeper's cache) also archives; unknown or reopened never does.
    R3  superseded          a newer row of the same session (same owner for asks) has exactly the same words AND that
                            newer row is itself live. Near-duplicates (a changed word) stay live: only an exact match
                            of the full text counts.
    R4  expired             a requirement is older than REQUIREMENT_TTL_S with no owner, ticket or evidence AND it is not
                            sourced to the user (`user:`, `uuid:`, `answer:` or `queue:`). An ask is never archived by age or `until`: it
                            stays live, answerable, with a stale mark. The 30 days is an ASSUMPTION, tunable.

Everything else is live. A user-sourced requirement with no owner stays live with a note saying so; only the user's own
archive click moves it.
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone

REQUIREMENT_TTL_S = 30 * 86400
ASK_STALE_S = 72 * 3600
TEXT_MAX = 2000
TERMINAL_STATES = frozenset({"resolved", "closed", "done", "superseded", "expired", "declined", "withdrawn"})
CLEARED_RULES = {"resolved": "R1", "owner-reassigned": "R1", "ticket-closed": "R2", "duplicate": "R3"}
RULE_TITLES = {"M": "archived from the dashboard", "R1": "terminal state", "R2": "done live or ticket closed", "R3": "superseded",
               "R4": "expired", "live": "open"}
# The kinds provenance.parse_source maps to the user's own words: user:, its uuid: spelling (as `ah user-msg` prints it),
# answer: and queue:. tests.test_mission_control_archive checks this list against provenance itself, so it cannot drift.
USER_SOURCE_KINDS = frozenset({"user", "uuid", "answer", "queue"})
_KIND_RE = re.compile(r"^\s*([A-Za-z]+)\s*:")


def is_user_source(source) -> bool:
    """True when a `Source:` string is one of the user's own words in provenance's sense."""
    match = _KIND_RE.match(source) if isinstance(source, str) else None
    return bool(match) and match.group(1).lower() in USER_SOURCE_KINDS


def digest_of(row_id: str, text: str) -> str:
    """What a manual archive click signs: the id and the full text as the page was shown it."""
    return hashlib.sha256((str(row_id) + "\n" + str(text)).encode("utf-8", "replace")).hexdigest()[:16]


def _parse_iso(value: str):
    parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.timestamp()


def _epoch(value):
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        return _parse_iso(value)
    except (ValueError, OverflowError, OSError):
        return None


def _text(value, limit: int = TEXT_MAX) -> str:
    if isinstance(value, str):
        text = value
    elif value is None or isinstance(value, (dict, list)):
        text = ""
    else:
        text = str(value)
    text = " ".join(text.split())
    return text if len(text) <= limit else text[:limit - 1] + "…"


def _evidence(value) -> list[dict]:
    if isinstance(value, dict):
        return [value]
    if isinstance(value, list):
        return [v for v in value if isinstance(v, dict)]
    return []


def _newest(records: list[dict]):
    """The newest record by time (never by list position); ties break on the record's own content, so input order
    cannot change the answer."""
    if not records:
        return None
    return max(records, key=lambda r: (_epoch(r.get("at")) or 0.0, json.dumps(r, sort_keys=True, default=str)))


def _binding(row: dict, deploy: dict, test: dict):
    """The ticket or commit both records are bound to, or None. Bound means: both name the same non-empty commit or
    ticket, or the row's own ticket is named by both (in a ticket or commit field, or in the check or note)."""
    for key in ("commit", "ticket"):
        a, b = _text(deploy.get(key), 80), _text(test.get(key), 80)
        if a and a == b:
            return f"{key}:{a}"
    ticket = row.get("ticket") or ""
    if ticket:
        for rec in (deploy, test):
            blob = " ".join(_text(rec.get(k), 400) for k in ("ticket", "commit", "check", "note"))
            if ticket.lower() not in blob.lower():
                return None
        return f"ticket:{ticket}"
    return None


def done_live(row: dict):
    """(True, evidence_ref) when a deploy and a live test, bound together, prove the item is done live."""
    kinds = {"deploy": [], "live_test": []}
    for rec in row["evidence"]:
        kind = str(rec.get("kind", "")).lower()
        if kind in kinds:
            kinds[kind].append(rec)
    deploy, test = _newest(kinds["deploy"]), _newest(kinds["live_test"])
    if deploy is None or test is None:
        return False, ""
    if str(deploy.get("verdict", "")).upper() == "FAIL" or str(test.get("verdict", "")).upper() != "PASS":
        return False, ""
    d_at, t_at = _epoch(deploy.get("at")), _epoch(test.get("at"))
    if d_at is None or t_at is None or t_at < d_at:  # a later deploy invalidates an earlier live test
        return False, ""
    bound = _binding(row, deploy, test)
    if not bound:
        return False, ""
    return True, f"{bound} deploy {_text(deploy.get('id'), 40)} + live test {_text(test.get('id'), 40)}"


def _normalise(row: dict, kind: str) -> dict:
    text = row.get("text") if kind != "ask" else (row.get("note") if row.get("note") is not None else row.get("text"))
    state = row.get("state")
    source = _text(row.get("source"), 400)
    full = text if isinstance(text, str) else ""
    return {
        "id": _text(row.get("id"), 80), "kind": kind, "text": _text(text), "at": _text(row.get("at"), 40),
        "state": _text(state, 40).lower() if isinstance(state, str) else "",
        "session": _text(row.get("session"), 80), "owner": _text(row.get("owner"), 80),
        "ticket": row.get("ticket") if isinstance(row.get("ticket"), str) else "",
        "source": source, "user_sourced": is_user_source(source), "until": _text(row.get("until"), 40),
        "resolved_at": _text(row.get("resolved_at"), 40), "resolution": _text(row.get("resolution"), 300),
        "decision": _text(row.get("decision"), 40), "resolved_by": _text(row.get("resolved_by"), 80),
        "reason_in": _text(row.get("reason"), 300),
        "evidence_in": _text(row.get("evidence"), 200) if isinstance(row.get("evidence"), str) else "",
        "evidence": _evidence(row.get("evidence")),
        "full_len": len(full),
        # the words the duplicate rule compares: the whole text, so two long texts that only differ late never merge
        "words": row["words"] if isinstance(row.get("words"), str) else
        hashlib.sha256(" ".join(full.split()).lower().encode("utf-8", "replace")).hexdigest(),  # "" means completeness is unknown
        "digest": row.get("digest") if isinstance(row.get("digest"), str) else digest_of(row.get("id"), full),
    }


def _first_pass(row: dict, now: float, overrides: dict, ticket_closed):
    """The verdict of every rule except R3, or None when none of them matches."""
    kind = row["kind"]
    at = _epoch(row["at"])
    age = max(0.0, now - at) if at is not None else None
    manual = overrides.get(row["id"]) if kind == "requirement" else None
    if manual:
        # A dashboard click is never attributed to the user: any process holding a launch link can make it. The row
        # names the dashboard session that made the click, and nothing else.
        by = f"dashboard session {_text(manual.get('session'), 80)[:8] or 'unknown'}"
        info = {"manual": {**{k: manual.get(k, "") for k in ("action", "at", "reason", "source", "id")}, "by": by}}
        verb = "archived" if manual.get("action") == "archive" else "restored"
        why = f"{verb} from {by} at {manual.get('at', '')}: {manual.get('reason', '')}"
        if manual.get("action") == "archive":
            return "archived", "M", why, "action:" + str(manual.get("id", "")), info
        return "live", "live", why, "action:" + str(manual.get("id", "")), info
    if kind == "cleared":
        rule = CLEARED_RULES.get(row["reason_in"])
        if rule:
            return "archived", rule, f"cleared by the sweeper: {row['reason_in']}", row["evidence_in"], {}
    if row["state"] in TERMINAL_STATES:
        return "archived", "R1", f"state is {row['state']}", ("wal:" + row["resolved_by"]) if row["resolved_by"] else "", {}
    if kind == "ask" and row["resolved_at"]:
        how = row["resolution"] or row["decision"] or "resolved in a session WAL"
        return "archived", "R1", f"resolved: {how}", "wal:" + (row["resolved_by"] or "ask_resolved"), {}
    ok, ref = done_live(row)
    if ok:
        return "archived", "R2", "deployed and tested live for the same ticket or commit", ref, {}
    if row["ticket"] and ticket_closed is not None:
        try:
            closed = ticket_closed(row["ticket"])
        except Exception:  # noqa: BLE001 - a failed lookup decides nothing
            closed = None
        if closed is True:
            return "archived", "R2", f"ticket {row['ticket']} is closed", "ticket:" + row["ticket"], {}
    extra: dict = {}
    if kind == "ask":
        if age is not None and age >= ASK_STALE_S:
            extra["stale"] = True  # still live and answerable: quiet, never archived by age or by `until`
        until = _epoch(row["until"]) if row["until"] else None
        if until is not None and now >= until:
            extra["stale"] = True
            extra["past_until"] = True
    elif kind == "requirement":
        guarded = bool(row["owner"] or row["ticket"] or row["evidence"] or row["evidence_in"])
        by_user = is_user_source(row["source"])
        if age is not None and not guarded:
            if by_user:
                if age > REQUIREMENT_TTL_S:
                    extra["unowned_note"] = "Older than 30 d with no owner, ticket or evidence. It is yours, so it stays live until you archive it."
            elif age > REQUIREMENT_TTL_S:
                return "archived", "R4", f"older than {REQUIREMENT_TTL_S // 86400} d with no owner, ticket or evidence (not sourced to you)", "age", {}
            else:
                extra["expires_in_s"] = int(REQUIREMENT_TTL_S - age)
    return None if not extra else ("pending", "live", "", "", extra)


def classify_all(items, kind: str, now: float, ticket_closed=None, overrides=None) -> list[dict]:
    """Classify rows of one kind ("requirement", "ask" or "cleared"). Returns new dicts, newest first, one per id,
    each with bucket, rule, reason and evidence_ref. Bad rows are skipped, never raised on. `overrides` maps a
    requirement id to the user's latest archive or restore row."""
    overrides = overrides if isinstance(overrides, dict) else {}
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
    first = {ident: _first_pass(row, now, overrides, ticket_closed) for ident, row in rows.items()}

    def live_now(ident):
        verdict = first[ident]
        return verdict is None or verdict[0] in ("live", "pending")
    newest: dict = {}
    for row in rows.values():
        group = _group(row)
        if group is None:
            continue
        top = newest.get(group)
        if top is None or (_epoch(row["at"]) or 0.0, row["id"]) > (_epoch(top["at"]) or 0.0, top["id"]):
            newest[group] = row
    out = []
    for ident, row in rows.items():
        verdict = first[ident]
        manual_live = verdict is not None and verdict[4].get("manual") and verdict[0] == "live"
        top = newest.get(_group(row))
        if (verdict is None or verdict[0] == "pending") and top is not None and top["id"] != ident and live_now(top["id"]) \
                and not manual_live:
            bucket, rule, reason, ref = "archived", "R3", f"superseded by newer {kind} {top['id']} with exactly the same words", f"{kind}:{top['id']}"
            extra: dict = {}
        elif verdict is None or verdict[0] == "pending":
            bucket, rule, reason, ref = "live", "live", "open: nothing has resolved, superseded or expired it", ""
            extra = verdict[4] if verdict else {}
        else:
            bucket, rule, reason, ref, extra = verdict
        done = {k: v for k, v in row.items() if k not in ("_order", "evidence_in", "reason_in", "evidence", "words")}
        done["ask_reason"] = row["reason_in"] if kind == "ask" else ""
        done.update(bucket=bucket, rule=rule, rule_title=RULE_TITLES[rule], reason=reason, evidence_ref=ref, **extra)
        done["has_evidence"] = bool(row["evidence"] or row["evidence_in"])
        done["evidence_text"] = row["evidence_in"]
        out.append(done)
    out.sort(key=lambda r: (-(_epoch(r["at"]) or 0.0), r["id"]))
    return out


def _group(row: dict):
    if row["kind"] == "cleared":
        return None
    return (row["kind"], row["session"] if row["kind"] == "requirement" else row["owner"], row["words"]) if row["full_len"] and row["words"] else None


def summary(rows) -> dict:
    counts = {"live": 0, "archived": 0, "rules": {}, "manual_user": 0}
    for row in rows:
        counts[row["bucket"]] += 1
        if row["bucket"] == "archived" and row["rule"] == "M" and row.get("user_sourced"):
            counts["manual_user"] += 1  # a user-sourced requirement archived from the dashboard: shown on the Overview
        counts["rules"][row["rule"]] = counts["rules"].get(row["rule"], 0) + 1
    return counts
