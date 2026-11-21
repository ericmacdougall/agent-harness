"""The one rule for "is this ask open" (GoodQA goodqa#16599).

An ask is a WAL `ask` row with an id; it is closed by an `ask_resolved` row whose `ref` names that id in the SAME WAL
(an ask id never closes an ask of another WAL: ids repeat across sessions). Seven readers used to carry their own copy of
this rule and had drifted (id format, rejected-record handling, a re-asked id). Every reader now folds its records
through `fold` and keeps only its own I/O budget, so the answer cannot differ between them (tests/test_ask_close.py runs
each reader over the same fixtures).

Pure: no I/O besides `read_records`. Stdlib only.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

ASK_TAG = re.compile(r"\[ask:\s*([A-Za-z0-9_-]{4,40})\s*\]")   # how a question card names the ask it asks
MAX_ID = 64   # wal_note writes w + 11 hex; older and hand-written rows use shorter ids, all are asks


def tagged_ids(text) -> list:
    """The ask ids a question text names as [ask:<id>], in order, without repeats."""
    seen = []
    for match in ASK_TAG.finditer(str(text or "")):
        if match.group(1) not in seen:
            seen.append(match.group(1))
    return seen


def record_ok(rec) -> bool:
    """A parsed WAL line that every reader accepts as a record (provenance.wal_record_problem is the one validator)."""
    try:
        import provenance  # noqa: PLC0415
        return not provenance.wal_record_problem(rec)
    except ImportError:  # provenance.py travels with this module; the fallback keeps the rule's core
        return isinstance(rec, dict) and isinstance(rec.get("event"), str) and bool(rec["event"].strip())


def _id(value) -> bool:
    return isinstance(value, str) and 0 < len(value) <= MAX_ID


def fold(records) -> dict:
    """{ask id: {"ask": the `ask` row, "resolved": the `ask_resolved` row or None}} over the records of ONE WAL.
    Order does not matter (ids are random, never legitimately reused); a rejected record opens and
    closes nothing."""
    asks, resolved = {}, {}
    for rec in records:
        if not record_ok(rec):
            continue
        event = rec.get("event")
        if event == "ask" and _id(rec.get("id")):
            asks[rec["id"]] = rec
        elif event == "ask_resolved" and _id(rec.get("ref")):
            resolved[rec["ref"]] = rec
    return {k: {"ask": v, "resolved": resolved.get(k)} for k, v in asks.items()}


def resolved_refs(records) -> set:
    """Every ask id an `ask_resolved` row of this WAL names, whether or not the ask row is in the same WAL (main closes an
    owner WAL's ask by citing the answer; readers of main alone still see that the ask is resolved)."""
    return {r["ref"] for r in records if record_ok(r) and r.get("event") == "ask_resolved" and _id(r.get("ref"))}


def open_asks(records) -> dict:
    """{ask id: ask row} for the asks of one WAL that nothing closed."""
    return {k: v["ask"] for k, v in fold(records).items() if v["resolved"] is None}


AUTO_CLOSER = "ask-close"   # `by` of a resolution the ask-close hook wrote from an answered card


def auto_closed(resolved) -> bool:
    """True for a resolution written by the ask-close hook. It carries the user's answer but never an approve or decline
    (no decision field), so approval consumers (escalation, ah kill) refuse it until an agent records the decision."""
    return isinstance(resolved, dict) and resolved.get("by") == AUTO_CLOSER


def session_open(wal_paths, tail_bytes=4 << 20) -> dict:
    """{ask id: (WAL path, ask row)} over ALL WALs of one session: an ask in an owner WAL that main closed with `ask_wal`
    is closed, as the provenance ledger reads it. Every session-wide reader (SessionStart, the ask-close sweep) uses this."""
    asks, closed = {}, set()
    for path in wal_paths:
        records = read_records(path, tail_bytes=tail_bytes)
        for ident, row in fold(records).items():
            asks[ident] = (path, row["ask"])
        closed |= resolved_refs(records)
    return {k: v for k, v in asks.items() if k not in closed}


def parse_lines(lines):
    """Parsed JSON objects of raw JSONL lines (bytes or str); lines that do not parse are skipped."""
    for raw in lines:
        try:
            rec = json.loads(raw)
        except ValueError:
            continue
        if isinstance(rec, dict):
            yield rec


def read_records(path, tail_bytes=None):
    """Records of one WAL file. `tail_bytes` limits the read to the end of a large file (a partial first line is
    dropped by the parse). A missing or unreadable file has no records."""
    try:
        if tail_bytes:
            import safe_input  # noqa: PLC0415
            data = safe_input.read_tail(Path(path), tail_bytes)
            return list(parse_lines(data.splitlines()))
        with open(path, "rb") as handle:
            return list(parse_lines(handle))
    except Exception:  # noqa: BLE001 - a WAL that cannot be read holds no open ask
        return []
