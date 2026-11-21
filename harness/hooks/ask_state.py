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
from pathlib import Path

MAX_ID = 64   # wal_note writes w + 11 hex; older and hand-written rows use shorter ids, all are asks


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
