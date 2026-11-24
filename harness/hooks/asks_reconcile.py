#!/usr/bin/env python3
"""Find open asks that are already answered, so they stop reaching the user as reminders (GoodQA goodqa#16944).

An ask stays open in `provenance.py asks` and in ops_watch until its WAL has an `ask_resolved` row. Answers often
land as `decision` rows instead, or the user runs the step himself in a terminal, so answered asks keep reminding
him. This tool is read-only: it never writes a WAL row. For each open ask it lists the evidence that resolves it and
prints the exact `wal_note.py --event ask_resolved` line for the main agent to review and run.

Evidence, strongest first (each candidate names its kind; main decides):
  resolved-elsewhere  an `ask_resolved` row in another of the named sessions' WALs closes this ask id.
  answer              a later row names this ask id and cites the user's own words (`answer:` or `user:` source).
  terminal            a later `<bash-input>` command of the user, in a named session's transcript, contains a
                      distinctive token of the ask (a path or a name with `/` or `_`, at least 10 characters).
                      The weakest kind: always marked CONFIRM, never given a decision.
  superseded          a later `ask` row says it SUPERSEDES this ask id. Not the user's words: no decision.

Usage:
  asks_reconcile.py --session ID [--session ID ...] [--json]
Every session named is searched for asks and for evidence, so pass a session together with its successors.
Exit codes: 0 candidates or none found with every source read, 2 a source could not be read (the list is partial),
3 usage.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import provenance  # noqa: E402

ANSWER_PREFIXES = ("answer:", "user:", "uuid:")
APPROVING = re.compile(r"^\W*(yes|approve|approved|i'll run it|i will run it|do it|use |go ahead|grant)", re.I)
TOKEN = re.compile(r"[~\w.\-/]*[/_][~\w.\-/]*")
MIN_TOKEN = 10
NOTE_CLIP = 140
MAX_LINE = 4 * 1024 * 1024
MAX_TRANSCRIPT = 512 * 1024 * 1024
GENERIC_TOKENS = {"/home/eric", "/Users/eric", "~/.claude/hooks", "/home/eric/.agent-harness/work",
                  "/Users/eric/.agent-harness/work", "~/.agent-harness/work"}


def clip(text, limit: int) -> str:
    text = " ".join(str(text or "").split())
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _records(path: Path, unread: list):
    """Every JSON object line of one WAL file; an unreadable file is named in `unread`, never skipped silently."""
    try:
        handle = open(path, "rb")
    except OSError as error:
        unread.append({"source": str(path), "reason": type(error).__name__})
        return
    with handle:
        for raw in handle:
            if len(raw) > MAX_LINE:
                continue
            try:
                record = json.loads(raw)
            except ValueError:
                continue
            if isinstance(record, dict):
                yield record


def session_rows(session: str, home, unread: list) -> list:
    """All rows of the session's main and agent WALs, each tagged with its file and session."""
    paths, missing = provenance.session_wals_read(session, home)
    for entry in missing:
        unread.append({"source": f"{session}/{entry['source']}", "reason": entry["reason"]})
    rows = []
    for path in paths:
        for record in _records(path, unread):
            record["_wal"] = str(path)
            record["_session"] = session
            rows.append(record)
    return rows


def bash_inputs(session: str, home, unread: list) -> list:
    """The user's own `<bash-input>` commands in the session transcript: (uuid, timestamp, command)."""
    try:
        path = provenance.find_transcript(session, home)
    except provenance.Problem as problem:
        unread.append({"source": f"{session} transcript", "reason": problem.code})
        return []
    try:
        if os.path.getsize(path) > MAX_TRANSCRIPT:
            unread.append({"source": f"{session} transcript", "reason": "too large to scan"})
            return []
        handle = open(path, "rb")
    except OSError as error:
        unread.append({"source": f"{session} transcript", "reason": type(error).__name__})
        return []
    found = []
    with handle:
        for raw in handle:
            if b"<bash-input>" not in raw or len(raw) > MAX_LINE:
                continue
            try:
                record = json.loads(raw)
            except ValueError:
                continue
            if (not isinstance(record, dict) or record.get("type") != "user" or record.get("isSidechain")
                    or record.get("isMeta")):
                continue
            content = (record.get("message") or {}).get("content")
            if isinstance(content, list):
                content = " ".join(p.get("text", "") for p in content if isinstance(p, dict) and p.get("type") == "text")
            if not isinstance(content, str) or not content.lstrip().startswith("<bash-input>"):
                continue
            match = re.search(r"<bash-input>(.*?)</bash-input>", content, re.S)
            if match and isinstance(record.get("uuid"), str):
                found.append((record["uuid"], str(record.get("timestamp") or ""), match.group(1)))
    return found


def distinctive_tokens(note: str) -> set:
    tokens = set()
    for token in TOKEN.findall(note or ""):
        token = token.strip(".,;:()'\"`")
        if len(token) >= MIN_TOKEN and token not in GENERIC_TOKENS and not token.endswith("/"):
            tokens.add(token)
    return tokens


ANSWER_WORDS = re.compile(r"\b(answer(s|ed)?|approved|chose|decided|confirmed)\b", re.I)
WAITING = re.compile(r"\b(pending|awaiting|awaits|waiting|waits|still open|until|blocked on|needs)\b[^.;]{0,40}$", re.I)


def still_waiting(note: str, ident: str) -> bool:
    """True when every mention of the ask in the note reads as still waiting ("pending ask X", "awaiting X")."""
    starts = [m.start() for m in re.finditer(re.escape(ident), note)]
    return bool(starts) and all(WAITING.search(note[max(0, s - 60):s]) for s in starts)


def _when(value) -> str:
    """ISO timestamps compare as text once normalised to the same shape (Z and +00:00 both mean UTC)."""
    text = str(value or "")
    return text.replace("Z", "+00:00")


def _excerpt(text: str) -> str:
    return clip(text, 58).replace('"', "'")


def resolve_command(ask: dict, kind: str, evidence: dict) -> str:
    source = evidence["source"]
    note = f"Resolved by {kind} evidence {evidence['ref']}: {clip(evidence['summary'], 90)}"
    parts = ["python3", "~/.claude/hooks/wal_note.py", "--wal", ask["_wal"], "--event", "ask_resolved",
             "--ref", ask["id"], "--source", source, "--note", note]
    if evidence.get("decision"):
        parts += ["--decision", evidence["decision"]]
    return " ".join(p if p.startswith("~/") else shlex.quote(p) for p in parts)


def reconcile(sessions: list, home=None) -> dict:
    unread = []
    rows = []
    for session in sessions:
        rows.extend(session_rows(session, home, unread))
    resolved_ids = {r.get("ref") for r in rows if r.get("event") == "ask_resolved" and isinstance(r.get("ref"), str)}
    resolutions = {}
    for r in rows:
        if r.get("event") == "ask_resolved" and isinstance(r.get("ref"), str):
            resolutions.setdefault(r["ref"], r)
    inputs = {s: bash_inputs(s, home, unread) for s in sessions}
    candidates, still_open = [], []
    for session in sessions:
        local_resolved = {r.get("ref") for r in rows if r["_session"] == session and r.get("event") == "ask_resolved"}
        for ask in (r for r in rows if r["_session"] == session and r.get("event") == "ask"):
            ident = ask.get("id")
            if not isinstance(ident, str) or ident in local_resolved:
                continue
            at = _when(ask.get("at"))
            found = []
            if ident in resolved_ids:
                other = resolutions[ident]
                found.append(("resolved-elsewhere", {
                    "ref": str(other.get("id")), "session": other["_session"], "at": other.get("at"),
                    "source": str(other.get("source") or f"wal:{other['_wal']}#{other.get('id')}"),
                    "summary": str(other.get("note") or ""), "decision": other.get("decision")
                    if other.get("decision") in ("approved", "declined") else None}))
            for r in rows:
                if r is ask or _when(r.get("at")) <= at or ident not in str(r.get("note") or ""):
                    continue
                source = str(r.get("source") or "")
                if r.get("event") == "ask" and re.search(r"\bSUPERSEDES\s+" + re.escape(ident), str(r.get("note"))):
                    found.append(("superseded", {
                        "ref": str(r.get("id")), "session": r["_session"], "at": r.get("at"),
                        "source": f"wal:{r['_wal']}#{r.get('id')}", "summary": str(r.get("note")), "decision": None}))
                elif (source.startswith(ANSWER_PREFIXES) and not still_waiting(str(r.get("note")), ident)
                      and r.get("event") in ("decision", "ask_resolved", "result", "status", "check", "handoff")):
                    excerpt = source.split('"', 1)[1] if '"' in source else ""
                    found.append(("answer", {
                        "ref": str(r.get("id")), "session": r["_session"], "at": r.get("at"), "source": source,
                        "summary": str(r.get("note")),
                        "decision": "approved" if APPROVING.match(excerpt) else None}))
            tokens = distinctive_tokens(str(ask.get("note") or ""))
            for s in sessions:
                for uuid, stamp, command in inputs[s]:
                    if _when(stamp) <= at:
                        continue
                    hit = sorted(t for t in tokens if t in command)
                    if hit:
                        found.append(("terminal", {
                            "ref": f"{s}/{uuid}", "session": s, "at": stamp,
                            "source": f'user:{s}/{uuid} "{_excerpt(command)}"',
                            "summary": f"user ran in a terminal: {clip(command, 70)} (matched {hit[0]})",
                            "decision": None, "confirm": True}))
            item = {"id": ident, "session": session, "at": ask.get("at"), "note": clip(ask.get("note"), NOTE_CLIP),
                    "_wal": ask["_wal"]}
            if not found:
                still_open.append(item)
                continue
            order = {"resolved-elsewhere": 0, "answer": 1, "terminal": 2, "superseded": 3}
            found.sort(key=lambda kv: (order[kv[0]], not kv[1]["source"].startswith("answer:"),
                                       not ANSWER_WORDS.search(kv[1]["summary"]), _when(kv[1]["at"])))
            kind, best = found[0]
            candidates.append({**item, "kind": kind, "confirm": bool(best.get("confirm")),
                               "evidence": [{"kind": k, **v} for k, v in found],
                               "command": resolve_command(ask, kind, best)})
    for row in candidates + still_open:
        row["wal"] = row.pop("_wal")
    return {"schema": "harness.asks-reconcile/1", "sessions": sessions, "candidates": candidates,
            "still_open": still_open, "unread": unread, "writes": 0}


def render(result: dict) -> str:
    lines = [f"asks_reconcile: read-only; {len(result['candidates'])} answered ask(s) with no ask_resolved row, "
             f"{len(result['still_open'])} still open. Nothing was written."]
    for c in result["candidates"]:
        flag = " CONFIRM (terminal match; check it is the same step)" if c["confirm"] else ""
        lines.append(f"\n[{c['kind']}]{flag} {c['id']} ({c['session'][:8]}, {str(c['at'])[:16]}): {c['note']}")
        for e in c["evidence"]:
            lines.append(f"  evidence {e['kind']}: {e['ref']} ({str(e['at'])[:16]}) source: {clip(e['source'], 110)}")
        lines.append(f"  run: {c['command']}")
    if result["still_open"]:
        lines.append("\nStill open (no evidence found):")
        for s in result["still_open"]:
            lines.append(f"  {s['id']} ({s['session'][:8]}): {s['note']}")
    if result["unread"]:
        lines.append("\nPARTIAL: these sources could not be read, so an answer may be missing from this list:")
        for u in result["unread"]:
            lines.append(f"  {u['source']}: {u['reason']}")
    return "\n".join(lines)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--session", action="append", required=True,
                        help="session id; repeat it, naming each session with its successors")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    sessions = []
    for session in args.session:
        if not provenance.SESSION_RE.match(session) or session in (".", ".."):
            print(f"asks_reconcile: bad session id {clip(session, 40)!r}", file=sys.stderr)
            return 3
        if session not in sessions:
            sessions.append(session)
    result = reconcile(sessions, home=os.environ.get("ASKS_RECONCILE_HOME") or None)
    print(json.dumps(result, indent=1) if args.json else render(result))
    return 2 if result["unread"] else 0


if __name__ == "__main__":
    sys.exit(main())
