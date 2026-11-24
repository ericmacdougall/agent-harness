"""The rules of ask evidence that ask_sweep.py, ask_reminders.py and wal_note.py share (GoodQA goodqa#16944). Each rule
lives here once, and the tools import it, so the listing can never be looser than the close it proposes:

- jsonl_records: the one bounded reader for the WALs and transcripts that ask_sweep lists from. A regular file only
  (never a symlink, FIFO, device or directory), at most MAX_FILE bytes, lines over MAX_LINE skipped, and a time budget.
  EVERY record it does not return is listed in `unread`: a refused file, a stop at the time or byte budget, each skipped
  over-long line and each line that does not parse (an unterminated last line is named as a write in progress). Only
  a line that does not contain the caller's `needle` is skipped without a listing, because it cannot be evidence.
- read_asks: the open and the resolved asks of one main WAL, read through jsonl_records (ask_reminders.open_asks is
  this fold).
- cite / quote_excerpt: the quoted excerpt of a user's answer that provenance accepts. The quoting is the exact inverse
  of provenance.parse_excerpt (an inner `"` is written `\\"`), and every excerpt is checked with provenance's own
  parse_excerpt and excerpt_in before it is printed, so a printed close can never disagree with the check that
  wal_note runs on it.
- supersedes: a later `ask` row whose note says `SUPERSEDES <ref>` for exactly that id, with a word boundary on both
  sides.
- human_traced: a source that names a human turn anywhere in its text, including `inferred: from user:...`. That is an
  answer, and it closes an ask the normal way (answer:/user:), never as obsolete.

wal_note.py reads the entry an --outcome close cites through provenance's own resolver (provenance.wal_entry), the same
read that verifies it, not through jsonl_records.
"""
from __future__ import annotations

import os
import re
import stat
import time

MAX_LINE = 8 * 1024 * 1024        # provenance.MAX_LINE: a line provenance can verify is a line the listing can read
MAX_FILE = 512 * 1024 * 1024
MAX_DEPTH = 200                   # provenance.MAX_JSON_DEPTH, for the same reason
MAX_SECONDS = 20.0
LISTED_LINES = 20                 # line numbers named per file and reason; `count` has the total
HUMAN_KIND = re.compile(r"(?i)(?<![A-Za-z0-9_])(user|answer|uuid|pasted)\s*:")
_clock = time.monotonic           # tests inject a clock to reach the time budget deterministically


def _refused(unread, path, reason):
    if unread is not None:
        unread.append({"source": str(path), "reason": reason})


def jsonl_records(path, unread=None, needle: bytes | None = None, max_file: int | None = None):
    """The dict records of a JSONL file. A symlink is refused (a WAL folder entry that points elsewhere would pull in
    another session's rows); the file is opened through safe_input.open_regular_file (no blocking open, no final
    symlink, re-checked on the fd). `needle` skips every line that does not contain it before parsing. Whatever is not
    returned is listed in `unread`, so a partial read is never mistaken for a complete one."""
    import safe_input  # noqa: PLC0415
    limit = MAX_FILE if max_file is None else max_file
    try:
        info = os.lstat(os.fspath(path))
    except OSError as error:
        _refused(unread, path, type(error).__name__)
        return []
    if stat.S_ISLNK(info.st_mode):
        _refused(unread, path, "file-symlink")
        return []
    if not stat.S_ISREG(info.st_mode):
        _refused(unread, path, "file-not-regular")
        return []
    if info.st_size > limit:
        _refused(unread, path, "file-too-large")
        return []
    try:
        fd = safe_input.open_regular_file(os.fspath(path))
    except safe_input.InputRejected as error:
        _refused(unread, path, error.code)
        return []
    skipped = {}  # reason -> [line numbers]
    stop = None
    out = []
    deadline = _clock() + MAX_SECONDS
    try:
        with os.fdopen(fd, "rb", closefd=False) as handle:
            number = total = 0
            while True:
                if _clock() > deadline:
                    stop = {"reason": "time-budget", "line": number + 1}
                    break
                line = handle.readline(MAX_LINE + 1)
                if not line:
                    break
                number += 1
                total += len(line)
                if len(line) > MAX_LINE and not line.endswith(b"\n"):
                    while True:  # drain the rest of the over-long line in bounded pieces
                        rest = handle.readline(MAX_LINE)
                        total += len(rest)
                        if not rest or rest.endswith(b"\n") or total > limit:
                            break
                    skipped.setdefault("line-too-long", []).append(number)
                elif line.strip() and (needle is None or needle in line):  # a blank line holds no record
                    try:
                        record = safe_input.safe_json_loads(line, max_depth=MAX_DEPTH, max_bytes=MAX_LINE + 1)
                    except ValueError:
                        record = None
                    if isinstance(record, dict):
                        out.append(record)
                    else:
                        reason = "line-incomplete" if not line.endswith(b"\n") else "line-malformed"
                        skipped.setdefault(reason, []).append(number)
                if total > limit:
                    stop = {"reason": "byte-budget", "line": number + 1}  # the file grew past the cap while it was read
                    break
    except OSError as error:
        stop = {"reason": type(error).__name__, "line": None}
    finally:
        os.close(fd)
    if unread is not None:
        for reason, lines in skipped.items():
            unread.append({"source": str(path), "reason": reason, "lines": lines[:LISTED_LINES], "count": len(lines)})
        if stop is not None:
            unread.append({"source": str(path), **stop})
    return out


def read_asks(wal_path, parse_ts, unread=None) -> dict:
    """{"open": [{"id", "opened", "note", "session"}], "resolved": {ask id: its last ask_resolved row}} of one main
    WAL. An ask is open when no ask_resolved row names it."""
    asks, resolved = {}, {}
    for rec in jsonl_records(wal_path, unread):
        if rec.get("event") == "ask" and isinstance(rec.get("id"), str):
            asks[rec["id"]] = {"id": rec["id"], "opened": parse_ts(rec.get("at")) or 0.0,
                               "note": rec.get("note") or "", "session": os.path.basename(os.path.dirname(os.fspath(wal_path)))}
        elif rec.get("event") == "ask_resolved" and isinstance(rec.get("ref"), str):
            resolved[rec["ref"]] = rec
    return {"open": [a for k, a in asks.items() if k not in resolved], "resolved": resolved}


def quote_excerpt(body: str) -> str:
    """`body` in double quotes, written so provenance.parse_excerpt reads back exactly `body`: each inner `"` becomes
    `\\"`. (parse_excerpt turns every `\\"` into `"`; every `"` here is preceded by an inserted backslash, so no other
    pair can match.)"""
    return '"' + body.replace('"', '\\"') + '"'


def cite(answer: str, turn_text: str):
    """(quoted excerpt, elided) for the user's `answer`, checked against `turn_text` (the turn as provenance reads it),
    or None when provenance would accept no excerpt of it. provenance reads `...` in an excerpt as an elision and needs
    each piece to be EXCERPT_MIN+ characters, at most EXCERPT_SEGMENTS pieces and EXCERPT_MAX in all; so a literal
    ellipsis (`...` or `…`) is kept as an elision, a piece too short to cite is elided, and an over-long answer is cut
    with a closing `...`. `elided` says the excerpt is not the whole answer: read the answer in the listing."""
    import provenance  # noqa: PLC0415
    body = provenance.norm(answer or "")
    pieces = [piece.strip() for piece in body.split("...")]
    kept, size, cut = [], 0, False
    for index, piece in enumerate(pieces):
        if len(piece) < provenance.EXCERPT_MIN:
            continue
        if len(kept) == provenance.EXCERPT_SEGMENTS or size >= provenance.EXCERPT_MAX:
            cut = True
            break
        room = provenance.EXCERPT_MAX - size
        if len(piece) > room:
            piece = piece[:room].rstrip()
            cut = True
            if len(piece) < provenance.EXCERPT_MIN:
                break
        kept.append((index, piece))
        size += len(piece)
        if cut:
            break
    if not kept:
        return None
    parts = []
    if kept[0][0] > 0:
        parts.append("")  # a leading `...`: the start of the answer is elided
    parts.extend(piece for _, piece in kept)
    if cut or kept[-1][0] < len(pieces) - 1:
        parts.append("")  # a closing `...`
    excerpt = "...".join(parts)
    quoted = quote_excerpt(excerpt)
    try:
        if provenance.parse_excerpt(quoted) != excerpt or provenance.excerpt_in(turn_text or "", excerpt) is not None:
            return None
    except provenance.Problem:
        return None
    return quoted, excerpt != body


def supersedes(record, ref: str) -> bool:
    """True when record is a later `ask` whose note says `SUPERSEDES <ref>` for exactly this id."""
    return (isinstance(record, dict) and record.get("event") == "ask" and record.get("id") != ref
            and isinstance(record.get("note"), str) and isinstance(ref, str) and bool(ref)
            and re.search(r"\bSUPERSEDES\s+" + re.escape(ref) + r"\b", record["note"]) is not None)


def human_traced(*sources) -> bool:
    """True when any of these source strings names a human turn (user:, answer:, uuid:, pasted:), at its start or inside
    an `inferred:` chain."""
    return any(isinstance(s, str) and HUMAN_KIND.search(s) for s in sources)
