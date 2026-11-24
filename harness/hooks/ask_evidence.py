"""The rules of ask evidence that wal_note.py and ask_sweep.py share (GoodQA goodqa#16944). Each rule lives here once, and
both tools import it, so the listing can never be looser than the close it proposes:

- jsonl_records: the one bounded reader for WALs and transcripts. A regular file only (never a symlink, FIFO, device or
  directory), at most MAX_FILE bytes, lines over MAX_LINE skipped, and a time budget. An unreadable file is reported in
  `unread` and is never a silent empty list.
- supersedes: a later `ask` row whose note says `SUPERSEDES <ref>` for exactly that id, with a word boundary on both sides.
- human_traced: a source that names a human turn anywhere in its text, including `inferred: from user:...`. That is an
  answer, and it closes an ask the normal way (answer:/user:), never as obsolete.
"""
from __future__ import annotations

import json
import os
import re
import stat

MAX_LINE = 4 * 1024 * 1024
MAX_FILE = 512 * 1024 * 1024
MAX_SECONDS = 20.0
HUMAN_KIND = re.compile(r"(?i)(?<![A-Za-z0-9_])(user|answer|uuid|pasted)\s*:")


def jsonl_records(path, unread=None, needle: bytes | None = None, max_file: int = MAX_FILE):
    """The dict records of a JSONL file, read through safe_input (regular file, no blocking open, size and line caps).
    A symlink is refused: a WAL folder entry that points elsewhere would pull in another session's rows. needle skips
    every line that does not contain it before parsing. On any refusal: [] and one `unread` entry naming the reason."""
    import safe_input  # noqa: PLC0415
    try:
        info = os.lstat(os.fspath(path))
        if stat.S_ISLNK(info.st_mode):
            raise safe_input.InputRejected("file-symlink", "a symlink is never read as evidence")
        if not stat.S_ISREG(info.st_mode):
            raise safe_input.InputRejected("file-not-regular", "not a regular file")
        if info.st_size > max_file:
            raise safe_input.InputRejected("file-too-large", "too large to scan")
        out = []
        for _number, line in safe_input.iter_jsonl_lines(os.fspath(path), max_line=MAX_LINE, max_total_bytes=max_file,
                                                         max_seconds=MAX_SECONDS):
            if line is None or (needle is not None and needle not in line):
                continue
            try:
                record = json.loads(line)
            except (ValueError, RecursionError):
                continue
            if isinstance(record, dict):
                out.append(record)
        return out
    except (safe_input.InputRejected, OSError) as error:
        if unread is not None:
            unread.append({"source": str(path), "reason": getattr(error, "code", None) or type(error).__name__})
        return []


def supersedes(record, ref: str) -> bool:
    """True when record is a later `ask` whose note says `SUPERSEDES <ref>` for exactly this id."""
    return (isinstance(record, dict) and record.get("event") == "ask" and record.get("id") != ref
            and isinstance(record.get("note"), str) and isinstance(ref, str) and bool(ref)
            and re.search(r"\bSUPERSEDES\s+" + re.escape(ref) + r"\b", record["note"]) is not None)


def human_traced(*sources) -> bool:
    """True when any of these source strings names a human turn (user:, answer:, uuid:, pasted:), at its start or inside
    an `inferred:` chain."""
    return any(isinstance(s, str) and HUMAN_KIND.search(s) for s in sources)
