#!/usr/bin/env python3
"""Requirement provenance: every requirement, ask, blocker, AC-n, NEG-n and decision names its origin.

A `Source:` is one of
  user:<session-id>/<message-uuid> "excerpt"        a real user-authored turn that contains the excerpt
  ticket:GoodQA <project>#<n> [comment <id>]         a ticket (offline: syntax checked, marked deferred)
  wal:<path>#<entry-id>                              another WAL entry; its own source is followed
  file:<repo-path>:<line>@<sha> ["excerpt"]          a line of a committed file
  inferred: from <source> ; <source> -- <rationale>  an assumption, never a user requirement

Subcommands: check, check-spec, check-packet, trace, find-user, asks.
Exit codes: 0 ok, 2 rejected or untraceable, 3 usage.

Fail safe: malformed or oversized transcript lines, missing files and internal errors become rejection
statuses, never tracebacks. Messages carry at most 60 characters of any excerpt. No network access:
ticket sources are syntax-checked and flagged `deferred` unless a local cache already lists them.
"""

from __future__ import annotations

import json
import os
import re
import sys
import time
import unicodedata
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))  # hooks live side by side; works when run as a script or imported
import safe_input  # noqa: E402
POLICY_FILE = HERE / "provenance_policy.json"
MAX_LINE = 8 * 1024 * 1024        # a transcript or WAL line larger than this is never parsed
MAX_HITS = 200                    # lines parsed per lookup
MAX_TEXT = 2 * 1024 * 1024
MAX_SCAN_BYTES = 1 << 30          # a transcript or WAL larger than this is not scanned
SCAN_SECONDS = 3.0                # wall-clock budget for one scan
SMALL_FILE = 1 << 20              # policy, cache and similar small files
MAX_RESOLVES = 40                 # sources resolved per top-level claim
MAX_DEPTH = 8                     # wal: pointer chain depth
EXCERPT_MIN, EXCERPT_MAX, EXCERPT_SEGMENTS = 12, 300, 3
RATIONALE_MIN = 10
MODES = ("off", "warn", "enforce")
DEFAULT_POLICY = {
    "schema": 1, "spec": "enforce", "plan_packet": "warn", "ask_user_question": "enforce", "stop_lint": "warn", "ticket_lookup": "enforce",
    "wal": {"requirement": "enforce", "ask": "enforce", "blocker": "warn", "scope": "warn", "decision": "warn"},
}
ID_RE = re.compile(r"^[A-Za-z0-9_-]{4,40}$")
SESSION_RE = re.compile(r"^[A-Za-z0-9._-]{1,120}$")
UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
SHA_RE = re.compile(r"^[0-9a-f]{7,40}$")
LABELS = {"user": "USER", "ticket": "TICKET", "file": "FILE"}


class Problem(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def safe_name(value) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", str(value or "unknown"))[:120]


def clip(value, limit: int = 60) -> str:
    """Short, single-line, control-free text for errors and logs: never echo a whole excerpt."""
    text = re.sub(r"[\x00-\x1f\x7f-\x9f\u200b-\u200f\u202a-\u202e\u2066-\u2069]+", " ", str(value))
    return text if len(text) <= limit else text[:limit - 3] + "..."


# --------------------------------------------------------------------------- policy

def _roots(root):
    return None if root is None else [root]


def _translate(call, *args, **kwargs):
    try:
        return call(*args, **kwargs)
    except safe_input.InputRejected as rejected:
        raise Problem(rejected.code, rejected.message)


def open_regular(path, root=None) -> int:
    """fd of a regular file or Problem (see safe_input.open_regular_file: no devices, FIFOs, escapes, TOCTOU)."""
    return _translate(safe_input.open_regular_file, path, _roots(root))


def read_small(path, limit: int = SMALL_FILE, root=None) -> bytes:
    return _translate(safe_input.read_bounded, path, limit, _roots(root))


def read_tail(path, window: int, root=None) -> bytes:
    return _translate(safe_input.read_tail, path, window, _roots(root))


def read_text_arg(path, limit: int = 4 * SMALL_FILE) -> str:
    return read_small(path, limit).decode("utf-8", "replace")


MODE_RANK = {"off": 0, "warn": 1, "enforce": 2}
POLICY_KEYS = ("spec", "plan_packet", "ask_user_question", "stop_lint", "ticket_lookup")


def stricter(current, wanted):
    """The stricter of two modes. Environment overrides go through this: they may tighten, never loosen."""
    if wanted in MODE_RANK and MODE_RANK[wanted] > MODE_RANK.get(current, 0):
        return wanted
    return current


def _overlay(policy: dict, loaded: dict, tighten_only: bool) -> None:
    pick = stricter if tighten_only else (lambda current, wanted: wanted if wanted in MODES else current)
    for key in POLICY_KEYS:
        if key in loaded:
            policy[key] = pick(policy[key], loaded[key])
    if isinstance(loaded.get("wal"), dict):
        for event, mode in loaded["wal"].items():
            policy["wal"][event] = pick(policy["wal"].get(event, "warn"), mode)


def _read_policy_file(path) -> dict:
    loaded = loads_line(read_small(path, 1 << 16))
    if not isinstance(loaded, dict) or loaded.get("schema") != 1:
        raise ValueError("not a schema 1 provenance policy")
    return loaded


def load_policy(path=None) -> dict:
    """The installed provenance_policy.json (or `path`) decides the modes. The environment can only tighten them:
    HARNESS_PROVENANCE_POLICY names an extra policy whose modes apply only where stricter, so an agent that sets
    a variable inline cannot downgrade an enforce policy. Loosening happens in the installed file alone."""
    policy = json.loads(json.dumps(DEFAULT_POLICY))
    policy.setdefault("ticket_lookup", "enforce")
    main_path = Path(path or POLICY_FILE)
    try:
        _overlay(policy, _read_policy_file(main_path), tighten_only=False)
    except Problem as error:
        if error.code != "file-unreadable" or main_path.exists():
            policy["policy_error"] = clip(error.message, 120)
    except (OSError, ValueError) as error:  # a broken policy must not silently disable the gate
        policy["policy_error"] = clip(error, 120)
    extra = None if path else os.environ.get("HARNESS_PROVENANCE_POLICY")
    if extra:
        try:
            _overlay(policy, _read_policy_file(extra), tighten_only=True)
        except (Problem, OSError, ValueError) as error:
            policy["policy_error"] = clip(getattr(error, "message", error), 120)
    policy["ticket_lookup"] = stricter(policy["ticket_lookup"], os.environ.get("HARNESS_PROVENANCE_TICKET_LOOKUP"))
    return policy


# --------------------------------------------------------------------------- text normalisation

_FOLD = {"‘": "'", "’": "'", "‚": "'", "‛": "'", "′": "'",
         "“": '"', "”": '"', "„": '"', "‟": '"', "«": '"', "»": '"',
         "‐": "-", "‑": "-", "‒": "-", "–": "-", "—": "-", "−": "-",
         "…": "..."}
# Deliberately NFC, not NFKC: compatibility folding would let fullwidth or ligature look-alikes pass.
# Case, zero-width characters and homoglyphs are never folded, so near-miss forgeries do not match.


def norm(text: str) -> str:
    text = unicodedata.normalize("NFC", text)
    text = "".join(_FOLD.get(char, char) for char in text)
    return re.sub(r"\s+", " ", text).strip()


NOT_USER_TAGS = ("agent-message", "task-notification", "system-reminder", "pasted_content",
                 "local-command-stdout", "local-command-stderr", "local-command-caveat", "command-name",
                 "command-message", "command-args", "bash-input", "bash-stdout", "bash-stderr",
                 "artifact-content-authored-by-others", "ide_opened_file", "ide_selection", "browser_instruction",
                 "user-prompt-submit-hook", "teammate-message", "command-stdout")
_TAGS = "|".join(re.escape(tag) for tag in NOT_USER_TAGS)
# Fail closed: an opener is just `<tag`, whatever follows (nested angle brackets, long attributes); a closer must
# be exactly `</tag>` (spaces before `>` allowed). Looser closers or stricter openers would let hidden text through.
_TAG_TOKEN = re.compile(r"</(" + _TAGS + r")\s*>|<(" + _TAGS + r")\b", re.I)
# goodqa#15253 item 2: the same scan without pasted_content, whose own tag tokens are then replaced by the sentinel,
# so an excerpt cannot run from typed text into a paste. Every other block inside a paste is still removed.
_TAGS_KEEP_PASTED = "|".join(re.escape(tag) for tag in NOT_USER_TAGS if tag != "pasted_content")
_TAG_TOKEN_KEEP_PASTED = re.compile(r"</(" + _TAGS_KEEP_PASTED + r")\s*>|<(" + _TAGS_KEEP_PASTED + r")\b", re.I)
_PASTED_TAG = re.compile(r"</pasted_content\s*>|<pasted_content\b[^>]*>", re.I)
PASTED_TRUST = "text the user pasted into a human turn: the user chose to send it, but it may not be their own words"
_WRAPPER = re.compile(r"^\s*<([A-Za-z][\w:-]*)\b[^>]*>.*</\1\s*>\s*$", re.S)
SENTINEL = "\ufffc"  # replaces a removed block so an excerpt cannot span text on both sides of it


def strip_blocks(text: str, keep_pasted: bool = False) -> str:
    """Remove every non-user-authored block; an unclosed opener removes the rest of the text.
    Linear: one pass over the tags with a stack (the earlier nested-regex form was quadratic on many openers).
    keep_pasted keeps the content of <pasted_content> blocks (their tags become sentinels)."""
    if len(text) > MAX_TEXT:
        text = text[:MAX_TEXT] + SENTINEL  # bound the work on absurdly long turns
    stack, spans = [], []  # open tags awaiting a close; closed top-level (start, end) blocks
    by_name = {}  # tag name -> indexes into `stack`, so a close finds its opener in O(1)
    for tag in (_TAG_TOKEN_KEEP_PASTED if keep_pasted else _TAG_TOKEN).finditer(text):
        if tag.group(2):
            name = tag.group(2).lower()
            by_name.setdefault(name, []).append(len(stack))
            stack.append((name, tag.start()))
            continue
        name = tag.group(1).lower()
        positions = by_name.get(name)
        if not positions:
            continue  # a close with no opener is plain text
        index = positions[-1]
        start = stack[index][1]
        del stack[index:]  # openers inside this block go with it
        for other in by_name.values():
            while other and other[-1] >= index:
                other.pop()
        while spans and spans[-1][0] >= start:
            spans.pop()
        spans.append((start, tag.end()))
    cut = stack[0][1] if stack else None  # an unclosed opener hides everything after it
    out, pos = [], 0
    for start, end in spans:
        if cut is not None and start >= cut:
            break
        out.append(text[pos:start])
        out.append(SENTINEL)
        pos = end
    if cut is not None:
        out.append(text[pos:cut])
        out.append(SENTINEL)
    else:
        out.append(text[pos:])
    joined = "".join(out)
    return _PASTED_TAG.sub(SENTINEL, joined) if keep_pasted else joined


# --------------------------------------------------------------------------- parsing

_QUOTES = {'"': '"', "“": "”", "«": "»"}


def split_outside_quotes(text: str, separator: str) -> list:
    parts, current, closer, i = [], [], None, 0
    while i < len(text):
        char = text[i]
        if closer is None and text.startswith(separator, i):
            parts.append("".join(current))
            current = []
            i += len(separator)
            continue
        if char == "\\" and i + 1 < len(text):
            current.append(text[i:i + 2])
            i += 2
            continue
        if closer is None and char in _QUOTES:
            closer = _QUOTES[char]
        elif closer is not None and (char == closer or (closer == "”" and char == '"')):
            closer = None
        current.append(char)
        i += 1
    parts.append("".join(current))
    return parts


def inline_source(text: str):
    """The source inside `[src: ...]`, ending at the first `]` outside quotes; None when absent or unterminated."""
    start = text.find("[src:")
    if start < 0:
        return None
    body = text[start + 5:]
    closer, i = None, 0
    while i < len(body):
        char = body[i]
        if char == "\\" and i + 1 < len(body):
            i += 2
            continue
        if closer is None and char in _QUOTES:
            closer = _QUOTES[char]
        elif closer is not None and (char == closer or (closer == "\u201d" and char == '"')):
            closer = None
        elif closer is None and char == "]":
            return body[:i].strip() or None
        i += 1
    return None


def parse_excerpt(rest: str):
    rest = rest.strip()
    if not rest:
        return None
    opener = rest[0]
    if opener not in _QUOTES:
        raise Problem("bad-syntax", "an excerpt must be quoted: \"...\" (escape inner double quotes as \\\")")
    closer = _QUOTES[opener]
    end = max(rest.rfind(closer), rest.rfind('"') if closer == "”" else -1)
    if end <= 0:
        raise Problem("bad-syntax", "unterminated excerpt quote")
    if rest[end + 1:].strip():
        raise Problem("bad-syntax", "text after the closing quote of the excerpt")
    return rest[1:end].replace('\\"', '"')


def parse_source(text: str) -> dict:
    value = (text or "").strip()
    if not value:
        raise Problem("no-source", "no Source given")
    if len(value) > 4000:
        raise Problem("bad-syntax", "Source longer than 4000 characters")
    match = re.match(r"(?is)^([A-Za-z]+)\s*:\s*(.*)$", value)
    if not match:
        raise Problem("bad-syntax", "Source must start with user:, answer:, queue:, ticket:, wal:, file: or inferred:")
    kind, rest = match.group(1).lower(), match.group(2).strip()
    if kind == "user":
        found = re.match(r"^([0-9a-fA-F-]{36})/([0-9a-fA-F-]{36})\s*(.*)$", rest, re.S)
        if not found or not UUID_RE.match(found.group(2)) or not UUID_RE.match(found.group(1)):
            raise Problem("bad-syntax", "user: needs <session-id>/<message-uuid> then a quoted excerpt")
        excerpt = parse_excerpt(found.group(3))
        if excerpt is None:
            raise Problem("excerpt-missing", "a user: source needs a verbatim quoted excerpt of the user's words")
        return {"kind": "user", "session": found.group(1).lower(), "uuid": found.group(2).lower(), "excerpt": excerpt}
    if kind in ("answer", "queue"):
        # Same trust class as user:, different record kind (see ah user-msg and docs/provenance.md).
        if kind == "answer":
            found = re.match(r"^([0-9a-fA-F-]{36})/([0-9a-fA-F-]{36})\s*(.*)$", rest, re.S)
            ok = found and UUID_RE.match(found.group(1)) and UUID_RE.match(found.group(2))
            ident = found.group(2).lower() if found else None
        else:
            found = re.match(r"^([0-9a-fA-F-]{36})/(\d{4}-\d\d-\d\dT[\d:.]{8,16}Z)#([0-9a-f]{12})\s*(.*)$", rest, re.S)
            ok = found and UUID_RE.match(found.group(1))
            ident = (found.group(2), found.group(3)) if found else None
        if not ok:
            raise Problem("bad-syntax", "answer: needs <session>/<uuid>; queue: needs <session>/<timestamp>#<sha12>; then a quoted excerpt")
        excerpt = parse_excerpt(found.group(found.lastindex))
        if excerpt is None:
            raise Problem("excerpt-missing", f"a {kind}: source needs a verbatim quoted excerpt of the user's words")
        return {"kind": "user", "variant": kind, "session": found.group(1).lower(), "ident": ident, "excerpt": excerpt,
                "uuid": ident if kind == "answer" else f"{ident[0]}#{ident[1]}"}
    if kind == "ticket":
        found = re.match(r"^GoodQA\s+([A-Za-z0-9_.-]{1,80})#(\d{1,9})(?:\s+comment\s+([0-9A-Za-z-]{4,64}))?$", rest)
        if not found:
            raise Problem("bad-syntax", "ticket: needs `GoodQA <project>#<number>` and optionally `comment <id>`")
        return {"kind": "ticket", "project": found.group(1), "number": int(found.group(2)), "comment": found.group(3)}
    if kind == "wal":
        path, _, entry = rest.rpartition("#")
        if not path or not ID_RE.match(entry) and not re.match(r"^L\d{1,9}$", entry):
            raise Problem("bad-syntax", "wal: needs <path>#<entry-id> (the id printed by wal_note, or L<line>)")
        return {"kind": "wal", "path": path.strip(), "entry": entry}
    if kind == "file":
        found = re.match(r"^(.+?):(\d{1,9})(?:-(\d{1,9}))?@([0-9a-fA-F]{7,40})\s*(.*)$", rest, re.S)
        if not found:
            raise Problem("bad-syntax", "file: needs <repo-path>:<line>@<sha> and optionally a quoted excerpt")
        path = found.group(1)
        if path.startswith(("/", "-", "~")) or ".." in path.split("/") or "\x00" in path:
            raise Problem("file-path", "file: path must be repo-relative with no .. segments")
        return {"kind": "file", "path": path, "line": int(found.group(2)),
                "line_end": int(found.group(3) or found.group(2)), "sha": found.group(4).lower(),
                "excerpt": parse_excerpt(found.group(5))}
    if kind == "inferred":
        head = split_outside_quotes(rest, " -- ")
        if len(head) < 2 or not re.match(r"(?is)^from\s+\S", head[0]):
            raise Problem("inferred-no-inputs", "inferred: needs `from <source> ; <source> -- <rationale>`")
        rationale = " -- ".join(head[1:]).strip()
        if len(rationale) < RATIONALE_MIN:
            raise Problem("inferred-no-rationale", f"inferred: needs a rationale of {RATIONALE_MIN}+ characters after ` -- `")
        inputs = [part.strip() for part in split_outside_quotes(head[0].strip()[4:].strip(), ";") if part.strip()]
        if not inputs:
            raise Problem("inferred-no-inputs", "inferred: lists no input sources")
        return {"kind": "inferred", "inputs": inputs, "rationale": rationale}
    raise Problem("unknown-kind", f"`{clip(kind, 20)}:` is not a source kind; agent memory and chat are not sources")


# --------------------------------------------------------------------------- transcripts

def claude_home(home=None) -> Path:
    if home:
        return Path(home)
    configured = os.environ.get("CLAUDE_CONFIG_DIR")  # Claude Code can relocate its config and transcripts
    return Path(configured) if configured else Path.home() / ".claude"


def find_transcript(session: str, home=None):
    if not SESSION_RE.match(session) or session in (".", ".."):
        raise Problem("user-session-invalid", "session id has characters a transcript name cannot have")
    projects = claude_home(home) / "projects"
    try:
        with os.scandir(projects) as entries:
            for entry in entries:
                candidate = Path(entry.path) / (session + ".jsonl")
                if entry.is_dir() and candidate.is_file():
                    return candidate
    except OSError:
        pass
    raise Problem("transcript-missing", f"no transcript for session {clip(session, 40)} on this host")


CHUNK = 8 * 1024 * 1024
MAX_JSON_DEPTH = 200


def loads_line(raw):
    """json.loads for untrusted lines (size and nesting limits; ValueError for anything it will not parse)."""
    return safe_input.safe_json_loads(raw, MAX_JSON_DEPTH, MAX_LINE)


def _line_around(fd: int, index: int, size: int):
    """(line_start, line_bytes) for the line holding absolute offset index; None bytes when over MAX_LINE."""
    back = fwd = 1 << 16
    while True:
        lo = max(0, index - back)
        window = os.pread(fd, min(size, index + fwd) - lo, lo)
        start = window.rfind(b"\n", 0, index - lo) + 1 if index > lo else 0
        has_start = start > 0 or lo == 0
        end = window.find(b"\n", index - lo)
        has_end = end >= 0 or lo + len(window) >= size
        if has_start and has_end:
            end = len(window) if end < 0 else end
            return lo + start, window[start:end]
        if back + fwd > 2 * MAX_LINE:
            return None, None
        if not has_start:
            back *= 4
        if not has_end:
            fwd *= 4


def _lines_containing(path: Path, needle: bytes):
    """Yield the line (or None when oversized) for each line containing needle. bytes.find on 8 MiB chunks:
    mmap.find is a naive loop on Python 3.9 and 5 to 10 times slower on a 75 MB transcript."""
    fd = open_regular(path)
    try:
        size = os.fstat(fd).st_size
        if size > MAX_SCAN_BYTES:
            raise Problem("file-too-large", f"{clip(path.name, 60)} is larger than {MAX_SCAN_BYTES >> 20} MiB; not scanned")
        deadline = time.monotonic() + SCAN_SECONDS
        offset, hits, carry, next_line = 0, 0, b"", 0
        while offset < size and hits < MAX_HITS:
            if time.monotonic() > deadline:
                raise Problem("scan-timeout", f"scan of {clip(path.name, 60)} exceeded {SCAN_SECONDS:.0f}s")
            chunk = os.pread(fd, min(CHUNK, size - offset), offset)
            if not chunk:
                return
            base = offset - len(carry)
            data = carry + chunk
            pos = 0
            while hits < MAX_HITS:
                index = data.find(needle, pos)
                if index < 0:
                    break
                absolute = base + index
                pos = index + 1
                if absolute < next_line:
                    continue  # same line as a previous hit
                start, line = _line_around(fd, absolute, size)
                hits += 1
                if line is None:
                    next_line = absolute + MAX_LINE  # skip the rest of an oversized line, do not re-read it per hit
                    yield None
                else:
                    next_line = start + len(line) + 1
                    yield line
            offset += len(chunk)
            carry = data[-(len(needle) - 1):] if len(needle) > 1 else b""
    except (OSError, ValueError) as error:
        raise Problem("file-unreadable", f"cannot read {clip(path.name, 60)} ({type(error).__name__})")
    finally:
        os.close(fd)


def load_record(path: Path, key: str, value: str):
    """The JSON object on a line of path whose top-level `key` equals value, or a Problem-worthy reason."""
    # Compact `"key":"value"` first: it matches only the record's own field, not parentUuid references or
    # quotes of the id elsewhere. The bare-value pass handles differently spaced JSON and costs one more scan.
    first = load_lines(path, f'"{key}":"{value}"'.encode("utf-8"), key, value)
    if first not in (None, "malformed") or _compact_json(path, key):
        return first
    return load_lines(path, value.encode("utf-8"), key, value) or first


def _compact_json(path: Path, key: str) -> bool:
    """True when the file's first megabyte already shows compact `"key":"` fields, so a miss is a real miss."""
    try:
        fd = open_regular(path)
        try:
            return f'"{key}":"'.encode() in os.pread(fd, 1 << 20, 0)
        finally:
            os.close(fd)
    except (OSError, Problem):
        return False


def load_lines(path: Path, needle: bytes, key: str, value: str):
    saw_bad, match = False, None
    for line in _lines_containing(path, needle):
        if line is None:
            saw_bad = True
            continue
        try:
            record = loads_line(line)
        except ValueError:
            saw_bad = True
            continue
        if isinstance(record, dict) and record.get(key) == value:
            if match is not None and record != match:
                raise Problem("ambiguous", f"more than one different record has {key} {clip(value, 12)}")
            match = record
    if match is not None:
        return match
    return "malformed" if saw_bad else None


def user_authorship(record: dict, keep_pasted: bool = False):
    """(text, None) for a human-authored turn, else (None, reason). keep_pasted: include pasted blocks."""
    if record.get("type") != "user":
        return None, f"entry type is {clip(record.get('type'), 20)}, not a user turn"
    if record.get("isSidechain"):
        return None, "turn belongs to a sub-agent conversation"
    if record.get("isMeta") or record.get("isCompactSummary") or record.get("isVisibleInTranscriptOnly"):
        return None, "turn is meta, a compaction summary or injected (not typed by the user)"
    if "toolUseResult" in record or record.get("sourceToolAssistantUUID"):
        return None, "turn is a tool result"
    origin = record.get("origin")
    kind = origin.get("kind") if isinstance(origin, dict) else None
    if kind != "human":
        return None, f"turn origin is {clip(kind or 'unmarked', 30)}, not human"
    message = record.get("message")
    content = message.get("content") if isinstance(message, dict) else None
    if isinstance(content, str):
        return strip_blocks(content, keep_pasted), None
    if isinstance(content, list):
        pieces = []
        for block in content:
            if not isinstance(block, dict) or block.get("type") not in ("text", "image"):
                return None, "turn carries non-text blocks (tool results)"
            if block.get("type") == "text" and isinstance(block.get("text"), str):
                if _WRAPPER.match(block["text"]):
                    continue  # a block that is one wrapper element was injected by the harness or an extension
                pieces.append(strip_blocks(block["text"], keep_pasted))
        return "\n".join(pieces), None
    return None, "turn has no readable text"


QUEUE_WRAPPER = re.compile(r"^\s*<[A-Za-z][\w:-]*[\s>/]")
ANSWER_TRUST = "AskUserQuestion tool result bound to an AskUserQuestion tool_use in the same transcript"
QUEUE_TRUST = "transcript queue-operation record without an origin marker (accidental-damage threat model)"


def queue_user_text(record):
    """Text of a queued mid-turn user message record, else None. Harness wrapper elements (task notifications,
    agent messages, reminders) are never user text."""
    if not isinstance(record, dict) or record.get("type") != "queue-operation":
        return None
    if record.get("operation") not in ("enqueue", "popAll"):
        return None
    content = record.get("content")
    if not isinstance(content, str) or not content.strip() or QUEUE_WRAPPER.match(content):
        return None
    return content


def askuser_use_ids(record) -> set:
    """tool_use ids of AskUserQuestion calls made by the main conversation in an assistant record."""
    out = set()
    if isinstance(record, dict) and record.get("type") == "assistant" and not record.get("isSidechain"):
        content = (record.get("message") or {}).get("content")
        for block in content if isinstance(content, list) else []:
            if (isinstance(block, dict) and block.get("type") == "tool_use" and block.get("name") == "AskUserQuestion"
                    and isinstance(block.get("id"), str)):
                out.add(block["id"])
    return out


def answer_text(record, ask_ids):
    """Text of the user's answer to an AskUserQuestion, else None. The result must answer an AskUserQuestion
    tool_use (ask_ids), so another tool's output can never stand in for the user."""
    if not isinstance(record, dict) or record.get("type") != "user" or record.get("isSidechain"):
        return None
    blocks = (record.get("message") or {}).get("content")
    if ("toolUseResult" not in record or not isinstance(blocks, list) or len(blocks) != 1
            or not isinstance(blocks[0], dict) or blocks[0].get("type") != "tool_result"
            or blocks[0].get("tool_use_id") not in ask_ids):
        return None
    if blocks[0].get("is_error"):
        return None
    # Only the user's selections count (toolUseResult.answers: question -> answer). The rendered tool_result string
    # embeds the agent's own question text, so it is never parsed; no structured answers means no answer.
    answers = record["toolUseResult"].get("answers") if isinstance(record["toolUseResult"], dict) else None
    if not isinstance(answers, dict):
        return None
    values = [v.strip() for v in answers.values() if isinstance(v, str) and v.strip()]
    return "\n".join(values) if values else None


def excerpt_in(text: str, excerpt: str):
    """None when the excerpt is a faithful quote of text, else a rejection reason."""
    if SENTINEL in excerpt:
        return "excerpt contains the removed-block marker"
    wanted = norm(excerpt)
    if any(re.search(r"<" + tag + r"\b", wanted, re.I) for tag in NOT_USER_TAGS):
        return "excerpt contains a non-user block tag"
    segments = [seg.strip() for seg in wanted.split("...")]
    segments = [seg for seg in segments if seg]
    if not segments or len(segments) > EXCERPT_SEGMENTS:
        return f"excerpt needs 1 to {EXCERPT_SEGMENTS} quoted segments"
    if any(len(seg) < EXCERPT_MIN for seg in segments) or sum(len(seg) for seg in segments) > EXCERPT_MAX:
        return f"each excerpt segment needs {EXCERPT_MIN}+ characters and the total at most {EXCERPT_MAX}"
    haystack, pos = norm(text), 0
    for segment in segments:
        index = haystack.find(segment, pos)
        if index < 0:
            return f"excerpt not found in that turn: \"{clip(segment, 40)}\""
        if pos and SENTINEL in haystack[pos:index]:
            return "excerpt segments are separated by a removed non-user block"
        pos = index + len(segment)
    return None


def user_turn(session: str, uid: str, home=None) -> dict:
    """The human-authored turn, or Problem."""
    path = find_transcript(session, home)
    record = load_record(path, "uuid", uid)
    if record == "malformed":
        raise Problem("transcript-malformed", "only malformed or oversized lines mention that uuid")
    if record is None:
        raise Problem("message-not-found", f"no message {uid[:8]}... in session {clip(session, 40)}")
    text, reason = user_authorship(record)
    if text is None:
        raise Problem("not-user-authored", reason)
    return {"text": text, "timestamp": record.get("timestamp"), "uuid": uid, "session": session,
            "with_pasted": user_authorship(record, keep_pasted=True)[0]}


def askuser_bound(path: Path, use_id) -> set:
    """{use_id} when the transcript holds a main-conversation AskUserQuestion tool_use with that id, else empty."""
    ids = set()
    if isinstance(use_id, str) and use_id:
        for line in _lines_containing(path, use_id.encode()):
            try:
                ids |= askuser_use_ids(loads_line(line)) if line is not None else set()
            except ValueError:
                continue
    return ids & {use_id}


def answer_turn(session: str, uid: str, home=None) -> dict:
    path = find_transcript(session, home)
    record = load_record(path, "uuid", uid)
    if record == "malformed":
        raise Problem("transcript-malformed", "only malformed or oversized lines mention that uuid")
    if record is None:
        raise Problem("message-not-found", f"no message {uid[:8]}... in session {clip(session, 40)}")
    blocks = (record.get("message") or {}).get("content") if isinstance(record, dict) else None
    use_id = blocks[0].get("tool_use_id") if isinstance(blocks, list) and blocks and isinstance(blocks[0], dict) else None
    ids = set()
    if isinstance(use_id, str):
        for line in _lines_containing(path, use_id.encode()):
            try:
                ids |= askuser_use_ids(loads_line(line)) if line is not None else set()
            except ValueError:
                continue
    text = answer_text(record, ids)
    if text is None:
        raise Problem("not-user-authored", "record is not an AskUserQuestion answer bound to an AskUserQuestion tool_use")
    return {"text": text, "timestamp": record.get("timestamp"), "uuid": uid, "session": session}


def _has_human_turn(path: Path) -> bool:
    for line in _lines_containing(path, b'"human"'):  # spacing-agnostic; the parsed record decides
        if line is None:
            continue
        try:
            record = loads_line(line)
        except ValueError:
            continue
        if isinstance(record, dict) and user_authorship(record)[0] is not None:
            return True
    return False


def queue_turn(session: str, ident, home=None) -> dict:
    import hashlib
    stamp, sha = ident
    path = find_transcript(session, home)
    if not _has_human_turn(path):
        raise Problem("message-not-found", "that transcript has no human-origin turn (a helper session): queue records are not user text")
    for line in _lines_containing(path, stamp.encode()):
        if line is None:
            continue
        try:
            record = loads_line(line)
        except ValueError:
            continue
        text = queue_user_text(record)
        if text is not None and record.get("timestamp") == stamp and hashlib.sha256(text.encode()).hexdigest()[:12] == sha:
            return {"text": text, "timestamp": stamp, "uuid": f"{stamp}#{sha}", "session": session}
    raise Problem("message-not-found", f"no queued user message {stamp}#{sha} in session {clip(session, 40)}")


# --------------------------------------------------------------------------- resolution

def wals_root(home=None) -> Path:
    return claude_home(home) / "wals"


def resolve_wal_path(raw: str, home=None) -> Path:
    root = wals_root(home)
    path = Path(os.path.expanduser(raw))
    if not path.is_absolute():
        path = root / path
    try:
        real, real_root = path.resolve(strict=False), root.resolve(strict=False)
    except (OSError, RuntimeError):
        raise Problem("wal-bad-path", "WAL path does not resolve")
    if real.suffix != ".jsonl" or real_root not in real.parents:
        raise Problem("wal-bad-path", "wal: must name a .jsonl under ~/.claude/wals")
    if not real.is_file():
        raise Problem("wal-missing", f"WAL {clip(real.name, 60)} not found on this host")
    return real


def wal_entry(path: Path, entry: str):
    if entry.startswith("L") and entry[1:].isdigit():
        number = int(entry[1:])
        try:
            for index, line in safe_input.iter_jsonl_lines(path, MAX_LINE, max_seconds=SCAN_SECONDS):
                if index == number:
                    return "malformed" if line is None else loads_line(line)
                if index > number:
                    break
        except (safe_input.InputRejected, ValueError):
            return "malformed"
        return None
    return load_record(path, "id", entry)


def ticket_cache_path() -> Path:
    return Path.home() / ".agent-harness" / "provenance" / "tickets.json"


def ticket_cache(home=None) -> dict:
    try:
        data = loads_line(read_small(ticket_cache_path()))
        return data if isinstance(data, dict) else {}
    except (Problem, OSError, ValueError):
        return {}


def git_line(repo: Path, sha: str, path: str, start: int, end: int):
    import signal
    import subprocess
    cap = MAX_LINE * 2
    try:
        child = subprocess.Popen(["git", "-C", str(repo), "cat-file", "blob", f"{sha}:{path}"], stdout=subprocess.PIPE,
                                 stderr=subprocess.DEVNULL, start_new_session=True)
    except (OSError, ValueError):
        raise Problem("file-git", "git could not be run")
    try:
        data = child.stdout.read(cap + 1)  # bounded: a huge blob is cut off, never buffered whole
    finally:
        try:
            os.killpg(child.pid, signal.SIGKILL)  # also reaps any helper git spawned
        except OSError:
            pass
        child.stdout.close()
        child.wait()
    if len(data) > cap:
        raise Problem("file-too-large", f"{clip(path, 50)} is larger than {cap} bytes")
    if not data and child.returncode != 0:
        raise Problem("file-not-found", f"{clip(path, 50)} does not exist at {sha[:8]}")
    lines = data.decode("utf-8", "replace").split("\n")
    if start < 1 or end > len(lines) or end < start:
        raise Problem("file-line", f"{clip(path, 50)} has {len(lines)} lines at {sha[:8]}; cited {start}-{end}")
    return "\n".join(lines[start - 1:end])


def resolve(source: str, ctx=None, depth: int = 0, seen=()) -> dict:
    """Resolve one Source. Never raises: the result says ok, why not, and the chain to the origin."""
    ctx = ctx if ctx is not None else {}
    result = {"source": clip(source, 200), "kind": None, "ok": False, "assumption": False, "origin": None,
              "deferred": False, "weak": False, "weak_reasons": [], "backed": False, "problems": [], "chain": [], "inputs": []}
    ctx["_resolves"] = ctx.get("_resolves", 0) + 1
    try:
        if ctx["_resolves"] > MAX_RESOLVES:
            raise Problem("too-many-sources", f"more than {MAX_RESOLVES} sources resolved for one claim")
        _resolve(source, ctx, depth, seen, result)
    except Problem as problem:
        result["problems"].append({"code": problem.code, "message": problem.message})
        result["ok"] = False
    except Exception as error:  # a resolver bug is a rejection, never a crash of the calling hook
        result["problems"].append({"code": "internal", "message": f"resolver error {type(error).__name__}"})
        result["ok"] = False
    result["label"] = label_of(result)
    return result


def weak_problem(result: dict):
    """Message when a source rests only on an unverified citation; asks and requirements refuse these, outage or
    not. A citation that is also backed by a verified user, wal or file source (an `inferred:` item with such an
    input) is not refused: the unverified part only warns."""
    if result.get("ok") and result.get("weak") and not result.get("backed"):
        return ("the only cite is an unverified ticket or file line (ticket not confirmed, outage or not; file line "
                "without an excerpt): add a `user:` or `wal:` source, which can be checked locally, or have main run "
                "`provenance.py cache-ticket` after checking the ticket")
    return None


def unreachable_warning(result: dict):
    if result.get("ok") and "ticket-unreachable" in (result.get("weak_reasons") or []):
        return "ticket could not be verified (tracker unreachable or out of scope): marked unverified"
    return None


# --------------------------------------------------------------------------- ticket lookup (bounded, cached)

TICKET_TIMEOUT = 4.0
_TICKET_MEMO = {}
_OUTAGE = {"until": 0.0}


def store_ticket(project: str, number: int, title: str, checked_by: str) -> None:
    cache_path = ticket_cache_path()
    cache_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    data = ticket_cache()
    data[f"{project}#{number}"] = {"title": clip(title, 160), "checked_by": clip(checked_by, 60)}
    tmp = cache_path.with_suffix(f".{os.getpid()}.tmp")
    tmp.write_text(json.dumps(data, indent=1), encoding="utf-8")
    os.replace(tmp, cache_path)


def lookup_ticket(project: str, number: int):
    """('found', title) | ('missing', None) | ('unreachable', reason). Uses the harness ticket adapter with a
    hard deadline of TICKET_TIMEOUT seconds and one attempt; never raises."""
    if os.environ.get("HARNESS_PROVENANCE_OFFLINE", "").strip().lower() in ("1", "true", "yes"):  # tightening only
        return "unverified", "offline mode"
    try:
        import spec_flow
        import ticket_adapters as ta
        spec_policy = spec_flow.load_spec_policy()
        _, _, config = spec_flow.ticket_config(spec_policy)
        adapter = spec_flow.make_adapter(config, spec_policy, project, time.monotonic() + TICKET_TIMEOUT)
        adapter.timeout, adapter.attempts = min(float(adapter.timeout), TICKET_TIMEOUT), 1
        try:
            with direct_connections():
                ticket = adapter.lookup(project, number)
        except ta.TicketOutOfScope:
            return "out-of-scope", "project not visible to this credential"
        except ta.TicketSystemUnavailable as error:
            # Only a genuine transport failure (connection, DNS, timeout, deadline) is an outage. Server errors,
            # 4xx answers and credential problems are not: they stay `unverified` and never start the skip window.
            text = str(error)
            if text.startswith("GoodQA unreachable") or "total deadline" in text:
                return "unreachable", "transport failure"
            return "unverified", "tracker refused or credentials unusable"
        return ("missing", None) if ticket is None else ("found", str(getattr(ticket, "title", "") or ""))
    except BaseException as error:  # anything else is "could not check", never a crash or a guess
        if isinstance(error, (KeyboardInterrupt, SystemExit)):
            raise
        return "unverified", type(error).__name__


class direct_connections:
    """urllib.request.urlopen without proxies for the duration of a ticket lookup: an inline HTTPS_PROXY must not
    be able to turn a lookup into a fake outage or a fake answer."""

    def __enter__(self):
        import urllib.request
        self._request, self._saved = urllib.request, urllib.request.urlopen
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        urllib.request.urlopen = lambda *args, **kwargs: opener.open(*args, **kwargs)
        return self

    def __exit__(self, *exc):
        self._request.urlopen = self._saved
        return False


TICKET_LOOKUP = lookup_ticket  # tests replace this


def check_ticket(project: str, number: int):
    """('found', title) | ('missing', None) | ('unreachable', why) | ('unknown', None). A positive answer is cached
    on disk; an answer is remembered for this process so one claim never waits twice."""
    mode = load_policy().get("ticket_lookup", "enforce")  # env may already have tightened it inside load_policy
    if mode not in MODES:
        mode = "enforce"
    if mode == "off":
        return "unknown", None
    key = (project, number)
    now = time.monotonic()
    memo = _TICKET_MEMO.get(key)
    if memo and now - memo[0] < 60:
        return memo[1]
    if now < _OUTAGE["until"]:  # a transport failure was just seen: skip the network call, never change a verdict
        return "unverified", "lookup skipped after a recent tracker transport failure"
    outcome = TICKET_LOOKUP(project, number)
    if outcome[0] == "found":
        try:
            store_ticket(project, number, outcome[1] or "", "goodqa-lookup")
        except OSError:
            pass
    if outcome[0] == "missing" and mode == "warn":
        outcome = ("missing-warn", "missing (warn mode)")
    _TICKET_MEMO[key] = (now, outcome)
    if outcome[0] == "unreachable":
        _OUTAGE["until"] = now + 60  # skip the remaining lookups of this process for a minute
    return outcome


def label_of(result: dict) -> str:
    if result.get("assumption"):
        return "ASSUMPTION"
    return LABELS.get(result.get("origin") or "", "UNTRACEABLE")


def _resolve(source, ctx, depth, seen, result):
    if depth > MAX_DEPTH:
        raise Problem("too-deep", f"source chain deeper than {MAX_DEPTH}")
    parsed = parse_source(source)
    kind = result["kind"] = parsed["kind"]
    home = ctx.get("home")
    if kind == "user":
        variant = parsed.get("variant", "user")
        if variant == "answer":
            turn = answer_turn(parsed["session"], parsed["ident"], home)
        elif variant == "queue":
            turn = queue_turn(parsed["session"], parsed["ident"], home)
        else:
            turn = user_turn(parsed["session"], parsed["uuid"], home)
        reason = excerpt_in(turn["text"], parsed["excerpt"])
        pasted = False
        if reason and turn.get("with_pasted") and excerpt_in(turn["with_pasted"], parsed["excerpt"]) is None:
            reason, pasted = None, True  # goodqa#15253 item 2: inside text the user pasted
        if reason:
            raise Problem("excerpt-not-found", reason)
        node = {"kind": "user", "session": parsed["session"], "uuid": parsed["uuid"],
                "timestamp": turn["timestamp"], "status": "verified"}
        if pasted:
            node["pasted"], node["trust"] = True, PASTED_TRUST
        if variant != "user":
            node["variant"] = variant
            node["trust"] = ANSWER_TRUST if variant == "answer" else QUEUE_TRUST
        if ctx.get("want_text"):
            node["text"] = turn["text"]
        node["excerpt"] = parsed["excerpt"]
        result["chain"].append(node)
        result["origin"], result["ok"], result["backed"] = "user", True, True
    elif kind == "ticket":
        key = f"{parsed['project']}#{parsed['number']}"
        cached = ticket_cache(home).get(key)
        state, detail = ("cache", None) if cached else check_ticket(parsed["project"], parsed["number"])
        if state == "missing":
            raise Problem("ticket-missing", f"GoodQA {key} does not exist (the tracker answered not found)")
        node = {"kind": "ticket", "ref": f"GoodQA {key}", "comment": parsed["comment"],
                "status": "verified" if state in ("cache", "found") else "unverified"}
        title = (cached or {}).get("title") if isinstance(cached, dict) else detail if state == "found" else None
        if title:
            node["title"] = clip(title, 120)
        result["chain"].append(node)
        result["origin"], result["ok"] = "ticket", True
        if state not in ("cache", "found"):
            result["deferred"], result["weak"] = True, True
            # Only a true outage may be warned about; out-of-scope projects and warn-mode misses stay refusable.
            result["weak_reasons"] = [{"unreachable": "ticket-unreachable", "out-of-scope": "ticket-out-of-scope",
                                       "missing-warn": "ticket-missing-warn"}.get(state, "ticket-unverified")]
    elif kind == "file":
        repo = Path(ctx.get("repo") or os.environ.get("HARNESS_PROVENANCE_REPO") or os.getcwd())
        text = git_line(repo, parsed["sha"], parsed["path"], parsed["line"], parsed["line_end"])
        result["weak"] = parsed["excerpt"] is None  # a bare line number proves the line exists, not what it says
        result["weak_reasons"] = ["file-no-excerpt"] if result["weak"] else []
        if parsed["excerpt"] is not None:
            reason = excerpt_in(text, parsed["excerpt"])
            if reason:
                raise Problem("excerpt-not-found", reason)
        result["chain"].append({"kind": "file", "ref": f"{parsed['path']}:{parsed['line']}@{parsed['sha'][:12]}",
                                "status": "verified", "text": text if ctx.get("want_text") else None})
        result["origin"], result["ok"], result["backed"] = "file", True, not result["weak"]
    elif kind == "wal":
        path = resolve_wal_path(parsed["path"], home)
        marker = f"{path}#{parsed['entry']}"
        if marker in seen:
            raise Problem("cycle", "wal: pointers form a cycle")
        record = wal_entry(path, parsed["entry"])
        if record == "malformed":
            raise Problem("wal-malformed", "the WAL entry line is malformed or oversized")
        if not isinstance(record, dict):
            raise Problem("wal-entry-not-found", f"no entry {clip(parsed['entry'], 20)} in {clip(path.name, 40)}")
        node = {"kind": "wal", "ref": f"{path.parent.name}/{path.name}#{parsed['entry']}", "event": record.get("event"),
                "at": record.get("at"), "note": clip(record.get("note", ""), 300), "status": "verified"}
        result["chain"].append(node)
        upstream = record.get("source")
        if not upstream:
            node["status"] = "legacy-unsourced"
            raise Problem("wal-unsourced", "that WAL entry has no Source (legacy or grandfathered entry); it cannot ground a claim")
        sub = resolve(upstream, ctx, depth + 1, seen + (marker,))
        result["chain"].extend(sub["chain"])
        result["inputs"] = sub["inputs"]
        result["problems"].extend(sub["problems"])
        result["assumption"] = sub["assumption"]
        result["origin"], result["ok"], result["deferred"] = sub["origin"], sub["ok"], sub["deferred"]
        result["weak"], result["weak_reasons"], result["backed"] = sub["weak"], list(sub["weak_reasons"]), sub["backed"]
    elif kind == "inferred":
        grounded = 0
        result["assumption"] = True
        for item in parsed["inputs"]:
            try:
                item_kind = parse_source(item)["kind"]
            except Problem as problem:
                # Name the input: the generic "Source must start with ..." text read as if the whole `inferred:`
                # source were malformed (main WAL w8d5f765ea4c, 2026-11-06).
                message = ("is free text, not a source: each input after `from` must be user:, answer:, queue:, "
                           "ticket:, wal: or file:, separated by ` ; `; the rationale goes after ` -- `"
                           if problem.code == "bad-syntax" and problem.message.startswith("Source must start with")
                           else problem.message)
                result["problems"].append({"code": problem.code, "message": f"inferred input `{clip(item, 60)}` {message}"})
                continue
            if item_kind == "inferred":
                result["problems"].append({"code": "inferred-nested", "message": "inferred inputs must be user/ticket/file/wal sources"})
                continue
            sub = resolve(item, ctx, depth + 1, seen)
            result["inputs"].append(sub)
            if sub["ok"] and not sub["assumption"] and not sub["weak"]:
                grounded += 1
            elif not sub["ok"]:
                result["problems"].extend({"code": p["code"], "message": "input: " + p["message"]} for p in sub["problems"])
        if grounded == 0 and not result["problems"]:
            result["problems"].append({"code": "inferred-ungrounded", "message": "inferred: has no input that traces to a user, ticket or file origin"})
        result["chain"].append({"kind": "inferred", "rationale": clip(parsed["rationale"], 300), "status": "assumption"})
        result["ok"] = not result["problems"]
        result["backed"] = grounded > 0  # a verified user, wal or file input stands behind the claim
        result["deferred"] = any(sub["deferred"] for sub in result["inputs"])
        result["weak"] = any(sub["weak"] for sub in result["inputs"])
        result["weak_reasons"] = sorted({r for sub in result["inputs"] for r in sub["weak_reasons"]})
    result["ok"] = bool(result["ok"]) and not result["problems"]


# --------------------------------------------------------------------------- rendering

def render(result: dict, indent: str = "  ") -> list:
    lines = []
    head = f"[{result['label']}]" + ("" if result["ok"] else " REJECTED")
    lines.append(f"{indent}{head} {clip(result['source'], 120)}")
    for problem in result["problems"]:
        lines.append(f"{indent}  ! {problem['code']}: {problem['message']}")
    for node in result["chain"]:
        kind = node["kind"]
        if kind == "user":
            lines.append(f"{indent}  user turn {node['uuid']} in session {node['session']} at {node.get('timestamp')}")
            if node.get("trust"):
                lines.append(f"{indent}  trust [{node['variant']}]: {node['trust']}")
            lines.append(f"{indent}  excerpt: \"{clip(node['excerpt'], 200)}\"")
            if node.get("text") is not None:
                lines.append(f"{indent}  message:")
                lines.extend(f"{indent}    | {line}" for line in node["text"].replace(SENTINEL, "[non-user block removed]").split("\n"))
        elif kind == "wal":
            lines.append(f"{indent}  wal {node['ref']} ({node.get('event')}, {node.get('at')}): {node.get('note')}")
        elif kind == "ticket":
            lines.append(f"{indent}  ticket {node['ref']} [{node['status']}]" + (f" {node['title']}" if node.get("title") else ""))
        elif kind == "file":
            lines.append(f"{indent}  file {node['ref']}")
            if node.get("text"):
                lines.extend(f"{indent}    | {line}" for line in node["text"].split("\n")[:20])
        elif kind == "inferred":
            lines.append(f"{indent}  ASSUMPTION (not a user requirement): {node['rationale']}")
    if result.get("ok") and result.get("weak"):
        lines.append(f"{indent}  note: UNVERIFIED citation (offline ticket or file line without an excerpt)")
    for sub in result["inputs"]:
        lines.append(f"{indent}  input:")
        lines.extend(render(sub, indent + "    "))
    return lines


def context_of(text, excerpt: str) -> str:
    """The user's own words around the quoted part, so a clipped quote cannot change the meaning unnoticed."""
    if not text:
        return excerpt
    body = norm(text.replace(SENTINEL, " "))
    first = norm(excerpt).split("...")[0].strip()
    index = body.find(first)
    if index < 0:
        return excerpt
    dot = body.rfind(". ", 0, index)
    start = max(0 if dot < 0 else dot + 2, index - 160)
    end = body.find(". ", index + len(first))
    end = len(body) if end < 0 else end + 1
    return body[start:min(end, index + len(first) + 160)]


def status_word(result: dict) -> str:
    if not result["ok"]:
        return "UNTRACEABLE"
    return "ASSUMPTION" if result["assumption"] else f"{result['label']}-SOURCED"


# --------------------------------------------------------------------------- spec and packet linting

SOURCE_RE = re.compile(r"(?<!\S)Source:\s*(.+)$", re.S)
ITEM_RE = re.compile(r"^\s*(?:(?:[>|]|[-*]|\d{1,3}[.)])\s*)*(?:\*\*|`)?((?:AC|NEG|REQ|ASK|DEC)-\d+)\b")
GRANDFATHER_RE = re.compile(r"(?m)^Provenance:\s*grandfathered\s*\((.{10,})\)\s*$")


def extract_items(text: str, sections=None) -> list:
    """[(id, line_number, full_text)] for bullets/lines naming AC-n/NEG-n/REQ-n/ASK-n/DEC-n, continuations joined."""
    items, current, section = [], None, None
    for number, line in enumerate(text.split("\n"), 1):
        heading = re.match(r"^## (.+?)\s*$", line)
        if heading:
            section, current = heading.group(1), None
            continue
        if sections is not None and section not in sections:
            continue
        match = ITEM_RE.match(line)
        if match and (sections is not None or not line.startswith("    ")):
            current = [match.group(1), number, line.strip()]
            items.append(current)
        elif current is not None and line.startswith((" ", "\t")) and line.strip():
            current[2] += " " + line.strip()
        else:
            current = None
    return [(ident, number, body) for ident, number, body in items]


def check_items(items: list, ctx=None) -> list:
    """[(id, line, result-or-None, problem-text-or-None)]."""
    out = []
    for ident, number, body in items:
        found = SOURCE_RE.search(body)
        if not found:
            out.append((ident, number, None, f"{ident} has no `Source:` (user:, ticket:, wal:, file: or inferred:)"))
            continue
        result = resolve(found.group(1).strip(), ctx)
        if result["ok"]:
            out.append((ident, number, result, None))
        else:
            first = result["problems"][0] if result["problems"] else {"code": "rejected", "message": "rejected"}
            out.append((ident, number, result, f"{ident} Source rejected ({first['code']}): {first['message']}"))
    return out


def spec_lint(text: str, mode=None, ctx=None):
    """(problems, warnings) for spec_flow.lint. Specs carry Source on every AC-n and NEG-n."""
    mode = mode or load_policy()["spec"]
    if mode == "off":
        return [], []
    if GRANDFATHERED_RE_SEARCH(text):
        head = text.split("\n## ", 1)[0]
        if not re.search(r"(?m)^Sign-off:\s*human\s*$", head):
            return ["provenance: `Provenance: grandfathered` is only valid with `Sign-off: human`"], []
        return [], ["provenance: GRANDFATHERED spec, origins not verified: " + clip(GRANDFATHER_RE.search(text).group(1), 80)]
    items = extract_items(text, sections={"Acceptance criteria", "Negative cases"})
    results = check_items(items, ctx)
    problems = [p for _, _, _, p in results if p]
    # An AC or NEG whose only cite is unverified (ticket not confirmed, outage or not; file line without excerpt) is
    # refused in enforce mode, as for asks; it only warns when a verified user, wal or file source also backs it.
    refused = [f"{i} {weak_problem(r)}" for i, _, r, p in results if r and not p and weak_problem(r)]
    backed = [f"provenance: {i} also cites an unverified source (ticket not confirmed or file line without excerpt)"
              for i, _, r, p in results if r and not p and r.get("weak") and not weak_problem(r)]
    if not items:
        return [], []
    if mode == "enforce":
        return problems + refused, backed
    return [], backed + ["provenance (warn mode): " + p for p in problems + refused]


def GRANDFATHERED_RE_SEARCH(text: str):
    # Only the header block counts, so a marker cannot hide in a later section.
    head = text.split("\n## ", 1)[0]
    return GRANDFATHER_RE.search(head)


def packet_gate(text: str, mode=None, ctx=None):
    """(exit_code, text) for peer_review plan: requirement lines without a verifiable Source."""
    mode = mode or load_policy()["plan_packet"]
    if mode == "off":
        return 0, ""
    try:
        items = [item for item in extract_items(text) if not item[2].startswith("#")]
        problems = [p for _, _, _, p in check_items(items, ctx) if p]
    except Exception as error:
        return (2 if mode == "enforce" else 0), f"provenance: packet check failed ({type(error).__name__})"
    if not problems:
        return 0, ""
    body = "provenance: plan packet items without a verifiable origin:\n" + "\n".join("  - " + p for p in problems[:30])
    if len(problems) > 30:
        body += f"\n  ... {len(problems) - 30} more"
    if mode == "enforce":
        return 2, body
    return 0, body + "\n(warn mode: review continues; set plan_packet to enforce in provenance_policy.json to block)"


# --------------------------------------------------------------------------- asks ledger

def session_wals(session: str, home=None) -> list:
    if not SESSION_RE.match(session):
        raise Problem("user-session-invalid", "bad session id")
    folder = wals_root(home) / session
    try:
        return sorted(p for p in folder.glob("*.jsonl") if p.name == "main.jsonl" or p.name.startswith("agent-"))
    except OSError:
        return []


def ledger(session: str, home=None) -> list:
    """Asks and their resolutions across the main and agent WALs of a session."""
    asks, closed = {}, {}
    for path in session_wals(session, home):
        for needle in (b'"event":"ask"', b'"event":"ask_resolved"'):
            try:
                for line in _lines_containing(path, needle):
                    if line is None:
                        continue
                    try:
                        record = loads_line(line)
                    except ValueError:
                        continue
                    if not isinstance(record, dict):
                        continue
                    if record.get("event") == "ask" and isinstance(record.get("id"), str):
                        record["at"] = str(record.get("at") or "")
                        record["_wal"] = path
                        asks[record["id"]] = record
                    elif record.get("event") == "ask_resolved" and isinstance(record.get("ref"), str):
                        closed[record["ref"]] = record
            except Exception:  # one unreadable WAL must not hide every other ask
                continue
    for ident, record in asks.items():
        record["_closed"] = closed.get(ident)
    return sorted(asks.values(), key=lambda r: r["at"])


def render_asks(session: str, home=None, ctx=None) -> tuple:
    entries = ledger(session, home)
    ctx = dict(ctx or {}, home=home, want_text=True)
    traced, assumptions, blocked, unverified, closed = [], [], [], [], 0
    for record in entries:
        if record.get("_closed"):
            closed += 1
            continue
        source = record.get("source") or ""
        result = resolve(source, dict(ctx)) if source else None
        row = (record, result)
        if result is None or not result["ok"]:
            blocked.append(row)
        elif result["assumption"]:
            assumptions.append(row)
        elif result["weak"] or result["deferred"] or result["origin"] == "file":
            unverified.append(row)
        else:
            traced.append(row)
    lines = [f"Asks ledger for session {session}: {len(traced)} traceable, {len(assumptions)} assumptions, {len(unverified)} unverified citations, "
             f"{len(blocked)} blocked, {closed} resolved"]

    def block(title, rows, mark):
        if not rows:
            return
        lines.append("")
        lines.append(title)
        for record, result in rows:
            lines.append(f"  {mark} {record['id']}  {clip(record.get('note', ''), 200)}")
            lines.append(f"      why: {clip(record.get('reason', '(no reason recorded)'), 200)}")
            lines.append(f"      owner: {record['_wal'].stem}")
            if result is None:
                lines.append("      source: NONE")
            else:
                lines.append(f"      source [{result['label']}]: {clip(result['source'], 160)}")
                for problem in result["problems"][:2]:
                    lines.append(f"      ! {problem['code']}: {problem['message']}")
                for node in result["chain"]:
                    if node["kind"] == "user":
                        lines.append(f"      user said: \"{clip(context_of(node.get('text'), node['excerpt']), 240, )}\"")
                    elif node["kind"] == "inferred":
                        lines.append(f"      assumed because: {node['rationale']}")

    block("ASKS (each traces to a real source)", traced, "*")
    block("UNVERIFIED CITATIONS (offline ticket or repo-file origin; check before relying, never a user requirement)", unverified, "~")
    block("ASSUMPTIONS TO CONFIRM (agent inference, not a user requirement)", assumptions, "?")
    block("BLOCKED: untraceable, do NOT present these to the user until a source is added", blocked, "!")
    return "\n".join(lines), {"traced": len(traced), "unverified": len(unverified), "assumptions": len(assumptions), "blocked": len(blocked), "closed": closed}


# --------------------------------------------------------------------------- CLI

def find_user(session: str, text: str, home=None, limit: int = 5) -> list:
    path = find_transcript(session, home)
    wanted = norm(text)
    if len(wanted) < EXCERPT_MIN:
        raise Problem("excerpt-short", f"search text needs {EXCERPT_MIN}+ characters")
    found = []
    for line in _lines_containing(path, b'"kind":"human"'):
        if line is None:
            continue
        try:
            record = loads_line(line)
        except ValueError:
            continue
        body, _ = user_authorship(record) if isinstance(record, dict) else (None, None)
        if body and excerpt_in(body, text) is None:
            found.append({"uuid": record.get("uuid"), "timestamp": record.get("timestamp"), "preview": clip(body.strip(), 100)})
        elif body is not None:
            pasted, _ = user_authorship(record, keep_pasted=True)
            if pasted and excerpt_in(pasted, text) is None:
                found.append({"uuid": record.get("uuid"), "timestamp": record.get("timestamp"),
                              "preview": clip(pasted.strip(), 100), "pasted": True})
    return found[-limit:]


def build_parser():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    check = sub.add_parser("check", help="resolve one Source")
    check.add_argument("--source", required=True)
    check.add_argument("--repo")
    check.add_argument("--json", action="store_true")
    spec = sub.add_parser("check-spec", help="check every AC-n/NEG-n of a spec")
    spec.add_argument("spec")
    packet = sub.add_parser("check-packet", help="check AC/NEG/REQ/ASK/DEC lines of a plan packet")
    packet.add_argument("packet")
    trace = sub.add_parser("trace", help="print the chain from an item back to its origin")
    trace.add_argument("item", nargs="?", help="wal:<path>#<id>, or a bare entry id with --session")
    trace.add_argument("--source")
    trace.add_argument("--session")
    trace.add_argument("--spec")
    trace.add_argument("--max-chars", type=int, default=800)
    trace.add_argument("--full", action="store_true")
    find = sub.add_parser("find-user", help="find the user turn(s) containing some words, to cite them")
    find.add_argument("--session", required=True)
    find.add_argument("--text", required=True)
    cache = sub.add_parser("cache-ticket", help="main records that it checked a ticket in the tracker (offline cache)")
    cache.add_argument("--ref", required=True, help="GoodQA <project>#<n>")
    cache.add_argument("--title", required=True)
    cache.add_argument("--checked-by", required=True)
    asks = sub.add_parser("asks", help="list the session's open asks with citations")
    asks.add_argument("--session", required=True)
    asks.add_argument("--json", action="store_true")
    return parser


def _find_wal_entry(item: str, session):
    if item.startswith("wal:"):
        return item
    if not session:
        raise Problem("bad-syntax", "a bare entry id needs --session (or give wal:<path>#<id>)")
    for path in session_wals(session):
        if wal_entry(path, item) not in (None, "malformed"):
            return f"wal:{path}#{item}"
    raise Problem("wal-entry-not-found", f"no entry {clip(item, 20)} in session {clip(session, 40)}")


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "check":
            result = resolve(args.source, {"repo": args.repo})
            print(json.dumps(result, indent=1) if args.json else "\n".join(render(result, "")))
            return 0 if result["ok"] else 2
        if args.command == "check-spec":
            text = read_text_arg(args.spec)
            if GRANDFATHERED_RE_SEARCH(text):
                problems, warnings = spec_lint(text, mode="enforce")
                print("\n".join(problems + warnings))
                return 2 if problems else 0
            rows = check_items(extract_items(text, sections={"Acceptance criteria", "Negative cases"}))
            for ident, number, result, problem in rows:
                print(f"{ident} line {number}: " + (problem or f"{status_word(result)}" + (" (deferred ticket check)" if result["deferred"] else "")))
            return 2 if any(p for *_, p in rows) or not rows else 0
        if args.command == "check-packet":
            body = read_text_arg(args.packet)
            code, text = packet_gate(body, mode="enforce")
            found = len(extract_items(body))
            print(text or (f"ok: {found} packet items, each with a verifiable Source" if found
                           else "no AC/NEG/REQ/ASK/DEC items found in the packet: nothing was checked"))
            return code if found or code else 2
        if args.command == "trace":
            ctx = {"want_text": True}
            if args.spec:
                text = read_text_arg(args.spec)
                wanted = [row for row in extract_items(text, sections={"Acceptance criteria", "Negative cases"}) if row[0] == args.item]
                if not wanted:
                    raise Problem("item-not-found", f"{clip(args.item, 20)} not in spec")
                found = SOURCE_RE.search(wanted[0][2])
                source = found.group(1).strip() if found else ""
                if not source:
                    print(f"{args.item}: no Source (UNTRACEABLE)")
                    return 2
            elif args.source:
                source = args.source
            elif args.item:
                source = _find_wal_entry(args.item, args.session)
            else:
                raise Problem("bad-syntax", "give an item, --source or --spec with an item id")
            result = resolve(source, ctx)
            lines = render(result, "")
            limit = None if args.full else max(args.max_chars, 200)
            body = "\n".join(lines)
            print(body if limit is None or len(body) <= limit * 4 else body[:limit * 4] + "\n... (truncated; use --full)")
            print(f"ORIGIN: {status_word(result)}")
            return 0 if result["ok"] else 2
        if args.command == "find-user":
            rows = find_user(args.session, args.text)
            print(json.dumps(rows, indent=1))
            return 0 if rows else 2
        if args.command == "cache-ticket":
            found = re.match(r"^GoodQA\s+([A-Za-z0-9_.-]{1,80})#(\d{1,9})$", args.ref.strip())
            if not found:
                raise Problem("bad-syntax", "--ref must look like `GoodQA <project>#<n>`")
            store_ticket(found.group(1), int(found.group(2)), args.title, args.checked_by)
            print(f"cached {args.ref}")
            return 0
        if args.command == "asks":
            text, counts = render_asks(args.session)
            print(json.dumps(counts) if args.json else text)
            return 2 if counts["blocked"] else 0
    except Problem as problem:
        print(f"provenance: {problem.code}: {problem.message}", file=sys.stderr)
        return 2
    except OSError as error:
        print(f"provenance: cannot read input ({type(error).__name__})", file=sys.stderr)
        return 2
    return 3


if __name__ == "__main__":
    sys.exit(main())
