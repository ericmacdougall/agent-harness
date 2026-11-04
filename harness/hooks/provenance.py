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
import unicodedata
from pathlib import Path

HERE = Path(__file__).resolve().parent
POLICY_FILE = HERE / "provenance_policy.json"
MAX_LINE = 8 * 1024 * 1024        # a transcript or WAL line larger than this is never parsed
MAX_HITS = 200                    # lines parsed per lookup
MAX_RESOLVES = 40                 # sources resolved per top-level claim
MAX_DEPTH = 8                     # wal: pointer chain depth
EXCERPT_MIN, EXCERPT_MAX, EXCERPT_SEGMENTS = 12, 300, 3
RATIONALE_MIN = 10
MODES = ("off", "warn", "enforce")
DEFAULT_POLICY = {
    "schema": 1, "spec": "enforce", "plan_packet": "warn",
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


def clip(value, limit: int = 60) -> str:
    """Short, single-line, control-free text for errors and logs: never echo a whole excerpt."""
    text = re.sub(r"[\x00-\x1f\x7f-\x9f\u200b-\u200f\u202a-\u202e\u2066-\u2069]+", " ", str(value))
    return text if len(text) <= limit else text[:limit - 3] + "..."


# --------------------------------------------------------------------------- policy

def load_policy(path: Path = POLICY_FILE) -> dict:
    policy = json.loads(json.dumps(DEFAULT_POLICY))
    try:
        with open(path, encoding="utf-8") as handle:
            loaded = json.load(handle)
        if not isinstance(loaded, dict) or loaded.get("schema") != 1:
            raise ValueError("not a schema 1 provenance policy")
        for key in ("spec", "plan_packet"):
            if loaded.get(key) in MODES:
                policy[key] = loaded[key]
        if isinstance(loaded.get("wal"), dict):
            for event, mode in loaded["wal"].items():
                if mode in MODES:
                    policy["wal"][event] = mode
    except FileNotFoundError:
        pass
    except (OSError, ValueError) as error:  # a broken policy must not silently disable the gate
        policy["policy_error"] = clip(error, 120)
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
_INNER = re.compile(r"<(" + _TAGS + r")\b[^>]*>(?:(?!<(?:" + _TAGS + r")\b[^>]*>).)*?</\1\s*>", re.S | re.I)
_OPEN = re.compile(r"<(?:" + _TAGS + r")\b[^>]*>", re.I)
_WRAPPER = re.compile(r"^\s*<([A-Za-z][\w:-]*)\b[^>]*>.*</\1\s*>\s*$", re.S)
SENTINEL = "\ufffc"  # replaces a removed block so an excerpt cannot span text on both sides of it


def strip_blocks(text: str) -> str:
    """Remove every non-user-authored block; an unclosed opener removes the rest of the text."""
    for _ in range(100):
        new = _INNER.sub(SENTINEL, text)
        if new == text:
            break
        text = new
    opener = _OPEN.search(text)
    return text[:opener.start()] + SENTINEL if opener else text


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
        raise Problem("bad-syntax", "Source must start with user:, ticket:, wal:, file: or inferred:")
    kind, rest = match.group(1).lower(), match.group(2).strip()
    if kind == "user":
        found = re.match(r"^([0-9a-fA-F-]{36})/([0-9a-fA-F-]{36})\s*(.*)$", rest, re.S)
        if not found or not UUID_RE.match(found.group(2)) or not UUID_RE.match(found.group(1)):
            raise Problem("bad-syntax", "user: needs <session-id>/<message-uuid> then a quoted excerpt")
        excerpt = parse_excerpt(found.group(3))
        if excerpt is None:
            raise Problem("excerpt-missing", "a user: source needs a verbatim quoted excerpt of the user's words")
        return {"kind": "user", "session": found.group(1).lower(), "uuid": found.group(2).lower(), "excerpt": excerpt}
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
    return Path(home) if home else Path.home() / ".claude"


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
_TOKENS = re.compile(rb'["\\\[\]{}]')


def loads_line(raw):
    """json.loads for untrusted lines. Python 3.9 aborts the whole interpreter (SIGABRT, not RecursionError)
    on JSON nested about 1000 deep, so cap the size and pre-scan the nesting depth before parsing.
    Raises ValueError for anything it will not parse; callers count that line as malformed and move on."""
    if isinstance(raw, str):
        raw = raw.encode("utf-8", "replace")
    if len(raw) > MAX_LINE:
        raise ValueError("line too large")
    if raw.count(b"[") + raw.count(b"{") > MAX_JSON_DEPTH:  # cheap bound first: depth <= bracket count
        depth, in_string, skip = 0, False, -1  # linear: one pass over structural bytes only
        for token in _TOKENS.finditer(raw):
            at = token.start()
            if at == skip:
                continue
            char = token.group()
            if in_string:
                if char == b"\\":
                    skip = at + 1
                elif char == b'"':
                    in_string = False
            elif char == b'"':
                in_string = True
            elif char in (b"[", b"{"):
                depth += 1
                if depth > MAX_JSON_DEPTH:
                    raise ValueError("nested too deeply")
            elif char in (b"]", b"}"):
                depth -= 1
    try:
        return json.loads(raw)
    except RecursionError:
        raise ValueError("nested too deeply")


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
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError as error:
        raise Problem("file-unreadable", f"cannot read {clip(path.name, 60)} ({type(error).__name__})")
    try:
        size = os.fstat(fd).st_size
        offset, hits, carry, next_line = 0, 0, b"", 0
        while offset < size and hits < MAX_HITS:
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
                    next_line = absolute + len(needle)
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
        with open(path, "rb") as handle:
            return f'"{key}":"'.encode() in handle.read(1 << 20)
    except OSError:
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


def user_authorship(record: dict):
    """(text, None) for a human-authored turn, else (None, reason)."""
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
        return strip_blocks(content), None
    if isinstance(content, list):
        pieces = []
        for block in content:
            if not isinstance(block, dict) or block.get("type") not in ("text", "image"):
                return None, "turn carries non-text blocks (tool results)"
            if block.get("type") == "text" and isinstance(block.get("text"), str):
                if _WRAPPER.match(block["text"]):
                    continue  # a block that is one wrapper element was injected by the harness or an extension
                pieces.append(strip_blocks(block["text"]))
        return "\n".join(pieces), None
    return None, "turn has no readable text"


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
    return {"text": text, "timestamp": record.get("timestamp"), "uuid": uid, "session": session}


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
            with open(path, "rb") as handle:
                for index, line in enumerate(handle, 1):
                    if index == number:
                        return loads_line(line)
        except (OSError, ValueError):
            return "malformed"
        return None
    return load_record(path, "id", entry)


def ticket_cache_path() -> Path:
    return Path.home() / ".agent-harness" / "provenance" / "tickets.json"


def ticket_cache(home=None) -> dict:
    try:
        with open(ticket_cache_path(), encoding="utf-8") as handle:
            data = json.load(handle)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def git_line(repo: Path, sha: str, path: str, start: int, end: int):
    import subprocess
    try:
        run = subprocess.run(["git", "-C", str(repo), "cat-file", "blob", f"{sha}:{path}"], capture_output=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        raise Problem("file-git", "git could not be run")
    if run.returncode != 0:
        raise Problem("file-not-found", f"{clip(path, 50)} does not exist at {sha[:8]}")
    lines = run.stdout[:MAX_LINE * 2].decode("utf-8", "replace").split("\n")
    if start < 1 or end > len(lines) or end < start:
        raise Problem("file-line", f"{clip(path, 50)} has {len(lines)} lines at {sha[:8]}; cited {start}-{end}")
    return "\n".join(lines[start - 1:end])


def resolve(source: str, ctx=None, depth: int = 0, seen=()) -> dict:
    """Resolve one Source. Never raises: the result says ok, why not, and the chain to the origin."""
    ctx = ctx if ctx is not None else {}
    result = {"source": clip(source, 200), "kind": None, "ok": False, "assumption": False, "origin": None,
              "deferred": False, "weak": False, "problems": [], "chain": [], "inputs": []}
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
    """Message when a resolved source is only a syntax-level citation; asks and requirements refuse these."""
    if result.get("ok") and result.get("weak"):
        return ("source is an unverified citation (ticket not in the local cache, or file line without an excerpt); "
                "cite the user's words or a sourced WAL entry, add a file excerpt, or have main run "
                "`provenance.py cache-ticket` after checking the ticket")
    return None


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
        turn = user_turn(parsed["session"], parsed["uuid"], home)
        reason = excerpt_in(turn["text"], parsed["excerpt"])
        if reason:
            raise Problem("excerpt-not-found", reason)
        node = {"kind": "user", "session": parsed["session"], "uuid": parsed["uuid"],
                "timestamp": turn["timestamp"], "status": "verified"}
        if ctx.get("want_text"):
            node["text"] = turn["text"]
        node["excerpt"] = parsed["excerpt"]
        result["chain"].append(node)
        result["origin"], result["ok"] = "user", True
    elif kind == "ticket":
        key = f"{parsed['project']}#{parsed['number']}"
        cached = ticket_cache(home).get(key)
        node = {"kind": "ticket", "ref": f"GoodQA {key}", "comment": parsed["comment"],
                "status": "verified" if cached else "deferred"}
        if isinstance(cached, dict) and cached.get("title"):
            node["title"] = clip(cached["title"], 120)
        result["chain"].append(node)
        result["origin"], result["ok"], result["deferred"] = "ticket", True, not cached
        result["weak"] = not cached  # syntax only: nothing proves the ticket exists
    elif kind == "file":
        repo = Path(ctx.get("repo") or os.environ.get("HARNESS_PROVENANCE_REPO") or os.getcwd())
        text = git_line(repo, parsed["sha"], parsed["path"], parsed["line"], parsed["line_end"])
        result["weak"] = parsed["excerpt"] is None  # a bare line number proves the line exists, not what it says
        if parsed["excerpt"] is not None:
            reason = excerpt_in(text, parsed["excerpt"])
            if reason:
                raise Problem("excerpt-not-found", reason)
        result["chain"].append({"kind": "file", "ref": f"{parsed['path']}:{parsed['line']}@{parsed['sha'][:12]}",
                                "status": "verified", "text": text if ctx.get("want_text") else None})
        result["origin"], result["ok"] = "file", True
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
        result["weak"] = sub["weak"]
    elif kind == "inferred":
        grounded = 0
        result["assumption"] = True
        for item in parsed["inputs"]:
            try:
                item_kind = parse_source(item)["kind"]
            except Problem as problem:
                result["problems"].append({"code": problem.code, "message": "input: " + problem.message})
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
        result["deferred"] = any(sub["deferred"] for sub in result["inputs"])
        result["weak"] = any(sub["weak"] for sub in result["inputs"])
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
    reviewed = re.search(r"(?m)^## Reviews[ \t]*$", text) is not None
    results = check_items(items, ctx)
    problems = [p for _, _, _, p in results if p]
    unverified = [f"{i} cites an unverified source (offline ticket or file line without excerpt)"
                  for i, _, r, p in results if r and not p and r.get("weak")]
    if reviewed:  # specs reviewed before provenance existed keep working until someone edits them
        return [], ["provenance: spec already carries recorded reviews, not enforced: " + "; ".join(problems[:3])] if problems else []
    if not items:
        return [], []
    if unverified:
        warnings_extra = ["provenance: " + u for u in unverified]
        return (problems, warnings_extra) if mode == "enforce" else ([], warnings_extra + ["provenance (warn mode): " + p for p in problems])
    return (problems, []) if mode == "enforce" else ([], ["provenance (warn mode): " + p for p in problems])


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
            text = Path(args.spec).read_text(encoding="utf-8")
            if GRANDFATHERED_RE_SEARCH(text):
                problems, warnings = spec_lint(text, mode="enforce")
                print("\n".join(problems + warnings))
                return 2 if problems else 0
            rows = check_items(extract_items(text, sections={"Acceptance criteria", "Negative cases"}))
            for ident, number, result, problem in rows:
                print(f"{ident} line {number}: " + (problem or f"{status_word(result)}" + (" (deferred ticket check)" if result["deferred"] else "")))
            return 2 if any(p for *_, p in rows) or not rows else 0
        if args.command == "check-packet":
            body = Path(args.packet).read_text(encoding="utf-8")
            code, text = packet_gate(body, mode="enforce")
            found = len(extract_items(body))
            print(text or (f"ok: {found} packet items, each with a verifiable Source" if found
                           else "no AC/NEG/REQ/ASK/DEC items found in the packet: nothing was checked"))
            return code if found or code else 2
        if args.command == "trace":
            ctx = {"want_text": True}
            if args.spec:
                text = Path(args.spec).read_text(encoding="utf-8")
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
            cache_path = ticket_cache_path()
            cache_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            data = ticket_cache()
            data[f"{found.group(1)}#{found.group(2)}"] = {"title": clip(args.title, 160), "checked_by": clip(args.checked_by, 60)}
            tmp = cache_path.with_suffix(f".{os.getpid()}.tmp")
            tmp.write_text(json.dumps(data, indent=1), encoding="utf-8")
            os.replace(tmp, cache_path)
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
