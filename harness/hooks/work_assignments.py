#!/usr/bin/env python3
"""Harness-kept ledger of every human request: ~/.agent-harness/work-assignments.json (see docs/work-assignments.md).

Hooks (Claude Code and Codex, `--runtime codex` for the latter) capture, check and re-inject; the CLI triages.

  hook:  prompt | stop | session | compact | ask-answer | guard | subagent-start
  cli:   status split no-ask update cancel remove prune import sync failures verify show

Capture is deterministic: UserPromptSubmit records every genuine human message as `untriaged`, and a transcript sync
binds it to its message uuid and line (or catches up a message no hook saw). Stop blocks while untriaged messages or
stale items of the session exist, a bounded number of times, then records a violation and lets go. Removal needs the
item done with evidence, or cancelled with transcript proof of a human turn, for more than 24 hours. Hooks never
block the user's turn on their own bugs: they exit 0 and write a failure that the next prompt shows loudly.
The installed work_assignments_policy.json is the only thing that can loosen modes (never env, repo or CLI).
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import subprocess
import sys
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import provenance as prov  # noqa: E402  (reuse: human-turn detection, transcript reading, clip)
import safe_input  # noqa: E402

POLICY_FILE = HERE / "work_assignments_policy.json"
SCHEMA = 1
STATES = ("open", "assigned", "in_progress", "blocked", "ready", "done", "cancelled")
CLOSED = ("done", "cancelled")
KINDS = ("request", "question", "decision", "bug", "feature", "chore")
GATE_SECONDS = 24 * 3600
PENDING_BIND_SECONDS = 2 * 3600
MAX_STORE_BYTES = 128 * 1024 * 1024
MAX_PAYLOAD = 8 * 1024 * 1024
SYNC_WINDOW = 64 * 1024
SYNC_MAX_BYTES = 64 * 1024 * 1024
LOCK_SECONDS = 3.0
HOOK_SECONDS = 6.0
DEFAULT_POLICY = {"schema": 1, "capture": "enforce", "stop": "enforce", "guard": "enforce",
                  "stale_hours": 12, "max_stop_blocks": 3}
NO_OWNER = ("unassigned", "none", "")
PROTECTED = re.compile(r"work-assign[A-Za-z0-9._*?-]*|work_assignments_policy[A-Za-z0-9._*?-]*|work_assign[a-z]*[*?]")
SAFE_CLI = re.compile(r"^\s*python3\s+(?:~|\$HOME|/[^\s;&|<>`$]*)?[^\s;&|<>`$]*/work_assignments\.py\s+[A-Za-z-]+(?:\s+[^;&|<>`$\n]*)?$")
WRITEISH = re.compile(r"(?:>|\btee\b|\brm\b|\bmv\b|\bcp\b|sed\s+-i|\btruncate\b|\bpython3?\b|\bperl\b|\bruby\b|\bnode\b|"
                      r"\bdd\b|\bln\b|\bchmod\b|\binstall\b|\bgit\s+(?:checkout|restore|stash)\b)")


class WAError(Exception):
    pass


class StoreCorrupt(WAError):
    pass


class LockTimeout(WAError):
    pass


def now() -> float:  # tests replace this clock; production never reads time from env
    return time.time()


def iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_ts(text) -> float:
    try:
        return datetime.fromisoformat(str(text).replace("Z", "+00:00")).timestamp()
    except ValueError:
        return 0.0


# --------------------------------------------------------------------------- policy

def load_policy(path=None) -> dict:
    """Installed file only. Missing or corrupt means the strict defaults plus `policy_error`; never env or CLI."""
    policy = dict(DEFAULT_POLICY)
    target = Path(path or POLICY_FILE)
    try:
        loaded = prov.loads_line(prov.read_small(target, 1 << 16))
        if not isinstance(loaded, dict) or loaded.get("schema") != 1:
            raise ValueError("not a schema 1 work-assignments policy")
        for key in ("capture", "stop", "guard"):
            if loaded.get(key) in prov.MODES:
                policy[key] = loaded[key]
        for key, low, high in (("stale_hours", 1, 24 * 14), ("max_stop_blocks", 1, 10)):
            if isinstance(loaded.get(key), int) and not isinstance(loaded[key], bool) and low <= loaded[key] <= high:
                policy[key] = loaded[key]
    except (prov.Problem, ValueError, OSError) as error:
        policy["policy_error"] = prov.clip(getattr(error, "message", error), 120)
    return policy


# --------------------------------------------------------------------------- store

def base() -> Path:
    return Path(os.environ.get("AGENT_HARNESS_HOME") or Path.home() / ".agent-harness")


def files() -> dict:
    d = base()
    return {"dir": d, "store": d / "work-assignments.json", "lock": d / "work-assignments.lock",
            "bak": d / "work-assignments.json.bak", "audit": d / "work-assignments.audit.jsonl",
            "fail": d / "work-assignments.failures.jsonl"}


def new_store() -> dict:
    return {"schema": SCHEMA, "rev": 0, "created_at": iso(now()), "seq": {"m": 0, "i": 0},
            "sessions": {}, "messages": {}, "items": {}, "violations": []}


def private_dir() -> Path:
    d = base()
    d.mkdir(mode=0o700, parents=True, exist_ok=True)
    return d


@contextmanager
def locked(timeout: float = LOCK_SECONDS):
    private_dir()
    fd = os.open(files()["lock"], os.O_RDWR | os.O_CREAT, 0o600)
    deadline = time.monotonic() + timeout
    try:
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except OSError:
                if time.monotonic() > deadline:
                    raise LockTimeout(f"work-assignments lock busy for {timeout:.0f}s")
                time.sleep(0.01)
        yield
    finally:
        os.close(fd)


def read_store() -> tuple:
    """(data, raw_bytes). Never returns an empty store for an unreadable file: preserve a copy and fail loudly."""
    path = files()["store"]
    try:
        raw = prov.read_small(path, MAX_STORE_BYTES)
    except prov.Problem as error:
        if error.code == "file-unreadable" and not path.exists():
            return new_store(), None
        raise StoreCorrupt(f"cannot read {path.name}: {error.message}")
    try:
        data = json.loads(raw.decode("utf-8"))
        if not isinstance(data, dict) or data.get("schema") != SCHEMA or not isinstance(data.get("items"), dict) \
                or not isinstance(data.get("messages"), dict):
            raise ValueError("unexpected shape")
    except (ValueError, UnicodeDecodeError) as error:
        stamp = time.strftime("%Y%m%dT%H%M%S", time.gmtime(now()))
        keep = path.with_name(f"work-assignments.corrupt-{stamp}-{hashlib.sha256(raw).hexdigest()[:8]}.json")
        if not keep.exists():
            write_private(keep, raw)
        raise StoreCorrupt(f"{path.name} is corrupt ({error}); preserved at {keep.name}. Restore with "
                           f"`work_assignments.py recover` (uses {files()['bak'].name}); nothing was overwritten")
    return data, raw


def write_private(path: Path, payload: bytes) -> None:
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    try:
        dfd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    except OSError:
        pass


def audit_line(event: str, **fields) -> None:
    """Hash-chained append-only log; caller holds the lock."""
    path = files()["audit"]
    prev = "0" * 64
    try:
        tail = prov.read_tail(path, 8192).split(b"\n")
        for raw in reversed([part for part in tail if part.strip()]):
            prev = json.loads(raw).get("hash", prev)
            break
    except (prov.Problem, ValueError):
        pass
    record = {"ts": iso(now()), "event": event, "prev": prev, **fields}
    record["hash"] = hashlib.sha256((prev + json.dumps(record, sort_keys=True, ensure_ascii=False)).encode()).hexdigest()
    fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    try:
        os.write(fd, (json.dumps(record, ensure_ascii=False) + "\n").encode())
        os.fsync(fd)
    finally:
        os.close(fd)


def verify_audit() -> list:
    problems, prev = [], "0" * 64
    try:
        raw = prov.read_small(files()["audit"], MAX_STORE_BYTES)
    except prov.Problem:
        return problems
    for number, line in enumerate(raw.split(b"\n"), 1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
            given = record.pop("hash")
            expected = hashlib.sha256((prev + json.dumps(record, sort_keys=True, ensure_ascii=False)).encode()).hexdigest()
        except (ValueError, KeyError, AttributeError):
            problems.append(f"line {number}: unreadable")
            break
        if record.get("prev") != prev or given != expected:
            problems.append(f"line {number}: chain broken")
            break
        prev = given
    return problems


@contextmanager
def transaction(timeout: float = LOCK_SECONDS):
    """lock, load, yield the data, save atomically (previous good copy kept as .bak)."""
    with locked(timeout):
        data, raw = read_store()
        yield data
        data["rev"] = int(data.get("rev", 0)) + 1
        if raw is not None:
            write_private(files()["bak"], raw)
        write_private(files()["store"], json.dumps(data, ensure_ascii=False, indent=1, sort_keys=True).encode())


def record_failure(event: str, error) -> None:
    try:
        private_dir()
        line = json.dumps({"ts": iso(now()), "event": event, "error": prov.clip(f"{type(error).__name__}: {error}", 300)})
        fd = os.open(files()["fail"], os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        try:
            os.write(fd, (line + "\n").encode())
        finally:
            os.close(fd)
    except OSError:
        print(f"work_assignments: FAILED to record failure for {event}", file=sys.stderr)


def pending_failures() -> list:
    try:
        raw = prov.read_tail(files()["fail"], 1 << 20)  # tail: a huge file must not hide the newest failures
    except prov.Problem:
        return []
    out = []
    for line in raw.split(b"\n"):
        try:
            out.append(json.loads(line))
        except ValueError:
            continue
    return out


# --------------------------------------------------------------------------- capture

def redact(text: str) -> str:
    try:
        from integrate_local import redact_output
        text = redact_output(text)
        text = re.sub(r"(?i)\b(pass(?:word|wd)?|pwd|secret|token|api[_ -]?key)\s+(?![\[\"'])\S+", r"\1 [redacted]", text)
        return re.sub(r"\b[0-9a-fA-F]{32,}\b", "[redacted]", text)
    except Exception:  # never store an unredacted excerpt when the redactor is unavailable
        return "[excerpt withheld: redactor unavailable]"


def excerpt_of(text: str) -> str:
    words = text[:65536].split()[:15]
    return prov.clip(redact(" ".join(words)), 200)


def classify_prompt(prompt: str):
    """(typed_text, pasted_only) or None when nothing in it is human-typed."""
    typed = prov.strip_blocks(prompt).replace(prov.SENTINEL, "").strip()
    if typed:
        return typed, False
    tags = {(m.group(1) or m.group(2)).lower() for m in prov._TAG_TOKEN.finditer(prompt)}
    if tags and tags <= {"pasted_content"}:
        return re.sub(r"</?pasted_content[^>]*>", "", prompt).strip(), True
    return None


def text_hash(text: str) -> str:
    return hashlib.sha256(prov.norm(text[:prov.MAX_TEXT]).encode("utf-8", "replace")).hexdigest()[:20]


def next_id(data: dict, kind: str) -> str:
    data["seq"][kind] += 1
    return ("M-" if kind == "m" else "WA-") + f"{data['seq'][kind]:04d}"


def add_message(data, *, runtime, session, transcript, text, pasted, source="prompt", uuid=None, line=None, ts=None):
    if uuid and any(m.get("uuid") == uuid for m in data["messages"].values()):
        return None
    mid = next_id(data, "m")
    data["messages"][mid] = {
        "id": mid, "runtime": runtime, "session": session, "uuid": uuid, "transcript": transcript, "line": line,
        "ts": ts or iso(now()), "captured_at": iso(now()), "excerpt": excerpt_of(text), "words": len(text.split()),
        "chars": len(text), "text_sha": text_hash(text), "pasted_only": pasted, "source": source,
        "triage": "untriaged", "reason": None, "items": []}
    return mid


def session_record(data, session, runtime, transcript):
    rec = data["sessions"].setdefault(session, {"runtime": runtime, "transcript": transcript, "offset": None, "line": 0,
                                                 "first_seen": iso(now()), "blocks": {}, "reinject": False})
    rec["transcript"] = transcript or rec.get("transcript")
    rec["runtime"] = runtime
    return rec


def capture_prompt(data: dict, payload: dict, runtime: str):
    session = str(payload.get("session_id") or "")
    if not valid_session(session) or payload.get("agent_id"):
        return None  # sub-agent payloads are not human requests
    prompt = payload.get("prompt")
    if not isinstance(prompt, str):
        return None
    found = classify_prompt(prompt)
    if found is None:
        return None
    text, pasted = found
    transcript = payload.get("transcript_path") if isinstance(payload.get("transcript_path"), str) else None
    session_record(data, session, runtime, transcript)
    return add_message(data, runtime=runtime, session=session, transcript=transcript, text=text, pasted=pasted)


def valid_session(session: str) -> bool:
    return bool(prov.SESSION_RE.match(session)) and session not in (".", "..")


def human_records(raw: bytes, runtime: str, first_line: int):
    """Yield (line_number, id, ts, text, pasted) for genuine human turns in complete transcript lines."""
    marker = b'"origin"' if runtime == "claude" else b'"UserMessage"'
    for number, line in enumerate(raw.split(b"\n"), first_line):
        if marker not in line or len(line) > prov.MAX_LINE:
            continue
        try:
            record = prov.loads_line(line)
        except ValueError:
            continue
        if not isinstance(record, dict):
            continue
        if runtime == "claude":
            text, _ = prov.user_authorship(record)
            if text is None:
                continue
            uid, ts = record.get("uuid"), record.get("timestamp")
            pasted = not text.replace(prov.SENTINEL, "").strip() and b"pasted_content" in line
            text = text.replace(prov.SENTINEL, "").strip()
        else:
            item = (record.get("payload") or {}).get("item") if record.get("type") == "event_msg" else None
            if not isinstance(item, dict) or item.get("type") != "UserMessage":
                continue
            uid, ts = item.get("id"), record.get("timestamp")
            joined = "\n".join(str(c.get("text", "")) for c in item.get("content") or [] if isinstance(c, dict))
            found = classify_prompt(joined)
            if found is None:
                continue
            text, pasted = found
        if isinstance(uid, str) and prov.UUID_RE.match(uid) or (runtime == "codex" and isinstance(uid, str) and uid):
            if text or pasted:
                yield number, uid, ts, text, pasted


def count_lines(path: str, upto: int) -> int:
    total, read = 0, 0
    fd = prov.open_regular(path)
    try:
        while read < upto:
            chunk = os.pread(fd, min(8 << 20, upto - read), read)
            if not chunk:
                break
            total += chunk.count(b"\n")
            read += len(chunk)
    finally:
        os.close(fd)
    return total


def sync_session(data: dict, session: str) -> int:
    """Bind pending messages to transcript uuid and line; catch up human turns no hook saw. Returns changes."""
    rec = data["sessions"].get(session)
    if not rec or not rec.get("transcript"):
        return 0
    path, runtime = rec["transcript"], rec.get("runtime", "claude")
    changes = 0
    try:
        size = os.stat(path).st_size
        if rec.get("offset") is None or rec["offset"] > size:
            start = max(0, size - SYNC_WINDOW)
            if start:
                tail = prov.read_tail(path, size - start + 1)
                start = start - 1 + tail.find(b"\n") + 1 if b"\n" in tail[:SYNC_WINDOW + 1] else size
            rec["offset"], rec["line"] = start, (count_lines(path, start) if start <= prov.MAX_SCAN_BYTES else 0)
        want = min(size - rec["offset"], SYNC_MAX_BYTES)
        if want <= 0:
            return 0
        fd = prov.open_regular(path)
        try:
            raw = os.pread(fd, want, rec["offset"])
        finally:
            os.close(fd)
    except (OSError, prov.Problem):
        return 0
    cut = raw.rfind(b"\n") + 1  # complete lines only
    raw = raw[:cut]
    created = parse_ts(data.get("created_at"))
    known = {m["uuid"] for m in data["messages"].values() if m.get("uuid")} | set(data.get("tombstones", []))
    for number, uid, ts, text, pasted in human_records(raw, runtime, rec["line"] + 1):
        if uid in known:
            continue
        digest = text_hash(text) if text else None
        match = next((m for m in sorted(data["messages"].values(), key=lambda m: m["captured_at"])
                      if m["session"] == session and m.get("uuid") is None and m.get("source") == "prompt"
                      and (m["text_sha"] == digest or (pasted and m["pasted_only"]))), None)
        if match:
            match.update(uuid=uid, line=number, transcript=path, ts=ts or match["ts"])
            changes += 1
        elif parse_ts(ts) >= created:  # a turn no hook saw: catch it up (nothing older than the ledger itself)
            if add_message(data, runtime=runtime, session=session, transcript=path, text=text, pasted=pasted,
                           uuid=uid, line=number, ts=ts):
                data["messages"][f"M-{data['seq']['m']:04d}"]["caught_up"] = True
                changes += 1
        known.add(uid)
    rec["offset"] += cut
    rec["line"] += raw.count(b"\n")
    return changes


def discover_codex(data: dict) -> None:
    """Track Codex rollouts that began after the ledger did, so a hook-less Codex session is still captured."""
    root = Path(os.environ.get("CODEX_HOME") or Path.home() / ".codex") / "sessions"
    created = parse_ts(data.get("created_at"))
    tracked = {rec.get("transcript") for rec in data["sessions"].values()}
    today = datetime.fromtimestamp(now(), timezone.utc)
    for back in (0, 1):
        day = root / (today - timedelta(days=back)).strftime("%Y/%m/%d")
        try:
            names = sorted(os.listdir(day))[-40:]
        except OSError:
            continue
        for name in names:
            path = str(day / name)
            match = re.match(r"rollout-.*-([0-9a-f-]{36})\.jsonl$", name)
            if not match or path in tracked:
                continue
            try:
                if os.stat(path).st_mtime < created:
                    continue
                first = prov.read_small(path, 1 << 16).split(b"\n")[0]
                started = parse_ts(json.loads(first).get("timestamp"))
            except (OSError, prov.Problem, ValueError):
                continue
            if started >= created - 60:
                rec = session_record(data, match.group(1), "codex", path)
                rec["offset"], rec["line"] = 0, 0


def sync_all(data: dict, session=None) -> int:
    discover_codex(data)
    wanted = [session] if session else sorted(data["sessions"], key=lambda s: data["sessions"][s].get("first_seen", ""))[-40:]
    return sum(sync_session(data, sid) for sid in wanted if sid in data["sessions"])


# --------------------------------------------------------------------------- problems and digests

def agent_stopped(session: str, agent: str) -> bool:
    try:
        wal = Path.home() / ".claude" / "wals" / prov.safe_name(session) / f"agent-{prov.safe_name(agent)}.jsonl"
        return b'"event":"subagent_stop"' in prov.read_tail(wal, 65536)
    except prov.Problem:
        return False


def item_flags(item: dict, policy: dict, ts: float) -> list:
    if item["state"] in CLOSED:
        return []
    flags = []
    owner = item.get("owner", "")
    if owner in NO_OWNER:
        flags.append("no-owner")
    elif owner.startswith("agent:") and agent_stopped(item.get("session") or "", owner[6:]):
        flags.append("owner-stopped")
    if ts - parse_ts(item.get("last_checked")) > policy["stale_hours"] * 3600:
        flags.append("stale")
    return flags


def problems_for(data: dict, session: str, policy: dict, ts=None) -> list:
    ts = ts or now()
    found = []
    for m in data["messages"].values():
        if m["triage"] == "untriaged" and m["session"] == session:
            found.append(("untriaged", m["id"], f"{m['id']}: \"{m['excerpt']}\"" + (" [pasted]" if m["pasted_only"] else "")))
    for item in data["items"].values():
        if item.get("session") == session:
            flags = item_flags(item, policy, ts)
            if flags:
                found.append(("stale", item["id"], f"{item['id']} ({item['state']}, owner {item.get('owner')}): "
                              + ",".join(flags) + f" - {prov.clip(item['description'], 60)}"))
    return found


def digest(data: dict, policy: dict, session=None, limit: int = 20) -> str:
    ts = now()
    untriaged = [m for m in data["messages"].values() if m["triage"] == "untriaged"]
    open_items = [i for i in data["items"].values() if i["state"] not in CLOSED]
    flagged = [i for i in open_items if item_flags(i, policy, ts)]
    ordered = sorted(open_items, key=lambda i: (not item_flags(i, policy, ts), i.get("session") != session, i["id"]))
    lines = [f"Work assignments: {len(untriaged)} untriaged message(s), {len(open_items)} open item(s), "
             f"{len(flagged)} flagged (no owner, stopped owner or stale)."]
    for m in untriaged[:8]:
        lines.append(f"  UNTRIAGED {m['id']}: \"{m['excerpt']}\" -> work_assignments.py split --msg {m['id']} --item '...' | no-ask")
    for item in ordered[:limit]:
        flag = ",".join(item_flags(item, policy, ts))
        lines.append(f"  {item['id']} [{item['state']}] owner={item.get('owner')}{' !' + flag if flag else ''}: "
                     f"{prov.clip(item['description'], 70)}" + (f" -> {prov.clip(item['next_step'], 50)}" if item.get("next_step") else ""))
    if len(ordered) > limit:
        lines.append(f"  ... {len(ordered) - limit} more: run `work_assignments.py status`")
    return "\n".join(lines)


# --------------------------------------------------------------------------- hooks

def read_payload() -> dict:
    try:
        raw = safe_input.read_stdin_bounded(MAX_PAYLOAD)
        data = prov.loads_line(raw) if raw.strip() else {}
        return data if isinstance(data, dict) else {}
    except safe_input.InputRejected as rejected:
        raise WAError(f"hook payload rejected ({rejected.code}); the message was NOT captured")
    except ValueError as error:
        raise WAError(f"hook payload unreadable ({error})")


def context(event: str, text: str) -> dict:
    return {"hookSpecificOutput": {"hookEventName": event, "additionalContext": text}}


def surface_warnings(data: dict, session: str) -> list:
    lines = []
    fails = pending_failures()
    if fails:
        lines.append(f"WORK-ASSIGNMENTS CAPTURE FAILURE ({len(fails)} unacknowledged, latest: {fails[-1]['event']}: "
                     f"{fails[-1]['error']}). A user message may be missing from the ledger. Investigate, then run "
                     "`work_assignments.py failures --ack`.")
    for violation in data.get("violations", []):
        if violation.get("session") == session and not violation.get("surfaced"):
            lines.append(f"WORK-ASSIGNMENTS VIOLATION: Stop was allowed with unresolved {violation['signature']}; resolve it now.")
            violation["surfaced"] = True
    for m in data["messages"].values():
        if m["session"] == session and m["triage"] == "untriaged" and m.get("uuid") is None \
                and now() - parse_ts(m["captured_at"]) > PENDING_BIND_SECONDS and not m.get("bind_violation"):
            m["bind_violation"] = True
            lines.append(f"WORK-ASSIGNMENTS: {m['id']} could not be bound to a transcript line after 2h (cannot-bind).")
    return lines


def hook_prompt(payload: dict, runtime: str) -> dict:
    policy = load_policy()
    out = []
    session = str(payload.get("session_id") or "")
    if policy["capture"] != "off" or pending_failures():
        with transaction() as data:
            if policy["capture"] != "off":
                capture_prompt(data, payload, runtime)
                if valid_session(session):
                    sync_all(data, session)
            out += surface_warnings(data, session)
            rec = data["sessions"].get(session)
            if rec and rec.get("reinject"):
                rec["reinject"] = False
                out.append(digest(data, policy, session))
            elif any(m["triage"] == "untriaged" and m["session"] == session for m in data["messages"].values()):
                out.append("Work assignments: triage the untriaged message(s) with work_assignments.py status / split / no-ask "
                           "before ending the turn (Stop enforces).")
    return context("UserPromptSubmit", "\n".join(out)) if out else {}


def hook_session(payload: dict, runtime: str) -> dict:
    policy = load_policy()
    session = str(payload.get("session_id") or "")
    with transaction() as data:
        if valid_session(session) and not payload.get("agent_id"):
            transcript = payload.get("transcript_path") if isinstance(payload.get("transcript_path"), str) else None
            session_record(data, session, runtime, transcript)
            sync_all(data, session)
        text = "\n".join(surface_warnings(data, session) + [digest(data, policy, session)])
    return context("SessionStart", text)


def hook_compact(payload: dict, runtime: str) -> dict:
    session = str(payload.get("session_id") or "")
    if not valid_session(session):
        return {}
    with transaction() as data:
        if session in data["sessions"]:
            data["sessions"][session]["reinject"] = True
    return {}


def hook_ask_answer(payload: dict, runtime: str) -> dict:
    session = str(payload.get("session_id") or "")
    if load_policy()["capture"] == "off" or not valid_session(session) or payload.get("agent_id"):
        return {}
    response = payload.get("tool_response", payload.get("tool_result"))
    text = json.dumps(response, ensure_ascii=False)[:20000] if response is not None else ""
    if not text.strip() or text in ("null", "{}", '""'):
        return {}
    transcript = payload.get("transcript_path") if isinstance(payload.get("transcript_path"), str) else None
    with transaction() as data:
        session_record(data, session, runtime, transcript)
        key = f"ask:{payload.get('tool_use_id') or text_hash(text)}"
        if not any(m.get("uuid") == key for m in data["messages"].values()):
            add_message(data, runtime=runtime, session=session, transcript=transcript, text=text, pasted=False,
                        source="ask-answer", uuid=key)
    return {}


def hook_stop(payload: dict, runtime: str) -> dict:
    policy = load_policy()
    session = str(payload.get("session_id") or "")
    if policy["stop"] == "off" or not valid_session(session) or payload.get("agent_id"):
        return {}
    with transaction() as data:
        if isinstance(payload.get("transcript_path"), str) and session in data["sessions"]:
            data["sessions"][session]["transcript"] = payload["transcript_path"]
        sync_all(data, session)
        found = problems_for(data, session, policy)
        rec = data["sessions"].setdefault(session, {"runtime": runtime, "transcript": None, "offset": None, "line": 0,
                                                     "first_seen": iso(now()), "blocks": {}, "reinject": False})
        if not found:
            rec["blocks"] = {}
            return {}
        signature = ",".join(sorted(f"{k}:{i}" for k, i, _ in found))
        used = rec["blocks"].get(signature, 0)
        listing = "\n".join("  - " + line for _, _, line in found[:12]) + (f"\n  ... {len(found) - 12} more" if len(found) > 12 else "")
        if policy["stop"] == "enforce" and used < policy["max_stop_blocks"]:
            rec["blocks"][signature] = used + 1
            return {"decision": "block", "reason": (
                f"Work assignments ({used + 1}/{policy['max_stop_blocks']}): unresolved before you stop:\n{listing}\n"
                "Triage each message (`work_assignments.py split --msg M-n --item '...'` or `no-ask --msg M-n --reason '...'`) "
                "and update stale items (`work_assignments.py update WA-n --owner ... --next ...` or `--state done --evidence <commit|PR#|url|tested:id>`).")}
        if policy["stop"] == "enforce":
            if not any(v.get("session") == session and v.get("signature") == signature for v in data["violations"]):
                data["violations"].append({"session": session, "signature": signature, "ts": iso(now()), "surfaced": False})
                audit_line("stop-violation", session=session, signature=signature[:500])
            return {"systemMessage": f"work-assignments VIOLATION: stopping with {len(found)} unresolved item(s); logged and shown next prompt"}
        return {"systemMessage": f"work-assignments (warn mode): {len(found)} unresolved item(s):\n{listing}"}


def hook_subagent_start(payload: dict, runtime: str) -> dict:
    agent = str(payload.get("agent_id") or "")
    with locked():
        data, _ = read_store()
    mine = [i for i in data["items"].values() if i.get("owner") == f"agent:{agent}" and i["state"] not in CLOSED]
    script = Path(__file__).resolve()
    text = ("Request ledger: you do not create requests. Record progress on the items you own with "
            f"`python3 {script} update WA-n --actor agent:{agent} --state in_progress|blocked|ready|done "
            "--next '...' --evidence <commit|PR#n|url|tested:id>` (done needs evidence).")
    if mine:
        text += " Items owned by you: " + "; ".join(f"{i['id']} {prov.clip(i['description'], 60)}" for i in mine[:10])
    return context("SubagentStart", text)


def hook_guard(payload: dict, runtime: str) -> dict:
    mode = load_policy()["guard"]
    if mode == "off":
        return {}
    tool, tool_input = str(payload.get("tool_name") or ""), payload.get("tool_input")
    blob = json.dumps(tool_input, ensure_ascii=False) if tool_input is not None else ""
    command = tool_input.get("command") if isinstance(tool_input, dict) else None
    if isinstance(command, list):
        command = " ".join(str(part) for part in command)
    if not PROTECTED.search(blob):
        return {}
    if isinstance(command, str) and SAFE_CLI.match(command):  # exactly one CLI call: no redirection, chaining or substitution
        return {}
    writer = bool(re.search(r"(?i)write|edit|patch|notebook", tool)) or bool(WRITEISH.search(blob))
    if not writer:
        return {}
    reason = ("The work-assignments store, backup, audit log, lock and policy are changed only through "
              "work_assignments.py (the 24h removal gate lives there); direct edits are refused.")
    if mode == "enforce":
        return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                       "permissionDecisionReason": reason}}
    return context("PreToolUse", "(warn mode) " + reason)


HOOKS = {"prompt": hook_prompt, "stop": hook_stop, "session": hook_session, "compact": hook_compact,
         "ask-answer": hook_ask_answer, "guard": hook_guard, "subagent-start": hook_subagent_start}


def run_hook(name: str, runtime: str) -> int:
    def timeout():
        record_failure(f"{name}:timeout", TimeoutError(f"hook exceeded {HOOK_SECONDS:.0f}s"))
        os._exit(0)

    timer = threading.Timer(HOOK_SECONDS, timeout)
    timer.daemon = True
    timer.start()
    try:
        result = HOOKS[name](read_payload(), runtime)
    except Exception as error:  # a ledger bug must never block the user's turn; it is recorded and shown next prompt
        record_failure(name, error)
        print(f"work_assignments {name}: FAILED ({type(error).__name__}: {prov.clip(error, 160)}); recorded", file=sys.stderr)
        result = {"systemMessage": f"work-assignments {name} FAILED: {prov.clip(error, 160)} (recorded; shown at next prompt)"} \
            if name in ("prompt", "stop", "session") else {}
    finally:
        timer.cancel()
    if result:
        print(json.dumps(result))
    return 0


# --------------------------------------------------------------------------- evidence and proof

EVIDENCE = (("commit", re.compile(r"^(?:commit:)?([0-9a-f]{7,40})$")), ("pr", re.compile(r"^(?:pr:|PR\s?#)(\d{1,7})$", re.I)),
            ("url", re.compile(r"^(https?://[^\s]{4,300})$")), ("tested", re.compile(r"^(?:tested:|REALLY_TESTED[: ]\s*)([A-Za-z0-9_-]{6,40})$")))


def commit_exists(sha: str, repo=None) -> bool:
    try:
        run = subprocess.run(["git", "-C", str(repo or os.getcwd()), "cat-file", "-e", sha + "^{commit}"],
                             capture_output=True, timeout=5, env={**os.environ, "GIT_OPTIONAL_LOCKS": "0"})
        return run.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def wal_has_test(entry: str) -> bool:
    """A REALLY_TESTED WAL note with this id exists in a session or Codex WAL on this host (bounded scan)."""
    roots = [Path.home() / ".claude" / "wals", base() / "codex-wals"]
    deadline, needle = time.monotonic() + 4.0, f'"id":"{entry}"'.encode()
    for root in roots:
        try:
            paths = [Path(e.path) for d in os.scandir(root) if d.is_dir() for e in os.scandir(d.path) if e.name.endswith(".jsonl")]
        except OSError:
            continue
        for path in paths:
            if time.monotonic() > deadline:
                return False
            try:
                for line in prov._lines_containing(path, needle):
                    if line and b"REALLY_TESTED" in line:
                        return True
            except prov.Problem:
                continue
    return False


def parse_evidence(text: str, repo=None):
    """Format plus what can be checked offline: a commit must exist locally, a tested id must be a REALLY_TESTED WAL
    note. PR numbers and URLs cannot be checked here and are recorded as self-attested."""
    text = text.strip()
    for kind, pattern in EVIDENCE:
        found = pattern.match(text)
        if found:
            ref = found.group(1)
            if kind == "commit" and not commit_exists(ref, repo):
                raise WAError(f"commit {ref} not found in {repo or os.getcwd()} (pass --repo PATH)")
            if kind == "tested" and not wal_has_test(ref):
                raise WAError(f"no REALLY_TESTED WAL note with id {ref} on this host")
            return {"kind": kind, "ref": ref, "at": iso(now()), "attested": kind in ("pr", "url")}
    raise WAError("evidence must be a commit sha, PR#<n>, https URL or tested:<WAL id>; got " + repr(prov.clip(text, 40)))


def transcript_roots() -> list:
    return [prov.claude_home() / "projects", Path(os.environ.get("CODEX_HOME") or Path.home() / ".codex") / "sessions"]


def verify_proof(file: str, line: int, uuid: str, quote: str) -> dict:
    """Read the actual transcript line: it must be that uuid, a genuine human turn, and contain the quote."""
    if len(quote.strip()) < prov.EXCERPT_MIN:
        raise WAError(f"quote needs {prov.EXCERPT_MIN}+ characters from the user's message")
    if len(quote) > 120 or redact(quote) != quote:
        raise WAError("quote must be at most 120 characters and free of secret-like text; choose other words")
    roots = [str(r) for r in transcript_roots()]
    target = None
    try:
        for number, raw in safe_input.iter_jsonl_lines(file, prov.MAX_LINE, max_total_bytes=prov.MAX_SCAN_BYTES,
                                                        max_seconds=20, allowed_roots=roots):
            if number == line:
                target = raw
                break
    except safe_input.InputRejected as rejected:
        raise WAError(f"proof file refused: {rejected.message}")
    if target is None:
        raise WAError(f"transcript has no line {line}")
    if uuid.encode() not in target:
        raise WAError(f"line {line} is not message {uuid[:8]}...")
    try:
        record = prov.loads_line(target)
    except ValueError:
        raise WAError(f"line {line} is not readable JSON")
    if isinstance(record, dict) and record.get("type") == "event_msg":
        found = list(human_records(target, "codex", line))
    else:
        found = list(human_records(target, "claude", line)) if isinstance(record, dict) and record.get("uuid") == uuid else []
        if not found and isinstance(record, dict):
            _, why = prov.user_authorship(record)
            raise WAError(f"line {line} is not a genuine human turn: {why or 'uuid mismatch'}")
    if not found or found[0][1] != uuid:
        raise WAError(f"line {line} is not a genuine human turn with uuid {uuid[:8]}...")
    text = found[0][3]
    why = prov.excerpt_in(text, quote)
    if why:
        raise WAError("quote not in that human message: " + why)
    return {"file": file, "line": line, "uuid": uuid, "quote": quote, "verified_at": iso(now())}


def bound_proof(data: dict, item: dict, proof: dict) -> None:
    """The proving turn must be a human message this ledger captured (hook or sync) from a transcript it tracks,
    not older than the item. A forged transcript file or a stranger's message cannot cancel an item."""
    for msg in data["messages"].values():
        if msg.get("uuid") == proof["uuid"] and msg.get("source") == "prompt":
            tracked = data["sessions"].get(msg["session"], {}).get("transcript")
            if tracked and os.path.realpath(tracked) == os.path.realpath(proof["file"]) \
                    and parse_ts(msg["ts"]) >= parse_ts(item.get("created")) - 1:
                return
            raise WAError("proof message is not from a transcript this ledger tracks, or predates the item")
    raise WAError("proof uuid is not a human message captured by this ledger (run `sync` first if it is recent)")


def eligible(item: dict, ts: float, data=None) -> tuple:
    """(ok, reason). The 24h clock is state_since; done needs evidence, cancelled needs re-verifiable proof."""
    state = item["state"]
    if state not in CLOSED:
        return False, f"state is {state}; only done or cancelled items can be removed"
    age = ts - parse_ts(item.get("state_since"))
    if age <= GATE_SECONDS:
        return False, f"{state} for {age / 3600:.1f}h; removal needs more than 24h"
    if state == "done":
        if not item.get("evidence"):
            return False, "done without evidence"
        return True, "done with evidence for more than 24h"
    proof = item.get("cancel_proof")
    if not proof:
        return False, "cancelled without user proof"
    try:
        verify_proof(proof["file"], proof["line"], proof["uuid"], proof["quote"])
        if data is not None:
            bound_proof(data, item, proof)
    except (WAError, KeyError) as error:
        return False, f"cancel proof no longer verifies: {error}"
    return True, "cancelled with verified user proof for more than 24h"


# --------------------------------------------------------------------------- cli

def find_message(data, ref):
    if ref in data["messages"]:
        return data["messages"][ref]
    hits = [m for m in data["messages"].values() if m.get("uuid") and len(ref) >= 8 and m["uuid"].startswith(ref)]
    if len(hits) != 1:
        raise WAError(f"message {ref!r} not found" if not hits else f"message prefix {ref!r} is ambiguous")
    return hits[0]


def find_item(data, ref):
    if ref not in data["items"]:
        raise WAError(f"item {ref!r} not found")
    return data["items"][ref]


def history(item, actor, event, **fields):
    item["history"].append({"ts": iso(now()), "actor": actor, "event": event, **fields})


def set_state(item, state, actor):
    if state != item["state"]:
        history(item, actor, "state", **{"from": item["state"], "to": state})
        item["state"], item["state_since"] = state, iso(now())
        if state not in CLOSED:
            item.pop("cancel_proof", None)


def new_item(data, *, description, kind="request", owner="unassigned", message=None, session=None, actor="main",
             next_step="", tickets=(), branch="", prs=()):
    if kind not in KINDS:
        raise WAError("kind must be one of " + ", ".join(KINDS))
    item = {"id": next_id(data, "i"), "description": prov.clip(redact(description), 400), "kind": kind, "owner": owner,
            "message": message, "session": session, "state": "assigned" if owner not in NO_OWNER else "open",
            "state_since": iso(now()), "last_checked": iso(now()), "created": iso(now()), "next_step": prov.clip(redact(next_step), 300),
            "links": {"branch": branch, "tickets": list(tickets), "prs": list(prs)}, "evidence": [], "history": []}
    history(item, actor, "created", owner=owner)
    data["items"][item["id"]] = item
    return item


def cmd_split(args):
    with transaction() as data:
        msg = find_message(data, args.msg)
        if msg["triage"] == "no-ask":
            raise WAError("message was marked no-ask; it cannot also have items")
        made = [new_item(data, description=text, kind=args.kind, owner=args.owner, message=msg["id"], session=msg["session"],
                         actor=args.actor, next_step=args.next or "", tickets=args.ticket or (), branch=args.branch or "")
                for text in args.item]
        msg["triage"] = "split"
        msg["items"] += [i["id"] for i in made]
        audit_line("split", message=msg["id"], items=[i["id"] for i in made], actor=args.actor)
    print("created " + ", ".join(i["id"] for i in made))


def cmd_no_ask(args):
    if len(args.reason.strip()) < 10:
        raise WAError("--reason needs at least 10 characters")
    with transaction() as data:
        msg = find_message(data, args.msg)
        if msg["items"]:
            raise WAError("message already has items")
        msg.update(triage="no-ask", reason=prov.clip(redact(args.reason), 300), triaged_at=iso(now()), triaged_by=args.actor)
        audit_line("no-ask", message=msg["id"], actor=args.actor, reason=msg["reason"])
    print(f"{msg['id']} marked no-ask")


def cmd_update(args):
    with transaction() as data:
        item = find_item(data, args.id)
        if args.state == "cancelled":
            raise WAError("use `cancel` with user proof to cancel an item")
        for text in args.evidence or ():
            item["evidence"].append(parse_evidence(text, args.repo))
            history(item, args.actor, "evidence", ref=item["evidence"][-1]["ref"])
        if args.state == "done" and not item["evidence"]:
            raise WAError("done requires evidence (--evidence commit sha, PR#n, https URL or tested:<WAL id>)")
        if args.state:
            if args.state not in STATES:
                raise WAError("state must be one of " + ", ".join(STATES))
            set_state(item, args.state, args.actor)
        if args.owner is not None:
            history(item, args.actor, "owner", **{"from": item["owner"], "to": args.owner})
            item["owner"] = args.owner
            if item["state"] == "open" and args.owner not in NO_OWNER:
                set_state(item, "assigned", args.actor)
        if args.next is not None:
            item["next_step"] = prov.clip(redact(args.next), 300)
        if args.description:
            item["description"] = prov.clip(redact(args.description), 400)
        if args.branch:
            item["links"]["branch"] = args.branch
        for ticket in args.ticket or ():
            if ticket not in item["links"]["tickets"]:
                item["links"]["tickets"].append(ticket)
        if args.note:
            history(item, args.actor, "note", text=prov.clip(redact(args.note), 300))
        item["last_checked"] = iso(now())
        audit_line("update", item=item["id"], actor=args.actor, state=item["state"], owner=item["owner"])
    print(f"{item['id']} {item['state']} owner={item['owner']}")


def cmd_cancel(args):
    proof = verify_proof(args.file, args.line, args.uuid, args.quote)
    with transaction() as data:
        item = find_item(data, args.id)
        sync_all(data)
        bound_proof(data, item, proof)
        set_state(item, "cancelled", args.actor)
        item["cancel_proof"] = proof
        item["last_checked"] = iso(now())
        history(item, args.actor, "cancel", uuid=args.uuid, line=args.line)
        audit_line("cancel", item=item["id"], actor=args.actor, proof=proof)
    print(f"{item['id']} cancelled (proof verified; removable after 24h)")


def drop(data, item, why):
    audit_line("remove", item=item, why=why)
    del data["items"][item["id"]]
    msg = data["messages"].get(item.get("message"))
    if msg:
        msg["items"] = [i for i in msg["items"] if i != item["id"]]


def cmd_remove(args):
    with transaction() as data:
        item = find_item(data, args.id)
        ok, why = eligible(item, now(), data)
        if not ok:
            raise WAError(f"refused: {why}")
        drop(data, item, why)
    print(f"{args.id} removed ({why})")


def cmd_prune(args):
    ts, removed, kept = now(), [], 0
    with transaction() as data:
        for item in list(data["items"].values()):
            ok, why = eligible(item, ts, data)
            if ok and args.apply:
                drop(data, item, why)
                removed.append(item["id"])
            elif ok:
                removed.append(item["id"] + " (dry run)")
            else:
                kept += 1
        if args.apply:
            for m in list(data["messages"].values()):
                done_noask = m["triage"] == "no-ask" and ts - parse_ts(m.get("triaged_at")) > GATE_SECONDS
                if done_noask or (m["triage"] == "split" and not m["items"]):
                    audit_line("remove-message", message=m["id"], triage=m["triage"], reason=m.get("reason"))
                    if m.get("uuid"):  # a removed message must not be re-caught from the transcript
                        data.setdefault("tombstones", []).append(m["uuid"])
                        data["tombstones"] = data["tombstones"][-20000:]
                    del data["messages"][m["id"]]
    print(f"{'removed' if args.apply else 'would remove'} {len(removed)}: {', '.join(removed[:20])}; kept {kept}")


def cmd_status(args):
    policy = load_policy()
    with locked():
        data, _ = read_store()
    if args.json:
        print(json.dumps({"messages": data["messages"], "items": data["items"]}, indent=1, sort_keys=True))
        return
    print(digest(data, policy, args.session, limit=args.limit))
    fails = pending_failures()
    if fails:
        print(f"CAPTURE FAILURES: {len(fails)} unacknowledged (work_assignments.py failures)")
    chain = verify_audit()
    if chain:
        print("AUDIT LOG PROBLEM: " + "; ".join(chain))


def cmd_show(args):
    with locked():
        data, _ = read_store()
    print(json.dumps(data["items"].get(args.id) or find_message(data, args.id), indent=1, sort_keys=True))


def cmd_sync(args):
    with transaction() as data:
        changed = sync_all(data, args.session)
    print(f"sync: {changed} change(s)")


def cmd_failures(args):
    fails = pending_failures()
    for f in fails:
        print(f"{f['ts']} {f['event']}: {f['error']}")
    if args.ack and fails:
        with locked():
            path, stamp = files()["fail"], time.strftime("%Y%m%dT%H%M%S", time.gmtime(now()))
            os.replace(path, path.with_name(f"work-assignments.failures.acked-{stamp}.jsonl"))
            audit_line("failures-acked", count=len(fails))
        print(f"acknowledged {len(fails)} (kept as acked file)")
    if not fails:
        print("no unacknowledged failures")


def cmd_recover(args):
    with locked():
        raw = prov.read_small(files()["bak"], MAX_STORE_BYTES)
        data = json.loads(raw)
        if data.get("schema") != SCHEMA:
            raise WAError("backup is not a schema 1 store")
        write_private(files()["store"], raw)
        audit_line("recover", from_backup=True)
    print("restored from backup")


def cmd_verify(args):
    problems = verify_audit()
    print("audit chain ok" if not problems else "audit chain BROKEN: " + "; ".join(problems))
    return 1 if problems else 0


LEDGER_STATES = {"SHIPPED": "done", "ANSWERED": "done", "SUPERSEDED": "cancelled", "STALLED": "blocked",
                 "IN_PROGRESS": "in_progress", "READY": "ready", "UNKNOWN": "open"}


def cmd_import(args):
    path = Path(args.file)
    rows = [json.loads(line) for line in prov.read_small(path, 64 << 20).decode("utf-8").splitlines() if line.strip()]
    added = skipped = 0
    with transaction() as data:
        have = {i.get("source_id") for i in data["items"].values()}
        for row in rows:
            source_id = "ledger:" + str(row.get("id"))
            if source_id in have:
                skipped += 1
                continue
            state = LEDGER_STATES.get(str(row.get("status")).upper(), "open")
            no_owner = str(row.get("status")).upper() in ("STALLED", "UNKNOWN")
            kind = row.get("kind") if row.get("kind") in KINDS else "request"
            item = new_item(data, description=str(row.get("ask") or row.get("id")), kind=kind,
                            owner="unassigned" if no_owner else "main", session="import", actor="import",
                            next_step=str(row.get("next") or ""))
            item["source_id"], item["imported"] = source_id, {"when": row.get("when"), "ledger_status": row.get("status"),
                                                              "excerpt": prov.clip(row.get("excerpt") or "", 300)}
            if row.get("evidence"):
                item["evidence"].append({"kind": "imported", "ref": prov.clip(redact(row["evidence"]), 400), "at": iso(now())})
            if state == "done" and not item["evidence"]:
                state = "ready"
            if state == "cancelled":
                item["owner"] = "none"
            if state != item["state"]:
                set_state(item, state, "import")
            added += 1
        audit_line("import", added=added, skipped=skipped, source=path.name)
    print(f"imported {added}, skipped {skipped} already present")


def build_parser():
    p = argparse.ArgumentParser(prog="work_assignments.py", description=__doc__.split("\n\n")[0])
    sub = p.add_subparsers(dest="cmd", required=True)
    hook = sub.add_parser("hook", help="run a hook (payload on stdin)")
    hook.add_argument("name", choices=sorted(HOOKS))
    hook.add_argument("--runtime", choices=("claude", "codex"), default="claude")
    s = sub.add_parser("status"); s.add_argument("--session"); s.add_argument("--json", action="store_true"); s.add_argument("--limit", type=int, default=400)
    s = sub.add_parser("split"); s.add_argument("--msg", required=True); s.add_argument("--item", action="append", required=True)
    s.add_argument("--kind", default="request"); s.add_argument("--owner", default="unassigned"); s.add_argument("--next")
    s.add_argument("--ticket", action="append"); s.add_argument("--branch"); s.add_argument("--actor", default="main")
    s = sub.add_parser("no-ask"); s.add_argument("--msg", required=True); s.add_argument("--reason", required=True); s.add_argument("--actor", default="main")
    s = sub.add_parser("update"); s.add_argument("id"); s.add_argument("--state"); s.add_argument("--owner"); s.add_argument("--next")
    s.add_argument("--evidence", action="append"); s.add_argument("--branch"); s.add_argument("--ticket", action="append")
    s.add_argument("--description"); s.add_argument("--note"); s.add_argument("--repo"); s.add_argument("--actor", default="main")
    s = sub.add_parser("cancel"); s.add_argument("id"); s.add_argument("--uuid", required=True); s.add_argument("--file", required=True)
    s.add_argument("--line", type=int, required=True); s.add_argument("--quote", required=True); s.add_argument("--actor", default="main")
    s = sub.add_parser("remove"); s.add_argument("id")
    s = sub.add_parser("prune"); s.add_argument("--apply", action="store_true")
    s = sub.add_parser("import"); s.add_argument("file")
    s = sub.add_parser("sync"); s.add_argument("--session")
    s = sub.add_parser("failures"); s.add_argument("--ack", action="store_true")
    s = sub.add_parser("show"); s.add_argument("id")
    sub.add_parser("recover"); sub.add_parser("verify")
    return p


COMMANDS = {"status": cmd_status, "split": cmd_split, "no-ask": cmd_no_ask, "update": cmd_update, "cancel": cmd_cancel,
            "remove": cmd_remove, "prune": cmd_prune, "import": cmd_import, "sync": cmd_sync, "failures": cmd_failures,
            "show": cmd_show, "recover": cmd_recover, "verify": cmd_verify}


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if args.cmd == "hook":
        return run_hook(args.name, args.runtime)
    try:
        return COMMANDS[args.cmd](args) or 0
    except (WAError, prov.Problem, OSError, ValueError) as error:
        print(f"work_assignments: {getattr(error, 'message', error)}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
