#!/usr/bin/env python3
"""ah: deterministic lookups and writes against the agent harness history, files and tickets.

Reads are local and read-only, JSON by default (--text for a summary). ah is the only writer of harness
state: each write takes the store flock, validates, checks its idempotency key, then appends to an
append-only ledger plus audit log. Comments GoodQA cannot take now go to a spool (`ah spool drain`).

Slice 1 commands: owners, user-msg, ticket get|comments|comment, disk, task register|status|done, write result, spool drain.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import platform
import re
import socket
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import liveness  # noqa: E402

SECRET_NAMES = re.compile(r"(\.secret$|^\.env(\..*)?$|^member\.key$|^credentials(\..*)?$|\.pem$|^id_(rsa|ed25519|ecdsa)$)", re.I)
SESSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
TICKET_RE = re.compile(r"^GoodQA\s+(?:([a-z0-9][a-z0-9-]{0,62})\s*)?#([1-9]\d{0,9})$")
KEY_RE = re.compile(r"^[A-Za-z0-9._:-]{8,128}$")
ASK_ID_RE = re.compile(r"^w[0-9a-f]{11}$")
OWNER_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
TASK_WAL_WINDOW_S = 48 * 3600  # a task-named WAL untouched this long is history (ahd owner_window_seconds)
WRAPPER = re.compile(r"^\s*<[A-Za-z][\w-]*[\s>/]")
MAX_REQUEST = 256 * 1024
SKIP_DARWIN = ("Library", "Desktop", "Documents", "Downloads", "Pictures", "Movies", "Music", "Applications")


class AhError(Exception):
    def __init__(self, code, message, exit_code=2):
        super().__init__(message)
        self.code, self.exit_code = code, exit_code


def env_session() -> str:
    """The calling agent's session id: CLAUDE_CODE_SESSION_ID (set in agent shells) first, then CLAUDE_SESSION_ID."""
    return os.environ.get("CLAUDE_CODE_SESSION_ID") or os.environ.get("CLAUDE_SESSION_ID") or ""


def _bounded(path, limit: int = 64 << 20) -> bytes:
    """Whole small file, or InputRejected: regular files only, never more than limit bytes (safe_input)."""
    import safe_input
    try:
        return safe_input.read_bounded(str(path), limit)
    except safe_input.InputRejected as e:  # callers already treat OSError as "missing or unusable"
        raise OSError(e.code) from None


def home_dir() -> Path:
    return Path(os.environ.get("AH_HOME") or Path.home())


def is_secret_path(path) -> bool:
    return bool(SECRET_NAMES.search(Path(path).name))


def iso(ts):
    return dt.datetime.fromtimestamp(ts, dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if ts else None


def parse_ts(value):
    if not isinstance(value, str):
        return 0.0
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return 0.0
    if parsed.tzinfo is None:  # a naive ISO time is UTC, never the reader's local zone
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.timestamp()


def state_dir(home: Path, *parts) -> Path:
    path = home / ".agent-harness" / "state" / Path(*parts) if parts else home / ".agent-harness" / "state"
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    return path


def atomic_json(path: Path, data) -> None:
    tmp = path.with_name(path.name + f".{os.getpid()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as handle:
        json.dump(data, handle)
    os.replace(tmp, path)


# ------------------------------------------------------------------ incremental line index

def read_new_lines(path: Path, meta: dict):
    """(iterator of (offset, line), rebuilt) over complete lines appended since meta['offset'].

    Reads in bounded chunks, so memory stays flat for any file size. meta (inode, offset, tail = sha256 of the
    up-to-64 bytes before offset) is cleared when the file was replaced or truncated and advanced once the
    iterator is exhausted. A partial last line is left for the next call.
    """
    st = path.stat()
    rebuilt = False
    offset = meta.get("offset", 0)
    if offset:
        fd = os.open(path, os.O_RDONLY)
        try:
            ok = meta.get("inode") == st.st_ino and st.st_size >= offset
            if ok:
                n = min(64, offset)
                ok = hashlib.sha256(os.pread(fd, n, offset - n)).hexdigest() == meta.get("tail")
        finally:
            os.close(fd)
        if not ok:
            meta.clear()
            offset, rebuilt = 0, True

    def gen():
        fd = os.open(path, os.O_RDONLY)
        try:
            pos, carry, carry_off = offset, b"", offset
            while True:
                chunk = os.pread(fd, 4 << 20, pos)
                if not chunk:
                    break
                pos += len(chunk)
                data = carry + chunk
                start = 0
                while True:
                    nl = data.find(b"\n", start)
                    if nl < 0:
                        break
                    yield carry_off + start, data[start:nl]
                    start = nl + 1
                carry, carry_off = data[start:], carry_off + start
            n = min(64, carry_off)
            meta.update(inode=st.st_ino, offset=carry_off,
                        tail=hashlib.sha256(os.pread(fd, n, carry_off - n)).hexdigest() if n else "")
        finally:
            os.close(fd)
    return gen(), rebuilt


# ------------------------------------------------------------------ owners

TICKET_IN_NOTE = re.compile(r"GoodQA\s+(?:[a-z0-9-]+\s*)?#\d{1,10}|\bgoodqa#\d{1,10}", re.I)


def wal_dirs(home: Path):
    return home / ".claude" / "wals"


def newest_session(home: Path):
    root = wal_dirs(home)
    best, stamp = None, -1.0
    try:
        for entry in os.scandir(root):
            main = Path(entry.path) / "main.jsonl"
            if main.is_file() and main.stat().st_mtime > stamp:
                best, stamp = entry.name, main.stat().st_mtime
    except OSError:
        pass
    return best


def summarize_agent_wal(path: Path, index_dir: Path) -> dict:
    own = path.name[len("agent-"):-len(".jsonl")] if path.name.startswith("agent-") else path.name[:-len(".jsonl")]
    cache = index_dir / ("wal-" + hashlib.sha256(str(path).encode()).hexdigest()[:16] + ".json")
    try:
        summary = json.loads(_bounded(cache))
    except (OSError, ValueError):
        summary = {}
    if summary.get("schema", 1) > SCHEMA:
        raise AhError("schema_newer", "index written by a newer ah; update this install", 4)
    summary["schema"] = SCHEMA
    meta = summary.setdefault("meta", {})
    lines, rebuilt = read_new_lines(path, meta)
    if rebuilt or "first" not in summary:
        summary.update(first=None, last_at=0.0, outcome=None, last_note="", tickets=[], events=0)
    for _off, raw in lines:
        try:
            rec = json.loads(raw)
        except ValueError:
            continue
        if not isinstance(rec, dict):
            continue
        at = parse_ts(rec.get("at"))
        if not rec.get("by") or rec.get("by") == own:  # a record another actor wrote on this owner's behalf is not its activity (review H2)
            summary["last_at"] = max(summary["last_at"], at)
        summary["events"] += 1
        event, note = rec.get("event"), rec.get("note") if isinstance(rec.get("note"), str) else ""
        if event == "intent":
            summary["outcome"] = None  # new work after an earlier result/handoff: not finished
            if summary["first"] is None and note:
                summary["first"] = note[:160]
        if event in ("handoff", "result"):
            summary["outcome"] = event
        if event in ("handoff", "result", "status", "blocker", "decision") and note:
            summary["last_note"] = note[:300]
        for match in TICKET_IN_NOTE.findall(note):
            if match not in summary["tickets"] and len(summary["tickets"]) < 8:
                summary["tickets"].append(match)
    atomic_json(cache, summary)
    return summary


def transcript_mtime(home: Path, session: str, agent: str) -> float:
    base = home / ".claude" / "projects"
    best = 0.0
    try:
        for proj in os.scandir(base):
            cand = Path(proj.path) / session / "subagents" / f"agent-{agent}.jsonl"
            try:
                best = max(best, cand.stat().st_mtime)
            except OSError:
                pass
    except OSError:
        pass
    return best


RESTRICTED = re.compile(r"\b(solve|interview)", re.I)  # fail-closed: show liveness only, never the task text


def discover_agents(home: Path, session: str, wal: Path) -> dict:
    """agent id -> {type, description, parent, finished, tmtime} from the two sources that exist for every
    sub-agent (the main WAL only lists the few types whose spawn is hooked): task WALs and transcript meta files."""
    found = {}
    try:
        with os.scandir(wal) as it:
            for e in it:
                if e.name.startswith("agent-") and e.name.endswith(".jsonl"):
                    found.setdefault(e.name[6:-6], {})
    except OSError:
        pass
    try:
        with os.scandir(home / ".claude" / "projects") as projects:
            for proj in projects:
                sub_dir = Path(proj.path) / session / "subagents"
                try:
                    with os.scandir(sub_dir) as it:
                        for e in it:
                            if not (e.name.startswith("agent-") and e.name.endswith(".meta.json")):
                                continue
                            agent = e.name[6:-10]
                            info = found.setdefault(agent, {})
                            try:  # the meta file only: transcript content is never read here
                                if e.stat().st_size <= 65536:
                                    meta = json.loads(_bounded(Path(e.path), 65536))
                                    info.update(type=meta.get("agentType"), description=meta.get("description"),
                                                parent=meta.get("parentAgentId"), finished=bool(meta.get("finished")))
                            except (OSError, ValueError):
                                pass
                except OSError:
                    continue
    except OSError:
        pass
    return found


def owners(home: Path, session: str, now: float | None = None, comments=None) -> dict:
    now = time.time() if now is None else now
    wal = wal_dirs(home) / session
    main = wal / "main.jsonl"
    if not main.is_file():
        raise AhError("session_unknown", f"no main WAL for session {session!r}")
    index_dir = state_dir(home, "ah-index")
    spawned, stopped, named, stop_at = {}, set(), [], {}
    with open(main, "rb") as handle:
        for raw in handle:
            try:
                rec = json.loads(raw)
            except ValueError:
                continue
            if isinstance(rec, dict) and rec.get("event") in ("scope", "intent", "decision") \
                    and isinstance(rec.get("note"), str):
                named.append(rec["note"])
            if not isinstance(rec, dict) or not isinstance(rec.get("agent_id"), str):
                continue
            if rec.get("event") == "subagent":
                spawned.setdefault(rec["agent_id"], {"type": rec.get("agent_type"), "at": parse_ts(rec.get("at"))})
            elif rec.get("event") == "subagent_stop":
                stopped.add(rec["agent_id"])
                stop_at[rec["agent_id"]] = parse_ts(rec.get("at"))
    for agent, meta in discover_agents(home, session, wal).items():
        info = spawned.setdefault(agent, {"type": None, "at": 0.0})
        info["type"] = info["type"] or meta.get("type")
        info.update({k: meta[k] for k in ("description", "parent", "finished") if k in meta})
    registered = {r["args"].get("owner_agent") for r in _ledger(home) if r.get("op") == "task.register"}
    pending = pending_stops(home, session)
    named_text = "\n".join(named)
    rows = []
    for agent, info in spawned.items():
        path = wal / f"agent-{agent}.jsonl"
        summary = summarize_agent_wal(path, index_dir) if path.is_file() else {
            "first": None, "last_at": 0.0, "outcome": None, "last_note": "", "tickets": []}
        last_wal = max(summary["last_at"], 0.0) or info["at"]
        tmtime = transcript_mtime(home, session, agent)
        if info.get("finished") and agent not in stopped:  # transcript meta says it ended; hook never saw the stop
            stopped.add(agent)
            stop_at[agent] = max(tmtime, last_wal)
        is_stopped = agent in stopped and max(last_wal, tmtime) <= stop_at.get(agent, 0.0) + 10
        by_name = info["type"] in liveness.NAMEABLE_TYPES and agent in named_text
        is_owner = agent in registered or info["type"] in liveness.OWNER_TYPES or by_name
        grace = 0.0 if pending.get(agent, 0.0) >= max(last_wal, tmtime) - 10 else None  # I7: no finishing grace (10 s, as is_stopped)
        verdict = liveness.classify(now, last_wal, tmtime, is_stopped,
                                    summary["outcome"], summary["last_note"], info["type"],
                                    agent in registered, owner=is_owner, finish_grace=grace)
        idle = verdict["idle_s"]
        text = " ".join(filter(None, [info.get("description"), summary["first"]]))
        restricted = bool(RESTRICTED.search(text))
        row = {"agent_id": agent, "type": info["type"], "task": None if restricted else (summary["first"] or info.get("description")),
               "restricted": restricted, "parent": info.get("parent"),
               "owner": bool(is_owner), "registered": agent in registered,
               "flags": (["unregistered-owner"] if is_owner and agent not in registered else []),
               "state": verdict["state"], "severity": verdict["severity"],
               "last_activity": iso(last_wal), "idle_s": None if idle == float("inf") else int(idle),
               "ticket": summary["tickets"][0] if summary["tickets"] else None,
               "ticket_comment_age_s": None}
        if comments and row["ticket"]:
            row["ticket_comment_age_s"] = comments(row["ticket"], now)
        rows.append(row)
    for f in sorted(wal.glob("*.jsonl")):  # I8: task-named WALs are owners too, with no process behind them
        name = f.name[:-len(".jsonl")]
        if name == "main" or name.startswith("agent-") or not OWNER_ID_RE.match(name):
            continue
        try:
            if now - f.stat().st_mtime > TASK_WAL_WINDOW_S:
                continue  # history, not an owner (same window ahd uses for sessions)
        except OSError:
            continue
        summary = summarize_agent_wal(f, index_dir)
        verdict = liveness.classify_task_wal(now, summary["last_at"], summary["outcome"], summary["last_note"])
        idle = verdict["idle_s"]
        text = summary["first"] or ""
        restricted = bool(RESTRICTED.search(text))
        rows.append({"agent_id": name, "type": "task-wal", "task": None if restricted else text, "restricted": restricted,
                     "parent": None, "owner": True, "registered": name in registered, "flags": ["task-wal"],
                     "state": verdict["state"], "severity": verdict["severity"],
                     "last_activity": iso(summary["last_at"]), "idle_s": None if idle == float("inf") else int(idle),
                     "ticket": summary["tickets"][0] if summary["tickets"] else None, "ticket_comment_age_s": None})
    disp = dispositions(home, session)
    live_ids = {r["agent_id"] for r in rows if r["state"] not in ("DROPPED", "done", "handoff", "returned")}
    for r in rows:
        d = disp.get(r["agent_id"])
        last_wal = parse_ts(r["last_activity"]) or 0.0
        alive = liveness.disposition_live(d, now, last_activity=last_wal,
                                          replacement_live=bool(d and d.get("ref") in live_ids))
        r["disposition"] = dict(d, live=alive) if d else None
        r["decision_required"] = bool(r["owner"] and r["state"] == "DROPPED" and not alive)
    # a wait on another agent holds only while that agent is live; a wait on a DROPPED, done or unknown agent is a drop
    states = {r["agent_id"]: r["state"] for r in rows}
    for r in rows:
        target = r["state"][len("waiting-on-"):] if r["state"].startswith("waiting-on-") else ""
        if r["owner"] and target and OWNER_ID_RE.match(target) and not ASK_ID_RE.match(target) and "#" not in target \
                and target != "main" and states.get(target, "absent") in ("DROPPED", "done", "handoff", "returned", "absent"):
            d = disp.get(r["agent_id"])
            if not liveness.disposition_live(d, now, last_activity=parse_ts(r["last_activity"]) or 0.0):
                r["decision_required"] = True
                r["flags"] = list(r.get("flags") or []) + [f"wait-target-{states.get(target, 'absent').lower()}"]
    rows.sort(key=lambda r: (r["state"] in ("done", "handoff"), -(r["idle_s"] or 0)))
    counts = {}
    for r in rows:
        counts[r["state"]] = counts.get(r["state"], 0) + 1
    return {"session": session, "generated": iso(now), "counts": counts, "owners": rows, "source": "direct",
            "undisposed": sorted(r["agent_id"] for r in rows if r["decision_required"])}


# ------------------------------------------------------------------ user-msg

def norm(text: str) -> str:
    return re.sub(r"\s+", " ", text or "").strip().lower()


def _prov():
    import provenance
    return provenance


def find_transcript(home: Path, session: str) -> Path:
    if not SESSION_RE.match(session):
        raise AhError("session_invalid", "session id has characters a transcript name cannot have")
    try:
        with os.scandir(home / ".claude" / "projects") as it:
            for proj in it:
                cand = Path(proj.path) / (session + ".jsonl")
                if cand.is_file():
                    return cand
    except OSError:
        pass
    raise AhError("transcript_missing", f"no transcript for session {session[:40]!r} on this host")


def newest_transcript_session(home: Path):
    best, stamp = None, -1.0
    try:
        for proj in os.scandir(home / ".claude" / "projects"):
            for f in os.scandir(proj.path):
                if f.name.endswith(".jsonl") and SESSION_RE.match(f.name[:-6]) and f.is_file() and f.stat().st_mtime > stamp:
                    best, stamp = f.name[:-6], f.stat().st_mtime
    except OSError:
        pass
    return best


def _blocks_text(content):
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        out = []
        for b in content:
            if isinstance(b, dict) and isinstance(b.get("text"), str):
                out.append(b["text"])
            elif isinstance(b, dict) and isinstance(b.get("content"), str):
                out.append(b["content"])
        return "\n".join(out)
    return ""


def index_transcript(home: Path, session: str) -> dict:
    """Incrementally index human turns, queued mid-turn messages and AskUserQuestion answers."""
    path = find_transcript(home, session)
    cache = state_dir(home, "ah-index", "transcripts") / (session + ".json")
    try:
        idx = json.loads(_bounded(cache))
    except (OSError, ValueError):
        idx = {}
    if idx.get("schema", 1) > SCHEMA:
        raise AhError("schema_newer", "index written by a newer ah; update this install", 4)
    idx["schema"] = SCHEMA
    meta = idx.setdefault("meta", {})
    lines, rebuilt = read_new_lines(path, meta)
    if rebuilt or "msgs" not in idx:
        idx.update(msgs=[], askq=[])
    askq = set(idx["askq"])
    prov = _prov()
    for off, raw in lines:
        if b'"type"' not in raw:
            continue
        try:
            rec = json.loads(raw)
        except ValueError:
            continue
        if not isinstance(rec, dict):
            continue
        kind = rec.get("type")
        if kind == "assistant":
            askq |= prov.askuser_use_ids(rec)
        elif kind == "user":
            body, _ = prov.user_authorship(rec)
            if body and body.strip():
                idx["msgs"].append(_msg("uuid", f"uuid:{session}/{rec.get('uuid')}", rec.get("timestamp"), body,
                                        "human-origin turn", off))
                continue
            answer = prov.answer_text(rec, askq)
            if answer is not None:
                idx["msgs"].append(_msg("answer", f"answer:{session}/{rec.get('uuid')}", rec.get("timestamp"),
                                        answer, prov.ANSWER_TRUST, off))
        elif kind == "queue-operation":
            content = prov.queue_user_text(rec)  # provenance.py owns the rule; wrappers are never user text
            if content is not None:
                digest = hashlib.sha256(content.encode()).hexdigest()[:12]
                idx["msgs"].append(_msg("queued", f"queue:{session}/{rec.get('timestamp')}#{digest}",
                                        rec.get("timestamp"), content, prov.QUEUE_TRUST, off))
    idx["askq"] = sorted(askq)
    atomic_json(cache, idx)
    return idx


def _line_at(fd: int, off: int, cap: int = 8 << 20) -> bytes:
    """The line starting at off, read in growing steps (a row costs its own line, not the rest of the file)."""
    out, step = b"", 1 << 16
    while len(out) < cap:
        chunk = os.pread(fd, step, off + len(out))
        if not chunk:
            break
        nl = chunk.find(b"\n")
        if nl >= 0:
            return out + chunk[:nl]
        out += chunk
        step = min(step * 2, 4 << 20)
    return out


def verify_rows(path: Path, rows: list) -> list:
    """Keep only rows whose text still matches the transcript line at their recorded offset (cache is untrusted)."""
    ok = []
    fd = os.open(path, os.O_RDONLY)
    try:
        for m in rows:
            off = m.get("off")
            if not isinstance(off, int) or off < 0 or m.get("kind") not in ("uuid", "queued", "answer"):
                continue
            try:
                rec = json.loads(_line_at(fd, off))
            except ValueError:
                continue
            if not isinstance(rec, dict):
                continue
            prov = _prov()
            if m["kind"] == "uuid":
                text, _ = prov.user_authorship(rec)
                good = text is not None and rec.get("uuid") == m["id"].split("/", 1)[1]
            elif m["kind"] == "queued":
                text = prov.queue_user_text(rec)
                good = text is not None and m["id"].endswith("#" + hashlib.sha256(text.encode()).hexdigest()[:12])
            else:
                text = _answer_values_cache(rec, path)
                good = text is not None and rec.get("uuid") == m["id"].split("/", 1)[1]
            if good and text[:8000] == m["text"]:
                ok.append(m)
    finally:
        os.close(fd)
    return ok


def _answer_values_cache(rec, path: Path):
    """Answer text of an AskUserQuestion result record; the tool_use binding is re-checked in the transcript."""
    blocks = (rec.get("message") or {}).get("content") if isinstance(rec, dict) else None
    if isinstance(blocks, list) and len(blocks) == 1 and isinstance(blocks[0], dict):
        prov = _prov()
        return prov.answer_text(rec, prov.askuser_bound(path, blocks[0].get("tool_use_id")))
    return None


def _msg(kind, ident, ts, text, trust, off=None):
    return {"id": ident, "kind": kind, "timestamp": ts, "trust": trust, "text": text[:8000], "chars": len(text),
            "off": off}


def user_msgs(home: Path, session: str, text=None, recent=None, full=False, limit=20) -> dict:
    idx = index_transcript(home, session)
    msgs = verify_rows(find_transcript(home, session), idx["msgs"])
    # A queued message that later became a human turn is the same message: point the queue id at the uuid id.
    human = [(m["id"], norm(m["text"])) for m in msgs if m["kind"] == "uuid"]
    seen, out = set(), []
    for m in msgs:
        if m["id"] in seen:
            continue
        seen.add(m["id"])
        row = dict(m)
        if m["kind"] == "queued":
            n = norm(m["text"])
            for uid, body in human:
                if n and n in body:
                    row["also"] = uid
                    break
        out.append(row)
    if text:
        wanted = norm(text)
        if len(wanted) < 6:
            raise AhError("text_short", "search text needs 6+ characters")
        out = [r for r in out if wanted in norm(r["text"])]
    elif recent:
        out = out[-int(recent):]
    else:
        raise AhError("bad_request", "give --text or --recent N")
    if not any(m["kind"] == "uuid" for m in msgs):
        # No human-origin turn: a `claude -p` helper session, whose prompt is agent text. Nothing here is a user.
        out = []
    out = out[-limit:]
    for r in out:
        r["preview"] = re.sub(r"\s+", " ", r["text"]).strip()[:120]
        if not full:
            del r["text"]
    return {"session": session, "matches": out, "source": "direct"}


# ------------------------------------------------------------------ tickets

def load_adapter(home: Path | None = None):
    import ticket_adapters
    import commit_policy  # overlay-aware: the shipped policy no longer carries the org id (GoodQA #14538)
    cfg = commit_policy.load_policy(Path(__file__).with_name("commit_policy.json"))["ticket_systems"]["goodqa"]
    if os.environ.get("AH_GOODQA_ENDPOINT"):  # loopback endpoints only (tests); the adapter enforces the scheme
        cfg = dict(cfg, endpoint=os.environ["AH_GOODQA_ENDPOINT"])
    if os.environ.get("AH_GOODQA_KEY_FILE"):
        cfg = dict(cfg, key_file=os.environ["AH_GOODQA_KEY_FILE"])
    return ticket_adapters.adapter_for(dict(cfg, max_comment_pages=1000, total_deadline_seconds=120)), ticket_adapters


def ticket_ref(value: str, project: str = "goodqa"):
    m = re.fullmatch(r"(?:GoodQA\s+(?:([a-z0-9-]+)\s*)?)?#?(\d{1,10})", value.strip())
    if not m:
        raise AhError("bad_request", "ticket must be N, #N or 'GoodQA <project>#N'")
    return (m.group(1) or project), int(m.group(2))


def ticket_issue(adapter, mod, project, number):
    try:
        ticket = adapter.lookup(project, number)
    except mod.TicketSystemUnavailable as e:
        raise AhError("ticket_unavailable", str(e), 3)
    if ticket is None:
        raise AhError("not_found", f"ticket {project}#{number} not found", 3)
    return ticket


def ticket_get(value: str, project: str = "goodqa") -> dict:
    adapter, mod = load_adapter()
    project, number = ticket_ref(value, project)
    ticket = ticket_issue(adapter, mod, project, number)
    issue = adapter.issue(ticket.id)
    return {"ticket": f"GoodQA {project}#{number}", "issue": issue, "truncated": False, "source": "goodqa"}


def ticket_comments(value: str, project: str = "goodqa", since=None, last=None) -> dict:
    """Every active comment, oldest first, paginated by cursor and never clipped."""
    adapter, mod = load_adapter()
    project, number = ticket_ref(value, project)
    ticket = ticket_issue(adapter, mod, project, number)
    try:
        items = adapter.all_comments(ticket.id, max_pages=1000)
    except mod.TicketSystemUnavailable as e:
        raise AhError("ticket_unavailable", str(e), 3)
    if since:
        floor = parse_ts(since)
        if not floor:
            raise AhError("bad_request", "--since must be an ISO timestamp")
        items = [c for c in items if parse_ts(c.get("createdAt")) >= floor]
    total = len(items)
    if last:
        items = items[-int(last):]
    return {"ticket": f"GoodQA {project}#{number}", "total": total, "returned": len(items),
            "comments": items, "truncated": False, "source": "goodqa"}


def comment_age(ref: str, now: float):
    try:
        adapter, mod = load_adapter()
        project, number = ticket_ref(ref)
        ticket = ticket_issue(adapter, mod, project, number)
        data = adapter.call("get_issue_comments", {"issueId": ticket.id, "order": "desc", "limit": 1})
        items = data.get("comments") or []
        return int(now - parse_ts(items[0].get("createdAt"))) if items else None
    except Exception:
        return None


# ------------------------------------------------------------------ disk

def _volume(path: str, label: str):
    try:
        st, vfs = os.stat(path), os.statvfs(path)
    except OSError:
        return None
    total = vfs.f_blocks * vfs.f_frsize
    used = (vfs.f_blocks - vfs.f_bfree) * vfs.f_frsize
    avail = vfs.f_bavail * vfs.f_frsize
    denom = used + avail
    return {"path": path, "role": label, "dev": st.st_dev, "total_bytes": total, "used_bytes": used,
            "avail_bytes": avail, "used_pct": round(100.0 * used / denom, 1) if denom else 0.0}


def volumes(system: str | None = None, extra=()) -> list:
    system = system or platform.system()
    cands = []
    if system == "Darwin":
        # "/" is the sealed read-only system snapshot: its usage says nothing about free space.
        cands = [("/System/Volumes/Data", "data"), ("/", "system-snapshot (read-only; ignore for capacity)")]
    else:
        cands = [("/", "data")] + [(p, "data") for p in ("/home", "/data", "/var") if os.path.ismount(p)]
    cands += [(p, "extra") for p in extra]
    out, seen = [], set()
    for path, label in cands:
        v = _volume(path, label)
        if not v:
            continue
        if v["dev"] in seen and not label.startswith("system"):
            continue
        seen.add(v["dev"])
        out.append(v)
    return out


def top_dirs(root: str, system: str, count: int = 10, budget_s: float = 20.0, runner=None) -> dict:
    runner = runner or subprocess.run
    skipped, targets = [], []
    try:
        names = sorted(os.listdir(root))
    except OSError as e:
        return {"root": root, "error": e.strerror, "entries": []}
    for name in names:
        full = os.path.join(root, name)
        if os.path.islink(full):
            continue
        if system == "Darwin" and root == str(Path.home()) and name in SKIP_DARWIN:
            skipped.append(name)
            continue
        if os.path.isdir(full):
            targets.append(full)
    deadline = time.monotonic() + budget_s
    entries, partial = [], False
    for t in targets:
        left = deadline - time.monotonic()
        if left <= 0:
            partial = True
            break
        try:
            r = runner(["du", "-sk", "-x", t], capture_output=True, text=True, timeout=min(left, 10.0))
            kib = int(r.stdout.split()[0]) if r.stdout.split() else None
        except (subprocess.TimeoutExpired, ValueError, OSError):
            partial = True
            entries.append({"path": t, "bytes": None, "timed_out": True})
            continue
        if kib is not None:
            entries.append({"path": t, "bytes": kib * 1024})
    entries.sort(key=lambda e: -1 if e["bytes"] is None else -e["bytes"])
    entries.sort(key=lambda e: 0 if e["bytes"] is None else 1)
    return {"root": root, "entries": entries[:count], "partial": partial, "skipped_protected": skipped}


def disk(host=None, root=None, count=10, budget_s=20.0, top=True) -> dict:
    if host:
        if not re.fullmatch(r"[A-Za-z0-9._][A-Za-z0-9._-]{0,99}", host):
            raise AhError("bad_request", "host has characters ssh targets cannot have")
        argv = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", "--", host,
                "python3 .claude/hooks/ah.py disk" + (" --no-top" if not top else f" --count {int(count)}")]
        try:
            r = subprocess.run(argv, capture_output=True, text=True, timeout=budget_s + 30)
            data = json.loads(r.stdout)
        except (subprocess.SubprocessError, ValueError, OSError):
            raise AhError("host_unreachable", f"could not read disk from {host}", 3)
        data["host"] = host
        return data
    system = platform.system()
    vols = volumes(system)
    data = {"host": socket.gethostname(), "os": system, "volumes": vols,
            "capacity_volume": next((v["path"] for v in vols if v["role"] == "data"), None)}
    if top:
        data["top"] = top_dirs(root or str(home_dir()), system, count, budget_s)
    return data


# ------------------------------------------------------------------ writes
# ah is the only writer: one flock per store, validate, idempotency key, append-only ledger + audit.
# Slow side effects (a GoodQA comment) that cannot complete go to a spool drained by the next ah call.

LOCK_TIMEOUT_S = 10.0
SCHEMA = 1  # on every ledger, audit, spool and index row; readers refuse a newer schema


def store_dir(home: Path) -> Path:
    return state_dir(home, "ah", "store")


def canonical(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def operation_id(key: str) -> str:
    """GoodQA requires a UUID operationId; a UUID derived from the key keeps re-posts idempotent."""
    import uuid
    return str(uuid.uuid5(uuid.NAMESPACE_URL, "ah-operation:" + key))


def derive_key(op: str, args: dict, session: str) -> str:
    return "ah:" + hashlib.sha256(canonical([op, args, session]).encode()).hexdigest()[:32]


def actor_id() -> str:
    return os.environ.get("AH_AGENT_ID") or os.environ.get("AGENT_ID") or "main"


def actor(session, host=None):
    return {"session": session or "", "agent_id": os.environ.get("AH_AGENT_ID", "main"),
            "host": host or socket.gethostname()}


def precheck(op: str, args: dict) -> None:
    def need(*names):
        for n in names:
            v = args.get(n)
            if not isinstance(v, str) or not v.strip():
                raise AhError("bad_request", f"{op}: {n} is required")
    if op == "task.register":
        need("task", "owner_agent", "session", "scope", "source")
        if not TICKET_RE.match(args.get("ticket") or ""):
            raise AhError("bad_request", "task.register: ticket must look like 'GoodQA <project>#<n>'")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,119}", args["session"]):
            raise AhError("bad_request", "task.register: session id is malformed")
        if not re.fullmatch(r"[A-Za-z0-9]{1,40}|main", args["owner_agent"]):
            raise AhError("bad_request", "task.register: owner_agent must be an agent id or 'main'")
    elif op == "task.status":
        need("task", "stage", "note")
        if args.get("ticket") and not TICKET_RE.match(args["ticket"]):
            raise AhError("bad_request", "task.status: ticket must look like 'GoodQA <project>#<n>'")
    elif op == "task.done":
        need("task")
        ev = args.get("evidence")
        if not isinstance(ev, list) or not ev:
            raise AhError("evidence", "task.done needs evidence: --really-tested ID --wal PATH or --commit SHA --repo PATH")
        for e in ev:
            ok = isinstance(e, dict) and (
                (isinstance(e.get("really_tested"), str) and e["really_tested"].strip() and e.get("wal")) or
                (re.fullmatch(r"[0-9a-f]{7,40}", str(e.get("commit", ""))) and e.get("repo")))
            if not ok:
                raise AhError("evidence", "each evidence item is {really_tested, wal} or {commit, repo}")
    elif op == "task.dispose":
        need("agent", "session", "kind", "at")
        if args["kind"] not in liveness.DISPOSITIONS:
            raise AhError("bad_request", f"task.dispose: kind must be one of {', '.join(liveness.DISPOSITIONS)}")
        if not OWNER_ID_RE.match(args["agent"]):
            raise AhError("bad_request", "task.dispose: agent must be an agent id or a task WAL name")
        if parse_ts(args["at"]) is None:
            raise AhError("bad_request", "task.dispose: at must be an ISO timestamp")
        if args["kind"] == "waiting":
            if parse_ts(args.get("until") or "") is None:
                raise AhError("bad_request", "task.dispose waiting: --until <ISO time> is required (when it expires)")
            ref = args.get("ref") or ""
            if not (ASK_ID_RE.match(ref) or TICKET_RE.match(ref)):
                raise AhError("bad_request", "task.dispose waiting: --ref must be an ask id (w + 11 hex) or 'GoodQA <project>#N'; "
                                             "a wait must name what it waits on")
        elif args["kind"] == "reassigned":
            if not OWNER_ID_RE.match(args.get("ref") or ""):
                raise AhError("bad_request", "task.dispose reassigned: --ref <replacement agent id> is required")
        elif args["kind"] == "closed":
            if len((args.get("reason") or "").strip()) < 8:
                raise AhError("bad_request", "task.dispose closed: --reason (8+ characters) is required")
            ev = args.get("evidence") or ""
            if not (TICKET_RE.match(ev) or ASK_ID_RE.match(ev) or re.fullmatch(r"[0-9a-f]{7,40}", ev)):
                raise AhError("bad_request", "task.dispose closed: --evidence must be a ticket, a WAL id or a commit sha")
    elif op == "task.pending":
        need("agent", "session", "at")
        if not OWNER_ID_RE.match(args["agent"]) or parse_ts(args["at"]) is None:
            raise AhError("bad_request", "task.pending: agent id and ISO at are required")
    elif op in ("alert.raise", "alert.clear"):
        need("alert_key", "source")
        if not ALERT_KEY_RE.match(args["alert_key"]) or not ALERT_SOURCE_RE.match(args["source"]):
            raise AhError("bad_request", f"{op}: alert_key is 1-200 characters, no spaces or control characters; source is "
                                         "lower-case [a-z0-9_.-], up to 32")
        if op == "alert.raise":
            need("message")
            if args.get("severity") not in ALERT_SEVERITIES:
                raise AhError("bad_request", f"alert.raise: severity is one of {', '.join(ALERT_SEVERITIES)}")
            if len(args["message"]) > 1000:
                raise AhError("bad_request", "alert.raise: message is at most 1000 characters")
            detail = args.get("detail", {})
            if not isinstance(detail, dict) or len(canonical(detail)) > 4096:
                raise AhError("bad_request", "alert.raise: detail is a JSON object of at most 4 KiB")
    elif op == "queue.add":
        need("item", "title", "session", "priority", "source")
        if not QUEUE_ITEM_RE.match(args["item"]):
            raise AhError("bad_request", "queue.add: item is 1-64 characters of [A-Za-z0-9._-]")
        if args["priority"] not in QUEUE_PRIORITIES:
            raise AhError("bad_request", f"queue.add: priority is one of {', '.join(QUEUE_PRIORITIES)}")
        if args.get("deadline") is not None and parse_ts(args["deadline"]) is None:
            raise AhError("bad_request", "queue.add: deadline must be an ISO time")
        if args.get("ticket") and not TICKET_RE.match(args["ticket"]):
            raise AhError("bad_request", "queue.add: ticket must look like 'GoodQA <project>#<n>'")
        blocked = args.get("blocked_by") or []
        if not isinstance(blocked, list) or len(blocked) > 20 or not all(isinstance(b, str) and QUEUE_ITEM_RE.match(b)
                                                                          for b in blocked):
            raise AhError("bad_request", "queue.add: blocked_by is a list of at most 20 item ids")
    elif op == "queue.rank":
        need("item", "before", "source")
        if args["item"] == args["before"]:
            raise AhError("bad_request", "queue.rank: an item cannot go before itself")
    elif op in ("queue.promote", "queue.resume"):
        need("item")
    elif op == "queue.pause":
        need("item", "agent", "resume_at", "reason")
        if parse_ts(args["resume_at"]) is None:
            raise AhError("bad_request", "queue.pause: resume_at must be an ISO time")
    elif op == "ticket.comment":
        need("body")
        if not TICKET_RE.match(args.get("ticket") or ""):
            raise AhError("bad_request", "ticket.comment: ticket must look like 'GoodQA <project>#<n>'")
    else:
        raise AhError("unknown_op", f"unknown op {op}")
    if len(canonical(args).encode()) > MAX_REQUEST:
        raise AhError("too_large", f"{op}: request exceeds {MAX_REQUEST} bytes")


class StoreLock:
    def __init__(self, home: Path, timeout: float = LOCK_TIMEOUT_S):
        self.path, self.timeout, self.fd = store_dir(home) / "store.lock", timeout, None

    def __enter__(self):
        import fcntl
        self.fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o600)
        deadline = time.monotonic() + self.timeout
        while True:
            try:
                fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                return self
            except OSError:
                if time.monotonic() >= deadline:
                    os.close(self.fd)
                    raise AhError("lock_timeout", "another ah write holds the store lock; retry with the same key", 3)
                time.sleep(0.05)

    def __exit__(self, *exc):
        os.close(self.fd)  # closing releases the flock


def _append_line(path: Path, record: dict) -> None:
    """One write() per line; a torn tail from a crash is closed with a newline first so it cannot swallow us."""
    record = dict(record, schema=SCHEMA)
    record["lsha"] = hashlib.sha256(canonical(record).encode()).hexdigest()[:16]
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_APPEND | os.O_NOFOLLOW, 0o600)
    try:
        size = os.fstat(fd).st_size
        prefix = b"\n" if size and os.pread(fd, 1, size - 1) != b"\n" else b""
        os.write(fd, prefix + (canonical(record) + "\n").encode())
        os.fsync(fd)
    finally:
        os.close(fd)


def _ledger(home: Path, include_intents: bool = False) -> list:
    """Applied rows (rows written before `state` existed count as applied); intents only on request."""
    path = store_dir(home) / "ledger.jsonl"
    out = []
    try:
        with open(path, "rb") as handle:
            for raw in handle:
                try:
                    row = json.loads(raw)
                except ValueError:
                    continue  # a torn line from a crash is ignored, never fatal
                if not isinstance(row, dict):
                    continue
                if row.get("schema", 1) > SCHEMA:
                    raise AhError("schema_newer", "the ledger was written by a newer ah; update this install", 4)
                if row.get("state", "applied") == "applied" or include_intents:
                    out.append(row)
    except OSError:
        pass
    return out


def _spool_comment(home: Path, job: dict) -> str:
    spool = store_dir(home) / "spool"
    spool.mkdir(exist_ok=True, mode=0o700)
    tag = hashlib.sha256(job["operation_id"].encode()).hexdigest()[:16]
    for existing in spool.glob(f"*-{tag}.json"):
        return existing.name
    name = f"{int(time.time() * 1000):013d}-{tag}.json"
    fd = os.open(spool / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, canonical(dict(job, schema=SCHEMA)).encode())
        os.fsync(fd)
    finally:
        os.close(fd)
    return name


def post_comment(ref: str, body: str, operation_id: str) -> None:
    import redact
    import uuid
    try:
        uuid.UUID(operation_id)
    except ValueError:  # jobs spooled by an earlier build carried a non-UUID id
        operation_id = str(uuid.uuid5(uuid.NAMESPACE_URL, "ah-operation:" + operation_id))
    adapter, mod = load_adapter()
    project, number = ticket_ref(ref)
    ticket = ticket_issue(adapter, mod, project, number)
    try:
        adapter.comment(ticket, redact.redact(body), operation_id)
    except mod.TicketSystemUnavailable as e:
        raise AhError("ticket_unavailable", str(e), 3)


def spool_drain(home: Path, only_opid: str | None = None, limit: int | None = None, budget_s: float | None = None) -> dict:
    """Post spooled comments. A transport failure keeps the job; a ticket that does not exist moves it to dead/.
    The GoodQA operationId makes a re-post after a crash harmless. One drainer at a time."""
    import fcntl
    spool = store_dir(home) / "spool"
    lockfd = os.open(store_dir(home) / "spool.lock", os.O_RDWR | os.O_CREAT, 0o600)
    try:
        try:
            fcntl.flock(lockfd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            return {"ok": True, "drained": 0, "pending": len(list(spool.glob("*.json"))), "busy": True}
        done, failed, dead = 0, 0, 0
        stop_at_ = time.monotonic() + budget_s if budget_s else None
        for n_, f in enumerate(sorted(spool.glob(f"*-{hashlib.sha256(only_opid.encode()).hexdigest()[:16]}.json" if only_opid else "*.json"))):
            if (limit is not None and n_ >= limit) or (stop_at_ and time.monotonic() > stop_at_):
                break
            try:
                job = json.loads(_bounded(f))
                post_comment(job["ticket"], job["body"], job["operation_id"])
            except AhError as e:
                if e.code == "not_found":
                    (spool / "dead").mkdir(exist_ok=True, mode=0o700)
                    os.replace(f, spool / "dead" / f.name)
                    dead += 1
                else:
                    failed += 1
                continue
            except (OSError, ValueError, KeyError):
                failed += 1
                continue
            f.unlink(missing_ok=True)
            done += 1
        if done or dead:
            _append_line(store_dir(home) / "audit.jsonl", {"at": iso(time.time()), "op": "spool.drain",
                                                           "result": "drained", "drained": done, "dead": dead})
        return {"ok": True, "drained": done, "pending": failed, "dead": dead}
    finally:
        os.close(lockfd)


def _wal_path(home: Path, session: str, agent: str) -> Path:
    return home / ".claude" / "wals" / session / ("main.jsonl" if agent == "main" else f"agent-{agent}.jsonl")


def _wal_append(home: Path, path: Path, record: dict) -> None:
    import wal
    try:  # a retry after a crash between this append and the ledger row must not duplicate the entry
        with open(path, "rb") as handle:
            handle.seek(0, 2)
            handle.seek(max(0, handle.tell() - 262144))
            if (b'"id":"%s"' % record["id"].encode()) in handle.read(262144):  # input-ok: tail window only
                return
    except OSError:
        pass
    old = os.environ.get("HOME")
    try:
        os.environ["HOME"] = str(home)  # wal.append pins ~/.claude/wals under HOME
        wal.append(path, record)
    finally:
        if old is not None:
            os.environ["HOME"] = old


def _task(ledger: list, name: str):
    reg = [r for r in ledger if r.get("op") == "task.register" and r["args"].get("task") == name]
    return reg[-1] if reg else None


def _evidence_ok(home: Path, ev: list, allowed: set, reg: dict) -> None:
    reg_ts = parse_ts(reg.get("received_at"))
    reg_args = reg["args"]
    root = (home / ".claude" / "wals").resolve()
    for e in ev:
        if "really_tested" in e:
            wid = e["really_tested"].strip()
            try:
                p = Path(e["wal"]).expanduser().resolve(strict=True)
            except OSError:
                raise AhError("evidence", f"WAL not found: {e['wal'][:80]}", 3)
            if root not in p.parents:
                raise AhError("evidence", "evidence WAL must be under ~/.claude/wals", 3)
            if p not in allowed:
                raise AhError("evidence", "evidence WAL must be this task's session or owner WAL", 3)
            found = False
            with open(p, "rb") as handle:
                for raw in handle:
                    try:
                        rec = json.loads(raw)
                    except ValueError:
                        continue
                    note = rec.get("note") if isinstance(rec, dict) and isinstance(rec.get("note"), str) else ""
                    # token-exact, and written after the task was registered (an old test proves nothing for this task)
                    if note.startswith(f"REALLY_TESTED {wid}:") and parse_ts(rec.get("at")) >= reg_ts:
                        found = True
                        break
            if not found:
                raise AhError("evidence", f"no REALLY_TESTED entry {wid} in that WAL", 3)
        else:
            repo = reg_args.get("worktree") or e["repo"]  # the registered checkout wins over a caller-chosen repo
            if reg_args.get("branch"):
                argv = ["git", "-C", repo, "merge-base", "--is-ancestor", e["commit"], reg_args["branch"]]
            else:
                argv = ["git", "-C", repo, "cat-file", "-e", e["commit"] + "^{commit}"]
            r = subprocess.run(argv, capture_output=True, timeout=20)
            if r.returncode != 0:
                raise AhError("evidence", f"commit {e['commit']} is not in the registered checkout/branch", 3)


def _apply(home: Path, op: str, args: dict, key: str, ledger: list) -> dict:
    """Validate and perform one op; returns the result fields. Called under the store lock."""
    opid = operation_id(key)
    wid = "w" + hashlib.sha256(key.encode()).hexdigest()[:11]
    now = dt.datetime.now(dt.timezone.utc).isoformat()
    out = {}

    def comment(ticket, body):
        # Queue only: the network call happens after the store lock is released (see write()).
        _spool_comment(home, {"ticket": ticket, "body": body, "operation_id": opid})
        out["comment"] = "pending"

    if op == "task.register":
        if _task(ledger, args["task"]):
            raise AhError("task_exists", f"task {args['task']!r} is already registered; ownership is not reassigned silently", 3)
        import provenance
        try:
            res = provenance.resolve(args["source"])
        except Exception as e:  # a resolver crash is a rejection, never a silent pass
            raise AhError("provenance", f"source check failed ({type(e).__name__})", 3)
        if not res["ok"]:
            first = res["problems"][0] if res["problems"] else {"code": "rejected", "message": "rejected"}
            raise AhError("provenance", f"source rejected ({first['code']}): {first['message']}"[:300], 3)
        rec = {"at": now, "event": "scope", "id": wid, "source": args["source"][:2000],
               "note": f"task {args['task']} registered: owner {args['owner_agent']}, {args['ticket']}; {args['scope']}"[:3900]}
        _wal_append(home, _wal_path(home, args["session"], "main"), rec)
        out["wal"] = wid
    elif op == "task.status":
        reg = _task(ledger, args["task"])
        if not reg:
            raise AhError("unknown_task", f"task {args['task']!r} is not registered (ah task register)", 3)
        r = reg["args"]
        rec = {"at": now, "event": "status", "id": wid, "by": actor_id(), "note": f"[{args['stage']}] {args['note']}"[:3900]}
        _wal_append(home, _wal_path(home, r["session"], r["owner_agent"]), rec)
        out["wal"] = wid
        comment(args.get("ticket") or r["ticket"], f"Task {args['task']} [{args['stage']}]: {args['note']}")
    elif op == "task.done":
        reg = _task(ledger, args["task"])
        if not reg:
            raise AhError("unknown_task", f"task {args['task']!r} is not registered", 3)
        allowed = {_wal_path(home, r_["session"], a_).resolve() for r_ in [reg["args"]] for a_ in ("main", r_["owner_agent"])}
        _evidence_ok(home, args["evidence"], allowed, reg)
        r = reg["args"]
        cites = "; ".join(e.get("really_tested") or e["commit"] for e in args["evidence"])
        rec = {"at": now, "event": "result", "id": wid, "by": actor_id(), "note": f"task {args['task']} done; evidence: {cites}"[:3900]}
        _wal_append(home, _wal_path(home, r["session"], r["owner_agent"]), rec)
        out["wal"] = wid
        comment(r["ticket"], rec["note"])
    elif op == "task.pending":
        wal = _wal_path(home, args["session"], args["agent"])
        if wal.is_file():  # the marker is written by the gate, never counted as the owner's activity
            _wal_append(home, wal, {"at": now, "event": "pending_stop", "id": wid, "by": "dropped_gate",
                                    "note": "stopped with pending work and no armed waiter (goodqa#14791 I7)"})
        out["wal"] = wid
    elif op in ("alert.raise", "alert.clear"):
        import ops_watch  # noqa: PLC0415 - installed beside ah; the ring's one writer implementation
        raising = op == "alert.raise"
        out["ring_seq"] = ops_watch.emit({
            "host": ring_host(), "source": args["source"], "event": "raise" if raising else "clear",
            "severity": args["severity"] if raising else "info", "key": args["alert_key"],
            "message": args["message"] if raising else "cleared", "detail": args.get("detail") or {}},
            path=home / ".agent-harness" / "state" / "alerts.jsonl")
    elif op in ("queue.add", "queue.rank", "queue.promote", "queue.pause", "queue.resume"):
        added = {r["args"]["item"] for r in ledger if r.get("op") == "queue.add"}
        if op in ("queue.add", "queue.rank"):
            import provenance  # every queued item and every re-rank is a requirement and carries a source that resolves
            try:
                res = provenance.resolve(args["source"])
            except Exception as e:  # a resolver crash is a rejection, never a silent pass
                raise AhError("provenance", f"source check failed ({type(e).__name__})", 3)
            if not res["ok"]:
                first = res["problems"][0] if res["problems"] else {"code": "rejected", "message": "rejected"}
                raise AhError("provenance", f"source rejected ({first['code']}): {first['message']}"[:300], 3)
        if op == "queue.add":
            if args["item"] in added:
                raise AhError("queue_exists", f"queue item {args['item']!r} already exists", 3)
            missing = [b for b in args.get("blocked_by") or [] if b not in added]
            if missing:
                raise AhError("bad_request", f"queue.add: blocked_by names unknown items: {', '.join(missing)}")
        else:
            for name in (args["item"], args.get("before")):
                if name is not None and name not in added:
                    raise AhError("bad_request", f"{op}: no queue item {name!r}")
    elif op == "ticket.comment":
        comment(args["ticket"], args["body"])
    elif op == "task.dispose":
        main_wal = _wal_path(home, args["session"], "main")
        if not main_wal.is_file():
            raise AhError("session_unknown", f"no main WAL for session {args['session']!r}", 3)
        ref = args.get("ref") or ""
        if args["kind"] == "waiting" and ASK_ID_RE.match(ref) and not _wal_has(main_wal, "ask", ref):
            raise AhError("bad_request", f"task.dispose waiting: ask {ref} is not in this session's WAL", 3)
        if args["kind"] == "reassigned" and not (_wal_has(main_wal, "subagent", None, agent=ref)
                                                or (main_wal.parent / f"{ref}.jsonl").is_file()):
            raise AhError("bad_request", f"task.dispose reassigned: {ref} is not an agent of this session", 3)
        ev = args.get("evidence") or ""
        if args["kind"] == "closed" and ASK_ID_RE.match(ev) and not (_wal_has(main_wal, None, ev) or
                _wal_has(_wal_path(home, args["session"], args["agent"]), None, ev)):
            raise AhError("evidence", f"task.dispose closed: WAL id {ev} is not in this session's WALs", 3)
        rec = {"at": now, "event": "disposition", "id": wid, "agent": args["agent"], "kind": args["kind"],
               "note": f"owner {args['agent']} {args['kind']}: {args.get('reason') or args.get('ref') or ''}"[:300]}
        for k in ("until", "ref", "reason", "evidence"):
            if args.get(k):
                rec[k] = args[k]
        _wal_append(home, main_wal, rec)
        out["wal"] = wid
    return out


def _wal_has(path: Path, event: str, ident, agent=None) -> bool:
    """True when the session WAL holds an entry of `event` with that id (or that agent_id)."""
    try:
        with open(path, "rb") as handle:
            for raw in handle:
                try:
                    rec = json.loads(raw)
                except ValueError:
                    continue
                if not isinstance(rec, dict) or (event is not None and rec.get("event") != event):
                    continue
                if (ident is not None and rec.get("id") == ident) or (agent is not None and rec.get("agent_id") == agent):
                    return True
    except OSError:
        return False
    return False


def pending_stops(home: Path, session: str) -> dict:
    """agent id -> epoch of the latest task.pending row (a stop with pending work, I7)."""
    out = {}
    for r in _ledger(home):
        a = r.get("args") or {}
        if r.get("op") == "task.pending" and a.get("session") == session:
            out[a["agent"]] = max(out.get(a["agent"], 0.0), parse_ts(a.get("at")) or 0.0)
    return out


def dispositions(home: Path, session: str) -> dict:
    """agent id -> latest applied disposition row for that session (from the ah ledger, the only writer)."""
    out = {}
    for r in _ledger(home):
        a = r.get("args") or {}
        if r.get("op") == "task.dispose" and a.get("session") == session:
            d = {"kind": a.get("kind"), "at": parse_ts(a.get("at")) or 0.0, "ref": a.get("ref"),
                 "reason": a.get("reason"), "evidence": a.get("evidence"), "seq": r.get("seq")}
            if a.get("until"):
                d["until"] = parse_ts(a["until"]) or 0.0
            if a["agent"] not in out or (d["seq"] or 0) >= (out[a["agent"]].get("seq") or 0):
                out[a["agent"]] = d
    return out


def _redact_args(obj, fn):
    if isinstance(obj, str):
        return fn(obj)
    if isinstance(obj, list):
        return [_redact_args(x, fn) for x in obj]
    if isinstance(obj, dict):
        return {k: _redact_args(v, fn) for k, v in obj.items()}
    return obj


def task_list(home: Path, open_only: bool = False) -> dict:
    """Fold the ledger into one row per task (the supported read path; nobody reads ledger.jsonl directly)."""
    tasks = {}
    for r in _ledger(home):
        a = r.get("args") or {}
        name = a.get("task")
        if not name:
            continue
        if r.get("op") == "task.register":
            tasks.setdefault(name, {"task": name, "owner_agent": a.get("owner_agent"), "session": a.get("session"),
                                    "ticket": a.get("ticket"), "scope": a.get("scope"), "state": "registered",
                                    "stage": None, "updated": r.get("received_at"), "seq": r.get("seq")})
        elif name in tasks and r.get("op") == "task.status":
            tasks[name].update(stage=a.get("stage"), note=a.get("note"), updated=r.get("received_at"))
        elif name in tasks and r.get("op") == "task.done":
            tasks[name].update(state="done", updated=r.get("received_at"))
    rows = [t for t in tasks.values() if not (open_only and t["state"] == "done")]
    return {"tasks": rows, "source": "direct"}


def write(home: Path, op: str, args: dict, session: str, key: str | None = None) -> dict:
    precheck(op, args)
    import redact
    if isinstance(args.get("source"), str):
        import wal_note
        if wal_note.SECRET_PATTERN.search(args["source"]):
            raise AhError("bad_request", "source appears to contain a credential; cite it without the secret", 2)
    args = {k: (v if k == "source" else _redact_args(v, redact.redact)) for k, v in args.items()}  # source is checked as typed
    key = key or derive_key(op, args, session)
    if not KEY_RE.match(key):
        raise AhError("bad_request", "idempotency key must be 8-128 chars of [A-Za-z0-9._:-]")
    body_sha = hashlib.sha256(canonical([op, args]).encode()).hexdigest()
    who = actor(session)
    audit = store_dir(home) / "audit.jsonl"
    with StoreLock(home):
        everything = _ledger(home, include_intents=True)
        ledger = [r for r in everything if r.get("state", "applied") == "applied"]
        intent = None
        for row in everything:
            if row.get("key") == key:
                if row.get("sha") != body_sha:
                    _append_line(audit, {"at": iso(time.time()), "op": op, "key": key, "actor": who,
                                         "result": "key_conflict"})
                    raise AhError("key_conflict", "that key was used with a different request", 3)
                if row.get("state", "applied") == "applied":
                    return {"ok": True, "result": "duplicate", "id": row["id"], "seq": row["seq"], "key": key}
                intent = row  # an earlier attempt died after its intent: resume, side effects are idempotent
        seq = intent["seq"] if intent else max([r.get("seq", 0) for r in everything if isinstance(r.get("seq"), int)] or [0]) + 1
        if not intent:  # write-ahead: the key is durable before any side effect
            _append_line(store_dir(home) / "ledger.jsonl", {"state": "intent", "key": key, "sha": body_sha, "seq": seq,
                                                            "intent_op": op, "at": iso(time.time())})
        try:
            out = _apply(home, op, args, key, ledger)
        except AhError as e:
            _append_line(audit, {"at": iso(time.time()), "op": op, "key": key, "actor": who,
                                 "result": "rejected", "code": e.code})
            raise
        except Exception as e:  # never an unaudited traceback
            _append_line(audit, {"at": iso(time.time()), "op": op, "key": key, "actor": who,
                                 "result": "rejected", "code": "internal"})
            raise AhError("internal", f"{type(e).__name__} while applying {op}", 3)
        rid = "ah" + hashlib.sha256(key.encode()).hexdigest()[:10]
        _append_line(store_dir(home) / "ledger.jsonl", {
            "state": "applied", "seq": seq, "id": rid, "key": key, "sha": body_sha, "op": op, "args": args, "actor": who,
            "received_at": iso(time.time())})
        _append_line(audit, {"at": iso(time.time()), "op": op, "key": key, "actor": who, "result": "applied", "seq": seq})
    reply = {"ok": True, "result": "applied", "id": rid, "seq": seq, "key": key}
    reply.update(out)
    if out.get("comment") == "pending":  # post now, outside the lock; on failure it stays spooled for the next drain
        opid = operation_id(key)
        spool_drain(home, only_opid=opid)  # only this write's job: other queued jobs never delay or colour this reply
        tag = hashlib.sha256(opid.encode()).hexdigest()[:16]
        spool = store_dir(home) / "spool"
        if list(spool.glob(f"*-{tag}.json")):
            reply["comment"] = "pending"
        elif list((spool / "dead").glob(f"*-{tag}.json")):
            reply["comment"] = "dead"  # the ticket does not exist; nothing was posted
        else:
            reply["comment"] = "posted"
        spool_drain(home, limit=2, budget_s=10.0)  # a little of the backlog, bounded; ahd drains the rest
    return reply


# ------------------------------------------------------------------ rendering and CLI

def fmt_age(s):
    if s is None:
        return "-"
    s = int(s)
    return f"{s // 3600}h{(s % 3600) // 60:02d}m" if s >= 3600 else f"{s // 60}m" if s >= 60 else f"{s}s"


def render_text(cmd: str, data: dict) -> str:
    if cmd == "owners":
        lines = [f"session {data['session']}  " + " ".join(f"{k}={v}" for k, v in sorted(data["counts"].items()))]
        for r in data["owners"]:
            lines.append(f"{r['state']:<14} idle {fmt_age(r['idle_s']):>7}  {r['agent_id'][:12]:<12} {r['type'] or '-':<12} "
                         f"{(r['ticket'] or '-'):<18} c-age {fmt_age(r['ticket_comment_age_s']):>6}  {(r['task'] or '')[:70]}")
        return "\n".join(lines)
    if cmd == "user-msg":
        return "\n".join(f"{m['id']}  [{m['kind']}] {m['timestamp']}  {m['preview']}" for m in data["matches"]) or "no match"
    if cmd == "disk":
        lines = [f"{data['host']} ({data.get('os', '?')}) capacity volume: {data.get('capacity_volume')}"]
        for v in data["volumes"]:
            lines.append(f"  {v['path']:<24} {v['used_pct']:>5}% used  {v['avail_bytes'] / 2**30:7.1f} GiB free  [{v['role']}]")
        for e in (data.get("top") or {}).get("entries", []):
            lines.append(f"    {(e['bytes'] or 0) / 2**30:8.2f} GiB  {e['path']}" + ("  (timed out)" if e.get("timed_out") else ""))
        return "\n".join(lines)
    return json.dumps(data, indent=2)


def doctor() -> dict:
    """Partial installs are the common failure: import every module ah needs and hash the files."""
    checks = []
    for name in ("liveness", "provenance", "safe_input", "redact", "wal", "wal_note", "ticket_adapters"):
        try:
            __import__(name)
            checks.append({"check": f"import {name}", "ok": True})
        except Exception as e:
            checks.append({"check": f"import {name}", "ok": False, "error": type(e).__name__})
    here = Path(__file__).resolve().parent
    for name in ("ah.py", "liveness.py", "provenance.py", "commit_policy.json"):
        f = here / name
        try:
            checks.append({"check": f"file {name}", "ok": True, "sha256": hashlib.sha256(_bounded(f, 16 << 20)).hexdigest()[:16]})
        except OSError:
            checks.append({"check": f"file {name}", "ok": False})
    running = ahd_running_check(home_dir())
    if os.environ.get("AH_EXPECT_AHD", "1") == "0":  # hosts without the daemon (and partial-install tests) only report it
        running = dict(running, ok=True, expected=False)
    checks.append(running)
    return {"ok": all(c["ok"] for c in checks), "checks": checks}


# ------------------------------------------------------------------ the verbs ahd calls (goodqa#14848)

ALERT_SEVERITIES = ("info", "warning", "high", "critical")  # ops_watch.SEVERITIES
ALERT_KEY_RE = re.compile(r"^[^\s\x00-\x1f\x7f]{1,200}$")  # ahd keys embed task names; no spaces or controls
ALERT_SOURCE_RE = re.compile(r"^[a-z][a-z0-9_.-]{0,31}$")
SERVICE_RE = re.compile(r"^[a-z][a-z0-9-]{1,31}$")
BATCH_MAX_BYTES = 1024 * 1024
BATCH_MAX_LINES = 500
BATCH_OPS = ("alert.raise", "alert.clear")  # apply is ahd's batching path for ring transitions, nothing else


def ring_host() -> str:
    """The host name ahd uses for its ring rows (ahd.host()); one definition so ring_state matches."""
    return socket.gethostname().split(".")[0]


def heartbeat(home: Path, service: str, key: str) -> dict:
    """Atomically replace ~/.agent-harness/state/<service>/heartbeat.json (the file `ah doctor` reads). A beat is
    state, not history: no ledger row, so a beat a minute never grows the ledger. A symlink at the target is
    replaced, never followed."""
    if not SERVICE_RE.match(service or ""):
        raise AhError("bad_request", "heartbeat: --service is lower-case [a-z0-9-], 2-32 characters")
    if not KEY_RE.match(key or ""):
        raise AhError("bad_request", "heartbeat: --key must be 8-128 chars of [A-Za-z0-9._:-]")
    d = home / ".agent-harness" / "state" / service
    for p in (home / ".agent-harness", home / ".agent-harness" / "state", d):
        if p.is_symlink():
            raise AhError("bad_request", f"heartbeat: {p} is a symlink; refusing to write through it", 3)
    d.mkdir(parents=True, exist_ok=True, mode=0o700)
    at = iso(time.time())
    data = (json.dumps({"service": service, "host": ring_host(), "at": at, "key": key}) + "\n").encode()
    tmp = d / f".heartbeat.{os.getpid()}.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, d / "heartbeat.json")
    return {"ok": True, "result": "beat", "service": service, "at": at}


def apply_batch(home: Path, text: str, session: str) -> dict:
    """`ah apply --batch -`: JSON lines {op, key, args}, alert ops only. Every line is validated before any is
    applied; then each goes through write() (its own key, ledger row and audit). A failure part way reports the
    results so far with ok false; ahd then resends one by one, and the applied keys come back as duplicates."""
    if len(text.encode()) > BATCH_MAX_BYTES:
        raise AhError("too_large", f"apply: a batch is at most {BATCH_MAX_BYTES} bytes")
    lines = [ln for ln in text.splitlines() if ln.strip()]
    if not lines or len(lines) > BATCH_MAX_LINES:
        raise AhError("bad_request", f"apply: 1 to {BATCH_MAX_LINES} lines")
    items = []
    for n, ln in enumerate(lines, 1):
        try:
            row = json.loads(ln)
        except ValueError:
            raise AhError("bad_request", f"apply: line {n} is not JSON")
        if not isinstance(row, dict) or row.get("op") not in BATCH_OPS or not isinstance(row.get("args"), dict) \
                or not KEY_RE.match(str(row.get("key") or "")):
            raise AhError("bad_request", f"apply: line {n} must be {{op: {'|'.join(BATCH_OPS)}, key, args}}")
        if any(r["key"] == row["key"] for r in items):
            raise AhError("bad_request", f"apply: line {n} repeats key {row['key']}")
        precheck(row["op"], row["args"])
        items.append(row)
    results = []
    for row in items:
        try:
            r = write(home, row["op"], row["args"], session, row["key"])
            results.append({"key": row["key"], "result": r.get("result"), "seq": r.get("seq")})
        except AhError as e:
            results.append({"key": row["key"], "result": "rejected", "code": e.code})
            return {"ok": False, "results": results}
    return {"ok": True, "results": results}


# ------------------------------------------------------------------ the work queue (NEVER-LOSE.md 9b, main WAL wf4ec9675ad6)

QUEUE_PRIORITIES = ("P0", "P1", "P2", "P3")
QUEUE_ITEM_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
QUEUE_DEFAULT_CAP = 4
QUEUE_TAIL_BYTES = 65536
QUEUE_PROMOTE_WARN_S = 15 * 60
QUEUE_PROMOTE_HIGH_S = 60 * 60
_OWNER_TO_QUEUE = {"live": "active", "quiet": "active", "finishing": "active", "SILENT": "active", "idle-helper": "active",
                   "done": "finished", "handoff": "finished", "returned": "finished",
                   "SILENT-HIGH": "stuck", "DROPPED": "stuck"}


def queue_cap(home: Path) -> int:
    """queue.max_active from ahd_policy.json beside this file (default 4)."""
    try:
        cap = int(json.loads(_bounded(Path(__file__).resolve().parent / "ahd_policy.json", 1 << 20))
                  .get("queue", {}).get("max_active", QUEUE_DEFAULT_CAP))
        return cap if 0 < cap <= 64 else QUEUE_DEFAULT_CAP
    except (OSError, ValueError, TypeError, AttributeError):
        return QUEUE_DEFAULT_CAP


def queue_view(home: Path, now: float) -> dict:
    """Fold the ledger into queue items with a derived state, ranked. State is never stored twice: it comes from
    the item's registered owner (`ah task register --task <item>`), its dispositions and the queue.* rows."""
    import work_queue  # noqa: PLC0415
    led = _ledger(home)
    items, order, promos, pauses, resumes, regs, done = {}, {}, {}, {}, {}, {}, set()
    for r in led:
        op, a = r.get("op"), r.get("args") or {}
        at = parse_ts(r.get("received_at")) or 0.0
        if op == "queue.add":
            items[a["item"]] = {"item": a["item"], "title": a.get("title"), "ticket": a.get("ticket"),
                                "session": a.get("session"), "priority": a["priority"], "added_at": at,
                                "deadline": parse_ts(a["deadline"]) if a.get("deadline") else None,
                                "blocked_by": list(a.get("blocked_by") or []), "source": a.get("source")}
        elif op == "queue.rank" and a.get("item") in items and a.get("before") in items:
            p = items[a["before"]]["priority"]
            items[a["item"]]["priority"] = p
            for lst in order.values():
                if a["item"] in lst:
                    lst.remove(a["item"])
            lst = order.setdefault(p, [])
            if a["before"] not in lst:
                lst.append(a["before"])
            lst.insert(lst.index(a["before"]), a["item"])
        elif op == "queue.promote":
            promos[a["item"]] = {"n": a.get("n", 1), "at": at}
        elif op == "queue.pause":
            pauses[a["item"]] = dict(a, at=at)
        elif op == "queue.resume":
            resumes[a["item"]] = {"at": at}
        elif op == "task.register":
            regs[a.get("task")] = a
        elif op == "task.done":
            done.add(a.get("task"))
    docs = {}
    for name, it in items.items():
        reg = regs.get(name)
        it["owner"] = reg.get("owner_agent") if reg else None
        row = None
        if reg:
            s = reg.get("session")
            if s not in docs:
                try:
                    docs[s] = {r["agent_id"]: r for r in owners(home, s, now=now)["owners"]}
                except Exception:  # noqa: BLE001 - an unreadable session: the owner shows as missing (stuck)
                    docs[s] = {}
            row = docs[s].get(reg.get("owner_agent"))
        it["owner_state"] = row["state"] if row else None
        disp = (row or {}).get("disposition") or {}
        pause, res = pauses.get(name), resumes.get(name)
        paused = pause and (not res or res["at"] < pause["at"])
        if pause:
            it["resume_at"] = pause.get("resume_at")
        if name in done or disp.get("kind") == "closed":
            state = "done"
        elif paused:
            state = "paused-limit" if (parse_ts(pause["resume_at"]) or 0.0) > now else "resume-due"
        elif not reg:
            state = "promoted" if name in promos else "queued"
        elif res and (row is None or (parse_ts(row.get("last_activity")) or 0.0) <= res["at"]):
            state = "promoted"  # resumed: waiting for main to message the owner
        elif row is None:
            state = "stuck"
        elif row["state"].startswith("waiting-on-") or (disp.get("kind") == "waiting" and disp.get("live")):
            state = "waiting"
        else:
            state = _OWNER_TO_QUEUE.get(row["state"], "active")
        it["state"] = state
    ranked = work_queue.rank(list(items.values()), now, order=order)
    return {"items": ranked, "order": order, "promos": promos, "pauses": pauses}


def _limit_in_transcript(home: Path, session: str, agent: str, now: float):
    """(resume_at, flags) when the owner's transcript ends on a usage-limit message; None otherwise. Reads at most the
    last 64 KiB; interview material is never read (the RESTRICTED rule)."""
    import work_queue  # noqa: PLC0415
    base = home / ".claude" / "projects"
    try:
        projects = list(os.scandir(base))
    except OSError:
        return None
    for proj in projects:
        path = Path(proj.path) / session / "subagents" / f"agent-{agent}.jsonl"
        if RESTRICTED.search(str(path)) or not path.is_file():
            continue
        try:
            with open(path, "rb") as fh:
                fh.seek(max(0, path.stat().st_size - QUEUE_TAIL_BYTES))
                lines = fh.read(QUEUE_TAIL_BYTES).splitlines()[-5:]
        except OSError:
            continue
        for raw in reversed(lines):
            try:
                rec = json.loads(raw)
            except ValueError:
                continue
            msg = rec.get("message") if isinstance(rec, dict) else None
            content = msg.get("content") if isinstance(msg, dict) else None
            texts = [c.get("text", "") for c in content if isinstance(c, dict)] if isinstance(content, list) else \
                [content] if isinstance(content, str) else []
            for text in texts:
                hit = work_queue.parse_limit(str(text)[:4000], parse_ts(rec.get("timestamp")) or now)
                if hit:
                    return hit
    return None


def queue_tick(home: Path, cap: int | None = None) -> dict:
    """One pass: record usage-limit pauses, then promote or resume the top dispatchable items into the free slots.
    Every write has a key derived from what was observed, so a repeated tick writes nothing new."""
    now = time.time()  # the writer clock that stamps received_at; no caller-chosen time
    cap = cap or queue_cap(home)
    view = queue_view(home, now)
    paused = []
    for it in view["items"]:
        if it["state"] in ("active", "stuck", "finished") and it.get("owner") and \
                it.get("owner_state") in ("finishing", "DROPPED", "SILENT-HIGH"):
            reg = next((r["args"] for r in reversed(_ledger(home)) if r.get("op") == "task.register"
                        and r["args"].get("task") == it["item"]), {})
            hit = _limit_in_transcript(home, reg.get("session") or "", it["owner"], now)
            if hit:
                resume_at, flags = hit
                r = write(home, "queue.pause", {"item": it["item"], "agent": it["owner"], "resume_at": iso(resume_at),
                                            "reason": "usage-limit", "flags": flags}, "",
                      f"qpause:{it['item']}:{it['owner']}:{int(resume_at)}")
                if r.get("result") == "applied":
                    paused.append(it["item"])
    if paused:
        view = queue_view(home, now)
    promoted, resumed = [], []
    for name in __import__("work_queue").plan(view["items"], cap):
        it = next(i for i in view["items"] if i["item"] == name)
        if it["state"] == "resume-due":
            pause = view["pauses"][name]
            r = write(home, "queue.resume", {"item": name}, "", f"qresume:{name}:{int(pause['at'])}")
            if r.get("result") == "applied":
                resumed.append(name)
            _queue_alert(home, f"queue:resume:{name}", "warning",
                         f"resume {pause['agent']} for queue item {name}: its usage limit reset at {pause['resume_at']}; "
                         f"SendMessage to {pause['agent']} keeps its context", f"qalert:resume:{name}:{int(pause['at'])}")
            continue
        n = view["promos"].get(name, {}).get("n", 0) + 1
        r = write(home, "queue.promote", {"item": name, "n": n}, "", f"qpromote:{name}:{n}")
        if r.get("result") == "applied":
            promoted.append(name)
        _queue_alert(home, f"queue:promoted:{name}", "info",
                     f"promoted {name} ({(it.get('title') or '')[:80]}): start an owner and register it with "
                     f"`ah task register --task {name}`", f"qalert:promote:{name}:{n}:info")
    for it in queue_view(home, now)["items"]:  # an unstarted promotion escalates; a started one clears
        name, promo = it["item"], view["promos"].get(it["item"])
        if it["state"] == "promoted" and promo and not it.get("owner"):
            age = now - promo["at"]
            sev = "high" if age >= QUEUE_PROMOTE_HIGH_S else "warning" if age >= QUEUE_PROMOTE_WARN_S else None
            if sev:
                _queue_alert(home, f"queue:promoted:{name}", sev, f"promoted {name} {int(age // 60)} min ago and no owner "
                             f"has started it", f"qalert:promote:{name}:{promo['n']}:{sev}")
        elif it.get("owner") and promo:
            _queue_alert(home, f"queue:promoted:{name}", None, "", f"qalert:started:{name}:{promo['n']}")
    running = sum(1 for i in queue_view(home, now)["items"] if i["state"] in ("active", "promoted"))
    return {"ok": True, "cap": cap, "running": running, "promoted": promoted, "paused": paused, "resumed": resumed}


def _queue_alert(home: Path, alert_key: str, severity, message: str, key: str) -> None:
    """Raise (severity) or clear (None) a source=ah-queue ring alert through the audited writer; never fatal."""
    try:
        if severity:
            write(home, "alert.raise", {"alert_key": alert_key, "source": "ah-queue", "severity": severity,
                                        "message": message, "detail": {}}, "", key)
        else:
            write(home, "alert.clear", {"alert_key": alert_key, "source": "ah-queue"}, "", key)
    except AhError:
        pass


def ahd_running_check(home: Path, now: float | None = None, max_beat_age: float = 300.0) -> dict:
    """ahd is the deterministic manager (goodqa#14791): doctor fails while it is not running on this host. Running =
    its lock is held (a non-blocking flock attempt fails) or its heartbeat is fresher than max_beat_age."""
    import fcntl  # noqa: PLC0415
    now = time.time() if now is None else now
    lock = home / ".agent-harness" / "run" / "ahd.lock"
    held = False
    try:
        fd = os.open(lock, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                fcntl.flock(fd, fcntl.LOCK_UN)
            except OSError:
                held = True
        finally:
            os.close(fd)
    except OSError:
        held = False
    beat = home / ".agent-harness" / "state" / "ahd" / "heartbeat.json"
    beat_age = None
    try:
        beat_age = now - beat.stat().st_mtime
    except OSError:
        pass
    ok = held or (beat_age is not None and beat_age <= max_beat_age)
    return {"check": "ahd running", "ok": ok, "lock_held": held, "heartbeat_age_s": None if beat_age is None else int(beat_age),
            "fix": None if ok else "python3 ~/.claude/hooks/ahd.py install --apply (or install.py --apply --services)"}


def build_parser():
    p = argparse.ArgumentParser(prog="ah", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--text", action="store_true", help="human summary instead of JSON")
    sub = p.add_subparsers(dest="cmd", required=True)
    o = sub.add_parser("owners")
    o.add_argument("--session")
    o.add_argument("--comments", action="store_true", help="also fetch latest ticket comment age (network)")
    o.add_argument("--gate", action="store_true", help="exit 1 while any DROPPED owner has no live disposition")
    u = sub.add_parser("user-msg")
    u.add_argument("--session")
    u.add_argument("--text-match", "--search", dest="search", help="words to find in a real human turn")
    u.add_argument("--recent", type=int)
    u.add_argument("--full", action="store_true")
    t = sub.add_parser("ticket")
    ts = t.add_subparsers(dest="sub", required=True)
    g = ts.add_parser("get")
    g.add_argument("number")
    c = ts.add_parser("comments")
    c.add_argument("number")
    c.add_argument("--since")
    c.add_argument("--last", type=int)
    cc = ts.add_parser("comment")
    cc.add_argument("ticket", help="GoodQA <project>#N")
    cc.add_argument("--body", required=True)
    for x in (g, c):
        x.add_argument("--project", default="goodqa")
    d = sub.add_parser("disk")
    d.add_argument("--host")
    d.add_argument("--root")
    d.add_argument("--count", type=int, default=10)
    d.add_argument("--budget", type=float, default=20.0)
    d.add_argument("--no-top", action="store_true")
    k = sub.add_parser("task")
    ks = k.add_subparsers(dest="sub", required=True)
    r = ks.add_parser("register")
    for f in ("task", "owner-agent", "scope", "ticket", "source"):
        r.add_argument("--" + f, required=True)
    r.add_argument("--branch")
    r.add_argument("--worktree")
    st = ks.add_parser("status")
    st.add_argument("--task", required=True)
    st.add_argument("--stage", required=True)
    st.add_argument("--note", required=True)
    st.add_argument("--ticket")
    tl = ks.add_parser("list")
    tl.add_argument("--open", action="store_true", help="hide done tasks")
    dn = ks.add_parser("done")
    dn.add_argument("--task", required=True)
    dn.add_argument("--really-tested", action="append", default=[], metavar="WALID")
    dn.add_argument("--wal")
    dn.add_argument("--commit", action="append", default=[])
    dn.add_argument("--repo")
    dp = ks.add_parser("dispose", help="record the decision for a DROPPED owner: resumed, reassigned, waiting or closed")
    dp.add_argument("--agent", required=True)
    dp.add_argument("--kind", required=True, choices=list(liveness.DISPOSITIONS))
    dp.add_argument("--ref", help="waiting: ask id or ticket; reassigned: replacement agent id")
    dp.add_argument("--until", help="waiting: ISO time when the wait expires")
    dp.add_argument("--reason", help="closed: why (8+ characters)")
    dp.add_argument("--evidence", help="closed: ticket, WAL id or commit sha")
    for x in (r, st, dn, cc, dp):
        x.add_argument("--session")
        x.add_argument("--key", help="idempotency key (default: derived from the request)")
    sub.add_parser("doctor", help="check the import chain and file hashes of this install")
    qp = sub.add_parser("queue", help="the work queue: cap, rank, promotion (NEVER-LOSE.md 9b)")
    qs = qp.add_subparsers(dest="sub", required=True)
    qa = qs.add_parser("add")
    for f in ("item", "title", "priority", "session", "source", "ticket", "deadline"):
        qa.add_argument(f"--{f}")
    qa.add_argument("--blocked-by", dest="blocked_by", action="append", default=[])
    qa.add_argument("--key", required=True)
    qr = qs.add_parser("rank")
    for f in ("item", "before", "source"):
        qr.add_argument(f"--{f}")
    qr.add_argument("--key", required=True)
    qs.add_parser("list")
    qt = qs.add_parser("tick")
    qt.add_argument("--cap", type=int)
    hb = sub.add_parser("heartbeat", help="record a service heartbeat (the file `ah doctor` reads)")
    hb.add_argument("action", choices=["beat"])
    hb.add_argument("--service", required=True)
    hb.add_argument("--key", required=True)
    al = sub.add_parser("alert", help="raise or clear an alert in the ops ring (an audited write)")
    al.add_argument("action", choices=["raise", "clear"])
    al.add_argument("--alert-key", dest="alert_key", required=True)
    al.add_argument("--source", required=True)
    al.add_argument("--key", required=True, help="idempotency key: a repeat returns duplicate")
    al.add_argument("--severity", help="raise: info, warning, high or critical")
    al.add_argument("--message", help="raise: the alert text")
    al.add_argument("--detail", help="raise: a JSON object")
    al.add_argument("--session")
    ap = sub.add_parser("apply", help="apply a batch of alert ops from stdin (JSON lines {op, key, args})")
    ap.add_argument("--batch", required=True, choices=["-"])
    ap.add_argument("--session")
    sp = sub.add_parser("spool")
    sp.add_argument("action", choices=["drain"])
    w = sub.add_parser("write")
    ws = w.add_subparsers(dest="sub", required=True)
    wr = ws.add_parser("result")
    wr.add_argument("--key", required=True)
    wr.add_argument("--session")
    return p


def session_of(args, home):
    return getattr(args, "session", None) or env_session()


def run(args, home: Path) -> dict:
    cmd = args.cmd
    if cmd == "owners":
        s = args.session or env_session() or newest_session(home)
        if not s or not SESSION_RE.match(s):
            raise AhError("session_unknown", "no session: pass --session")
        return owners(home, s, comments=comment_age if args.comments else None)
    if cmd == "user-msg":
        s = args.session or env_session()
        if not s:  # never guess "the newest transcript": a running helper session would win
            raise AhError("session_unknown", "no session: pass --session or set CLAUDE_CODE_SESSION_ID")
        return user_msgs(home, s, text=args.search, recent=args.recent, full=args.full)
    if cmd == "disk":
        return disk(args.host, args.root, args.count, args.budget, not args.no_top)
    if cmd == "ticket":
        if args.sub == "get":
            return ticket_get(args.number, args.project)
        if args.sub == "comments":
            return ticket_comments(args.number, args.project, args.since, args.last)
        return write(home, "ticket.comment", {"ticket": args.ticket, "body": args.body}, session_of(args, home), args.key)
    if cmd == "task":
        s = session_of(args, home)
        if args.sub == "list":
            return task_list(home, args.open)
        if args.sub == "register":
            a = {"task": args.task, "owner_agent": args.owner_agent, "session": s or "", "ticket": args.ticket,
                 "scope": args.scope, "source": args.source}
            for opt in ("branch", "worktree"):
                if getattr(args, opt):
                    a[opt] = getattr(args, opt)
            return write(home, "task.register", a, s, args.key)
        if args.sub == "dispose":
            a = {"agent": args.agent, "session": s or "", "kind": args.kind, "at": iso(time.time())}
            for opt in ("ref", "until", "reason", "evidence"):
                if getattr(args, opt):
                    a[opt] = getattr(args, opt)
            return write(home, "task.dispose", a, s, args.key)
        if args.sub == "status":
            a = {"task": args.task, "stage": args.stage, "note": args.note}
            if args.ticket:
                a["ticket"] = args.ticket
            return write(home, "task.status", a, s, args.key)
        ev = [{"really_tested": i, "wal": args.wal or ""} for i in args.really_tested]
        ev += [{"commit": c, "repo": args.repo or ""} for c in args.commit]
        return write(home, "task.done", {"task": args.task, "evidence": ev}, s, args.key)
    if cmd == "queue":
        if args.sub == "add":
            a = {k: getattr(args, k) for k in ("item", "title", "priority", "session", "source", "ticket", "deadline")
                 if getattr(args, k) is not None}
            a["blocked_by"] = args.blocked_by
            return write(home, "queue.add", a, args.session or "", args.key)
        if args.sub == "rank":
            a = {k: getattr(args, k) for k in ("item", "before", "source") if getattr(args, k) is not None}
            return write(home, "queue.rank", a, "", args.key)
        if args.sub == "list":
            now = time.time()  # the writer clock that stamps received_at; no caller-chosen time
            view = queue_view(home, now)
            return {"ok": True, "generated": iso(now), "cap": queue_cap(home), "items": view["items"]}
        if args.sub == "tick":
            return queue_tick(home, args.cap)
    if cmd == "heartbeat":
        return heartbeat(home, args.service, args.key)
    if cmd == "alert":
        a = {"alert_key": args.alert_key, "source": args.source}
        if args.action == "raise":
            try:
                detail = json.loads(args.detail) if args.detail else {}
            except ValueError:
                raise AhError("bad_request", "alert raise: --detail must be a JSON object")
            a.update(severity=args.severity, message=args.message or "", detail=detail)
        return write(home, f"alert.{args.action}", a, session_of(args, home) or "", args.key)
    if cmd == "apply":
        text = sys.stdin.read(BATCH_MAX_BYTES + 1)  # bounded: one character past the cap is enough to refuse
        return apply_batch(home, text, session_of(args, home) or "")
    if cmd == "doctor":
        return doctor()
    if cmd == "spool":
        return spool_drain(home)
    if cmd == "write":
        for row in _ledger(home):
            if row.get("key") == args.key:
                return {"ok": True, "result": "applied", "id": row["id"], "seq": row["seq"], "key": args.key}
        return {"ok": True, "result": "unknown", "key": args.key}
    raise AhError("unknown_command", cmd)


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        data = run(args, home_dir())
    except AhError as e:
        json.dump({"ok": False, "code": e.code, "message": str(e)}, sys.stdout)
        sys.stdout.write("\n")
        return e.exit_code
    except BrokenPipeError:
        return 0
    except Exception as e:  # a partial install or a bug: one JSON line, never a traceback
        json.dump({"ok": False, "code": "internal", "type": type(e).__name__}, sys.stdout)
        sys.stdout.write("\n")
        return 4
    if args.text:
        sys.stdout.write(render_text(args.cmd, data) + "\n")
    else:
        sys.stdout.write(json.dumps(data, indent=None if args.cmd == "write" else 2) + "\n")
    if isinstance(data, dict) and data.get("ok") is False:
        return 3
    if args.cmd == "owners" and getattr(args, "gate", False) and data.get("undisposed"):
        sys.stdout.write("GATE: undisposed DROPPED owners: " + ", ".join(data["undisposed"]) +
                         " (record a decision with `ah task dispose --agent <id> --kind resumed|reassigned|waiting|closed ...`)\n")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
