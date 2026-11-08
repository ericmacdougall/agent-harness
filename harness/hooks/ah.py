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
# The forms owners actually write: goodqa#N, GoodQA goodqa#N, GoodQA 1ae27b6b#N (project id prefix), GoodQA #N, #N, N.
_REF_FORMS = re.compile(r"(?:(?i:goodqa)(?:\s+([A-Za-z0-9][A-Za-z0-9-]{0,62})\s*#|\s*#)|#)?([1-9][0-9]{0,9})", re.ASCII)
PROJECT_ID_PREFIXES = {"1ae27b6b": "goodqa"}  # GoodQA project id (first 8 hex) -> slug
DEFAULT_PROJECT = "goodqa"
KEY_RE = re.compile(r"^[A-Za-z0-9._:-]{8,128}$")
ASK_ID_RE = re.compile(r"^w[0-9a-f]{11}$")
OWNER_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
# ahd's writes (goodqa#14848): heartbeat beat, alert raise|clear, apply --batch
SERVICE_RE = re.compile(r"^[a-z][a-z0-9-]{0,31}$")  # a heartbeat service names a directory: no paths
ALERT_KEY_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9:._/@-]{0,199}$")
ALERT_SEVERITIES = ("info", "warning", "high", "critical")  # = ops_watch.SEVERITIES
APPLY_OPS = ("alert.raise", "alert.clear")  # the only ops `ah apply --batch` accepts
APPLY_MAX_LINES = 200
APPLY_MAX_BYTES = 1024 * 1024
TASK_WAL_WINDOW_S = 48 * 3600  # a task-named WAL untouched this long is history (ahd owner_window_seconds)
OWNERS_RECENT_S = 6 * 3600  # `ah owners` (CLI) hides terminal rows idle longer than this unless --all (2026-11-06)
TERMINAL_STATES = frozenset({"done", "handoff", "returned", "idle-helper", "unverified-legacy", "superseded", "wontdo", "legacy"})
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


def wal_roots(home: Path) -> list:
    """Both WAL roots: Claude Code sessions and Codex sessions (B1, goodqa#14791)."""
    return [home / ".claude" / "wals", home / ".agent-harness" / "codex-wals"]


def session_dir(home: Path, session: str) -> Path:
    """The directory holding a session's WALs, whichever runtime wrote them; the Claude root when neither has it."""
    for root in wal_roots(home):
        if (root / session / "main.jsonl").is_file():
            return root / session
    return wal_roots(home)[0] / session


def wal_dirs(home: Path):
    return home / ".claude" / "wals"


def newest_session(home: Path):
    best, stamp = None, -1.0
    try:
        for root in wal_roots(home):  # Claude and Codex sessions alike (goodqa#14791 B1)
            if not root.is_dir():
                continue
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
    wal = session_dir(home, session)
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
    led = _ledger(home)  # one read per call
    registered = {r["args"].get("owner_agent") for r in led if r.get("op") == "task.register"}
    pending = pending_stops(home, session, led)
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
    asks = ask_states(main)
    for r in rows:  # round 5 MJ-1: a wait on an ask holds only while that ask is open in this session
        target = r["state"][len("waiting-on-"):] if r["state"].startswith("waiting-on-") else ""
        if r["owner"] and ASK_ID_RE.match(target) and asks.get(target) != "open":
            r["flags"] = list(r.get("flags") or []) + [f"wait-ask-{asks.get(target, 'missing')}"]
            r["state"], r["severity"] = "DROPPED", "high"
    disp = dispositions(home, session, led)
    for d in disp.values():
        if d.get("kind") == "waiting" and ASK_ID_RE.match(str(d.get("ref") or "")) and asks.get(d["ref"]) != "open":
            d["until"] = min(float(d.get("until") or 0.0), float(d.get("at") or 0.0))  # answered: the wait is over
    # a returned parent with live children is still doing the work through them (main's finding: a4720127 and its 7
    # reviewers), so it counts as live for a reassignment (dispose guard). Only a child with recent activity counts:
    # a crashed child stays idle-helper or SILENT for ever (PR review of 24a786c, F3)
    live_parents = {r["parent"] for r in rows if r.get("parent") and r["state"] == "live"}
    by_id = {r["agent_id"]: r for r in rows}

    def covered(agent_id, seen=()):
        """A reassignment target holds the work when it is live, or is DROPPED but excused by its own live disposition
        (a named wait, a fresh resume, or a further reassignment). The chain is cycle-safe and each link
        keeps its own expiry, so an inherited wait ends when the target's wait ends (goodqa#14791).
        A target whose own disposition is permanent (closed, legacy, superseded, wontdo) does not hold reassigned
        work: that excuse would skip every check the dispose guard makes on the reassigned owner, and one legacy row
        could clear any number of drops (PR review of 24a786c, F1; main's decision). Close each owner on its own."""
        t = by_id.get(agent_id)
        if t is None or agent_id in seen:
            return False
        td = disp.get(agent_id)
        if td and td.get("kind") in GUARDED_KINDS and not t["state"].startswith(("live", "working", "waiting")):
            return False  # checked first: the row loop below relabels such a target (superseded, unverified-legacy)
        if t["state"] not in ("DROPPED", "done", "handoff", "returned") or agent_id in live_parents:
            return True
        # Any non-live state (DROPPED, done, handoff, returned) is excused only by the target's own live disposition:
        # an owner that returned a result and then went into a named wait still holds the work (main repro
        # 2026-11-06: pet-leads-x reassigned to a done owner waiting on goodqa#14883).
        if td and td.get("kind") == "reassigned":
            return covered(td.get("ref"), seen + (agent_id,))
        if td and td.get("kind") == "resumed" and t["state"] != "DROPPED":
            # `resumed` stays live once any later activity exists; a target that resumed and then finished (done,
            # handoff, returned) holds no wait, so only a named wait excuses it (PR #107 review F1)
            return False
        return liveness.disposition_live(td, now, last_activity=parse_ts(t["last_activity"]) or 0.0)

    for r in rows:
        d = disp.get(r["agent_id"])
        last_wal = parse_ts(r["last_activity"]) or 0.0
        alive = liveness.disposition_live(d, now, last_activity=last_wal,
                                          replacement_live=bool(d and d.get("kind") == "reassigned"
                                                                and covered(d.get("ref"), (r["agent_id"],))))
        r["disposition"] = dict(d, live=alive) if d else None
        r["decision_required"] = bool(r["owner"] and r["state"] == "DROPPED" and not alive)
        if d and d.get("kind") in ("legacy", "superseded", "wontdo") and r["state"] not in ("done", "handoff", "returned") \
                and not r["state"].startswith(("live", "working", "waiting")):
            label = "unverified-legacy" if d["kind"] == "legacy" else d["kind"]
            r["state"], r["severity"] = label, "info"  # ended, never "done"
            r["flags"] = list(r.get("flags") or []) + [label]
    for r in rows:  # I9: a handoff is real only once someone takes it (a disposition at/after the handoff)
        if r["owner"] and r["state"] == "handoff":
            handed = parse_ts(r["last_activity"]) or 0.0
            d = disp.get(r["agent_id"])
            kind = d.get("kind") if d else None
            # #134 red-team P4: only main's wait acknowledges, marked --ack-handoff (an owner cannot set it)
            acknowledged = kind in ("resumed", "reassigned") + GUARDED_KINDS or (
                kind == "waiting" and d.get("ack_handoff") is True
                and liveness.disposition_live(d, now, last_activity=handed))
            acked = bool(acknowledged and float(d.get("at") or 0) >= handed - 10)
            if not acked and now - handed >= HANDOFF_ACK_S:
                r["decision_required"] = True
                r["flags"] = list(r.get("flags") or []) + ["handoff-unacked"]
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
    dls = deadlines(home, session, now, led)
    missed = [d for d in dls if d["state"] == "missed" and not liveness.disposition_live(disp.get(d["id"]), now)]
    return {"session": session, "generated": iso(now), "counts": counts, "owners": rows, "source": "direct",
            "deadlines": dls,
            "undisposed": sorted([r["agent_id"] for r in rows if r["decision_required"]] + [d["id"] for d in missed]),
            "legacy_unverified": sorted(a for a, d in disp.items() if d.get("kind") == "legacy")}


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


def _message_source(row):
    """A verified citation and its shell-quoted --source argument, ready to paste into wal_note.

    The transcript index has already established authorship. Reuse the provenance parser and excerpt
    matcher rather than maintaining a second, subtly different source grammar. Very short or unusual
    messages may need a human-chosen excerpt; never emit a citation that did not verify.
    """
    import provenance  # noqa: PLC0415
    import shlex  # noqa: PLC0415

    ident = row["id"].replace("uuid:", "user:", 1)
    normalized = re.sub(r"\s+", " ", row["text"]).strip()
    chunks = [normalized] + [part.strip() for part in normalized.split("...")]
    for chunk in chunks:
        for size in (120, 80, 60, 40, 24, 12):  # no more than the existing preview exposes
            excerpt = chunk[:size].strip()
            if len(excerpt) < provenance.EXCERPT_MIN:
                continue
            source = f'{ident} "{excerpt.replace(chr(34), chr(92) + chr(34))}"'
            try:
                parsed = provenance.parse_source(source)
                if parsed["excerpt"] != excerpt or provenance.excerpt_in(row["text"], parsed["excerpt"]):
                    continue
            except provenance.Problem:
                continue
            return {"source": source, "source_arg": "--source " + shlex.quote(source)}
    return {"source_error": "no automatically verified excerpt; use --full and quote exact user text"}


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
        r.update(_message_source(r))
        if not full:
            del r["text"]
    return {"session": session, "matches": out, "source": "direct"}


# ------------------------------------------------------------------ tickets

def load_adapter(home: Path | None = None, quick: bool = False):
    import ticket_adapters
    import commit_policy  # overlay-aware: the shipped policy no longer carries the org id (GoodQA #14538)
    cfg = commit_policy.load_policy(Path(__file__).with_name("commit_policy.json"))["ticket_systems"]["goodqa"]
    if os.environ.get("AH_GOODQA_ENDPOINT"):  # loopback endpoints only (tests); the adapter enforces the scheme
        cfg = dict(cfg, endpoint=os.environ["AH_GOODQA_ENDPOINT"])
    if os.environ.get("AH_GOODQA_KEY_FILE"):
        cfg = dict(cfg, key_file=os.environ["AH_GOODQA_KEY_FILE"])
    if quick:  # pre-checks must not stall a write: one attempt, short deadline
        return ticket_adapters.adapter_for(dict(cfg, attempts=1, timeout_seconds=6, total_deadline_seconds=10)), ticket_adapters
    return ticket_adapters.adapter_for(dict(cfg, max_comment_pages=1000, total_deadline_seconds=120)), ticket_adapters


def ticket_ref(value: str, project: str = DEFAULT_PROJECT):
    """(slug, number) for any ref form owners use; an unknown or malformed ref is refused here, never spooled."""
    m = _REF_FORMS.fullmatch(value.strip()) if isinstance(value, str) else None
    if not m:
        raise AhError("bad_request", "ticket must be N, #N, goodqa#N or 'GoodQA <project>#N'")
    slug = (m.group(1) or project).lower()
    if slug in PROJECT_ID_PREFIXES:
        slug = PROJECT_ID_PREFIXES[slug]
    elif re.fullmatch(r"[0-9a-f]{8}", slug):
        raise AhError("bad_request", f"{slug!r} looks like a project id, not a slug; write the slug (for example 'GoodQA goodqa#N')")
    return slug, int(m.group(2))


def canonical_ref(value: str) -> str:
    slug, number = ticket_ref(value)
    return f"GoodQA {slug}#{number}"


def check_ticket_exists(ref: str) -> None:
    """Refuse a ticket GoodQA says is missing or out of scope before anything is queued. Offline: nothing to check."""
    slug, number = ticket_ref(ref)
    try:
        import commit_policy  # overlay-aware: unreachable projects now live in the local profile (main ebb61fc)
        policy = commit_policy.load_policy(Path(__file__).with_name("commit_policy.json"))["ticket_systems"]["goodqa"]
        if slug in (policy.get("unreachable_projects") or []):
            return  # the member key cannot see these projects: nothing to verify (commit policy treats them as warn-only)
        adapter, mod = load_adapter(quick=True)
        ticket = adapter.lookup(slug, number)
    except Exception as e:  # only a definite answer refuses; anything else (outage, odd response) queues the comment
        if type(e).__name__ == "TicketOutOfScope":
            raise AhError("ticket_out_of_scope", f"project {slug!r} is not visible to this credential", 2) from None
        return
    if ticket is None:
        raise AhError("not_found", f"ticket {slug}#{number} does not exist", 2)


def ticket_issue(adapter, mod, project, number):
    try:
        ticket = adapter.lookup(project, number)
    except mod.TicketOutOfScope:
        raise AhError("ticket_out_of_scope", f"project {project!r} is not visible to this credential", 2) from None
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
    """The acting agent from the launcher env; "unknown" when absent (never a claimed "main")."""
    return os.environ.get("AH_AGENT_ID") or os.environ.get("AGENT_ID") or "unknown"


def in_child_session() -> bool:
    """Retired (S3b review round 3, B1): no environment variable tells main from a sub-agent. Main's own shell carries
    CLAUDE_CODE_CHILD_SESSION=1 and AI_AGENT=claude-code_<v>_agent exactly like a sub-agent's (observed in main's
    shell, 2026-11-05). The caller's identity comes from the hook payload instead: `dropped_gate.py pretool` denies
    a sub-agent's acknowledging `ah task dispose` before it runs."""
    return False


def actor(session, host=None):
    return {"session": session or "", "agent_id": actor_id(),
            "host": host or socket.gethostname()}


def precheck(op: str, args: dict) -> None:
    def need(*names):
        for n in names:
            v = args.get(n)
            if not isinstance(v, str) or not v.strip():
                raise AhError("bad_request", f"{op}: {n} is required")
    if op == "task.register":
        need("task", "owner_agent", "session", "scope", "source")
        ticket_ref(args.get("ticket") or "")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,119}", args["session"]):
            raise AhError("bad_request", "task.register: session id is malformed")
        if not re.fullmatch(r"[A-Za-z0-9]{1,40}|main", args["owner_agent"]):
            raise AhError("bad_request", "task.register: owner_agent must be an agent id or 'main'")
    elif op == "task.status":
        need("task", "stage", "note")
        if args.get("ticket"):
            ticket_ref(args["ticket"])
    elif op == "task.done":
        need("task")
        ev = args.get("evidence")
        if not isinstance(ev, list) or not ev:
            raise AhError("evidence", "task.done needs --deployed WID plus --really-tested ID --wal PATH (done means "
                                      "deployed to live and tested)")
        for e in ev:
            ok = isinstance(e, dict) and (
                (isinstance(e.get("really_tested"), str) and e["really_tested"].strip() and e.get("wal")) or
                (re.fullmatch(r"[0-9a-f]{7,40}", str(e.get("commit", ""))) and e.get("repo")) or
                bool(ASK_ID_RE.match(str(e.get("deployed", "")))))
            if not ok:
                raise AhError("evidence", "each evidence item is {deployed}, {really_tested, wal} or {commit, repo}")
        if not (any("deployed" in e for e in ev) and any("really_tested" in e for e in ev)):
            raise AhError("evidence", "task.done: done means deployed to live and tested; give a deploy record "
                                      "(--deployed WID) and a live REALLY_TESTED run. A commit or merge alone is not done")
    elif op in ("alert.raise", "alert.clear"):
        need("alert_key", "source")
        if not ALERT_KEY_RE.match(args["alert_key"]) or not SERVICE_RE.match(args["source"]):
            raise AhError("bad_request", f"{op}: alert_key or source is malformed")
        if op == "alert.raise":
            need("message")
            if args.get("severity") not in ALERT_SEVERITIES:
                raise AhError("bad_request", f"alert.raise: severity must be one of {', '.join(ALERT_SEVERITIES)}")
        if not isinstance(args.get("detail", {}), dict):
            raise AhError("bad_request", f"{op}: detail must be a JSON object")
    elif op == "task.dispose":
        need("agent", "session", "kind", "at")
        if args["kind"] not in liveness.DISPOSITIONS:
            raise AhError("bad_request", f"task.dispose: kind must be one of {', '.join(liveness.DISPOSITIONS)}")
        if not OWNER_ID_RE.match(args["agent"]):
            raise AhError("bad_request", "task.dispose: agent must be an agent id or a task WAL name")
        if parse_ts(args["at"]) is None:
            raise AhError("bad_request", "task.dispose: at must be an ISO timestamp")
        if args.get("ack_handoff") not in (None, True) or (args.get("ack_handoff") and args["kind"] != "waiting"):
            raise AhError("bad_request", "task.dispose: --ack-handoff goes with --kind waiting only")
        if args["kind"] == "waiting":
            if parse_ts(args.get("until") or "") is None:
                raise AhError("bad_request", "task.dispose waiting: --until <ISO time> is required (when it expires)")
            cap = WAIT_UNVERIFIED_MAX_S if args.get("ref_unverified") else WAIT_MAX_S
            if parse_ts(args["until"]) - parse_ts(args["at"]) > cap:
                raise AhError("bad_request", f"task.dispose waiting: --until may be at most {cap // 3600} h after now"
                                             + (" (GoodQA could not confirm the ticket)" if args.get("ref_unverified") else "")
                                             + "; renew the wait when it expires")
            ref = args.get("ref") or ""
            if not (ASK_ID_RE.match(ref) or TICKET_RE.match(ref)):
                raise AhError("bad_request", "task.dispose waiting: --ref must be an ask id (w + 11 hex) or 'GoodQA <project>#N'; "
                                             "a wait must name what it waits on")
        elif args["kind"] == "reassigned":
            if not OWNER_ID_RE.match(args.get("ref") or ""):
                raise AhError("bad_request", "task.dispose reassigned: --ref <replacement agent id> is required")
        elif args["kind"] in liveness.CLOSING:
            reason = (args.get("reason") or "").strip()
            if len(reason) < REASON_MIN or len(set(re.findall(r"[a-z0-9]+", reason.lower()))) < REASON_MIN_WORDS:
                raise AhError("reason", f"task.dispose {args['kind']}: --reason must say what you verified about this "
                                        f"owner ({REASON_MIN}+ characters, {REASON_MIN_WORDS}+ different words)")
            if args["kind"] == "closed":
                if not (ASK_ID_RE.match(args.get("deployed") or "") and LIVE_TEST_RE.match(args.get("live_test") or "")):
                    raise AhError("evidence", "task.dispose closed means done, and done means deployed to live and tested: "
                                              "--deployed <WAL id of the deploy or install record> --live-test <REALLY_TESTED "
                                              "id run against the live target>. A merge or commit alone is not done; work "
                                              "that will not ship is --kind superseded|wontdo --ref <ticket>")
                if args.get("evidence"):
                    raise AhError("evidence", "task.dispose closed: --evidence is retired; give --deployed and --live-test")
            elif not TICKET_RE.match(args.get("ref") or ""):
                raise AhError("evidence", f"task.dispose {args['kind']}: --ref 'GoodQA <project>#N' (the ticket that "
                                          "records why) is required")
        elif args["kind"] == "legacy" and (args.get("evidence") or args.get("deployed") or args.get("live_test")):
            raise AhError("bad_request", "task.dispose legacy takes no evidence: it records that nobody verified the owner")
    elif op == "deadline.add":
        need("session", "at", "ref", "owner", "note")
        if parse_ts(args["at"]) is None:
            raise AhError("bad_request", "deadline.add: --at must be an ISO time")
        if not (TICKET_RE.match(args["ref"]) or ASK_ID_RE.match(args["ref"])):
            raise AhError("bad_request", "deadline.add: --ref must be a GoodQA ticket or an ask id")
        if not OWNER_ID_RE.match(args["owner"]):
            raise AhError("bad_request", "deadline.add: --owner must be an agent id or task name")
    elif op == "deadline.done":
        need("session", "id")
        if not re.fullmatch(r"dl[0-9a-f]{10}", args["id"]):
            raise AhError("bad_request", "deadline.done: --id must be a deadline id (dl + 10 hex)")
    elif op == "task.pending":
        need("agent", "session", "at")
        if not OWNER_ID_RE.match(args["agent"]) or parse_ts(args["at"]) is None:
            raise AhError("bad_request", "task.pending: agent id and ISO at are required")
    elif op == "ticket.comment":
        need("body")
        ticket_ref(args.get("ticket") or "")
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
    except mod.TicketOutOfScope:
        raise AhError("ticket_out_of_scope", f"project {project!r} is not visible to this credential", 2) from None
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
        done, failed, dead, parked, dead_names = 0, 0, 0, 0, []
        stop_at_ = time.monotonic() + budget_s if budget_s else None
        for n_, f in enumerate(sorted(spool.glob(f"*-{hashlib.sha256(only_opid.encode()).hexdigest()[:16]}.json" if only_opid else "*.json"))):
            if (limit is not None and n_ >= limit) or (stop_at_ and time.monotonic() > stop_at_):
                break
            def move(kind):
                (spool / kind).mkdir(parents=True, exist_ok=True, mode=0o700)
                os.replace(f, spool / kind / f.name)

            try:  # reading the job: only a malformed job (or a symlink) is dead; a read error keeps it
                if f.is_symlink():
                    raise ValueError("symlinked job")
                job = json.loads(_bounded(f))
                ticket, body, opid = job["ticket"], job["body"], job["operation_id"]
                if not all(isinstance(x, str) for x in (ticket, body, opid)):
                    raise TypeError("job fields")
            except (ValueError, KeyError, TypeError):
                try:
                    move("dead")
                    dead += 1
                    dead_names.append(f.name)
                except OSError:
                    failed += 1
                continue
            except Exception:
                failed += 1
                continue
            try:
                post_comment(ticket, body, opid)
            except AhError as e:
                try:
                    if e.code in ("not_found", "bad_request"):  # a definite answer: this ticket does not exist
                        move("dead")
                        dead += 1
                        dead_names.append(f.name)
                    elif e.code == "ticket_out_of_scope":  # could change with access or credentials: park, never lose
                        move("parked")
                        parked += 1
                    else:
                        failed += 1
                except OSError:
                    failed += 1
                continue
            except Exception:  # one bad job (or a bad policy file) must never change another job or caller
                failed += 1
                continue
            try:
                f.unlink(missing_ok=True)
            except OSError:  # posted, but the file cannot be removed: the re-post is idempotent; keep draining the rest
                failed += 1
                continue
            done += 1
        if done or dead or parked:
            _append_line(store_dir(home) / "audit.jsonl", {"at": iso(time.time()), "op": "spool.drain",
                                                           "result": "drained", "drained": done, "dead": dead, "parked": parked,
                                                           "dead_jobs": dead_names[:50]})
        return {"ok": True, "drained": done, "pending": failed, "dead": dead, "parked": parked}
    finally:
        os.close(lockfd)


def spool_retry(home: Path) -> dict:
    """Put parked jobs (out of scope when tried) back in the spool, e.g. after access or the credential was fixed."""
    spool = store_dir(home) / "spool"
    moved = []
    parked = spool / "parked"
    for f in sorted(parked.glob("*.json")) if parked.is_dir() else []:
        if f.is_file() and not f.is_symlink():
            os.replace(f, spool / f.name)
            moved.append(f.name)
    if moved:
        _append_line(store_dir(home) / "audit.jsonl", {"at": iso(time.time()), "op": "spool.retry", "result": "requeued",
                                                       "jobs": moved[:50]})
    return {"ok": True, "requeued": moved}


JOB_NAME = re.compile(r"\d{13}-[0-9a-f]{16}\.json")


def spool_ack(home: Path, jobs: list, evidence: str | None) -> dict:
    """Settle spool jobs that were delivered some other way: move them to spool/delivered/ (never deleted) and audit."""
    import fcntl
    if not jobs:
        raise AhError("bad_request", "spool ack needs one or more job file names")
    if not evidence or len(evidence.strip()) < 10:
        raise AhError("evidence", "spool ack needs --evidence (10+ characters): how you know the comment was delivered")
    for name in jobs:
        if not JOB_NAME.fullmatch(name):
            raise AhError("bad_request", f"{name[:40]!r} is not a spool job file name")
    spool = store_dir(home) / "spool"
    lockfd = os.open(store_dir(home) / "spool.lock", os.O_RDWR | os.O_CREAT, 0o600)
    try:
        try:
            fcntl.flock(lockfd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raise AhError("lock_timeout", "a spool drain is running; retry", 3) from None
        moved, absent = [], []
        (spool / "delivered").mkdir(parents=True, exist_ok=True, mode=0o700)
        details = []
        for name in jobs:
            src = spool / name
            if src.is_file() and not src.is_symlink():
                try:
                    job = json.loads(_bounded(src, 1 << 20))
                    details.append({"job": name, "ticket": job.get("ticket"), "operation_id": job.get("operation_id")})
                except (OSError, ValueError, AttributeError):
                    details.append({"job": name})
                os.replace(src, spool / "delivered" / name)
                moved.append(name)
            else:
                absent.append(name)
        if moved:
            _append_line(store_dir(home) / "audit.jsonl", {"at": iso(time.time()), "op": "spool.ack", "result": "acked",
                                                           "jobs": details, "evidence": _redact_args(evidence.strip()[:500], __import__("redact").redact),
                                                           "actor": actor(None)})
        return {"ok": True, "acked": moved, "not_found": absent}
    finally:
        os.close(lockfd)


def _wal_path(home: Path, session: str, agent: str) -> Path:
    return session_dir(home, session) / ("main.jsonl" if agent == "main" else f"agent-{agent}.jsonl")


def _wal_append(home: Path, path: Path, record: dict) -> None:
    try:  # a retry after a crash between this append and the ledger row must not duplicate the entry
        with open(path, "rb") as handle:
            handle.seek(0, 2)
            handle.seek(max(0, handle.tell() - 262144))
            if (b'"id":"%s"' % record["id"].encode()) in handle.read(262144):  # input-ok: tail window only
                return
    except OSError:
        pass
    # ah is the writer: its own bounded append, valid under either WAL root, independent of which wal.py is installed
    import fcntl  # noqa: PLC0415
    real_parent = path.parent.resolve()
    if path.suffix != ".jsonl" or not any(real_parent.parent == r.resolve() for r in wal_roots(home) if r.exists()) \
            or not SESSION_RE.match(path.parent.name):
        raise AhError("bad_request", "WAL path must be a session JSONL under ~/.claude/wals or ~/.agent-harness/codex-wals", 3)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    payload = (json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n").encode()
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0), 0o600)
    except OSError as e:
        raise AhError("wal_unsafe", f"WAL {path.name} is not a writable regular file ({e.__class__.__name__}); a symlinked WAL is refused", 3)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        os.write(fd, payload)
        os.fsync(fd)
    finally:
        os.close(fd)


def _task(ledger: list, name: str):
    reg = [r for r in ledger if r.get("op") == "task.register" and r["args"].get("task") == name]
    return reg[-1] if reg else None


def _evidence_ok(home: Path, ev: list, allowed: set, reg: dict, ledger=None) -> None:
    reg_ts = parse_ts(reg.get("received_at"))
    reg_args = reg["args"]
    ctx = _owner_context(home, reg_args["session"], reg_args["owner_agent"], ledger or [], task=reg_args["task"])
    deploy_at = 0.0
    for e in ev:
        if "deployed" in e:
            dep, _named = _deploy_record(home, reg_args["session"], e["deployed"], ctx)
            deploy_at = max(deploy_at, parse_ts(dep.get("at")) or 0.0)
    for e in ev:
        if "really_tested" in e:  # done is a live test after the deploy (main WAL w07450081c12)
            _live_test(home, reg_args["session"], e["really_tested"].strip(), None, deploy_at)
    roots = [r.resolve() for r in wal_roots(home) if r.exists()] or [(home / ".claude" / "wals").resolve()]
    for e in ev:
        if "deployed" in e:
            continue
        if "really_tested" in e:
            wid = e["really_tested"].strip()
            try:
                p = Path(e["wal"]).expanduser().resolve(strict=True)
            except OSError:
                raise AhError("evidence", f"WAL not found: {e['wal'][:80]}", 3)
            if not any(root in p.parents for root in roots):
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
        _evidence_ok(home, args["evidence"], allowed, reg, ledger)
        r = reg["args"]
        cites = "; ".join(e.get("really_tested") or e.get("deployed") or e["commit"] for e in args["evidence"])
        rec = {"at": now, "event": "result", "id": wid, "by": actor_id(), "note": f"task {args['task']} done; evidence: {cites}"[:3900]}
        _wal_append(home, _wal_path(home, r["session"], r["owner_agent"]), rec)
        out["wal"] = wid
        comment(r["ticket"], rec["note"])
    elif op in ("deadline.add", "deadline.done"):
        main_wal = _wal_path(home, args["session"], "main")
        if not main_wal.is_file():
            raise AhError("session_unknown", f"no main WAL for session {args['session']!r}", 3)
        if op == "deadline.add":
            did = "dl" + hashlib.sha256(key.encode()).hexdigest()[:10]
            _wal_append(home, main_wal, {"at": now, "event": "deadline", "id": did, "by": actor_id(), "due": args["at"],
                                         "ref": args["ref"], "owner": args["owner"], "note": args["note"][:300]})
            out["deadline"] = did
        else:
            known = {"dl" + hashlib.sha256(r["key"].encode()).hexdigest()[:10] for r in ledger
                     if r.get("op") == "deadline.add" and (r.get("args") or {}).get("session") == args["session"]}
            if args["id"] not in known:
                raise AhError("unknown_deadline", f"deadline.done: {args['id']} is not a deadline of this session", 3)
            _wal_append(home, main_wal, {"at": now, "event": "deadline_done", "id": wid, "by": actor_id(), "ref": args["id"],
                                         "note": (args.get("note") or "")[:300]})
    elif op == "task.pending":
        wal = _wal_path(home, args["session"], args["agent"])
        if wal.is_file():  # the marker is written by the gate, never counted as the owner's activity
            _wal_append(home, wal, {"at": now, "event": "pending_stop", "id": wid, "by": "dropped_gate",
                                    "note": "stopped with pending work and no armed waiter (goodqa#14791 I7)"})
        out["wal"] = wid
    elif op == "ticket.comment":
        comment(args["ticket"], args["body"])
    elif op in ("alert.raise", "alert.clear"):
        # The ops-watch ring is the one alert channel (goodqa#14591); emit() redacts and fsyncs. host is the short
        # hostname, as ahd.host(), because ahd diffs its desired alerts against this host's ring entries.
        import ops_watch  # noqa: PLC0415
        kind = op.split(".", 1)[1]
        out["ring_seq"] = ops_watch.emit({
            "host": socket.gethostname().split(".")[0], "source": args["source"], "event": kind,
            "severity": args.get("severity") or "info", "key": args["alert_key"], "check": args["source"],
            "message": args.get("message") or "cleared", "detail": args.get("detail") or {}}, home=home)
    elif op == "task.dispose":
        if args["kind"] in ("resumed", "reassigned") + GUARDED_KINDS and actor_id() == args["agent"]:
            raise AhError("forbidden", f"task.dispose {args['kind']}: a sub-agent or the owner itself cannot acknowledge; "
                                       "main records it (waiting is allowed)", 3)
        main_wal = _wal_path(home, args["session"], "main")
        if not main_wal.is_file():
            raise AhError("session_unknown", f"no main WAL for session {args['session']!r}", 3)
        ref = args.get("ref") or ""
        if args["kind"] == "waiting" and ASK_ID_RE.match(ref) and ask_states(main_wal).get(ref) != "open":
            state = ask_states(main_wal).get(ref)
            raise AhError("bad_request", f"task.dispose waiting: ask {ref} " + ("is already answered (ask_resolved)"
                          if state == "resolved" else "is not in this session's WAL"), 3)
        if args["kind"] == "reassigned" and not (_wal_has(main_wal, "subagent", None, agent=ref)
                                                or (main_wal.parent / f"{ref}.jsonl").is_file()):
            raise AhError("bad_request", f"task.dispose reassigned: {ref} is not an agent of this session", 3)
        if (args["kind"] == "closed" and not args.get("deploy_at")) or (args["kind"] == "legacy" and not args.get("gate_epoch")) \
                or (args["kind"] in ("superseded", "wontdo") and not args.get("ref_checked")):
            raise AhError("evidence", f"task.dispose {args['kind']}: evidence was not verified", 3)  # preflight sets these
        if args["kind"] in liveness.CLOSING:
            _closing_checks(args, ledger, time.time())
        rec = {"at": now, "event": "disposition", "id": wid, "agent": args["agent"], "kind": args["kind"],
               "note": f"owner {args['agent']} {args['kind']}: {args.get('reason') or args.get('ref') or ''}"[:300]}
        for k in ("until", "ref", "reason", "deployed", "live_test", "gate_epoch", "owner_last"):
            if args.get(k):
                rec[k] = args[k]
        _wal_append(home, main_wal, rec)
        out["wal"] = wid
        if args["kind"] in ("reassigned",) + tuple(liveness.CLOSING):  # the owner is retired: its waiters are leftovers
            try:
                waiters = leftover_waiters(home, args["agent"], args["session"])
            except Exception:  # noqa: BLE001 - a process scan failure never blocks a disposition
                waiters = []
            if waiters:
                out["leftover_waiters"] = waiters
                pids = [str(w["pid"]) for w in waiters if w.get("kind") == "process"]
                out["warning"] = (f"{len(waiters)} live waiter(s) still attributed to {args['agent']} or its session: "
                                  + "; ".join(f"pid {w['pid']} ({w['elapsed']}, {w['scope']}) {w['command'][:80]}" if w.get("kind") == "process"
                                              else f"ah-run {w['run']} {' '.join(w.get('argv') or [])[:80]}" for w in waiters)
                                  + ". Each wake-up of a retired agent rereads its whole context: stop them "
                                  + (f"(`ah kill --pid {','.join(pids)} --reason '<why>'`) " if pids else "")
                                  + "or hand them to the replacement.")
    return out


WAIT_LOOP_RE = re.compile(r"\b(?:until|while)\b.{0,400}?\b(?:sleep|pgrep|grep|inotifywait|wait)\b", re.S)
WAITER_CAP = 20
WAITER_PROBE_CAP = 50  # environment probes per dispose; each is one bounded `ps eww`


def _ps_rows() -> list:
    """[(pid, elapsed, command)] for this user's processes, bounded; [] when ps is unavailable."""
    try:
        r = subprocess.run(["ps", "-u", str(os.getuid()), "-o", "pid=,etime=,command="], capture_output=True, text=True,
                           timeout=15, env=dict(os.environ, LC_ALL="C", LANG="C"))
    except (OSError, subprocess.SubprocessError):
        return []
    rows = []
    for line in r.stdout.splitlines()[:5000]:
        parts = line.split(None, 2)
        if len(parts) == 3 and parts[0].isdigit():
            rows.append((int(parts[0]), parts[1], parts[2]))
    return rows


def _session_env_of(pid: int):
    """CLAUDE_CODE_SESSION_ID in a process's environment (ps eww shows it for own processes), else None."""
    try:
        r = subprocess.run(["ps", "eww", "-o", "command=", "-p", str(pid)], capture_output=True, text=True, timeout=8,
                           env=dict(os.environ, LC_ALL="C"))
    except (OSError, subprocess.SubprocessError):
        return None
    m = re.search(r"CLAUDE_CODE_SESSION_ID=([A-Za-z0-9._-]{1,128})", r.stdout)
    return m.group(1) if m else None


def leftover_waiters(home: Path, agent: str, session: str, ps_rows=None, session_of=None) -> list:
    """Live background waiters a retired owner may have left behind (goodqa#14927): wait loops (until/while with
    sleep, grep or pgrep) whose command line names the agent (`scope: agent`) or whose environment carries this
    session's id (`scope: session`), plus ah-run ledger rows attributed to the agent that have not ended. Read-only
    and bounded; it never signals anything. 2026-11-06: a retired 580k-context agent was woken repeatedly by its own
    `until grep` waiters, each wake a full context reread."""
    import redact  # noqa: PLC0415
    found = []
    ledger = home / ".agent-harness" / "reserve" / "ledger"
    try:
        entries = sorted(os.scandir(ledger), key=lambda e: e.name)[-500:]
    except OSError:
        entries = []
    for entry in entries:
        if not entry.name.endswith(".json") or not entry.is_file(follow_symlinks=False):
            continue
        try:
            with open(entry.path, "rb") as handle:
                row = json.loads(handle.read(65536))  # input-ok: one bounded ledger row
        except (OSError, ValueError):
            continue
        if isinstance(row, dict) and row.get("agent") == agent and not row.get("end"):
            argv = row.get("argv") if isinstance(row.get("argv"), list) else []
            found.append({"kind": "ah-run", "run": entry.name[:-5], "argv": [redact.redact(str(a))[:60] for a in argv[:8]]})
    rows = _ps_rows() if ps_rows is None else ps_rows
    session_of = session_of or _session_env_of
    me = os.getpid()
    probes = 0
    for pid, elapsed, command in rows:
        if len(found) >= WAITER_CAP:
            break
        if pid == me or not isinstance(command, str) or not WAIT_LOOP_RE.search(command):
            continue
        if agent and agent in command:
            scope = "agent"
        elif session and session in command:
            scope = "session"
        elif session and probes < WAITER_PROBE_CAP:
            probes += 1  # one `ps eww` per unattributed wait loop, capped (review LOW, 2026-11-06)
            if session_of(pid) != session:
                continue
            scope = "session"
        else:
            continue
        found.append({"kind": "process", "pid": pid, "elapsed": elapsed, "scope": scope, "command": redact.redact(command)[:200]})
    return found


def ask_states(main_wal: Path) -> dict:
    """{ask id: "open" | "resolved"} from the session main WAL (an `ask` entry, closed by `ask_resolved --ref`)."""
    states = {}
    try:
        with open(main_wal, "rb") as handle:
            for raw in handle:
                if b'"ask' not in raw:
                    continue
                try:
                    rec = json.loads(raw)
                except ValueError:
                    continue
                if not isinstance(rec, dict):
                    continue
                if rec.get("event") == "ask" and ASK_ID_RE.match(str(rec.get("id") or "")):
                    states.setdefault(rec["id"], "open")
                elif rec.get("event") == "ask_resolved" and ASK_ID_RE.match(str(rec.get("ref") or "")):
                    states[rec["ref"]] = "resolved"
    except OSError:
        pass
    return states


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


def deadlines(home: Path, session: str, now: float, ledger=None) -> list:
    """Deadlines of a session from the ah ledger (G3): [{id, due, ref, owner, note, state: open|due|missed|done}]."""
    rows, done = {}, set()
    for r in (ledger if ledger is not None else _ledger(home)):
        a = r.get("args") or {}
        if a.get("session") != session:
            continue
        if r.get("op") == "deadline.add":
            did = "dl" + hashlib.sha256(r["key"].encode()).hexdigest()[:10]
            rows[did] = {"id": did, "due": parse_ts(a.get("at")) or 0.0, "ref": a.get("ref"), "owner": a.get("owner"),
                         "note": a.get("note")}
        elif r.get("op") == "deadline.done":
            done.add(a.get("id"))
    out = []
    for d in rows.values():
        if d["id"] in done:
            d["state"] = "done"
        elif now >= d["due"]:
            d["state"] = "missed"
        elif d["due"] - now <= 3600:
            d["state"] = "due"
        else:
            d["state"] = "open"
        d["due_iso"] = iso(d["due"])
        out.append(d)
    return sorted(out, key=lambda d: d["due"])


HANDOFF_ACK_S = 3600  # a handoff nobody acknowledged within this window is a drop in disguise (I9)


def pending_stops(home: Path, session: str, ledger=None) -> dict:
    """agent id -> epoch of the latest task.pending row (a stop with pending work, I7)."""
    out = {}
    for r in (ledger if ledger is not None else _ledger(home)):
        a = r.get("args") or {}
        if r.get("op") == "task.pending" and a.get("session") == session:
            out[a["agent"]] = max(out.get(a["agent"], 0.0), parse_ts(a.get("at")) or 0.0)
    return out


def dispositions(home: Path, session: str, ledger=None) -> dict:
    """agent id -> latest applied disposition row for that session (from the ah ledger, the only writer)."""
    out = {}
    for r in (ledger if ledger is not None else _ledger(home)):
        a = r.get("args") or {}
        if r.get("op") == "task.dispose" and a.get("session") == session:
            d = {"kind": a.get("kind"), "at": parse_ts(a.get("at")) or 0.0, "ref": a.get("ref"),
                 "reason": a.get("reason"), "evidence": a.get("evidence"), "seq": r.get("seq")}
            for k in ("deployed", "live_test", "gate_epoch", "ack_handoff"):
                if a.get(k):
                    d[k] = a[k]
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


# ------------------------------------------------------------------ dispose guard (goodqa#14791, the 19-owner loop)

REASON_MIN = 40  # characters of a closing reason
REASON_MIN_WORDS = 6  # different words in it
REASON_REPEAT_S = 7 * 86400  # a normalized reason may not repeat another owner's within this window
CLOSE_BURST_MAX = 3  # distinct owners one actor may try to close ...
CLOSE_BURST_WINDOW_S = 600  # ... within this window; the next one is refused as a possible bulk close
LIVE_TEST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
DEPLOY_EVENTS = {"deploy", "release", "install"}
DEPLOY_NOTE_RE = re.compile(r"^\s*(DEPLOYED|INSTALLED|RELEASED)\b")
SHA_RE = re.compile(r"\b[0-9a-f]{7,40}\b")
VERSION_RE = re.compile(r"\bv?\d+\.\d+(?:\.\d+)?\b")
LIVE_RE = re.compile(r"\b(live|production|prod)\b|https?://(?!(?:localhost|127\.|0\.0\.0\.0|\[::1\]))", re.I)
NOT_LIVE_RE = re.compile(r"https?://(?:localhost|127\.|0\.0\.0\.0|\[::1\])", re.I)
# A note that says it was not live does not prove live, whatever else it says (spec_flow.NOT_LIVE_WORDS_RE is the twin).
NOT_LIVE_WORDS_RE = re.compile(r"\b(?:not|never|isn't|wasn't|aren't|weren't)\s+(?:(?:yet|on|in|to|the|deployed|released)\s+)*"
                               r"(?:live|prod|production)\b|\b(?:staging|pre-?prod(?:uction)?|locally|local[- ]only|dry[- ]run)\b",
                               re.I)
GUARDED_KINDS = ("closed", "superseded", "wontdo", "legacy")
GUARD_FIELDS = ("deploy_specific", "live_specific", "gate_epoch", "owner_last", "ref_checked", "deploy_at")
WAL_SCAN_MAX = 64 * 1024 * 1024  # bytes of a session's WALs searched for one evidence id


def ring_host() -> str:
    """The host name ahd uses for its ring rows (ahd.host()); one definition so ring_state matches."""
    return socket.gethostname().split(".")[0]


def _ring_alert(home: Path, key: str, severity: str, message: str, detail: dict) -> None:
    """Raise one alert in the shared ops ring as source "ah", unless the same key is already raised. Best effort."""
    try:
        import ops_watch  # noqa: PLC0415
        ring = home / ".agent-harness" / "state" / "alerts.jsonl"
        latest = None
        for e in ops_watch.read_ring(ring):
            if e.get("source") == "ah" and e.get("key") == key and e.get("host") == ring_host():
                latest = e
        if latest and latest.get("event") == "raise" and latest.get("severity") == severity:
            return
        ops_watch.emit({"host": ring_host(), "source": "ah", "event": "raise", "severity": severity, "key": key,
                        "message": message, "detail": detail}, path=ring)
    except Exception:  # noqa: BLE001 - the refusal stands even when the ring cannot be written
        pass


def gate_epoch(home: Path, ledger=None):
    """When the dropped-owner gate was installed on this host (epoch seconds), or None when unknown. install.py writes
    the marker once; the earliest epoch a legacy row already used is pinned, so moving the marker cannot widen legacy."""
    vals = []
    p = home / ".agent-harness" / "state" / "dropped-gate" / "installed_at.json"
    try:
        st = os.lstat(p)
        if st.st_size <= 4096 and (st.st_mode & 0o170000) == 0o100000:
            v = parse_ts(json.loads(p.read_text()).get("at"))  # input-ok: 4 KiB regular file, checked above
            if v:
                vals.append(v)
    except (OSError, ValueError, AttributeError):
        pass
    for r in (ledger if ledger is not None else _ledger(home)):
        a = r.get("args") or {}
        if r.get("op") == "task.dispose" and a.get("kind") == "legacy" and parse_ts(a.get("gate_epoch")):
            vals.append(parse_ts(a["gate_epoch"]))
    return min(vals) if vals else None


def _norm_ticket(project, number) -> str:
    return f"GoodQA {(project or 'goodqa').lower()}#{int(number)}"


def _tickets_in(text: str) -> set:
    out = set()
    for m in re.finditer(r"(?:GoodQA\s+([a-z0-9-]+)\s*#|\b([a-z][a-z0-9-]*)#|GoodQA\s+#|(?<![\w#])#)(\d{1,10})\b",
                         text or "", re.I):
        out.add(_norm_ticket(m.group(1) or m.group(2), m.group(3)))
    return out


def _owner_context(home: Path, session: str, agent: str, ledger: list, task: str | None = None) -> dict:
    """What evidence may name to be about this owner: its id, its registered task, and its tickets."""
    ctx = {"agent": agent, "tasks": {task.lower()} if task and len(task) >= 4 else set(), "tickets": set(),
           "branch": None, "repo": None}
    for r in ledger:
        a = r.get("args") or {}
        if r.get("op") == "task.register" and (a.get("owner_agent") == agent or (task and a.get("task") == task)) \
                and a.get("session") == session:
            if len(a.get("task") or "") >= 4:
                ctx["tasks"].add(a["task"].lower())
            ctx["tickets"] |= _tickets_in(a.get("ticket") or "")
            ctx["branch"], ctx["repo"] = a.get("branch") or ctx["branch"], a.get("worktree") or ctx["repo"]
    path = _wal_path(home, session, agent)
    if not path.is_file():
        path = session_dir(home, session) / f"{agent}.jsonl"  # a task-named WAL
    if path.is_file():
        try:
            for t in summarize_agent_wal(path, state_dir(home, "ah-index")).get("tickets") or []:
                ctx["tickets"] |= _tickets_in(t)
        except Exception:  # noqa: BLE001 - a WAL we cannot summarize gives no tickets, never a pass
            pass
    return ctx


def _names_owner(text: str, ctx: dict):
    """"id" or "task" when the text names this owner specifically, "ticket" when only through a shared ticket."""
    text = text or ""
    agent = ctx["agent"]
    for tok in re.findall(r"[A-Za-z0-9][A-Za-z0-9._-]*", text):
        t = tok.rstrip("._-")
        if t == agent or (len(t) >= 8 and re.fullmatch(r"a[0-9a-f]{7,}", agent) and agent.startswith(t)):
            return "id"
        if t.lower() in ctx["tasks"]:
            return "task"
    return "ticket" if _tickets_in(text) & ctx["tickets"] else None


def _git(repo: str, *argv, timeout: float = 10.0):
    env = {**os.environ, "GIT_OPTIONAL_LOCKS": "0"}
    return subprocess.run(["git", "-C", repo, *argv], capture_output=True, text=True, timeout=timeout, env=env)


def _sha_contains_branch(ctx: dict, sha: str) -> None:
    """A deployed sha must contain the owner's registered branch tip; otherwise what is live predates its work."""
    branch, repo = ctx["branch"], ctx["repo"]
    if not re.fullmatch(r"[A-Za-z0-9._/-]{1,200}", branch) or ".." in branch:
        raise AhError("evidence", f"registered branch {branch!r} is not a plain branch name", 3)
    try:
        full = _git(repo, "rev-parse", "--verify", "--quiet", f"{sha}^{{commit}}")
        tip = None
        for ref in (f"refs/heads/{branch}", f"refs/remotes/origin/{branch}"):
            r = _git(repo, "rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}")
            if r.returncode == 0:
                tip = r.stdout.strip()
                break
        if full.returncode != 0 or not tip:
            raise AhError("evidence", f"deployed {sha} or branch {branch} is not in the registered checkout {repo}", 3)
        if _git(repo, "merge-base", "--is-ancestor", tip, full.stdout.strip()).returncode != 0:
            raise AhError("evidence", f"deployed {sha} does not contain {branch}: what is live predates this owner's work", 3)
    except (OSError, subprocess.SubprocessError):
        raise AhError("evidence_unverifiable", f"git could not read {repo}", 3)


def _session_entries(home: Path, session: str, match):
    """WAL entries of the session (any of its WALs) for which match(raw bytes, record) is true, oldest first."""
    seen, out = 0, []
    for f in sorted(session_dir(home, session).glob("*.jsonl")):
        try:
            if not os.path.isfile(f) or os.path.islink(f):
                continue
            with open(f, "rb") as handle:
                for raw in handle:
                    seen += len(raw)
                    if seen > WAL_SCAN_MAX:
                        raise AhError("evidence_unverifiable", "the session's WALs are too large to search", 3)
                    rec = match(raw)
                    if rec is not None:
                        out.append(rec)
        except OSError:
            continue
    return sorted(out, key=lambda r: parse_ts(r.get("at")) or 0.0)


def _by_id(wid: str):
    def match(raw):
        if wid.encode() not in raw:
            return None
        try:
            rec = json.loads(raw)
        except ValueError:
            return None
        return rec if isinstance(rec, dict) and rec.get("id") == wid else None
    return match


def _by_test(tid: str):
    head = f"REALLY_TESTED {tid}:"

    def match(raw):
        if head.encode() not in raw:
            return None
        try:
            rec = json.loads(raw)
        except ValueError:
            return None
        return rec if isinstance(rec, dict) and str(rec.get("note") or "").startswith(head) else None
    return match


def _deploy_record(home: Path, session: str, wid: str, ctx: dict) -> tuple:
    """(record, how it names the owner): a deploy, install or release record about this owner, with a sha or version."""
    recs = _session_entries(home, session, _by_id(wid))
    if not recs:
        raise AhError("evidence", f"deploy record {wid} is not in this session's WALs", 3)
    rec = recs[-1]
    note = str(rec.get("note") or "")
    if not (rec.get("event") in DEPLOY_EVENTS or DEPLOY_NOTE_RE.match(note)):
        raise AhError("evidence", f"{wid} is a {rec.get('event')!r} entry, not a deploy record (event deploy, release or "
                                  "install, or a note starting DEPLOYED, INSTALLED or RELEASED); merged is not live", 3)
    shas, version = SHA_RE.findall(note), VERSION_RE.search(note)
    if not (shas or version):
        raise AhError("evidence", f"deploy record {wid} names no deployed sha or version", 3)
    named = _names_owner(note, ctx)
    if not named:
        raise AhError("evidence", f"deploy record {wid} does not name {ctx['agent']}, its task or its ticket", 3)
    if ctx["branch"] and ctx["repo"] and shas:
        _sha_contains_branch(ctx, shas[0])
    return rec, named


def _live_test(home: Path, session: str, tid: str, ctx, after: float) -> tuple:
    """(record, how it names the owner): the latest REALLY_TESTED run of tid, against a live target, after the deploy.
    ctx None skips the naming check (task.done: the test must already sit in the task's own WALs)."""
    recs = _session_entries(home, session, _by_test(tid))
    if not recs:
        raise AhError("evidence", f"no REALLY_TESTED {tid} entry in this session's WALs", 3)
    rec = recs[-1]
    note = str(rec.get("note") or "")
    if NOT_LIVE_RE.search(note) or not LIVE_RE.search(note):
        raise AhError("evidence", f"REALLY_TESTED {tid} does not name a live target (live, production, or a non-local "
                                  "URL); a local test is not done", 3)
    said = NOT_LIVE_WORDS_RE.search(note)
    if said:
        raise AhError("evidence", f"REALLY_TESTED {tid} says {said.group(0)!r}: a run that was not on the live target is "
                                  "not done; cite the run against the live deployment", 3)
    if (parse_ts(rec.get("at")) or 0.0) < after:
        raise AhError("evidence", f"REALLY_TESTED {tid} ran before the deploy it would prove", 3)
    named = _names_owner(note, ctx) if ctx else "task"
    if not named:
        raise AhError("evidence", f"REALLY_TESTED {tid} does not name {ctx['agent']}, its task or its ticket", 3)
    return rec, named


_OWNER_VIEW_SCOPE: dict = {}


class owner_view_scope:
    """In-process only: lets the Stop gate's grandfather hand ah the owner view it just computed, so a legacy check of
    up to 50 owners reads the WALs once instead of once per owner (which can outrun the 15 s Stop timeout). The view
    is used only inside the `with` block and only for its (home, session); every other legacy check reads afresh."""
    def __init__(self, home: Path, session: str, doc: dict):
        self.key, self.doc = (str(home), session), doc

    def __enter__(self):
        _OWNER_VIEW_SCOPE[self.key] = self.doc
        return self

    def __exit__(self, *exc):
        _OWNER_VIEW_SCOPE.pop(self.key, None)
        return False


def _legacy_last_activity(home: Path, session: str, agent: str, now) -> float | None:
    doc = _OWNER_VIEW_SCOPE.get((str(home), session)) or owners(home, session, now=now)
    row = next((r for r in doc["owners"] if r["agent_id"] == agent), None)
    return parse_ts(row["last_activity"]) if row else None


def _dispose_preflight(home: Path, args: dict) -> dict:
    """Read-only checks before the store lock (WALs, git, the ticket API). Adds the guard fields."""
    args = dict(args)
    agent, session, kind = args["agent"], args["session"], args["kind"]
    ledger = _ledger(home)
    if kind == "legacy":
        epoch = gate_epoch(home, ledger)
        if not epoch:
            raise AhError("legacy", "task.dispose legacy: the gate's install time is unknown on this host "
                                    "(install.py writes it); legacy is only for owners that went quiet before the gate", 3)
        last = _legacy_last_activity(home, session, agent, parse_ts(args["at"]))
        if not last:
            raise AhError("legacy", f"task.dispose legacy: {agent} is not an owner in this session", 3)
        if last >= epoch:
            raise AhError("legacy", f"task.dispose legacy: {agent} was active at {iso(last)}, after the gate was installed "
                                    f"({iso(epoch)}); a drop since then needs a real disposition", 3)
        args.update(gate_epoch=iso(epoch), owner_last=iso(last))
        args.setdefault("reason", f"legacy: last activity {iso(last)} predates the dropped-owner gate ({iso(epoch)}); "
                                  "not verified")
        return args
    if kind in ("superseded", "wontdo"):
        found = _ticket_exists(args["ref"])
        if found is False:
            raise AhError("evidence", f"task.dispose {kind}: {args['ref']} does not exist", 3)
        if found is None:
            raise AhError("evidence_unverifiable", f"task.dispose {kind}: GoodQA could not confirm {args['ref']}; retry", 3)
        args["ref_checked"] = True
        return args
    ctx = _owner_context(home, session, agent, ledger)
    dep, dnamed = _deploy_record(home, session, args["deployed"], ctx)
    _lt, lnamed = _live_test(home, session, args["live_test"], ctx, parse_ts(dep.get("at")) or 0.0)
    args.update(deploy_specific=dnamed in ("id", "task"), live_specific=lnamed in ("id", "task"),
                deploy_at=str(dep.get("at") or ""))
    return args


def _reason_shape(reason: str, agent: str) -> str:
    s = (reason or "").lower().replace(agent.lower(), "<owner>")
    s = re.sub(r"\b[0-9a-f]{7,}\b", "<hex>", s)
    s = re.sub(r"#\d+", "#n", s)
    s = re.sub(r"\d+", "0", s)
    return re.sub(r"\s+", " ", s).strip(" .;:")


def _closing_checks(args: dict, ledger: list, now: float) -> None:
    """Under the store lock: shared evidence must name each owner, and no templated reasons."""
    agent = args["agent"]
    shape = _reason_shape(args.get("reason") or "", agent)
    for r in ledger:
        a = r.get("args") or {}
        if r.get("op") != "task.dispose" or a.get("kind") not in liveness.CLOSING or a.get("agent") == agent:
            continue
        if args["kind"] == "closed" and a.get("kind") == "closed":
            for field, specific in (("deployed", "deploy_specific"), ("live_test", "live_specific")):
                if a.get(field) and a.get(field) == args.get(field) and not args.get(specific):
                    raise AhError("evidence_reused", f"task.dispose closed: {field} {args[field]} already closed "
                                                     f"{a.get('agent')} and names this owner only through a shared "
                                                     "ticket; cite a record that names this owner", 3)
        at = parse_ts(r.get("received_at")) or 0.0
        if now - at < REASON_REPEAT_S and _reason_shape(a.get("reason") or "", a.get("agent") or "") == shape:
            raise AhError("reason", f"task.dispose {args['kind']}: this reason repeats the one used for {a.get('agent')}; "
                                    "say what you verified about this owner", 3)


def _audit_tail(home: Path, limit: int = 1024 * 1024) -> list:
    p = store_dir(home) / "audit.jsonl"
    try:
        with open(p, "rb") as handle:
            handle.seek(0, 2)
            size = handle.tell()
            handle.seek(max(0, size - limit))
            data = handle.read(limit)  # input-ok: bounded tail
    except OSError:
        return []
    out = []
    for raw in data.splitlines()[1 if size > limit else 0:]:
        try:
            row = json.loads(raw)
        except ValueError:
            continue
        if isinstance(row, dict):
            out.append(row)
    return out


def _close_burst(home: Path, args: dict, who: dict, now: float) -> None:
    """A burst of closes over many owners from one actor is refused and alerted (it is how 19 owners were cleared)."""
    tried = set()
    for row in _audit_tail(home):
        a = row.get("actor") or {}
        if row.get("op") == "task.dispose" and row.get("kind") in liveness.CLOSING and a.get("session") == who["session"] \
                and a.get("agent_id") == who["agent_id"] and now - (parse_ts(row.get("at")) or 0.0) < CLOSE_BURST_WINDOW_S:
            tried.add(row.get("agent"))
    tried.discard(None)
    if args.get("agent") in tried or len(tried) < CLOSE_BURST_MAX:
        return
    key = f"bulk-close:{who['session'][:8]}:{who['agent_id']}"
    _ring_alert(home, key, "high",
                f"possible bulk-close: {who['agent_id']} tried to close {len(tried) + 1} owners within "
                f"{CLOSE_BURST_WINDOW_S // 60} min in session {who['session'][:8]}; refused (goodqa#14791)",
                {"session": who["session"], "actor": who["agent_id"], "owners": sorted(tried | {args.get("agent")})[:20]})
    raise AhError("bulk_close", f"task.dispose: {len(tried)} other owners were closed or tried within "
                                f"{CLOSE_BURST_WINDOW_S // 60} min; closing owners in bulk is refused. Verify each one, "
                                "and resume, reassign or name a wait for the rest", 3)


def _audit_reject(home: Path, op: str, key, session, code: str, tag: dict) -> None:
    with StoreLock(home):
        _append_line(store_dir(home) / "audit.jsonl", {"at": iso(time.time()), "op": op, "key": key or "",
                                                       "actor": actor(session), "result": "rejected", "code": code, **tag})


WAIT_MAX_S = 7 * 86400  # a named wait expires within a week; it is renewed, never parked for years (review M-b)
WAIT_UNVERIFIED_MAX_S = 86400  # when GoodQA cannot confirm the ticket a wait names


def _ticket_exists(ref: str):
    """True or False from GoodQA; None when it cannot be reached."""
    try:
        ticket_get(ref)
        return True
    except AhError as e:
        return False if e.code == "not_found" else None
    except Exception:  # noqa: BLE001 - no adapter, no key, no network: unknown, never "exists"
        return None


SERVER_STAMPED_OPS = ("task.dispose", "task.pending")
SERVER_STAMPED_FIELDS = ("at", "ref_unverified")


def server_now() -> str:
    """The writer's clock for stamped ops. No environment override: a caller-chosen time is a gate bypass
    (a forward-dated resumed would be live forever). Tests patch this function."""
    return iso(time.time())


def write(home: Path, op: str, args: dict, session: str, key: str | None = None) -> dict:
    if op == "task.dispose":
        args = {k: v for k, v in args.items() if k not in GUARD_FIELDS}  # only ah sets these
    if op in ("task.dispose", "task.pending", "deadline.add"):
        stamped = {k: v for k, v in args.items() if k != "ref_unverified"}  # set only here
        if op != "deadline.add":
            stamped["at"] = server_now()  # never the caller's clock (M4): a backdated disposition cannot be forged
        if op == "task.dispose" and stamped.get("kind") == "waiting" and TICKET_RE.match(stamped.get("ref") or ""):
            found = _ticket_exists(stamped["ref"])
            if found is False:
                raise AhError("bad_request", f"task.dispose waiting: {stamped['ref']} does not exist", 3)
            if found is None:
                stamped["ref_unverified"] = True
        args = stamped
    tag = {"kind": args.get("kind"), "agent": args.get("agent")} if op == "task.dispose" else {}
    guarded = op == "task.dispose" and args.get("kind") in GUARDED_KINDS
    try:
        if op == "task.dispose" and args.get("ack_handoff"):
            import caller_identity  # noqa: PLC0415
            # #134 red-team B4: AH_AGENT_ID is not set by any launcher, so the self-ack check below cannot be the
            # control. A main payload's hook stamps this agent; anything else (a sub-agent, Codex, a script) has none.
            if caller_identity.take_stamp("ack-handoff", [args.get("agent")], home=home) is None:
                raise AhError("forbidden", "task.dispose --ack-handoff: only the main agent acknowledges a handoff (its "
                                           "hook stamps the call); none was found for " + str(args.get("agent")), 3)
        if op == "task.dispose" and (args.get("kind") in ("resumed", "reassigned") + GUARDED_KINDS
                                     or args.get("ack_handoff")) \
                and actor_id() == args.get("agent"):  # first, so an owner's self-ack is named as such
            raise AhError("forbidden", f"task.dispose {args['kind']}: an owner cannot acknowledge itself; main records it "
                                       "(waiting is allowed)", 3)
        if guarded and args.get("kind") in liveness.CLOSING:
            _close_burst(home, args, actor(session), time.time())  # first: a burst is refused whatever its arguments
        precheck(op, args)
    except AhError as e:
        if guarded:
            _audit_reject(home, op, key, session, e.code, tag)
        raise
    legacy_args = args  # the spelling earlier builds hashed and keyed (kept so retries across the upgrade still match)
    if args.get("ticket"):
        args = dict(args, ticket=canonical_ref(args["ticket"]))  # one spelling in the key, the ledger and the spool
    import redact
    if isinstance(args.get("source"), str):
        import wal_note
        if wal_note.SECRET_PATTERN.search(args["source"]):
            raise AhError("bad_request", "source appears to contain a credential; cite it without the secret", 2)
    args = {k: (v if k == "source" else _redact_args(v, redact.redact)) for k, v in args.items()}  # source is checked as typed
    legacy_args = {k: (v if k == "source" else _redact_args(v, redact.redact)) for k, v in legacy_args.items()}
    if guarded:
        try:
            args = _dispose_preflight(home, args)
        except AhError as e:
            _audit_reject(home, op, key, session, e.code, tag)
            raise
    explicit = key is not None
    key = key or derive_key(op, args, session)
    if not KEY_RE.match(key):
        raise AhError("bad_request", "idempotency key must be 8-128 chars of [A-Za-z0-9._:-]")

    def unstamped(a):  # a retry at a later second, or after GoodQA reachability flipped, is the same request:
        # duplicate, not key_conflict (round 5, minor 4)
        return {k: v for k, v in a.items() if not (op in SERVER_STAMPED_OPS and k in SERVER_STAMPED_FIELDS)}
    body_sha = hashlib.sha256(canonical([op, unstamped(args)]).encode()).hexdigest()
    shas = {body_sha, hashlib.sha256(canonical([op, unstamped(legacy_args)]).encode()).hexdigest()}
    keys = {key} if explicit else {key, derive_key(op, legacy_args, session)}
    if args.get("ticket") and (op == "ticket.comment" or (op == "task.status" and "ticket" in legacy_args)):
        if not any(r.get("key") in keys and r.get("state", "applied") == "applied" for r in _ledger(home)):
            check_ticket_exists(args["ticket"])  # a retry of an applied write needs no network
    who = actor(session)
    audit = store_dir(home) / "audit.jsonl"
    with StoreLock(home):
        everything = _ledger(home, include_intents=True)
        ledger = [r for r in everything if r.get("state", "applied") == "applied"]
        intent = None
        for row in everything:
            if row.get("key") in keys:
                key = row["key"]  # an intent or applied row from the previous build keeps its own key and operation id
                if row.get("sha") not in shas:
                    _append_line(audit, {"at": iso(time.time()), "op": op, "key": key, "actor": who,
                                         "result": "key_conflict", **tag})
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
                                 "result": "rejected", "code": e.code, **tag})
            raise
        except Exception as e:  # never an unaudited traceback
            _append_line(audit, {"at": iso(time.time()), "op": op, "key": key, "actor": who,
                                 "result": "rejected", "code": "internal", **tag})
            raise AhError("internal", f"{type(e).__name__} while applying {op}", 3)
        rid = "ah" + hashlib.sha256(key.encode()).hexdigest()[:10]
        _append_line(store_dir(home) / "ledger.jsonl", {
            "state": "applied", "seq": seq, "id": rid, "key": key, "sha": body_sha, "op": op, "args": args, "actor": who,
            "received_at": iso(time.time())})
        _append_line(audit, {"at": iso(time.time()), "op": op, "key": key, "actor": who, "result": "applied", "seq": seq,
                             **tag})
    reply = {"ok": True, "result": "applied", "id": rid, "seq": seq, "key": key}
    reply.update(out)
    if out.get("comment") == "pending":  # post now, outside the lock; on failure it stays spooled for the next drain
        opid = operation_id(key)
        try:
            spool_drain(home, only_opid=opid)  # only this write's job: other queued jobs never delay or colour this reply
        except Exception:
            pass  # the job stays spooled and the reply says pending; the write itself is applied
        tag = hashlib.sha256(opid.encode()).hexdigest()[:16]
        spool = store_dir(home) / "spool"
        if list(spool.glob(f"*-{tag}.json")):
            reply["comment"] = "pending"
        elif list((spool / "dead").glob(f"*-{tag}.json")):
            reply["comment"] = "dead"  # the ticket does not exist; nothing was posted
        elif list((spool / "parked").glob(f"*-{tag}.json")):
            reply["comment"] = "parked"  # not visible to this credential yet; `ah spool retry` after access is fixed
        else:
            reply["comment"] = "posted"
        try:
            spool_drain(home, limit=2, budget_s=10.0)  # a little of the backlog, bounded; ahd drains the rest
        except Exception:  # best effort: it must never turn this caller's applied write into a failure
            pass
    return reply


# ------------------------------------------------------------------ rendering and CLI

def fmt_age(s):
    if s is None:
        return "-"
    s = int(s)
    return f"{s // 3600}h{(s % 3600) // 60:02d}m" if s >= 3600 else f"{s // 60}m" if s >= 60 else f"{s}s"


def recent_owners(data: dict) -> dict:
    """The CLI default view: every row that is live, waiting, silent, dropped or needs a decision, plus terminal rows
    (done, handoff, returned, helpers) that ended within OWNERS_RECENT_S. counts and undisposed still cover every row;
    `hidden` says how many rows --all would add. Library callers (ops_watch, dropped_gate) use owners() unfiltered."""
    def keep(r):
        if r.get("decision_required") or r.get("state") not in TERMINAL_STATES:
            return True
        return r.get("idle_s") is not None and r["idle_s"] <= OWNERS_RECENT_S
    rows = [r for r in data["owners"] if keep(r)]
    return dict(data, owners=rows, hidden=len(data["owners"]) - len(rows), filter=f"recent<={OWNERS_RECENT_S // 3600}h")


def render_text(cmd: str, data: dict) -> str:
    if cmd == "owners":
        lines = [f"session {data['session']}  " + " ".join(f"{k}={v}" for k, v in sorted(data["counts"].items()))
                 + (f"  hidden={data['hidden']} (terminal rows idle over {OWNERS_RECENT_S // 3600} h; --all shows them)"
                    if data.get("hidden") else "")]
        for r in data["owners"]:
            lines.append(f"{r['state']:<14} idle {fmt_age(r['idle_s']):>7}  {r['agent_id'][:12]:<12} {r['type'] or '-':<12} "
                         f"{(r['ticket'] or '-'):<18} c-age {fmt_age(r['ticket_comment_age_s']):>6}  {(r['task'] or '')[:70]}")
        return "\n".join(lines)
    if cmd == "user-msg":
        lines = []
        for m in data["matches"]:
            lines.append(f"{m['id']}  [{m['kind']}] {m['timestamp']}  {m['preview']}")
            lines.append("  " + (m.get("source_arg") or "source unavailable: " + m.get("source_error", "choose an exact excerpt")))
        return "\n".join(lines) or "no match"
    if cmd == "disk":
        lines = [f"{data['host']} ({data.get('os', '?')}) capacity volume: {data.get('capacity_volume')}"]
        for v in data["volumes"]:
            lines.append(f"  {v['path']:<24} {v['used_pct']:>5}% used  {v['avail_bytes'] / 2**30:7.1f} GiB free  [{v['role']}]")
        for e in (data.get("top") or {}).get("entries", []):
            lines.append(f"    {(e['bytes'] or 0) / 2**30:8.2f} GiB  {e['path']}" + ("  (timed out)" if e.get("timed_out") else ""))
        return "\n".join(lines)
    return json.dumps(data, indent=2)


def nearest_source(wal: Path, before_id: str | None = None) -> dict | None:
    """The newest sourced scope/decision/requirement/ask entry of `wal` (before `before_id` when given): a wal: source
    that follows that entry's own source, so a re-cited note never invents provenance (goodqa#14791 P11)."""
    import safe_input  # noqa: PLC0415
    try:
        tail = safe_input.read_tail(wal, 4 << 20)
    except Exception:  # noqa: BLE001
        return None
    rows = []
    for raw in tail.splitlines():
        try:
            rec = json.loads(raw)
        except ValueError:
            continue
        if isinstance(rec, dict) and rec.get("id"):
            rows.append(rec)
    cut = len(rows)
    if before_id:
        for i, rec in enumerate(rows):
            if rec.get("id") == before_id:
                cut = i
                break
    for rec in reversed(rows[:cut]):
        if rec.get("event") in ("scope", "decision", "requirement", "ask") and rec.get("source") and not rec.get("unsourced"):
            return {"id": rec["id"], "event": rec["event"], "source": f"wal:{wal}#{rec['id']}",
                    "note80": str(rec.get("note") or "")[:80], "assumption": bool(rec.get("assumption"))}
    return None


def note_cmd(home: Path, args) -> dict:
    wal = Path(args.wal).expanduser()
    text = args.note
    if args.id and not ASK_ID_RE.match(args.id):
        raise AhError("bad_request", "note: --id must be a WAL entry id (w + 11 hex)")
    if args.id:  # re-cite an existing quarantined entry: its event kind is kept; its text unless --note overrides
        import safe_input  # noqa: PLC0415
        for raw in (safe_input.read_tail(wal, 4 << 20).splitlines() if wal.is_file() else []):
            try:
                rec = json.loads(raw)
            except ValueError:
                continue
            if isinstance(rec, dict) and rec.get("id") == args.id:
                text = f"[re-cites {args.id}] " + str(args.note or rec.get("note") or "")
                args.event = rec.get("event") or args.event
    if not text:
        raise AhError("bad_request", "note: --note text or --id of an existing entry is required")
    source = args.source
    picked = None
    if source == "auto":
        picked = nearest_source(wal, args.id)
        if not picked:
            raise AhError("no_source", "note: no sourced scope/decision/requirement/ask ancestor in this WAL; cite the user turn "
                                       "(ah user-msg), a ticket, or write it as an assumption with --source 'inferred: ...'", 2)
        # auto never mints provenance: the nearest sourced ancestor is a guess about relation, so it is an assumption (M4)
        source = f"inferred: from {picked['source']} -- auto-picked nearest sourced ancestor" + (
            " (itself an assumption)" if picked["assumption"] else "")
    plan = {"ok": True, "dry_run": bool(args.dry_run), "wal": str(wal), "event": args.event, "source": source,
            "ancestor": picked, "note": text[:200]}
    if args.dry_run:
        return plan
    argv = [sys.executable, str(Path(__file__).resolve().parent / "wal_note.py"), "--wal", str(wal), "--event", args.event,
            "--note", text, "--source", source] + (["--recites", args.id] if args.id else [])
    r = subprocess.run(argv, capture_output=True, text=True, timeout=60)
    plan["wal_note_rc"] = r.returncode
    try:
        plan["written"] = json.loads(r.stdout.strip().splitlines()[-1]) if r.stdout.strip() else None
    except ValueError:
        plan["written"] = None
    if r.returncode != 0:
        plan["ok"] = False
        plan["stderr"] = r.stderr[-300:]
        try:  # wal_note refused (rejected source: nothing written); surface its problem instead of a bare stderr tail
            refusal = json.loads((r.stderr.strip().splitlines() or ["{}"])[-1])
        except ValueError:
            refusal = {}
        if isinstance(refusal, dict) and refusal.get("status") == "REFUSED":
            plan["refused"] = True
            plan["problem"] = str(refusal.get("problem") or "")[:300]
    elif isinstance(plan.get("written"), dict) and plan["written"].get("warnings"):
        plan["ok"] = False  # written, but quarantined: the source did not resolve here (M2); say so instead of ok
        plan["quarantined"] = True
        plan["warnings"] = plan["written"]["warnings"]
    return plan


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


def heartbeat_beat(home: Path, service: str, key: str | None = None) -> dict:
    """Write ~/.agent-harness/state/<service>/heartbeat.json (atomic replace, 0600). Deliberately not ledgered: ahd
    beats once a minute on every host, and the file's mtime is what ahd_running_check and the deadman read."""
    if not isinstance(service, str) or not SERVICE_RE.match(service):
        raise AhError("bad_request", "heartbeat beat: --service must be lowercase letters, digits and dashes")
    if key is not None and not KEY_RE.match(key):
        raise AhError("bad_request", "idempotency key must be 8-128 chars of [A-Za-z0-9._:-]")
    d = home / ".agent-harness" / "state" / service
    d.mkdir(parents=True, exist_ok=True, mode=0o700)
    at = iso(time.time())
    body = json.dumps({"service": service, "host": socket.gethostname().split(".")[0], "at": at,
                       "pid": os.getppid(), "key": key}, sort_keys=True) + "\n"
    tmp = d / f".heartbeat.{os.getpid()}.tmp"
    fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0), 0o600)
    try:
        os.write(fd, body.encode())
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(tmp, d / "heartbeat.json")
    return {"ok": True, "result": "applied", "service": service, "at": at}


def apply_batch(home: Path, text: str, session) -> dict:
    """`ah apply --batch -`: JSON lines {"op", "key", "args"} as ahd.send builds them. Only APPLY_OPS. Every line is
    parsed and prechecked before any is written, so a bad line rejects the batch with nothing applied; each line
    then goes through write(), so a replay of the same keys after a kill mid-tick reports duplicates."""
    if len(text.encode("utf-8", "replace")) > APPLY_MAX_BYTES:
        raise AhError("bad_request", f"apply: batch over {APPLY_MAX_BYTES} bytes")
    lines = [ln for ln in text.splitlines() if ln.strip()]
    if not lines or len(lines) > APPLY_MAX_LINES:
        raise AhError("bad_request", f"apply: a batch holds 1-{APPLY_MAX_LINES} lines")
    plan = []
    for n, ln in enumerate(lines, 1):
        try:
            row = json.loads(ln)
        except ValueError:
            raise AhError("bad_request", f"apply: line {n} is not JSON")
        if not isinstance(row, dict) or row.get("op") not in APPLY_OPS or not isinstance(row.get("args"), dict) \
                or not isinstance(row.get("key"), str) or not KEY_RE.match(row["key"]):
            raise AhError("bad_request", f"apply: line {n} must be {{op: {'|'.join(APPLY_OPS)}, key, args}}")
        precheck(row["op"], row["args"])
        plan.append(row)
    counts = {"applied": 0, "duplicate": 0}
    for row in plan:
        res = write(home, row["op"], row["args"], session, row["key"])
        counts[res.get("result", "applied")] = counts.get(res.get("result", "applied"), 0) + 1
    return dict({"ok": True, "lines": len(plan)}, **counts)


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


# ------------------------------------------------------------------ asks / requirements / sessions (read-only views)

STALE_ASK_S = 24 * 3600
VIEW_ROW_CAP = 2000
VIEW_BUDGET_S = 8.0  # wall-clock budget per view; newest sessions first, then say truncated


def _view_sessions(home: Path, session, every: bool) -> list:
    if every:
        return [s for s, _ in list_sessions(home)]
    s = session or env_session() or newest_session(home)
    if not s or not SESSION_RE.match(s):
        raise AhError("session_unknown", "no session: pass --session or --all")
    return [s]


def list_sessions(home: Path) -> list:
    """(session id, main WAL mtime) newest first; only directories with a main WAL."""
    out = []
    try:
        for entry in os.scandir(wal_dirs(home)):
            main = Path(entry.path) / "main.jsonl"
            if SESSION_RE.match(entry.name) and main.is_file():
                out.append((entry.name, main.stat().st_mtime))
    except OSError:
        pass
    return sorted(out, key=lambda x: -x[1])


def sessions_view(home: Path) -> dict:
    return {"generated": iso(time.time()),
            "sessions": [{"session": s, "last_activity": iso(m)} for s, m in list_sessions(home)]}


def _epoch(text):
    try:
        t = dt.datetime.fromisoformat(str(text).replace("Z", "+00:00"))
        return (t if t.tzinfo else t.replace(tzinfo=dt.timezone.utc)).timestamp()  # naive stamps are UTC, as in parse_ts
    except (ValueError, TypeError):
        return None


def asks_view(home: Path, session=None, every: bool = False, now=None) -> dict:
    """Every ask with its state. State: open | stale (open > 24 h) | resolved | assumption | blocked (untraceable)."""
    import redact
    prov = _prov()
    now = time.time() if now is None else now
    rows, total, limited = [], 0, False
    deadline = time.monotonic() + VIEW_BUDGET_S
    for s in _view_sessions(home, session, every):
        if time.monotonic() > deadline:
            limited = True
            break
        try:
            records = prov.ledger(s, home / ".claude")
        except Exception:  # one unreadable session must not hide the others
            continue
        per_wal = {}
        for rec in records:
            per_wal[rec["_wal"]] = per_wal.get(rec["_wal"], 0) + 1
        # the shared reader reads at most MAX_HITS ask and MAX_HITS ask_resolved lines per WAL: later ones are unseen
        limited = limited or any(n >= prov.MAX_HITS for n in per_wal.values())
        for rec in records:
            total += 1
            if time.monotonic() > deadline:
                limited = True
            if len(rows) >= VIEW_ROW_CAP:
                continue
            closed = rec.get("_closed")
            at = _epoch(rec.get("at"))
            age = int(now - at) if at else None
            label, state = None, "open"
            if closed:
                state = "resolved"
            else:
                src = rec.get("source") or ""
                if src and time.monotonic() > deadline:
                    limited = True  # out of budget: no more resolves; the row is shown as unverified, never as traced
                    res = None
                else:
                    res = prov.resolve(src, {"home": home / ".claude", "want_text": True}) if src else None
                if res is None or not res.get("ok"):
                    state = "blocked"
                elif res.get("assumption"):
                    state = "assumption"
                elif rec.get("waiting_on_user"):
                    state = "waiting-on-user"
                elif age is not None and age > STALE_ASK_S:
                    state = "stale"
                label = res.get("label") if res else None
            rows.append({
                "id": str(rec.get("id"))[:40], "session": s,
                "text": redact.redact(str(rec.get("note") or ""))[:600],
                "why": redact.redact(str(rec.get("reason") or ""))[:400],
                "owner": Path(str(rec.get("_wal"))).stem,
                "source": redact.redact(str(rec.get("source") or ""))[:300], "source_label": label,
                "at": rec.get("at") or None, "age_s": age, "state": state,
                "resolved_at": (closed or {}).get("at"),
                "surfaced_count": rec.get("surfaced_count") if isinstance(rec.get("surfaced_count"), int) else None})
    return {"generated": iso(now), "asks": rows, "total": total, "truncated": limited or total > len(rows)}


def _clean_field(value, cap: int = 300):
    """Redacted, clipped text for a free-form WAL field; anything that is not text or a list of text is dropped."""
    import redact
    if isinstance(value, list):
        value = ", ".join(str(v) for v in value[:10] if isinstance(v, (str, int)))
    if not isinstance(value, (str, int)):
        return None
    return redact.redact(str(value))[:cap] or None


def requirements_view(home: Path, session=None, every: bool = False, now=None) -> dict:
    """Requirement entries (event=requirement) from the main WAL of each session, read with provenance's reader."""
    import redact
    prov = _prov()
    now = time.time() if now is None else now
    rows, total, limited = [], 0, False
    deadline = time.monotonic() + VIEW_BUDGET_S
    for s in _view_sessions(home, session, every):
        if time.monotonic() > deadline:
            limited = True
            break
        path = wal_dirs(home) / s / "main.jsonl"
        try:
            lines = list(prov._lines_containing(path, b'"event":"requirement"'))
        except Exception:
            continue
        limited = limited or len(lines) >= prov.MAX_HITS  # the shared reader stops at MAX_HITS lines: say so
        for line in lines:
            if line is None:
                continue
            try:
                rec = prov.loads_line(line)
            except ValueError:
                continue
            if not isinstance(rec, dict) or rec.get("event") != "requirement" or not isinstance(rec.get("id"), str) or not rec["id"]:
                continue
            total += 1
            if len(rows) >= VIEW_ROW_CAP:
                continue
            at = _epoch(rec.get("at"))
            rows.append({
                "id": str(rec.get("id") or "")[:40], "session": s,
                "text": redact.redact(str(rec.get("note") or ""))[:600],
                "source": redact.redact(str(rec.get("source") or ""))[:300],
                "at": rec.get("at") or None, "age_s": int(now - at) if at else None,
                "state": str(rec.get("state") or "recorded")[:20],
                "ticket": _clean_field(rec.get("ticket")), "owner": _clean_field(rec.get("owner")),
                "evidence": _clean_field(rec.get("evidence"))})
    return {"generated": iso(now), "requirements": rows, "total": total, "truncated": limited or total > len(rows)}


def build_parser():
    p = argparse.ArgumentParser(prog="ah", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--text", action="store_true", help="human summary instead of JSON")
    sub = p.add_subparsers(dest="cmd", required=True)
    o = sub.add_parser("owners")
    o.add_argument("--session")
    o.add_argument("--text", action="store_true", default=argparse.SUPPRESS, help="human summary (also accepted before the subcommand)")
    o.add_argument("--all", action="store_true", help=f"every row; the default hides terminal rows idle over {OWNERS_RECENT_S // 3600} h")
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
    tc = ts.add_parser("create", help="file a GoodQA ticket (idempotent on --key)")
    tc.add_argument("--project", required=True)
    tc.add_argument("--title", required=True)
    tc.add_argument("--body-file", required=True)
    tc.add_argument("--type", default="task")
    tc.add_argument("--priority")
    tc.add_argument("--key", help="idempotency key (default: hash of project, title and body)")
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
    dn.add_argument("--deployed", action="append", default=[], metavar="WID",
                    help="WAL id of the deploy, release or install record (done means deployed live and tested)")
    dp = ks.add_parser("dispose", help="record the decision for a DROPPED owner: resumed, reassigned, waiting or closed")
    dp.add_argument("--agent", required=True)
    dp.add_argument("--kind", required=True, choices=list(liveness.DISPOSITIONS))
    dp.add_argument("--ref", help="waiting: ask id or ticket; reassigned: replacement agent id")
    dp.add_argument("--until", help="waiting: ISO time when the wait expires")
    dp.add_argument("--ack-handoff", dest="ack_handoff", action="store_true",
                    help="waiting: main acknowledges this owner's handoff while the wait is live (main only)")
    dp.add_argument("--reason", help="closed, superseded, wontdo: what you verified about this owner (40+ characters)")
    dp.add_argument("--deployed", help="closed: WAL id of the deploy, release or install record naming this owner")
    dp.add_argument("--live-test", dest="live_test", help="closed: REALLY_TESTED id run against the live target")
    dp.add_argument("--evidence", help=argparse.SUPPRESS)  # retired: closed takes --deployed and --live-test
    for x in (r, st, dn, cc, dp):
        x.add_argument("--session")
        x.add_argument("--key", help="idempotency key (default: derived from the request)")
    for name in ("asks", "requirements"):
        v = sub.add_parser(name, help="read-only JSON view for the console")
        v.add_argument("--session")
        v.add_argument("--all", action="store_true", help="every session with a main WAL")
        v.add_argument("--json", action="store_true", help="accepted for symmetry; output is always JSON")
    sub.add_parser("sessions", help="sessions with a main WAL, newest first")
    dl = sub.add_parser("deadline", help="dated one-shot obligations (goodqa#14791 G3)")
    dls = dl.add_subparsers(dest="sub", required=True)
    da = dls.add_parser("add")
    da.add_argument("--at", required=True, help="ISO time it is due")
    da.add_argument("--ref", required=True, help="GoodQA ticket or ask id")
    da.add_argument("--owner", required=True)
    da.add_argument("--note", required=True)
    dd = dls.add_parser("done")
    dd.add_argument("--id", required=True)
    dd.add_argument("--note")
    dls.add_parser("list")
    for x in (da, dd):
        x.add_argument("--session")
        x.add_argument("--key")
    nt = sub.add_parser("note", help="write a WAL note through wal_note.py; --source auto picks the nearest sourced ancestor")
    nt.add_argument("--wal", required=True)
    nt.add_argument("--event", default="decision")
    nt.add_argument("--note", help="the note text (omit with --id to re-cite an existing quarantined entry)")
    nt.add_argument("--id", help="re-cite an existing unsourced entry of this WAL by id")
    nt.add_argument("--source", default="auto", help="a Source: string, or auto")
    nt.add_argument("--dry-run", action="store_true", help="print the Source that would be written; write nothing")
    sub.add_parser("doctor", help="check the import chain and file hashes of this install")
    sp = sub.add_parser("spool")
    sp.add_argument("action", choices=["drain", "ack", "retry"])
    sp.add_argument("jobs", nargs="*", help="ack: spool job file names (<ms>-<hash>.json)")
    sp.add_argument("--evidence", help="ack: why these jobs are settled (the delivered comment, the ticket); 10+ characters")
    hb = sub.add_parser("heartbeat", help="record a service heartbeat (ahd, goodqa#14848)")
    hb.add_argument("action", choices=["beat"])
    hb.add_argument("--service", required=True)
    hb.add_argument("--key")
    al = sub.add_parser("alert", help="raise or clear an alert in the ops-watch ring (ahd, goodqa#14848)")
    al.add_argument("action", choices=["raise", "clear"])
    al.add_argument("--alert-key", required=True)
    al.add_argument("--source", required=True)
    al.add_argument("--key")
    al.add_argument("--severity")
    al.add_argument("--message")
    al.add_argument("--detail", help="JSON object")
    al.add_argument("--session")
    ap = sub.add_parser("apply", help="apply a batch of alert ops from stdin (JSON lines)")
    ap.add_argument("--batch", required=True, choices=["-"])
    ap.add_argument("--session")
    w = sub.add_parser("write")
    ws = w.add_subparsers(dest="sub", required=True)
    wr = ws.add_parser("result")
    wr.add_argument("--key", required=True)
    wr.add_argument("--session")
    kp = sub.add_parser("kill", help="signal your own runaway processes: audited, with hard refusals (see ah_kill.py)")
    kp.add_argument("--pid", required=True, help="N[,N...]")
    kp.add_argument("--reason", required=True, help="why (mandatory, logged)")
    kp.add_argument("--tree", action="store_true", help="signal children first")
    kp.add_argument("--grace", type=float, default=10.0, help="seconds between SIGTERM and SIGKILL (default 10)")
    kp.add_argument("--host", help="run on dev2, t2-dev or ah-mac-mini over ssh")
    kp.add_argument("--foreign", action="store_true",
                    help="allow a process outside your worktree and process tree (audited; raises a high ops-watch notice)")
    kp.add_argument("--session")
    kp.add_argument("--agent", help="calling agent id for the audit row")
    kp.add_argument("--wal", help="caller WAL path (default: this session's main WAL)")
    kp.add_argument("--via", help=argparse.SUPPRESS)
    _no_abbrev(p)
    return p


def _no_abbrev(parser) -> None:
    """`--kin closed` must not mean `--kind closed`: the pretool gate matches flags as written (round 5, minor 1)."""
    parser.allow_abbrev = False
    for action in parser._actions:
        for child in (getattr(action, "choices", None) or {}).values() if isinstance(action, argparse._SubParsersAction) else ():
            _no_abbrev(child)


def session_of(args, home):
    return getattr(args, "session", None) or env_session()


def run(args, home: Path) -> dict:
    cmd = args.cmd
    if cmd == "owners":
        s = args.session or env_session() or newest_session(home)
        if not s or not SESSION_RE.match(s):
            raise AhError("session_unknown", "no session: pass --session")
        data = owners(home, s, comments=comment_age if args.comments else None)
        return data if args.all else recent_owners(data)
    if cmd == "asks":
        return asks_view(home, args.session, args.all)
    if cmd == "requirements":
        return requirements_view(home, args.session, args.all)
    if cmd == "sessions":
        return sessions_view(home)
    if cmd == "user-msg":
        s = args.session or env_session()
        if not s:  # never guess "the newest transcript": a running helper session would win
            raise AhError("session_unknown", "no session: pass --session or set CLAUDE_CODE_SESSION_ID")
        return user_msgs(home, s, text=args.search, recent=args.recent, full=args.full)
    if cmd == "disk":
        return disk(args.host, args.root, args.count, args.budget, not args.no_top)
    if cmd == "ticket":
        if args.sub == "create":
            import ah_ticket
            try:
                return ah_ticket.create(args.project, args.title, args.body_file, args.type, args.priority, args.key, home)
            except ah_ticket.TicketCreateError as e:
                raise AhError(e.code, str(e), e.exit_code)
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
            for opt in ("ref", "until", "reason", "evidence", "deployed", "live_test", "ack_handoff"):
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
        ev += [{"deployed": d} for d in args.deployed]
        return write(home, "task.done", {"task": args.task, "evidence": ev}, s, args.key)
    if cmd == "deadline":
        s = session_of(args, home) or newest_session(home)
        if args.sub == "list":
            return {"session": s, "deadlines": deadlines(home, s, time.time())}
        if args.sub == "add":
            return write(home, "deadline.add", {"session": s or "", "at": args.at, "ref": args.ref, "owner": args.owner,
                                                "note": args.note}, s, args.key)
        return write(home, "deadline.done", {"session": s or "", "id": args.id, "note": args.note or ""}, s, args.key)
    if cmd == "note":
        return note_cmd(home, args)
    if cmd == "doctor":
        return doctor()
    if cmd == "spool":
        if args.action == "retry":
            return spool_retry(home)
        if args.action == "ack":
            return spool_ack(home, args.jobs, args.evidence)
        return spool_drain(home)
    if cmd == "heartbeat":
        return heartbeat_beat(home, args.service, args.key)
    if cmd == "alert":
        a = {"alert_key": args.alert_key, "source": args.source}
        if args.action == "raise":
            a.update(severity=args.severity or "", message=args.message or "")
        if args.detail is not None:
            try:
                a["detail"] = json.loads(args.detail)
            except ValueError:
                raise AhError("bad_request", "alert: --detail must be a JSON object")
        return write(home, f"alert.{args.action}", a, session_of(args, home), args.key)
    if cmd == "apply":
        return apply_batch(home, sys.stdin.read(APPLY_MAX_BYTES + 1), session_of(args, home))
    if cmd == "write":
        for row in _ledger(home):
            if row.get("key") == args.key:
                return {"ok": True, "result": "applied", "id": row["id"], "seq": row["seq"], "key": args.key}
        return {"ok": True, "result": "unknown", "key": args.key}
    if cmd == "kill":
        import ah_kill
        try:
            pids = ah_kill.parse_pids(args.pid)
            agent = args.agent or os.environ.get("AH_AGENT_ID", "")
            if args.host:
                return ah_kill.kill_remote(args.host, pids, (args.reason or "").strip(), args.tree, args.grace,
                                           args.session or env_session(), agent, home, foreign=args.foreign)
            return ah_kill.kill_local(pids, args.reason, args.tree, args.grace, home,
                                      session=args.session or env_session(), agent=agent, wal_path=args.wal,
                                      via=args.via, foreign=args.foreign)
        except ah_kill.KillError as e:
            raise AhError(e.code, str(e), e.exit_code)
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
