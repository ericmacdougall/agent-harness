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
WRAPPER = re.compile(r"^\s*<[A-Za-z][\w-]*[\s>/]")
MAX_REQUEST = 256 * 1024
SKIP_DARWIN = ("Library", "Desktop", "Documents", "Downloads", "Pictures", "Movies", "Music", "Applications")


class AhError(Exception):
    def __init__(self, code, message, exit_code=2):
        super().__init__(message)
        self.code, self.exit_code = code, exit_code


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
        return dt.datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return 0.0


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
    """Yield complete lines appended since meta['offset']; resets meta when the file was replaced or truncated.

    meta: inode, offset, tail (sha256 of the up-to-64 bytes before offset). Returns (lines, rebuilt).
    """
    st = path.stat()
    rebuilt = False
    fd = os.open(path, os.O_RDONLY)
    try:
        offset = meta.get("offset", 0)
        if offset:
            ok = meta.get("inode") == st.st_ino and st.st_size >= offset
            if ok:
                n = min(64, offset)
                ok = hashlib.sha256(os.pread(fd, n, offset - n)).hexdigest() == meta.get("tail")
            if not ok:
                meta.clear()
                offset, rebuilt = 0, True
        data = b""
        pos = offset
        while True:
            chunk = os.pread(fd, 8 << 20, pos)
            if not chunk:
                break
            data += chunk
            pos += len(chunk)
        end = data.rfind(b"\n") + 1
        lines = data[:end].split(b"\n")[:-1] if end else []
        new_offset = offset + end
        n = min(64, new_offset)
        meta.update(inode=st.st_ino, offset=new_offset,
                    tail=hashlib.sha256(os.pread(fd, n, new_offset - n)).hexdigest() if n else "")
        return lines, rebuilt
    finally:
        os.close(fd)


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
    cache = index_dir / ("wal-" + hashlib.sha256(str(path).encode()).hexdigest()[:16] + ".json")
    try:
        summary = json.loads(cache.read_text())
    except (OSError, ValueError):
        summary = {}
    meta = summary.setdefault("meta", {})
    lines, rebuilt = read_new_lines(path, meta)
    if rebuilt or "first" not in summary:
        summary.update(first=None, last_at=0.0, outcome=None, last_note="", tickets=[], events=0)
    for raw in lines:
        try:
            rec = json.loads(raw)
        except ValueError:
            continue
        if not isinstance(rec, dict):
            continue
        at = parse_ts(rec.get("at"))
        summary["last_at"] = max(summary["last_at"], at)
        summary["events"] += 1
        event, note = rec.get("event"), rec.get("note") if isinstance(rec.get("note"), str) else ""
        if event == "intent" and summary["first"] is None and note:
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


def owners(home: Path, session: str, now: float | None = None, comments=None) -> dict:
    now = time.time() if now is None else now
    wal = wal_dirs(home) / session
    main = wal / "main.jsonl"
    if not main.is_file():
        raise AhError("session_unknown", f"no main WAL for session {session!r}")
    index_dir = state_dir(home, "ah-index")
    spawned, stopped = {}, set()
    with open(main, "rb") as handle:
        for raw in handle:
            try:
                rec = json.loads(raw)
            except ValueError:
                continue
            if not isinstance(rec, dict) or not isinstance(rec.get("agent_id"), str):
                continue
            if rec.get("event") == "subagent":
                spawned.setdefault(rec["agent_id"], {"type": rec.get("agent_type"), "at": parse_ts(rec.get("at"))})
            elif rec.get("event") == "subagent_stop":
                stopped.add(rec["agent_id"])
    rows = []
    for agent, info in spawned.items():
        path = wal / f"agent-{agent}.jsonl"
        summary = summarize_agent_wal(path, index_dir) if path.is_file() else {
            "first": None, "last_at": 0.0, "outcome": None, "last_note": "", "tickets": []}
        last_wal = max(summary["last_at"], 0.0) or info["at"]
        verdict = liveness.classify(now, last_wal, transcript_mtime(home, session, agent), agent in stopped,
                                    summary["outcome"], summary["last_note"], info["type"])
        idle = verdict["idle_s"]
        row = {"agent_id": agent, "type": info["type"], "task": summary["first"],
               "state": verdict["state"], "severity": verdict["severity"],
               "last_activity": iso(last_wal), "idle_s": None if idle == float("inf") else int(idle),
               "ticket": summary["tickets"][0] if summary["tickets"] else None,
               "ticket_comment_age_s": None}
        if comments and row["ticket"]:
            row["ticket_comment_age_s"] = comments(row["ticket"], now)
        rows.append(row)
    rows.sort(key=lambda r: (r["state"] in ("done", "handoff"), -(r["idle_s"] or 0)))
    counts = {}
    for r in rows:
        counts[r["state"]] = counts.get(r["state"], 0) + 1
    return {"session": session, "generated": iso(now), "counts": counts, "owners": rows, "source": "direct"}


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
        idx = json.loads(cache.read_text())
    except (OSError, ValueError):
        idx = {}
    meta = idx.setdefault("meta", {})
    lines, rebuilt = read_new_lines(path, meta)
    if rebuilt or "msgs" not in idx:
        idx.update(msgs=[], askq=[])
    askq = set(idx["askq"])
    prov = _prov()
    for raw in lines:
        if b'"type"' not in raw:
            continue
        try:
            rec = json.loads(raw)
        except ValueError:
            continue
        if not isinstance(rec, dict):
            continue
        kind = rec.get("type")
        if kind == "assistant" and not rec.get("isSidechain"):
            content = (rec.get("message") or {}).get("content")
            for b in content if isinstance(content, list) else []:
                if isinstance(b, dict) and b.get("type") == "tool_use" and b.get("name") == "AskUserQuestion" \
                        and isinstance(b.get("id"), str):
                    askq.add(b["id"])
        elif kind == "user":
            body, _ = prov.user_authorship(rec)
            if body and body.strip():
                idx["msgs"].append(_msg("uuid", f"uuid:{session}/{rec.get('uuid')}", rec.get("timestamp"), body,
                                        "human-origin turn"))
                continue
            blocks = (rec.get("message") or {}).get("content")
            if (not rec.get("isSidechain") and "toolUseResult" in rec and isinstance(blocks, list) and len(blocks) == 1
                    and isinstance(blocks[0], dict) and blocks[0].get("type") == "tool_result"
                    and blocks[0].get("tool_use_id") in askq):
                idx["msgs"].append(_msg("answer", f"answer:{session}/{rec.get('uuid')}", rec.get("timestamp"),
                                        _blocks_text(blocks[0].get("content")),
                                        "AskUserQuestion tool result bound to an AskUserQuestion tool_use"))
        elif kind == "queue-operation" and rec.get("operation") in ("enqueue", "popAll"):
            content = rec.get("content")
            # Harness wrappers (task notifications, agent messages, reminders) are never user text.
            if isinstance(content, str) and content.strip() and not WRAPPER.match(content):
                digest = hashlib.sha256(content.encode()).hexdigest()[:12]
                idx["msgs"].append(_msg("queued", f"queue:{session}/{rec.get('timestamp')}#{digest}",
                                        rec.get("timestamp"), content,
                                        "transcript queue-operation record without an origin marker"))
    idx["askq"] = sorted(askq)
    atomic_json(cache, idx)
    return idx


def _msg(kind, ident, ts, text, trust):
    return {"id": ident, "kind": kind, "timestamp": ts, "trust": trust, "text": text[:8000], "chars": len(text)}


def user_msgs(home: Path, session: str, text=None, recent=None, full=False, limit=20) -> dict:
    idx = index_transcript(home, session)
    msgs = idx["msgs"]
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
    out = out[-limit:]
    for r in out:
        r["preview"] = re.sub(r"\s+", " ", r["text"]).strip()[:120]
        if not full:
            del r["text"]
    return {"session": session, "matches": out, "source": "direct"}


# ------------------------------------------------------------------ tickets

def load_adapter(home: Path | None = None):
    import ticket_adapters
    cfg = json.loads(Path(__file__).with_name("commit_policy.json").read_text())["ticket_systems"]["goodqa"]
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
            continue
        if kib is not None:
            entries.append({"path": t, "bytes": kib * 1024})
    entries.sort(key=lambda e: -e["bytes"])
    return {"root": root, "entries": entries[:count], "partial": partial, "skipped_protected": skipped}


def disk(host=None, root=None, count=10, budget_s=20.0, top=True) -> dict:
    if host:
        if not re.fullmatch(r"[A-Za-z0-9._@-]{1,100}", host):
            raise AhError("bad_request", "host has characters ssh targets cannot have")
        argv = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", host,
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


def store_dir(home: Path) -> Path:
    return state_dir(home, "ah", "store")


def canonical(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def derive_key(op: str, args: dict, session: str) -> str:
    return "ah:" + hashlib.sha256(canonical([op, args, session]).encode()).hexdigest()[:32]


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
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,120}", args["session"]):
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
                (isinstance(e.get("really_tested"), str) and e.get("wal")) or
                (re.fullmatch(r"[0-9a-f]{7,40}", str(e.get("commit", ""))) and e.get("repo")))
            if not ok:
                raise AhError("evidence", "each evidence item is {really_tested, wal} or {commit, repo}")
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
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        os.write(fd, (canonical(record) + "\n").encode())
        os.fsync(fd)
    finally:
        os.close(fd)


def _ledger(home: Path) -> list:
    path = store_dir(home) / "ledger.jsonl"
    out = []
    try:
        with open(path, "rb") as handle:
            for raw in handle:
                try:
                    out.append(json.loads(raw))
                except ValueError:
                    continue  # a torn last line from a crash is ignored, never fatal
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
        os.write(fd, canonical(job).encode())
        os.fsync(fd)
    finally:
        os.close(fd)
    return name


def post_comment(ref: str, body: str, operation_id: str) -> None:
    import redact
    adapter, mod = load_adapter()
    project, number = ticket_ref(ref)
    ticket = ticket_issue(adapter, mod, project, number)
    try:
        adapter.comment(ticket, redact.redact(body), operation_id)
    except mod.TicketSystemUnavailable as e:
        raise AhError("ticket_unavailable", str(e), 3)


def spool_drain(home: Path) -> dict:
    """Post spooled comments; the GoodQA operationId makes a re-post after a crash harmless."""
    spool = store_dir(home) / "spool"
    done, failed = 0, 0
    for f in sorted(spool.glob("*.json")):
        try:
            job = json.loads(f.read_text())
            post_comment(job["ticket"], job["body"], job["operation_id"])
        except (AhError, OSError, ValueError, KeyError):
            failed += 1
            continue
        f.unlink()
        done += 1
    return {"ok": True, "drained": done, "pending": failed}


def _wal_path(home: Path, session: str, agent: str) -> Path:
    return home / ".claude" / "wals" / session / ("main.jsonl" if agent == "main" else f"agent-{agent}.jsonl")


def _wal_append(home: Path, path: Path, record: dict) -> None:
    import wal
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


def _evidence_ok(home: Path, ev: list) -> None:
    root = (home / ".claude" / "wals").resolve()
    for e in ev:
        if "really_tested" in e:
            try:
                p = Path(e["wal"]).expanduser().resolve(strict=True)
            except OSError:
                raise AhError("evidence", f"WAL not found: {e['wal'][:80]}", 3)
            if root not in p.parents:
                raise AhError("evidence", "evidence WAL must be under ~/.claude/wals", 3)
            found = False
            with open(p, "rb") as handle:
                for raw in handle:
                    if e["really_tested"].encode() in raw and b"REALLY_TESTED" in raw:
                        found = True
                        break
            if not found:
                raise AhError("evidence", f"no REALLY_TESTED entry {e['really_tested']} in that WAL", 3)
        else:
            r = subprocess.run(["git", "-C", e["repo"], "cat-file", "-e", e["commit"] + "^{commit}"],
                               capture_output=True, timeout=20)
            if r.returncode != 0:
                raise AhError("evidence", f"commit {e['commit']} not found in {e['repo'][:80]}", 3)


def _apply(home: Path, op: str, args: dict, key: str, ledger: list) -> dict:
    """Validate and perform one op; returns the result fields. Called under the store lock."""
    opid = "ah:" + hashlib.sha256(key.encode()).hexdigest()[:24]
    wid = "w" + hashlib.sha256(key.encode()).hexdigest()[:11]
    now = dt.datetime.now(dt.timezone.utc).isoformat()
    out = {}

    def comment(ticket, body):
        try:
            post_comment(ticket, body, opid)
            out["comment"] = "posted"
        except AhError:
            _spool_comment(home, {"ticket": ticket, "body": body, "operation_id": opid})
            out["comment"] = "pending"

    if op == "task.register":
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
        rec = {"at": now, "event": "status", "id": wid, "note": f"[{args['stage']}] {args['note']}"[:3900]}
        _wal_append(home, _wal_path(home, r["session"], r["owner_agent"]), rec)
        out["wal"] = wid
        comment(args.get("ticket") or r["ticket"], f"Task {args['task']} [{args['stage']}]: {args['note']}")
    elif op == "task.done":
        reg = _task(ledger, args["task"])
        if not reg:
            raise AhError("unknown_task", f"task {args['task']!r} is not registered", 3)
        _evidence_ok(home, args["evidence"])
        r = reg["args"]
        cites = "; ".join(e.get("really_tested") or e["commit"] for e in args["evidence"])
        rec = {"at": now, "event": "result", "id": wid, "note": f"task {args['task']} done; evidence: {cites}"[:3900]}
        _wal_append(home, _wal_path(home, r["session"], r["owner_agent"]), rec)
        out["wal"] = wid
        comment(r["ticket"], rec["note"])
    elif op == "ticket.comment":
        comment(args["ticket"], args["body"])
    return out


def write(home: Path, op: str, args: dict, session: str, key: str | None = None) -> dict:
    precheck(op, args)
    key = key or derive_key(op, args, session)
    if not KEY_RE.match(key):
        raise AhError("bad_request", "idempotency key must be 8-128 chars of [A-Za-z0-9._:-]")
    body_sha = hashlib.sha256(canonical([op, args]).encode()).hexdigest()
    who = actor(session)
    audit = store_dir(home) / "audit.jsonl"
    with StoreLock(home):
        ledger = _ledger(home)
        for row in ledger:
            if row.get("key") == key:
                if row["sha"] != body_sha:
                    _append_line(audit, {"at": iso(time.time()), "op": op, "key": key, "actor": who,
                                         "result": "key_conflict"})
                    raise AhError("key_conflict", "that key was used with a different request", 3)
                return {"ok": True, "result": "duplicate", "id": row["id"], "seq": row["seq"], "key": key,
                        "comment": row.get("comment")}
        seq = len(ledger) + 1
        try:
            out = _apply(home, op, args, key, ledger)
        except AhError as e:
            _append_line(audit, {"at": iso(time.time()), "op": op, "key": key, "actor": who,
                                 "result": "rejected", "code": e.code})
            raise
        rid = "ah" + hashlib.sha256(key.encode()).hexdigest()[:10]
        _append_line(store_dir(home) / "ledger.jsonl", {
            "seq": seq, "id": rid, "key": key, "sha": body_sha, "op": op, "args": args, "actor": who,
            "received_at": iso(time.time()), "comment": out.get("comment")})
        _append_line(audit, {"at": iso(time.time()), "op": op, "key": key, "actor": who, "result": "applied", "seq": seq})
    reply = {"ok": True, "result": "applied", "id": rid, "seq": seq, "key": key}
    reply.update(out)
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
            lines.append(f"    {e['bytes'] / 2**30:8.2f} GiB  {e['path']}")
        return "\n".join(lines)
    return json.dumps(data, indent=2)


def build_parser():
    p = argparse.ArgumentParser(prog="ah", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--text", action="store_true", help="human summary instead of JSON")
    sub = p.add_subparsers(dest="cmd", required=True)
    o = sub.add_parser("owners")
    o.add_argument("--session")
    o.add_argument("--comments", action="store_true", help="also fetch latest ticket comment age (network)")
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
    dn = ks.add_parser("done")
    dn.add_argument("--task", required=True)
    dn.add_argument("--really-tested", action="append", default=[], metavar="WALID")
    dn.add_argument("--wal")
    dn.add_argument("--commit", action="append", default=[])
    dn.add_argument("--repo")
    for x in (r, st, dn, cc):
        x.add_argument("--session")
        x.add_argument("--key", help="idempotency key (default: derived from the request)")
    sp = sub.add_parser("spool")
    sp.add_argument("action", choices=["drain"])
    w = sub.add_parser("write")
    ws = w.add_subparsers(dest="sub", required=True)
    wr = ws.add_parser("result")
    wr.add_argument("--key", required=True)
    wr.add_argument("--session")
    return p


def session_of(args, home):
    s = getattr(args, "session", None) or os.environ.get("CLAUDE_SESSION_ID") or ""
    return s


def run(args, home: Path) -> dict:
    cmd = args.cmd
    if cmd == "owners":
        s = args.session or os.environ.get("CLAUDE_SESSION_ID") or newest_session(home)
        if not s or not SESSION_RE.match(s):
            raise AhError("session_unknown", "no session: pass --session")
        return owners(home, s, comments=comment_age if args.comments else None)
    if cmd == "user-msg":
        s = args.session or os.environ.get("CLAUDE_SESSION_ID") or newest_transcript_session(home)
        if not s:
            raise AhError("session_unknown", "no session: pass --session")
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
        if args.sub == "register":
            a = {"task": args.task, "owner_agent": args.owner_agent, "session": s or "", "ticket": args.ticket,
                 "scope": args.scope, "source": args.source}
            for opt in ("branch", "worktree"):
                if getattr(args, opt):
                    a[opt] = getattr(args, opt)
            return write(home, "task.register", a, s, args.key)
        if args.sub == "status":
            a = {"task": args.task, "stage": args.stage, "note": args.note}
            if args.ticket:
                a["ticket"] = args.ticket
            return write(home, "task.status", a, s, args.key)
        ev = [{"really_tested": i, "wal": args.wal or ""} for i in args.really_tested]
        ev += [{"commit": c, "repo": args.repo or ""} for c in args.commit]
        return write(home, "task.done", {"task": args.task, "evidence": ev}, s, args.key)
    if cmd == "spool":
        return spool_drain(home)
    if cmd == "write":
        for row in _ledger(home):
            if row.get("key") == args.key:
                return {"ok": True, "result": "applied", "id": row["id"], "seq": row["seq"], "key": args.key,
                        "comment": row.get("comment")}
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
    if args.text:
        sys.stdout.write(render_text(args.cmd, data) + "\n")
    else:
        sys.stdout.write(json.dumps(data, indent=None if args.cmd == "write" else 2) + "\n")
    if isinstance(data, dict) and data.get("ok") is False:
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
