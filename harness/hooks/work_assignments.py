#!/usr/bin/env python3
"""Harness-kept ledger of every human request, schema 2 (docs/work-assignments.md, work_ledger.schema.json).

`~/.agent-harness/work-ledger.events.jsonl` is the source of truth: one hash-chained event per mutation. The snapshot
`work-ledger.json` is a fold of those events (`apply_event`) and carries an index for cheap hooks; `verify` re-folds and
diffs, `recover` rebuilds the snapshot from the events. Hooks (Claude Code and Codex, `--runtime codex`) capture every
genuine human message as untriaged, block Stop (bounded) while untriaged or stale work exists, and re-inject open items.

  hook:  prompt | stop | session | compact | ask-answer | guard | subagent-start
  cli:   status split no-ask update cancel remove prune decision relate import migrate sync failures verify recover show

The installed work_assignments_policy.json alone loosens modes (never env, repo or CLI). Hook bugs exit 0 and are
recorded in a failures file shown at the next prompt; a capture a stalled store cannot take is spooled and drained.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import random
import re
import socket
import string
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
SCHEMA = 2
TRANSITIONS = {
    "open": ["assigned", "blocked", "cancelled", "superseded"],
    "assigned": ["in_progress", "open", "blocked", "cancelled", "superseded"],
    "in_progress": ["ready", "blocked", "assigned", "open", "cancelled", "superseded"],
    "blocked": ["open", "assigned", "in_progress", "cancelled", "superseded"],
    "ready": ["done", "in_progress", "blocked", "cancelled", "superseded"],
    "done": ["in_progress"], "cancelled": [], "superseded": []}
CLOSED = ("done", "cancelled", "superseded")
KINDS = ("request", "bug", "feature", "chore", "question", "follow_up")
GATE_SECONDS = 24 * 3600
PENDING_BIND_SECONDS = 2 * 3600
BLOCK_MEMORY_SECONDS = 6 * 3600
MAX_STORE_BYTES = 128 * 1024 * 1024
MAX_PAYLOAD = 8 * 1024 * 1024
SYNC_WINDOW = 64 * 1024
SYNC_MAX_BYTES = 64 * 1024 * 1024
LOCK_SECONDS = 3.0
HOOK_SECONDS = 6.0
ZERO = "0" * 64
DEFAULT_POLICY = {"schema": 1, "capture": "enforce", "stop": "enforce", "guard": "enforce",
                  "stale_hours": 12, "max_stop_blocks": 3}
PROTECTED = re.compile(r"work-(?:assign|ledger)[A-Za-z0-9._*?-]*|work_assignments_policy[A-Za-z0-9._*?-]*|"
                       r"work_assign[a-z]*[*?]|work-[a-z]+[*?]|\bhive\.json\b")
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


def sha(text) -> str:
    return hashlib.sha256(text if isinstance(text, bytes) else str(text).encode("utf-8", "replace")).hexdigest()


# --------------------------------------------------------------------------- policy

def load_policy(path=None) -> dict:
    """Installed file only. Missing or corrupt means the strict defaults plus `policy_error`; never env or CLI."""
    policy = dict(DEFAULT_POLICY)
    try:
        loaded = prov.loads_line(prov.read_small(Path(path or POLICY_FILE), 1 << 16))
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


# --------------------------------------------------------------------------- files, identity, locking

def base() -> Path:
    return Path(os.environ.get("AGENT_HARNESS_HOME") or Path.home() / ".agent-harness")


def files() -> dict:
    d = base()
    return {"dir": d, "snap": d / "work-ledger.json", "events": d / "work-ledger.events.jsonl",
            "archive": d / "work-ledger.archive.jsonl", "lock": d / "work-ledger.lock", "hive": d / "hive.json",
            "fail": d / "work-ledger.failures.jsonl", "spool": d / "work-ledger.spool.jsonl",
            "v1": d / "work-assignments.json"}


def private_dir() -> Path:
    d = base()
    d.mkdir(mode=0o700, parents=True, exist_ok=True)
    return d


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


def hive_identity() -> dict:
    """{hiveId, machineId, ledgerId}: one per harness installation, minted once into hive.json."""
    path = files()["hive"]
    private_dir()
    for _ in range(2):
        try:
            found = json.loads(prov.read_small(path, 4096))
            if re.fullmatch(r"[a-z0-9]{4,12}", str(found.get("hiveId"))):
                return found
            raise StoreCorrupt("hive.json is unreadable; fix or remove it deliberately (removing forks the ledger identity)")
        except prov.Problem:
            pass
        alphabet = string.ascii_lowercase + string.digits
        machine = re.sub(r"[^A-Za-z0-9._-]", "-", socket.gethostname().split(".")[0])[:60] or "machine"
        fresh = {"hiveId": "".join(random.SystemRandom().choice(alphabet) for _ in range(8)), "machineId": machine,
                 "ledgerId": "L-" + "".join(random.SystemRandom().choice(alphabet) for _ in range(10)), "createdAt": iso(now())}
        try:
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            continue
        with os.fdopen(fd, "w") as handle:
            handle.write(json.dumps(fresh))
        return fresh
    raise StoreCorrupt("could not establish hive identity")


def actor(kind="agent", provider="claude-code", session=None, label=None, agent=None, model=None, human_model=False) -> dict:
    ident = hive_identity()
    out = {"kind": kind, "provider": provider, "hiveId": ident["hiveId"], "machineId": ident["machineId"]}
    if kind != "human":
        out["pid"] = os.getpid()
        if model:
            out["model"] = model[:80]
    if session and re.fullmatch(r"[A-Za-z0-9._:-]{8,128}", session):
        out["sessionId"] = session
    if agent:
        out["agentId"] = str(agent)[:128]
    if label:
        out["label"] = str(label)[:80]
    return out


def provider_of(runtime: str) -> str:
    return "codex" if runtime == "codex" else "claude-code"


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
                    raise LockTimeout(f"work-ledger lock busy for {timeout:.0f}s")
                time.sleep(0.01)
        yield
    finally:
        os.close(fd)


# --------------------------------------------------------------------------- snapshot and fold

def new_snapshot() -> dict:
    ident = hive_identity()
    return {"schema": SCHEMA, "schemaUrl": "https://agent-harness.local/schemas/work-ledger/v2.schema.json",
            "ledgerId": ident["ledgerId"], "hiveId": ident["hiveId"], "rev": 0, "generatedAt": iso(now()),
            "writers": {}, "appliedThrough": {}, "sessions": {}, "messages": {}, "asks": {}, "decisions": {},
            "tombstones": {}, "violations": [], "index": empty_index()}


def empty_index() -> dict:
    return {"builtAt": iso(now()), "builtFromRev": 0, "openAsks": [], "openDecisions": [], "untriagedMessages": [],
            "pendingBindings": [], "bySession": {}, "byOwner": {}, "blockedOn": {}, "staleAfter": [], "removable": [],
            "unsurfacedViolations": 0}


def read_snapshot():
    """Snapshot, or None when absent. A corrupt snapshot is preserved and fails loudly: never an empty ledger."""
    path = files()["snap"]
    try:
        raw = prov.read_small(path, MAX_STORE_BYTES)
    except prov.Problem as error:
        if error.code == "file-unreadable" and not path.exists():
            return None
        raise StoreCorrupt(f"cannot read {path.name}: {error.message}")
    try:
        data = json.loads(raw.decode("utf-8"))
        if not isinstance(data, dict) or data.get("schema") != SCHEMA or not isinstance(data.get("asks"), dict):
            raise ValueError("unexpected shape")
        return data
    except (ValueError, UnicodeDecodeError) as error:
        stamp = time.strftime("%Y%m%dT%H%M%S", time.gmtime(now()))
        keep = path.with_name(f"work-ledger.corrupt-{stamp}-{sha(raw)[:8]}.json")
        if not keep.exists():
            write_private(keep, raw)
        raise StoreCorrupt(f"{path.name} is corrupt ({error}); preserved at {keep.name}. `work_assignments.py recover` "
                           "rebuilds it from the event log; nothing was overwritten")


def read_events(limit_tail=None) -> list:
    path = files()["events"]
    try:
        raw = prov.read_tail(path, limit_tail) if limit_tail else prov.read_small(path, MAX_STORE_BYTES)
    except prov.Problem:
        return []
    lines = raw.split(b"\n")
    if limit_tail:
        lines = lines[1:]  # first line of a tail window may be partial
    out = []
    for line in lines:
        if line.strip():
            try:
                out.append(json.loads(line))
            except ValueError:
                if not limit_tail:
                    raise StoreCorrupt("event log has an unreadable line; run `verify`")
    return out


def event_sha(ev: dict) -> str:
    body = {k: v for k, v in ev.items() if k != "sha256"}
    return sha(json.dumps(body, sort_keys=True, ensure_ascii=False, separators=(",", ":")))


def touch(rec: dict, ev: dict, created=False) -> None:
    if created:
        rec.setdefault("createdAt", ev["at"])
    rec["updatedAt"] = ev["at"]
    rec["writer"] = ev["hiveId"]
    rec["lastEvent"] = {"hiveId": ev["hiveId"], "seq": ev["seq"]}


def span_of(rec: dict, span_id: str):
    return next((s for s in rec.get("assignments", []) if s.get("spanId") == span_id), None)


def apply_event(data: dict, ev: dict) -> None:
    """The only way the snapshot changes. Deterministic: events folded in (at, hive, seq) order give the same state."""
    op, data_, tgt = ev["op"], ev["data"], ev["target"]
    kind = {"ask": "asks", "decision": "decisions", "message": "messages"}.get(tgt["type"])
    rec = data[kind].get(tgt["id"]) if kind else None
    if op in ("captured", "migrated", "created"):
        record = data_.get("record") or data_.get("message") or data_.get("ask") or data_.get("decision")
        kind = {"ask": "asks", "decision": "decisions", "message": "messages"}[tgt["type"]]
        data[kind][tgt["id"]] = rec = json.loads(json.dumps(record))
        if tgt["type"] != "message":
            touch(rec, ev, created=True)
    elif rec is None and op not in ("violation", "acknowledged", "sync", "tombstoned"):
        pass  # event for a record this fold never saw (tombstoned or cross-hive): ignored, verify reports drift
    elif op == "bound":
        rec["origin"]["log"].update(data_["log"])
        rec["origin"]["binding"] = {"status": "bound", "boundAt": ev["at"], "attempts": data_.get("attempts", 1)}
    elif op == "unbindable":
        rec["origin"]["binding"] = {"status": "unbindable", "attempts": data_.get("attempts", 1), "reason": data_.get("reason", "")[:300]}
    elif op == "triaged":
        rec["triage"] = data_["triage"]
    elif op == "state":
        rec["state"], rec["stateSince"] = data_["to"], ev["at"]
        rec.update(data_.get("set", {}))
        for key in data_.get("unset", []):
            rec.pop(key, None)
        touch(rec, ev)
    elif op == "assign":
        for span_id in data_.get("ended", []):
            old = span_of(rec, span_id)
            if old:
                old.update(status="reassigned", endedAt=ev["at"])
        rec.setdefault("assignments", []).extend(data_.get("spans", []))
        touch(rec, ev)
    elif op == "span_status":
        span = span_of(rec, data_["spanId"])
        if span:
            span.update(data_.get("set", {}))
        touch(rec, ev)
    elif op in ("relate", "unrelate"):
        relation = data_["relation"]
        rec.setdefault("related", [])
        rec["related"] = [r for r in rec["related"] if (r["kind"], r["target"]) != (relation["kind"], relation["target"])]
        if op == "relate":
            rec["related"].append(relation)
        touch(rec, ev)
    elif op == "prerequisite":
        rec.setdefault("prerequisites", []).append(data_["prerequisite"])
        touch(rec, ev)
    elif op == "prerequisite_status":
        for pre in rec.get("prerequisites", []):
            if pre["ref"] == data_["ref"]:
                pre.update(status=data_["status"], checkedAt=ev["at"])
        touch(rec, ev)
    elif op == "evidence":
        rec.setdefault("evidence", []).append(data_["evidence"])
        touch(rec, ev)
    elif op == "evidence_verified":
        for item in rec.get("evidence", []):
            if item["id"] == data_["evidenceId"]:
                item["verification"] = data_["verification"]
        touch(rec, ev)
    elif op == "commit":
        rec.setdefault("completion", {"status": "none"}).setdefault("commits", []).append(data_["commit"])
        touch(rec, ev)
    elif op == "checked":
        rec.setdefault("times", {})["lastCheckedAt"] = ev["at"]
        if "nextStep" in data_:
            rec["nextStep"] = data_["nextStep"]
        if "description" in data_:
            rec.setdefault("request", {})["compressed"] = data_["description"]
        for ref in data_.get("externalRefs", []):
            if ref not in rec.setdefault("externalRefs", []):
                rec["externalRefs"].append(ref)
        touch(rec, ev)
    elif op == "answered":
        rec["answer"], rec["state"], rec["stateSince"] = data_["answer"], "answered", ev["at"]
        rec["removableAfter"] = iso(parse_ts(ev["at"]) + GATE_SECONDS)
        touch(rec, ev)
    elif op == "assumed":
        rec["assumption"], rec["state"], rec["stateSince"] = data_["assumption"], "assumed", ev["at"]
        touch(rec, ev)
    elif op == "withdrawn":
        rec["withdrawal"], rec["state"], rec["stateSince"] = data_["withdrawal"], "withdrawn", ev["at"]
        touch(rec, ev)
    elif op == "cancelled":
        rec["state"], rec["stateSince"] = "cancelled", ev["at"]
        rec["cancellation"] = {"at": ev["at"], "by": ev["actor"], "proof": data_["proof"]}
        if data_.get("reason"):
            rec["cancellation"]["reason"] = data_["reason"]
        rec["removableAfter"] = iso(parse_ts(ev["at"]) + GATE_SECONDS)
        rec.setdefault("times", {})["endedAt"] = ev["at"]
        touch(rec, ev)
    elif op == "reopened":
        rec["state"], rec["stateSince"] = "in_progress", ev["at"]
        rec.pop("removableAfter", None)
        rec["completion"] = {"status": "none"}
        rec.get("times", {}).pop("endedAt", None)
        for item in rec.get("evidence", []):  # the old proof was for the old completion: done again needs fresh evidence
            if item["verification"]["status"] == "verified":
                item["verification"] = dict(item["verification"], status="stale", detail="ask reopened after done")
        touch(rec, ev)
    elif op == "tombstoned":
        data[kind].pop(tgt["id"], None)
        data["tombstones"][tgt["id"]] = data_["tombstone"]
    elif op == "violation":
        data["violations"].append(data_["violation"])
    elif op == "acknowledged":
        for v in data["violations"]:
            if v["id"] == data_["violationId"]:
                v["surfaced"] = True
                if data_.get("acknowledgedAt"):
                    v.update(acknowledgedAt=data_["acknowledgedAt"], acknowledgedBy=ev["actor"])
    writers = data["writers"].setdefault(ev["hiveId"], {"machineId": ev["actor"].get("machineId", "unknown")})
    writers.update(lastSeq=ev["seq"], lastEventSha256=ev["sha256"])
    data["appliedThrough"][ev["hiveId"]] = ev["seq"]


def emit(data: dict, op: str, ttype: str, tid: str, payload: dict, who: dict, cause=None) -> dict:
    """Mint, apply and queue one event. Committed (events first, then snapshot) when the transaction ends."""
    ident = hive_identity()
    hive = ident["hiveId"]
    last = data["writers"].get(hive, {})
    ev = {"id": f"E-{hive}-{last.get('lastSeq', 0) + 1}", "hiveId": hive, "seq": last.get("lastSeq", 0) + 1, "at": iso(now()),
          "actor": who, "target": {"type": ttype, "id": tid}, "op": op, "data": payload,
          "prevSha256": last.get("lastEventSha256", ZERO)}
    if cause:
        ev["cause"] = cause
    ev["sha256"] = event_sha(ev)
    apply_event(data, ev)
    data.setdefault("_events", []).append(ev)
    return ev


def tombstoned_uuids(data: dict) -> set:
    return {u for t in data["tombstones"].values() for u in t.get("messageUuids", [])}


def mint(data: dict, prefix: str) -> str:
    """Next record id for this hive: shares the event seq space, so ids need no separate counter."""
    hive = hive_identity()["hiveId"]
    return f"{prefix}-{hive}-{data['writers'].get(hive, {}).get('lastSeq', 0) + 1:04d}"


# --------------------------------------------------------------------------- index

def owner_of(ask: dict) -> str:
    for span in reversed(ask.get("assignments", [])):
        if span.get("role") == "owner" and span.get("status") not in ("reassigned", "stopped", "lost", "finished", "failed"):
            a = span["actor"]
            return f"agent:{a['agentId']}" if a.get("agentId") else (a.get("label") or "main")
    return ""


def build_index(data: dict) -> dict:
    ix = empty_index()
    ix.update(builtAt=iso(now()), builtFromRev=data["rev"])
    for rid, ask in data["asks"].items():
        entry = {"id": rid, "state": ask["state"], "stateSince": ask["stateSince"], "compressed": ask["request"]["compressed"][:300],
                 "lastCheckedAt": ask["times"]["lastCheckedAt"]}
        sess = ask["origin"]["actor"].get("sessionId")
        if sess:
            entry["sessionId"] = sess
            ix["bySession"].setdefault(sess, []).append(rid)
        owner = owner_of(ask)
        if owner:
            entry["owner"] = owner
        if ask.get("nextStep"):
            entry["nextStep"] = ask["nextStep"][:300]
        if ask["state"] not in CLOSED:
            ix["openAsks"].append(entry)
            ix["byOwner"].setdefault(owner or "unassigned", []).append(rid)
            ix["staleAfter"].append({"id": rid, "lastCheckedAt": ask["times"]["lastCheckedAt"]})
        for pre in ask.get("prerequisites", []):
            if pre["status"] != "satisfied":
                ix["blockedOn"].setdefault(pre["ref"], []).append(rid)
        if ask.get("removableAfter"):
            ix["removable"].append({"id": rid, "removableAfter": ask["removableAfter"]})
    for rid, dec in data["decisions"].items():
        if dec["state"] in ("asked", "assumed"):
            ix["openDecisions"].append({"id": rid, "state": dec["state"], "stateSince": dec["stateSince"],
                                        "compressed": dec["question"].get("data", {}).get("summary", "")[:300]})
        if dec.get("removableAfter"):
            ix["removable"].append({"id": rid, "removableAfter": dec["removableAfter"]})
    for mid, msg in data["messages"].items():
        if msg["triage"]["status"] == "untriaged":
            ix["untriagedMessages"].append(mid)
        if msg["origin"].get("binding", {}).get("status") == "pending":
            ix["pendingBindings"].append(mid)
    ix["staleAfter"].sort(key=lambda e: e["lastCheckedAt"])
    ix["unsurfacedViolations"] = sum(1 for v in data["violations"] if not v.get("surfaced"))
    return ix


# --------------------------------------------------------------------------- transaction

def fold(events: list) -> dict:
    data = new_snapshot()
    for ev in sorted(events, key=lambda e: (e["at"], e["hiveId"], e["seq"])):
        apply_event(data, ev)
    data["rev"] = len(events)
    data["index"] = build_index(data)
    return data


def catch_up(data: dict) -> None:
    """The events file may be ahead of the snapshot (crash between the two writes): fold what the snapshot lacks."""
    ident = hive_identity()["hiveId"]
    tail = read_events(limit_tail=256 * 1024)
    if not tail:
        return
    last = tail[-1]
    if data["writers"].get(last["hiveId"], {}).get("lastEventSha256") == last["sha256"]:
        return
    applied = data["appliedThrough"]
    missing = [e for e in tail if e["seq"] > applied.get(e["hiveId"], 0)]
    first = min((e["seq"] for e in missing), default=0)
    if missing and first != applied.get(missing[0]["hiveId"], 0) + 1:  # gap: replay everything
        replayed = fold(read_events())
        data.clear()
        data.update(replayed)
        return
    for ev in sorted(missing, key=lambda e: (e["at"], e["hiveId"], e["seq"])):
        apply_event(data, ev)


def load_for_write() -> dict:
    data = read_snapshot()
    if data is None:
        events = read_events()
        data = fold(events) if events else new_snapshot()
        return data
    catch_up(data)
    return data


def commit(data: dict) -> None:
    queued = data.pop("_events", [])
    if queued:
        fd = os.open(files()["events"], os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        try:
            os.write(fd, ("".join(json.dumps(e, ensure_ascii=False, separators=(",", ":")) + "\n" for e in queued)).encode())
            os.fsync(fd)
        finally:
            os.close(fd)
    data["rev"] = int(data.get("rev", 0)) + (1 if queued else 0)
    data["generatedAt"] = iso(now())
    data["index"] = build_index(data)
    write_private(files()["snap"], json.dumps(data, ensure_ascii=False, indent=None, sort_keys=True, separators=(",", ":")).encode())


@contextmanager
def transaction(timeout: float = LOCK_SECONDS):
    """lock, load (folding any events the snapshot lacks), drain the spool, yield, append events, write the snapshot."""
    with locked(timeout):
        data = load_for_write()
        drain_spool(data)
        yield data
        unlink = data.pop("_unlink_draining", False)
        commit(data)
        if unlink:
            try:
                files()["spool"].with_name(files()["spool"].name + ".draining").unlink()
            except OSError:
                pass


@contextmanager
def reading():
    with locked():
        data = read_snapshot()
        yield data if data is not None else new_snapshot()


# --------------------------------------------------------------------------- failures and spool

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


def spool_message(fields: dict) -> None:
    """Lock-free fallback for a capture the store could not take: one O_APPEND line, drained by the next transaction."""
    private_dir()
    record = dict(fields, spoolId=sha(os.urandom(16))[:16], spooledAt=iso(now()))
    fd = os.open(files()["spool"], os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    try:
        os.write(fd, (json.dumps(record, ensure_ascii=False) + "\n").encode())
        os.fsync(fd)
    finally:
        os.close(fd)


def drain_spool(data: dict) -> None:
    """Caller holds the lock. Each spooled capture becomes one untriaged message (spoolId dedupes a crash replay)."""
    path = files()["spool"]
    draining = path.with_name(path.name + ".draining")
    try:
        if path.exists():
            if draining.exists():
                extra = prov.read_small(path, 32 << 20)
                with open(draining, "ab") as out:
                    out.write(extra)
                path.unlink()
            else:
                os.replace(path, draining)
        raw = prov.read_small(draining, 32 << 20)
    except (OSError, prov.Problem):
        return
    seen = {m["humanCheck"].get("providerItemId") for m in data["messages"].values()}
    for line in raw.split(b"\n"):
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        if not isinstance(rec, dict) or "tref" not in rec:
            continue
        key = rec.get("item") or f"spool:{rec['spoolId']}"
        if key in seen:
            continue
        seen.add(key)
        build_capture(data, rec["runtime"], rec["session"], rec.get("transcript"), "", rec["pasted"], rec["source"],
                      via="spool", method=rec["method"], provider_item=key, tref=rec["tref"])
    data["_unlink_draining"] = True


# --------------------------------------------------------------------------- capture

def redact(text: str) -> str:
    try:
        from integrate_local import redact_output
        text = redact_output(text)
        text = re.sub(r"(?i)\b(pass(?:word|wd)?|pwd|secret|token|api[_ -]?key)\s+(?![\[\"'])\S+", r"\1 [redacted]", text)
        return re.sub(r"\b[0-9a-fA-F]{32,}\b", "[redacted]", text)
    except Exception:  # never store an unredacted excerpt when the redactor is unavailable
        return "[excerpt withheld: redactor unavailable]"


def short(text, limit=300) -> str:
    return prov.clip(redact(str(text)), limit)


def excerpt_of(text: str) -> str:
    return prov.clip(redact(" ".join(text[:65536].split()[:15])), 160)


def text_ref(text: str) -> dict:
    ex = excerpt_of(text)
    return {"sha256": sha(prov.norm(text[:prov.MAX_TEXT])), "chars": len(text), "words": len(text.split()), "excerpt": ex,
            "redaction": {"policy": "harness-redactor/1", "applied": True, "hits": ex.count("[redacted]")}}


def classify_prompt(prompt: str):
    """(typed_text, pasted_only) or None when nothing in it is human-typed."""
    typed = prov.strip_blocks(prompt).replace(prov.SENTINEL, "").strip()
    if typed:
        return typed, False
    tags = {(m.group(1) or m.group(2)).lower() for m in prov._TAG_TOKEN.finditer(prompt)}
    if tags and tags <= {"pasted_content"}:
        return re.sub(r"</?pasted_content[^>]*>", "", prompt).strip(), True
    return None


def valid_session(session: str) -> bool:
    return bool(prov.SESSION_RE.match(session)) and session not in (".", "..") and len(session) >= 8


def session_record(data, session, runtime, transcript):
    ident = hive_identity()
    rec = data["sessions"].setdefault(session, {"provider": provider_of(runtime), "hiveId": ident["hiveId"],
                                                 "firstSeenAt": iso(now()), "stopBlocks": {}, "reinject": False})
    if transcript:
        rec["transcript"] = transcript[:1024]
    rec["provider"] = provider_of(runtime)
    rec["lastSeenAt"] = iso(now())
    return rec


def build_capture(data, runtime, session, transcript, text, pasted, source="prompt", *, via, method, uuid=None, line=None,
                  at=None, line_sha=None, provider_item=None, tref=None):
    if uuid and any(m["origin"]["log"].get("messageUuid") == uuid for m in data["messages"].values()):
        return None
    if uuid and uuid in tombstoned_uuids(data):
        return None
    who = actor("human", provider_of(runtime), session, "user")
    mid = mint(data, "M")
    log = {"file": (transcript or "(unknown)")[:1024]}
    binding = {"status": "pending", "attempts": 0}
    if uuid:
        log["messageUuid"] = uuid[:128]
        if line:
            log.update(lineStart=line, lineEnd=line)
        if line_sha:
            log["lineSha256"] = line_sha
        binding = {"status": "bound", "boundAt": iso(now()), "attempts": 1} if line else binding
    msg = {"id": mid, "sessionId": session, "writer": who["hiveId"],
           "origin": {"actor": who, "at": at or iso(now()), "log": log, "binding": binding}, "capturedAt": iso(now()),
           "capturedVia": via, "pastedOnly": pasted, "text": tref or text_ref(text), "triage": {"status": "untriaged"},
           "humanCheck": {"isHuman": True, "method": method}}
    if provider_item:
        msg["humanCheck"]["providerItemId"] = str(provider_item)[:200]
    emit(data, "captured", "message", mid, {"message": msg}, actor("harness", provider_of(runtime), session, "work-assignments-hook"))
    return mid


def method_for(runtime: str, source: str) -> str:
    if source == "ask-answer":
        return "claude_ask_answer"
    return "codex_user_message_item" if runtime == "codex" else "claude_user_turn"


def prompt_capture_fields(payload: dict, runtime: str):
    session = str(payload.get("session_id") or "")
    if not valid_session(session) or payload.get("agent_id") or not isinstance(payload.get("prompt"), str):
        return None
    found = classify_prompt(payload["prompt"])
    if found is None:
        return None
    transcript = payload.get("transcript_path") if isinstance(payload.get("transcript_path"), str) else None
    return {"runtime": runtime, "session": session, "transcript": transcript, "text": found[0], "pasted": found[1],
            "source": "prompt", "method": method_for(runtime, "prompt")}


def spoolable(fields: dict) -> dict:
    """Spool the redacted text reference only: raw human text never reaches disk outside the transcript."""
    out = {k: v for k, v in fields.items() if k != "text"}
    out["tref"] = text_ref(fields["text"])
    return out


def human_records(raw: bytes, runtime: str, first_line: int):
    """Yield (line_number, id, ts, text, pasted, line_sha) for genuine human turns in complete transcript lines."""
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
        if isinstance(uid, str) and (prov.UUID_RE.match(uid) or (runtime == "codex" and uid)) and (text or pasted):
            yield number, uid, ts, text, pasted, sha(line)


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
    path, runtime = rec["transcript"], "codex" if rec.get("provider") == "codex" else "claude"
    changes = 0
    try:
        size = os.stat(path).st_size
        if rec.get("syncOffset") is None or rec["syncOffset"] > size:
            start = max(0, size - SYNC_WINDOW)
            if start:
                tail = prov.read_tail(path, size - start + 1)
                start = start - 1 + tail.find(b"\n") + 1 if b"\n" in tail[:SYNC_WINDOW + 1] else size
            rec["syncOffset"], rec["syncLine"] = start, (count_lines(path, start) if start <= prov.MAX_SCAN_BYTES else 0)
        want = min(size - rec["syncOffset"], SYNC_MAX_BYTES)
        if want <= 0:
            return 0
        fd = prov.open_regular(path)
        try:
            raw = os.pread(fd, want, rec["syncOffset"])
        finally:
            os.close(fd)
    except (OSError, prov.Problem):
        return 0
    cut = raw.rfind(b"\n") + 1  # complete lines only
    raw = raw[:cut]
    first_event = parse_ts(hive_identity().get("createdAt"))  # nothing older than this ledger is caught up
    known = {m["origin"]["log"].get("messageUuid") for m in data["messages"].values()} | tombstoned_uuids(data)
    for number, uid, ts, text, pasted, line_sha in human_records(raw, runtime, rec["syncLine"] + 1):
        if uid in known:
            continue
        digest = sha(prov.norm(text[:prov.MAX_TEXT])) if text else None
        match = next((m for m in sorted(data["messages"].values(), key=lambda m: m["capturedAt"])
                      if m["sessionId"] == session and "messageUuid" not in m["origin"]["log"]
                      and m["humanCheck"]["method"] != "claude_ask_answer"
                      and (m["text"]["sha256"] == digest or (pasted and m.get("pastedOnly")))), None)
        who = actor("harness", provider_of(runtime), session, "work-assignments-sync")
        if match:
            emit(data, "bound", "message", match["id"],
                 {"log": {"file": path[:1024], "lineStart": number, "lineEnd": number, "messageUuid": uid[:128], "lineSha256": line_sha},
                  "attempts": match["origin"]["binding"].get("attempts", 0) + 1}, who)
            changes += 1
        elif parse_ts(ts) >= first_event:  # a turn no hook saw: catch it up (nothing older than this session's first touch)
            if build_capture(data, runtime, session, path, text, pasted, via="rollout_sync" if runtime == "codex" else "transcript_sync",
                             method=method_for(runtime, "prompt"), uuid=uid, line=number, at=ts, line_sha=line_sha,
                             provider_item=uid if runtime == "codex" else None):
                changes += 1
        known.add(uid)
    rec["syncOffset"] += cut
    rec["syncLine"] += raw.count(b"\n")
    return changes


def discover_codex(data: dict) -> None:
    """Track Codex rollouts that began after this ledger did, so a hook-less Codex session is still captured."""
    root = Path(os.environ.get("CODEX_HOME") or Path.home() / ".codex") / "sessions"
    created = parse_ts(hive_identity().get("createdAt"))
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
                rec["syncOffset"], rec["syncLine"] = 0, 0


def sync_all(data: dict, session=None) -> int:
    discover_codex(data)
    recent = sorted(data["sessions"], key=lambda s: data["sessions"][s].get("firstSeenAt", ""))[-40:]
    if session:  # this session plus the Codex rollouts the watcher tracks, so a hook-less Codex session is caught up
        wanted = [session] + [sid for sid in recent[-10:] if sid != session and data["sessions"][sid].get("provider") == "codex"]
    else:
        wanted = recent
    return sum(sync_session(data, sid) for sid in wanted if sid in data["sessions"])


# --------------------------------------------------------------------------- problems and digests

def agent_stopped(session: str, agent: str) -> bool:
    try:
        wal = Path.home() / ".claude" / "wals" / prov.safe_name(session) / f"agent-{prov.safe_name(agent)}.jsonl"
        return b'"event":"subagent_stop"' in prov.read_tail(wal, 65536)
    except prov.Problem:
        return False


def ask_flags(ask: dict, policy: dict, ts: float) -> list:
    if ask["state"] in CLOSED:
        return []
    flags = []
    owner = owner_of(ask)
    if not owner:
        flags.append("no-owner")
    elif owner.startswith("agent:") and agent_stopped(ask["origin"]["actor"].get("sessionId") or "", owner[6:]):
        flags.append("owner-stopped")
    if ts - parse_ts(ask["times"]["lastCheckedAt"]) > policy["stale_hours"] * 3600:
        flags.append("stale")
    return flags


def problems_for(data: dict, session: str, policy: dict, ts=None) -> list:
    ts, found = ts or now(), []
    for mid, m in data["messages"].items():
        if m["triage"]["status"] == "untriaged" and m["sessionId"] == session:
            found.append(("untriaged", mid, f"{mid}: \"{m['text']['excerpt']}\"" + (" [pasted]" if m.get("pastedOnly") else "")))
    for rid, ask in data["asks"].items():
        if ask["origin"]["actor"].get("sessionId") == session:
            flags = ask_flags(ask, policy, ts)
            if flags:
                found.append(("stale", rid, f"{rid} ({ask['state']}, owner {owner_of(ask) or 'none'}): " + ",".join(flags)
                              + f" - {prov.clip(ask['request']['compressed'], 60)}"))
    return found


def digest(data: dict, policy: dict, session=None, limit: int = 20) -> str:
    ts = now()
    ix = data["index"]
    asks = [data["asks"][e["id"]] for e in ix["openAsks"] if e["id"] in data["asks"]]
    flagged = [a for a in asks if ask_flags(a, policy, ts)]
    ordered = sorted(asks, key=lambda a: (not ask_flags(a, policy, ts), a["origin"]["actor"].get("sessionId") != session, a["id"]))
    lines = [f"Work assignments: {len(ix['untriagedMessages'])} untriaged message(s), {len(asks)} open ask(s), "
             f"{len(flagged)} flagged (no owner, stopped owner or stale), {len(ix['openDecisions'])} open decision(s)."]
    for mid in ix["untriagedMessages"][:8]:
        lines.append(f"  UNTRIAGED {mid}: \"{data['messages'][mid]['text']['excerpt']}\" -> work_assignments.py split --msg {mid} --item '...' | no-ask")
    for ask in ordered[:limit]:
        flag = ",".join(ask_flags(ask, policy, ts))
        lines.append(f"  {ask['id']} [{ask['state']}] owner={owner_of(ask) or 'none'}{' !' + flag if flag else ''}: "
                     f"{prov.clip(ask['request']['compressed'], 70)}" + (f" -> {prov.clip(ask['nextStep'], 50)}" if ask.get("nextStep") else ""))
    if len(ordered) > limit:
        lines.append(f"  ... {len(ordered) - limit} more: run `work_assignments.py status`")
    for d in ix["openDecisions"][:5]:
        lines.append(f"  DECISION {d['id']} [{d['state']}]: {prov.clip(d['compressed'], 80)}")
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


def add_violation(data: dict, kind: str, session, detail: str, signature="", targets=()) -> None:
    ident = hive_identity()
    vid = f"X-{ident['hiveId']}-{data['writers'].get(ident['hiveId'], {}).get('lastSeq', 0) + 1}"
    v = {"id": vid, "kind": kind, "at": iso(now()), "hiveId": ident["hiveId"], "targets": list(targets), "detail": prov.clip(detail, 300),
         "surfaced": False}
    if session and valid_session(session):
        v["sessionId"] = session
    if signature:
        v["signature"] = signature[:128]
    emit(data, "violation", "ledger", "ledger", {"violation": v}, actor("harness", "harness", session, "work-assignments"))


def surface_warnings(data: dict, session: str) -> list:
    lines = []
    fails = pending_failures()
    if fails:
        lines.append(f"WORK-ASSIGNMENTS CAPTURE FAILURE ({len(fails)} unacknowledged, latest: {fails[-1]['event']}: "
                     f"{fails[-1]['error']}). A user message may be missing from the ledger. Investigate, then run "
                     "`work_assignments.py failures --ack`.")
    for v in list(data["violations"]):
        if v.get("sessionId") == session and not v.get("surfaced"):
            lines.append(f"WORK-ASSIGNMENTS VIOLATION ({v['kind']}): {v.get('detail', '')}; resolve it now.")
            emit(data, "acknowledged", "ledger", "ledger", {"violationId": v["id"]}, actor("harness", "harness", session))
    for mid, m in list(data["messages"].items()):
        if m["sessionId"] == session and m["triage"]["status"] == "untriaged" and m["origin"]["binding"]["status"] == "pending" \
                and now() - parse_ts(m["capturedAt"]) > PENDING_BIND_SECONDS:
            emit(data, "unbindable", "message", mid, {"reason": "no transcript line after 2h", "attempts": m["origin"]["binding"].get("attempts", 0)},
                 actor("harness", "harness", session))
            add_violation(data, "cannot_bind", session, f"{mid} could not be bound to a transcript line after 2h (cannot-bind)", targets=())
            lines.append(f"WORK-ASSIGNMENTS: {mid} could not be bound to a transcript line after 2h (cannot-bind); it stays untriaged.")
    return lines


def hook_prompt(payload: dict, runtime: str) -> dict:
    policy = load_policy()
    session = str(payload.get("session_id") or "")
    if policy["capture"] == "off":
        return {}
    fields = prompt_capture_fields(payload, runtime)
    try:
        return prompt_with_store(payload, runtime, policy, session, fields)
    except Exception as error:  # whatever stopped the store: keep the message in the spool
        if fields:
            spool_message({**spoolable(fields), "item": None})
            record_failure("prompt:spooled", error)
        raise


def prompt_with_store(payload, runtime, policy, session, fields):
    out = []
    with transaction() as data:
        if fields:
            session_record(data, session, runtime, fields["transcript"])
            build_capture(data, runtime, session, fields["transcript"], fields["text"], fields["pasted"], via="hook_prompt",
                          method=fields["method"])
        if valid_session(session):
            sync_all(data, session)
        out += surface_warnings(data, session)
        rec = data["sessions"].get(session)
        if rec and rec.get("reinject"):
            rec["reinject"] = False
            out.append(digest(data, policy, session))
        elif any(m["triage"]["status"] == "untriaged" and m["sessionId"] == session for m in data["messages"].values()):
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
    key = f"ask:{payload.get('tool_use_id') or sha(text)[:16]}"
    fields = {"runtime": runtime, "session": session, "transcript": transcript, "text": text, "pasted": False,
              "source": "ask-answer", "method": "claude_ask_answer", "item": key}
    try:
        with transaction() as data:
            session_record(data, session, runtime, transcript)
            if not any(m["humanCheck"].get("providerItemId") == key for m in data["messages"].values()):
                build_capture(data, runtime, session, transcript, text, False, "ask-answer", via="hook_post_tool",
                              method="claude_ask_answer", provider_item=key)
    except Exception:
        spool_message(spoolable(fields))
        raise
    return {}


def hook_stop(payload: dict, runtime: str) -> dict:
    policy = load_policy()
    session = str(payload.get("session_id") or "")
    if policy["stop"] == "off" or not valid_session(session) or payload.get("agent_id"):
        return {}
    with transaction() as data:
        rec = data["sessions"].get(session)
        if rec is not None and isinstance(payload.get("transcript_path"), str):
            rec["transcript"] = payload["transcript_path"][:1024]
        sync_all(data, session)
        found = problems_for(data, session, policy)
        rec = data["sessions"].get(session) or session_record(data, session, runtime, None)
        if not found:
            rec["stopBlocks"] = {}
            return {}
        signature = ",".join(sorted(f"{k}:{i}" for k, i, _ in found))[:128]
        entry = rec["stopBlocks"].get(signature)
        if entry and now() - parse_ts(entry.get("lastAt")) > BLOCK_MEMORY_SECONDS:
            entry = None  # the same unresolved problem returning hours later is blocked afresh
        used = entry["count"] if entry else 0
        listing = "\n".join("  - " + line for _, _, line in found[:12]) + (f"\n  ... {len(found) - 12} more" if len(found) > 12 else "")
        if policy["stop"] == "enforce" and used < policy["max_stop_blocks"]:
            rec["stopBlocks"][signature] = {"count": used + 1, "lastAt": iso(now())}
            return {"decision": "block", "reason": (
                f"Work assignments ({used + 1}/{policy['max_stop_blocks']}): unresolved before you stop:\n{listing}\n"
                "Triage each message (`work_assignments.py split --msg M-... --item '...'` or `no-ask --msg M-... --reason '...'`) "
                "and update stale asks (`work_assignments.py update A-... --owner ... --next ...` or `--state done --evidence <commit|PR#n|url|tested:id>`).")}
        if policy["stop"] == "enforce":
            if not any(v.get("sessionId") == session and v.get("signature") == signature
                       and now() - parse_ts(v["at"]) < BLOCK_MEMORY_SECONDS for v in data["violations"]):
                add_violation(data, "stop_block_exhausted", session, f"Stop was allowed with {len(found)} unresolved item(s)", signature)
            return {"systemMessage": f"work-assignments VIOLATION: stopping with {len(found)} unresolved item(s); logged and shown next prompt"}
        return {"systemMessage": f"work-assignments (warn mode): {len(found)} unresolved item(s):\n{listing}"}


def hook_subagent_start(payload: dict, runtime: str) -> dict:
    agent = str(payload.get("agent_id") or "")
    with reading() as data:
        mine = [a for a in data["asks"].values() if owner_of(a) == f"agent:{agent}" and a["state"] not in CLOSED]
    script = Path(__file__).resolve()
    text = ("Request ledger: you do not create requests. Record progress on the asks you own with "
            f"`python3 {script} update A-... --actor agent:{agent} --state in_progress|blocked|ready|done "
            "--next '...' --evidence <commit|PR#n|url|tested:id>` (done needs a verified commit or tested id).")
    if mine:
        text += " Asks owned by you: " + "; ".join(f"{a['id']} {prov.clip(a['request']['compressed'], 60)}" for a in mine[:10])
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
    reason = ("The work ledger, its event log, archive, lock, spool, hive identity and policy are changed only through "
              "work_assignments.py (the 24h removal gate lives there); direct edits are refused.")
    if mode == "enforce":
        return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny", "permissionDecisionReason": reason}}
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


def commit_exists(sha_: str, repo=None) -> bool:
    try:
        run = subprocess.run(["git", "-C", str(repo or os.getcwd()), "cat-file", "-e", sha_ + "^{commit}"],
                             capture_output=True, timeout=5, env={**os.environ, "GIT_OPTIONAL_LOCKS": "0"})
        return run.returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def git_branch(repo=None) -> str:
    try:
        run = subprocess.run(["git", "-C", str(repo or os.getcwd()), "rev-parse", "--abbrev-ref", "HEAD"], capture_output=True,
                             timeout=5, text=True)
        return (run.stdout.strip() or "HEAD")[:200]
    except (OSError, subprocess.SubprocessError):
        return "HEAD"


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


def verification(status, method="none", system=None, who=None, detail=None) -> dict:
    out = {"status": status, "method": method}
    if status in ("verified", "failed", "stale"):
        out.update(verifiedAt=iso(now()), verifiedBy=who or actor("harness", "harness", label="work-assignments"))
    if system:
        out["systemOfRecord"] = system[:200]
    if detail:
        out["detail"] = prov.clip(detail, 300)
    return out


def parse_evidence(text: str, who: dict, repo=None, span_id=None) -> dict:
    """Format plus what can be checked offline: a commit must exist locally (git-object), a tested id must be a
    REALLY_TESTED WAL note (wal-really-tested). PR numbers and URLs cannot be checked here and stay attested."""
    text = text.strip()
    for kind, pattern in EVIDENCE:
        found = pattern.match(text)
        if not found:
            continue
        ref = found.group(1)
        item = {"kind": kind, "ref": ref if kind != "pr" else f"PR#{ref}", "claimedBy": who, "claimedAt": iso(now())}
        if kind == "commit":
            if not commit_exists(ref, repo):
                raise WAError(f"commit {ref} not found in {repo or os.getcwd()} (pass --repo PATH)")
            item["verification"] = verification("verified", "git-object", f"git:{repo or os.getcwd()}")
        elif kind == "tested":
            if not wal_has_test(ref):
                raise WAError(f"no REALLY_TESTED WAL note with id {ref} on this host")
            item["verification"] = verification("verified", "wal-really-tested", "agent WAL")
        else:
            item["verification"] = verification("attested")
        return item
    raise WAError("evidence must be a commit sha, PR#n, https URL or tested:WAL-ID; got " + repr(prov.clip(text, 40)))


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
    why = prov.excerpt_in(found[0][3], quote)
    if why:
        raise WAError("quote not in that human message: " + why)
    return {"line": line, "uuid": uuid, "lineSha256": sha(target), "quote": quote, "text": found[0][3]}


def words_of(text: str) -> set:
    return {w for w in re.findall(r"[a-z0-9]{4,}", text.lower())}


def check_binding(data: dict, ask: dict, msg: dict, binding: str, quote: str, decision_id=None) -> None:
    """The proving turn must relate to THIS ask: its own origin message, a quote that names it, or the answer to a
    decision tied to it. A stranger's human message cannot cancel an unrelated ask."""
    if binding == "same_message_retraction":
        if ask["origin"].get("messageId") != msg["id"]:
            raise WAError("same_message_retraction needs the ask's own origin message")
    elif binding == "explicit_reference":
        ref = {ask["id"].lower(), (ask.get("migratedFrom", {}).get("id") or "").lower()} - {""}
        if not (any(r in quote.lower() for r in ref) or len(words_of(quote) & words_of(ask["request"]["compressed"])) >= 3):
            raise WAError("explicit_reference: the quote must name the ask id or share 3+ words with its request")
    elif binding in ("answer_to_decision", "answer_to_cancel_question"):
        dec = data["decisions"].get(decision_id or "")
        if not dec or dec["state"] != "answered" or dec["answer"]["messageId"] != msg["id"]:
            raise WAError(f"{binding}: decision {decision_id} is not answered by this message")
        if not any(r["target"] == ask["id"] for r in dec.get("related", [])):
            raise WAError(f"{binding}: decision {decision_id} is not related to {ask['id']}")
    else:
        raise WAError("unknown binding " + str(binding))


def proof_for(data: dict, ask: dict, file: str, line: int, uuid: str, quote: str, binding: str, decision_id=None) -> dict:
    verified = verify_proof(file, line, uuid, quote)
    msg = next((m for m in data["messages"].values() if m["origin"]["log"].get("messageUuid") == uuid), None)
    if not msg or msg.get("humanCheck", {}).get("isHuman") is not True or msg["origin"]["actor"]["kind"] != "human":
        raise WAError("proof uuid is not a human message captured by this ledger (run `sync` first if it is recent)")
    tracked = data["sessions"].get(msg["sessionId"], {}).get("transcript")
    if not tracked or os.path.realpath(tracked) != os.path.realpath(file):
        raise WAError("proof message is not from a transcript this ledger tracks")
    if parse_ts(msg["origin"]["at"]) < parse_ts(ask["createdAt"]) - 1:
        raise WAError("proof message predates the ask")
    check_binding(data, ask, msg, binding, quote, decision_id)
    proof = {"messageId": msg["id"], "log": {"file": file[:1024], "lineStart": line, "lineEnd": line, "messageUuid": uuid,
                                              "lineSha256": verified["lineSha256"]},
             "quoteSha256": sha(quote), "quoteExcerpt": prov.clip(quote, 160), "verifiedAt": iso(now()),
             "verifiedBy": actor("harness", "harness", label="work-assignments"), "targets": [ask["id"]], "binding": binding}
    if decision_id:
        proof["decisionId"] = decision_id
    return proof


def reverify_proof(data: dict, ask: dict) -> None:
    """At removal: the transcript line still says what the proof says, and the proof still binds to this ask."""
    proof = ask["cancellation"]["proof"]
    log = proof["log"]
    quote_stored = proof.get("quoteExcerpt", "")
    verified = verify_proof(log["file"], log["lineStart"], log["messageUuid"], quote_stored)
    if verified["lineSha256"] != log["lineSha256"] or sha(quote_stored) != proof["quoteSha256"]:
        raise WAError("transcript line changed since the proof was taken")
    msg = data["messages"].get(proof["messageId"])
    if not msg:
        raise WAError("proof message is no longer in the ledger")
    if ask["id"] not in proof["targets"]:
        raise WAError("proof does not target this ask")
    check_binding(data, ask, msg, proof["binding"], quote_stored, proof.get("decisionId"))


def reverify_evidence(ask: dict, item: dict) -> bool:
    if item["kind"] == "commit":
        repo = next((c["repo"] for c in ask.get("completion", {}).get("commits", []) if c["sha"] == item["ref"]), None)
        return commit_exists(item["ref"], repo)
    if item["kind"] == "tested":
        return wal_has_test(item["ref"])
    return False


def eligible(ask: dict, ts: float, data=None) -> tuple:
    """(ok, reason). The 24h clock is stateSince; done needs verified evidence, cancelled needs re-verifiable proof."""
    state = ask["state"]
    if state not in CLOSED:
        return False, f"state is {state}; only done, cancelled or superseded asks can be removed"
    age = ts - parse_ts(ask["stateSince"])
    if age <= GATE_SECONDS:
        return False, f"{state} for {age / 3600:.1f}h; removal needs more than 24h"
    if state == "done":
        verified = [e for e in ask["evidence"] if e["verification"]["status"] == "verified"]
        if not verified:
            return False, "done without verified evidence"
        if not any(reverify_evidence(ask, e) for e in verified):
            return False, "no verified evidence re-verifies now (rewritten commit or missing WAL note)"
        return True, "done with verified evidence for more than 24h"
    if state == "cancelled":
        try:
            reverify_proof(data, ask)
        except (WAError, KeyError) as error:
            return False, f"cancel proof no longer verifies: {error}"
        return True, "cancelled with verified user proof for more than 24h"
    target = next((r["target"] for r in ask.get("related", []) if r["kind"] == "superseded_by"), None)
    if data is not None and target in data["asks"] and data["asks"][target]["state"] in CLOSED:
        return True, "superseded by a closed ask"
    return False, "superseding ask is not closed"


# --------------------------------------------------------------------------- ask construction and cli

def find_message(data, ref):
    if ref in data["messages"]:
        return data["messages"][ref]
    hits = [m for m in data["messages"].values() if len(ref) >= 8 and (m["origin"]["log"].get("messageUuid") or "").startswith(ref)]
    if len(hits) != 1:
        raise WAError(f"message {ref!r} not found" if not hits else f"message prefix {ref!r} is ambiguous")
    return hits[0]


def find_ask(data, ref):
    if ref in data["asks"]:
        return data["asks"][ref]
    legacy = [a for a in data["asks"].values() if ref in (a.get("migratedFrom", {}).get("id"), a.get("migratedFrom", {}).get("sourceId"))]
    if len(legacy) == 1:
        return legacy[0]
    raise WAError(f"ask {ref!r} not found")


def cli_actor(name: str, provider="claude-code") -> dict:
    name = name or "main"
    if name.startswith("agent:"):
        return actor("agent", provider, label=name, agent=name[6:])
    return actor("agent", provider, label=name)


def owner_span(data: dict, ask: dict, owner: str, who: dict, provider="claude-code") -> tuple:
    """(span_ids_to_end, [new owner span]) for a reassignment."""
    ended = [s["spanId"] for s in ask.get("assignments", []) if s.get("role") == "owner"
             and s.get("status") not in ("reassigned", "stopped", "lost", "finished", "failed")]
    if owner in ("", "unassigned", "none"):
        return ended, []
    holder = cli_actor(owner, provider)
    span = {"spanId": f"S-{len(ask.get('assignments', [])) + 1}", "actor": holder, "role": "owner", "startedAt": iso(now()),
            "lastSeenAt": iso(now()), "status": "active"}
    return ended, [span]


def new_ask(data, *, description, kind="request", owner="unassigned", message=None, source=None, who, provider="claude-code",
            next_step="", tickets=(), branch="", origin_actor=None, at=None, legacy=None, state=None, extra=None) -> dict:
    if kind not in KINDS:
        raise WAError("kind must be one of " + ", ".join(KINDS))
    aid = mint(data, "A")
    if message is not None:
        msg_rec = data["messages"][message]
        origin = {"actor": msg_rec["origin"]["actor"], "at": msg_rec["origin"]["at"], "messageId": message,
                  "log": msg_rec["origin"]["log"], "binding": msg_rec["origin"]["binding"]}
        src = {"kind": "user", "ref": message}
    else:
        origin = {"actor": origin_actor or who, "at": at or iso(now())}
        src = source or {"kind": "inferred", "ref": "cli", "why": "created without a captured message"}
    ask = {"id": aid, "kind": kind, "origin": json.loads(json.dumps(origin)), "source": src,
           "request": {"compressed": short(description, 300)}, "state": state or "open", "stateSince": iso(now()),
           "times": {"startedAt": iso(now()), "lastCheckedAt": iso(now())}, "related": [], "prerequisites": [],
           "assignments": [], "evidence": [], "completion": {"status": "none"}, "writer": who["hiveId"]}
    if next_step:
        ask["nextStep"] = short(next_step)
    refs = [{"system": "goodqa", "ref": t[:512]} for t in tickets] + ([{"system": "branch", "ref": branch[:512]}] if branch else [])
    if refs:
        ask["externalRefs"] = refs
    if legacy:
        ask["migratedFrom"] = legacy
    if extra:
        ask.update(extra)
    emit(data, "created", "ask", aid, {"ask": ask}, who)
    ended, spans = owner_span(data, data["asks"][aid], owner, who, provider)
    if spans:
        emit(data, "assign", "ask", aid, {"ended": ended, "spans": spans}, who)
        if data["asks"][aid]["state"] == "open":
            emit(data, "state", "ask", aid, {"from": "open", "to": "assigned", "reason": "owner assigned"}, who)
    return data["asks"][aid]


def cmd_split(args):
    who = cli_actor(args.actor)
    with transaction() as data:
        msg = find_message(data, args.msg)
        if msg["triage"]["status"] == "no_ask":
            raise WAError("message was marked no-ask; it cannot also have asks")
        made = [new_ask(data, description=text, kind=args.kind, owner=args.owner, message=msg["id"], who=who,
                        next_step=args.next or "", tickets=args.ticket or (), branch=args.branch or "") for text in args.item]
        ids = list(msg["triage"].get("askIds", [])) + [a["id"] for a in made]
        emit(data, "triaged", "message", msg["id"], {"triage": {"status": "split", "at": iso(now()), "by": who, "askIds": ids}}, who)
    print("created " + ", ".join(a["id"] for a in made))


def cmd_no_ask(args):
    if len(args.reason.strip()) < 10:
        raise WAError("--reason needs at least 10 characters")
    who = cli_actor(args.actor)
    with transaction() as data:
        msg = find_message(data, args.msg)
        if msg["triage"].get("askIds"):
            raise WAError("message already has asks")
        emit(data, "triaged", "message", msg["id"], {"triage": {"status": "no_ask", "at": iso(now()), "by": who,
                                                                "reason": short(args.reason)}}, who)
    print(f"{msg['id']} marked no-ask")


def recompute_completion(ask: dict, who: dict, repo=None) -> dict:
    commits = []
    for item in ask["evidence"]:
        if item["kind"] == "commit" and item["verification"]["status"] == "verified":
            commits.append({"repo": os.path.realpath(repo or os.getcwd())[:512], "branch": git_branch(repo), "sha": item["ref"],
                            "at": item["claimedAt"], "verification": item["verification"], "mergeStatus": "unknown"})
    return {"status": "verified", "claimedAt": iso(now()), "verifiedAt": iso(now()), "verifiedBy": who, "commits": commits,
            "pendingRealTests": ask.get("completion", {}).get("pendingRealTests", [])}


def cmd_update(args):
    who = cli_actor(args.actor)
    with transaction() as data:
        ask = find_ask(data, args.id)
        aid = ask["id"]
        if args.state == "cancelled":
            raise WAError("use `cancel` with user proof to cancel an ask")
        if args.state == "superseded" and not any(
                r["kind"] == "superseded_by" and r["target"] in data["asks"] and data["asks"][r["target"]]["state"] not in CLOSED
                for r in ask["related"]):
            raise WAError("superseding needs `relate A superseded_by B` where B exists and is not closed")
        for text in args.evidence or ():
            item = parse_evidence(text, who, args.repo)
            item["id"] = f"V-{len(ask['evidence']) + 1}"
            emit(data, "evidence", "ask", aid, {"evidence": item}, who)
        if args.owner is not None:
            ended, spans = owner_span(data, ask, args.owner, who)
            if ended or spans:
                emit(data, "assign", "ask", aid, {"ended": ended, "spans": spans}, who)
                if spans and ask["state"] == "open":
                    emit(data, "state", "ask", aid, {"from": "open", "to": "assigned", "reason": "owner assigned"}, who)
        if args.state:
            cur = ask["state"]
            if args.state != cur:
                if args.state not in TRANSITIONS.get(cur, []):
                    raise WAError(f"transition {cur} -> {args.state} is not allowed")
                if cur == "done":  # reopen: only by a human-sourced message
                    msg = find_message(data, args.reopen_by) if args.reopen_by else None
                    if not msg or not msg["humanCheck"]["isHuman"]:
                        raise WAError("reopening a done ask needs --reopen-by M-... (a human-captured message)")
                    emit(data, "reopened", "ask", aid, {"by": msg["id"]}, who)
                else:
                    payload = {"from": cur, "to": args.state, "reason": short(args.note or "update")}
                    if args.state == "blocked":
                        kind = args.block_reason or "external"
                        reason = {"kind": kind, "since": iso(now())}
                        if args.decision:
                            reason["decisionId"] = args.decision
                        elif kind == "user_input":
                            raise WAError("block-reason user_input needs --decision D-...")
                        if args.note:
                            reason["note"] = short(args.note)
                        payload["set"] = {"blockReason": reason}
                    if cur == "blocked":
                        payload["unset"] = ["blockReason"]
                    if args.state in ("ready", "done") and not ask["evidence"]:
                        raise WAError(f"{args.state} requires evidence (--evidence commit sha, PR#n, https URL or tested:WAL-ID)")
                    if args.state == "done":
                        if not any(e["verification"]["status"] == "verified" for e in ask["evidence"]):
                            raise WAError("done requires at least one verified evidence item (a commit that exists or a tested: WAL id); "
                                          "PR numbers and URLs are attested only")
                        if ask.get("completion", {}).get("pendingRealTests"):
                            raise WAError("done requires pendingRealTests to be empty")
                        payload.setdefault("set", {}).update(completion=recompute_completion(ask, who, args.repo),
                                                             removableAfter=iso(now() + GATE_SECONDS))
                        payload["set"]["times"] = {**ask["times"], "endedAt": iso(now())}
                    emit(data, "state", "ask", aid, payload, who)
        checked = {}
        if args.next is not None:
            checked["nextStep"] = short(args.next)
        if args.description:
            checked["description"] = short(args.description)
        refs = [{"system": "goodqa", "ref": t[:512]} for t in args.ticket or ()]
        if args.branch:
            refs.append({"system": "branch", "ref": args.branch[:512]})
        if refs:
            checked["externalRefs"] = refs
        emit(data, "checked", "ask", aid, checked, who)
    print(f"{aid} {ask['state']} owner={owner_of(ask) or 'none'}")


def cmd_cancel(args):
    who = cli_actor(args.actor)
    with transaction() as data:
        ask = find_ask(data, args.id)
        sync_all(data)
        if "cancelled" not in TRANSITIONS.get(ask["state"], []):
            raise WAError(f"cannot cancel an ask that is {ask['state']}")
        proof = proof_for(data, ask, args.file, args.line, args.uuid, args.quote, args.binding, args.decision)
        emit(data, "cancelled", "ask", ask["id"], {"proof": proof, "reason": short(args.reason or "cancelled by the user")}, who)
    print(f"{ask['id']} cancelled (proof verified, binding {args.binding}; removable after 24h)")


def drop(data, ask, why, proof, kind):
    archive = files()["archive"]
    line = json.dumps({"archivedAt": iso(now()), "ask": ask}, ensure_ascii=False, sort_keys=True)
    fd = os.open(archive, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    try:
        number = (os.fstat(fd).st_size and prov.read_small(archive, MAX_STORE_BYTES).count(b"\n")) or 0
        os.write(fd, (line + "\n").encode())
        os.fsync(fd)
    finally:
        os.close(fd)
    uuids = [m["origin"]["log"].get("messageUuid") for m in data["messages"].values() if m["id"] == ask["origin"].get("messageId")]
    tomb = {"id": ask["id"], "type": "ask", "finalState": ask["state"], "stateSince": ask["stateSince"], "removedAt": iso(now()),
            "removedBy": actor("harness", "harness", label="work-assignments"), "proofKind": kind, "proof": proof,
            "messageUuids": [u for u in uuids if u], "archive": {"file": archive.name, "line": number + 1}, "snapshotSha256": sha(line)}
    if tomb["proof"] is None:
        del tomb["proof"]
    emit(data, "tombstoned", "ask", ask["id"], {"tombstone": tomb}, tomb["removedBy"])


def removal_proof(ask: dict) -> tuple:
    if ask["state"] == "done":
        return "verified_evidence", next(e for e in ask["evidence"] if e["verification"]["status"] == "verified")
    if ask["state"] == "cancelled":
        return "user_proof", ask["cancellation"]["proof"]
    return "superseded_by_closed", None


def cmd_remove(args):
    with transaction() as data:
        ask = find_ask(data, args.id)
        ok, why = eligible(ask, now(), data)
        if not ok:
            raise WAError(f"refused: {why}")
        kind, proof = removal_proof(ask)
        drop(data, ask, why, proof, kind)
    print(f"{args.id} removed ({why})")


def cmd_prune(args):
    ts, removed, kept = now(), [], 0
    with transaction() as data:
        for ask in list(data["asks"].values()):
            ok, why = eligible(ask, ts, data)
            if ok and args.apply:
                kind, proof = removal_proof(ask)
                drop(data, ask, why, proof, kind)
                removed.append(ask["id"])
            elif ok:
                removed.append(ask["id"] + " (dry run)")
            else:
                kept += 1
    print(f"{'removed' if args.apply else 'would remove'} {len(removed)}: {', '.join(removed[:20])}; kept {kept}")


def cmd_relate(args):
    who = cli_actor(args.actor)
    inverse = {"supersedes": "superseded_by", "superseded_by": "supersedes", "extends": "extended_by", "extended_by": "extends",
               "duplicates": "duplicates", "parent_of": "child_of", "child_of": "parent_of", "decided_by": "decides",
               "decides": "decided_by", "follows": "see_also", "see_also": "see_also"}
    if args.kind not in inverse:
        raise WAError("kind must be one of " + ", ".join(sorted(inverse)))
    with transaction() as data:
        left = data["asks"].get(args.a) or data["decisions"].get(args.a)
        right = data["asks"].get(args.b) or data["decisions"].get(args.b)
        if not left or not right:
            raise WAError("both ids must exist")
        for src, dst, kind in ((left, right, args.kind), (right, left, inverse[args.kind])):
            ttype = "ask" if src["id"] in data["asks"] else "decision"
            emit(data, "relate", ttype, src["id"], {"relation": {"kind": kind, "target": dst["id"], "at": iso(now()), "by": who}}, who)
    print(f"{args.a} {args.kind} {args.b}")


def cmd_prereq(args):
    who = cli_actor(args.actor)
    with transaction() as data:
        ask = find_ask(data, args.id)
        target = data["asks"].get(args.ref) or data["decisions"].get(args.ref)
        kind = "external" if not target else ("ask" if args.ref in data["asks"] else "decision")
        status = "pending"
        if target:
            status = "satisfied" if target["state"] in ("done", "answered") else "pending"
        emit(data, "prerequisite", "ask", ask["id"], {"prerequisite": {"kind": kind, "ref": args.ref[:512], "requiredState":
                                                                       "answered" if kind == "decision" else "done", "status": status,
                                                                       "checkedAt": iso(now())}}, who)
    print(f"{ask['id']} waits on {args.ref} ({status})")


def cmd_decision(args):
    who = cli_actor(args.actor)
    with transaction() as data:
        if args.action == "ask":
            did = mint(data, "D")
            rec = {"id": did, "origin": {"actor": who, "at": iso(now())}, "source": {"kind": "inferred", "ref": "cli", "why": "decision recorded by an agent"},
                   "question": {"askedBy": who, "tool": args.tool, "at": iso(now()), "data": {"summary": short(args.text)}},
                   "state": "asked", "stateSince": iso(now()), "related": [], "writer": who["hiveId"]}
            emit(data, "created", "decision", did, {"decision": rec}, who)
            for ref in args.ask or ():
                src = find_ask(data, ref)
                for a, b, k in ((did, src["id"], "decides"), (src["id"], did, "decided_by")):
                    emit(data, "relate", "decision" if a == did else "ask", a, {"relation": {"kind": k, "target": b, "at": iso(now()), "by": who}}, who)
            print(did)
        elif args.action == "answer":
            dec = data["decisions"].get(args.id)
            msg = find_message(data, args.msg)
            if not dec or dec["state"] not in ("asked", "assumed"):
                raise WAError("decision not found or already closed")
            if not msg["humanCheck"]["isHuman"] or msg["origin"]["binding"]["status"] != "bound":
                raise WAError("an answer needs a human message bound to a transcript line (run `sync`)")
            answer = {"actor": msg["origin"]["actor"], "at": msg["origin"]["at"], "messageId": msg["id"], "log": msg["origin"]["log"],
                      "binding": msg["origin"]["binding"], "text": msg["text"]}
            emit(data, "answered", "decision", dec["id"], {"answer": answer}, msg["origin"]["actor"])
            print(f"{dec['id']} answered")
        else:
            dec = data["decisions"].get(args.id)
            if not dec or dec["state"] != "asked":
                raise WAError("decision not found or not asked")
            emit(data, "assumed", "decision", dec["id"], {"assumption": {
                "text": short(args.text), "source": {"kind": "inferred", "ref": "cli", "why": "agent assumption"}, "by": who, "at": iso(now())}}, who)
            print(f"{dec['id']} assumed (never a user requirement)")


def cmd_status(args):
    policy = load_policy()
    with reading() as data:
        if args.json:
            print(json.dumps({k: data[k] for k in ("messages", "asks", "decisions", "index")}, indent=1, sort_keys=True))
            return
        print(digest(data, policy, args.session, limit=args.limit))
    fails = pending_failures()
    if fails:
        print(f"CAPTURE FAILURES: {len(fails)} unacknowledged (work_assignments.py failures)")
    chain = verify_events()
    if chain:
        print("EVENT LOG PROBLEM: " + "; ".join(chain))


def cmd_show(args):
    with reading() as data:
        rec = data["asks"].get(args.id) or data["decisions"].get(args.id) or data["messages"].get(args.id) or data["tombstones"].get(args.id)
        if rec is None:
            rec = find_ask(data, args.id)
        print(json.dumps(rec, indent=1, sort_keys=True))


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
            os.replace(path, path.with_name(f"work-ledger.failures.acked-{stamp}.jsonl"))
        print(f"acknowledged {len(fails)} (kept as acked file)")
    if not fails:
        print("no unacknowledged failures")


def verify_events() -> list:
    """Per-hive hash chain, and the snapshot equals a fold of the events (index and session caches excluded)."""
    problems, prev = [], {}
    try:
        events = read_events()
    except StoreCorrupt as error:
        return [str(error)]
    for ev in events:
        want = prev.get(ev["hiveId"], ZERO)
        if ev["prevSha256"] != want or ev["sha256"] != event_sha(ev):
            problems.append(f"{ev['id']}: chain broken")
            break
        prev[ev["hiveId"]] = ev["sha256"]
    if problems:
        return problems
    try:
        snap = read_snapshot()
    except StoreCorrupt as error:
        return [str(error)]
    if snap is None:
        return [] if not events else ["snapshot missing; run recover"]
    folded = fold(events)
    for key in ("messages", "asks", "decisions", "tombstones", "violations"):
        if json.dumps(snap.get(key), sort_keys=True) != json.dumps(folded.get(key), sort_keys=True):
            problems.append(f"snapshot {key} differs from the event fold")
    return problems


def cmd_verify(args):
    problems = verify_events()
    print("event log and snapshot ok" if not problems else "BROKEN: " + "; ".join(problems))
    return 1 if problems else 0


def cmd_recover(args):
    with locked():
        events = read_events()
        if not events:
            raise WAError("no events to rebuild from")
        data = fold(events)
        old = read_snapshot_raw()
        for key in ("sessions",):
            if old:
                data[key] = old.get(key, {})
        write_private(files()["snap"], json.dumps(data, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode())
    print(f"snapshot rebuilt from {len(events)} event(s)")


def read_snapshot_raw():
    try:
        return json.loads(prov.read_small(files()["snap"], MAX_STORE_BYTES))
    except (prov.Problem, ValueError):
        return None


LEDGER_STATES = {"SHIPPED": "ready", "ANSWERED": "ready", "SUPERSEDED": "open", "STALLED": "blocked", "IN_PROGRESS": "in_progress",
                 "READY": "ready", "UNKNOWN": "open"}
V1_KINDS = {"decision": "question", "question": "question"}


def walk_to(data, aid, target, who, set_=None, note=""):
    """Emit the legal state events from the ask's current state to `target` (the import path: open/assigned first)."""
    path = {"open": [], "assigned": ["assigned"], "in_progress": ["assigned", "in_progress"],
            "ready": ["assigned", "in_progress", "ready"], "blocked": ["blocked"]}[target]
    for step in path:
        cur = data["asks"][aid]["state"]
        if cur == step:
            continue
        if step not in TRANSITIONS[cur]:
            continue
        payload = {"from": cur, "to": step, "reason": note or "import"}
        if step == "blocked":
            payload["set"] = set_ or {}
        emit(data, "state", "ask", aid, payload, who)


def import_ask(data, *, sid, desc, kind, status, at, evidence, next_step, no_owner, legacy, who, extra_note=""):
    at = iso(parse_ts(at)) if parse_ts(at) else iso(now())  # a malformed legacy timestamp must not poison the record
    state = LEDGER_STATES.get(status, "open")
    if state == "ready" and not evidence:
        state = "in_progress"  # ready needs evidence; the ledger had none
    note = (extra_note + " " + next_step).strip()
    if status == "SUPERSEDED":
        note = ("ledger says SUPERSEDED: needs a human-sourced supersede or cancel. " + note).strip()
    ask = new_ask(data, description=desc, kind=kind if kind in KINDS else V1_KINDS.get(kind, "request"),
                  owner="unassigned" if no_owner else "main", who=who, next_step=note,
                  origin_actor=actor("harness", "other", label="ledger-import"), at=at,
                  source={"kind": "file", "ref": sid[:512], "why": "imported from the ask-audit ledger"}, legacy=legacy)
    aid = ask["id"]
    if evidence:
        item = {"id": "V-1", "kind": "log", "ref": short(evidence, 512), "claimedBy": who, "claimedAt": iso(now()),
                "verification": verification("attested")}
        emit(data, "evidence", "ask", aid, {"evidence": item}, who)
    if state != "open":
        walk_to(data, aid, state, who, {"blockReason": {"kind": "external", "since": iso(now()),
                                                         "note": "ledger status STALLED; needs an owner"}} if state == "blocked" else None,
                "imported ledger status " + status)
    return data["asks"][aid]


def cmd_import(args):
    path = Path(args.file)
    rows = [json.loads(line) for line in prov.read_small(path, 64 << 20).decode("utf-8").splitlines() if line.strip()]
    who = actor("harness", "harness", label="work-assignments-import")
    added = skipped = 0
    with transaction() as data:
        have = {a.get("migratedFrom", {}).get("sourceId") for a in data["asks"].values()} | set(data["tombstones"])
        for row in rows:
            source_id = "ledger:" + str(row.get("id"))
            if source_id in have:
                skipped += 1
                continue
            status = str(row.get("status")).upper()
            import_ask(data, sid=f"LEDGER.jsonl:{row.get('id')}", desc=str(row.get("ask") or row.get("id")), kind=row.get("kind"),
                       status=status, at=str(row.get("when") or iso(now())), evidence=str(row.get("evidence") or ""),
                       next_step=str(row.get("next") or ""), no_owner=status in ("STALLED", "UNKNOWN"),
                       legacy={"sourceId": source_id}, who=who)
            added += 1
    print(f"imported {added}, skipped {skipped} already present")


def cmd_migrate(args):
    """One-way, idempotent v1 -> v2 (DESIGN.md field map) for items; legacy ids stay under migratedFrom."""
    src = Path(args.file or files()["v1"])
    v1 = json.loads(prov.read_small(src, MAX_STORE_BYTES))
    if v1.get("schema") != 1 or not isinstance(v1.get("items"), dict):
        raise WAError("not a schema 1 work-assignments file")
    who = actor("harness", "harness", label="work-assignments-migrate")
    added = skipped = 0
    with transaction() as data:
        have = set()
        for a in data["asks"].values():
            have |= {(a.get("migratedFrom") or {}).get("id"), (a.get("migratedFrom") or {}).get("sourceId")}
        for wid, item in sorted(v1["items"].items()):
            if wid in have or (item.get("source_id") and item["source_id"] in have):
                skipped += 1
                continue
            imported = item.get("imported") or {}
            status = str(imported.get("ledger_status") or "").upper() or {
                "in_progress": "IN_PROGRESS", "blocked": "STALLED", "ready": "READY", "done": "READY",
                "assigned": "IN_PROGRESS"}.get(item.get("state"), "UNKNOWN")
            legacy = {"schema": 1, "id": wid}
            if item.get("source_id"):
                legacy["sourceId"] = item["source_id"]
            import_ask(data, sid=f"v1:{wid}", desc=item["description"], kind=item.get("kind"), status=status,
                       at=str(imported.get("when") or item.get("created") or iso(now())),
                       evidence=" ".join(str(e.get("ref", "")) for e in item.get("evidence", []))[:512],
                       next_step=item.get("next_step", ""), no_owner=item.get("owner") in ("unassigned", "none", ""),
                       legacy=legacy, who=who, extra_note="" if status in ("STALLED", "UNKNOWN") else "")
            added += 1
    print(f"migrated {added} item(s), skipped {skipped} already present (v1 messages stay in {src.name}; sync re-captures live ones)")


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
    s.add_argument("--block-reason", choices=("prerequisite", "user_input", "external", "resource", "review")); s.add_argument("--decision")
    s.add_argument("--reopen-by")
    s = sub.add_parser("cancel"); s.add_argument("id"); s.add_argument("--uuid", required=True); s.add_argument("--file", required=True)
    s.add_argument("--line", type=int, required=True); s.add_argument("--quote", required=True); s.add_argument("--actor", default="main")
    s.add_argument("--binding", default="explicit_reference", choices=("answer_to_cancel_question", "explicit_reference", "same_message_retraction", "answer_to_decision"))
    s.add_argument("--decision"); s.add_argument("--reason")
    s = sub.add_parser("remove"); s.add_argument("id")
    s = sub.add_parser("prune"); s.add_argument("--apply", action="store_true")
    s = sub.add_parser("relate"); s.add_argument("a"); s.add_argument("kind"); s.add_argument("b"); s.add_argument("--actor", default="main")
    s = sub.add_parser("prereq"); s.add_argument("id"); s.add_argument("ref"); s.add_argument("--actor", default="main")
    s = sub.add_parser("decision"); s.add_argument("action", choices=("ask", "answer", "assume")); s.add_argument("--id"); s.add_argument("--text")
    s.add_argument("--tool", default="other", choices=("AskUserQuestion", "request_user_input", "plain_text", "goodqa_ticket", "other"))
    s.add_argument("--ask", action="append"); s.add_argument("--msg"); s.add_argument("--actor", default="main")
    s = sub.add_parser("import"); s.add_argument("file")
    s = sub.add_parser("migrate"); s.add_argument("file", nargs="?")
    s = sub.add_parser("sync"); s.add_argument("--session")
    s = sub.add_parser("failures"); s.add_argument("--ack", action="store_true")
    s = sub.add_parser("show"); s.add_argument("id")
    sub.add_parser("recover"); sub.add_parser("verify")
    return p


COMMANDS = {"status": cmd_status, "split": cmd_split, "no-ask": cmd_no_ask, "update": cmd_update, "cancel": cmd_cancel,
            "remove": cmd_remove, "prune": cmd_prune, "relate": cmd_relate, "prereq": cmd_prereq, "decision": cmd_decision,
            "import": cmd_import, "migrate": cmd_migrate, "sync": cmd_sync, "failures": cmd_failures, "show": cmd_show,
            "recover": cmd_recover, "verify": cmd_verify}


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
