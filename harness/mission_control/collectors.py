"""Mission Control collectors (GoodQA #15585 AC-1..AC-4, AC-9, AC-13). Each collector has a fixed interval;
`tick()` does one bounded unit of work and never raises. All reads go through safeio.Reader/Runner."""

from __future__ import annotations

import json
import os
import re
import stat
import time
from pathlib import Path

import events as ev
from safeio import Refused, TICKET_RE

TOOL_EVENTS = ("pretool", "posttool", "PreToolUse", "PostToolUse")
LIFECYCLE_EVENTS = ("subagent", "subagent_stop", "SubagentStart", "SubagentStop", "prompt", "UserPromptSubmit", "session",
                    "SessionStart", "stop", "Stop", "compact", "PreCompact", "pending_stop")
DEPLOY_RE = re.compile(r"\bDEPLOYED\b|\bdeployed to (?:live|prod)|\blive deploy\b|\bdeploy(?:ed)? (?:live|to production)\b",
                       re.I)
TERMINAL = ("done", "handoff", "returned", "idle-helper", "unverified-legacy", "superseded", "wontdo", "legacy")


class Collector:
    name = "collector"
    interval = 60.0

    def __init__(self, hub, health):
        self.hub, self.health = hub, health
        self.next_at = 0.0

    def due(self, now: float) -> bool:
        return now >= self.next_at

    def run(self, now: float) -> None:
        self.next_at = now + self.interval  # set first: a failing source is never retried faster
        try:
            detail = self.tick(now)
            self.health.ok(self.name, detail)
        except Refused as exc:
            self.health.error(self.name, f"refused: {exc}")
        except Exception as exc:  # noqa: BLE001 - a collector failure is shown, never fatal
            self.health.error(self.name, f"{type(exc).__name__}: {str(exc)[:160]}")

    def tick(self, now: float):
        raise NotImplementedError


class Health:
    def __init__(self, hub):
        self.hub, self.rows = hub, {}

    def _set(self, name, status, detail):
        row = {"name": name, "status": status, "checked": time.time(), "detail": ev.short(detail or "", 160)}
        changed = self.rows.get(name, {}).get("status") != status
        self.rows[name] = row
        if changed or status != "ok":
            self.hub.snapshot("health", list(self.rows.values()))

    def ok(self, name, detail=""):
        self._set(name, "ok", detail)

    def error(self, name, detail):
        self._set(name, "error", detail)

    def off(self, name, detail):
        self._set(name, "off", detail)

    def snapshot(self):
        return list(self.rows.values())


class _Tail:
    __slots__ = ("ino", "offset", "partial", "runtime", "session", "agent", "size", "dropped", "skipping")

    def __init__(self, ino, offset, runtime, session, agent):
        self.ino, self.offset, self.partial = ino, offset, b""
        self.dropped, self.skipping = 0, False
        self.runtime, self.session, self.agent, self.size = runtime, session, agent, offset


def split_lines(state: _Tail, data: bytes, max_line: int = 64 * 1024) -> list[bytes]:
    """Complete lines from state.partial + data; a partial tail is kept (bounded) until its newline."""
    buf = state.partial + data
    lines = buf.split(b"\n")
    state.partial = lines.pop()
    out = []
    for n, line in enumerate(lines):
        if state.skipping and n == 0:
            state.skipping = False  # the tail of an over-long line already counted as dropped
            continue
        if len(line) > max_line:
            state.dropped += 1
        elif line.strip():
            out.append(line)
    if len(state.partial) > max_line:
        state.partial = b""  # an over-long line is dropped, not buffered without bound
        if not state.skipping:
            state.dropped += 1
        state.skipping = True
    return out


class WalTailer(Collector):
    """Tails Claude WALs (~/.claude/wals/<session>/*.jsonl) and Codex WALs (~/.agent-harness/codex-wals/<thread>/)."""
    name = "wals"
    interval = 2.0
    RESCAN_S = 30.0
    WINDOW_S = 48 * 3600
    MAX_FILES = 4000
    READ_CAP = 256 * 1024

    def __init__(self, hub, health, reader, roots):
        super().__init__(hub, health)
        self.reader, self.roots = reader, roots  # [(Path, runtime)]
        self.files: dict[str, _Tail] = {}
        self.last_scan = 0.0
        self.last_items: dict[tuple, dict] = {}
        self.max_events_per_tick = 60

    def _discover(self, now: float, initial: bool) -> None:
        for root, runtime in self.roots:
            try:
                sessions = list(os.scandir(root))
            except OSError:
                continue
            for entry in sessions:
                if len(self.files) >= self.MAX_FILES:
                    return
                try:
                    if entry.is_symlink() or not entry.is_dir(follow_symlinks=False):
                        continue
                    if now - entry.stat(follow_symlinks=False).st_mtime > self.WINDOW_S and not initial:
                        pass  # appends do not touch the directory mtime, so old directories are still listed
                    names = os.scandir(entry.path)
                except OSError:
                    continue
                for item in names:
                    if not item.name.endswith(".jsonl") or item.path in self.files:
                        continue
                    try:
                        info = item.stat(follow_symlinks=False)
                    except OSError:
                        continue
                    if not stat.S_ISREG(info.st_mode) or now - info.st_mtime > self.WINDOW_S:
                        continue
                    agent = "main" if item.name == "main.jsonl" else re.sub(r"^agent-", "", item.name[:-6])
                    tail = _Tail(info.st_ino, info.st_size if initial else 0, runtime, entry.name, agent)
                    self.files[item.path] = tail
                    if initial:
                        self._seed_last(item.path, tail, info)
                    if len(self.files) >= self.MAX_FILES:
                        return

    def _seed_last(self, path: str, tail: _Tail, info) -> None:
        """Remember the newest meaningful line of a file without replaying it as a pulse."""
        try:
            with self.reader.open(path) as handle:
                handle.seek(max(0, info.st_size - 16384))
                lines = handle.read(16384).split(b"\n")
        except (OSError, Refused):
            return
        newest = None
        for raw in reversed(lines):
            entry = _json(raw)
            if not entry:
                continue
            newest = newest or entry
            if _meaningful(entry):
                self._remember(tail, entry)
                break
        if newest:
            self._remember(tail, newest, meaningful=False)

    def _remember(self, tail: _Tail, entry: dict, meaningful: bool = True) -> None:
        """Keep the newest meaningful work item, and separately the time of any activity (tool calls included)."""
        key = (tail.runtime, tail.session, tail.agent)
        at = str(entry.get("at", ""))[:40]
        item = dict(self.last_items.get(key) or {"at": "", "event": "", "note": ""})
        if meaningful:
            item.update({"at": at, "event": str(entry.get("event", ""))[:40], "note": ev.short(_note(entry), 200)})
        item["active_at"] = max(at, item.get("active_at") or "", item.get("at") or "")
        self.last_items[key] = item
        if len(self.last_items) > 6000:
            for old in list(self.last_items)[:1000]:
                self.last_items.pop(old, None)

    def tick(self, now: float):
        initial = self.last_scan == 0.0
        if initial or now - self.last_scan >= self.RESCAN_S:
            self._discover(now, initial)
            self.last_scan = now
        budget = self.max_events_per_tick
        overflow = 0
        for path, tail in list(self.files.items()):
            try:
                info = os.stat(path, follow_symlinks=False)
            except OSError:
                self.files.pop(path, None)
                continue
            if info.st_ino != tail.ino or info.st_size < tail.offset:  # replaced or truncated: start over
                tail.ino, tail.offset, tail.partial = info.st_ino, 0, b""
            if info.st_size == tail.offset:
                continue
            try:
                with self.reader.open(path) as handle:
                    handle.seek(tail.offset)
                    data = handle.read(self.READ_CAP)
            except (OSError, Refused):
                self.files.pop(path, None)
                continue
            tail.offset += len(data)
            emitted = self._lines(tail, split_lines(tail, data), budget)
            budget -= emitted[0]
            overflow += emitted[1]
        if overflow:
            self.hub.publish(ev.make("wal", "wals", f"{overflow} more WAL writes in this burst",
                                     eid=f"walburst:{int(now * 1000)}", count=overflow))
        return f"{len(self.files)} files"

    def _lines(self, tail: _Tail, lines: list[bytes], budget: int) -> tuple[int, int]:
        tools = 0
        sent = skipped = 0
        last_tool = None
        for raw in lines:
            entry = _json(raw)
            if not entry:
                continue
            kind = str(entry.get("event", ""))
            if kind in TOOL_EVENTS:
                tools += 1
                last_tool = entry
                self._remember(tail, entry, meaningful=False)
                continue
            self._remember(tail, entry, meaningful=_meaningful(entry))
            if sent >= budget:
                skipped += 1
                continue
            sent += self._emit(tail, entry, kind)
        if tools:
            if sent < budget:
                tool = str((last_tool or {}).get("tool", "tool"))[:40]
                self.hub.publish(ev.make("wal", f"{tail.runtime}-wal",
                                         f"{tools} tool call{'s' if tools > 1 else ''} · last {tool}",
                                         eid=f"wal:{tail.session}:{tail.agent}:{tail.offset}:t", count=tools,
                                         actor=self._actor(tail), quiet=True))
                sent += 1
            else:
                skipped += tools
        return sent, skipped

    def _actor(self, tail: _Tail) -> dict:
        return {"runtime": tail.runtime, "session": tail.session, "agent": tail.agent}

    def _emit(self, tail: _Tail, entry: dict, kind: str) -> int:
        note = _note(entry)
        actor = self._actor(tail)
        subject = {"ticket": _ticket_in(note)}
        meaningful = _meaningful(entry)
        summary = f"{kind}: {note}" if meaningful else _lifecycle_summary(entry, kind, note)
        self.hub.publish(ev.make("wal", f"{tail.runtime}-wal", summary,
                                 eid=f"wal:{tail.session}:{tail.agent}:{tail.offset}:{str(entry.get('id', ''))[:20]}",
                                 actor=actor, subject=subject, quiet=not meaningful,
                                 severity="warn" if kind in ("blocker", "risk", "incident") else "info"))
        if DEPLOY_RE.search(note) or kind in ("deploy", "deployed"):
            self.hub.publish(ev.make("deploy", f"{tail.runtime}-wal", note or kind, actor=actor, subject=subject,
                                     eid=f"deploy:{tail.session}:{tail.agent}:{tail.offset}"))
            return 2
        return 1

    def last_for(self, runtime: str, session: str, agent: str):
        return self.last_items.get((runtime, session, agent))


def _json(raw: bytes):
    try:
        value = json.loads(raw.decode("utf-8", "replace"))
    except (json.JSONDecodeError, ValueError):
        return None
    return value if isinstance(value, dict) else None


def _disposition(value) -> dict | None:
    """The recorded decision for a DROPPED/SILENT owner (waiting, resumed, closed, reassigned), shown beside the state."""
    if not isinstance(value, dict) or not isinstance(value.get("kind"), str):
        return None
    until = value.get("until") if isinstance(value.get("until"), (int, float)) else None
    return {"kind": re.sub(r"[^a-z_-]", "", value["kind"].lower())[:20],
            "ref": ev.short(str(value.get("ref") or ""), 60), "reason": ev.short(str(value.get("reason") or ""), 200),
            "until": ev.iso(until) if until else None, "live": value.get("live") is True}


def _meaningful(entry: dict) -> bool:
    """A work item worth a feed row: a WAL note the agent wrote, not a hook's lifecycle, gate or tool record."""
    if entry.get("by"):  # written by a gate (dropped_gate pending_stop), not by the agent itself
        return False
    kind = str(entry.get("event", ""))
    if kind in TOOL_EVENTS or kind in LIFECYCLE_EVENTS:
        return False
    return bool(isinstance(entry.get("note"), str) and entry["note"].strip())


def _lifecycle_summary(entry: dict, kind: str, note: str) -> str:
    agent = re.sub(r"[^A-Za-z0-9_-]", "", str(entry.get("agent_id") or ""))[:8]
    role = re.sub(r"[^A-Za-z0-9_ -]", "", str(entry.get("agent_type") or ""))[:30]
    if kind in ("subagent", "SubagentStart"):
        return f"started {role or 'agent'} {agent}".strip()
    if kind in ("subagent_stop", "SubagentStop"):
        return f"{role or 'agent'} {agent} stopped".strip()
    if kind in ("prompt", "UserPromptSubmit"):
        return "new prompt"
    if kind == "pending_stop":
        return "stop gate: pending work, no armed waiter"
    return f"{kind}: {note}" if note else kind


def _note(entry: dict) -> str:
    for field in ("note", "summary", "reason", "task", "source"):
        value = entry.get(field)
        if isinstance(value, str) and value.strip():
            return value
    if entry.get("prompt_chars"):
        return f"prompt ({entry['prompt_chars']} chars)"
    return ""


def _ticket_in(text: str) -> str:
    found = re.search(r"\b([a-z][a-z0-9-]{1,30}#\d{2,7})\b", text or "")
    return found.group(1) if found else ""


class Initiatives(Collector):
    name = "initiatives"
    interval = 2.0
    FIELDS = ("id", "initiative", "state", "milestones_done", "milestones_total", "pct", "owner", "ticket",
              "milestones", "next_step", "next_eta", "full_eta", "note", "updated", "estimate_by")

    def __init__(self, hub, health, reader, path):
        super().__init__(hub, health)
        self.reader, self.path = reader, Path(path) if path else None
        self.sig = None
        self.items: list[dict] = []
        self.stale = False
        self.error = ""

    def tick(self, now: float):
        if not self.path:
            self.health.off(self.name, "no initiatives file configured")
            return "off"
        try:
            info = os.stat(self.path, follow_symlinks=False)
        except OSError:
            return self._fail("initiatives file missing")
        sig = (info.st_ino, info.st_size, info.st_mtime_ns)
        previous = self.sig
        if sig == self.sig:
            if self.error:
                raise ValueError(self.error)
            return f"{len(self.items)} initiatives"
        self.sig = sig
        try:
            data = json.loads(self.reader.read(self.path, 1024 * 1024).decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return self._fail("initiatives file is not valid JSON; showing the last good copy")
        rows = data.get("initiatives") if isinstance(data, dict) else data
        if not isinstance(rows, list):
            return self._fail("initiatives file must be a list")
        self.items = [clean_initiative(r, n) for n, r in enumerate(rows[:100])]
        self.stale, self.error = False, ""
        self.publish(info.st_mtime)
        if previous is not None:
            self.hub.publish(ev.make("initiative", "initiatives", f"{len(self.items)} initiatives updated",
                                     eid=f"initiatives:{info.st_mtime_ns}"))
        return f"{len(self.items)} initiatives"

    def _fail(self, message: str):
        self.stale, self.error = True, message
        self.publish(None)
        raise ValueError(message)

    def publish(self, mtime) -> None:
        self.hub.snapshot("initiatives", self.snapshot(mtime))

    def snapshot(self, mtime=None) -> dict:
        return {"items": self.items, "stale": self.stale, "error": self.error, "path": str(self.path or ""),
                "mtime": mtime}


def _num(value):
    return value if isinstance(value, (int, float)) and not isinstance(value, bool) else None


def clean_initiative(row, index: int) -> dict:
    if not isinstance(row, dict):
        return {"id": f"row-{index}", "initiative": "data error", "error": "row is not an object"}
    out = {k: ev.short(row.get(k), 600) if isinstance(row.get(k), str) else None for k in Initiatives.FIELDS}
    out["id"] = re.sub(r"[^A-Za-z0-9._-]", "_", str(row.get("id") or f"row-{index}"))[:64]
    done, total, pct = _num(row.get("milestones_done")), _num(row.get("milestones_total")), _num(row.get("pct"))
    errors = []
    if done is not None and total is not None:
        if total <= 0 or done < 0 or done > total:
            errors.append("milestones_done must be between 0 and milestones_total")
            done = total = None
    elif (row.get("milestones_done") is not None and done is None) or (row.get("milestones_total") is not None
                                                                         and total is None):
        errors.append("milestone counts must be numbers or null")
    out["milestones_done"], out["milestones_total"] = done, total
    out["pct"] = round(100 * done / total) if done is not None and total else (
        pct if pct is not None and 0 <= pct <= 100 else None)
    out["estimate_by"] = out.get("estimate_by") or "main"
    items = []
    for part in (row.get("milestones") or "").split(" · ") if isinstance(row.get("milestones"), str) else []:
        part = part.strip()
        if part:
            items.append({"done": part.lower().startswith("done:"), "text": ev.short(part, 200)})
    out["milestone_items"] = items[:20]
    ticket = str(row.get("ticket") or "")
    out["ticket"] = ticket if TICKET_RE.match(ticket) else ""
    if errors:
        out["error"] = "; ".join(errors)
    return out


class Owners(Collector):
    name = "owners"
    interval = 60.0

    def __init__(self, hub, health, runner, tailer):
        super().__init__(hub, health)
        self.runner, self.tailer = runner, tailer
        self.rows: list[dict] = []
        self.states: dict[str, str] = {}
        self.session = ""

    def tick(self, now: float):
        code, out = self.runner.run("ah-owners", timeout=30)
        if code != 0:
            raise RuntimeError(f"ah owners exited {code}")
        data = json.loads(out)
        self.session = str(data.get("session") or "")
        rows = []
        for row in data.get("owners") or []:
            if not isinstance(row, dict):
                continue
            state = str(row.get("state") or "")
            idle = row.get("idle_s") if isinstance(row.get("idle_s"), (int, float)) else None
            if state in TERMINAL and (idle is None or idle > 6 * 3600):
                continue
            agent = str(row.get("agent_id") or "")
            if not re.fullmatch(r"[A-Za-z0-9_-]{1,40}", agent):
                continue  # a malformed id is dropped, never rewritten into a different-looking one
            ticket = str(row.get("ticket") or "")
            item = {"agent_id": agent, "runtime": "claude", "type": str(row.get("type") or "")[:40],
                    "task": ev.short(row.get("task") or "", 160), "ticket": ticket if TICKET_RE.match(ticket) else "",
                    "state": state[:24], "severity": str(row.get("severity") or "info")[:8],
                    "last_activity": str(row.get("last_activity") or "")[:40], "idle_s": idle,
                    "last_item": self.tailer.last_for("claude", self.session, agent) if self.tailer else None,
                    "disposition": _disposition(row.get("disposition"))}
            rows.append(item)
            previous = self.states.get(agent)
            if previous and previous != state:
                self.hub.publish(ev.make("owner", "ah-owners", f"{agent} {previous} → {state}",
                                         eid=f"owner:{agent}:{state}:{int(now)}",
                                         actor={"runtime": "claude", "session": self.session, "agent": agent},
                                         subject={"ticket": item["ticket"]},
                                         severity="high" if state.startswith(("DROPPED", "SILENT")) else "info"))
            self.states[agent] = state
        rows.sort(key=lambda r: (r["state"] not in ("live", "working"), r["idle_s"] or 0))
        self.rows = rows[:60] + self.codex_rows(now)
        self.hub.snapshot("owners", self.rows)
        return f"{len(rows)} owners"

    def codex_rows(self, now: float) -> list[dict]:
        rows = []
        if not self.tailer:
            return rows
        for (runtime, session, agent), item in list(self.tailer.last_items.items()):
            if runtime != "codex":
                continue
            rows.append({"agent_id": session[:40], "runtime": "codex", "type": "codex", "task": "", "ticket": "",
                         "state": "codex", "severity": "info", "last_activity": item.get("at"), "idle_s": None,
                         "last_item": item})
        rows.sort(key=lambda r: r.get("last_activity") or "", reverse=True)
        return rows[:12]

    def tickets(self) -> list[str]:
        return [r["ticket"] for r in self.rows if r.get("ticket") and r.get("state") in ("live", "working", "quiet")]


class GitHub(Collector):
    """Pushes and releases from the authenticated user's GitHub events feed: one request per minute."""
    name = "github"
    interval = 60.0

    def __init__(self, hub, health, runner):
        super().__init__(hub, health)
        self.runner = runner
        self.login = None
        self.seen: set[str] = set()
        self.seeded = False

    def tick(self, now: float):
        if not self.login:
            code, out = self.runner.run("gh-user", timeout=20)
            if code != 0:
                raise RuntimeError(f"gh api user exited {code}")
            self.login = str(json.loads(out).get("login") or "")
            if not self.login:
                raise RuntimeError("gh is not logged in")
        code, out = self.runner.run("gh-events", self.login, timeout=20)
        if code != 0:
            raise RuntimeError(f"gh events exited {code}")
        items = json.loads(out)
        if not isinstance(items, list):
            raise RuntimeError("unexpected events payload")
        fresh = 0
        for item in reversed(items[:100]):
            event = self.convert(item, historic=not self.seeded)
            if event is None or event["id"] in self.seen:
                continue
            self.seen.add(event["id"])
            self.hub.publish(event)
            fresh += 1
        if len(self.seen) > 5000:
            self.seen = set(list(self.seen)[-2000:])
        self.seeded = True
        return f"{fresh} new"

    @staticmethod
    def convert(item, historic=False):
        if not isinstance(item, dict):
            return None
        kind = item.get("type")
        repo = str((item.get("repo") or {}).get("name") or "")[:120]
        payload = item.get("payload") if isinstance(item.get("payload"), dict) else {}
        eid = "github:" + re.sub(r"[^0-9A-Za-z]", "", str(item.get("id") or ""))[:30]
        ts = ev.parse_ts(item.get("created_at"))
        if kind == "PushEvent":
            branch = str(payload.get("ref") or "").replace("refs/heads/", "")[:120]
            size = payload.get("size") if isinstance(payload.get("size"), int) else 1
            return ev.make("push", "github", f"{repo}: {size} commit(s) to {branch}", eid=eid, ts=ts,
                           subject={"repo": repo, "branch": branch}, count=max(1, size), historic=historic)
        if kind == "ReleaseEvent":
            release = payload.get("release") if isinstance(payload.get("release"), dict) else {}
            tag = str(release.get("tag_name") or "")[:80]
            return ev.make("release", "github", f"{repo}: release {tag} {payload.get('action', '')}", eid=eid,
                           ts=ts, subject={"repo": repo, "ref": tag}, historic=historic)
        if kind == "CreateEvent" and payload.get("ref_type") == "branch":
            branch = str(payload.get("ref") or "")[:120]
            return ev.make("push", "github", f"{repo}: new branch {branch}", eid=eid, ts=ts,
                           subject={"repo": repo, "branch": branch}, historic=historic)
        return None


class Tickets(Collector):
    """GoodQA checkpoint comments on tracked tickets: one ticket read per tick (10 s), round robin, max 12."""
    name = "goodqa"
    interval = 10.0
    MAX_TICKETS = 12

    def __init__(self, hub, health, runner, sources):
        super().__init__(hub, health)
        self.runner, self.sources = runner, sources  # callable -> iterable of ticket refs
        self.seen: dict[str, set] = {}
        self.cursor = 0

    def tracked(self) -> list[str]:
        out = []
        for ref in self.sources():
            ref = str(ref or "").replace("GoodQA ", "")
            if TICKET_RE.match(ref) and ref not in out:
                out.append(ref)
            if len(out) >= self.MAX_TICKETS:
                break
        return out

    def tick(self, now: float):
        tickets = self.tracked()
        if not tickets:
            return "no tickets"
        ref = tickets[self.cursor % len(tickets)]
        self.cursor += 1
        code, out = self.runner.run("ah-ticket-comments", ref, timeout=20)
        if code != 0:
            raise RuntimeError(f"ticket read for {ref} exited {code}")
        data = json.loads(out)
        comments = data.get("comments") if isinstance(data, dict) else None
        if not isinstance(comments, list):
            raise RuntimeError("unexpected comments payload")
        seen = self.seen.get(ref)
        first = seen is None
        seen = seen if seen is not None else set()
        for comment in comments[-50:]:
            if not isinstance(comment, dict):
                continue
            cid = re.sub(r"[^0-9A-Za-z-]", "", str(comment.get("id") or ""))[:40]
            if not cid or cid in seen:
                continue
            seen.add(cid)
            ts = ev.parse_ts(comment.get("createdAt"), now)
            self.hub.publish(ev.make("ticket", "goodqa", f"{ref}: {comment.get('body') or ''}", eid=f"goodqa:{cid}",
                                     ts=ts, subject={"ticket": ref}, historic=first))
        self.seen[ref] = seen
        return f"{ref} ({len(tickets)} tracked)"


class Remote(Collector):
    """At most one ssh to the remote host per minute: a fixed WAL probe, alternating with the Fabric export once
    Fabric ships `control export`."""
    name = "t2-dev"
    interval = 60.0

    def __init__(self, hub, health, runner, enabled=True, fabric=False, drop_dir=None):
        super().__init__(hub, health)
        self.runner, self.enabled, self.fabric, self.drop_dir = runner, enabled, fabric, drop_dir
        self.seen: dict[str, str] = {}
        self.turn = 0
        self.cursor = ""

    def tick(self, now: float):
        if not self.enabled:
            self.health.off(self.name, "remote probe disabled")
            return "off"
        self.turn += 1
        if self.fabric and self.turn % 2 == 0:
            return self.fabric_export()
        code, out = self.runner.run("remote-wal-probe", timeout=15, limit=65536)
        if code != 0:
            raise RuntimeError(f"ssh probe exited {code}")
        fresh = 0
        for line in out.splitlines()[:50]:
            path, _, tail = line.partition("\t")
            last = tail.split("\x1e")
            last = [x for x in last if x.strip()]
            if not last:
                continue
            newest = last[-1][:2000]
            if self.seen.get(path) == newest:
                continue
            first = path not in self.seen
            self.seen[path] = newest
            entry = _json(newest.encode("utf-8")) or {}
            parts = path.rstrip("/").split("/")
            session, agent = (parts[-2] if len(parts) > 1 else ""), re.sub(r"^agent-|\.jsonl$", "", parts[-1])
            note = _note(entry) or str(entry.get("event") or "")
            self.hub.publish(ev.make("wal", "t2-dev-wal", f"{entry.get('event', '')}: {note}",
                                     eid=f"t2wal:{session}:{agent}:{abs(hash(newest)) % 10**12}",
                                     actor={"runtime": "claude", "session": session, "agent": agent},
                                     historic=first))
            fresh += 1
        return f"{fresh} remote updates"

    def fabric_export(self):
        code, out = self.runner.run("fabric-export", self.cursor, timeout=15, limit=1024 * 1024)
        if code != 0:
            raise RuntimeError(f"fabric export exited {code}")
        lines = [line for line in out.splitlines() if line.strip()]
        if lines:
            tail = _json(lines[-1].encode("utf-8"))
            if tail and set(tail) == {"cursor"} and isinstance(tail["cursor"], str):
                self.cursor = tail["cursor"][:128]
                lines = lines[:-1]
        if lines and self.drop_dir:
            path = Path(self.drop_dir) / "fabric.jsonl"
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_NOFOLLOW", 0), 0o600)
            with os.fdopen(fd, "a", encoding="utf-8") as handle:
                for line in lines[:5000]:
                    if len(line) <= 8192:
                        handle.write(line + "\n")
        return f"fabric {len(lines)} lines"


class FileDrop(Collector):
    """External sources (Fabric first) append mc.event/1 lines to <drop_dir>/<name>.jsonl."""
    name = "sources"
    interval = 5.0
    MAX_LINE = 8192

    def __init__(self, hub, health, reader, drop_dir):
        super().__init__(hub, health)
        self.reader, self.drop_dir = reader, Path(drop_dir)
        self.files: dict[str, _Tail] = {}
        self.skipped = 0
        self.accepted = 0
        self.seen: set[str] = set()
        self.bad_files: set[str] = set()

    def tick(self, now: float):
        try:
            entries = list(os.scandir(self.drop_dir))
        except OSError:
            return "no drop directory"
        for entry in entries[:32]:
            name = entry.name
            if not name.endswith(".jsonl") or not re.match(r"^[a-z0-9][a-z0-9_-]{0,31}\.jsonl$", name):
                continue
            if entry.is_symlink():
                if entry.path not in self.bad_files:
                    self.bad_files.add(entry.path)
                    self.skipped += 1
                continue
            try:
                info = entry.stat(follow_symlinks=False)
            except OSError:
                continue
            if not stat.S_ISREG(info.st_mode):
                continue
            tail = self.files.get(entry.path)
            if tail is None or tail.ino != info.st_ino or info.st_size < tail.offset:
                tail = self.files[entry.path] = _Tail(info.st_ino, 0, "external", name[:-6], name[:-6])
            if info.st_size == tail.offset:
                continue
            try:
                with self.reader.open(entry.path) as handle:
                    handle.seek(tail.offset)
                    data = handle.read(512 * 1024)
            except (OSError, Refused):
                self.skipped += 1
                continue
            tail.offset += len(data)
            before = tail.dropped
            lines = split_lines(tail, data, self.MAX_LINE)
            self.skipped += tail.dropped - before
            for raw in lines:
                event = _json(raw)
                reason = ev.validate(event)
                if reason:
                    self.skipped += 1
                    continue
                normalized = ev.normalize_external(event, name[:-6])
                if normalized["id"] in self.seen:
                    continue
                self.seen.add(normalized["id"])
                self.accepted += 1
                self.hub.publish(normalized)
        if len(self.seen) > 20000:
            self.seen = set(list(self.seen)[-5000:])
        return f"{self.accepted} accepted, {self.skipped} skipped"
