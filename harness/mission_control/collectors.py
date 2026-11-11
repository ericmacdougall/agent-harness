"""Mission Control collectors (GoodQA #15585 AC-1..AC-4, AC-9, AC-13). Each collector has a fixed interval;
`tick()` does one bounded unit of work and never raises. All reads go through safeio.Reader/Runner."""

from __future__ import annotations

import json
import hashlib
import fcntl
import os
import re
import secrets
import stat
import time
from pathlib import Path

import events as ev
from safeio import CURSOR_RE, Refused, TICKET_RE

TOOL_EVENTS = ("pretool", "posttool", "PreToolUse", "PostToolUse")
LIFECYCLE_EVENTS = ("subagent", "subagent_stop", "SubagentStart", "SubagentStop", "prompt", "UserPromptSubmit", "session",
                    "SessionStart", "stop", "Stop", "compact", "PreCompact", "pending_stop")
DEPLOY_RE = re.compile(r"\bDEPLOYED\b|\bdeployed to (?:live|prod)|\blive deploy\b|\bdeploy(?:ed)? (?:live|to production)\b",
                       re.I)
TERMINAL = ("done", "handoff", "returned", "idle-helper", "unverified-legacy", "superseded", "wontdo", "legacy")


class Collector:
    name = "collector"
    interval = 60.0
    idle_interval = 0.0  # when greater than interval: the cadence while no page is attached (costly sources)

    def __init__(self, hub, health):
        self.hub, self.health = hub, health
        self.next_at = 0.0
        self.ran_at = None

    def due(self, now: float) -> bool:
        return now >= self.next_at

    def watched(self) -> bool:
        return bool(getattr(self.hub, "clients", True))

    def wake(self, now: float) -> None:
        """A page attached: a source that was on its idle cadence runs as soon as its normal interval allows."""
        if self.idle_interval > self.interval and self.ran_at is not None:
            self.next_at = min(self.next_at, self.ran_at + self.interval)

    def run(self, now: float) -> None:
        # set first: a failing source is never retried faster
        self.next_at = now + (self.interval if self.watched() else max(self.interval, self.idle_interval))
        self.ran_at = now
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
    __slots__ = ("ino", "offset", "partial", "runtime", "session", "agent", "size", "dropped", "skipping", "line_offsets", "source", "generation")

    def __init__(self, ino, offset, runtime, session, agent):
        self.ino, self.offset, self.partial = ino, offset, b""
        self.dropped, self.skipping = 0, False
        self.runtime, self.session, self.agent, self.size = runtime, session, agent, offset
        self.line_offsets, self.source, self.generation = [], "", 0


def split_lines(state: _Tail, data: bytes, max_line: int = 64 * 1024) -> list[bytes]:
    """Complete lines from state.partial + data; a partial tail is kept (bounded) until its newline."""
    position = state.offset - len(data) - len(state.partial)
    state.line_offsets = []
    buf = state.partial + data
    lines = buf.split(b"\n")
    state.partial = lines.pop()
    out = []
    for n, line in enumerate(lines):
        start = position
        position += len(line) + 1
        if state.skipping and n == 0:
            state.skipping = False  # the tail of an over-long line already counted as dropped
            continue
        if len(line) > max_line:
            state.dropped += 1
        elif line.strip():
            out.append(line)
            state.line_offsets.append(start)
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
        self.on_ask = None  # called when a WAL line registers or resolves an ask (the asks collector re-reads)
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
                    tail.source = hashlib.sha256(os.fsencode(item.path) + str(info.st_dev).encode()).hexdigest()[:16]
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
        found_item = found_progress = False
        for raw in reversed(lines):
            entry = _json(raw)
            if not entry:
                continue
            newest = newest or entry
            if not found_item and _meaningful(entry):
                self._remember(tail, entry)
                found_item = True
            if not found_progress and _progress(entry):
                self._remember_progress(tail, entry)
                found_progress = True
            if found_item and found_progress:
                break
        if newest:
            self._remember(tail, newest, meaningful=False)

    def _remember_progress(self, tail: _Tail, entry: dict) -> None:
        """The newest real progress (PROGRESS_EVENTS) for the slowest/at-risk ranking; never moves backwards."""
        key = (tail.runtime, tail.session, tail.agent)
        at = str(entry.get("at", ""))[:40]
        item = dict(self.last_items.get(key) or {"at": "", "event": "", "note": ""})
        if at > (item.get("progress_at") or ""):
            item.update({"progress_at": at, "progress_event": str(entry.get("event", ""))[:40],
                         "progress_note": ev.short(_note(entry), 160)})
            self.last_items[key] = item

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
                tail.generation += 1
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
        for index, raw in enumerate(lines):
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
            if _progress(entry):
                self._remember_progress(tail, entry)
            if sent >= budget:
                skipped += 1
                continue
            offset = tail.line_offsets[index] if index < len(tail.line_offsets) else tail.offset + index
            sent += self._emit(tail, entry, kind, offset)
        if tools:
            if sent < budget:
                tool = str((last_tool or {}).get("tool", "tool"))[:40]
                self.hub.publish(ev.make("wal", f"{tail.runtime}-wal",
                                         f"{tools} tool call{'s' if tools > 1 else ''} · last {tool}",
                                         eid=f"wal:{tail.runtime}:{tail.session}:{tail.agent}:{tail.source}:{tail.ino}:{tail.generation}:{tail.offset}:t", count=tools,
                                         actor=self._actor(tail), quiet=True))
                sent += 1
            else:
                skipped += tools
        return sent, skipped

    def _actor(self, tail: _Tail) -> dict:
        return {"runtime": tail.runtime, "session": tail.session, "agent": tail.agent}

    def _emit(self, tail: _Tail, entry: dict, kind: str, offset=None) -> int:
        if kind in ("ask", "ask_resolved") and self.on_ask:
            self.on_ask()
        note = _note(entry)
        actor = self._actor(tail)
        subject = {"ticket": _ticket_in(note)}
        meaningful = _meaningful(entry)
        summary = f"{kind}: {note}" if meaningful else _lifecycle_summary(entry, kind, note)
        location = f"{tail.runtime}:{tail.session}:{tail.agent}:{tail.source}:{tail.ino}:{tail.generation}:{tail.offset if offset is None else offset}"
        self.hub.publish(ev.make("wal", f"{tail.runtime}-wal", summary,
                                 eid="wal:" + hashlib.sha256(location.encode()).hexdigest(),
                                 actor=actor, subject=subject, quiet=not meaningful,
                                 severity="warn" if kind in ("blocker", "risk", "incident") else "info"))
        if DEPLOY_RE.search(note) or kind in ("deploy", "deployed"):
            self.hub.publish(ev.make("deploy", f"{tail.runtime}-wal", note or kind, actor=actor, subject=subject,
                                     eid="deploy:" + hashlib.sha256(location.encode()).hexdigest()))
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


PROGRESS_EVENTS = frozenset({"result", "check", "commit", "deploy", "live", "merge", "release", "handoff"})


def _progress(entry: dict) -> bool:
    """Real progress: an agent-written result, check, commit, deploy, merge, release or handoff (not a plan or note)."""
    return not entry.get("by") and str(entry.get("event", "")).lower() in PROGRESS_EVENTS


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
        return {"items": self.items, "stale": self.stale, "error": self.error,
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


class SupervisedOwners(Collector):
    """Named OpenAI supervisors, independent of ah and the WAL discovery path."""
    name = 'codex-owners'
    interval = 2.0

    def __init__(self, hub, health, reader, root, *, alive=None, on_change=None):
        super().__init__(hub, health)
        self.reader, self.root = reader, Path(root)
        self.alive = alive or self._alive
        self.on_change = on_change
        self.rows = []

    @staticmethod
    def _alive(pid):
        if not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0:
            return False
        try:
            os.kill(pid, 0)  # existence probe only, never signals an owner
            return True
        except PermissionError:
            return True
        except ProcessLookupError:
            return False

    def tick(self, now):
        try:
            rows = []
            known = {row['name'] for row in self.rows}
            for name, raw in self.reader.owner_statuses(self.root):
                if raw is None:
                    if name in known:
                        raise ValueError('known owner status is missing')
                    continue
                value = _json(raw)
                if not value or value.get('name') != name or value.get('harness') != 'openai':
                    raise ValueError('invalid owner status identity')
                state = value.get('state')
                if state not in ('running', 'idle', 'stopped'):
                    raise ValueError('invalid supervisor state')
                if state != 'stopped':
                    if not self.alive(value.get('supervisor_pid')):
                        state = 'offline'
                    elif state == 'running':
                        state = 'live'
                    else:
                        state = {'WAITING': 'waiting', 'BLOCKED': 'blocked', 'ERROR': 'error'}.get(
                            value.get('last_status'), 'idle')
                ticket = str(value.get('ticket') or '')
                activity = str(value.get('last_activity') or value.get('turn_ended') or value.get('started') or '')[:40]
                reply = ev.short(value.get('last_reply') or '', 2000)
                rows.append({'agent_id': 'openai:' + name, 'name': name, 'runtime': 'codex', 'harness': 'openai',
                             'model': ev.short(value.get('model'), 80), 'stream': ev.short(value.get('stream'), 160),
                             'type': 'owner', 'task': ev.short(value.get('stream') or name, 160),
                             'ticket': ticket if TICKET_RE.fullmatch(ticket) else '', 'state': state,
                             'last_activity': activity, 'last_reply': reply, 'last_status': ev.short(value.get('last_status'), 40),
                             'thread': ev.short(value.get('thread'), 64), 'source_stale': False,
                             'last_item': {'at': str(value.get('turn_ended') or '')[:40] if reply else '',
                                           'active_at': activity, 'event': 'reply' if reply else '',
                                           'note': ev.short(reply, 200) if reply else 'No reply recorded yet'}})
            self.rows = rows
        except Exception:
            self.rows = [{**row, 'source_stale': True} for row in self.rows]
            if self.on_change:
                self.on_change()
            raise
        if self.on_change:
            self.on_change()
        return f'{len(self.rows)} supervised owners'


class Owners(Collector):
    name = "owners"
    interval = 60.0
    idle_interval = 300.0  # `ah owners` costs about 6 CPU seconds a run: five times less often with no page open

    def __init__(self, hub, health, runner, tailer):
        super().__init__(hub, health)
        self.runner, self.tailer = runner, tailer
        self.rows: list[dict] = []
        self.states: dict[str, str] = {}
        self.session = ""
        self.claude_rows = []
        self.supervised = None
        self.native_projects = {}
        self.native_observation = {}

    def publish(self):
        managed = []
        for source in self.supervised.rows if self.supervised else []:
            row = dict(source)
            # Keep verified progress and meaningful work from the supervisor's real WAL thread.
            # A reply timestamp alone is not evidence of progress for the at-risk strip.
            items = [item for (runtime, session, _), item in list(self.tailer.last_items.items())
                     if runtime == 'codex' and session == row.get('thread')] if self.tailer else []
            if items:
                last = dict(max(items, key=lambda item: item.get('at') or ''))
                progress = max(items, key=lambda item: item.get('progress_at') or '')
                for key in ('progress_at', 'progress_event', 'progress_note'):
                    if progress.get(key):
                        last[key] = progress[key]
                last['active_at'] = max([row.get('last_activity') or ''] +
                                        [item.get('active_at') or item.get('at') or '' for item in items])
                row['last_item'] = last
            managed.append(row)
        threads = {r.get('thread') for r in managed if r.get('thread')}
        wals = [r for r in self.codex_rows(time.time()) if r['agent_id'] not in threads]
        combined = {}
        for row in self.claude_rows + wals + managed:
            row = dict(row)
            thread = row.get('thread')
            key = (row.get('runtime'), thread, row.get('agent', 'main')) if thread else (row.get('runtime'), row['agent_id'])
            previous = combined.get(key, {})
            merged = {**previous, **row}
            for field in ('name', 'model', 'stream', 'ticket'):
                merged[field] = row.get(field) or previous.get(field, '')
            combined[key] = merged
        aliases = {'codex-' + r.get('name', '') for r in managed}
        self.rows = [r for r in combined.values() if not (r.get('runtime') == 'codex' and
                     r.get('agent_id') in aliases and not r.get('thread'))]
        self.hub.snapshot('owners', self.rows)

    def tick(self, now: float):
        try:
            return self._tick(now)
        except Exception:
            self.claude_rows = [{**row, 'source_stale': True} for row in self.claude_rows]
            self.publish()
            raise

    def _tick(self, now: float):
        code, out = self.runner.run("ah-owners", timeout=30)
        if code != 0:
            raise RuntimeError(f"ah owners exited {code}")
        data = json.loads(out)
        if not isinstance(data, dict) or not isinstance(data.get('owners'), list):
            raise ValueError('invalid Claude owner snapshot')
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
            explicit = ('codex' if row.get('runtime') == 'codex' or row.get('harness') == 'openai' or agent.startswith('codex-')
                        else 'claude' if row.get('runtime') == 'claude' or row.get('harness') == 'claude' else None)
            worker = str(row.get('agent') or row.get('worker_id') or agent)
            matches = [(runtime, session, w) for runtime, session, w in self.tailer.last_items
                       if w == worker and (not explicit or runtime == explicit)
                       and (not (row.get('thread') or row.get('thread_id')) or session == (row.get('thread') or row.get('thread_id')))] if self.tailer else []
            runtime = explicit or (matches[0][0] if len(matches) == 1 else 'claude' if re.fullmatch(r'a[0-9a-f]{16}', agent) else 'unknown')
            thread = str(row.get('thread') or row.get('thread_id') or (matches[0][1] if len(matches) == 1 else ''))
            item = {"agent_id": agent, "runtime": runtime, "type": str(row.get("type") or "")[:40],
                    "harness": 'openai' if runtime == 'codex' else runtime, 'thread': thread, 'agent': worker,
                    "model": ev.short(row.get("model"), 80),
                    "stream": ev.short(row.get("stream") or row.get("task"), 160),
                    "last_reply": ev.short(row.get("last_reply"), 2000),
                    "task": ev.short(row.get("task") or "", 160), "ticket": ticket if TICKET_RE.match(ticket) else "",
                    "state": state[:24], "severity": str(row.get("severity") or "info")[:8],
                    "last_activity": str(row.get("last_activity") or "")[:40], "idle_s": idle,
                    "last_item": self.tailer.last_for(runtime, thread or self.session, worker) if self.tailer else None,
                    "disposition": _disposition(row.get("disposition"))}
            rows.append(item)
            previous = self.states.get(agent)
            if previous and previous != state:
                self.hub.publish(ev.make("owner", "ah-owners", f"{agent} {previous} → {state}",
                                         eid=f"owner:{agent}:{state}:{int(now)}",
                                         actor={"runtime": runtime, "session": thread or self.session, "agent": agent},
                                         subject={"ticket": item["ticket"]},
                                         severity="high" if state.startswith(("DROPPED", "SILENT")) else "info"))
            self.states[agent] = state
        rows.sort(key=lambda r: (r["state"] not in ("live", "working"), r["idle_s"] or 0))
        self.claude_rows = rows[:60]
        self.publish()
        return f"{len(rows)} owners"

    def codex_rows(self, now: float) -> list[dict]:
        rows = []
        if not self.tailer:
            return rows
        projects = dict(self.native_projects)
        registry_stale = False
        config = Path(os.environ.get('MC_HOME') or Path.home() / '.agent-harness/mission-control') / 'projects.json'
        try:
            fd = os.open(config, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(fd, 'rb') as handle:
                if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
                    raise ValueError('projects source is not regular')
                data = handle.read(65537)
            if len(data) > 65536:
                raise ValueError('projects source exceeds budget')
            value = json.loads(data)
            if not isinstance(value, dict) or not isinstance(value.get('projects'), list) or len(value['projects']) > 32:
                raise ValueError('invalid project registry')
            fresh = {}
            for item in value['projects']:
                if not isinstance(item, dict) or not re.fullmatch(r'[A-Za-z0-9-]{8,64}', str(item.get('thread_id', ''))):
                    raise ValueError('invalid project identity')
                fresh[item['thread_id']] = item
            self.native_projects = projects = fresh
            self.native_observation = {k: value.get(k) for k in ('schema', 'ttl_seconds', 'observed_at_utc')}
            self.health.ok('native-projects', f'{len(projects)} registered projects')
        except FileNotFoundError:
            registry_stale = bool(projects)
            self.health.off('native-projects', 'Project registry missing; cached names are stale' if projects else 'Project registry not configured')
        except (OSError, ValueError, TypeError, AttributeError):
            registry_stale = True
            self.health.error('native-projects', 'Native project registry unavailable; WAL streams remain visible')
        observed = set()
        metadata = self.native_observation
        observed_at = metadata.get('observed_at_utc')
        # Root's native format uses a UTC suffix; never reinterpret this as activity.
        stamp = ev.parse_ts(str(observed_at or '').replace(' UTC', 'Z').replace(' ', 'T'), 0)
        observation_age = now - stamp
        observation_valid = metadata.get('schema') == 'mc.native-project-observations/1' and type(metadata.get('ttl_seconds')) is int and metadata['ttl_seconds'] == 120 and stamp > 0
        def observation(project):
            valid = observation_valid and project.get('runtime') == 'codex' and project.get('observation_source') == 'codex_app.wait_threads'
            active = valid and isinstance(project.get('native_status'), dict) and project['native_status'].get('type') == 'active'
            return ('observed' if active and 0 <= observation_age <= 120 and not registry_stale else
                    'stale' if valid and observation_age > 120 else 'unknown')
        for (runtime, session, agent), item in list(self.tailer.last_items.items()):
            if runtime != "codex":
                continue
            project = projects.get(session, {})
            observed.add((session, agent))
            active = item.get('active_at') or item.get('at')
            age = now - ev.parse_ts(active, 0)
            stale = not active or age < 0 or age > 120 or bool(project and registry_stale)
            rows.append({"agent_id": f'codex:{session}:{agent}', 'thread': session, 'agent': agent,
                         'name': ev.short(project.get('project') or session[:8], 48) + ('' if agent == 'main' else ' · ' + agent[:8]),
                         "runtime": "codex", 'harness': 'openai', 'model': ev.short(project.get('model'), 80),
                         "type": 'project' if agent == 'main' and project else 'background',
                         "task": ev.short(project.get('title') or 'Observed native Codex WAL', 160), 'stream': ev.short(project.get('project'), 80),
                         "ticket": "", "state": 'stale' if stale else 'observed',
                         'source_stale': stale, "severity": "info", "last_activity": active,
                         "idle_s": max(0, age) if active else None, "last_item": item})
        for session, project in projects.items():
            if (session, 'main') not in observed:
                rows.insert(0, {'agent_id': f'codex:{session}:main', 'thread': session, 'agent': 'main',
                               'name': ev.short(project.get('project'), 64), 'runtime': 'codex', 'harness': 'openai',
                               'type': 'project', 'state': observation(project), 'source_stale': observation(project) != 'observed',
                               'observed_at': observed_at, 'native_status': project.get('native_status'),
                               'model': ev.short(project.get('model'), 80), 'provider': ev.short(project.get('provider'), 80),
                               'task': 'Registered project; no current WAL observation', 'last_item': {}})
        for row in rows:
            project = projects.get(row['thread'], {})
            if row.get('type') == 'project' and observation_valid:
                row['observed_at'] = observed_at
                row['native_status'] = project.get('native_status')
                if observation(project) == 'observed':
                    row['state'], row['source_stale'] = 'observed', False
        rows.sort(key=lambda r: r.get("last_activity") or "", reverse=True)
        rows.sort(key=lambda r: r.get('type') != 'project')
        if len(rows) > 200:
            self.health.error('native-streams', f'{len(rows)} streams observed; showing 200 with registered projects first')
        else:
            self.health.ok('native-streams', f'{len(rows)} streams observed')
        return rows[:200]

    def tickets(self) -> list[str]:
        return [r["ticket"] for r in self.rows if r.get("ticket") and r.get("state") in ("live", "working", "quiet")]


ASK_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,40}$")


class Asks(Collector):
    """Open asks for the user from main's session (provenance ledger), shown as the page's "Needs you" list.

    Read-only. Replies go through the existing chat channel as `[ask:<id>] text`; a decision goes through
    POST /api/approve, which re-reads the ledger with `read()` at the click. Main resolves the ask either way."""
    name = "asks"
    # The ledger read costs about 5 CPU seconds on a busy session, so it is not a poll: it runs when a WAL line
    # registers or resolves an ask (mark_dirty, debounced), at an Approve or Deny click, and at every sweep.
    interval = 300.0
    DEBOUNCE_S = 5.0

    def __init__(self, hub, health, runner, session_fn, root=None, owners_fn=None):
        super().__init__(hub, health)
        self.runner, self.session_fn = runner, session_fn
        self.root, self.owners_fn = root, owners_fn  # with a root, every ledger read is also a sweep (needs_sweep)
        self.items: list[dict] = []
        self.resolved: list[dict] = []
        self.stale: list[dict] = []
        self.flagged: list[dict] = []
        self.cleared: list[dict] = []
        self.swept_at = ""
        self.session = ""
        self.dirty = False      # set when a WAL ask or ask_resolved line was seen: read the ledger at the next tick
        self.read_at = 0.0

    def tick(self, now: float):
        session = self.session_fn() or ""
        if not session:
            self.next_at = now + 10  # the owners collector learns main's session shortly after start
            self.health.off(self.name, "no main session known yet")
            return "off"
        self.publish(self.read(session, now), session)
        return f"{len(self.items)} open, {len(self.stale)} stale, {len(self.flagged)} flagged"

    def read(self, session: str, now: float | None = None) -> dict:
        """One fresh ledger read and sweep. Raises when the ledger cannot be read; never returns a partial list
        as whole. The view: active items, stale items, flagged (untraceable) items, cleared-recently rows."""
        now = time.time() if now is None else now
        code, out = self.runner.run("provenance-asks", session, timeout=60, limit=1024 * 1024)
        data = _json(out.encode("utf-8", "replace")) if out else None
        if code not in (0, 2) or not isinstance(data, dict) or not isinstance(data.get("items"), list):
            raise RuntimeError(f"provenance asks exited {code}")
        self.dirty, self.read_at = False, now
        raw = [r for r in data["items"][:100] if isinstance(r, dict) and ASK_ID_RE.match(str(r.get("id", "")))]
        blocked = [r for r in (data.get("blocked") if isinstance(data.get("blocked"), list) else [])[:100]
                   if isinstance(r, dict) and ASK_ID_RE.match(str(r.get("id", "")))]
        resolved = []
        for row in (data.get("resolved") if isinstance(data.get("resolved"), list) else [])[:100]:
            if not isinstance(row, dict) or not ASK_ID_RE.match(str(row.get("id", ""))):
                continue
            note = ev.short(str(row.get("note", "")), 400)
            resolved.append({"id": str(row["id"]), "at": str(row.get("at", ""))[:40], "text": note,
                             "ticket": _ticket_in(note), "owner": ev.short(str(row.get("owner", "")), 60),
                             "resolved_at": str(row.get("resolved_at", ""))[:40],
                             "resolution": ev.short(str(row.get("resolution", "")), 300),
                             "decision": ev.short(str(row.get("decision", "")), 40)})
        view = {"items": [], "stale": [], "flagged": [], "cleared": [], "resolved": resolved, "swept_at": ""}
        status = {}
        if self.root is not None:
            import needs_sweep  # noqa: PLC0415
            swept = needs_sweep.sweep(self.root, session, {"items": raw, "blocked": blocked, "resolved": data.get("resolved") or []},
                                      owners=self.owners_fn() if self.owners_fn else (), ticket_status=self.ticket_status,
                                      activity=self.activity(), now=now)
            status, view["cleared"], view["swept_at"] = swept["status"], swept["cleared"], ev.iso(swept["swept_at"])
        for row in raw:
            verdict = status.get(str(row["id"]), {"state": "active"})
            if verdict["state"] == "cleared":
                continue  # settled: listed under cleared-recently with its reason, never as an open ask
            item = self.item(session, row)
            if verdict["state"] == "stale":
                view["stale"].append(dict(item, stale=verdict["reason"]))
            else:
                view["items"].append(item)
        for row in blocked:
            verdict = status.get(str(row["id"]))
            item = self.item(session, row)
            why = verdict["reason"] if verdict else "no traceable source: " + ev.short(str(row.get("problem", "")), 160)
            view["flagged"].append(dict(item, digest="", approvable=False, flagged=why,
                                        blocked="This ask does not trace to a real source, so it is not shown as a valid ask. Main has to restate it with its source."))
        return view

    def mark_dirty(self) -> None:
        self.dirty = True

    def due(self, now: float) -> bool:
        return now >= self.next_at or (self.dirty and now - self.read_at >= self.DEBOUNCE_S)

    def ticket_status(self, ref: str):
        """'closed', 'open' or None (unknown) for one ticket: a read-only lookup through the allowlisted runner."""
        code, out = self.runner.run("ah-ticket-get", ref, timeout=15, limit=256 * 1024)
        issue = (_json(out.encode("utf-8", "replace")) or {}).get("issue") if code == 0 and out else None
        if not isinstance(issue, dict):
            return None
        return "closed" if issue.get("closedAt") or issue.get("archivedAt") else "open"

    def activity(self) -> dict:
        """ask id -> epoch of the user's newest reply or decision on it (from the dashboard inbox)."""
        import mc_chat  # noqa: PLC0415
        out: dict[str, float] = {}
        for record in mc_chat.inbox(self.root, limit=200):
            if not record.get("verified"):
                continue
            approval = record.get("approval") if isinstance(record.get("approval"), dict) else {}
            tagged = re.match(r"\[ask:([A-Za-z0-9_-]{1,40})\]", str(record.get("text", "")))
            ident = approval.get("ask_id") or (tagged.group(1) if tagged else None)
            stamp = ev.parse_ts(record.get("created"))
            if ident and stamp:
                out[ident] = max(out.get(ident, 0), stamp)
        return out

    @staticmethod
    def item(session: str, raw: dict) -> dict:
        """One open ask as the page shows it. `text` and `why` are the whole ask (redacted, never clipped) and
        `digest` covers exactly them, so what the user reads is what a decision signs. An ask that cannot be shown
        whole, that an owner registered, or that needs the terminal carries `blocked` and is not approvable."""
        import mc_chat  # noqa: PLC0415 - the chat store lives with the hooks; the server puts it on sys.path
        ask_id, owner = str(raw["id"]), ev.short(str(raw.get("owner", "")), 60)
        note, reason = str(raw.get("note", "")), str(raw.get("reason", ""))
        text, why, digest, blocked = ev.short(note, mc_chat.MAX_TEXT), ev.short(reason, mc_chat.REASON_MAX), "", ""
        if owner != "main":
            blocked = "Registered by an owner, not by main. Answer with a reply; main decides what to do with it."
        else:
            try:
                shown = mc_chat.ask_snapshot(session, "main", ask_id, note, reason)
                text, why, digest = shown["text"], shown["reason"], shown["digest"]
                blocked = mc_chat.terminal_only(text, why) or ""
                if blocked:
                    blocked += ". Answer it there."
            except mc_chat.ChatError:
                blocked = "This ask cannot be shown in full, so it cannot be decided here. Answer with a reply."
        return {"id": ask_id, "kind": str(raw.get("kind", ""))[:12], "at": str(raw.get("at", ""))[:40],
                "text": text, "why": why, "owner": owner, "ticket": _ticket_in(text), "session": session,
                "digest": digest if not blocked else "", "approvable": not blocked, "blocked": blocked}

    def publish(self, view: dict, session: str) -> None:
        self.items, self.resolved, self.session = view["items"], view["resolved"], session
        self.stale, self.flagged, self.cleared, self.swept_at = view["stale"], view["flagged"], view["cleared"], view["swept_at"]
        self.hub.snapshot("asks", self.snapshot())

    def snapshot(self) -> dict:
        return {"items": self.items, "resolved": self.resolved, "session": self.session, "stale": self.stale,
                "flagged": self.flagged, "cleared": self.cleared, "swept_at": self.swept_at}


class GitHub(Collector):
    """Pushes and releases from the authenticated user's GitHub events feed: one request per minute."""
    name = "github"
    interval = 60.0
    idle_interval = 300.0

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
    idle_interval = 120.0
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


FABRIC_CHECKPOINT = ".fabric-commit.json"


def _fabric_offset(path: Path, info, data_fd: int) -> int | None:
    """The accepted prefix of the MC-managed drop file. An absent checkpoint is a legacy file.

    A malformed checkpoint is never permission to read an unaccepted tail.
    """
    try:
        fd = os.open(path.parent / FABRIC_CHECKPOINT, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return None
    try:
        checkpoint_info = os.fstat(fd)
        if not stat.S_ISREG(checkpoint_info.st_mode) or checkpoint_info.st_nlink != 1:
            raise Refused("unsafe Fabric checkpoint")
        data = os.read(fd, 1025)
    finally:
        os.close(fd)
    try:
        checkpoint = json.loads(data) if len(data) <= 1024 else None
    except (ValueError, UnicodeDecodeError):
        checkpoint = None
    if (not isinstance(checkpoint, dict) or set(checkpoint) != {"schema", "dev", "ino", "offset"}
            or checkpoint.get("schema") != "mc.fabric.commit/1"
            or checkpoint.get("dev") != info.st_dev or checkpoint.get("ino") != info.st_ino
            or type(checkpoint.get("offset")) is not int
            or not 0 <= checkpoint["offset"] <= info.st_size):
        raise Refused("invalid Fabric committed-prefix checkpoint")
    if checkpoint["offset"] and os.pread(data_fd, 1, checkpoint["offset"] - 1) != b"\n":
        raise Refused("Fabric committed prefix is not a complete line")
    return checkpoint["offset"]


def _write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        size = os.write(fd, view)
        if size <= 0:
            raise OSError("short Fabric write")
        view = view[size:]


def _fabric_checkpoint(path: Path, info, offset: int) -> None:
    checkpoint = path.parent / FABRIC_CHECKPOINT
    temporary = checkpoint.with_name(checkpoint.name + "." + secrets.token_hex(8) + ".tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        value = {"schema": "mc.fabric.commit/1", "dev": info.st_dev, "ino": info.st_ino, "offset": offset}
        _write_all(fd, (json.dumps(value) + "\n").encode())
        os.fsync(fd)
        os.close(fd)
        fd = -1
        os.replace(temporary, checkpoint)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if fd != -1:
            os.close(fd)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _fabric_append(path: Path, payload: bytes) -> None:
    """Publish only a complete durable batch. A failed tail stays invisible and is replaced on retry.

    Readers take a shared lock and obey the committed prefix even after this process exits unexpectedly.
    Only unaccepted bytes beyond that prefix can be truncated; accepted events are never rewritten.
    """
    fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        from fabric_state import maintenance_guard
        maintenance_guard(path.parent)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise Refused("Fabric drop must be a private regular file")
        offset = _fabric_offset(path, info, fd)
        if offset is None:
            offset = info.st_size
            if offset and os.pread(fd, 1, offset - 1) != b"\n":
                raise Refused("legacy Fabric drop ends in an incomplete line")
            # Publish the old accepted prefix before any new data can reach the file.
            os.fsync(fd)
            _fabric_checkpoint(path, info, offset)
        elif info.st_size > offset:
            os.ftruncate(fd, offset)  # only the previous attempt's unaccepted tail
        os.lseek(fd, offset, os.SEEK_SET)
        _write_all(fd, payload)
        os.fsync(fd)
        _fabric_checkpoint(path, info, offset + len(payload))
    finally:
        os.close(fd)


class Remote(Collector):
    """At most one ssh to the remote host per minute: a fixed WAL probe, alternating with the Fabric export once
    Fabric ships `control export`."""
    name = "t2-dev"
    interval = 60.0
    idle_interval = 300.0

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
        if not isinstance(out, str) or len(out.encode("utf-8")) > 1024 * 1024:
            raise ValueError("Fabric response exceeds its byte budget")
        lines = [line for line in out.split("\n") if line.strip()]
        if not lines or len(lines) > 5001:
            raise ValueError("Fabric response is incomplete or exceeds its line budget")
        tail = _json(lines[-1].encode("utf-8"))
        if (not isinstance(tail, dict) or set(tail) != {"cursor"}
                or not isinstance(tail["cursor"], str) or not CURSOR_RE.fullmatch(tail["cursor"])):
            raise ValueError("Fabric response has no valid cursor footer")
        lines = lines[:-1]
        for line in lines:
            if len(line.encode("utf-8")) > 8192 or ev.validate(_json(line.encode("utf-8"))):
                raise ValueError("Fabric response contains an invalid event line")
        if lines:
            if not self.drop_dir:
                raise ValueError("Fabric event sink is not configured")
            _fabric_append(Path(self.drop_dir) / "fabric.jsonl", ("\n".join(lines) + "\n").encode("utf-8"))
        self.cursor = tail["cursor"]  # acknowledgment only after the whole batch is accepted
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
            try:
                with self.reader.open(entry.path) as handle:
                    try:
                        fcntl.flock(handle.fileno(), fcntl.LOCK_SH | fcntl.LOCK_NB)
                    except BlockingIOError:
                        continue  # an active publisher owns the file; observation never waits on it
                    info = os.fstat(handle.fileno())
                    if name == "fabric.jsonl":
                        from fabric_state import maintenance_guard
                        maintenance_guard(self.drop_dir)
                    accepted = _fabric_offset(Path(entry.path), info, handle.fileno()) if name == "fabric.jsonl" else None
                    end = info.st_size if accepted is None else accepted
                    tail = self.files.get(entry.path)
                    if tail is None or tail.ino != info.st_ino or end < tail.offset:
                        tail = self.files[entry.path] = _Tail(info.st_ino, 0, "external", name[:-6], name[:-6])
                    if end == tail.offset:
                        continue
                    handle.seek(tail.offset)
                    data = handle.read(min(512 * 1024, end - tail.offset))
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
