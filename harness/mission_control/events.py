"""mc.event/1: the published Mission Control event shape, its validator, and the in-memory hub that fans
events out to SSE clients (GoodQA #15585 AC-2, AC-9, AC-13). Schema doc: docs/mission-control-events.md."""

from __future__ import annotations

import calendar
import collections
import json
import re
import socket
import threading
import time

SCHEMA = "mc.event/1"
KINDS = ("wal", "push", "release", "deploy", "ticket", "chat", "owner", "initiative", "system")
SEVERITIES = ("info", "warn", "high")
SUMMARY_MAX = 280
ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/#-]{0,199}$")
TS_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z$")
WORD_RE = re.compile(r"^[A-Za-z0-9._:@/#+-]{0,160}$")
HOST = socket.gethostname().split(".")[0][:64]


def _redact(text: str) -> str:
    import redact
    return redact.redact(text)


def iso(ts: float | None = None) -> str:
    ts = time.time() if ts is None else ts
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(ts)) + ".%03dZ" % int((ts % 1) * 1000)


def parse_ts(value, default: float | None = None) -> float:
    """Seconds since the epoch for an ISO-8601 UTC string (Z or +00:00), else default (now)."""
    try:
        return float(calendar.timegm(time.strptime(str(value)[:19], "%Y-%m-%dT%H:%M:%S")))
    except (ValueError, TypeError):
        return time.time() if default is None else default


def short(text, limit: int = SUMMARY_MAX) -> str:
    text = " ".join(str(text or "").split())
    text = _redact(text)
    return text if len(text) <= limit else text[:limit - 1] + "…"


def _word(value) -> str:
    value = str(value or "")[:160]
    return value if WORD_RE.match(value) else re.sub(r"[^A-Za-z0-9._:@/#+-]", "_", value)


def make(kind: str, source: str, summary, *, eid: str, ts: float | None = None, actor: dict | None = None,
         subject: dict | None = None, severity: str = "info", count: int = 1, historic: bool = False,
         quiet: bool = False) -> dict:
    actor = actor or {}
    subject = subject or {}
    event = {
        "schema": SCHEMA, "id": _word(eid)[:200], "ts": iso(ts), "kind": kind, "source": _word(source)[:40],
        "host": HOST,
        "actor": {k: _word(actor.get(k)) for k in ("runtime", "session", "agent") if actor.get(k)},
        "subject": {k: _word(subject.get(k)) for k in ("repo", "branch", "ref", "ticket", "initiative")
                    if subject.get(k)},
        "summary": short(summary), "severity": severity if severity in SEVERITIES else "info",
        "count": max(1, int(count)),
    }
    if historic:
        event["historic"] = True
    if quiet:
        event["quiet"] = True  # activity (tool calls, lifecycle): pulses and ages, not a feed row by default
    return event


def validate(event) -> str | None:
    """None when the event is a valid mc.event/1 object, else the reason. Used for external file-drop lines."""
    if not isinstance(event, dict):
        return "not an object"
    if event.get("schema") != SCHEMA:
        return "unknown schema"
    if event.get("kind") not in KINDS:
        return "unknown kind"
    if not isinstance(event.get("id"), str) or not ID_RE.match(event["id"]):
        return "bad id"
    if not isinstance(event.get("ts"), str) or not TS_RE.match(event["ts"]):
        return "bad ts"
    if not isinstance(event.get("summary", ""), str) or len(event.get("summary", "")) > SUMMARY_MAX:
        return "bad summary"
    for field in ("actor", "subject"):
        value = event.get(field, {})
        if not isinstance(value, dict) or any(not isinstance(v, str) or len(v) > 160 for v in value.values()):
            return f"bad {field}"
    if event.get("severity", "info") not in SEVERITIES:
        return "bad severity"
    count = event.get("count", 1)
    if not isinstance(count, int) or isinstance(count, bool) or not 1 <= count <= 10**9:
        return "bad count"
    return None


def normalize_external(event: dict, source: str) -> dict:
    """Re-build a validated external event through make(): re-redacted, fields re-sanitized, source pinned."""
    return make(event["kind"], source, event.get("summary", ""), eid=event["id"], ts=parse_ts(event["ts"]),
                actor=event.get("actor"), subject=event.get("subject"), severity=event.get("severity", "info"),
                count=event.get("count", 1))


class Client:
    def __init__(self, maxlen: int = 256):
        self.queue = collections.deque()
        self.maxlen = maxlen
        self.cond = threading.Condition()
        self.dropped = False

    def push(self, frame: bytes) -> None:
        with self.cond:
            if len(self.queue) >= self.maxlen:
                self.dropped = True  # a slow client is cut off rather than buffered without bound
            else:
                self.queue.append(frame)
            self.cond.notify()

    def take(self, timeout: float):
        with self.cond:
            if not self.queue and not self.dropped:
                self.cond.wait(timeout)
            if self.dropped:
                return None
            items = list(self.queue)
            self.queue.clear()
            return items


class Hub:
    """Ring of recent events plus SSE fan-out. publish() never blocks on a client."""

    def __init__(self, ring: int = 500, max_clients: int = 8, max_rate: float = 20.0):
        self.lock = threading.Lock()
        self.ring = collections.deque(maxlen=ring)
        self.seq = 0
        self.clients: list[Client] = []
        self.max_clients = max_clients
        self.max_rate = max_rate
        self.window = [time.monotonic(), 0]
        self.suppressed = self.suppressed_quiet = 0
        self.snapshots: dict[str, object] = {}

    def frame(self, seq: int, name: str, data) -> bytes:
        body = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
        return f"id: {seq}\nevent: {name}\ndata: {body}\n\n".encode("utf-8")

    def _broadcast(self, frame: bytes) -> None:
        for client in list(self.clients):
            client.push(frame)

    def publish(self, event: dict) -> bool:
        """Add an event; over the rate budget it is counted into a burst summary instead of sent."""
        with self.lock:
            now = time.monotonic()
            if now - self.window[0] >= 1.0:
                if self.suppressed:
                    loud = self.suppressed - self.suppressed_quiet
                    self._emit_locked(make("system", "mission-control", f"{self.suppressed} more events in a burst",
                                           eid=f"burst:{int(now * 1000)}", count=self.suppressed, severity="info",
                                           quiet=loud == 0))
                    self.suppressed = self.suppressed_quiet = 0
                self.window = [now, 0]
            # Quiet activity (tool calls, lifecycle) gets half the budget so it never crowds out work items.
            limit = self.max_rate // 2 if event.get("quiet") else self.max_rate
            if self.window[1] >= limit:
                weight = max(1, int(event.get("count", 1)))
                self.suppressed += weight
                if event.get("quiet"):
                    self.suppressed_quiet += weight
                return False
            self.window[1] += 1
            self._emit_locked(event)
            return True

    def _emit_locked(self, event: dict) -> None:
        self.seq += 1
        self.ring.append((self.seq, event))
        self._broadcast(self.frame(self.seq, "event", event))

    def snapshot(self, name: str, data) -> None:
        """Replace a named snapshot (initiatives, owners, health, chat, targets) and push it to clients."""
        with self.lock:
            self.snapshots[name] = data
            self.seq += 1
            self._broadcast(self.frame(self.seq, name, data))

    def recent(self, after: int = 0, limit: int = 500) -> list[dict]:
        with self.lock:
            return [e for s, e in self.ring if s > after][-limit:]

    def attach(self) -> Client | None:
        with self.lock:
            if len(self.clients) >= self.max_clients:
                return None
            client = Client()
            self.clients.append(client)
            return client

    def detach(self, client: Client) -> None:
        with self.lock:
            if client in self.clients:
                self.clients.remove(client)
