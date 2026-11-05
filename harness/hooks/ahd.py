#!/usr/bin/env python3
"""ahd: the harness daemon (GoodQA 1ae27b6b#14601; design: ahd-design/DESIGN.md sections 2, 5, 7, 10).

A monitor and scheduler. One instance per host (flock on ~/.agent-harness/run/ahd.lock, an empty file that holds no
state; a second instance exits 0). Every 60 s it reads state and asks the `ah` CLI, the single writer, to record
what it found. ahd has no private write path, no socket and no state file: its only own file is its log
(~/.agent-harness/logs/ahd.log, 5 x 8 MiB). Because every write is an `ah` call with a deterministic idempotency key
derived from what ahd observed, a restart or a kill mid-tick re-issues the same keys and `ah` applies them once.

Tick (bounded to tick_budget_seconds of wall time; each step gets the remaining budget as its timeout):
  1. heartbeat     ah heartbeat beat --service ahd
  2. checks        ops_watch.checks.run_all(cfg), only once ops-watch exposes it (until then its own timer runs)
  3. owners        ah owners --session S for every session with recent WAL activity (liveness.py lives in ah)
  4. asks          read-only: the v1 ledger and WAL ask entries (the #14465 ledger once installed)
  5. alerts        diff the desired ahd alerts against the active ahd entries in the ring (read-only);
                   ah alert raise|clear for each transition; liveness raises are held 2 ticks after a clock jump
  6. spool         ah spool drain
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import logging
import logging.handlers
import os
import re
import resource
import selectors
import signal
import socket
import stat
import subprocess
import sys
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import ahd_peek as peek  # noqa: E402
import liveness  # noqa: E402

SOURCE = "ahd"
OPEN_STATES = ("open", "assigned", "in_progress", "blocked")
UNOWNED = ("", "unassigned", "none", None)
LIVENESS_SEVERITY = {"SILENT": "warning", "SILENT-HIGH": "high", "DROPPED": "high"}
SEV = {"info": 0, "warning": 1, "high": 2, "critical": 3}
SESSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{7,63}$")
RING_SLOT = 1024   # bytes per slot
RING_SLOTS = 1024  # slots in the ring

log = logging.getLogger("ahd")
logging.raiseExceptions = False  # a log write that fails (full disk) must never take the loop down


def now() -> float:  # tests patch both clocks
    return time.time()


def mono() -> float:
    return time.monotonic()


def iso(ts) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(float(ts)))


def parse_ts(text):
    if not isinstance(text, str) or len(text) < 19:
        return None
    try:
        import datetime as _dt
        d = _dt.datetime.fromisoformat(text.strip().replace("Z", "+00:00"))
        if d.tzinfo is None:
            d = d.replace(tzinfo=_dt.timezone.utc)
        return d.timestamp()
    except ValueError:
        return None


def home() -> Path:
    return peek.home()


def host() -> str:
    return socket.gethostname().split(".")[0]


def load_policy(path=None) -> dict:
    pol = peek.load_policy(path)
    user = home() / ".agent-harness" / "ahd.json"  # per-host overrides; "exclude" may only grow
    try:
        if user.is_file():
            extra = json.loads(peek.safe_read(user, 1 << 20).decode("utf-8"))
            if isinstance(extra, dict):
                for k, v in extra.items():
                    if k != "exclude":
                        pol[k] = v
                ex = extra.get("exclude")
                if isinstance(ex, dict) and isinstance(pol.get("exclude"), dict):
                    for k in ("token_prefixes", "path_substrings", "hosts"):
                        pol["exclude"][k] = list(pol["exclude"].get(k) or ()) + [
                            x for x in ex.get(k) or () if isinstance(x, str)]
    except (OSError, ValueError):
        pol["override_error"] = True
    return pol


MESSAGE_MAX = 400  # characters of an alert message handed to `ah alert raise`
OUTPUT_CAP = 32 << 20  # bytes accepted from one child; a child past it is killed, never buffered


def kill_group(p) -> None:
    try:
        os.killpg(p.pid, signal.SIGKILL)
    except OSError:
        pass


def run_cmd(argv, timeout, stdin=None, env=None, cap=None):
    """(rc, stdout, stderr), stdin closed unless given; never raises for a child problem. The child gets its own
    process group, so a timeout or an output flood ends everything it started. Output is bounded in memory."""
    data = stdin.encode() if isinstance(stdin, str) else stdin
    cap = OUTPUT_CAP if cap is None else cap
    try:
        p = subprocess.Popen(argv, stdin=subprocess.PIPE if data else subprocess.DEVNULL,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, start_new_session=True)
    except OSError as exc:
        return 127, "", type(exc).__name__
    if data:
        try:  # batches are small (at most a few hundred short lines); a dead child just closes the pipe
            p.stdin.write(data)
        except OSError:
            pass
        try:
            p.stdin.close()
        except OSError:
            pass
    bufs = {p.stdout: bytearray(), p.stderr: bytearray()}
    end = time.monotonic() + max(1.0, timeout)
    sel = selectors.DefaultSelector()
    for f in bufs:
        sel.register(f, selectors.EVENT_READ)
    verdict = None
    while sel.get_map() and verdict is None:
        left = end - time.monotonic()
        if left <= 0:
            verdict = (124, "timeout")
            break
        for key, _ in sel.select(min(left, 1.0)):
            chunk = os.read(key.fd, 1 << 16)
            if not chunk:
                sel.unregister(key.fileobj)
                continue
            bufs[key.fileobj] += chunk
            if len(bufs[key.fileobj]) > cap:
                verdict = (125, "output over cap")
    sel.close()
    if verdict is None:
        try:
            rc = p.wait(timeout=max(0.1, end - time.monotonic()))
        except subprocess.TimeoutExpired:
            verdict = (124, "timeout")
    if verdict is not None:
        kill_group(p)
        p.wait()
    for f in bufs:
        f.close()
    if verdict is not None:
        return verdict[0], "", verdict[1]
    return rc, bufs[p.stdout].decode("utf-8", "replace"), bufs[p.stderr].decode("utf-8", "replace")


def peak_rss_bytes() -> int:
    v = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return int(v if sys.platform == "darwin" else v * 1024)  # bytes on macOS, KiB on Linux


def memory_guard(cap: int, stop, period: float = 2.0, die=os._exit, peak=peak_rss_bytes) -> None:
    """Last line of defence on hosts with no cgroup limit (launchd): past the cap the daemon exits nonzero and the
    service manager restarts it, whatever allocated. The peak never falls, so this cannot flap within one process."""
    while not stop.wait(period):
        if peak() > cap:
            try:
                log.error("memory cap exceeded: peak %s > %s; exiting", peak(), cap)
            except Exception:
                pass
            die(70)
            return


# ---------------------------------------------------------------- read-only inputs

def read_ring(path=None) -> list:
    """Every event in the ops-watch alert ring (fixed 1 KiB slots). Read-only; bad slots are skipped."""
    p = Path(path) if path else home() / ".agent-harness" / "state" / "alerts.jsonl"
    try:
        data = peek.safe_read(p, RING_SLOT * RING_SLOTS, offset=0)
    except OSError:
        return []
    out = []
    for raw in data.split(b"\n"):
        raw = raw.strip()
        if not raw:
            continue
        try:
            ev = json.loads(raw)
        except ValueError:
            continue
        if isinstance(ev, dict) and not ev.get("empty") and isinstance(ev.get("seq"), int):
            out.append(ev)
    out.sort(key=lambda e: e["seq"])
    return out


def ring_state(events: list, src: str, hostname: str) -> dict:
    """key -> latest event for this host and source (active when its event is 'raise')."""
    latest = {}
    for ev in events:
        if ev.get("source") == src and ev.get("host") == hostname and isinstance(ev.get("key"), str):
            latest[ev["key"]] = ev
    return latest


def wal_problem(path: str, limit: int):
    """Why `ah owners` must not be given this WAL: not a regular file (a symlink could be /dev/zero), or too big."""
    st = os.lstat(path)
    if not stat.S_ISREG(st.st_mode):
        return "not a regular file"
    return f"{st.st_size} bytes" if st.st_size > limit else None


def scan_sessions(policy: dict, ts: float) -> tuple:
    """(usable sessions, {session: "<wal name>: <problem>"}). `ah owners` reads a session's main and task WALs, so a
    session with an unsafe one is left out. Its liveness alerts are held and a wal:unsafe alert says why."""
    base = home() / ".claude" / "wals"
    look = policy.get("owner_window_seconds", 172800)
    limit = policy.get("owners_wal_max_bytes", 256 << 20)
    usable, blocked = [], {}
    try:
        entries = list(os.scandir(base))
    except FileNotFoundError:
        return [], {}  # no WALs at all on this host; any other error propagates so the step counts as failed
    for d in entries:
        if not SESSION_RE.match(d.name) or not d.is_dir(follow_symlinks=False):
            continue
        main = os.path.join(d.path, "main.jsonl")
        try:
            st = os.lstat(main)
        except OSError:
            continue
        if ts - st.st_mtime > look:
            continue
        problem = None
        try:
            names = ["main.jsonl"] + sorted(n for n in os.listdir(d.path) if n.startswith("agent-") and n.endswith(".jsonl"))
            for name in names:
                why = wal_problem(os.path.join(d.path, name), limit)
                if why:
                    problem = f"{name}: {why}"
                    break
        except OSError:
            problem = "unreadable"
        if problem:
            blocked[d.name] = problem
        else:
            usable.append(d.name)
    return sorted(usable), blocked


def active_sessions(policy: dict, ts: float) -> list:
    return scan_sessions(policy, ts)[0]


def wal_unsafe_alerts(blocked: dict, ts: float) -> dict:
    return {f"wal:unsafe:{sess[:8]}": {
        "severity": "high", "class": "self", "kind": "wal", "subject": sess[:8], "since": int(ts // 86400 * 86400),
        "message": f"session {sess[:8]} not monitored for liveness: {why}"[:200], "detail": {}}
        for sess, why in blocked.items()}


def v1_asks(policy: dict) -> list:
    p = home() / ".agent-harness" / "work-assignments.json"
    try:
        data = json.loads(peek.safe_read(p, policy.get("ledger_max_bytes", 64 << 20)))
    except FileNotFoundError:
        return []
    except (OSError, ValueError) as exc:
        return [{"error": f"v1 ledger unreadable: {type(exc).__name__}"}]
    items = data.get("items") if isinstance(data, dict) else None
    vals = list(items.values()) if isinstance(items, dict) else items if isinstance(items, list) else []
    out = []
    for it in vals:
        if not isinstance(it, dict) or not isinstance(it.get("id"), str):
            continue
        ev = it.get("evidence") if isinstance(it.get("evidence"), list) else []
        imported = it.get("imported") if isinstance(it.get("imported"), dict) else {}
        desc = it.get("description")
        created = parse_ts(imported.get("when")) or parse_ts(it.get("created"))  # an import's "created" is the import time
        out.append({"id": it["id"], "ledger": "v1", "state": it.get("state"),
                    "owner": it.get("owner") if isinstance(it.get("owner"), str) else "",
                    "text": "[excluded]" if peek.text_excluded(desc, policy) else peek.scrub(desc, 120),
                    "created": created, "since": max(filter(None, (parse_ts(it.get("state_since")), created)), default=None),
                    "checked": parse_ts(it.get("last_checked")),
                    "evidence": [e.get("kind") for e in ev if isinstance(e, dict)]})
    return out


def wal_asks(policy: dict, sessions: list) -> list:
    """`ask` entries in main WALs that no `ask_resolved` names: things agents are waiting on the user for."""
    out = []
    cap = policy.get("wal_asks_max_bytes", 8 << 20)
    for s in sessions:
        p = home() / ".claude" / "wals" / s / "main.jsonl"
        try:
            lines, stats = peek.read_tail_lines(str(p), cap, 1 << 20)
        except OSError:
            continue
        asks, resolved = {}, set()
        for ev in peek.parse_lines(lines, stats):
            if ev.get("event") == "ask" and isinstance(ev.get("id"), str):
                note = ev.get("note")
                asks[ev["id"]] = {"id": ev["id"], "session": s[:8], "at": parse_ts(ev.get("at")),
                                  "text": "[excluded]" if peek.text_excluded(note, policy) else peek.scrub(note, 140)}
            elif ev.get("event") == "ask_resolved" and isinstance(ev.get("ref"), str):
                resolved.add(ev["ref"])
        out.extend(a for k, a in asks.items() if k not in resolved)
    return out


# ---------------------------------------------------------------- reconcile (pure)

def liveness_alerts(owner_docs: dict, policy: dict) -> dict:
    """owner_docs: session -> `ah owners` JSON. Alert key liveness:<session8>/agent-<id> (DESIGN section 5).
    SILENT is warning, SILENT-HIGH and DROPPED high, and critical once idle passes critical_seconds (90 min) so the
    deadman path fires. High and critical carry detail.stop_block for the main session's Stop lint (D2)."""
    out = {}
    crit = int(policy.get("critical_seconds", 5400))
    for session, doc in sorted(owner_docs.items()):
        for r in (doc or {}).get("owners") or []:
            if not isinstance(r, dict) or not isinstance(r.get("agent_id"), str):
                continue
            sev = LIVENESS_SEVERITY.get(r.get("state"))
            if not sev or r.get("owner") is not True:  # ahd only raises rows ah marks as owners
                continue
            idle = r.get("idle_s") if isinstance(r.get("idle_s"), int) else None
            if sev == "high" and idle is not None and idle >= crit:
                sev = "critical"
            task = f"agent-{r['agent_id']}"
            what = r.get("task") if isinstance(r.get("task"), str) else ""
            if r.get("restricted") or peek.text_excluded(what, policy):
                what = ""
            ticket = r.get("ticket") if isinstance(r.get("ticket"), str) else None
            since = parse_ts(r.get("last_activity")) or 0
            if not re.match(r"^a[0-9a-f]{6,32}$", r["agent_id"]):
                continue
            typ = r.get("type") if isinstance(r.get("type"), str) else "?"
            if peek.value_excluded([typ, ticket], policy):
                typ, ticket = "?", None
            message = peek.scrub(f"owner {r['state']}: {r['agent_id']} ({typ}) "
                                 f"last active {iso(since) if since else 'unknown'}"
                                 f"{' ' + ticket if ticket else ''}{': ' + what if what else ''}", 300)
            if peek.text_excluded(message, policy):
                message = f"owner {r['state']}: {r['agent_id']}"
            out[f"liveness:{session[:8]}/{task}"] = {
                "severity": sev, "class": "liveness", "kind": "liveness", "subject": f"{session[:8]}.{task}",
                "since": int(since),
                # frozen text: no live minute counter, so repeated ticks never rewrite the message (M8)
                "message": message,
                "detail": {"session": session[:8], "main_session": session, "task": task, "agent": r["agent_id"],
                           "ticket": ticket, "state": r.get("state"),
                           "stop_block": sev in ("high", "critical")}}
    return out


def ask_alerts(asks: list, policy: dict, ts: float) -> dict:
    out = {}
    un, unh = policy.get("unowned_seconds", 900), policy.get("unowned_high_seconds", 7200)
    stale = policy.get("stale_ask_seconds", 86400)
    for a in asks:
        if "error" in a:
            out["ask:ledger:error"] = {"severity": "warning", "class": "ask", "kind": "ask", "subject": "ledger",
                                       "since": 0, "message": a["error"], "detail": {}}
            continue
        st = a.get("state")
        since = a.get("since") or a.get("created") or ts
        base = f"ask:{a['id']}"
        detail = {"ask": a["id"], "ledger": a.get("ledger")}
        common = {"class": "ask", "kind": "ask", "subject": a["id"], "since": int(since), "detail": detail}
        if st in OPEN_STATES and a.get("owner") in UNOWNED and ts - since >= un:
            recent = bool(a.get("created")) and ts - a["created"] <= 86400
            out[base + ":unowned"] = dict(common, severity="high" if recent and ts - since >= unh else "warning",
                                          message=peek.scrub(f"unowned ask {a['id']}: {a.get('text', '')}", 300))
        elif st == "in_progress" and ts - (a.get("checked") or since) >= stale:
            out[base + ":stale"] = dict(common, severity="warning",
                                        message=f"ask {a['id']} in progress, unchecked since "
                                                f"{iso(a.get('checked') or since)}: {a.get('text', '')}")
        if st == "done" and not a.get("evidence") and ts - since <= policy.get("no_evidence_window_seconds", 7 * 86400):
            out[base + ":no-evidence"] = dict(common, severity="warning",
                                              message=f"ask {a['id']} closed without evidence")
    return out


def ring_wrap_alert(events: list, ts: float, hostname: str) -> dict:
    """The ring holds 1024 transitions. Full and its oldest entry under an hour old means it wraps more than once
    an hour, so raises can vanish before anyone reads them (review item 7)."""
    if len(events) < RING_SLOTS:
        return {}
    oldest = min((parse_ts(e.get("at")) for e in events if parse_ts(e.get("at"))), default=None)
    if oldest is None or ts - oldest >= 3600:
        return {}
    return {"ring:wrap": {"severity": "warning", "class": "self", "kind": "ring", "subject": hostname,
                          "since": int(oldest // 3600 * 3600),
                          "message": f"alert ring on {hostname} wraps more than once an hour", "detail": {}}}


def plan_transitions(desired: dict, ring: dict, hold=frozenset(), now=None) -> list:
    """Deterministic diff: [(op, key, flag, ring_event)]. Keys in `hold` get no transition at all this tick.
    `now` also refreshes an active alert whose ring text no longer matches, or lowers its severity, marked
    detail.updated and rate limited by liveness. A rise is never delayed. Every raise carries the text's marks."""
    ops = []
    for k in sorted(desired):
        if k in hold:
            continue
        f = desired[k]
        cur = ring.get(k)
        active = cur is not None and cur.get("event") == "raise"
        marks = liveness.alert_marks(f.get("message"))
        new_sev, old_sev = SEV.get(f["severity"], 0), SEV.get(cur.get("severity"), 0) if active else 0
        if not active or new_sev > old_sev:
            ops.append(("raise", k, dict(f, detail={**(f.get("detail") or {}), **marks}), cur))
        elif now is not None:
            at = parse_ts(cur.get("at")) or 0
            lower = new_sev < old_sev and now - at >= liveness.ALERT_REFRESH_MIN_S
            if lower or (new_sev == old_sev and liveness.ring_text_stale(cur.get("detail"), cur.get("message"),
                                                                         f.get("message"), at, now)):
                ops.append(("raise", k, dict(f, detail={**(f.get("detail") or {}), **marks, "updated": True}), cur))
    for k in sorted(ring):
        if k in hold:
            continue
        if k not in desired and ring[k].get("event") == "raise":
            ops.append(("clear", k, None, ring[k]))
    return ops


KEY_SAFE = re.compile(r"[^A-Za-z0-9._-]")


def write_key(hostname: str, kind: str, subject: str, transition: str, since) -> str:
    """ahd:<host>:<kind>:<owner-or-ask>:<transition>:<since-epoch> (review M6). The same observation always yields
    the same key, so a restart or a repeated tick is a duplicate in ah, never a new row. Max 128 chars."""
    subj = KEY_SAFE.sub(".", str(subject))
    if len(subj) > 64:
        subj = subj[:40] + "." + hashlib.sha256(subj.encode()).hexdigest()[:16]
    return ":".join(("ahd", KEY_SAFE.sub(".", hostname)[:24], kind, subj, transition, str(int(since or 0))))[:128]


# ---------------------------------------------------------------- the daemon

class Daemon:
    def __init__(self, policy=None, runner=None):
        self.policy = policy or load_policy()
        self.runner = runner or run_cmd
        self.host = host()
        self.lock_fd = None
        self.tick_no = 0
        self.last_wall = None
        self.last_mono = None
        self.hold_ticks = 0
        self.unsupported = {}  # ah verb -> monotonic time until which it is not retried
        self.stop = threading.Event()
        self.last = {}
        self.dry_writes = dry_runner.writes if runner is dry_runner else []

    def ah(self) -> list:
        argv = self.policy.get("ah") or ["python3", "~/.claude/hooks/ah.py"]
        return [os.path.expanduser(str(x)) for x in argv]

    def posts_goodqa(self) -> bool:
        """Only the Mac posts to GoodQA (review M5 / D3); Linux ahds raise ring alerts and spool."""
        v = self.policy.get("goodqa_poster")
        return bool(v) if isinstance(v, bool) else sys.platform == "darwin"

    # -- lifecycle
    def acquire(self) -> bool:
        run = home() / ".agent-harness" / "run"
        run.mkdir(mode=0o700, parents=True, exist_ok=True)
        # never written (the lock holds no state); O_NOFOLLOW so a planted symlink cannot redirect it
        fd = os.open(run / "ahd.lock", os.O_RDONLY | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0), 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            os.close(fd)
            return False
        self.lock_fd = fd
        return True

    def release(self) -> None:
        if self.lock_fd is not None:
            os.close(self.lock_fd)
            self.lock_fd = None

    # -- writes, all through ah
    def call(self, verb: str, args: list, deadline: float, stdin=None):
        """Run `ah <verb...> <args>` within the tick deadline. Returns (rc, parsed-json-or-None)."""
        if self.unsupported.get(verb, 0) > mono():
            return 2, None
        left = deadline - mono()
        if left <= 1:
            return 124, None
        argv = self.ah() + verb.split() + args
        rc, out, err = self.runner(argv, min(left, float(self.policy.get("ah_timeout_seconds", 30))), stdin)
        doc = None
        try:
            doc = json.loads(out) if out.strip() else None
        except ValueError:
            doc = None
        if rc == 2 and ("invalid choice" in err or (isinstance(doc, dict) and doc.get("code") == "unknown_op")):
            self.unsupported[verb] = mono() + 600
            log.warning("ah %s not available yet; skipping it for 10 min", verb)
        elif rc != 0:
            log.warning("ah %s rc=%s %s", verb, rc, peek.scrub(err, 160))
        return rc, doc

    # -- one tick
    def tick(self) -> dict:
        self.tick_no += 1
        ts, mt = now(), mono()
        deadline = mt + float(self.policy.get("tick_budget_seconds", 45))
        summary = {"tick": self.tick_no, "at": iso(ts), "steps": {}, "skipped": []}
        if self.last_wall is not None:
            skew = (ts - self.last_wall) - (mt - self.last_mono)
            if abs(skew) > float(self.policy.get("clock_jump_seconds", 300)):
                self.hold_ticks = int(self.policy.get("clock_hold_ticks", 1))
                log.warning("clock:jump %+.0f s; liveness transitions held for %s tick(s)", skew, self.hold_ticks)
                summary["clock_jump"] = round(skew)
        self.last_wall, self.last_mono = ts, mt

        def step(name, fn):
            if mono() >= deadline:
                summary["skipped"].append(name)
                return None
            t0 = mono()
            try:
                return fn()
            except Exception as exc:  # one failing step never stops the others or the loop
                summary.setdefault("errors", []).append(f"{name}: {type(exc).__name__}")
                try:
                    log.error("step %s failed: %s", name, type(exc).__name__)
                except Exception:
                    pass
                return None
            finally:
                summary["steps"][name] = round(mono() - t0, 3)

        step("heartbeat", lambda: self.call("heartbeat beat", [
            "--service", SOURCE, "--key", write_key(self.host, "beat", SOURCE, f"t{self.tick_no}", ts)], deadline))
        step("checks", lambda: self.run_checks(deadline))
        sessions, blocked = step("sessions", lambda: scan_sessions(self.policy, ts)) or ([], {})
        docs = step("owners", lambda: self.owner_docs(sessions, deadline)) or {}
        asks = step("asks", lambda: v1_asks(self.policy)) or []
        pending = step("wal_asks", lambda: wal_asks(self.policy, sessions)) or []
        events = read_ring()
        desired = {}
        desired.update(liveness_alerts(docs, self.policy))
        desired.update(ask_alerts(asks, self.policy, ts))
        desired.update(ring_wrap_alert(events, ts, self.host))
        desired.update(wal_unsafe_alerts(blocked, ts))
        ring = ring_state(events, SOURCE, self.host)
        hold = set()
        if self.hold_ticks > 0:
            hold |= {k for k in list(desired) + list(ring) if k.startswith("liveness:")}
            self.hold_ticks -= 1
        # owners unreadable or session blocked: never clear on missing data
        missing = {s[:8] for s in sessions if s not in docs} | {s[:8] for s in blocked}
        hold |= {k for k in ring if k.startswith("liveness:") and k[9:17] in missing and k not in desired}
        bad = set(summary["skipped"]) | {e.split(":", 1)[0] for e in summary.get("errors", [])}
        if bad & {"sessions", "owners"}:
            hold |= {k for k in ring if k.startswith("liveness:") and k not in desired}
        if "asks" in bad or any("error" in a for a in asks):
            hold |= {k for k in ring if k.startswith("ask:") and k not in desired}
        plan = plan_transitions(desired, ring, frozenset(hold), now=ts)
        sent = step("alerts", lambda: self.send(plan, deadline)) or 0
        step("spool", lambda: self.call("spool drain", [], deadline))
        summary.update(sessions=len(sessions), owners=sum(len((d or {}).get("owners") or []) for d in docs.values()),
                       asks_open=sum(1 for a in asks if a.get("state") in OPEN_STATES),
                       wal_asks_open=len(pending), desired=len(desired), transitions=len(plan), sent=sent,
                       unowned=sorted(k for k in desired if k.endswith(":unowned")),
                       dropped=sorted(k for k, f in desired.items() if (f.get("detail") or {}).get("state") == "DROPPED"),
                       silent=sorted(k for k, f in desired.items()
                                     if (f.get("detail") or {}).get("state") in ("SILENT", "SILENT-HIGH")),
                       wall_s=round(mono() - mt, 3))
        if summary["skipped"]:
            log.warning("tick %s over budget; skipped %s", self.tick_no, ",".join(summary["skipped"]))
        self.last = {"summary": summary, "desired": desired, "wal_asks": pending}
        return summary

    def run_checks(self, deadline: float):
        try:
            import ops_watch
        except Exception:
            return None
        checks = getattr(ops_watch, "checks", None)
        if checks is None or not hasattr(checks, "run_all"):
            return None  # the ops-watch timer keeps running until it exposes run_all (DESIGN section 13)
        transitions = checks.run_all(ops_watch.load_config(home()), du=self.tick_no % 10 == 1)
        for ev in transitions or []:
            if mono() >= deadline:
                break
            op = "raise" if ev.get("event") == "raise" else "clear"
            src = str(ev.get("source") or "ops-watch")
            flag = {"severity": ev.get("severity") or "info", "message": ev.get("message", ""),
                    "detail": ev.get("detail") or {}, "kind": src, "subject": ev.get("key"),
                    "since": int(parse_ts(ev.get("at")) or 0)}
            self.call(f"alert {op}", self.alert_args(op, ev.get("key"), flag, src), deadline)
        return len(transitions or [])

    def owner_docs(self, sessions: list, deadline: float) -> dict:
        docs = {}
        for s in sessions:
            rc, doc = self.call("owners", ["--session", s], deadline)
            if rc == 0 and isinstance(doc, dict) and isinstance(doc.get("owners"), list):
                docs[s] = doc
        return docs

    def key_for(self, op: str, key: str, flag, cur, extra: str = "") -> str:
        if op == "clear":
            since = parse_ts((cur or {}).get("at")) or (cur or {}).get("seq", 0)
            kind = key.split(":", 1)[0]
            return write_key(self.host, kind, key.split(":", 1)[-1], "clear" + extra, since)
        if (flag.get("detail") or {}).get("updated"):  # one ring write per distinct text, not one per alert
            extra = "-u" + hashlib.sha256(str(flag.get("message", "")).encode()).hexdigest()[:8] + extra
        if cur and cur.get("event") == "raise":  # text or severity can return to an earlier value: the row it replaces
            extra = f"-s{cur.get('seq', 0)}" + extra  # tells those writes apart, and a retry repeats the same key
        return write_key(self.host, flag.get("kind") or key.split(":", 1)[0], flag.get("subject") or key,
                         f"raise-{flag['severity']}{extra}", flag.get("since", 0))

    def alert_args(self, op: str, key, flag, source, cur=None, extra: str = "") -> list:
        args = ["--alert-key", str(key), "--source", source, "--key", self.key_for(op, key, flag or {}, cur, extra)]
        if op == "raise":
            args += ["--severity", flag["severity"], "--message", str(flag.get("message", ""))[:MESSAGE_MAX]]
            detail = dict(flag.get("detail") or {})
            if extra:
                detail["reasserted"] = True
            if detail:
                args += ["--detail", json.dumps(detail, sort_keys=True)]
        return args

    def send(self, plan: list, deadline: float) -> int:
        if not plan:
            return 0
        batch_min = int(self.policy.get("batch_threshold", 10))
        if len(plan) > batch_min and self.unsupported.get("apply", 0) <= mono():
            lines = []
            for op, key, flag, cur in plan:
                args = {"alert_key": key, "source": SOURCE}
                if op == "raise":
                    args.update(severity=flag["severity"], message=flag.get("message", ""), detail=flag.get("detail") or {})
                lines.append(json.dumps({"op": f"alert.{op}", "key": self.key_for(op, key, flag or {}, cur),
                                         "args": args}, sort_keys=True))
            rc, _ = self.call("apply", ["--batch", "-"], deadline, stdin="\n".join(lines) + "\n")
            if rc == 0:
                for op, key, flag, cur in plan:
                    if op == "raise":
                        self.ticket_comment(key, flag, deadline)
                return len(plan)
        sent = 0
        for op, key, flag, cur in plan:
            rc, doc = self.call(f"alert {op}", self.alert_args(op, key, flag, SOURCE, cur), deadline)
            if rc == 0 and op == "raise" and isinstance(doc, dict) and doc.get("result") == "duplicate":
                # ah already applied this raise, yet the ring no longer shows it: the ring wrapped. Reassert.
                oldest = min((e.get("seq", 0) for e in read_ring()), default=0)
                rc, _ = self.call("alert raise", self.alert_args(op, key, flag, SOURCE, cur, f"-r{oldest}"), deadline)
            if rc == 0 and op == "raise":
                self.ticket_comment(key, flag, deadline)
            sent += rc == 0
        return sent

    def ticket_comment(self, key: str, flag: dict, deadline: float) -> None:
        """High/critical owner alerts also go to the task's own ticket, through ah, from the Mac only."""
        ticket = (flag.get("detail") or {}).get("ticket")
        if (flag.get("detail") or {}).get("updated"):
            return
        if not ticket or flag.get("class") != "liveness" or flag["severity"] not in ("high", "critical") \
                or not self.posts_goodqa():
            return
        ref = ticket if ticket.lower().startswith("goodqa ") else f"GoodQA {ticket}"
        self.call("ticket comment", [ref, "--body", f"ahd: {flag.get('message', '')} [{key}]"[:1000],
                                     "--key", self.key_for("raise", key, flag, None, "-comment")], deadline)

    # -- loop
    def serve_forever(self) -> int:
        signal.signal(signal.SIGTERM, lambda *_: self.stop.set())
        threading.Thread(target=memory_guard, args=(int(self.policy.get("memory_cap_bytes", 1 << 30)), self.stop),
                         name="ahd-memory-guard", daemon=True).start()
        period = float(self.policy.get("tick_seconds", 60))
        log.info("ahd started pid %s host %s", os.getpid(), self.host)
        while not self.stop.is_set():
            t0 = mono()
            try:
                s = self.tick()
                log.info("tick %s: %s", s["tick"], json.dumps({k: s[k] for k in (
                    "sessions", "owners", "asks_open", "desired", "transitions", "sent", "wall_s")}))
            except Exception as exc:  # never crash-loop
                log.error("tick failed: %s", type(exc).__name__)
            self.stop.wait(max(1.0, period - (mono() - t0)))
        self.release()
        log.info("ahd stopped")
        return 0


def setup_logging(to_stderr: bool = False) -> None:
    log.setLevel(logging.INFO)
    if to_stderr:
        h = logging.StreamHandler(sys.stderr)
    else:
        d = home() / ".agent-harness" / "logs"
        try:
            d.mkdir(mode=0o700, parents=True, exist_ok=True)
            h = logging.handlers.RotatingFileHandler(d / "ahd.log", maxBytes=8 << 20, backupCount=4)
        except OSError:
            h = logging.StreamHandler(sys.stderr)
    h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    log.addHandler(h)


# ---------------------------------------------------------------- service install

LABEL = "com.ericmacdougall.ahd"


def unit_files(script: Path) -> dict:
    h = home()
    if sys.platform == "darwin":
        logs = h / ".agent-harness" / "logs"
        plist = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>{LABEL}</string>
<key>ProgramArguments</key><array><string>/usr/bin/python3</string><string>-I</string><string>{script}</string><string>run</string></array>
<key>RunAtLoad</key><true/>
<key>KeepAlive</key><dict><key>SuccessfulExit</key><false/></dict>
<key>ThrottleInterval</key><integer>10</integer>
<key>Nice</key><integer>10</integer>
<key>LowPriorityIO</key><true/>
<key>StandardOutPath</key><string>/dev/null</string>
<key>StandardErrorPath</key><string>{logs}/ahd.err</string>
</dict></plist>
"""
        return {h / "Library" / "LaunchAgents" / f"{LABEL}.plist": plist}
    unit = f"""[Unit]
Description=agent harness daemon (ahd, GoodQA 1ae27b6b#14601)

[Service]
ExecStart=/usr/bin/env python3 -I {script} run
Restart=on-failure
RestartSec=10
Nice=10
IOSchedulingClass=idle
MemoryMax=1G
MemorySwapMax=0

[Install]
WantedBy=default.target
"""
    return {h / ".config" / "systemd" / "user" / "ahd.service": unit}


def install(apply: bool) -> int:
    script = Path(__file__).resolve()
    files = unit_files(script)
    for p, body in files.items():
        print(f"{'write' if apply else 'would write'} {p}")
        if apply:
            p.parent.mkdir(parents=True, exist_ok=True)
            tmp = p.with_name(p.name + ".tmp")
            tmp.write_text(body)
            os.replace(tmp, p)
    if sys.platform == "darwin":
        cmds = [["launchctl", "bootout", f"gui/{os.getuid()}/{LABEL}"],
                ["launchctl", "bootstrap", f"gui/{os.getuid()}", str(next(iter(files)))]]
    else:
        cmds = [["systemctl", "--user", "daemon-reload"], ["systemctl", "--user", "enable", "--now", "ahd.service"]]
    for c in cmds:
        print(("run " if apply else "would run ") + " ".join(c))
        if apply:
            subprocess.run(c, stdin=subprocess.DEVNULL, check=False)
    return 0


# ---------------------------------------------------------------- CLI

def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="ahd", description="harness daemon: monitor and schedule; writes only via ah")
    ap.add_argument("--once", action="store_true", help="one tick in the foreground, print its summary")
    sp = ap.add_subparsers(dest="cmd")
    sp.add_parser("run", help="the 60 s loop (launchd/systemd)")
    sp.add_parser("report", help="one tick, then print the unowned / dropped / silent lists")
    i = sp.add_parser("install")
    i.add_argument("--apply", action="store_true")
    a = ap.parse_args(argv)
    if a.cmd == "install":
        return install(a.apply)
    if a.cmd is None and not a.once:
        ap.print_help()
        return 2
    os.umask(0o077)  # ahd's own files (log, lock) are private
    setup_logging(to_stderr=a.once or a.cmd == "report")
    if a.cmd == "report":
        # read-only: no lock, so it works beside the running service, and every write verb is stubbed
        d = Daemon(runner=dry_runner)
        s = d.tick()
        out = {"summary": {k: v for k, v in s.items() if k not in ("unowned", "dropped", "silent")},
               "dropped": [d.last["desired"][k]["message"] for k in s["dropped"]],
               "silent": [d.last["desired"][k]["message"] for k in s["silent"]],
               "unowned": [d.last["desired"][k]["message"] for k in s["unowned"]],
               "waiting_on_user": [f"{w['id']} ({w['session']}): {w['text']}" for w in d.last["wal_asks"]],
               "would_write": d.dry_writes}
        print(json.dumps(out, indent=1))
        return 0
    d = Daemon()
    if not d.acquire():
        print("ahd: already running on this host", file=sys.stderr)
        return 0
    if a.cmd == "run":
        return d.serve_forever()
    try:
        s = d.tick()
    finally:
        d.release()
    print(json.dumps(s))
    return 0


READ_VERBS = ("owners",)


def dry_runner(argv, timeout, stdin=None, env=None):
    """For `report`: pass read verbs to ah, record every write verb instead of running it."""
    i = next((n for n, a in enumerate(argv) if a.endswith("ah.py")), len(argv) - 1)
    words = []
    for a in argv[i + 1:]:
        if a.startswith("-"):
            break
        words.append(a)
    if words[:1] and words[0] in READ_VERBS:
        return run_cmd(argv, timeout, stdin, env)
    dry_runner.writes.append(" ".join(words)[:80])
    return 0, json.dumps({"ok": True, "result": "dry-run"}), ""


dry_runner.writes = []


if __name__ == "__main__":
    sys.exit(main())
