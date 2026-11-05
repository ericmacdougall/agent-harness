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
import signal
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import ahd_peek as peek  # noqa: E402

SOURCE = "ahd"
OPEN_STATES = ("open", "assigned", "in_progress", "blocked")
UNOWNED = ("", "unassigned", "none", None)
LIVENESS_SEVERITY = {"SILENT": "warning", "SILENT-HIGH": "high", "DROPPED": "high"}
SEV = {"info": 0, "warning": 1, "high": 2, "critical": 3}
SESSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{7,63}$")
RING_SLOT = 1024

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
            extra = json.loads(user.read_text(encoding="utf-8"))
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


def run_cmd(argv, timeout, stdin=None, env=None):
    """(rc, stdout, stderr) with stdin closed unless given; never raises for a child problem."""
    try:
        p = subprocess.run(argv, input=stdin.encode() if isinstance(stdin, str) else stdin,
                           stdin=None if stdin is not None else subprocess.DEVNULL,
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=max(1.0, timeout), env=env)
        return p.returncode, p.stdout.decode("utf-8", "replace"), p.stderr.decode("utf-8", "replace")
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except OSError as exc:
        return 127, "", type(exc).__name__


def idem(*parts) -> str:
    """Deterministic idempotency key: same observation, same key, on every host restart."""
    return "ahd-" + hashlib.sha256("\x1f".join(str(p) for p in parts).encode()).hexdigest()[:40]


# ---------------------------------------------------------------- read-only inputs

def read_ring(path=None) -> list:
    """Every event in the ops-watch alert ring (fixed 1 KiB slots). Read-only; bad slots are skipped."""
    p = Path(path) if path else home() / ".agent-harness" / "state" / "alerts.jsonl"
    try:
        with open(p, "rb") as fh:
            data = fh.read(RING_SLOT * 1024 + 1)
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


def active_sessions(policy: dict, ts: float) -> list:
    base = home() / ".claude" / "wals"
    look = policy.get("owner_window_seconds", 172800)
    out = []
    try:
        for d in base.iterdir():
            if not SESSION_RE.match(d.name):
                continue
            try:
                if ts - (d / "main.jsonl").stat().st_mtime <= look:
                    out.append(d.name)
            except OSError:
                continue
    except OSError:
        return []
    return sorted(out)


def v1_asks(policy: dict) -> list:
    p = home() / ".agent-harness" / "work-assignments.json"
    try:
        if p.stat().st_size > policy.get("wal_read_max_bytes", 64 << 20):
            return [{"error": "v1 ledger oversized"}]
        data = json.loads(p.read_bytes())
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
    cap = policy.get("wal_read_max_bytes", 64 << 20)
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
    """owner_docs: session -> `ah owners` JSON. Alert key liveness:<session8>/agent-<id> (DESIGN section 5)."""
    out = {}
    for session, doc in sorted(owner_docs.items()):
        for r in (doc or {}).get("owners") or []:
            if not isinstance(r, dict) or not isinstance(r.get("agent_id"), str):
                continue
            sev = LIVENESS_SEVERITY.get(r.get("state"))
            if not sev or r.get("owner") is False:  # helpers are ah's call (owner flag); ahd only raises owners
                continue
            task = f"agent-{r['agent_id']}"
            what = r.get("task") if isinstance(r.get("task"), str) else ""
            if peek.text_excluded(what, policy):
                what = ""
            idle = r.get("idle_s")
            mins = f"{idle // 60} min" if isinstance(idle, int) else "unknown"
            ticket = r.get("ticket") if isinstance(r.get("ticket"), str) else None
            out[f"liveness:{session[:8]}/{task}"] = {
                "severity": sev, "class": "liveness",
                "message": peek.scrub(f"owner {r['state']}: {r['agent_id']} ({r.get('type') or '?'}) idle {mins}"
                                      f"{' ' + ticket if ticket else ''}{': ' + what if what else ''}", 300),
                "detail": {"session": session[:8], "task": task, "agent": r["agent_id"], "ticket": ticket,
                           "state": r.get("state")}}
    return out


def ask_alerts(asks: list, policy: dict, ts: float) -> dict:
    out = {}
    un, unh = policy.get("unowned_seconds", 900), policy.get("unowned_high_seconds", 7200)
    stale = policy.get("stale_ask_seconds", 86400)
    for a in asks:
        if "error" in a:
            out["ask:ledger:error"] = {"severity": "warning", "class": "ask", "message": a["error"], "detail": {}}
            continue
        st = a.get("state")
        since = a.get("since") or a.get("created") or ts
        base = f"ask:{a['id']}"
        detail = {"ask": a["id"], "ledger": a.get("ledger")}
        if st in OPEN_STATES and a.get("owner") in UNOWNED and ts - since >= un:
            recent = bool(a.get("created")) and ts - a["created"] <= 86400
            out[base + ":unowned"] = {"severity": "high" if recent and ts - since >= unh else "warning",
                                      "class": "ask", "message": f"unowned ask {a['id']}: {a.get('text', '')}",
                                      "detail": detail}
        elif st == "in_progress" and ts - (a.get("checked") or since) >= stale:
            h = int((ts - (a.get("checked") or since)) // 3600)
            out[base + ":stale"] = {"severity": "warning", "class": "ask",
                                    "message": f"ask {a['id']} in progress, unchecked {h} h: {a.get('text', '')}",
                                    "detail": detail}
        if st == "done" and not a.get("evidence"):
            out[base + ":no-evidence"] = {"severity": "warning", "class": "ask",
                                          "message": f"ask {a['id']} closed without evidence", "detail": detail}
    return out


def plan_transitions(desired: dict, ring: dict, hold=frozenset()) -> list:
    """Deterministic diff: [(op, key, flag, basis_seq)]. Keys in `hold` may clear but not newly raise/escalate."""
    ops = []
    for k in sorted(desired):
        f = desired[k]
        cur = ring.get(k)
        active = cur is not None and cur.get("event") == "raise"
        basis = cur.get("seq", 0) if cur else 0
        if k in hold:
            continue
        if not active or SEV.get(f["severity"], 0) > SEV.get(cur.get("severity"), 0):
            ops.append(("raise", k, f, basis))
    for k in sorted(ring):
        if k not in desired and ring[k].get("event") == "raise":
            ops.append(("clear", k, None, ring[k].get("seq", 0)))
    return ops


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

    def ah(self) -> list:
        argv = self.policy.get("ah") or ["python3", "~/.claude/hooks/ah.py"]
        return [os.path.expanduser(str(x)) for x in argv]

    # -- lifecycle
    def acquire(self) -> bool:
        run = home() / ".agent-harness" / "run"
        run.mkdir(parents=True, exist_ok=True)
        fd = os.open(run / "ahd.lock", os.O_RDONLY | os.O_CREAT, 0o600)  # never written: the lock holds no state
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
        if rc == 2 and (doc is None or (isinstance(doc, dict) and doc.get("code") in ("unknown_op", "bad_request"))) \
                and ("invalid choice" in err or (isinstance(doc, dict) and doc.get("code") == "unknown_op")):
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
                self.hold_ticks = int(self.policy.get("clock_hold_ticks", 2))
                log.warning("clock:jump %+.0f s; holding liveness raises for %s ticks", skew, self.hold_ticks)
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
                log.error("step %s failed: %s", name, type(exc).__name__)
                summary.setdefault("errors", []).append(f"{name}: {type(exc).__name__}")
                return None
            finally:
                summary["steps"][name] = round(mono() - t0, 3)

        step("heartbeat", lambda: self.call("heartbeat beat", ["--service", SOURCE, "--key",
                                                                idem(self.host, "beat", self.tick_no, int(ts))],
                                            deadline))
        step("checks", lambda: self.run_checks(deadline))
        sessions = step("sessions", lambda: active_sessions(self.policy, ts)) or []
        docs = step("owners", lambda: self.owner_docs(sessions, deadline)) or {}
        asks = step("asks", lambda: v1_asks(self.policy)) or []
        pending = step("wal_asks", lambda: wal_asks(self.policy, sessions)) or []
        desired = {}
        desired.update(liveness_alerts(docs, self.policy))
        desired.update(ask_alerts(asks, self.policy, ts))
        ring = ring_state(read_ring(), SOURCE, self.host)
        hold = frozenset(k for k in desired if k.startswith("liveness:")) if self.hold_ticks > 0 else frozenset()
        if self.hold_ticks > 0:
            self.hold_ticks -= 1
        if docs or not sessions:
            plan = plan_transitions(desired, ring, hold)
        else:  # owners unreadable this tick: never clear liveness alerts on missing data
            plan = [p for p in plan_transitions(desired, ring, hold) if not (p[0] == "clear" and p[1].startswith("liveness:"))]
        if "owners" in summary["skipped"] or "asks" in summary["skipped"]:
            plan = [p for p in plan if p[0] != "clear"]
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
            import ops_watch  # noqa: F401
        except Exception:
            return None
        checks = getattr(ops_watch, "checks", None)
        if checks is None or not hasattr(checks, "run_all"):
            return None  # the ops-watch timer keeps running until it exposes run_all (DESIGN section 13)
        du = self.tick_no % 10 == 1
        transitions = checks.run_all(ops_watch.load_config(home()), du=du)
        for ev in transitions or []:
            if mono() >= deadline:
                break
            op = "raise" if ev.get("event") == "raise" else "clear"
            self.call(f"alert {op}", self.alert_args(ev.get("key"), ev, ev.get("source", "ops-watch"),
                                                     ev.get("seq", 0)), deadline)
        return len(transitions or [])

    def owner_docs(self, sessions: list, deadline: float) -> dict:
        docs = {}
        for s in sessions:
            rc, doc = self.call("owners", ["--session", s], deadline)
            if rc == 0 and isinstance(doc, dict):
                docs[s] = doc
        return docs

    def alert_args(self, key, flag, source, basis) -> list:
        sev = (flag or {}).get("severity") or "info"
        args = ["--alert-key", str(key), "--source", source, "--key", idem(self.host, source, key, sev, basis)]
        if flag:
            args += ["--severity", sev, "--message", str(flag.get("message", ""))[:400]]
            if flag.get("detail"):
                args += ["--detail", json.dumps(flag["detail"], sort_keys=True)]
        return args

    def send(self, plan: list, deadline: float) -> int:
        if not plan:
            return 0
        sent = 0
        batch_min = int(self.policy.get("batch_threshold", 10))
        if len(plan) > batch_min and self.unsupported.get("apply", 0) <= mono():
            lines = []
            for op, key, flag, basis in plan:
                sev = (flag or {}).get("severity") or "info"
                lines.append(json.dumps({"op": f"alert.{op}", "key": idem(self.host, SOURCE, key, sev, basis),
                                         "args": {"alert_key": key, "source": SOURCE, "severity": sev,
                                                  "message": (flag or {}).get("message", "resolved"),
                                                  "detail": (flag or {}).get("detail") or {}}}, sort_keys=True))
            rc, _ = self.call("apply", ["--batch", "-"], deadline, stdin="\n".join(lines) + "\n")
            if rc == 0:
                return len(plan)
        for op, key, flag, basis in plan:
            rc, _ = self.call(f"alert {op}", self.alert_args(key, flag, SOURCE, basis), deadline)
            sent += rc == 0
        return sent

    # -- loop
    def serve_forever(self) -> int:
        signal.signal(signal.SIGTERM, lambda *_: self.stop.set())
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
            d.mkdir(parents=True, exist_ok=True)
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
    setup_logging(to_stderr=a.once or a.cmd == "report")
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
    if a.cmd == "report":
        out = {"summary": {k: v for k, v in s.items() if k not in ("unowned", "dropped", "silent")},
               "dropped": [d.last["desired"][k]["message"] for k in s["dropped"]],
               "silent": [d.last["desired"][k]["message"] for k in s["silent"]],
               "unowned": [d.last["desired"][k]["message"] for k in s["unowned"]],
               "waiting_on_user": [f"{w['id']} ({w['session']}): {w['text']}" for w in d.last["wal_asks"]]}
        print(json.dumps(out, indent=1))
    else:
        print(json.dumps(s))
    return 0


if __name__ == "__main__":
    sys.exit(main())
