#!/usr/bin/env python3
"""ops-watch: a small, deterministic, read-only watcher for the ops problem classes (GoodQA goodqa#14591).

Every 10 minutes (launchd on macOS, a systemd user timer on Linux) it runs seven checks:

  disk       volume use (85/92/97 %, free floor), growth attribution from a bounded, round-robin `du`
  units      failed systemd user units, and watched reclaim jobs that failed, lost their timer or logged failures
  crashes    macOS DiagnosticReports newer than the last run (process name, pid, parent, time only)
  processes  netwatch orphans (pid/name/age only), runaway orphans, Chrome-helper and shell counts
  delivery   delivery checkouts must be on main and clean (git status without optional locks)
  drift      CLAUDE.md managed block vs HARNESS.md at the harness repo's origin/main; installed hooks vs main
  codex      ~/.codex/config.toml hooks.state trust vs hooks.json ("Codex is skipping harness hooks")

Each problem is an alert keyed by (host, source, key). The alert is raised once, re-raised only when its severity
rises, and cleared once when it goes away. Transitions are written to the shared ring ~/.agent-harness/state/alerts.jsonl
(the canonical alert path, preallocated and written in place so it works on a full disk). wal.py injects the active
set into every agent. The same transitions are posted as one GoodQA comment per run, and critical raises also go
through the deadman alert script.

It never deletes, kills, reclaims or writes trust. Its only writes are its own state files, the ring and the
heartbeat. The one exception is a `du` that overruns its timeout: subprocess.run ends that child.

Exit codes: 0 ok; 2 an alert could not be persisted or delivered (queued and retried next run); 3 usage/config.
See docs/ops-watch.md.
"""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = 1
SOURCE = "ops-watch"
RING_SLOTS = 1024
SLOT_BYTES = 1024
STATE_SLOT_BYTES = 512 * 1024
SEVERITIES = {"info": 0, "warning": 1, "high": 2, "critical": 3}
REQUIRED = ("host", "source", "event", "severity", "key", "message")
GIB = 1024 ** 3
KIB = 1024
ALERTS_ISSUE_ID = "d1e67ce0-93a6-4a6b-a65c-9a7422e80b3f"  # GoodQA goodqa#14592 "ops-watch alerts"
MARK_START = "<!-- agent-harness:start -->"
MARK_END = "<!-- agent-harness:end -->"
DARWIN_PROTECTED = ("Library", "Desktop", "Documents", "Downloads", "Pictures", "Movies", "Music",
                    "Applications", "Public", "Dropbox", ".Trash")


# ---------------------------------------------------------------- config

def default_host() -> str:
    return "mac" if sys.platform == "darwin" else socket.gethostname().split(".")[0]


def defaults(host: str) -> dict:
    linux = sys.platform.startswith("linux")
    darwin = sys.platform == "darwin"
    return {
        "host": host,
        "disk": {"warn_pct": 85, "high_pct": 92, "critical_pct": 97, "free_floor_gib": 10, "growth_gib_h": 10,
                 "du_budget_s": 90, "du_per_dir_s": 60, "max_depth": 2, "max_children": 200,
                 "volumes": ["~", "/", "/tmp"],
                 "extra_roots": ["/tmp", "~/.goodqa-trash", "~/vm-backups", "~/.local/share/docker",
                                 "/var/lib/docker", "~/Library/Caches", "~/Library/Logs", "~/Library/Developer"],
                 "exclude": list(DARWIN_PROTECTED) if darwin else []},
        "units": {"enabled": linux, "reclaim": ["runner-worktree-retire", "inventory-hygiene", "ship-sample-watch",
                                                "disk-maintain", "dev2-lane-prune", "runner-byproduct-cleanup"]},
        "crashes": {"enabled": darwin, "dir": "~/Library/Logs/DiagnosticReports", "window_h": 6},
        "processes": {"netwatch": "~/.agent-harness/bin/netwatch", "orphan_warn": 5, "runaway_rss_mb": 4096,
                      "runaway_cpu": 80, "chrome_max": 150, "shell_max": 300},
        "delivery": [],
        "drift": {"repo": None, "ref": "origin/main", "claude_dir": "~/.claude"},
        "codex_dir": "~/.codex",
        "peers": [],
        "sinks": {"comment": {"mode": "none"}, "deadman": []},
    }


def expand(home: Path, value):
    if isinstance(value, str) and (value == "~" or value.startswith("~/")):
        return str(home) + value[1:]
    return value


def load_config(home: Path, host: str | None = None, overrides: dict | None = None) -> dict:
    """Defaults, then ~/.agent-harness/ops-watch.json, then overrides (dicts merge one level deep)."""
    cfg = defaults(host or default_host())
    layers = []
    path = home / ".agent-harness" / "ops-watch.json"
    if overrides is None and path.is_file():
        layers.append(json.loads(path.read_text()))
    if overrides:
        layers.append(overrides)
    for layer in layers:
        for key, value in layer.items():
            if isinstance(value, dict) and isinstance(cfg.get(key), dict):
                cfg[key] = {**cfg[key], **value}
            else:
                cfg[key] = value
    if host:
        cfg["host"] = host
    cfg["_home"] = str(home)
    return cfg


def home_of(cfg: dict) -> Path:
    return Path(cfg.get("_home") or Path.home())


def now_iso(ts: float | None = None) -> str:
    return datetime.fromtimestamp(time.time() if ts is None else ts, timezone.utc).isoformat()


def run(argv, timeout, stdin=None, env=None, cwd=None):
    """Default runner: (returncode, stdout). Raises subprocess.TimeoutExpired; stderr is discarded."""
    p = subprocess.run(argv, input=stdin, capture_output=True, text=True, timeout=timeout,
                       env=env, cwd=cwd)
    return p.returncode, p.stdout


def alert(check, key, severity, message, detail=None) -> dict:
    return {"check": check, "key": key, "severity": severity, "message": message, "detail": detail or {}}


# ---------------------------------------------------------------- ring (canonical alert path)

def ring_path(home: Path) -> Path:
    return home / ".agent-harness" / "state" / "alerts.jsonl"


EMPTY_SLOT = (json.dumps({"empty": True}).ljust(SLOT_BYTES - 1) + "\n").encode()


def _ensure_ring(fd: int) -> None:
    if os.fstat(fd).st_size == RING_SLOTS * SLOT_BYTES:
        return
    os.ftruncate(fd, 0)
    os.pwrite(fd, EMPTY_SLOT * RING_SLOTS, 0)
    os.fsync(fd)


def encode_slot(event: dict) -> bytes:
    event = dict(event)
    line = json.dumps(event, separators=(",", ":"), sort_keys=True)
    if len(line) > SLOT_BYTES - 1:
        event["detail"] = {"truncated": True}
        line = json.dumps(event, separators=(",", ":"), sort_keys=True)
    while len(line) > SLOT_BYTES - 1 and len(event.get("message", "")) > 8:
        event["message"] = event["message"][: max(8, len(event["message"]) - (len(line) - SLOT_BYTES + 1) - 4)] + "..."
        line = json.dumps(event, separators=(",", ":"), sort_keys=True)
    if len(line) > SLOT_BYTES - 1:
        raise ValueError("event does not fit a ring slot")
    return (line.ljust(SLOT_BYTES - 1) + "\n").encode()


def _parse_slots(data: bytes) -> list:
    out = []
    for i in range(0, len(data) - SLOT_BYTES + 1, SLOT_BYTES):
        try:
            obj = json.loads(data[i:i + SLOT_BYTES].decode("utf-8", "replace").strip())
        except ValueError:
            continue
        if isinstance(obj, dict) and isinstance(obj.get("seq"), int):
            out.append(obj)
    return sorted(out, key=lambda e: e["seq"])


def read_ring(path: Path) -> list:
    try:
        return _parse_slots(Path(path).read_bytes())
    except OSError:
        return []


def emit(event: dict, path: Path | None = None, home: Path | None = None) -> int:
    """Append one schema-1 alert event to the ring; returns its seq. Raises ValueError/OSError, never silent.

    Under an exclusive flock on the sidecar .lock: seq = max seq in the ring + 1, slot = seq % RING_SLOTS (the
    oldest entry is overwritten). The write is an in-place pwrite + fsync of a preallocated file."""
    missing = [k for k in REQUIRED if not event.get(k)]
    if missing:
        raise ValueError(f"alert event missing {missing}")
    if event["severity"] not in SEVERITIES or event["event"] not in ("raise", "clear"):
        raise ValueError("bad severity or event")
    path = Path(path) if path else ring_path(home or Path.home())
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    lock = os.open(str(path.with_suffix(".lock")), os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(lock, fcntl.LOCK_EX)
        fd = os.open(str(path), os.O_RDWR | os.O_CREAT, 0o600)
        try:
            _ensure_ring(fd)
            existing = _parse_slots(os.pread(fd, RING_SLOTS * SLOT_BYTES, 0))
            seq = (existing[-1]["seq"] if existing else 0) + 1
            record = {"schema": SCHEMA, "at": now_iso(), "detail": {}, **event, "seq": seq}
            os.pwrite(fd, encode_slot(record), (seq % RING_SLOTS) * SLOT_BYTES)
            os.fsync(fd)
            return seq
        finally:
            os.close(fd)
    finally:
        os.close(lock)


def latest_by_key(events: list) -> dict:
    latest = {}
    for e in events:
        latest[(e.get("host"), e.get("source"), e.get("key"))] = e
    return latest


def active_alerts(home: Path) -> list:
    """Active = the latest event per (host, source, key) is a raise. Highest severity first."""
    act = [e for e in latest_by_key(read_ring(ring_path(home))).values() if e.get("event") == "raise"]
    return sorted(act, key=lambda e: (-SEVERITIES.get(e.get("severity"), 0), e.get("key", "")))


# ---------------------------------------------------------------- state (two fixed slots, written in place)

def state_path(home: Path) -> Path:
    return home / ".agent-harness" / "state" / "ops-watch" / "state.json"


def load_state(home: Path) -> dict:
    try:
        data = state_path(home).read_bytes()
    except OSError:
        return {}
    best = {}
    for i in range(2):
        try:
            obj = json.loads(data[i * STATE_SLOT_BYTES:(i + 1) * STATE_SLOT_BYTES].decode("utf-8", "replace").strip())
        except ValueError:
            continue
        if isinstance(obj, dict) and obj.get("_gen", -1) > best.get("_gen", -1):
            best = obj
    return best


def save_state(home: Path, state: dict) -> None:
    state["_gen"] = int(state.get("_gen", 0)) + 1
    blob = json.dumps(state, separators=(",", ":"))
    dirs = state.get("dirs", {})
    while len(blob) > STATE_SLOT_BYTES - 1 and dirs:  # forget the least recently measured dirs first
        for path in sorted(dirs, key=lambda p: dirs[p].get("at", 0))[: max(1, len(dirs) // 5)]:
            dirs.pop(path, None)
        blob = json.dumps(state, separators=(",", ":"))
    if len(blob) > STATE_SLOT_BYTES - 1:
        raise ValueError("state too large")
    path = state_path(home)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(str(path), os.O_RDWR | os.O_CREAT, 0o600)
    try:
        if os.fstat(fd).st_size != 2 * STATE_SLOT_BYTES:
            os.ftruncate(fd, 0)
            os.pwrite(fd, b" " * (2 * STATE_SLOT_BYTES), 0)
        os.pwrite(fd, (blob.ljust(STATE_SLOT_BYTES - 1) + "\n").encode(), (state["_gen"] % 2) * STATE_SLOT_BYTES)
        os.fsync(fd)
    finally:
        os.close(fd)


# ---------------------------------------------------------------- 1. disk

def volumes(cfg: dict) -> list:
    home = home_of(cfg)
    seen, out = set(), []
    for p in cfg["disk"]["volumes"]:
        p = expand(home, p)
        try:
            st, vfs = os.stat(p), os.statvfs(p)
        except OSError:
            continue
        if st.st_dev in seen:
            continue
        seen.add(st.st_dev)
        used = (vfs.f_blocks - vfs.f_bfree) * vfs.f_frsize
        out.append({"fsid": str(st.st_dev), "path": p, "total": vfs.f_blocks * vfs.f_frsize,
                    "free": vfs.f_bavail * vfs.f_frsize, "used": used})
    return out


def used_pct(v: dict) -> float:
    used = v.get("used", v["total"] - v["free"])
    denom = used + v["free"]
    return 100.0 * used / denom if denom else 0.0


def volume_alerts(vols: list, dcfg: dict) -> list:
    out = []
    for v in vols:
        pct = used_pct(v)
        free_gib = v["free"] / GIB
        sev = None
        if pct >= dcfg["critical_pct"] or free_gib < dcfg["free_floor_gib"]:
            sev = "critical"
        elif pct >= dcfg["high_pct"]:
            sev = "high"
        elif pct >= dcfg["warn_pct"]:
            sev = "warning"
        if sev:
            out.append(alert("disk", f"disk:volume:{v['path']}", sev,
                             f"{v['path']} {pct:.0f}% used, {free_gib:.0f} GiB free",
                             {"fsid": v["fsid"], "used_pct": round(pct, 1), "free_bytes": v["free"],
                              "total_bytes": v["total"]}))
    return out


def record_volumes(vols: list, state: dict, now: float) -> None:
    store = state.setdefault("volumes", {})
    for v in vols:
        used = v.get("used", v["total"] - v["free"])
        prev = store.get(v["fsid"])
        entry = {"used": used, "at": now, "path": v["path"]}
        if prev and 600 <= now - prev["at"] <= 6 * 3600:
            entry["rate_gib_h"] = round((used - prev["used"]) / GIB / ((now - prev["at"]) / 3600), 2)
        elif prev and now - prev["at"] < 600:  # too soon: keep the older baseline
            entry = dict(prev, path=v["path"])
        store[v["fsid"]] = entry


def disk_roots(cfg: dict) -> list:
    home = home_of(cfg)
    exclude = set(cfg["disk"].get("exclude", []))
    roots = []
    try:
        for e in os.scandir(home):
            if e.name not in exclude and e.is_dir(follow_symlinks=False) and e.name != ".local":
                roots.append(e.path)
    except OSError:
        pass
    share = home / ".local" / "share"
    try:
        roots += [e.path for e in os.scandir(share) if e.is_dir(follow_symlinks=False)]
    except OSError:
        pass
    for extra in cfg["disk"]["extra_roots"]:
        p = expand(home, extra)
        if os.path.isdir(p) and os.access(p, os.R_OK | os.X_OK) and p not in roots:
            roots.append(p)
    return roots


def expand_split(state: dict, roots: list, max_children: int = 200) -> list:
    dirs = state.get("dirs", {})
    out = []

    def walk(path):
        d = dirs.get(path)
        if not (d and d.get("split")):
            out.append(path)
            return
        try:
            kids = sorted(e.path for e in os.scandir(path) if e.is_dir(follow_symlinks=False))
        except OSError:
            kids = []
        for k in kids[:max_children]:
            dirs.setdefault(k, {"depth": d.get("depth", 0) + 1})
            walk(k)
    for r in roots:
        walk(r)
    return out


def measure_dirs(roots: list, state: dict, runner, now: float, budget_s: float, per_dir_s: float,
                 max_depth: int = 2, max_children: int = 200) -> None:
    """Round-robin `du -skx`, least recently measured first, inside a wall-clock budget."""
    dirs = state.setdefault("dirs", {})
    deadline = time.monotonic() + budget_s
    for path in sorted(roots, key=lambda p: dirs.get(p, {}).get("tried", 0)):
        remaining = deadline - time.monotonic()
        if remaining < 1:
            break
        d = dirs.setdefault(path, {"depth": 0})
        d["tried"] = now
        try:
            rc, out = runner(["du", "-skx", path], min(per_dir_s, remaining))
        except subprocess.TimeoutExpired:
            d["timeouts"] = d.get("timeouts", 0) + 1
            try:
                kids = sum(1 for e in os.scandir(path) if e.is_dir(follow_symlinks=False))
            except OSError:
                kids = 0
            if d.get("depth", 0) < max_depth and 0 < kids <= max_children:
                d["split"] = True
            else:
                d["unmeasured"] = True
            continue
        first = (out or "").split("\t", 1)[0].strip()
        if not first.isdigit():
            if not os.path.exists(path):
                dirs.pop(path, None)
            else:
                d["errors"] = d.get("errors", 0) + 1
            continue
        kib = int(first)
        if d.get("kib") is not None and d.get("at") is not None:
            elapsed = now - d["at"]
            if elapsed >= 600:
                d["prev_kib"], d["prev_at"] = d["kib"], d["at"]
                d["rate_gib_h"] = round((kib - d["kib"]) * KIB / GIB / (elapsed / 3600), 2)
                d["kib"], d["at"] = kib, now
            else:
                d["kib"] = kib
        else:
            d["kib"], d["at"] = kib, now
        d["partial"] = rc != 0
        d.pop("unmeasured", None)


def growth_alerts(state: dict, vols: list, dcfg: dict, now: float) -> list:
    out = []
    dirs = state.get("dirs", {})
    thr = dcfg["growth_gib_h"]
    fresh = [(p, d) for p, d in dirs.items() if d.get("rate_gib_h") is not None and now - d.get("at", 0) <= 3 * 3600]
    growers = sorted((x for x in fresh if x[1]["rate_gib_h"] > 0), key=lambda x: -x[1]["rate_gib_h"])
    vol_rates = [v.get("rate_gib_h", 0) for v in state.get("volumes", {}).values() if now - v.get("at", 0) <= 3 * 3600]
    vol_max = max(vol_rates, default=0)
    if (growers and growers[0][1]["rate_gib_h"] >= thr) or vol_max >= thr:
        top = [{"path": p, "rate_gib_h": d["rate_gib_h"], "size_gib": round(d.get("kib", 0) * KIB / GIB, 1)}
               for p, d in growers[:3]]
        names = ", ".join(f"{t['path']} +{t['rate_gib_h']:.0f}G/h" for t in top) or "no measured dir explains it"
        out.append(alert("disk", "disk:growth", "high", f"disk growing >{thr}G/h: {names}",
                         {"top": top, "volume_rate_gib_h": vol_max, "threshold_gib_h": thr}))
    unmeasured = []
    for p, d in dirs.items():
        if d.get("kib") is not None or not d.get("timeouts"):
            continue
        if d.get("split"):
            kids = [k for k in dirs if os.path.dirname(k) == p]
            if kids and all(dirs[k].get("kib") is not None or dirs[k].get("split") for k in kids):
                continue
        unmeasured.append(p)
    if unmeasured:
        out.append(alert("disk", "disk:unmeasured", "warning",
                         f"{len(unmeasured)} dir(s) too slow to measure: {', '.join(sorted(unmeasured)[:3])}",
                         {"paths": sorted(unmeasured)[:10], "count": len(unmeasured)}))
    return out


def check_disk(cfg, state, runner, now):
    vols = volumes(cfg)
    record_volumes(vols, state, now)
    d = cfg["disk"]
    roots = expand_split(state, disk_roots(cfg), d["max_children"])
    measure_dirs(roots, state, runner, now, d["du_budget_s"], d["du_per_dir_s"], d["max_depth"], d["max_children"])
    return volume_alerts(vols, d) + growth_alerts(state, vols, d, now)


# ---------------------------------------------------------------- 2. systemd user units

TRANSIENT = re.compile(r"^run-[A-Za-z0-9]+\.(scope|service)$")


def _show(runner, unit):
    rc, out = runner(["systemctl", "--user", "show",
                      "--property=LoadState,ActiveState,Result,InvocationID", unit], 30)
    props = {}
    for line in (out or "").splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            props[k] = v
    return props


def check_units(cfg, state, runner, now):
    reclaim = list(cfg["units"].get("reclaim", []))
    out = []
    rc, text = runner(["systemctl", "--user", "list-units", "--failed", "--all", "--plain", "--no-legend",
                       "--no-pager"], 30)
    failed = []
    for line in (text or "").splitlines():
        parts = line.replace("●", " ").split()
        if not parts:
            continue
        unit = parts[0]
        base = unit.rsplit(".", 1)[0]
        if TRANSIENT.match(unit) or base in reclaim:
            continue
        failed.append(unit)
    if failed:
        out.append(alert("units", "units:failed", "high",
                         f"{len(failed)} failed user unit(s): {', '.join(sorted(failed)[:5])}",
                         {"units": sorted(failed)[:40], "count": len(failed)}))
    for name in reclaim:
        svc = _show(runner, f"{name}.service")
        if svc.get("LoadState") != "loaded":
            continue
        problems = []
        if svc.get("ActiveState") == "failed" or svc.get("Result") not in (None, "", "success"):
            problems.append(f"last run {svc.get('Result') or svc.get('ActiveState')}")
        tmr = _show(runner, f"{name}.timer")
        if tmr.get("LoadState") == "loaded" and tmr.get("ActiveState") != "active":
            problems.append("timer inactive")
        failed_lines = 0
        inv = svc.get("InvocationID", "")
        if re.fullmatch(r"[0-9a-f]{8,64}", inv or ""):
            rc, log = runner(["journalctl", "--user", f"_SYSTEMD_INVOCATION_ID={inv}", "-o", "cat",
                              "--no-pager", "-n", "500"], 30)
            failed_lines = sum(1 for ln in (log or "").splitlines() if re.search(r"\bfailed\b", ln, re.I))
            if failed_lines:
                problems.append(f"last run logged {failed_lines} failed item line(s)")
        if problems:
            out.append(alert("units", f"reclaim:{name}", "high", f"reclaim job {name}: {'; '.join(problems)}",
                             {"unit": name, "problems": problems, "failed_lines": failed_lines}))
    return out


# ---------------------------------------------------------------- 3. macOS crash reports

def _crash_item(path: Path):
    if path.stat().st_size > 8 * 1024 * 1024:
        return None
    with open(path, encoding="utf-8", errors="replace") as f:
        header = json.loads(f.readline() or "{}")
        body = json.loads(f.read() or "{}")
    if not isinstance(body, dict) or not ("exception" in body or "termination" in body):
        return None
    proc = str(body.get("procName") or header.get("app_name") or "?")[:64]
    exc = body.get("exception") or {}
    term = body.get("termination") or {}
    signal = str(exc.get("signal", ""))
    namespace = str(term.get("namespace", "")).upper()
    if signal == "SIGKILL" and "SANDBOX" in namespace:
        kind = "sandbox-sigkill"
    elif signal == "SIGKILL":
        kind = "sigkill"
    else:
        kind = "crash"
    return {"proc": proc, "pid": body.get("pid"), "ppid": body.get("parentPid"),
            "parent": str(body.get("parentProc", ""))[:64],
            "time": str(body.get("captureTime") or header.get("timestamp") or "")[:40], "kind": kind}


def check_crashes(cfg, state, now):
    c = cfg["crashes"]
    d = Path(expand(home_of(cfg), c["dir"]))
    cs = state.setdefault("crashes", {})
    last = cs.get("last_scan", now - 86400)
    recent = [r for r in cs.get("recent", []) if r.get("mtime", 0) >= now - c["window_h"] * 3600]
    try:
        entries = list(os.scandir(d))
    except OSError:
        entries = []
    for e in entries:
        if not e.name.endswith(".ips"):
            continue
        try:
            mtime = e.stat().st_mtime
            if mtime <= last or mtime < now - c["window_h"] * 3600:
                continue
            item = _crash_item(Path(e.path))
        except (OSError, ValueError):
            continue
        if item:
            recent.append({**item, "mtime": mtime})
    cs["last_scan"] = now
    cs["recent"] = recent[-50:]
    if not recent:
        return []
    high = any(r["kind"] == "sandbox-sigkill" or (r["kind"] == "sigkill" and "python" in r["proc"].lower())
               for r in recent)
    reports = [{k: r[k] for k in ("proc", "pid", "ppid", "parent", "time", "kind")} for r in recent[-10:]]
    kinds = sorted({r["kind"] for r in recent})
    return [alert("crashes", "crashes", "high" if high else "warning",
                  f"{len(recent)} crash report(s) in {c['window_h']}h ({', '.join(kinds)}); latest {reports[-1]['proc']}"
                  f" pid {reports[-1]['pid']}", {"reports": reports, "count": len(recent)})]


# ---------------------------------------------------------------- 4. processes

def check_processes(cfg, runner):
    p = cfg["processes"]
    out = []
    nw = expand(home_of(cfg), p.get("netwatch") or "")
    if nw and os.path.exists(nw):
        rc, text = runner([nw, "orphans", "--json"], 60)
        orphans = (json.loads(text or "{}") or {}).get("orphans") or []
        items = [{"pid": o.get("pid"), "name": str(o.get("name", ""))[:40], "age_s": o.get("age_s"),
                  "rss_mb": o.get("rss_mb"), "cpu": o.get("cpu")} for o in orphans]
        if len(items) >= p["orphan_warn"]:
            out.append(alert("processes", "procs:orphans", "warning", f"{len(items)} orphaned dev processes",
                             {"count": len(items), "orphans": items[:15]}))
        runaway = [i for i in items if (i["rss_mb"] or 0) >= p["runaway_rss_mb"] or (i["cpu"] or 0) >= p["runaway_cpu"]]
        if runaway:
            out.append(alert("processes", "procs:runaway", "high",
                             f"{len(runaway)} runaway orphan(s): " + ", ".join(f"{r['name']} {r['pid']}" for r in runaway[:3]),
                             {"orphans": runaway[:10]}))
    rc, text = runner(["ps", "-A", "-o", "pid=,ppid=,comm="], 30)
    chrome = shells = 0
    for line in (text or "").splitlines():
        parts = line.strip().split(None, 2)
        if len(parts) < 3:
            continue
        name = parts[2].rsplit("/", 1)[-1]
        if "chrome" in name.lower():
            chrome += 1
        if name.lstrip("-") in ("zsh", "bash", "sh", "fish", "dash"):
            shells += 1
    if chrome > p["chrome_max"]:
        out.append(alert("processes", "procs:chrome-helpers", "warning", f"{chrome} Chrome processes (max {p['chrome_max']})",
                         {"count": chrome, "max": p["chrome_max"]}))
    if shells > p["shell_max"]:
        out.append(alert("processes", "procs:shells", "warning", f"{shells} shells (max {p['shell_max']})",
                         {"count": shells, "max": p["shell_max"]}))
    return out


# ---------------------------------------------------------------- 5. delivery checkouts

def check_delivery(cfg, runner):
    out = []
    env = dict(os.environ, GIT_OPTIONAL_LOCKS="0", LC_ALL="C")
    for path in cfg.get("delivery", []):
        path = expand(home_of(cfg), path)
        key = f"delivery:{path}"
        if not os.path.isdir(path):
            out.append(alert("delivery", key, "high", f"delivery checkout missing: {path}", {"path": path}))
            continue
        rc, text = runner(["git", "-C", path, "status", "--porcelain=v1", "--branch", "--untracked-files=normal"],
                          60, env=env)
        lines = (text or "").splitlines()
        if rc != 0 or not lines or not lines[0].startswith("## "):
            out.append(alert("delivery", key, "high", f"git status failed in {path}", {"path": path, "rc": rc}))
            continue
        head = lines[0][3:]
        branch = head.split("...", 1)[0].split(" ", 1)[0]
        if head.startswith("No commits yet on "):
            branch = head[len("No commits yet on "):].split("...")[0]
        dirty = len(lines) - 1
        if branch != "main" or dirty:
            out.append(alert("delivery", key, "high", f"delivery checkout {path} on {branch}, {dirty} dirty path(s)",
                             {"path": path, "branch": branch, "dirty": dirty}))
    return out


# ---------------------------------------------------------------- 6. drift

def managed_block(text: str):
    lines = text.splitlines(keepends=True)
    starts = [i for i, ln in enumerate(lines) if ln.rstrip("\r\n") == MARK_START]
    ends = [i for i, ln in enumerate(lines) if ln.rstrip("\r\n").startswith(MARK_END)]
    if len(starts) != 1 or len(ends) != 1 or starts[0] >= ends[0]:
        return None
    return "".join(lines[starts[0] + 1:ends[0]])


def git_blob_sha(data: bytes) -> str:
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()


def check_drift(cfg, runner):
    d = cfg["drift"]
    home = home_of(cfg)
    repo = expand(home, d.get("repo") or "")
    if not repo or not os.path.isdir(repo):
        return []
    claude = Path(expand(home, d["claude_dir"]))
    ref = d.get("ref", "origin/main")
    env = dict(os.environ, GIT_OPTIONAL_LOCKS="0")
    out = []
    rc, harness = runner(["git", "-C", repo, "show", f"{ref}:HARNESS.md"], 30, env=env)
    if rc != 0:
        raise RuntimeError("git show HARNESS.md failed")
    cm = claude / "CLAUDE.md"
    if cm.is_file():
        block = managed_block(cm.read_text(errors="replace"))
        if block is None:
            out.append(alert("drift", "drift:claude-md", "warning", "CLAUDE.md has no single Agent Harness managed block",
                             {"path": str(cm)}))
        elif block.strip() != harness.strip():
            out.append(alert("drift", "drift:claude-md", "warning",
                             f"CLAUDE.md managed block differs from HARNESS.md at {ref}",
                             {"path": str(cm), "installed_sha256": hashlib.sha256(block.strip().encode()).hexdigest()[:16],
                              "main_sha256": hashlib.sha256(harness.strip().encode()).hexdigest()[:16]}))
    rc, tree = runner(["git", "-C", repo, "ls-tree", ref, "harness/hooks/"], 30, env=env)
    if rc != 0:
        raise RuntimeError("git ls-tree failed")
    differ, missing = [], []
    for line in (tree or "").splitlines():
        meta, _, rel = line.partition("\t")
        parts = meta.split()
        if len(parts) != 3 or parts[1] != "blob":
            continue
        name = rel.rsplit("/", 1)[-1]
        installed = claude / "hooks" / name
        if not installed.is_file():
            if name.endswith(".py"):
                missing.append(name)
            continue
        if git_blob_sha(installed.read_bytes()) != parts[2]:
            differ.append(name)
    if differ or missing:
        out.append(alert("drift", "drift:hooks", "warning",
                         f"installed hooks differ from {ref}: {len(differ)} changed, {len(missing)} missing",
                         {"differ": sorted(differ), "missing": sorted(missing), "ref": ref}))
    return out


# ---------------------------------------------------------------- 7. Codex hook trust

def snake(event: str) -> str:
    return re.sub(r"(?<!^)([A-Z])", r"_\1", event).lower()


def codex_hook_hash(label: str, matcher, handler: dict) -> str:
    """sha256 of the canonical (sorted-key, compact) JSON of {event_name, [matcher], hooks:[handler]}, with
    handler.async defaulting to false. This mirrors codex-rs hook discovery as documented by the sidekick crate's
    codex_trust.rs and is verified against a live trusted entry (tests: test_hash_matches_live_verified_algorithm)."""
    h = dict(handler)
    h.setdefault("async", False)
    ident = {"event_name": label, "hooks": [h]}
    if matcher is not None:
        ident["matcher"] = matcher
    blob = json.dumps(ident, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return "sha256:" + hashlib.sha256(blob.encode()).hexdigest()


def codex_expected_trust(hooks_path: Path) -> dict:
    data = json.loads(Path(hooks_path).read_text())
    out = {}
    for event, groups in (data.get("hooks") or {}).items():
        label = snake(event)
        for gi, group in enumerate(groups or []):
            for hi, handler in enumerate(group.get("hooks") or []):
                out[f"{hooks_path}:{label}:{gi}:{hi}"] = codex_hook_hash(label, group.get("matcher"), handler)
    return out


TRUST_RE = re.compile(r'^\[hooks\.state\."([^"]+)"\][ \t]*\r?\n(?:[ \t]*\r?\n)*[ \t]*trusted_hash[ \t]*=[ \t]*"([^"]+)"',
                      re.M)


def check_codex_trust(cfg):
    codex = Path(expand(home_of(cfg), cfg["codex_dir"]))
    hooks = codex / "hooks.json"
    conf = codex / "config.toml"
    if not hooks.is_file():
        return []
    expected = codex_expected_trust(hooks)
    trusted = dict(TRUST_RE.findall(conf.read_text(errors="replace"))) if conf.is_file() else {}
    prefix = f"{hooks}:"
    untrusted = sorted(k[len(prefix):] for k in expected if k not in trusted)
    changed = sorted(k[len(prefix):] for k, v in expected.items() if k in trusted and trusted[k] != v)
    if not untrusted and not changed:
        return []
    n = len(untrusted) + len(changed)
    return [alert("codex", "codex:trust", "high",
                  f"Codex is skipping harness hooks: {n} hook(s) untrusted or changed since trust "
                  f"({', '.join((untrusted + changed)[:4])}); review with /hooks in Codex",
                  {"untrusted": untrusted, "changed": changed, "hooks_json": str(hooks)})]


# ---------------------------------------------------------------- peers

def active_json_path(home: Path) -> Path:
    return home / ".agent-harness" / "state" / "ops-watch" / "active.json"


def check_peers(cfg, state, runner, now):
    out = []
    peers = state.setdefault("peers", {})
    for host in cfg.get("peers", []):
        p = peers.setdefault(host, {"first_try": now})
        try:
            rc, text = runner(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", host,
                               "cat .agent-harness/state/ops-watch/active.json"], 30)
            doc = json.loads(text) if rc == 0 else None
        except (subprocess.TimeoutExpired, ValueError, OSError):
            doc = None
        if isinstance(doc, dict):
            p.update(ok_at=now, active=doc.get("active", [])[:20], last_run=doc.get("last_run", 0))
            if now - float(doc.get("last_run") or 0) > 1800:
                out.append(alert("peers", f"peer:{host}:stale", "warning", f"ops-watch on {host} has not run for 30+ min",
                                 {"host": host}))
        elif now - p.get("ok_at", p["first_try"]) > 1800:
            out.append(alert("peers", f"peer:{host}:unreachable", "warning", f"cannot read ops-watch alerts from {host}",
                             {"host": host}))
    return out


# ---------------------------------------------------------------- run

DEFAULT_CHECKS = {
    "disk": check_disk,
    "units": lambda c, s, r, n: check_units(c, s, r, n) if c["units"].get("enabled") and shutil.which("systemctl") else [],
    "crashes": lambda c, s, r, n: check_crashes(c, s, n) if c["crashes"].get("enabled") else [],
    "processes": lambda c, s, r, n: check_processes(c, r),
    "delivery": lambda c, s, r, n: check_delivery(c, r),
    "drift": lambda c, s, r, n: check_drift(c, r),
    "codex": lambda c, s, r, n: check_codex_trust(c),
    "peers": check_peers,
}


def subject_of(e: dict) -> str:
    raw = f"[ops-watch] {e['host']} {e['severity']} {e['key']}: {e['message']}"
    return re.sub(r"[^A-Za-z0-9 ._:/%+()\[\]-]", "_", raw)[:180]


def comment_body(events: list) -> str:
    lines = [f"ops-watch: {len(events)} alert transition(s) (paths and counts only)."]
    for e in events:
        detail = json.dumps(e.get("detail", {}), separators=(",", ":"), sort_keys=True)
        lines.append(f"- {e['event'].upper()} [{e['severity']}] {e['host']} `{e['key']}`: {e['message']}"
                     f" (seq {e.get('seq', '?')}, {e.get('at', '')})")
        if detail not in ("{}", ""):
            lines.append(f"  detail: `{detail[:600]}`")
    return "\n".join(lines)[:8000]


def send_comment(cfg, runner, events) -> bool:
    c = cfg["sinks"].get("comment") or {}
    mode = c.get("mode", "none")
    if mode == "none":
        return True
    body = comment_body(events)
    try:
        if mode == "gq":
            op = str(uuid.uuid5(uuid.NAMESPACE_URL, f"ops-watch:{cfg['host']}:" +
                                ",".join(f"{e.get('key')}@{e.get('at')}" for e in events)))
            args = {"issueId": c.get("issue_id", ALERTS_ISSUE_ID), "body": body, "operationId": op}
            rc, out = runner(["python3", "-I", expand(home_of(cfg), c.get("gq", "~/.claude/goodqa-p0p1/gq.py")),
                              "comment_on_issue", json.dumps(args), "400"], 90)
            if rc != 0:
                return False
            try:
                parsed = json.loads(out)
                return not (isinstance(parsed, dict) and "error" in parsed)
            except ValueError:
                return "error" not in (out or "").lower()[:40]
        rc, _ = runner([expand(home_of(cfg), a) for a in c["argv"]], 90, stdin=body)
        return rc == 0
    except (subprocess.TimeoutExpired, OSError):
        return False


def send_deadman(cfg, runner, e) -> bool:
    subject = subject_of(e)
    body = f"{subject}\n\n{json.dumps(e.get('detail', {}), sort_keys=True)[:2000]}\n"
    for cmd in cfg["sinks"].get("deadman") or []:
        try:
            rc, _ = runner([expand(home_of(cfg), a).replace("{SUBJECT}", subject) for a in cmd], 90, stdin=body)
        except (subprocess.TimeoutExpired, OSError):
            continue
        if rc == 0:
            return True
    return False


def compact(e: dict) -> dict:
    return {k: e.get(k) for k in ("host", "event", "severity", "key", "message", "detail", "seq", "at")}


def run_once(cfg: dict, home: Path, runner=run, checks: dict | None = None, now: float | None = None) -> int:
    now = time.time() if now is None else now
    host = cfg["host"]
    state = load_state(home)
    active = state.setdefault("active", {})
    rc = 0
    current, ok = {}, set()
    for name, fn in (checks if checks is not None else DEFAULT_CHECKS).items():
        try:
            for a in fn(cfg, state, runner, now) or []:
                a = dict(a, check=a.get("check") or name)
                current[a["key"]] = a
            ok.add(name)
        except Exception as exc:  # noqa: BLE001 - surfaced as an alert, never silent
            current[f"ops-watch:check-error:{name}"] = alert(
                name, f"ops-watch:check-error:{name}", "warning", f"ops-watch {name} check failed ({type(exc).__name__})")
            print(f"ops-watch: {name} check failed: {type(exc).__name__}", file=sys.stderr)
    events = []
    for key, a in sorted(current.items()):
        prev = active.get(key)
        if prev is None or SEVERITIES[a["severity"]] > SEVERITIES.get(prev.get("severity"), 0):
            events.append({"host": host, "source": SOURCE, "event": "raise", "severity": a["severity"], "key": key,
                           "message": a["message"], "detail": a["detail"], "check": a["check"]})
        active[key] = {"severity": a["severity"], "message": a["message"], "detail": a["detail"], "check": a["check"],
                       "since": (prev or {}).get("since", now)}
    for key in sorted(set(active) - set(current)):
        prev = active[key]
        if prev.get("check") in ok:  # a check that errored this run keeps its alerts
            events.append({"host": host, "source": SOURCE, "event": "clear", "severity": prev.get("severity", "info"),
                           "key": key, "message": f"cleared: {prev.get('message', '')}", "detail": {},
                           "check": prev.get("check")})
            del active[key]
    ring = ring_path(home)
    ring_ok = True
    for e in events:
        e["at"] = now_iso(now)
        try:
            e["seq"] = emit(e, path=ring)
        except (OSError, ValueError) as exc:
            ring_ok, rc = False, 2
            print(f"ops-watch: alert ring write failed ({type(exc).__name__}): {e['key']}", file=sys.stderr)
    if ring_ok:  # reassert our active alerts whose raise the ring has overwritten; clear a past crash
        latest = latest_by_key(read_ring(ring))
        crash = latest.get((host, SOURCE, "ops-watch:internal-error"))
        if crash and crash.get("event") == "raise":
            try:
                events.append({"host": host, "source": SOURCE, "event": "clear", "severity": "high",
                               "key": "ops-watch:internal-error", "message": "cleared: ops-watch runs again",
                               "detail": {}, "at": now_iso(now)})
                events[-1]["seq"] = emit(events[-1], path=ring)
            except (OSError, ValueError):
                rc = 2
        for key, a in sorted(active.items()):
            if latest.get((host, SOURCE, key), {}).get("event") != "raise":
                try:
                    emit({"host": host, "source": SOURCE, "event": "raise", "severity": a["severity"], "key": key,
                          "message": a["message"], "detail": {**(a.get("detail") or {}), "reasserted": True},
                          "check": a.get("check")}, path=ring)
                except (OSError, ValueError):
                    rc = 2
    pending = (state.get("pending_comment") or []) + [compact(e) for e in events]
    pending = pending[-200:]
    if pending:
        if send_comment(cfg, runner, pending):
            pending = []
        else:
            rc = 2
            print(f"ops-watch: GoodQA comment failed; {len(pending)} transition(s) queued", file=sys.stderr)
    state["pending_comment"] = pending
    dead = (state.get("pending_deadman") or []) + [compact(e) for e in events
                                                   if e["event"] == "raise" and e["severity"] == "critical"]
    still = []
    for e in dead[-50:]:
        if not send_deadman(cfg, runner, e):
            still.append(e)
    if still:
        rc = 2
        print(f"ops-watch: deadman alert failed; {len(still)} critical alert(s) queued", file=sys.stderr)
    state["pending_deadman"] = still
    state["last_run"] = now
    try:
        save_state(home, state)
    except (OSError, ValueError) as exc:
        rc = 2
        print(f"ops-watch: state write failed ({type(exc).__name__})", file=sys.stderr)
    try:  # best effort: peers read this small file over ssh; the ring stays authoritative
        aj = active_json_path(home)
        tmp = aj.with_suffix(".json.tmp")
        tmp.write_text(json.dumps({"schema": SCHEMA, "host": host, "last_run": now,
                                   "active": [compact(e) for e in active_alerts(home)][:50]}))
        os.replace(tmp, aj)
    except OSError:
        pass
    if rc == 0:
        try:
            hb = home / ".agent-harness" / "logs" / "ops-watch.last-ok"
            hb.parent.mkdir(parents=True, exist_ok=True)
            if not hb.exists():
                hb.touch(mode=0o600)
            os.utime(hb, None)
        except OSError:
            rc = 2
            print("ops-watch: heartbeat write failed", file=sys.stderr)
    print(f"ops-watch {host}: {len(active)} active, {len(events)} transition(s), rc={rc}")
    return rc


def injection_text(home: Path | None = None, max_chars: int = 700) -> str:
    """Context line for wal.py. Never raises; "" when nothing is active."""
    try:
        home = home or Path.home()
        items = [(e.get("severity"), e.get("host"), e.get("key"), e.get("message")) for e in active_alerts(home)]
        state = load_state(home)
        for host, peer in (state.get("peers") or {}).items():
            if time.time() - float(peer.get("ok_at") or 0) < 3600:
                items += [(e.get("severity"), e.get("host") or host, e.get("key"), e.get("message"))
                          for e in peer.get("active") or [] if isinstance(e, dict)]
        last = float(state.get("last_run") or 0)
        stale = last and time.time() - last > 1800
        if not items and not stale:
            return ""
        items.sort(key=lambda x: -SEVERITIES.get(x[0], 0))
        text = (f" OPS ALERTS ({len(items)} active; ops-watch, details: python3 ~/.claude/hooks/ops_watch.py status;"
                " report them, never reclaim or kill to clear them): ")
        text += "; ".join(f"[{s}] {h} {k}: {str(m)[:110]}" for s, h, k, m in items)
        if stale:
            text += f" ops-watch last ran {int((time.time() - last) / 60)} min ago (stale)."
        return text if len(text) <= max_chars else text[:max_chars - 3] + "..."
    except Exception:  # noqa: BLE001 - the prompt hook blocks on failure; silence beats a blocked prompt
        return ""


# ---------------------------------------------------------------- install

LABEL = "com.ericmacdougall.ops-watch"


def unit_files(home: Path, script: Path) -> dict:
    logs = home / ".agent-harness" / "logs"
    if sys.platform == "darwin":
        plist = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>{LABEL}</string>
<key>ProgramArguments</key><array><string>/usr/bin/python3</string><string>{script}</string><string>run</string></array>
<key>StartInterval</key><integer>600</integer>
<key>RunAtLoad</key><true/>
<key>Nice</key><integer>19</integer>
<key>LowPriorityIO</key><true/>
<key>ProcessType</key><string>Background</string>
<key>StandardOutPath</key><string>{logs}/ops-watch.out</string>
<key>StandardErrorPath</key><string>{logs}/ops-watch.err</string>
</dict></plist>
"""
        return {home / "Library" / "LaunchAgents" / f"{LABEL}.plist": plist}
    unit = home / ".config" / "systemd" / "user"
    return {
        unit / "ops-watch.service": f"""[Unit]
Description=ops-watch: read-only ops problem watcher; alerts to ~/.agent-harness/state/alerts.jsonl (GoodQA goodqa#14591)
[Service]
Type=oneshot
ExecStart=/usr/bin/python3 {script} run
Nice=19
IOSchedulingClass=idle
CPUSchedulingPolicy=batch
TimeoutStartSec=540
""",
        unit / "ops-watch.timer": """[Unit]
Description=Run ops-watch every 10 minutes
[Timer]
OnBootSec=3min
OnUnitActiveSec=10min
[Install]
WantedBy=timers.target
""",
    }


def install(home: Path, apply: bool) -> int:
    script = Path(__file__).resolve()
    files = unit_files(home, script)
    for path, text in files.items():
        print(f"{'write' if apply else 'would write'} {path}")
        if apply:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
    (home / ".agent-harness" / "logs").mkdir(parents=True, exist_ok=True)
    if sys.platform == "darwin":
        dom = f"gui/{os.getuid()}"
        plist = str(next(iter(files)))
        cmds = [["launchctl", "bootout", f"{dom}/{LABEL}"], ["launchctl", "bootstrap", dom, plist]]
    else:
        cmds = [["systemctl", "--user", "daemon-reload"], ["systemctl", "--user", "enable", "--now", "ops-watch.timer"]]
    for cmd in cmds:
        print(("run " if apply else "would run ") + " ".join(cmd))
        if apply:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            if r.returncode and "bootout" not in cmd:
                print(f"failed ({r.returncode}): {r.stderr.strip()[:300]}", file=sys.stderr)
                return 2
    return 0


def lower_priority() -> None:
    try:
        os.nice(max(0, 19 - os.nice(0)))
    except OSError:
        pass
    if sys.platform.startswith("linux") and shutil.which("ionice"):
        subprocess.run(["ionice", "-c3", "-p", str(os.getpid())], capture_output=True, timeout=10)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd")
    sub.add_parser("run")
    sub.add_parser("status")
    a = sub.add_parser("active")
    a.add_argument("--json", action="store_true")
    e = sub.add_parser("emit")
    e.add_argument("--json", required=True)
    i = sub.add_parser("install")
    i.add_argument("--apply", action="store_true")
    sub.add_parser("config")
    args = ap.parse_args(argv)
    home = Path.home()
    cmd = args.cmd or "run"
    try:
        if cmd == "emit":
            print(emit(json.loads(args.json), home=home))
            return 0
        if cmd == "install":
            return install(home, args.apply)
        cfg = load_config(home)
        if cmd == "config":
            print(json.dumps({k: v for k, v in cfg.items() if k != "_home"}, indent=1))
            return 0
        if cmd in ("active", "status"):
            act = [compact(x) for x in active_alerts(home)]
            if cmd == "active":
                print(json.dumps(act) if args.json else "\n".join(f"{x['severity']} {x['key']}" for x in act))
                return 0
            st = load_state(home)
            print(f"ops-watch {cfg['host']}: last run {now_iso(st['last_run']) if st.get('last_run') else 'never'}; "
                  f"{len(st.get('pending_comment') or [])} comment(s) and {len(st.get('pending_deadman') or [])} "
                  f"deadman alert(s) queued")
            for x in act:
                print(f"  [{x['severity']}] {x['host']} {x['key']}: {x['message']}")
            for h, p in (st.get("peers") or {}).items():
                for x in p.get("active") or []:
                    print(f"  [{x.get('severity')}] {h} {x.get('key')}: {x.get('message')} (peer)")
            return 0
        lower_priority()
        return run_once(cfg, home)
    except Exception as exc:  # noqa: BLE001 - never fail silently
        print(f"ops-watch: internal error {type(exc).__name__}", file=sys.stderr)
        try:
            emit({"host": default_host(), "source": SOURCE, "event": "raise", "severity": "high",
                  "key": "ops-watch:internal-error", "message": f"ops-watch crashed ({type(exc).__name__})"}, home=home)
        except Exception:  # noqa: BLE001
            pass
        return 2


if __name__ == "__main__":
    sys.exit(main())
