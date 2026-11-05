#!/usr/bin/env python3
"""Standing log-backup freshness alert (rules S06/S07, GoodQA rules-deterministic batch B3).

log_backup.py owns the markers and the limits (classify, bulk_classify). This is a thin periodic caller: it never
redefines a marker name or an age limit. It exists because the SessionStart alert only fires when a session
starts; nobody is told when a running host's backup silently goes stale.

  run      classify both tiers; write one JSON line to ~/.agent-harness/logs/backup-alert.jsonl when the verdict
           changes or the same bad verdict is 60 min old; exit 0 fresh, 1 transcripts stale, 2 transcripts
           missing/invalid, 3 bulk tier bad (same codes as `log_backup.py check`), 4 log_backup.py unavailable.
  status   one line: last verdict, when it was written, whether the scheduler unit is installed.
  install  write the launchd or systemd unit (dry run unless --apply). Never reloads while a backup holds the lock.

The alert never pauses or stops any work; a non-zero exit makes the scheduled unit show as failed.
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
REPEAT_SECONDS = 3600
ALERT_LOG = "backup-alert.jsonl"
STATE = "backup-alert.state"
LABEL = "com.ericmacdougall.backup-watch"
UNIT = "backup-watch"


def _lb():
    try:
        import log_backup
        return log_backup
    except Exception:  # noqa: BLE001 - reported as exit 4, never silently treated as fresh
        return None


def verdict(home: Path, now: float | None = None) -> dict:
    lb = _lb()
    if lb is None:
        return {"code": 4, "transcripts": "unavailable", "bulk": "unavailable"}
    t = lb.classify(home, now=now)
    b = lb.bulk_classify(home, now=now)
    if t["state"] != "fresh":
        code = 1 if t["state"] == "stale" else 2
    elif b["state"] in ("stale", "missing", "invalid"):
        code = 3
    else:
        code = 0
    return {"code": code, "transcripts": t["state"], "transcripts_age": t.get("age"), "bulk": b["state"],
            "bulk_age": b.get("age")}


def _read_state(path: Path) -> dict:
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return {}


def run(home: Path, now: float | None = None) -> int:
    now = time.time() if now is None else now
    v = verdict(home, now)
    logs = home / ".agent-harness" / "logs"
    logs.mkdir(parents=True, exist_ok=True)
    prev = _read_state(logs / STATE)
    changed = prev.get("code") != v["code"]
    due = v["code"] != 0 and now - prev.get("at", 0) >= REPEAT_SECONDS
    if changed or due:
        line = {"at": now, "event": "recovered" if v["code"] == 0 else "alert", **v}
        with open(logs / ALERT_LOG, "a") as fh:
            fh.write(json.dumps(line) + "\n")
        (logs / STATE).write_text(json.dumps({"code": v["code"], "at": now}))
        if v["code"] != 0:
            print(f"BACKUP ALERT code={v['code']} transcripts={v['transcripts']} bulk={v['bulk']}", file=sys.stderr)
    return v["code"]


def unit_files(home: Path, system: str) -> list[tuple[Path, str]]:
    script = HERE / "backup_watch.py"
    if system == "Darwin":
        plist = (f'<?xml version="1.0" encoding="UTF-8"?>\n<plist version="1.0"><dict>\n'
                 f"<key>Label</key><string>{LABEL}</string>\n<key>ProgramArguments</key><array>"
                 f"<string>/usr/bin/python3</string><string>{script}</string><string>run</string></array>\n"
                 f"<key>StartInterval</key><integer>600</integer>\n<key>RunAtLoad</key><true/>\n</dict></plist>\n")
        return [(home / "Library" / "LaunchAgents" / f"{LABEL}.plist", plist)]
    d = home / ".config" / "systemd" / "user"
    service = f"[Unit]\nDescription=Agent log backup freshness alert\n[Service]\nType=oneshot\nExecStart=/usr/bin/python3 {script} run\n"
    timer = f"[Unit]\nDescription=Backup freshness alert every 10 min\n[Timer]\nOnBootSec=3min\nOnUnitActiveSec=10min\n[Install]\nWantedBy=timers.target\n"
    return [(d / f"{UNIT}.service", service), (d / f"{UNIT}.timer", timer)]


def status(home: Path, system: str | None = None) -> str:
    system = system or platform.system()
    st = _read_state(home / ".agent-harness" / "logs" / STATE)
    installed = all(p.exists() for p, _ in unit_files(home, system))
    last = f"code={st['code']} at={int(st['at'])}" if st else "never ran"
    return f"backup-watch: {last}; scheduler {'installed' if installed else 'NOT INSTALLED'}"


def install(home: Path, apply: bool, system: str | None = None) -> list[str]:
    system = system or platform.system()
    out = []
    for path, text in unit_files(home, system):
        if path.is_symlink() or path.parent.is_symlink():
            out.append(f"refused symlink {path}")
            continue
        same = path.exists() and path.read_text() == text
        out.append(f"{'unchanged' if same else ('wrote' if apply else 'would write')} {path}")
        if apply and not same:
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.with_suffix(path.suffix + ".tmp")
            tmp.write_text(text)
            os.replace(tmp, path)
    return out


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("cmd", choices=["run", "status", "install"])
    ap.add_argument("--home", type=Path, default=Path.home())
    ap.add_argument("--apply", action="store_true")
    a = ap.parse_args(argv)
    if a.cmd == "run":
        return run(a.home)
    if a.cmd == "status":
        print(status(a.home))
        return 0
    print("\n".join(install(a.home, a.apply)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
