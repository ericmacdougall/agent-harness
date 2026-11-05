#!/usr/bin/env python3
"""Standing log-backup freshness alert (rules S06/S07, GoodQA rules-deterministic batch B3).

log_backup.py owns the markers and the limits (classify, bulk_classify). This is a thin periodic caller: it never
redefines a marker name or an age limit. It exists because the SessionStart alert only fires when a session
starts; nobody is told when a running host's backup silently goes stale.

  run      classify both tiers; write one JSON line to ~/.agent-harness/logs/backup-alert.jsonl when the verdict
           changes or the same bad verdict is 60 min old; exit 0 fresh, 1 transcripts stale, 2 transcripts
           missing/invalid, 3 bulk tier bad (same codes as `log_backup.py check`), 4 log_backup.py unavailable,
           5 internal error (state write failed, symlink refused).
  status   one line: last verdict, when it was written, whether the scheduler unit is installed.
  install  write the launchd or systemd unit targeting ~/.claude/hooks/backup_watch.py and activate it (dry run unless
           --apply). Alerts go to stderr (launchd: backup-watch.err), to backup-alert.jsonl, and a non-zero exit shows
           the systemd unit as failed, where the dead-man picks it up. `log_backup.py session-start` is the second,
           independent reader of the same markers.

The alert never pauses or stops any work; a non-zero exit makes the scheduled unit show as failed.
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import subprocess
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
    elif b["state"] not in ("fresh", "pending"):
        code = 3
    else:
        code = 0
    return {"code": code, "transcripts": t["state"], "transcripts_age": t.get("age"), "bulk": b["state"],
            "bulk_age": b.get("age")}


def _read_state(path: Path, now: float | None = None) -> dict:
    """Previous verdict, or {} when the file is missing, corrupt, the wrong shape or dated in the future."""
    try:
        d = json.loads(path.read_text())
    except (OSError, ValueError):
        return {}
    now = time.time() if now is None else now
    if (not isinstance(d, dict) or not isinstance(d.get("code"), int) or isinstance(d.get("code"), bool)
            or not isinstance(d.get("at"), (int, float)) or isinstance(d.get("at"), bool)
            or not (0 <= d["at"] <= now + 300)):
        return {}
    return d


def _write_private(path: Path, text: str, append: bool = False) -> None:
    """Create-or-replace without following a symlink; state replaces atomically, the log appends."""
    if path.is_symlink():
        raise OSError(f"refusing symlink {path}")
    if append:
        fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "a") as fh:
            fh.write(text)
        return
    tmp = path.with_name(f"{path.name}.tmp.{os.getpid()}")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(text)
    os.replace(tmp, path)


def notify(text: str) -> None:
    """Visible desktop notice on macOS (the second reader besides the session-start check). Never raises."""
    if platform.system() != "Darwin":
        return
    try:
        subprocess.run(["osascript", "-e", f'display notification "{text.replace(chr(92), "").replace(chr(34), "")}" with title "Log backup alert"'],
                       capture_output=True, timeout=10)
    except (OSError, subprocess.TimeoutExpired):
        pass


def run(home: Path, now: float | None = None) -> int:
    now = time.time() if now is None else now
    v = verdict(home, now)
    logs = home / ".agent-harness" / "logs"
    logs.mkdir(parents=True, exist_ok=True)
    prev = _read_state(logs / STATE, now)
    changed = prev.get("code") != v["code"]
    due = v["code"] != 0 and now - prev.get("at", 0) >= REPEAT_SECONDS
    if changed or due:
        line = {"at": now, "event": "recovered" if v["code"] == 0 else "alert", **v}
        _write_private(logs / ALERT_LOG, json.dumps(line) + "\n", append=True)
        _write_private(logs / STATE, json.dumps({"code": v["code"], "at": now}))
        if v["code"] != 0:
            msg = f"BACKUP ALERT code={v['code']} transcripts={v['transcripts']} bulk={v['bulk']}"
            print(msg, file=sys.stderr)
            notify(msg)
    return v["code"]


def installed_script(home: Path) -> Path:
    """The unit targets the installed copy, never the checkout it was run from (a worktree can disappear)."""
    return home / ".claude" / "hooks" / "backup_watch.py"


def unit_files(home: Path, system: str) -> list[tuple[Path, str]]:
    from xml.sax.saxutils import escape
    script = installed_script(home)
    err = home / ".agent-harness" / "logs" / "backup-watch.err"
    if system == "Darwin":
        plist = (f'<?xml version="1.0" encoding="UTF-8"?>\n<plist version="1.0"><dict>\n'
                 f"<key>Label</key><string>{LABEL}</string>\n<key>ProgramArguments</key><array>"
                 f"<string>/usr/bin/python3</string><string>{escape(str(script))}</string><string>run</string></array>\n"
                 f"<key>StartInterval</key><integer>600</integer>\n<key>RunAtLoad</key><true/>\n"
                 f"<key>StandardErrorPath</key><string>{escape(str(err))}</string>\n</dict></plist>\n")
        return [(home / "Library" / "LaunchAgents" / f"{LABEL}.plist", plist)]
    d = home / ".config" / "systemd" / "user"
    q = '"' + str(script).replace("\\", "\\\\").replace('"', '\\"').replace("%", "%%").replace("$", "$$") + '"'
    service = (f"[Unit]\nDescription=Agent log backup freshness alert\n[Service]\nType=oneshot\n"
               f"ExecStart=/usr/bin/python3 {q} run\n")
    timer = ("[Unit]\nDescription=Backup freshness alert every 10 min\n[Timer]\nOnBootSec=3min\n"
             "OnUnitActiveSec=10min\n[Install]\nWantedBy=timers.target\n")
    return [(d / f"{UNIT}.service", service), (d / f"{UNIT}.timer", timer)]


def default_runner(argv: list[str], capture: str | None = None):
    """Exit code, or with capture=<anything> the stripped stdout (used only for loginctl --value)."""
    try:
        r = subprocess.run(argv, capture_output=True, text=True, errors="replace", timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return "" if capture else 127
    return r.stdout.strip() if capture else r.returncode


def active(home: Path, system: str, run=default_runner, uid: int | None = None) -> bool:
    """True only when the scheduler itself reports the job loaded/enabled, not merely when files exist."""
    if system == "Darwin":
        return run(["launchctl", "print", f"gui/{os.getuid() if uid is None else uid}/{LABEL}"]) == 0
    return (run(["systemctl", "--user", "is-enabled", f"{UNIT}.timer"]) == 0
            and run(["systemctl", "--user", "is-active", f"{UNIT}.timer"]) == 0)


def linger(run=default_runner) -> bool:
    """Linux user timers stop at logout unless lingering is on (dev2 is headless)."""
    user = os.environ.get("USER", "")
    return bool(user) and run(["loginctl", "show-user", user, "-p", "Linger", "--value"], capture="yes") == "yes"


def status(home: Path, system: str | None = None, run=default_runner) -> str:
    system = system or platform.system()
    st = _read_state(home / ".agent-harness" / "logs" / STATE)
    files = all(p.exists() for p, _ in unit_files(home, system))
    if not files:
        sched = "NOT INSTALLED (unit files missing)"
    elif not active(home, system, run):
        sched = "NOT ACTIVE (unit files exist but the scheduler does not report the job)"
    else:
        sched = "installed and active"
    last = f"code={st['code']} at={int(st['at'])}" if st else "never ran"
    return f"backup-watch: {last}; scheduler {sched}"


def install(home: Path, apply: bool, system: str | None = None, run=default_runner) -> tuple[list[str], int]:
    """Lines to print and an exit code: 0 ok, 3 script not installed, 4 a scheduler command failed, 5 refused."""
    system = system or platform.system()
    out, changed, rc = [], False, 0
    if apply and not installed_script(home).is_file():
        return [f"refused: {installed_script(home)} is not installed (run the harness installer first)"], 3
    for path, text in unit_files(home, system):
        if path.is_symlink() or path.parent.is_symlink():
            return out + [f"refused symlink {path}"], 5
        same = path.exists() and path.read_text() == text
        out.append(f"{'unchanged' if same else ('wrote' if apply else 'would write')} {path}")
        if apply and not same:
            path.parent.mkdir(parents=True, exist_ok=True)
            _write_private(path, text)
            changed = True
    if apply:
        (home / ".agent-harness" / "logs").mkdir(parents=True, exist_ok=True)
    if apply and (changed or not active(home, system, run)):
        if system == "Darwin":
            domain = f"gui/{os.getuid()}"
            run(["launchctl", "bootout", f"{domain}/{LABEL}"])  # not loaded is fine; loaded-with-old-plist must go
            plist = str(unit_files(home, system)[0][0])
            code = run(["launchctl", "bootstrap", domain, plist])
            if code:  # bootout can still be unloading; one short retry
                time.sleep(2)
                code = run(["launchctl", "bootstrap", domain, plist])
            out.append(f"launchctl bootstrap rc={code}")
            rc = 4 if code else 0
        else:
            run(["systemctl", "--user", "daemon-reload"])
            code = run(["systemctl", "--user", "enable", "--now", f"{UNIT}.timer"])
            out.append(f"systemctl enable --now rc={code}")
            rc = 4 if code else 0
            if not linger(run):
                out.append("WARNING: lingering is off; user timers stop at logout (run loginctl enable-linger)")
    return out, rc


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("cmd", choices=["run", "status", "install"])
    ap.add_argument("--home", type=Path, default=Path.home())
    ap.add_argument("--apply", action="store_true")
    a = ap.parse_args(argv)
    if a.cmd == "run":
        try:
            return run(a.home)
        except Exception as exc:  # noqa: BLE001 - an internal failure must not look like "transcripts stale"
            msg = f"backup-watch internal error: {type(exc).__name__}"
            print(msg, file=sys.stderr)
            notify(msg)
            return 5
    if a.cmd == "status":
        print(status(a.home))
        return 0
    try:
        lines, code = install(a.home, a.apply)
    except OSError as exc:
        print(f"install failed: {type(exc).__name__}", file=sys.stderr)
        return 5
    print("\n".join(lines))
    return code


if __name__ == "__main__":
    sys.exit(main())
