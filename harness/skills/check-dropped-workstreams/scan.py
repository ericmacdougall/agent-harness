#!/usr/bin/env python3
"""Dropped-workstream scan: a thin wrapper over `ah owners --gate` (GoodQA goodqa#14791, invariant I8).

There is one owner view. This script runs `ah owners --gate` for every session with WAL activity in the last
48 hours (or --session) and prints the undisposed DROPPED owners. Exit 1 while any exist, 0 otherwise; the
exit code is the record, so "0 dropped" cannot be written by hand over a drop. Read-only.
"""
import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path


def ah_path() -> Path:
    here = Path(__file__).resolve()
    for candidate in (Path.home() / ".claude" / "hooks" / "ah.py", here.parents[2] / "hooks" / "ah.py"):
        if candidate.is_file():
            return candidate
    return Path.home() / ".claude" / "hooks" / "ah.py"


def _wal_segments():
    """The segment-chain reader, from the installed hooks directory or the one beside the skill. Without it the scan
    cannot tell a rotated main WAL from an absent one, so it stops (never printing "0 dropped" over a view it lacks)."""
    here = Path(__file__).resolve()
    for folder in (Path.home() / ".claude" / "hooks", here.parents[2] / "hooks"):
        if (folder / "wal_segments.py").is_file():
            sys.path.insert(0, str(folder))
            import wal_segments  # noqa: PLC0415
            return wal_segments
    print("check-dropped-workstreams: wal_segments.py not found beside the hooks; cannot scan segmented WALs",
          file=sys.stderr)
    raise SystemExit(2)  # exit 2 is "owners view unavailable"; 1 would claim dropped owners


def sessions(home: Path, window_s: float) -> list:
    """Sessions whose main WAL (the live file or any closed segment: a crashed rotation still counts) moved in the window."""
    ws = _wal_segments()
    root = home / ".claude" / "wals"
    now = time.time()
    out = []
    try:
        for entry in os.scandir(root):
            if not entry.is_dir(follow_symlinks=False):
                continue
            chain = ws.chain(entry.path, "main")
            members = [Path(entry.path) / seg.name for seg in chain.segments] + (
                [Path(entry.path) / chain.live.name] if chain.live else [])
            if members and now - max(m.stat().st_mtime for m in members) <= window_s:
                out.append(entry.name)
    except OSError:
        pass
    return sorted(out)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--session")
    ap.add_argument("--window-hours", type=float, default=48)
    ap.add_argument("--text", action="store_true")
    ap.add_argument("--stale-min", type=float, help="ignored: the threshold lives in liveness.py (one rule)")
    a = ap.parse_args(argv)
    home = Path(os.environ.get("AH_HOME") or Path.home())
    targets = [a.session] if a.session else sessions(home, a.window_hours * 3600)
    report, rc = [], 0
    for s in targets:
        p = subprocess.run([sys.executable, "-I", str(ah_path()), "owners", "--session", s, "--gate", "--all"],
                           capture_output=True, text=True, timeout=120)
        head = p.stdout.split("\nGATE:")[0]
        try:
            doc = json.loads(head)
        except ValueError:
            doc = {"session": s, "error": (p.stdout or p.stderr)[:200]}
            rc = max(rc, 2)
        undisposed = doc.get("undisposed") or []
        rows = {r["agent_id"]: r for r in doc.get("owners") or []}
        report.append({"session": s, "undisposed": [{"agent": u, "state": rows.get(u, {}).get("state"),
                                                    "idle_s": rows.get(u, {}).get("idle_s"),
                                                    "ticket": rows.get(u, {}).get("ticket")} for u in undisposed],
                       "counts": doc.get("counts"), "error": doc.get("error")})
        if undisposed:
            rc = max(rc, 1)
    if a.text:
        for r in report:
            for u in r["undisposed"]:
                idle = u["idle_s"] or 0
                print(f"{r['session'][:8]} DROPPED {int(idle // 3600)}h{int(idle % 3600 // 60):02d}m {u['agent']} "
                      f"{u['ticket'] or 'no-ticket'}: ah task dispose --agent {u['agent']} --kind ...")
            if r["error"]:
                print(f"{r['session'][:8]} ERROR {r['error']}")
        print(("GATE: undisposed dropped owners present" if rc == 1 else
               "GATE: owners view unavailable" if rc == 2 else "gate clear"))
    else:
        print(json.dumps({"schema": 1, "sessions": report, "gate": rc}, indent=1))
    return rc


if __name__ == "__main__":
    sys.exit(main())
