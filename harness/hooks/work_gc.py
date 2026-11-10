#!/usr/bin/env python3
"""Audited garbage collection of ~/.agent-harness/work (GoodQA #15565).

The work directory had reached 183 GiB on a Mac at 97% disk. This tool finds two kinds of reclaimable content and removes
them only from a plan that a dry run printed:

  worktree  the git worktree of a FINISHED agent (`<repo>/.claude/worktrees/agent-<id>`), when
              * its agent log has not been written for `--idle-hours` (default 3) and no process has its cwd inside it,
              * `git status` shows nothing to lose (no changed or untracked file; ignored build output is fine), and
              * its HEAD is contained in a remote-tracking ref (pushed at least once), so the commits exist elsewhere.
            It is removed with `git worktree remove --force`, which leaves the branch and the repository alone.
  regen     a rebuildable folder anywhere under the work directory: node_modules, .venv, venv, .next, .nuxt, .turbo, dist,
            build, __pycache__, .pytest_cache, .mypy_cache, .ruff_cache, .cache, target, .gradle, .svelte-kit, .output.
            Only when nothing under it is a log, a session transcript, a state file or any `.jsonl`, and no process has
            its cwd inside it.

It never descends into or removes: `.git`, `~/.claude`, session logs (`wals`, `projects`, `sessions`, `transcripts`,
`*.jsonl`), state or approval files (`state`, `.agent-harness/state`), or a worktree that holds work. Everything it
removes is appended to `~/.agent-harness/state/work-gc.jsonl` (path, kind, bytes, reason, time).

    work_gc.py plan  [--root DIR] [--idle-hours H] [--out plan.json]   dry run: lists candidates with sizes
    work_gc.py apply --plan plan.json [--root DIR]                     re-verifies every item, then removes it

`apply` takes only a plan file produced by `plan` and re-checks each item right before removing it. Python 3.9+, stdlib only.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

REGEN_NAMES = frozenset((
    "node_modules", ".venv", "venv", ".next", ".nuxt", ".turbo", "dist", "build", "__pycache__", ".pytest_cache",
    ".mypy_cache", ".ruff_cache", ".cache", "target", ".gradle", ".svelte-kit", ".output"))
PROTECTED_NAMES = frozenset((".git", "wals", "projects", "sessions", "transcripts", "state", ".claude"))
CONTENT_PROTECTED = frozenset(("wals", "transcripts", ".claude"))  # inside a rebuildable folder these mean real records
MAX_DEPTH = 9
SCAN_SECONDS = 120.0
DU_TIMEOUT = 60
GIT_TIMEOUT = 30


def home() -> Path:
    return Path(os.environ.get("AH_HOME") or Path.home())


def work_root() -> Path:
    return home() / ".agent-harness" / "work"


def audit_path() -> Path:
    return home() / ".agent-harness" / "state" / "work-gc.jsonl"


def git(path, *args, timeout=GIT_TIMEOUT):
    env = dict(os.environ, GIT_OPTIONAL_LOCKS="0", GIT_TERMINAL_PROMPT="0")
    done = subprocess.run(["git", "-C", str(path), "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", *args],
                          capture_output=True, text=True, timeout=timeout, env=env)
    return done.returncode, done.stdout


def disk_bytes(path: Path) -> int:
    try:
        done = subprocess.run(["du", "-sk", str(path)], capture_output=True, text=True, timeout=DU_TIMEOUT)
        return int(done.stdout.split()[0]) * 1024
    except (OSError, ValueError, IndexError, subprocess.TimeoutExpired):
        return -1


def process_cwds() -> list:
    """Real paths of every process cwd (one lsof call); an unreadable list returns None so nothing is removed."""
    try:
        done = subprocess.run(["lsof", "-d", "cwd", "-Fn"], capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.TimeoutExpired):
        return None
    lines = [ln[1:] for ln in done.stdout.splitlines() if ln.startswith("n")]
    return lines or None


def busy(path: Path, cwds) -> bool:
    if cwds is None:
        return True
    prefix = str(path).rstrip("/") + "/"
    return any(c == str(path) or c.startswith(prefix) for c in cwds)


def has_protected_content(path: Path, limit=200000) -> bool:
    """True when anything under path is a log, transcript, state file or .jsonl (bounded walk; a bound hit counts as yes)."""
    seen = 0
    for root, dirs, files in os.walk(path, followlinks=False):
        if any(d in CONTENT_PROTECTED for d in dirs) or any(f.endswith(".jsonl") for f in files):
            return True
        seen += len(files) + len(dirs)
        if seen > limit:
            return True
    return False


def agent_log_idle_hours(worktree: Path, session: str):
    """Hours since the agent's own log was written; None when the log cannot be found (treated as not finished)."""
    wals = home() / ".claude" / "wals" / session
    name = worktree.name  # agent-<id>
    for candidate in (wals / f"{name}.jsonl",):
        try:
            return (time.time() - candidate.stat().st_mtime) / 3600.0
        except OSError:
            continue
    return None


def session_of(path: Path, root: Path):
    try:
        return path.relative_to(root).parts[0]
    except (ValueError, IndexError):
        return None


def worktree_verdict(path: Path, root: Path, idle_hours: float, cwds) -> tuple:
    """(ok, reason). ok only when removing the worktree loses nothing."""
    if not (path / ".git").is_file():
        return False, "not a linked worktree (.git is not a file)"
    session = session_of(path, root)
    idle = agent_log_idle_hours(path, session) if session else None
    if idle is None:
        return False, "no agent log found: cannot tell whether the agent finished"
    if idle < idle_hours:
        return False, "agent log written %.1f h ago (< %.1f h)" % (idle, idle_hours)
    if busy(path, cwds):
        return False, "a process has its cwd inside it (or the process list was unreadable)"
    code, status = git(path, "status", "--porcelain=v1", "--untracked-files=all", "-z")
    if code != 0:
        return False, "git status failed"
    if status:
        return False, "changed or untracked files: %s" % status.split("\0")[0][:60]
    code, head = git(path, "rev-parse", "--verify", "HEAD")
    if code != 0 or not head.strip():
        return False, "no HEAD"
    code, remotes = git(path, "for-each-ref", "--contains", head.strip(), "refs/remotes", "--format=%(refname)")
    if code != 0 or not remotes.strip():
        return False, "HEAD is on no remote-tracking ref (unpushed)"
    return True, "finished, clean, pushed (%s)" % remotes.split()[0]


def enclosing_worktree(path: Path):
    for parent in path.parents:
        if parent.parent.name == "worktrees" and parent.parent.parent.name == ".claude" and parent.name.startswith("agent-"):
            return parent
    return None


def regen_verdict(path: Path, cwds, root: Path = None, idle_hours: float = 3.0) -> tuple:
    if root is not None:
        owner = enclosing_worktree(path)
        if owner is not None:  # a live agent is probably using its own dependencies
            idle = agent_log_idle_hours(owner, session_of(owner, root) or "")
            if idle is None or idle < idle_hours:
                return False, "its agent worktree is not finished (log idle %s h)" % ("?" if idle is None else "%.1f" % idle)
        else:
            try:
                age = (time.time() - path.stat().st_mtime) / 3600.0
            except OSError:
                return False, "cannot stat"
            if age < idle_hours:
                return False, "changed %.1f h ago (< %.1f h)" % (age, idle_hours)
    if busy(path, cwds):
        return False, "a process has its cwd inside it (or the process list was unreadable)"
    if path.is_symlink() or not path.is_dir():
        return False, "not a real directory"
    if has_protected_content(path):
        return False, "contains a log, transcript, state file or .jsonl"
    return True, "rebuildable folder"


def scan(root: Path, deadline: float):
    """Yield (kind, path) candidates. Does not descend into candidates, .git or protected folders."""
    stack = [(root, 0)]
    while stack and time.monotonic() < deadline:
        base, depth = stack.pop()
        try:
            entries = sorted(os.scandir(base), key=lambda e: e.name)
        except OSError:
            continue
        for entry in entries:
            try:
                if entry.is_symlink() or not entry.is_dir(follow_symlinks=False):
                    continue
            except OSError:
                continue
            name, path = entry.name, Path(entry.path)
            if base.name == "worktrees" and base.parent.name == ".claude" and name.startswith("agent-"):
                yield "worktree", path
                stack.append((path, depth + 1))  # its rebuildable folders are judged too
                continue
            if name in REGEN_NAMES:
                yield "regen", path
                continue
            if name in PROTECTED_NAMES and not (name == ".claude"):
                continue
            if depth + 1 < MAX_DEPTH:
                stack.append((path, depth + 1))


def make_plan(root: Path, idle_hours: float, workers=8) -> dict:
    cwds = process_cwds()
    found = list(scan(root, time.monotonic() + SCAN_SECONDS))
    items = []

    def judge(item):
        kind, path = item
        ok, reason = worktree_verdict(path, root, idle_hours, cwds) if kind == "worktree" else regen_verdict(path, cwds, root, idle_hours)
        return {"kind": kind, "path": str(path), "ok": ok, "reason": reason,
                "bytes": disk_bytes(path) if ok else 0}

    with ThreadPoolExecutor(max_workers=workers) as pool:
        for row in pool.map(judge, found):
            items.append(row)
    # a regen folder inside a worktree that is itself removed is counted once, under the worktree
    removed = [Path(i["path"]) for i in items if i["kind"] == "worktree" and i["ok"]]
    for i in items:
        if i["kind"] == "regen" and i["ok"] and any(str(Path(i["path"])).startswith(str(w) + "/") for w in removed):
            i["ok"], i["reason"], i["bytes"] = False, "inside a worktree that is removed whole", 0
    return {"root": str(root), "at": time.time(), "idle_hours": idle_hours, "items": items,
            "total_bytes": sum(i["bytes"] for i in items if i["ok"])}


def record(row: dict) -> None:
    path = audit_path()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(row) + "\n")


def apply_plan(plan: dict, root: Path, idle_hours: float = None) -> list:
    """Re-verify and remove each ok item of a plan produced by make_plan. Returns result rows."""
    results = []
    cwds = process_cwds()
    idle = float(plan.get("idle_hours", 3.0)) if idle_hours is None else idle_hours
    root_real = os.path.realpath(root)
    for item in plan.get("items", []):
        if not item.get("ok"):
            continue
        path = Path(item["path"])
        row = {"at": time.time(), "path": str(path), "kind": item["kind"], "bytes": item.get("bytes", 0)}
        real = os.path.realpath(path)
        if real != str(path) or not real.startswith(root_real + "/"):
            row.update(status="skipped", reason="path is a symlink or outside the work root")
        elif item["kind"] == "worktree":
            ok, reason = worktree_verdict(path, root, idle, cwds)
            row.update(reason=reason)
            if ok:
                repo = _repo_of(path)
                code, _ = git(repo or path, "worktree", "remove", "--force", str(path), timeout=600)
                row["status"] = "removed" if code == 0 and not path.exists() else "failed"
            else:
                row["status"] = "skipped"
        elif item["kind"] == "regen":
            ok, reason = regen_verdict(path, cwds, root, idle)
            row.update(reason=reason)
            if ok:
                shutil.rmtree(path, ignore_errors=False)
                row["status"] = "removed" if not path.exists() else "failed"
            else:
                row["status"] = "skipped"
        else:
            row.update(status="skipped", reason="unknown kind")
        record(row)
        results.append(row)
    return results


def _repo_of(worktree: Path):
    """The main repository of a linked worktree (from its .git file), else None."""
    try:
        line = (worktree / ".git").read_text().strip()
        gitdir = Path(line.split("gitdir:", 1)[1].strip())
        common = gitdir.parent.parent  # <repo>/.git/worktrees/<name> -> <repo>/.git
        return common.parent if common.name == ".git" else None
    except (OSError, IndexError):
        return None


def human(n: int) -> str:
    return "%.1f GiB" % (n / 2**30) if n >= 2**30 else "%.0f MiB" % (n / 2**20)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("plan")
    p.add_argument("--root")
    p.add_argument("--idle-hours", type=float, default=3.0)
    p.add_argument("--out")
    a = sub.add_parser("apply")
    a.add_argument("--plan", required=True)
    a.add_argument("--root")
    args = parser.parse_args(argv)
    root = Path(args.root) if args.root else work_root()
    if args.cmd == "plan":
        plan = make_plan(root, args.idle_hours)
        if args.out:
            Path(args.out).write_text(json.dumps(plan, indent=1))
        for row in sorted(plan["items"], key=lambda r: -r["bytes"]):
            if row["ok"]:
                print("%10s  %-8s %s" % (human(row["bytes"]), row["kind"], row["path"]))
        kept = sum(1 for r in plan["items"] if not r["ok"] and r["kind"] == "worktree")
        print("reclaimable: %s in %d item(s); %d worktree(s) kept (not finished, dirty or unpushed)" % (
            human(plan["total_bytes"]), sum(1 for r in plan["items"] if r["ok"]), kept))
        return 0
    plan = json.loads(Path(args.plan).read_text())
    results = apply_plan(plan, root)
    freed = sum(r["bytes"] for r in results if r["status"] == "removed")
    for r in results:
        print("%-8s %-8s %s %s" % (r["status"], r["kind"], r["path"], "" if r["status"] == "removed" else r.get("reason", "")))
    print("removed %s in %d item(s)" % (human(freed), sum(1 for r in results if r["status"] == "removed")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
