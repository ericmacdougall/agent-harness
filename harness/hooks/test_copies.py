#!/usr/bin/env python3
"""Test copies: one reusable copy per PR or lane, a disk-low guard, and an idle-copy reaper (report-only by default).

WHY. On 2026-11-21 t2-dev's root volume reached 0 bytes free: ~/.agent-harness/work held 117 GB, most of it per-round
click-test copies (work/<session>/tester-1408-r3, tester-1408-r4, tester-1409-r1, ...). Each review round made a new
full copy and nothing removed the old ones. The full disk then stopped Elasticsearch writes and other sessions' builds.

WHAT.
  acquire   `test_copies.py acquire --repo <checkout> --key <pr-1408|lane> [--ref <ref>]` returns ONE stable path
            (~/.agent-harness/test-copies/<repo>/<key>) for that PR or lane. The first call makes a detached linked
            worktree; later calls reuse it and move it to the new ref, but only when it is clean (it never discards work).
            It refuses to create a copy when the volume is below the free-space floor.
  guard     The same floor as a PreToolUse Bash hook (`test_copies.py pretool`). When free space is below the floor it
            denies commands that create a copy (git worktree add, git clone, cp -R/-a, rsync -a, ditto) with a clear
            alert. Above the floor it never says anything. Fails OPEN on its own errors.
  shm       The same hook refuses commands that write scratch into /dev/shm (RAM) and points to disk scratch.
  reap      `test_copies.py reap [--apply] [--json]` lists idle copies (older than max_age_hours) and, when the total
            is over max_total_gb, the oldest copies above the cap. It is REPORT-ONLY unless BOTH the config flag
            "reaper_delete_enabled": true is set in ~/.agent-harness/state/test-copies.json AND --apply is passed.
            The installer never sets that flag, so installing or a first run deletes nothing. Even when enabled it
            removes only copies that are git checkouts with no uncommitted changes whose HEAD is on a remote ref,
            and never a copy a process is working in. A registered linked worktree goes through plain
            `git worktree remove` (no --force).

Config (~/.agent-harness/state/test-copies.json; every key optional):
  min_free_gb (25), max_age_hours (24), max_total_gb (60), reaper_delete_enabled (false),
  roots ([~/.agent-harness/work]), name_patterns (["tester-*", "test-copy-*", "click-test-*", "r[0-9]*-*"]).
Env overrides: HARNESS_TEST_COPY_MIN_FREE_GB, HARNESS_TEST_COPY_HOME (tests).
"""
from __future__ import annotations

import argparse
import fnmatch
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import time

GB = 1024 ** 3
DEFAULTS = {
    "min_free_gb": 25.0,
    "max_age_hours": 24.0,
    "max_total_gb": 60.0,
    "reaper_delete_enabled": False,
    "roots": None,                     # None = [<home>/.agent-harness/work]
    "name_patterns": ["tester-*", "test-copy-*", "click-test-*", "r[0-9]*-*"],
}
GIT_TIMEOUT = 60
# Scratch in /dev/shm is RAM: on 2026-11-21 sessions held 50 of t2-dev's 56 GB there. Writes into it are refused (reads,
# df/ls/du and rm stay allowed, so it can still be inspected and emptied).
SHM_WRITE = re.compile(r"""(?x)
    (?:^|[;&|(\s])(?:cp|mv|rsync|mkdir|tee|ln|ditto|touch|install|unzip|tar|dd|mktemp)\b[^;&|]*?/dev/shm
  | \bgit\b[^;&|]*?\b(?:clone|worktree\s+add)\b[^;&|]*?/dev/shm
  | >>?\s*["']?/dev/shm
  | \b(?:TMPDIR|TMP|TEMP|CLAUDE_CODE_TMPDIR|XDG_CACHE_HOME)=["']?/dev/shm
  | \bof=/dev/shm
""")
COPY_CMD = re.compile(r"""(?x)
    \bgit\s+(?:-C\s+\S+\s+)?(?:worktree\s+add|clone)\b
  | \bcp\s+-[A-Za-z]*[Ra][A-Za-z]*\b
  | \brsync\s+-[A-Za-z]*a[A-Za-z]*\b
  | \bditto\b
""")


def home() -> str:
    return os.environ.get("HARNESS_TEST_COPY_HOME") or os.path.expanduser("~")


def state_dir() -> str:
    return os.path.join(home(), ".agent-harness", "state")


def config_path() -> str:
    return os.path.join(state_dir(), "test-copies.json")


def copies_root() -> str:
    return os.path.join(home(), ".agent-harness", "test-copies")


def load_config() -> dict:
    cfg = dict(DEFAULTS)
    try:
        with open(config_path()) as f:
            user = json.load(f)
        if isinstance(user, dict):
            for k in DEFAULTS:
                if k in user:
                    cfg[k] = user[k]
    except (OSError, ValueError):
        pass
    env = os.environ.get("HARNESS_TEST_COPY_MIN_FREE_GB")
    if env:
        try:
            cfg["min_free_gb"] = float(env)
        except ValueError:
            pass
    cfg["reaper_delete_enabled"] = cfg.get("reaper_delete_enabled") is True   # only a literal true enables deletion
    if not cfg.get("roots"):
        cfg["roots"] = [os.path.join(home(), ".agent-harness", "work")]
    return cfg


def free_bytes(path: str) -> int:
    p = path
    while p and not os.path.exists(p):
        p = os.path.dirname(p)
    st = os.statvfs(p or "/")
    return st.f_bavail * st.f_frsize


def alert(kind: str, detail: dict) -> None:
    """Append one row to the alert log; never raises."""
    try:
        os.makedirs(state_dir(), exist_ok=True)
        row = {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "kind": kind}
        row.update(detail)
        with open(os.path.join(state_dir(), "test-copies-alerts.jsonl"), "a") as f:
            f.write(json.dumps(row) + "\n")
    except OSError:
        pass


def disk_low(path: str, cfg: dict) -> "tuple[bool, float]":
    gb = free_bytes(path) / GB
    return gb < float(cfg["min_free_gb"]), gb


def low_disk_message(path: str, free_gb: float, cfg: dict) -> str:
    return (f"DISK LOW: {free_gb:.1f} GB free on the volume holding {path} (floor {cfg['min_free_gb']} GB). "
            "The harness refuses to create another test copy. Reuse your PR's copy with "
            "`test_copies.py acquire --repo <checkout> --key pr-<N>`, and run `test_copies.py reap` to see idle "
            "copies (deleting them needs the owner's OK and reaper_delete_enabled).")


def git(cwd: str, *args: str) -> "tuple[int, str]":
    try:
        p = subprocess.run(["git", "-C", cwd, *args], capture_output=True, text=True, timeout=GIT_TIMEOUT,
                           env=dict(os.environ, GIT_OPTIONAL_LOCKS="0", GIT_TERMINAL_PROMPT="0"))
        return p.returncode, (p.stdout + p.stderr).strip()
    except (OSError, subprocess.TimeoutExpired) as e:
        return 99, str(e)


def safe_key(key: str) -> str:
    k = re.sub(r"[^A-Za-z0-9._-]+", "-", key).strip("-.")
    if not k:
        raise ValueError("empty key")
    return k[:80]


def index_path() -> str:
    return os.path.join(state_dir(), "test-copies-index.json")


def load_index() -> dict:
    try:
        with open(index_path()) as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def touch_index(path: str, **extra) -> None:
    idx = load_index()
    rec = idx.get(path, {})
    rec.update(extra, last_used=time.time())
    idx[path] = rec
    os.makedirs(state_dir(), exist_ok=True)
    tmp = index_path() + ".tmp"
    with open(tmp, "w") as f:
        json.dump(idx, f, indent=1)
    os.replace(tmp, index_path())


# ---------------------------------------------------------------- acquire
def acquire(repo: str, key: str, ref: str = "HEAD", cfg: "dict | None" = None) -> dict:
    cfg = cfg or load_config()
    repo = os.path.abspath(repo)
    rc, top = git(repo, "rev-parse", "--show-toplevel")
    if rc != 0:
        return {"ok": False, "error": f"not a git checkout: {repo}"}
    # Resolve the ref in the SOURCE checkout: "HEAD" inside the copy would mean the copy's own commit.
    rc, sha = git(top, "rev-parse", "--verify", "--quiet", ref + "^{commit}")
    if rc != 0 or not sha:
        return {"ok": False, "error": f"unknown ref in {top}: {ref}"}
    sha = sha.splitlines()[-1].strip()
    name = safe_key(os.path.basename(top))
    path = os.path.join(copies_root(), name, safe_key(key))
    if os.path.isdir(path):
        rc, dirty = git(path, "status", "--porcelain")
        if rc != 0:
            return {"ok": False, "error": f"existing copy is not a usable checkout: {path}", "path": path}
        if dirty:
            touch_index(path, repo=top, key=key)
            return {"ok": True, "path": path, "reused": True, "moved": False,
                    "note": "copy has uncommitted changes; left at its current commit (nothing discarded)"}
        rc, out = git(path, "checkout", "--detach", "--quiet", sha)
        touch_index(path, repo=top, key=key)
        return {"ok": rc == 0, "path": path, "commit": sha, "reused": True, "moved": rc == 0, **({} if rc == 0 else {"error": out[-300:]})}
    low, gb = disk_low(path, cfg)
    if low:
        msg = low_disk_message(path, gb, cfg)
        alert("disk-low-refused-acquire", {"path": path, "free_gb": round(gb, 2), "floor_gb": cfg["min_free_gb"]})
        return {"ok": False, "refused": "disk-low", "free_gb": round(gb, 2), "error": msg}
    os.makedirs(os.path.dirname(path), exist_ok=True)
    rc, out = git(top, "worktree", "add", "--detach", path, sha)
    if rc != 0:
        return {"ok": False, "error": out[-300:]}
    touch_index(path, repo=top, key=key)
    return {"ok": True, "path": path, "commit": sha, "reused": False, "moved": True}


# ---------------------------------------------------------------- guard (PreToolUse)
def pretool(event: dict, cfg: "dict | None" = None) -> "tuple[int, str]":
    """(exit code, stderr). 2 denies; 0 allows. Fails open."""
    try:
        if event.get("tool_name") != "Bash":
            return 0, ""
        cmd = str((event.get("tool_input") or {}).get("command") or "")
        if SHM_WRITE.search(cmd):
            alert("shm-write-denied", {"command": SHM_WRITE.search(cmd).group(0)[:60]})
            return 2, ("SCRATCH IN RAM REFUSED: /dev/shm is memory, not disk (2026-11-21: sessions filled 50 of t2-dev's "
                       "56 GB). Put scratch on disk instead: ~/.agent-harness/scratch/<session>/ or the session's $TMPDIR. "
                       "Reading, listing and removing files in /dev/shm stays allowed.\n")
        if not COPY_CMD.search(cmd):
            return 0, ""
        cfg = cfg or load_config()
        cwd = event.get("cwd") or home()
        low, gb = disk_low(cwd if os.path.isabs(str(cwd)) else home(), cfg)
        if not low:
            return 0, ""
        alert("disk-low-denied-copy", {"cwd": str(cwd)[:200], "free_gb": round(gb, 2), "floor_gb": cfg["min_free_gb"],
                                       "command": COPY_CMD.search(cmd).group(0)[:60]})
        return 2, low_disk_message(str(cwd), gb, cfg) + "\n"
    except Exception:          # noqa: BLE001 -- fail open
        return 0, ""


# ---------------------------------------------------------------- reap
def dir_size(path: str) -> int:
    try:
        p = subprocess.run(["du", "-sk", path], capture_output=True, text=True, timeout=300)
        return int(p.stdout.split()[0]) * 1024
    except (OSError, ValueError, IndexError, subprocess.TimeoutExpired):
        return 0


def last_activity(path: str, idx: dict) -> float:
    t = float((idx.get(path) or {}).get("last_used") or 0)
    for rel in ("", ".git", ".git/HEAD", ".git/index"):
        try:
            t = max(t, os.stat(os.path.join(path, rel)).st_mtime)
        except OSError:
            pass
    try:
        with os.scandir(path) as it:
            for e in it:
                try:
                    t = max(t, e.stat(follow_symlinks=False).st_mtime)
                except OSError:
                    pass
    except OSError:
        pass
    return t


def candidates(cfg: dict) -> list:
    pats = cfg["name_patterns"]
    seen, out = set(), []
    def add(p):
        rp = os.path.realpath(p)
        if rp not in seen and os.path.isdir(p) and not os.path.islink(p):
            seen.add(rp); out.append(p)
    cr = copies_root()
    if os.path.isdir(cr):
        for repo in sorted(os.listdir(cr)):
            rd = os.path.join(cr, repo)
            if os.path.isdir(rd):
                for k in sorted(os.listdir(rd)):
                    add(os.path.join(rd, k))
    for root in cfg["roots"]:
        if not os.path.isdir(root):
            continue
        for sess in sorted(os.listdir(root)):
            sd = os.path.join(root, sess)
            if not os.path.isdir(sd):
                continue
            if any(fnmatch.fnmatch(sess, p) for p in pats):
                add(sd); continue
            try:
                for e in sorted(os.listdir(sd)):
                    if any(fnmatch.fnmatch(e, p) for p in pats):
                        add(os.path.join(sd, e))
            except OSError:
                pass
    return out


def in_use(path: str) -> bool:
    """True when a process has its cwd or an open file under path (lsof; unknown counts as in use)."""
    if not shutil.which("lsof"):
        return True
    try:
        p = subprocess.run(["lsof", "-t", "+D", path], capture_output=True, text=True, timeout=120)
        return bool(p.stdout.strip())
    except (OSError, subprocess.TimeoutExpired):
        return True


def deletable(path: str) -> "tuple[bool, str]":
    if not os.path.exists(os.path.join(path, ".git")):
        return False, "not a git checkout (kept; check by hand)"
    rc, dirty = git(path, "status", "--porcelain")
    if rc != 0:
        return False, "git status failed"
    if dirty:
        return False, "uncommitted changes"
    rc, remote = git(path, "branch", "-r", "--contains", "HEAD")
    if rc != 0 or not remote.strip():
        return False, "HEAD is on no remote ref"
    if in_use(path):
        return False, "a process is working in it"
    return True, "clean and pushed"


def remove_copy(path: str) -> "tuple[bool, str]":
    dotgit = os.path.join(path, ".git")
    if os.path.isfile(dotgit):   # linked worktree
        rc, common = git(path, "rev-parse", "--git-common-dir")
        if rc != 0:
            return False, "cannot find the main repository"
        main = os.path.dirname(os.path.abspath(os.path.join(path, common)))
        rc, out = git(main, "worktree", "remove", path)
        return rc == 0, out[-200:] if rc else "git worktree remove"
    shutil.rmtree(path)
    return True, "removed standalone clone"


def reap(apply: bool = False, cfg: "dict | None" = None, now: "float | None" = None) -> dict:
    cfg = cfg or load_config()
    now = now or time.time()
    idx = load_index()
    rows = []
    for p in candidates(cfg):
        rows.append({"path": p, "bytes": dir_size(p), "idle_hours": round((now - last_activity(p, idx)) / 3600, 1)})
    rows.sort(key=lambda r: -r["idle_hours"])            # oldest first
    total = sum(r["bytes"] for r in rows)
    cap = float(cfg["max_total_gb"]) * GB
    over = total - cap
    for r in rows:
        reasons = []
        if r["idle_hours"] >= float(cfg["max_age_hours"]):
            reasons.append(f"idle {r['idle_hours']}h >= {cfg['max_age_hours']}h")
        elif over > 0 and r["idle_hours"] >= 1:
            reasons.append(f"total {total / GB:.1f} GB over cap {cfg['max_total_gb']} GB")
        if reasons:
            over -= r["bytes"]
        r["reap"] = bool(reasons)
        r["why"] = "; ".join(reasons)
    deleting = bool(apply and cfg["reaper_delete_enabled"])
    for r in rows:
        if not r["reap"]:
            r["action"] = "keep"
            continue
        if not deleting:
            r["action"] = "would-remove (report-only)"
            continue
        ok, why = deletable(r["path"])
        if not ok:
            r["action"] = f"kept: {why}"
            continue
        done, msg = remove_copy(r["path"])
        r["action"] = "removed" if done else f"remove failed: {msg}"
    res = {"mode": "delete" if deleting else "report-only", "delete_enabled": cfg["reaper_delete_enabled"],
           "total_gb": round(total / GB, 2), "cap_gb": cfg["max_total_gb"], "max_age_hours": cfg["max_age_hours"],
           "copies": rows}
    if apply and not cfg["reaper_delete_enabled"]:
        res["note"] = "--apply ignored: set \"reaper_delete_enabled\": true in " + config_path() + " (owner's OK first)"
    if any(r["reap"] for r in rows):
        alert("reap-candidates", {"mode": res["mode"], "count": sum(r["reap"] for r in rows),
                                  "gb": round(sum(r["bytes"] for r in rows if r["reap"]) / GB, 2)})
    return res


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="test_copies.py")
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("acquire"); a.add_argument("--repo", required=True); a.add_argument("--key", required=True)
    a.add_argument("--ref", default="HEAD")
    r = sub.add_parser("reap"); r.add_argument("--apply", action="store_true"); r.add_argument("--json", action="store_true")
    sub.add_parser("pretool")
    sub.add_parser("check-disk")
    args = ap.parse_args(argv)
    if args.cmd == "pretool":
        try:
            raw = sys.stdin.read(1 << 20) if not sys.stdin.isatty() else ""
            ev = json.loads(raw) if raw.strip() else {}
        except Exception:      # noqa: BLE001
            return 0
        code, err = pretool(ev if isinstance(ev, dict) else {})
        if err:
            sys.stderr.write(err)
        return code
    if args.cmd == "acquire":
        res = acquire(args.repo, args.key, args.ref)
        print(json.dumps(res))
        return 0 if res.get("ok") else (3 if res.get("refused") else 1)
    if args.cmd == "check-disk":
        cfg = load_config()
        low, gb = disk_low(copies_root(), cfg)
        print(json.dumps({"free_gb": round(gb, 2), "floor_gb": cfg["min_free_gb"], "low": low}))
        return 3 if low else 0
    res = reap(apply=args.apply)
    if args.json:
        print(json.dumps(res, indent=1))
    else:
        print(f"test copies: {len(res['copies'])}, {res['total_gb']} GB (cap {res['cap_gb']} GB, idle limit "
              f"{res['max_age_hours']} h), mode {res['mode']}")
        for c in res["copies"]:
            print(f"  {c['action']:<28} {c['bytes'] / GB:7.1f} GB  idle {c['idle_hours']:>7}h  {c['path']}  {c['why']}")
        if res.get("note"):
            print(res["note"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
