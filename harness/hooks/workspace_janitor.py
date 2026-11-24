#!/usr/bin/env python3
"""Workspace janitor: cleanup when a session or runner job ends, a TTL sweep, /dev/shm and container hygiene.

Built on the shared rules in hygiene_safety.py and the one config / deletion switch of copy_hygiene.py (PR #284).
Reuse of checkouts is `copy_hygiene.py acquire` (one worktree per repository and PR/lane from a shared bare mirror);
this tool only cleans up after sessions.

WHY. On 2026-11-21 t2-dev filled to 0 bytes: ~/.agent-harness/work held 117 GB of per-session clones and worktrees
that nothing removed after the session ended, /dev/shm (RAM) held 50 of 56 GB of session scratch, and uncapped
Elasticsearch/Java test containers drove ~895k kernel OOM kills that filled syslog. Earlier cleanups (Nov 17-18) also
removed folders that live systemd services ran from, so every removal first checks service references.

COMMANDS
  release    [--session ID | --path DIR] [--apply] [--budget SECONDS]
             For a session's work folder (~/.agent-harness/work/<ID>) or one folder inside ~/.agent-harness/{work,
             checkouts,test-copies}: remove every checkout that is verified recoverable (see hygiene_safety.recoverable)
             and not in use or referenced by a service. Removes the session folder when no file is left in it.
             Anything else is kept and listed. Call it at the end of every runner job.
  session-end  SessionEnd hook: starts a detached `release --apply` with a time budget and returns at once.
  sweep      [--apply] [--json]
             The TTL janitor (systemd user timer, hourly): `copy_hygiene.py reap` for test copies, `release` for every
             session folder idle (newest mtime or ctime) longer than max_age_hours (default 24) whose Claude session is
             not alive, user-owned /dev/shm entries idle longer than shm_ttl_hours (default 6) that no process holds
             open or maps, and a list of running containers that have no memory limit.
  pretool    PreToolUse Bash hook: denies `docker|podman run|create` and `compose up|run` without a memory cap (and
             Elasticsearch images without a heap cap) with the exact flags to add. Fails open on its own errors.

DELETION IS OFF BY DEFAULT. Everything removes only when the owner has set "reaper_delete_enabled": true in
~/.agent-harness/state/copy-hygiene.json (the same switch as `copy_hygiene.py reap --apply`); HARNESS_JANITOR=off is a
kill switch. Until then release/sweep/session-end only report. The installer never sets the switch.

SAFETY (hygiene_safety.py). Nothing is removed that a process uses (cwd, root, exe, open files, memory maps), that a
systemd unit (system or user: WorkingDirectory, ExecStart*, Environment*), cron entry, docker/podman container or
launchd plist references (resolved with realpath), that holds a mount, unpushed or ignored work, or that sits outside
~/.agent-harness/{work,checkouts,test-copies}. If any liveness probe fails (process scan, crontab, systemctl, docker,
podman) nothing is removed. Config keys shared with copy_hygiene: max_age_hours, shm_ttl_hours, roots, protect_names,
default_memory.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import stat
import subprocess
import sys
import time

import copy_hygiene as C
import hygiene_safety as S

GB = S.GB
SHM_DIR = "/dev/shm"
PROC = "/proc"
# Never removed by name: semaphores, PostgreSQL segments and Podman's lock segment (browser scratch is not exempt: the
# in-use scan keeps a live one, and crashed-browser leftovers are the thing to reclaim). (An allow-list of
# session-scratch prefixes would be safer still, but nobody has enumerated them; the in-use scan runs inside shm_sweep.)
SHM_SKIP = ("sem.", "PostgreSQL.", "libpod")
COMPOSE_FILES = ("compose.yaml", "compose.yml", "docker-compose.yaml", "docker-compose.yml")


def audit(op: str, row: dict) -> None:
    S.alert("janitor-" + op, row)


# ------------------------------------------------------------------ release
def _remaining_files(path: str, removed: list) -> bool:
    rem = tuple(r.rstrip("/") + "/" for r in removed)
    for dp, dn, fn in os.walk(path):
        dn[:] = [d for d in dn if not (os.path.join(dp, d) + "/").startswith(rem)]
        if fn:
            return True
    return False


def _idle_s(repo: str, now: float) -> float:
    """Seconds since the newest of: file activity in the checkout and its last acquire (index), read fresh."""
    idx = C.load_index()
    used_at = max(float((idx.get(k) or {}).get("last_used") or 0) for k in {repo, os.path.realpath(repo)})
    return now - max(S.newest_activity(repo), used_at)


def regenerable_dirs(root: str, repos: list) -> list:
    """Folders under root, outside every checkout in repos, that can be rebuilt from a manifest beside or inside them:
    `node_modules` whose parent holds a regular `package.json`, and `.venv`/`venv` holding a regular `pyvenv.cfg`.
    Nothing else counts outside a checkout (`build`, `dist`, `out`, `target` and caches are build output only inside a
    checkout, where git says they are ignored; outside one they may be the only copy of something). Never a symlink,
    never a folder that holds a nested repository. Not descended into."""
    def regular(p: str) -> bool:
        try:
            return stat.S_ISREG(os.lstat(p).st_mode)
        except OSError:
            return False
    inside = tuple(r.rstrip("/") + "/" for r in repos)
    out = []
    for dp, dn, _fn in os.walk(root):
        keep = []
        for d in dn:
            full = os.path.join(dp, d)
            if (full + "/").startswith(inside) or d == ".git" or os.path.islink(full):
                continue
            if d == "node_modules" and regular(os.path.join(dp, "package.json")):
                if not S._has_nested_repo(full):
                    out.append(full)
                continue
            if d in (".venv", "venv") and regular(os.path.join(full, "pyvenv.cfg")):
                if not S._has_nested_repo(full):
                    out.append(full)
                continue
            keep.append(d)
        dn[:] = keep
    return sorted(out)


def release(path: str, apply: bool, used=None, refs=None, cfg=None, deadline: "float | None" = None,
            min_idle_s: "float | None" = None, now: "float | None" = None, regenerable: bool = False) -> dict:
    """min_idle_s is the sweep's TTL: it is re-checked per checkout with the lock held (an acquire may have touched the
    checkout since the sweep looked). The in-use and service probes are repeated right before every removal.
    With deletion off nothing is removed: the result says mode "report-only" and lists `would_remove` /
    `would_free_bytes`; `removed` and `freed_bytes` stay empty/0 so nobody reports space that was not freed."""
    now = now or time.time()
    cfg = cfg or C.load_config()
    deleting = bool(apply and C.deletion_enabled(cfg))
    res = {"path": path, "mode": "apply" if deleting else "report-only", "removed": [], "kept": [], "freed_bytes": 0,
           "would_remove": [], "would_free_bytes": 0}
    gone, gone_bytes = [], 0
    def finish() -> dict:
        key = ("removed", "freed_bytes") if deleting else ("would_remove", "would_free_bytes")
        res[key[0]], res[key[1]] = gone, gone_bytes
        return res
    if not S.within_allowed(path):
        res["kept"].append({"path": path, "why": "outside ~/.agent-harness/{work,checkouts,test-copies}"})
        return res
    try:
        used = S.in_use_paths() if used is None else used
        refs = S.service_refs() if refs is None else refs
    except S.ProbeError as e:
        res["kept"].append({"path": path, "why": "liveness probe failed: %s" % e})
        return res
    why = S.protected_name(path, cfg)
    if why:
        res["kept"].append({"path": path, "why": why})
        return res
    why = S.busy(path, used, refs) or ("mount point inside" if S.mounts_under(path) else "")
    if why:
        res["kept"].append({"path": path, "why": why})
        return res
    kept_paths = []
    for repo in S.find_repos(path):
        if deadline is not None and time.time() > deadline:
            res["kept"].append({"path": repo, "why": "time budget exhausted"})
            kept_paths.append(repo)
            continue
        inner = [k for k in kept_paths if k.startswith(repo.rstrip("/") + "/")]
        in_copies = C.under_copies(repo)
        lk = S.lock_nonblocking(repo + ".lock") if in_copies else None   # shared with acquire
        try:
            if in_copies and lk is None:
                why = "locked by a running acquire"
            elif inner:
                why = "holds a kept checkout (%s)" % inner[0]
            else:
                why = S.protected_name(repo, cfg) or S.busy(repo, used, refs)    # per repo, incl. its remote URL
                if not why:
                    ok, why = S.recoverable(repo, deadline)
                    why = "" if ok else why
            if not why and min_idle_s is not None and _idle_s(repo, now) < min_idle_s:
                why = "used since the sweep started"
            if not why and deleting:
                try:
                    used, refs = S.in_use_paths(), S.service_refs()      # fresh, right before the removal
                except S.ProbeError as e:
                    why = "liveness probe failed: %s" % e
                else:
                    why = S.busy(repo, used, refs)
            if why:
                res["kept"].append({"path": repo, "why": why})
                kept_paths.append(repo)
                continue
            size = S.du(repo)
            if deleting:
                done, err = C.safe_remove(repo, "checkout", cfg)         # fresh unit scan + protect_names, fail closed
                if not done:
                    res["kept"].append({"path": repo, "why": "remove failed: " + err})
                    kept_paths.append(repo)
                    continue
                audit("remove-checkout", {"path": repo, "bytes": size})
            gone.append(repo)
            gone_bytes += size
        finally:
            if lk:
                lk.close()
    if regenerable and S.within_allowed(path) and os.path.dirname(os.path.realpath(path)) == os.path.realpath(S.ah("work")):
        # Only a whole session folder (never checkouts/ or test-copies/), and only when the caller judged the session
        # retired or its own: logs and every other file stay, so the folder itself usually stays too.
        repos = [r for r in S.find_repos(path)]
        for d in regenerable_dirs(path, repos):
            if deadline is not None and time.time() > deadline:
                res["kept"].append({"path": d, "why": "time budget exhausted"})
                kept_paths.append(d)
                continue
            why = S.protected_name(d, cfg) or S.busy(d, used, refs) or ("mount point inside" if S.mounts_under(d) else "")
            if not why and deleting:
                try:
                    used, refs = S.in_use_paths(), S.service_refs()
                except S.ProbeError as e:
                    why = "liveness probe failed: %s" % e
                else:
                    why = S.busy(d, used, refs)
            if why:
                res["kept"].append({"path": d, "why": why})
                continue
            size = S.du(d)
            if deleting:
                done, err = C.safe_remove(d, "tree", cfg)
                if not done:
                    res["kept"].append({"path": d, "why": "remove failed: " + err})
                    continue
                audit("remove-regenerable", {"path": d, "bytes": size})
            gone.append(d)
            gone_bytes += size
            res.setdefault("regenerable", []).append(d)
    if os.path.isdir(path) and not kept_paths and not _remaining_files(path, gone) and not S.busy(path, used, refs):
        size = S.du(path)
        if deleting:
            # Only empty folders should remain. Probe again, then remove bottom-up with rmdir (never rmtree): a file
            # written since the checks above (this is the durable work directory) stops the removal.
            try:
                used, refs = S.in_use_paths(), S.service_refs()
            except S.ProbeError as e:
                res["kept"].append({"path": path, "why": "liveness probe failed: %s" % e})
                return finish()
            why = S.busy(path, used, refs) or ("a file appeared in it" if _remaining_files(path, gone) else "")
            if why:
                res["kept"].append({"path": path, "why": why})
                return finish()
            done, err = C.safe_remove(path, "empty-tree", cfg)
            if not done:
                res["kept"].append({"path": path, "why": "remove failed: " + err})
                return finish()
            audit("remove-session-folder", {"path": path, "bytes": size})
        gone.append(path)
        gone_bytes += size
    return finish()


# ------------------------------------------------------------------ sweep
def _process_blob() -> "str | None":
    """Every process command line, one per line. /proc on Linux; `ps -axo command=` where /proc has no processes
    (macOS). None when neither lists any process: the caller must then treat every session as alive."""
    blob, seen = [], False
    for p in os.listdir(PROC) if os.path.isdir(PROC) else []:
        if p.isdigit():
            try:
                with open("%s/%s/cmdline" % (PROC, p), "rb") as f:
                    blob.append(f.read(8192).replace(b"\0", b" ").decode("utf-8", "replace"))
                seen = True
            except OSError:
                pass
    if seen:
        return "\n".join(blob)
    rc, out, _ = S.probe(["ps", "-axo", "command="], 30)
    return out if rc == 0 and out.strip() else None


def live_sessions(names: list, ttl_s: float, now: float) -> set:
    """Session folders that are not retired (session_verdicts gives the reasons). Without any process list at all, every
    session counts as alive (nothing is released on a guess)."""
    return {n for n, why in session_verdicts(names, ttl_s, now).items() if why}


# ------------------------------------------------------------------ session ownership (stream D, goodqa#16947)
# The rules of feat/takeover-cleanup's takeover.session_state that a janitor can check on its own host, without the
# claim file: R1 identity (one WAL flavor, real folders this user owns), R3 quiet past the TTL across WALs (file time AND
# last row stamp, so a backdated touch does not hide a fresh row), app transcripts and Codex rollouts, R4 no process that
# names the session, R5 no open ask, no open ah task, no live bg_job. takeover's R2 (a declared stop or a claim) is NOT
# required here: the janitor removes only recoverable checkouts and regenerable folders, so the worst case of releasing
# a quiet-but-live session is a re-clone, never lost work. Any input that cannot be read keeps the session (not retired).
SKEW_S = 300
TAIL_BYTES = 65536
ASK_SCAN_MAX = 16 << 20


def _wal_dirs(sid: str) -> dict:
    return {"claude": os.path.join(S.home(), ".claude", "wals", sid),
            "codex": os.path.join(S.home(), ".agent-harness", "codex-wals", sid)}


def _dir_state(path: str) -> "tuple[bool, bool]":
    """(exists, ok): ok means a real directory this user owns (not a symlink)."""
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return False, True
    except OSError:
        return True, False
    return True, stat.S_ISDIR(st.st_mode) and st.st_uid == os.getuid()


def _row_epoch(value) -> "float | None":
    if isinstance(value, (int, float)) and value > 0:
        return float(value)
    if not isinstance(value, str) or not value:
        return None
    try:
        import datetime as dt
        return dt.datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return None


def _jsonl_stamps(path: str) -> list:
    """[mtime, last row stamp] of a JSONL file (either may be missing). Raises OSError when it cannot be read."""
    st = os.stat(path)
    out = [st.st_mtime]
    with open(path, "rb") as fh:
        fh.seek(max(0, st.st_size - TAIL_BYTES))
        lines = fh.read(TAIL_BYTES).decode("utf-8", "replace").splitlines()
    for line in reversed(lines):
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if isinstance(row, dict):
            stamp = _row_epoch(row.get("at") or row.get("timestamp"))
            if stamp is not None:
                out.append(stamp)
                break
    return out


def _transcripts(sid: str) -> list:
    """Claude project transcripts (and their subagent files) and Codex rollouts of exactly this session id."""
    h = S.home()
    import glob
    found = (glob.glob(os.path.join(h, ".claude", "projects", "*", sid + ".jsonl"))[:512]
             + glob.glob(os.path.join(h, ".claude", "projects", "*", sid, "subagents", "*.jsonl"))[:512])
    found += [p for p in glob.glob(os.path.join(h, ".codex", "sessions", "*", "*", "*", "rollout-*-%s.jsonl" % sid))[:512]
              if p.endswith("-" + sid + ".jsonl")]
    return found


def _open_asks(wal_dir: str) -> "tuple[list, bool]":
    """(ask ids no ask_resolved row closes, unreadable)."""
    asks, closed = set(), set()
    try:
        names = [n for n in os.listdir(wal_dir) if n == "main.jsonl" or (n.startswith("agent-") and n.endswith(".jsonl"))]
    except OSError:
        return [], True
    for name in names:
        p = os.path.join(wal_dir, name)
        try:
            if os.stat(p).st_size > ASK_SCAN_MAX:
                return [], True
            with open(p, "rb") as fh:
                for raw in fh:
                    if b'"ask' not in raw:
                        continue
                    try:
                        row = json.loads(raw)
                    except ValueError:
                        continue
                    if isinstance(row, dict) and row.get("event") == "ask" and isinstance(row.get("id"), str):
                        asks.add(row["id"])
                    elif isinstance(row, dict) and row.get("event") == "ask_resolved" and isinstance(row.get("ref"), str):
                        closed.add(row["ref"])
        except OSError:
            return [], True
    return sorted(asks - closed), False


_TASKS: "dict | None" = None


def _open_task_sessions() -> "set | None":
    """Session ids that hold an open ah task, or None when the task ledger exists but cannot be read (or ah is missing).
    Read once per process. A missing ledger means no tasks."""
    global _TASKS
    if _TASKS is not None:
        return _TASKS.get("sessions")
    try:
        from pathlib import Path
        import ah  # sibling module in the hooks folder
        # the path ah.store_dir names, built here because store_dir creates the folders (report must write nothing)
        path = Path(S.home()) / ".agent-harness" / "state" / "ah" / "store" / "ledger.jsonl"
        if not path.exists():
            _TASKS = {"sessions": set()}
        else:
            with open(path, "rb"):
                pass                                          # readable (ah._ledger hides an OSError as "no rows")
            rows = ah.task_list(Path(S.home()), open_only=True)["tasks"]
            _TASKS = {"sessions": {str(t.get("session")) for t in rows if t.get("session")}}
    except Exception:  # noqa: BLE001 -- an unreadable ledger is unknown, never "no tasks"
        _TASKS = {"sessions": None}
    return _TASKS["sessions"]


def _bg_jobs_live(sid: str, blob: str) -> list:
    import glob
    base = S.ah("work", sid)
    live = []
    for rec in (glob.glob(os.path.join(base, "*", "bg-jobs", "*.json"))[:256] + glob.glob(os.path.join(base, "bg-jobs", "*.json"))[:256]):
        try:
            with open(rec, "rb") as fh:
                data = json.loads(fh.read(65536))
        except (OSError, ValueError):
            continue
        if isinstance(data, dict) and isinstance(data.get("pid"), int) and isinstance(data.get("nonce"), str) \
                and data["nonce"] and data["nonce"] in blob:
            live.append(os.path.basename(rec))
    return live


def session_verdict(sid: str, ttl_s: float, now: float, blob: "str | None") -> list:
    """[] when the session is retired (its work folder may be released), else the reasons it is not."""
    if blob is None:
        return ["no_process_list"]
    reasons = []
    if len(sid) >= 8 and sid in blob:
        reasons.append("session_live")
    flavors, bad = [], False
    for flavor, d in _wal_dirs(sid).items():
        exists, ok = _dir_state(d)
        bad = bad or not ok
        if exists and ok and os.path.isfile(os.path.join(d, "main.jsonl")):
            flavors.append(flavor)
    if bad:
        reasons.append("bad_dir")
    if len(flavors) > 1:
        reasons.append("ambiguous_session")
    stamps = []
    try:
        for flavor in flavors:
            d = _wal_dirs(sid)[flavor]
            for n in os.listdir(d):
                if n == "main.jsonl" or (n.startswith("agent-") and n.endswith(".jsonl")) or n == "continuation.json":
                    stamps += _jsonl_stamps(os.path.join(d, n)) if n.endswith(".jsonl") else [os.stat(os.path.join(d, n)).st_mtime]
            asks, unreadable = _open_asks(d)
            if unreadable:
                reasons.append("asks_unreadable")
            elif asks:
                reasons.append("open_work")
        for t in _transcripts(sid):
            stamps += _jsonl_stamps(t)
    except OSError:
        reasons.append("activity_unreadable")
    if stamps:
        newest = max(stamps)
        if newest > now + SKEW_S:
            reasons.append("clock_skew")
        elif now - newest < ttl_s:
            reasons.append("recent_activity")
    elif "activity_unreadable" not in reasons:
        # No WAL and no transcript of this session on THIS host: it may be a session of another machine (a Mac session
        # whose agents work on t2-dev) or a folder an agent named itself. Silence here is not retirement (takeover R1:
        # identity first), so the folder is kept and listed in `report` for its owner to release.
        reasons.append("no_local_record")
    tasks = _open_task_sessions()
    if tasks is None:
        reasons.append("tasks_unreadable")
    elif sid in tasks:
        reasons.append("open_work")
    if _bg_jobs_live(sid, blob):
        reasons.append("open_work")
    return list(dict.fromkeys(reasons))


def session_verdicts(names: list, ttl_s: float, now: float) -> dict:
    """{name: reasons} for each session folder name; one process scan for all."""
    blob = _process_blob()
    return {n: session_verdict(n, ttl_s, now, blob) for n in names}


def shm_sweep(apply: bool, cfg: dict, now: float) -> list:
    """The process scan is taken HERE (this runs last in a sweep, minutes after its start): a segment a process opened
    or mapped meanwhile is kept, and a failed scan keeps everything."""
    rows = []
    uid = os.getuid()
    deleting = bool(apply and C.deletion_enabled(cfg))
    try:
        names = os.listdir(SHM_DIR)
    except OSError:
        return rows
    try:
        used = S.in_use_paths()
    except S.ProbeError as e:
        return [{"path": SHM_DIR, "action": "kept: liveness probe failed: %s" % e}]
    for e in names:
        p = os.path.join(SHM_DIR, e)
        try:
            st = os.lstat(p)
            if st.st_uid != uid or e.startswith(SHM_SKIP):
                continue
            isdir = stat.S_ISDIR(st.st_mode)
            idle_h = (now - max(st.st_mtime, st.st_ctime, S.newest_activity(p) if isdir else 0)) / 3600
            if idle_h < cfg["shm_ttl_hours"]:
                continue
            if S.is_used(p, used):
                rows.append({"path": p, "action": "kept: open or mapped"})
                continue
            size = S.du(p) if isdir else st.st_blocks * 512
            action = "would remove"
            if deleting:
                try:
                    if isdir:
                        done, err = S.remove_tree(p)
                        if not done:
                            raise OSError(err)
                    else:
                        os.unlink(p)
                    audit("remove-shm", {"path": p, "bytes": size})
                    action = "removed"
                except OSError as err:
                    action = "kept: remove failed (%s)" % str(err)[:80]
            rows.append({"path": p, "bytes": size, "idle_hours": round(idle_h, 1), "action": action})
        except OSError:
            continue
    return rows


def uncapped_containers() -> list:
    out = []
    for tool in ("docker", "podman"):
        rc, ids, _ = S.probe([tool, "ps", "-q"])
        if rc != 0 or not ids.split():
            continue
        rc, o, _ = S.probe([tool, "inspect", "-f", "{{.Name}} {{.HostConfig.Memory}} {{.Config.Image}}"] + ids.split(), 120)
        for l in o.splitlines() if rc == 0 else []:
            f = l.split()
            if len(f) >= 3 and f[1] == "0":
                out.append({"tool": tool, "name": f[0].lstrip("/"), "image": f[2]})
    return out


def _mirror_worktree_entries(m: str) -> "list | None":
    """Names under <mirror>/worktrees (git's admin entries); None when they cannot be listed. An entry exists until
    `git worktree remove` or prune drops it, so a worktree whose folder is merely unmounted or moved still counts."""
    d = os.path.join(m, "worktrees")
    try:
        return sorted(os.listdir(d))
    except FileNotFoundError:
        return []
    except OSError:
        return None


def _mirror_unpushed(m: str) -> str:
    """'' when every commit reachable from any local ref of the mirror (all refs except refs/remotes/*: heads, tags,
    notes, refs/backup/*, anything) or from HEAD is on what its origin advertises RIGHT NOW (fresh ls-remote), else why
    not. Any failure answers with a reason: the mirror is kept."""
    rc, remotes, _ = S.git(m, "remote")
    names = remotes.split()
    if rc != 0 or not names:
        return "no remote to compare with"
    advertised = set()
    for name in names:
        rc, url, _ = S.git(m, "remote", "get-url", name)
        if rc != 0 or not url.strip():
            return "cannot read the remote URL"
        rc, adv, _ = S.git(m, "ls-remote", url.strip(), t=300)
        if rc != 0:
            return "ls-remote failed (cannot prove its commits are on the remote)"
        advertised |= {l.split()[0] for l in adv.splitlines() if l.strip()}
    # Offline throughout: the mirror is a partial clone, and checking must not download what it is about to delete.
    # Local work = every ref except refs/remotes/* (those are copies of what the remote had: a branch deleted upstream
    # after a squash-merge must not pin the mirror for ever), plus HEAD. A ref outside heads/tags (refs/backup/*, notes)
    # or a lightweight tag is how work is parked, so each counts; a lightweight tag deleted upstream pins the mirror only
    # when its commit is on no advertised ref, which errs on the safe side. An ANNOTATED tag that no remote ref carries
    # is local-only too (below).
    # HEAD goes in as a commit id and only when it resolves: with an unborn HEAD (the usual state of a mirror) git 2.43
    # answers `rev-list --count --branches HEAD` with 0 and rc 0, which would read as "nothing unpushed".
    rc, head, _ = S.git(m, "rev-parse", "--verify", "--quiet", "HEAD^{commit}")
    rc3, allrefs, _ = S.git(m, "for-each-ref", "--format=%(refname) %(objectname)")
    rc2, tagrefs, _ = S.git(m, "for-each-ref", "--format=%(objectname)", "refs/tags")
    if rc3 != 0 or rc2 != 0:
        return "cannot list the refs"
    tips = [l.split()[-1] for l in allrefs.splitlines() if l.strip() and not l.startswith("refs/remotes/")]
    if rc == 0 and head.strip():
        tips.append(head.strip())
    try:
        with S.offline_view(m) as v:
            ty = v.types(advertised)
            if ty is None:
                return "object check failed or timed out (kept)"
            have = {i for i, k in ty.items() if k == "commit"}
            n = v.unpushed(tips, have)
            if n is None:
                return "object check failed or timed out (kept)"
            if n != 0:
                return "it holds commits that are on no remote ref"
            tty = v.types(set(tagrefs.split()) | set(tips))
            if tty is None:
                return "tag check failed or timed out (kept)"
    except S.ProbeError as e:
        return "offline check unavailable (%s)" % e
    if any(k == "tag" and i not in advertised for i, k in tty.items()):
        return "it holds an annotated tag that is on no remote ref"
    # rev-list skips a ref pointing straight at a blob or a tree, so such a ref (parked by hand) keeps the mirror too.
    if any(k not in ("commit", "tag") for i, k in tty.items() if i in set(tips) and i not in advertised):
        return "it holds a non-commit object under a local ref"
    return ""


def mirror_sweep(apply: bool, cfg: dict, now: float) -> dict:
    """Count and size of ~/.agent-harness/mirrors; a mirror is removed after mirror_ttl_days idle only when it has no
    worktree admin entry at all, every commit reachable from any of its refs (all but refs/remotes/*) or HEAD is on its
    origin (fresh ls-remote), nothing uses it, no service references it and deletion is on (the shared switch)."""
    root = os.path.realpath(S.ah("mirrors"))
    deleting = bool(apply and C.deletion_enabled(cfg))
    ttl = cfg["mirror_ttl_days"] * 86400
    out = {"count": 0, "bytes": 0, "ttl_days": cfg["mirror_ttl_days"], "rows": []}
    for host in sorted(S._ls(root)):
        hd = os.path.join(root, host)
        if os.path.islink(hd) or not os.path.isdir(hd):
            continue
        for e in sorted(S._ls(hd)):
            m = os.path.join(hd, e)
            if not e.endswith(".git") or os.path.islink(m) or not os.path.isdir(m):
                continue
            size = S.du(m)
            row = {"path": m, "bytes": size, "idle_days": round((now - S.newest_activity(m)) / 86400, 1), "action": "keep"}
            out["count"] += 1
            out["bytes"] += size
            out["rows"].append(row)
            if now - S.newest_activity(m) < ttl:
                continue
            row["action"] = _drop_mirror(m, row, deleting, ttl, now, cfg)
    return out


def _drop_mirror(m: str, row: dict, deleting: bool, ttl: float, now: float, cfg: dict) -> str:
    lk = S.lock_nonblocking(m + ".lock")                  # the lock acquire holds while it fetches or adds a worktree
    if lk is None:
        return "kept: locked by a running acquire"
    try:
        if now - S.newest_activity(m) < ttl:
            return "kept: used since the sweep started"
        why = S.protected_name(m, cfg)
        if why:
            return "kept: " + why
        entries = _mirror_worktree_entries(m)
        if entries is None:
            return "kept: cannot list its worktrees"
        if entries:
            # Any admin entry keeps it (so each worktrees/<k>/HEAD is covered too): a copy's commits live only here.
            return "kept: %d registered worktree(s) exist" % len(entries)
        why = _mirror_unpushed(m)
        if why:
            return "kept: " + why
        try:
            used, refs = S.in_use_paths(), S.service_refs()
        except S.ProbeError as e:
            return "kept: liveness probe failed: %s" % e
        why = S.busy(m, used, refs)
        if why:
            return "kept: " + why
        if not deleting:
            return "would remove (report-only)"
        done, err = C.safe_remove(m, "tree", cfg)
        if not done:
            return "kept: remove failed: " + err
        audit("remove-mirror", {"path": m, "bytes": row["bytes"]})
        return "removed"
    finally:
        lk.close()


def sweep(apply: bool, cfg=None, now=None) -> dict:
    cfg = cfg or C.load_config()
    now = now or time.time()
    deleting = bool(apply and C.deletion_enabled(cfg))
    ttl = cfg["max_age_hours"] * 3600
    res = {"mode": "apply" if deleting else "report-only", "delete_enabled": C.deletion_enabled(cfg), "released": [],
           "copies": [], "shm": [], "mirrors": {"count": 0, "bytes": 0, "rows": []}, "freed_gb": 0.0,
           "would_free_gb": 0.0, "uncapped_containers": [], "probe_error": ""}
    if apply and not deleting:
        res["note"] = ("deletion is OFF: report-only. The owner enables it with \"reaper_delete_enabled\": true in "
                       + C.config_path())
    try:
        used, refs = S.in_use_paths(), S.service_refs()
    except S.ProbeError as e:           # keep everything and exit 0: a failed probe is a report, not a crash
        res["probe_error"] = str(e)
        res["uncapped_containers"] = uncapped_containers()
        audit("sweep", {"mode": "probe-failed", "error": str(e)[:200]})
        return res
    roots = []
    for r in cfg["roots"]:
        if S.within_allowed(r, strictly_inside=False):
            roots.append(r)
        else:
            S.alert_daily("janitor-root-ignored", r,
                          {"root": r, "why": "outside ~/.agent-harness/{work,checkouts,test-copies}"},
                          dedupe="root-ignored")
    for root in roots:
        names = [e for e in sorted(S._ls(root)) if os.path.isdir(os.path.join(root, e)) and not os.path.islink(os.path.join(root, e))]
        verdicts = session_verdicts(names, ttl, now)
        for e in names:
            p = os.path.join(root, e)
            why = verdicts.get(e) or []
            if why:
                res["released"].append({"path": p, "mode": "apply" if deleting else "report-only", "removed": [], "freed_bytes": 0,
                                        "would_remove": [], "would_free_bytes": 0, "session_reasons": why,
                                        "kept": [{"path": p, "why": "session is alive or recent (%s)" % ", ".join(why)}]})
            elif now - S.newest_activity(p) >= ttl:
                res["released"].append(release(p, apply, used, refs, cfg, min_idle_s=ttl, now=now, regenerable=True))
    co = S.ah("checkouts")
    for e in sorted(S._ls(co)):
        for k in sorted(S._ls(os.path.join(co, e))):
            p = os.path.join(co, e, k)
            if os.path.isdir(p) and not os.path.islink(p) and now - S.newest_activity(p) >= ttl:
                res["released"].append(release(p, apply, used, refs, cfg, min_idle_s=ttl, now=now))
    res["copies"] = C.reap(apply=apply, cfg=cfg, now=now)["copies"]
    res["mirrors"] = mirror_sweep(apply, cfg, now)
    res["shm"] = shm_sweep(apply, cfg, now)
    res["uncapped_containers"] = uncapped_containers()
    res["freed_gb"] = round(sum(r["freed_bytes"] for r in res["released"]) / GB, 2)
    res["would_free_gb"] = round(sum(r.get("would_free_bytes", 0) for r in res["released"]) / GB, 2)
    audit("sweep", {"mode": res["mode"], "freed_gb": res["freed_gb"], "would_free_gb": res["would_free_gb"],
                    "uncapped": len(res["uncapped_containers"])})
    return res


# ------------------------------------------------------------------ report (S6: who holds the space)
SESSION_BUDGET_GB = 15.0


def _session_budget_gb() -> float:
    """session_budget_gb from copy-hygiene.json (read raw: copy_hygiene's normalize keeps only its own keys)."""
    try:
        with open(C.config_path()) as fh:
            v = float(json.load(fh).get("session_budget_gb"))
        return v if v > 0 else SESSION_BUDGET_GB
    except (OSError, ValueError, TypeError, AttributeError):
        return SESSION_BUDGET_GB


NEXT_STEPS = (
    ("no_process_list", "the process list could not be read on this host; rerun when ps or /proc works"),
    ("session_live", "a running process carries this session id; nothing to do until it exits"),
    ("open_work", "the session has open asks, open ah tasks or live bg jobs; its owner resolves or hands them off"),
    ("no_local_record", "no WAL or transcript of this session on this host; its owner releases it from the host that "
                        "holds its records, or a ruling names it"),
    ("recent_activity", "active within max_age_hours; it is reconsidered after the quiet window"),
)


def _next_step(why: list) -> "str | None":
    """What would let a kept folder be released (the first matching reason wins); None for a retired one."""
    if not why:
        return None
    for reason, text in NEXT_STEPS:
        if reason in why:
            return text
    return "a session record could not be read or is ambiguous (%s); inspect it by hand" % ",".join(why)


def report(cfg=None, now=None) -> dict:
    """Read only. One row per session folder of each work root: the ownership verdict and its reasons, total bytes,
    regenerable bytes (what release would rebuild-free once the session is retired), checkouts, and whether the folder
    is over session_budget_gb. Rows are sorted by size; each names the sanctioned command for it."""
    cfg = cfg or C.load_config()
    now = now or time.time()
    ttl = cfg["max_age_hours"] * 3600
    budget = _session_budget_gb()
    rows = []
    for root in cfg["roots"]:
        if not S.within_allowed(root, strictly_inside=False):
            continue
        names = [e for e in sorted(S._ls(root)) if os.path.isdir(os.path.join(root, e)) and not os.path.islink(os.path.join(root, e))]
        verdicts = session_verdicts(names, ttl, now)
        for e in names:
            p = os.path.join(root, e)
            repos = S.find_repos(p)
            regen = regenerable_dirs(p, repos)
            size = S.du(p)
            why = verdicts.get(e) or []
            rows.append({"session": e, "path": p, "state": "retired" if not why else "kept", "reasons": why,
                         "bytes": size, "regenerable_bytes": sum(S.du(d) for d in regen), "checkouts": len(repos),
                         "over_budget": size > budget * GB,
                         # only a retired row gets a command: release refuses every other one
                         "command": None if why else "python3 -I %s release --path %s" % (os.path.abspath(__file__), p),
                         "next": _next_step(why)})
    rows.sort(key=lambda r: -r["bytes"])
    return {"budget_gb": budget, "sessions": rows, "total_gb": round(sum(r["bytes"] for r in rows) / GB, 2),
            "retired_gb": round(sum(r["bytes"] for r in rows if r["state"] == "retired") / GB, 2)}


# ------------------------------------------------------------------ pretool: container memory caps
RUN_VALUE_OPTS = {"-e", "--env", "-v", "--volume", "-p", "--publish", "--name", "-m", "--memory", "--memory-swap",
                  "--memory-reservation", "--network", "--net", "-w", "--workdir", "-u", "--user", "--entrypoint", "-l",
                  "--label", "--label-file", "--env-file", "--cpus", "--cpu-shares", "--restart", "--add-host",
                  "--device", "--mount", "--tmpfs", "--shm-size", "--ulimit", "--platform", "--pull", "--hostname", "-h",
                  "--dns", "--cap-add", "--cap-drop", "--security-opt", "--cgroup-parent", "--pid", "--ipc",
                  "--log-driver", "--log-opt", "--health-cmd", "--group-add", "--runtime", "--gpus", "--expose", "--link",
                  "--volumes-from", "--stop-signal", "--stop-timeout", "--sysctl", "--domainname", "--ip", "--mac-address",
                  "--pids-limit", "--cpuset-cpus", "-a", "--attach", "--cidfile", "--detach-keys", "--annotation",
                  "--blkio-weight", "--userns", "--uts", "--cgroupns", "--isolation", "--kernel-memory", "--oom-score-adj",
                  "--storage-opt", "--init-path", "--health-interval", "--health-retries", "--health-timeout",
                  "--health-start-period", "--tz", "--secret", "--pod", "--image-volume"}
SHORT_VALUE = set("evpmwulhac")
GLOBAL_VALUE = {"-H", "--host", "--context", "-c", "-l", "--log-level", "--config", "--tlscacert", "--tlscert", "--tlskey",
                "--connection", "--identity", "--url", "--root", "--runroot", "--storage-driver"}
COMPOSE_VALUE = {"-f", "--file", "-p", "--project-name", "--profile", "--env-file", "--project-directory", "--ansi",
                 "--parallel", "--progress"}
MEM_HINT = re.compile(r"\b(mem_limit|memory|mem_reservation|memswap_limit)\s*:", re.I)


def parse_run(args: list) -> dict:
    """Options of a `docker run|create` line, stopping at the image name (everything after it is the container's command)."""
    opts, i, image = [], 0, ""
    while i < len(args):
        a = args[i]
        if a == "--":
            image = args[i + 1] if i + 1 < len(args) else ""
            break
        if a.startswith("--"):
            flag, eq, val = a.partition("=")
            if eq:
                opts.append((flag, val)); i += 1
            elif flag in RUN_VALUE_OPTS:
                opts.append((flag, args[i + 1] if i + 1 < len(args) else "")); i += 2
            else:
                opts.append((flag, "")); i += 1
        elif a.startswith("-") and a != "-":
            j, consumed = 1, 1
            while j < len(a):
                if a[j] in SHORT_VALUE:
                    rest = a[j + 1:].lstrip("=")
                    if rest:
                        opts.append(("-" + a[j], rest))
                    else:
                        opts.append(("-" + a[j], args[i + 1] if i + 1 < len(args) else "")); consumed = 2
                    break
                j += 1
            i += consumed
        else:
            image = a
            break
    return {"opts": opts, "image": image}


def _capped(val: str) -> bool:
    return bool(val) and not re.fullmatch(r"0+[bkmg]?b?", val.strip(), re.I)


def run_problem(words: list, cwd: str, cfg: dict) -> str:
    """'' or the denial message for one `run`/`create` command (words after the subcommand)."""
    p = parse_run(words)
    mem = [v for f, v in p["opts"] if f in ("-m", "--memory")]
    if not any(_capped(v) for v in mem):
        return ("Container started without a memory limit. Uncapped test containers (Elasticsearch/Java) caused "
                "~895k OOM kills on t2-dev in Nov 2026. Add `--memory %s --memory-swap %s` (or a size that fits "
                "the job)." % (cfg["default_memory"], cfg["default_memory"]))
    if re.search(r"elasticsearch|opensearch", p["image"], re.I):
        envs = [v for f, v in p["opts"] if f in ("-e", "--env")]
        for f, v in p["opts"]:
            if f == "--env-file":
                try:
                    with open(os.path.join(cwd, v) if not os.path.isabs(v) else v, errors="replace") as fh:
                        envs += fh.read(65536).splitlines()
                except OSError:
                    return ""                 # cannot read it: fail open
        if not any("ES_JAVA_OPTS" in e or "OPENSEARCH_JAVA_OPTS" in e for e in envs):
            return ("Elasticsearch/OpenSearch without a heap cap. Add `-e ES_JAVA_OPTS='-Xms1g -Xmx1g'` "
                    "(heap at most half of --memory).")
    return ""


def compose_problem(args: list, cwd: str, cfg: dict) -> str:
    files, i, sub = [], 0, ""
    while i < len(args):
        a = args[i]
        flag, eq, val = a.partition("=")
        if a.startswith("-"):
            if flag in COMPOSE_VALUE:
                v = val if eq else (args[i + 1] if i + 1 < len(args) else "")
                if flag in ("-f", "--file"):
                    files.append(v)
                i += 1 if eq else 2
            else:
                i += 1
        else:
            sub = a
            break
    if sub not in ("up", "run", "create"):
        return ""
    found = [f for f in (files or [os.path.join(cwd, n) for n in COMPOSE_FILES]) if os.path.isfile(
        f if os.path.isabs(f) else os.path.join(cwd, f))]
    if not found:
        return ""
    for f in found:
        try:
            with open(f if os.path.isabs(f) else os.path.join(cwd, f), errors="replace") as fh:
                if MEM_HINT.search(fh.read(262144)):
                    return ""
        except OSError:
            return ""
    return ("Compose services without a memory limit. Add `mem_limit: %s` (or deploy.resources.limits.memory) to each "
            "service in %s; uncapped test containers caused ~895k OOM kills on t2-dev in Nov 2026."
            % (cfg["default_memory"], ", ".join(os.path.basename(f) for f in found)))


def command_problem(words: list, cwd: str, cfg: dict) -> str:
    name = os.path.basename(words[0])
    if name in ("docker-compose", "podman-compose"):
        return compose_problem(words[1:], cwd, cfg)
    if name not in ("docker", "podman"):
        return ""
    i = 1
    while i < len(words) and words[i].startswith("-"):
        i += 2 if words[i] in GLOBAL_VALUE else 1
    sub = words[i:]
    if sub[:1] == ["container"]:
        sub = sub[1:]
    if sub[:1] == ["compose"]:
        return compose_problem(sub[1:], cwd, cfg)
    if sub[:1] in (["run"], ["create"]):
        return run_problem(sub[1:], cwd, cfg)
    return ""


def pretool(event: dict, cfg=None) -> "tuple[int, str]":
    try:
        if event.get("tool_name") != "Bash":
            return 0, ""
        cfg = cfg or C.load_config()
        cmd = str((event.get("tool_input") or {}).get("command") or "")
        cwd = str(event.get("cwd") or os.getcwd())
        for words in S.simple_commands(cmd):
            msg = command_problem(words, cwd, cfg)
            if msg:
                return 2, msg
        return 0, ""
    except Exception:  # noqa: BLE001  fail open
        return 0, ""


# ------------------------------------------------------------------ CLI
SESSION_END_ENV = "HARNESS_JANITOR_SESSION_END"   # set only by session-end for its own session (accident prevention,
# not a boundary: an agent could set it, and then gains only what `release` did before this check existed)


def session_of(path: str) -> str:
    """The session folder name when path is ~/.agent-harness/work/<id> or inside it, else ''."""
    work = os.path.realpath(S.ah("work")).rstrip("/") + "/"
    rp = os.path.realpath(path)
    if not (rp + "/").startswith(work) or rp + "/" == work:
        return ""
    return rp[len(work):].split("/")[0]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("release"); s.add_argument("--session"); s.add_argument("--path"); s.add_argument("--apply", action="store_true")
    s.add_argument("--budget", type=float, default=0, help="stop starting new checks after this many seconds")
    sub.add_parser("session-end")
    s = sub.add_parser("sweep"); s.add_argument("--apply", action="store_true"); s.add_argument("--json", action="store_true")
    sub.add_parser("pretool")
    sub.add_parser("report", help="read only: session folders by size, ownership verdict, regenerable bytes, budget")
    a = ap.parse_args(argv)
    if a.cmd == "report":
        print(json.dumps(report(), indent=1))
        return 0
    if a.cmd == "release":
        if not (a.session or a.path):
            ap.error("--session or --path")
        try:
            p = os.path.realpath(a.path) if a.path else S.ah("work", S.safe_key(a.session))
        except ValueError as e:
            ap.error(str(e))
        if not S.within_allowed(p):
            ap.error("path must be inside ~/.agent-harness/{work,checkouts,test-copies}")
        sid = session_of(p)
        own = bool(sid) and os.environ.get(SESSION_END_ENV) == sid
        if sid and not own:
            cfg = C.load_config()
            why = session_verdict(sid, cfg["max_age_hours"] * 3600, time.time(), _process_blob())
            if why:
                print(json.dumps({"path": p, "mode": "report-only", "removed": [], "freed_bytes": 0, "would_remove": [],
                                  "would_free_bytes": 0, "session_reasons": why,
                                  "kept": [{"path": p, "why": "session %s is not retired (%s)" % (sid, ", ".join(why))}]},
                                 indent=1))
                return 0
        r = release(p, a.apply, deadline=time.time() + a.budget if a.budget else None, regenerable=bool(sid))
        print(json.dumps(r, indent=1))
        return 0
    if a.cmd == "session-end":
        # Claude Code SessionEnd hook: never blocks. The work (process scan, systemctl, ls-remote per repo) can take
        # minutes, so it runs detached with its own time budget; with deletion off there is nothing to do.
        try:
            ev = json.load(sys.stdin)
            sid = S.safe_key(ev.get("session_id", ""))
            if C.deletion_enabled(C.load_config()) and os.path.isdir(S.ah("work", sid)):
                subprocess.Popen([sys.executable, "-B", os.path.abspath(__file__), "release", "--session", sid, "--apply",
                                  "--budget", "600"], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL, start_new_session=True, close_fds=True,
                                 env=dict(os.environ, **{SESSION_END_ENV: sid}))
        except Exception:  # noqa: BLE001
            pass
        return 0
    if a.cmd == "sweep":
        r = sweep(a.apply)
        if a.json:
            print(json.dumps(r, indent=1))
        else:
            print("sweep (%s): " % r["mode"] + ("freed %.2f GB" % r["freed_gb"] if r["mode"] == "apply"
                  else "nothing removed, would free %.2f GB" % r["would_free_gb"]) + ", %d folders checked, %d test copies, %d shm entries, %d mirrors (%.2f GB), %d uncapped containers%s" % (
                len(r["released"]), len(r["copies"]), len(r["shm"]),
                r["mirrors"]["count"], r["mirrors"]["bytes"] / GB, len(r["uncapped_containers"]),
                "; kept everything, probe failed: " + r["probe_error"] if r["probe_error"] else ""))
            if r.get("note"):
                print(r["note"])
        return 0
    if a.cmd == "pretool":
        try:
            ev = json.load(sys.stdin)
        except ValueError:
            return 0
        code, msg = pretool(ev if isinstance(ev, dict) else {})
        if code:
            print(msg, file=sys.stderr)
        return code
    return 0


if __name__ == "__main__":
    sys.exit(main())
