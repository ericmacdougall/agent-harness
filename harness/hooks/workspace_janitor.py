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
SHM_SKIP = ("sem.", "PostgreSQL.")        # semaphores and PostgreSQL segments: never removed by name
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


def release(path: str, apply: bool, used=None, refs=None, cfg=None, deadline: "float | None" = None) -> dict:
    cfg = cfg or C.load_config()
    res = {"path": path, "removed": [], "kept": [], "freed_bytes": 0}
    if not S.within_allowed(path):
        res["kept"].append({"path": path, "why": "outside ~/.agent-harness/{work,checkouts,test-copies}"})
        return res
    try:
        used = S.in_use_paths() if used is None else used
        refs = S.service_refs() if refs is None else refs
    except S.ProbeError as e:
        res["kept"].append({"path": path, "why": "liveness probe failed: %s" % e})
        return res
    deleting = bool(apply and C.deletion_enabled(cfg))
    if any(n in path.lower() for n in cfg["protect_names"]):
        res["kept"].append({"path": path, "why": "protected name"})
        return res
    why = S.busy(path, used, refs) or ("mount point inside" if S.mounts_under(path) else "")
    if why:
        res["kept"].append({"path": path, "why": why})
        return res
    copies = C.copies_root() + os.sep
    kept_paths = []
    for repo in S.find_repos(path):
        if deadline is not None and time.time() > deadline:
            res["kept"].append({"path": repo, "why": "time budget exhausted"})
            kept_paths.append(repo)
            continue
        inner = [k for k in kept_paths if k.startswith(repo.rstrip("/") + "/")]
        lk = S.lock_nonblocking(repo + ".lock") if repo.startswith(copies) else None   # shared with acquire
        try:
            if repo.startswith(copies) and lk is None:
                why = "locked by a running acquire"
            elif inner:
                why = "holds a kept checkout (%s)" % inner[0]
            else:
                why = S.busy(repo, used, refs)
                if not why:
                    ok, why = S.recoverable(repo, deadline)
                    why = "" if ok else why
            if why:
                res["kept"].append({"path": repo, "why": why})
                kept_paths.append(repo)
                continue
            size = S.du(repo)
            if deleting:
                done, err = S.remove_checkout(repo)
                if not done:
                    res["kept"].append({"path": repo, "why": "remove failed: " + err})
                    kept_paths.append(repo)
                    continue
                audit("remove-checkout", {"path": repo, "bytes": size})
            res["removed"].append(repo)
            res["freed_bytes"] += size
        finally:
            if lk:
                lk.close()
    if os.path.isdir(path) and not kept_paths and not _remaining_files(path, res["removed"]) and not S.busy(path, used, refs):
        size = S.du(path)
        if deleting:
            done, err = S.remove_tree(path)
            if not done:
                res["kept"].append({"path": path, "why": "remove failed: " + err})
                return res
            audit("remove-session-folder", {"path": path, "bytes": size})
        res["removed"].append(path)
        res["freed_bytes"] += size
    return res


# ------------------------------------------------------------------ sweep
def live_sessions(names: list, ttl_s: float, now: float) -> set:
    """Session folders whose Claude process is alive (the id is on a command line) or whose WAL is newer than the TTL."""
    blob = ""
    for p in os.listdir("/proc") if os.path.isdir("/proc") else []:
        if p.isdigit():
            try:
                with open("/proc/%s/cmdline" % p, "rb") as f:
                    blob += f.read(8192).replace(b"\0", b" ").decode("utf-8", "replace") + "\n"
            except OSError:
                pass
    live = set()
    for n in names:
        if len(n) >= 8 and n in blob:
            live.add(n)
            continue
        wal = os.path.join(S.home(), ".claude", "wals", n)
        try:
            if os.path.isdir(wal) and now - S.newest_activity(wal) < ttl_s:
                live.add(n)
        except OSError:
            pass
    return live


def shm_sweep(apply: bool, used: set, cfg: dict, now: float) -> list:
    rows = []
    uid = os.getuid()
    deleting = bool(apply and C.deletion_enabled(cfg))
    try:
        names = os.listdir(SHM_DIR)
    except OSError:
        return rows
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


def sweep(apply: bool, cfg=None, now=None) -> dict:
    cfg = cfg or C.load_config()
    now = now or time.time()
    deleting = bool(apply and C.deletion_enabled(cfg))
    ttl = cfg["max_age_hours"] * 3600
    res = {"mode": "apply" if deleting else "report-only", "delete_enabled": C.deletion_enabled(cfg), "released": [],
           "copies": [], "shm": [], "freed_gb": 0.0, "uncapped_containers": [], "probe_error": ""}
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
    roots = [r for r in cfg["roots"] if S.within_allowed(r, strictly_inside=False)]
    for root in roots:
        names = [e for e in sorted(S._ls(root)) if os.path.isdir(os.path.join(root, e)) and not os.path.islink(os.path.join(root, e))]
        alive = live_sessions(names, ttl, now)
        for e in names:
            p = os.path.join(root, e)
            if e in alive:
                res["released"].append({"path": p, "removed": [], "freed_bytes": 0, "kept": [{"path": p, "why": "session is alive or recent"}]})
            elif now - S.newest_activity(p) >= ttl:
                res["released"].append(release(p, apply, used, refs, cfg))
    co = S.ah("checkouts")
    for e in sorted(S._ls(co)):
        for k in sorted(S._ls(os.path.join(co, e))):
            p = os.path.join(co, e, k)
            if os.path.isdir(p) and not os.path.islink(p) and now - S.newest_activity(p) >= ttl:
                res["released"].append(release(p, apply, used, refs, cfg))
    res["copies"] = C.reap(apply=apply, cfg=cfg, now=now)["copies"]
    res["shm"] = shm_sweep(apply, used, cfg, now)
    res["uncapped_containers"] = uncapped_containers()
    res["freed_gb"] = round(sum(r["freed_bytes"] for r in res["released"]) / GB, 2)
    audit("sweep", {"mode": res["mode"], "freed_gb": res["freed_gb"], "uncapped": len(res["uncapped_containers"])})
    return res


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
def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("release"); s.add_argument("--session"); s.add_argument("--path"); s.add_argument("--apply", action="store_true")
    s.add_argument("--budget", type=float, default=0, help="stop starting new checks after this many seconds")
    sub.add_parser("session-end")
    s = sub.add_parser("sweep"); s.add_argument("--apply", action="store_true"); s.add_argument("--json", action="store_true")
    sub.add_parser("pretool")
    a = ap.parse_args(argv)
    if a.cmd == "release":
        if not (a.session or a.path):
            ap.error("--session or --path")
        try:
            p = os.path.realpath(a.path) if a.path else S.ah("work", S.safe_key(a.session))
        except ValueError as e:
            ap.error(str(e))
        if not S.within_allowed(p):
            ap.error("path must be inside ~/.agent-harness/{work,checkouts,test-copies}")
        r = release(p, a.apply, deadline=time.time() + a.budget if a.budget else None)
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
                                 stderr=subprocess.DEVNULL, start_new_session=True, close_fds=True)
        except Exception:  # noqa: BLE001
            pass
        return 0
    if a.cmd == "sweep":
        r = sweep(a.apply)
        if a.json:
            print(json.dumps(r, indent=1))
        else:
            print("sweep (%s): freed %.2f GB, %d folders checked, %d test copies, %d shm entries, %d uncapped containers%s" % (
                r["mode"], r["freed_gb"], len(r["released"]), len(r["copies"]), len(r["shm"]), len(r["uncapped_containers"]),
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
