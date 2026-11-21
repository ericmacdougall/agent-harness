#!/usr/bin/env python3
"""Workspace janitor: shared mirrors + reusable checkouts, cleanup when a session ends, a TTL sweep, and RAM/
container hygiene. Companion to copy_hygiene.py (PR #284), which owns per-PR test copies and the disk floor.

WHY. On 2026-11-21 t2-dev filled to 0 bytes: ~/.agent-harness/work held 117 GB of per-session clones and worktrees
that nothing removed after the session ended, /dev/shm (RAM) held 50 of 56 GB of session scratch, and uncapped
Elasticsearch/Java test containers drove ~895k kernel OOM kills that filled syslog. Earlier cleanups (Nov 17-18) also
removed folders that live systemd services ran from, so every removal here first checks service references.

COMMANDS
  checkout   --url URL --key KEY [--ref REF]
             One bare mirror per repo (~/.agent-harness/mirrors/<host>/<owner>/<repo>.git, fetched on each call) and
             ONE linked worktree per (repo, key) at ~/.agent-harness/checkouts/<repo>/<key>. A second call with the
             same key reuses the worktree and moves it to REF only when it is clean; it never discards work. Prints
             the path. Use a PR number or lane name as the key, never a per-round name.
  release    [--session ID | --path DIR] [--apply]
             For a session's work folder (~/.agent-harness/work/<ID>) or one folder: remove every checkout in it that
             is verified recoverable (clean, no untracked or hidden edits, every local commit on what the remote
             advertises right now (ls-remote), no stash/LFS/submodule, not in use, not referenced by a service), and the regenerable folders (node_modules, .venv, target, ...) of
             those checkouts. Removes the session folder itself when nothing else is left in it. Anything else is kept
             and listed. Wire it as a SessionEnd hook and call it at the end of every runner job.
  sweep      [--apply] [--json]
             The TTL janitor (systemd user timer, hourly): `release` for every session folder idle longer than
             ttl_hours (default 24) and every checkout under ~/.agent-harness/checkouts idle that long; removes
             user-owned /dev/shm entries idle longer than shm_ttl_hours (default 6) that no process holds open; and
             lists running containers that have no memory limit.
  pretool    PreToolUse Bash hook: denies `docker run` / `docker create` without --memory/-m (and Elasticsearch
             images without ES_JAVA_OPTS heap caps) with the exact flags to add. Fails open on its own errors.

SAFETY. Removal is plain `git worktree remove` (no --force) for linked worktrees and a directory removal for
standalone clones only after the same verification. Paths referenced by systemd units (system and user: ExecStart*,
WorkingDirectory, Environment*, unit files), crontabs, docker mounts/compose dirs or launchd plists are never removed,
nor anything a process has open or works in, nor a folder with a mount inside. If any liveness probe fails
(process scan, crontab, systemctl, docker) nothing is removed. HARNESS_JANITOR=off disables release/sweep deletion (report only).
Config: ~/.agent-harness/state/workspace-janitor.json (ttl_hours, shm_ttl_hours, work_roots, protect_names,
default_memory).
"""
from __future__ import annotations

import argparse, glob, json, os, re, shlex, shutil, stat, subprocess, sys, time

GB = 1024 ** 3
REGEN = {"node_modules", ".venv", "venv", "target", "__pycache__", ".pytest_cache", ".mypy_cache", ".ruff_cache",
         ".turbo", ".next", ".nuxt", ".parcel-cache", ".svelte-kit", "test-results", "playwright-report", ".gradle"}
DEFAULTS = {"ttl_hours": 24.0, "shm_ttl_hours": 6.0, "work_roots": None, "protect_names": ["yates", "optinrouter"],
            "default_memory": "4g"}
GENV = dict(os.environ, GIT_OPTIONAL_LOCKS="0", GIT_TERMINAL_PROMPT="0",
            GIT_SSH_COMMAND="ssh -o BatchMode=yes -o ConnectTimeout=15")
GSAFE = ["-c", "core.fsmonitor=false", "-c", "gc.auto=0", "-c", "maintenance.auto=false"]


def home() -> str:
    return os.environ.get("HARNESS_JANITOR_HOME") or os.path.expanduser("~")


def ah(*p) -> str:
    return os.path.join(home(), ".agent-harness", *p)


def load_config() -> dict:
    cfg = dict(DEFAULTS)
    try:
        with open(ah("state", "workspace-janitor.json")) as f:
            cfg.update({k: v for k, v in json.load(f).items() if k in DEFAULTS})
    except (OSError, ValueError):
        pass
    if not cfg["work_roots"]:
        cfg["work_roots"] = [ah("work")]
    return cfg


def git(cwd, *args, t=120, inp=None):
    try:
        r = subprocess.run(["git", "-C", cwd] + GSAFE + list(args), capture_output=True, text=True, timeout=t,
                           env=GENV, errors="replace", input=inp)
        return r.returncode, r.stdout, r.stderr
    except Exception as e:  # noqa: BLE001
        return -1, "", str(e)


def audit(row: dict) -> None:
    try:
        os.makedirs(ah("state"), exist_ok=True)
        row["at"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        with open(ah("state", "workspace-janitor.jsonl"), "a") as f:
            f.write(json.dumps(row, sort_keys=True) + "\n")
    except OSError:
        pass


# ------------------------------------------------------------------ checkout
def parse_url(url: str):
    if url.startswith("/") or url.startswith("file://"):  # local repository (tests, local mirrors)
        p = url[7:] if url.startswith("file://") else url
        return "local", re.sub(r"\.git$", "", p.strip("/")).replace("/", "_")
    m = re.match(r"^(?:https?://|ssh://)?(?:[^@/]+@)?([^/:]+)[:/]+(.+?)(?:\.git)?/?$", url)
    if not m:
        raise SystemExit("cannot parse repo url: %s" % url)
    host, path = m.group(1), m.group(2)
    if ".." in path.split("/"):
        raise SystemExit("bad repo path")
    return host, path


def safe_key(key: str) -> str:
    k = re.sub(r"[^A-Za-z0-9._-]+", "-", key).strip("-.")
    if not k:
        raise SystemExit("empty key")
    return k[:80]


def mirror_for(url: str) -> str:
    host, path = parse_url(url)
    m = ah("mirrors", host, path + ".git")
    if not os.path.isdir(m):
        os.makedirs(os.path.dirname(m), exist_ok=True)
        rc, _, err = git(os.path.dirname(m), "clone", "--bare", "--filter=blob:none", url, m, t=3600)
        if rc != 0:
            raise SystemExit("mirror clone failed: " + err.strip()[-300:])
        git(m, "config", "remote.origin.fetch", "+refs/heads/*:refs/remotes/origin/*")
    rc, _, err = git(m, "fetch", "--prune", "--quiet", "origin", t=1800)
    if rc != 0:
        print("warning: fetch failed, using the mirror as is: " + err.strip()[-200:], file=sys.stderr)
    return m


def checkout(url: str, key: str, ref: str = "") -> str:
    m = mirror_for(url)
    _, path = parse_url(url)
    wt = ah("checkouts", path.replace("/", "__"), safe_key(key))
    target = ref or "origin/HEAD"
    rc, sha, _ = git(m, "rev-parse", "--verify", "-q", target + "^{commit}")
    if rc != 0:
        rc, sha, _ = git(m, "rev-parse", "--verify", "-q", "origin/" + target + "^{commit}")
    if rc != 0:
        rc, sha, _ = git(m, "rev-parse", "--verify", "-q", "refs/remotes/origin/main^{commit}")
    if rc != 0:
        raise SystemExit("unknown ref: %s" % target)
    sha = sha.strip()
    if os.path.isdir(wt):
        rc, st, _ = git(wt, "status", "--porcelain")
        if rc == 0 and not st.strip():
            git(wt, "checkout", "--quiet", "--detach", sha)
        else:
            print("checkout has uncommitted work; left at its current commit", file=sys.stderr)
    else:
        os.makedirs(os.path.dirname(wt), exist_ok=True)
        rc, _, err = git(m, "worktree", "add", "--detach", wt, sha, t=1800)
        if rc != 0:
            raise SystemExit("worktree add failed: " + err.strip()[-300:])
    audit({"op": "checkout", "url": re.sub(r"://[^@/]+@", "://", url), "key": key, "path": wt, "sha": sha})
    return wt


# ------------------------------------------------------------------ in-use and service references
class ProbeError(Exception):
    """a liveness probe failed: callers must keep everything rather than treat it as 'nothing found'."""


def _run(cmd, t=60) -> str:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=t, errors="replace").stdout
    except Exception:  # noqa: BLE001
        return ""


def _probe(cmd, t=60, ok=(0,)):
    """(rc, stdout, stderr); rc 127 when the tool is missing."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=t, errors="replace")
        return r.returncode, r.stdout, r.stderr
    except FileNotFoundError:
        return 127, "", "not installed"
    except Exception as e:  # noqa: BLE001
        return -1, "", str(e)


def mounts_under(path: str) -> list:
    out = []
    try:
        with open("/proc/self/mountinfo") as f:
            for l in f:
                mp = l.split()[4].replace("\\040", " ")
                if mp == path or mp.startswith(path.rstrip("/") + "/"):
                    out.append(mp)
    except OSError:
        pass
    return out


def in_use_paths() -> set:
    out = set()
    for p in glob.glob("/proc/[0-9]*"):
        for link in ["cwd", "root"] + ["fd/" + f for f in _ls(p + "/fd")]:
            try:
                t = os.readlink(os.path.join(p, link))
            except OSError:
                continue
            if t.startswith("/"):
                out.add(t.replace(" (deleted)", ""))
    if not out and sys.platform == "darwin":
        for l in _run(["lsof", "-Fn", "-u", str(os.getuid())], 120).splitlines():
            if l.startswith("n/"):
                out.add(l[1:])
    if not out:
        raise ProbeError("no open files or working folders seen (process scan failed)")
    return out


def _ls(d):
    try:
        return os.listdir(d)
    except OSError:
        return []


def service_refs() -> set:
    h = home()
    rc, cron, err = _probe(["crontab", "-l"])
    if rc not in (0, 127) and "no crontab" not in err:
        raise ProbeError("crontab -l failed")
    texts = [cron]
    for scope in ([], ["--user"]):
        rc, o, _ = _probe(["systemctl"] + scope + ["list-unit-files", "--no-legend", "--plain"], 60)
        if rc == 127 or (rc != 0 and scope):  # no systemd / no user bus: the unit FILES are still read below
            continue
        if rc != 0:
            raise ProbeError("systemctl list-unit-files failed")
        names = [l.split()[0] for l in o.splitlines() if l.strip()]
        for i in range(0, len(names), 100):
            texts.append(_run(["systemctl"] + scope + ["show"] + names[i:i + 100] + [
                "-p", "WorkingDirectory,ExecStart,ExecStartPre,ExecStartPost,ExecStop,ExecReload,Environment,EnvironmentFiles,"
                "ReadWritePaths,FragmentPath,RootDirectory"], 120))
    for g in [h + "/.config/systemd/user/**", "/etc/systemd/system/**", "/etc/systemd/user/**", "/etc/cron*/*", "/etc/crontab",
              "/var/spool/cron/crontabs/*", h + "/.config/environment.d/*", h + "/.profile", h + "/.bashrc", h + "/.zshrc",
              h + "/Library/LaunchAgents/*.plist", "/Library/LaunchAgents/*.plist", "/Library/LaunchDaemons/*.plist"]:
        for f in glob.glob(g, recursive=True):
            try:
                if os.path.isfile(f):
                    with open(f, "rb") as fh:
                        texts.append(fh.read(262144).decode("utf-8", "replace"))
            except OSError:
                pass
    rc, ids, _ = _probe(["docker", "ps", "-aq"])
    if rc not in (0, 127):
        raise ProbeError("docker ps failed")
    if ids.split():
        rc, o, _ = _probe(["docker", "inspect", "-f", "{{range .Mounts}}{{.Source}} {{end}}{{range $k,$v := .Config.Labels}}{{$v}} {{end}}{{.Config.WorkingDir}}"]
                          + ids.split(), 120)
        if rc != 0:
            raise ProbeError("docker inspect failed")
        texts.append(o)
    pat = re.compile(re.escape(h) + r"/[^\s\"'<>:,;=\)\]\}\\|&`]+")
    refs = set()
    for t in texts:
        t = t.replace("${HOME}", h).replace("$HOME", h).replace("%h", h).replace("~/", h + "/")
        for m in pat.findall(t):
            m = os.path.normpath(m.rstrip("/."))
            for x in {m, os.path.realpath(m)}:
                refs.add(x)
                if os.path.isfile(x):
                    refs.add(os.path.dirname(x))
    for d in (h, h + "/bin", h + "/.local/bin", h + "/.config"):  # tools symlinked from a work folder
        for e in _ls(d):
            p = os.path.join(d, e)
            if os.path.islink(p):
                t = os.path.realpath(p)
                if t.startswith(h + "/"):
                    refs.add(t)
    refs.discard(h)
    return refs


def busy(path: str, used: set, refs: set) -> str:
    pre = path.rstrip("/") + "/"
    if any(u == path or u.startswith(pre) for u in used):
        return "a process has files open or works inside"
    if any(r == path or r.startswith(pre) for r in refs):
        return "referenced by a systemd unit, cron job, container or launchd plist"
    return ""


# ------------------------------------------------------------------ verification
def recoverable(repo: str) -> "tuple[bool, str]":
    """clean (no tracked changes, no untracked files), no stash, no rebase/merge, every local commit on a remote ref."""
    rc, st, _ = git(repo, "status", "--porcelain", "--untracked-files=all", "--ignore-submodules=none", t=300)
    if rc != 0:
        return False, "git status failed"
    if st.strip():
        return False, "uncommitted or untracked files"
    rc, gd, _ = git(repo, "rev-parse", "--absolute-git-dir")
    gd = gd.strip()
    if any(os.path.exists(os.path.join(gd, x)) for x in ("rebase-merge", "rebase-apply", "MERGE_HEAD", "CHERRY_PICK_HEAD")):
        return False, "rebase or merge in progress"
    rc, hidden, _ = git(repo, "ls-files", "-v", t=300)
    if rc != 0 or any(l[:1] == "S" or l[:1].islower() for l in hidden.splitlines()):
        return False, "skip-worktree / assume-unchanged files (edits git status does not show)"
    rc, common, _ = git(repo, "rev-parse", "--git-common-dir")
    common = os.path.realpath(os.path.join(repo, common.strip()))
    if os.path.isdir(os.path.join(common, "lfs")) or os.path.exists(os.path.join(repo, ".gitmodules")) or "/modules/" in gd:
        return False, "LFS objects or submodules (not verified)"
    rc, url, _ = git(repo, "remote", "get-url", "origin")
    url = url.strip()
    if rc != 0 or not url:
        return False, "no origin remote"
    rc, adv, _ = git(repo, "ls-remote", url, t=120)
    if rc != 0:
        return False, "ls-remote failed (cannot prove the commits are on the remote)"
    advertised = {l.split()[0] for l in adv.splitlines() if l.strip()}
    linked = os.path.isfile(os.path.join(repo, ".git"))
    if not linked:
        for w in _ls(os.path.join(gd, "worktrees")):
            try:
                with open(os.path.join(gd, "worktrees", w, "gitdir")) as fh:
                    if os.path.exists(fh.read().strip()):
                        return False, "other linked worktrees use this repository"
            except OSError:
                continue
    # every local tip must be reachable from what the remote advertises NOW (stale remote-tracking refs are not trusted)
    refs = ["HEAD"] if linked else ["HEAD", "--branches", "--tags"]
    rc, present, _ = git(repo, "cat-file", "--batch-check=%(objectname) %(objecttype)", inp="\n".join(advertised), t=120)
    have = [l.split()[0] for l in present.splitlines() if l.endswith(" commit")]
    rc, n, _ = git(repo, "rev-list", "--count", "--stdin", *refs, inp="".join("^%s\n" % x for x in have), t=300)
    if rc != 0 or n.strip() != "0":
        return False, "commits that are on no remote branch (checked with ls-remote)"
    if not linked and git(repo, "stash", "list")[1].strip():
        return False, "stash entries"
    return True, ""


def find_repos(root: str) -> list:
    out = []
    for dp, dn, fn in os.walk(root):
        if ".git" in dn or ".git" in fn:
            out.append(dp)
        dn[:] = [d for d in dn if d != ".git" and d not in REGEN]
    return sorted(out, key=lambda p: -p.count("/"))  # innermost first


def newest(path: str) -> float:
    best = 0.0
    for dp, dn, fn in os.walk(path):
        dn[:] = [d for d in dn if d not in REGEN and not (d == "objects" and dp.endswith("/.git"))]
        for f in fn:
            try:
                best = max(best, os.lstat(os.path.join(dp, f)).st_mtime)
            except OSError:
                pass
    return best


def remove_repo(repo: str) -> "tuple[bool, str]":
    if os.path.isfile(os.path.join(repo, ".git")):
        rc, common, _ = git(repo, "rev-parse", "--git-common-dir")
        common = os.path.realpath(os.path.join(repo, common.strip()))
        main = os.path.dirname(common) if os.path.basename(common) == ".git" else common
        rc, _, err = git(main, "worktree", "remove", repo)
        return rc == 0, err.strip()[-200:]
    shutil.rmtree(repo, ignore_errors=True)
    return not os.path.exists(repo), ""


def only_regenerable_left(path: str) -> bool:
    for dp, dn, fn in os.walk(path):
        dn[:] = [d for d in dn if d not in REGEN]
        if fn:
            return False
    return True


def release(path: str, apply: bool, used=None, refs=None, cfg=None) -> dict:
    cfg = cfg or load_config()
    try:
        used = in_use_paths() if used is None else used
        refs = service_refs() if refs is None else refs
    except ProbeError as e:
        return {"path": path, "removed": [], "kept": [{"path": path, "why": "liveness probe failed: %s" % e}], "freed_bytes": 0}
    apply = apply and os.environ.get("HARNESS_JANITOR", "").lower() != "off"
    res = {"path": path, "removed": [], "kept": [], "freed_bytes": 0}
    if any(n in path.lower() for n in cfg["protect_names"]):
        res["kept"].append({"path": path, "why": "protected name"}); return res
    why = busy(path, used, refs) or ("mount point inside" if mounts_under(path) else "")
    if why:
        res["kept"].append({"path": path, "why": why}); return res
    for repo in find_repos(path):
        why = busy(repo, used, refs)
        ok, why2 = (False, why) if why else recoverable(repo)
        if not ok:
            res["kept"].append({"path": repo, "why": why2}); continue
        size = du(repo)
        if apply:
            done, err = remove_repo(repo)
            if not done:
                res["kept"].append({"path": repo, "why": "remove failed: " + err}); continue
            audit({"op": "remove-checkout", "path": repo, "bytes": size})
        res["removed"].append(repo); res["freed_bytes"] += size
    if os.path.isdir(path) and only_regenerable_left(path) and not busy(path, used, refs):
        size = du(path)
        if apply:
            shutil.rmtree(path, ignore_errors=True)
            audit({"op": "remove-empty-session-folder", "path": path, "bytes": size})
        res["removed"].append(path); res["freed_bytes"] += size
    return res


def du(path: str) -> int:
    total = 0
    for dp, dn, fn in os.walk(path):
        for f in fn + dn:
            try:
                total += os.lstat(os.path.join(dp, f)).st_blocks * 512
            except OSError:
                pass
    return total


# ------------------------------------------------------------------ sweep
def shm_sweep(apply: bool, used: set, cfg: dict, now: float) -> list:
    rows = []
    uid = os.getuid()
    for e in _ls("/dev/shm"):
        p = os.path.join("/dev/shm", e)
        try:
            st = os.lstat(p)
        except OSError:
            continue
        if st.st_uid != uid:
            continue
        idle_h = (now - max(st.st_mtime, newest(p) if stat.S_ISDIR(st.st_mode) else 0)) / 3600
        if idle_h < cfg["shm_ttl_hours"]:
            continue
        if any(u == p or u.startswith(p + "/") for u in used):
            rows.append({"path": p, "action": "kept: open"}); continue
        size = du(p) if stat.S_ISDIR(st.st_mode) else st.st_blocks * 512
        if apply:
            if stat.S_ISDIR(st.st_mode):
                shutil.rmtree(p, ignore_errors=True)
            else:
                os.unlink(p)
            audit({"op": "remove-shm", "path": p, "bytes": size})
        rows.append({"path": p, "bytes": size, "idle_hours": round(idle_h, 1), "action": "removed" if apply else "would remove"})
    return rows


def uncapped_containers() -> list:
    ids = _run(["docker", "ps", "-q"]).split()
    if not ids:
        return []
    out = []
    for l in _run(["docker", "inspect", "-f", "{{.Name}} {{.HostConfig.Memory}} {{.Config.Image}}"] + ids, 120).splitlines():
        f = l.split()
        if len(f) >= 3 and f[1] == "0":
            out.append({"name": f[0].lstrip("/"), "image": f[2]})
    return out


def sweep(apply: bool, cfg=None, now=None) -> dict:
    cfg = cfg or load_config()
    now = now or time.time()
    used, refs = in_use_paths(), service_refs()
    ttl = cfg["ttl_hours"] * 3600
    results = []
    roots = list(cfg["work_roots"]) + [ah("checkouts")]
    for root in roots:
        for e in sorted(_ls(root)):
            p = os.path.join(root, e)
            if not os.path.isdir(p) or os.path.islink(p):
                continue
            targets = [os.path.join(p, k) for k in _ls(p)] if root == ah("checkouts") else [p]
            for t in targets:
                if os.path.isdir(t) and now - newest(t) >= ttl:
                    results.append(release(t, apply, used, refs, cfg))
    res = {"mode": "apply" if apply else "report", "released": results,
           "freed_gb": round(sum(r["freed_bytes"] for r in results) / GB, 2),
           "shm": shm_sweep(apply, used, cfg, now), "uncapped_containers": uncapped_containers()}
    audit({"op": "sweep", "mode": res["mode"], "freed_gb": res["freed_gb"], "uncapped": len(res["uncapped_containers"])})
    return res


# ------------------------------------------------------------------ pretool: container memory caps
def pretool(event: dict, cfg=None) -> "tuple[int, str]":
    try:
        cfg = cfg or load_config()
        if event.get("tool_name") != "Bash":
            return 0, ""
        cmd = (event.get("tool_input") or {}).get("command", "")
        for seg in re.split(r"&&|\|\||;|\n", cmd):
            try:
                w = shlex.split(seg)
            except ValueError:
                continue
            while w and re.match(r"^[A-Z_][A-Z0-9_]*=", w[0]):
                w = w[1:]
            if w and w[0] == "sudo":
                w = w[1:]
            if len(w) < 2 or w[0] not in ("docker", "podman") or w[1] not in ("run", "create"):
                continue
            has_mem = any(x in ("-m", "--memory") or x.startswith(("--memory=", "-m=")) or re.match(r"^-m\d", x) for x in w)
            if not has_mem:
                return 2, ("Container started without a memory limit. Uncapped test containers (Elasticsearch/Java) caused "
                           "~895k OOM kills on t2-dev in Nov 2026. Add `--memory %s --memory-swap %s` (or a size that fits "
                           "the job)." % (cfg["default_memory"], cfg["default_memory"]))
            if any("elasticsearch" in x or "opensearch" in x for x in w) and not any("ES_JAVA_OPTS" in x or "OPENSEARCH_JAVA_OPTS" in x for x in w):
                return 2, ("Elasticsearch/OpenSearch without a heap cap. Add `-e ES_JAVA_OPTS='-Xms1g -Xmx1g'` "
                           "(heap at most half of --memory).")
        return 0, ""
    except Exception:  # noqa: BLE001  fail open
        return 0, ""


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("checkout"); s.add_argument("--url", required=True); s.add_argument("--key", required=True); s.add_argument("--ref", default="")
    s = sub.add_parser("release"); s.add_argument("--session"); s.add_argument("--path"); s.add_argument("--apply", action="store_true")
    s = sub.add_parser("session-end")
    s = sub.add_parser("sweep"); s.add_argument("--apply", action="store_true"); s.add_argument("--json", action="store_true")
    sub.add_parser("pretool")
    a = ap.parse_args(argv)
    if a.cmd == "checkout":
        print(checkout(a.url, a.key, a.ref)); return 0
    if a.cmd == "release":
        if not (a.session or a.path):
            ap.error("--session or --path")
        p = os.path.realpath(a.path) if a.path else ah("work", safe_key(a.session))
        if not (p.startswith(home() + "/") and p != home()):
            ap.error("path must be inside the home folder")
        print(json.dumps(release(p, a.apply), indent=1)); return 0
    if a.cmd == "session-end":  # Claude Code SessionEnd hook: stdin JSON with session_id; never blocks
        try:
            ev = json.load(sys.stdin)
            sid = safe_key(ev.get("session_id", ""))
            p = ah("work", sid)
            if os.path.isdir(p):
                r = release(p, True)
                if r["kept"]:
                    print(json.dumps({"systemMessage": "workspace janitor kept %d item(s) in %s: %s" % (
                        len(r["kept"]), p, "; ".join("%s (%s)" % (k["path"], k["why"]) for k in r["kept"][:3]))}))
        except Exception:  # noqa: BLE001
            pass
        return 0
    if a.cmd == "sweep":
        r = sweep(a.apply)
        print(json.dumps(r, indent=1) if a.json else "sweep (%s): freed %.2f GB, %d folders checked, %d shm entries, %d uncapped containers" % (
            r["mode"], r["freed_gb"], len(r["released"]), len(r["shm"]), len(r["uncapped_containers"])))
        return 0
    if a.cmd == "pretool":
        try:
            ev = json.load(sys.stdin)
        except ValueError:
            return 0
        code, msg = pretool(ev)
        if code:
            print(msg, file=sys.stderr)
        return code
    return 0


if __name__ == "__main__":
    sys.exit(main())
