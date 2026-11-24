#!/usr/bin/env python3
"""Update the installed harness on this Mac and on t2-dev to one merged commit. USER-RUN: an agent never runs it.

    python3 scripts/update_installed.py --preview                  # what would change; installs nothing
    python3 scripts/update_installed.py --ticket "GoodQA goodqa#N"  # install origin/main HEAD
    python3 scripts/update_installed.py --commit <sha> --ticket "GoodQA goodqa#N"

Steps, each of which stops the run when it fails:
  1. The install clone (default ~/harness-install, a plain clone of the canonical repository; created on a real run) must
     point at the canonical URL and be clean (no modified or untracked file). `git fetch origin main`.
  2. The commit (default: origin/main HEAD) must be on origin/main.
  3. The file list is DERIVED, never hand-kept: every file the installer lists at that commit (install.py AGENTS, HOOKS,
     TOOLS, SKILLS) whose installed copy in ~/.claude is missing or differs from the commit's bytes; for each remote host,
     every HOOKS file that `ah install-files --dry-run` does not report as already current there.
  4. Mac: the commit is checked out (detached) and `install.py --apply --hooks-only` runs (CLAUDE.md and settings.json are
     not touched; replaced files are backed up). Every listed file is then compared with the commit.
  5. Each remote host: `ah install-files --host H --from-ref <sha> --file ... --ticket T` (the sanctioned installer, in
     batches of 20), then a second dry run must report every file current.

--preview runs steps 1 to 3 without the clone step: it never checks out, never installs and never writes under
~/.claude. It does fetch into the install clone, and each remote dry run appends its own audit row (ah_install's record).
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

CANONICAL_URL = "https://github.com/ericmacdougall/agent-harness.git"
REMOTE_HOSTS = ("t2-dev",)
BATCH = 20                      # ah_install.MAX_FILES
FOLDERS = (("agents", "AGENTS"), ("hooks", "HOOKS"), ("tools", "TOOLS"), ("skills", "SKILLS"))
SHA_RE = re.compile(r"[0-9a-f]{40}")
TICKET_RE = re.compile(r"GoodQA [A-Za-z0-9_-]+#[0-9]+")


class Stop(Exception):
    """A refusal: nothing after the failed step ran."""


def git(repo, *args, data=False, timeout=300):
    r = subprocess.run(["git", "-C", str(repo), *args], capture_output=True, timeout=timeout)
    if r.returncode != 0:
        raise Stop("git %s failed: %s" % (args[0], r.stderr.decode("utf-8", "replace").strip()[-300:]))
    return r.stdout if data else r.stdout.decode("utf-8", "replace").strip()


def check_clone(repo):
    if not (Path(repo) / ".git").is_dir():
        raise Stop("%s is not a git clone" % repo)
    url = git(repo, "remote", "get-url", "origin")
    if url.rstrip("/") not in (CANONICAL_URL, CANONICAL_URL[:-len(".git")]):
        raise Stop("%s points at %s, not %s" % (repo, url, CANONICAL_URL))
    if git(repo, "status", "--porcelain", "--untracked-files=all", "--ignore-submodules=none"):
        raise Stop("%s has local changes or untracked files; nothing was changed" % repo)


def resolve_commit(repo, commit):
    git(repo, "fetch", "-q", "origin", "main")
    main = git(repo, "rev-parse", "--verify", "refs/remotes/origin/main^{commit}")
    if commit is None:
        commit = main
    if not isinstance(commit, str) or not SHA_RE.fullmatch(commit):
        raise Stop("--commit must be a full 40-hex lowercase sha")
    sha = subprocess.run(["git", "-C", str(repo), "rev-parse", "--verify", "--quiet", commit + "^{commit}"],
                         capture_output=True, text=True)
    if sha.returncode != 0 or sha.stdout.strip() != commit:
        raise Stop("%s is not a commit in %s" % (commit, repo))
    if subprocess.run(["git", "-C", str(repo), "merge-base", "--is-ancestor", commit, main]).returncode != 0:
        raise Stop("%s is not on origin/main; nothing was changed" % commit)
    return commit


def installer_lists(repo, commit):
    """{folder: [names]} from install.py AT THE COMMIT (literal tuples only; anything else stops the run)."""
    tree = ast.parse(git(repo, "show", "%s:install.py" % commit, data=True).decode("utf-8"))
    found = {}
    for stmt in tree.body:
        if isinstance(stmt, ast.Assign):
            for target in stmt.targets:
                for folder, var in FOLDERS:
                    if isinstance(target, ast.Name) and target.id == var:
                        try:
                            names = ast.literal_eval(stmt.value)
                        except ValueError:
                            raise Stop("install.py %s at %s is not a literal tuple" % (var, commit[:12]))
                        if not isinstance(names, tuple) or not all(isinstance(n, str) for n in names):
                            raise Stop("install.py %s at %s is not a tuple of names" % (var, commit[:12]))
                        found[folder] = list(names)
    if "hooks" not in found:
        raise Stop("install.py at %s has no HOOKS list" % commit[:12])
    return {folder: found.get(folder, []) for folder, _ in FOLDERS}


def blob_sha(repo, commit, path):
    return hashlib.sha256(git(repo, "cat-file", "blob", "%s:%s" % (commit, path), data=True)).hexdigest()


def file_sha(path):
    p = Path(path)
    if p.is_symlink() or not p.is_file():
        return None
    return hashlib.sha256(p.read_bytes()).hexdigest()


def local_changes(repo, commit, home, lists):
    """Installed files (folder/name) that are missing or differ from the commit."""
    out = []
    for folder, _ in FOLDERS:
        for name in lists[folder]:
            rel = "%s/%s" % (folder, name)
            if file_sha(Path(home) / ".claude" / rel) != blob_sha(repo, commit, "harness/" + rel):
                out.append(rel)
    return out


def ah_install(home, host, commit, names, ticket, dry_run, runner):
    """One `ah install-files` call per batch; returns {name: plan entry}. A non-zero exit or bad JSON stops the run."""
    plan = {}
    for i in range(0, len(names), BATCH):
        argv = [sys.executable, "-I", str(Path(home) / ".claude" / "hooks" / "ah.py"), "install-files", "--host", host,
                "--from-ref", commit]
        for name in names[i:i + BATCH]:
            argv += ["--file", name]
        argv += ["--dry-run"] if dry_run else ["--ticket", ticket]
        r = runner(argv, capture_output=True, text=True, timeout=1800)
        try:
            data = json.loads(r.stdout)
        except ValueError:
            data = None
        if r.returncode != 0 or not isinstance(data, dict) or not isinstance(data.get("files"), dict):
            raise Stop("ah install-files on %s (%s) failed with exit %s: %s"
                       % (host, "dry run" if dry_run else "install", r.returncode, (r.stdout or r.stderr or "")[-400:]))
        plan.update(data["files"])
    return plan


def remote_changes(home, host, commit, hooks, runner):
    plan = ah_install(home, host, commit, hooks, None, True, runner)
    missing = [n for n in hooks if n not in plan]
    if missing:
        raise Stop("the dry run on %s did not report %s" % (host, ", ".join(missing[:5])))
    return [n for n in hooks if (plan[n] or {}).get("action") != "already_current"]


def main(argv=None, runner=subprocess.run):
    ap = argparse.ArgumentParser(description="User-run: update the installed harness to one commit on origin/main.")
    ap.add_argument("--commit", help="full 40-hex sha on origin/main (default: origin/main HEAD)")
    ap.add_argument("--preview", action="store_true", help="show what would change; install nothing")
    ap.add_argument("--clone", default=str(Path.home() / "harness-install"), help="the install clone")
    ap.add_argument("--host", action="append", choices=REMOTE_HOSTS, help="remote host (default: t2-dev)")
    ap.add_argument("--no-remote", action="store_true", help="update this Mac only")
    ap.add_argument("--ticket", help="GoodQA project#N; required for a real run")
    ap.add_argument("--home", default=str(Path.home()), help=argparse.SUPPRESS)
    a = ap.parse_args(argv)
    hosts = [] if a.no_remote else (a.host or list(REMOTE_HOSTS))
    try:
        if not a.preview and hosts and not (a.ticket and TICKET_RE.fullmatch(a.ticket)):
            raise Stop("--ticket 'GoodQA project#N' is required for a real run")
        clone = Path(a.clone)
        if not clone.exists():
            if a.preview:
                raise Stop("%s does not exist; a preview creates nothing (a real run clones it)" % clone)
            r = subprocess.run(["git", "clone", "-q", CANONICAL_URL, str(clone)], capture_output=True, text=True)
            if r.returncode != 0:
                raise Stop("git clone failed: %s" % r.stderr.strip()[-300:])
        check_clone(clone)
        commit = resolve_commit(clone, a.commit)
        lists = installer_lists(clone, commit)
        mac = local_changes(clone, commit, a.home, lists)
        remote = {h: remote_changes(a.home, h, commit, lists["hooks"], runner) for h in hosts}
        print("Commit %s (%s)" % (commit, git(clone, "log", "-1", "--format=%s", commit)))
        print("Mac: %d file(s) differ: %s" % (len(mac), " ".join(mac) or "-"))
        for h, names in remote.items():
            print("%s: %d hook file(s) differ: %s" % (h, len(names), " ".join(names) or "-"))
        if a.preview:
            print("Preview only: nothing was installed.")
            return 0
        if mac:
            git(clone, "checkout", "-q", "--detach", commit)
            check_clone(clone)
            r = runner([sys.executable, "install.py", "--apply", "--hooks-only", "--home", a.home], cwd=str(clone),
                       capture_output=True, text=True, timeout=1800)
            if r.returncode != 0:
                raise Stop("install.py failed with exit %s: %s" % (r.returncode, (r.stderr or r.stdout or "")[-400:]))
            still = local_changes(clone, commit, a.home, lists)
            if still:
                raise Stop("after install.py these Mac files still differ from the commit: %s" % " ".join(still))
        print("Mac: every installed file matches %s" % commit[:12])
        for h, names in remote.items():
            if names:
                ah_install(a.home, h, commit, names, a.ticket, False, runner)
            left = remote_changes(a.home, h, commit, lists["hooks"], runner)
            if left:
                raise Stop("%s: these hook files still differ after the install: %s" % (h, " ".join(left)))
            print("%s: every hook file matches %s" % (h, commit[:12]))
        print("Done. Installed commit: %s" % commit)
        return 0
    except Stop as e:
        print("STOP: %s" % e, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
