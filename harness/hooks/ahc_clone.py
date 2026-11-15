"""ahc daemon-owned clones (GoodQA goodqa#16034 AC-3, NEG-3, spec D4).

The daemon never runs git inside an owner's checkout: an owner-controlled `.git/config` (core.fsmonitor,
core.hooksPath, filters, sshCommand) or hook would execute with the daemon's authority. Instead it keeps one full,
non-shallow clone per repo under its own state dir. Before every use it:
  * rewrites that clone's local config to a canonical file (origin URL and fetch refspec only), so a planted key
    cannot survive;
  * passes `-c core.hooksPath=/dev/null -c core.fsmonitor=false` on every git command line, which overrides any
    repo config;
  * fetches the exact head and base, unshallows if needed, force-checks-out the head detached and cleans it.
Stdlib only; every child is an argv list with a timeout.
"""
from __future__ import annotations

import os
import re
import sys
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent))
import ahc_core  # noqa: E402

SAFE = ["-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", "-c", "core.untrackedCache=false",
        "-c", "protocol.ext.allow=never", "-c", "advice.detachedHead=false"]
SLUG = re.compile(r"^([A-Za-z0-9_.-]{1,100})/([A-Za-z0-9_.-]{1,100})$")
HEAD_RE = re.compile(r"^[0-9a-f]{40}$")
GIT_TIMEOUT = 900


class CloneError(RuntimeError):
    pass


def _git(args, cwd=None, env=None, timeout=GIT_TIMEOUT, check=True):
    rc, out, err = ahc_core.run_argv(["git", *SAFE, *args], timeout, cwd=cwd, env=env)
    if check and rc != 0:
        raise CloneError(f"git {args[0]} failed (exit {rc}): {err.strip()[-300:]}")
    return SimpleNamespace(returncode=rc, stdout=out, stderr=err)


def _canonical_config(path, url):
    """The only local config the daemon's clone may carry."""
    text = ("[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n\tbare = false\n\tlogallrefupdates = true\n"
            "\thooksPath = /dev/null\n\tfsmonitor = false\n\tuntrackedCache = false\n"
            f"[remote \"origin\"]\n\turl = {url}\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n")
    config = Path(path) / ".git" / "config"
    tmp = config.with_name("config.ahc-tmp")
    tmp.write_text(text, encoding="utf-8")
    os.chmod(tmp, 0o600)
    os.replace(tmp, config)


def clone_dir(root, repo):
    match = SLUG.match(repo or "")
    if not match or match.group(1) in (".", "..") or match.group(2) in (".", ".."):
        raise CloneError("repo must be owner/name")
    return Path(root) / f"{match.group(1)}__{match.group(2)}"


def prepare(root, repo, url, head, base, env=None):
    """Return the path of the daemon-owned clone checked out at `head` (detached, clean, full history)."""
    if not (HEAD_RE.match(head or "") and HEAD_RE.match(base or "")):
        raise CloneError("head and base must be full SHAs")
    if "\n" in url or url.startswith("-"):
        raise CloneError("bad clone URL")
    path = clone_dir(root, repo)
    Path(root).mkdir(parents=True, exist_ok=True, mode=0o700)
    for real in (Path(root), path, path / ".git"):     # git must never write through a link (PR 258 v1 BLOCK)
        if os.path.islink(str(real)) or (os.path.lexists(str(real)) and not os.path.isdir(str(real))):
            raise CloneError("clone path %s is a symlink or not a directory" % real.name)
    if not (path / ".git").is_dir():
        _git(["clone", "--quiet", "--no-checkout", "--", url, str(path)], cwd=str(root), env=env)
    _canonical_config(path, url)
    if (path / ".git" / "shallow").exists():
        _git(["fetch", "--quiet", "--unshallow", "origin"], cwd=path, env=env)
    _git(["fetch", "--quiet", "--no-tags", "origin", "+refs/heads/*:refs/remotes/origin/*"], cwd=path, env=env)
    for sha in (head, base):
        if _git(["cat-file", "-e", sha + "^{commit}"], cwd=path, env=env, check=False).returncode != 0:
            # GitHub serves PR heads by SHA even from forks; a plain branch fetch may not include them
            _git(["fetch", "--quiet", "--no-tags", "origin", sha], cwd=path, env=env, check=False)
        if _git(["cat-file", "-e", sha + "^{commit}"], cwd=path, env=env, check=False).returncode != 0:
            raise CloneError(f"commit {sha[:12]} is not available from the remote")
    _git(["checkout", "--quiet", "--force", "--detach", head], cwd=path, env=env)
    _git(["clean", "-ffdxq"], cwd=path, env=env)
    actual = _git(["rev-parse", "HEAD"], cwd=path, env=env).stdout.strip()
    shallow = _git(["rev-parse", "--is-shallow-repository"], cwd=path, env=env).stdout.strip()
    if actual != head or shallow != "false":
        raise CloneError("clone is not at the exact head or is shallow")
    return str(path)
