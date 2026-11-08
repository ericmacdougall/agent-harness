#!/usr/bin/env python3
"""LOWER-LEVEL TOOL: never run this directly; only remote_delete.py sends it, after the approval checks.

Remote half of `remote_delete.py` (goodqa#15251). It runs ON the target host, sent over ssh on stdin by the main
host's guard. It never trusts anything it is told except the literal arguments: it re-checks the path and the
Dropbox archive itself.

  check  PATH ARCHIVE SHA256_FILE LISTING_FILE [BUNDLE]      -> one JSON line: identity, git state, verified archive
  delete PATH ARCHIVE SHA256_FILE LISTING_FILE IDENTITY [BUNDLE] -> re-check, then remove the tree; one JSON line

Archive checks:
- the Dropbox tar.gz streams to the sha256 recorded in its .sha256 file;
- every member of the archive (read from the same stream) is inside the tree, and the listing has as many lines;
- when the tree has commits no remote has, the bundle downloads, `git bundle verify` passes against the tree's
  repository, and its heads include HEAD.

A git worktree is removed with `git worktree remove --force`, then `git worktree prune`; any other directory is
removed with shutil.rmtree. Every run appends to ~/.agent-harness/state/remote-delete-audit.jsonl on this host.
Stdlib only.
"""
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time

RCLONE = os.environ.get("REMOTE_DELETE_RCLONE", "rclone")  # tests point this at a fake
TPS = "2"  # the agent-bulk share of the Dropbox write budget (reads, but keep within it)


def out(**fields):
    print(json.dumps(fields, sort_keys=True))
    return 0 if fields.get("ok") else 3


def audit(record):
    try:
        state = os.path.join(os.path.expanduser("~"), ".agent-harness", "state")
        os.makedirs(state, mode=0o700, exist_ok=True)
        fd = os.open(os.path.join(state, "remote-delete-audit.jsonl"), os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
        with os.fdopen(fd, "a") as handle:
            handle.write(json.dumps(dict(record, ts=round(time.time(), 3)), sort_keys=True) + "\n")
    except OSError:
        pass


def git(path, *args, timeout=60):
    done = subprocess.run(["git", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null", "-C", path, *args],
                          capture_output=True, text=True, timeout=timeout)
    return done.returncode, done.stdout


def identity(path):
    info = os.lstat(path)
    return "%d:%d" % (info.st_dev, info.st_ino)


def tree_state(path):
    home = os.path.realpath(os.path.expanduser("~"))
    if not os.path.isabs(path) or os.path.normpath(path) != path or os.path.realpath(path) != path:
        raise ValueError("not a literal real absolute path")
    if os.path.islink(path) or not os.path.isdir(path):
        raise ValueError("not a plain directory")
    if not path.startswith(home + "/") or path.count("/") - home.count("/") < 2:
        raise ValueError("only a directory at least two levels below the home directory")
    for protected in (".claude", ".codex", ".agent-harness", ".ssh", ".config"):
        if path == os.path.join(home, protected) or path.startswith(os.path.join(home, protected) + "/"):
            raise ValueError("a protected harness or credential location")
    state = {"identity": identity(path), "home": home, "git": None}
    marker = os.path.join(path, ".git")
    if os.path.lexists(marker):
        code, status = git(path, "status", "--porcelain=v1", "--untracked-files=all")
        if code != 0:
            raise ValueError("git status failed")
        code, head = git(path, "rev-parse", "HEAD")
        _, common = git(path, "rev-parse", "--path-format=absolute", "--git-common-dir")
        _, local_only = git(path, "rev-list", "-n1", "HEAD", "--not", "--remotes")
        state["git"] = {"clean": status.strip() == "", "head": head.strip(), "common": common.strip(),
                        "linked": os.path.isfile(marker), "local_only": bool(local_only.strip())}
    return state


def rclone(*args, timeout=1800):
    return subprocess.run([RCLONE, "--tpslimit", TPS, *args], capture_output=True, timeout=timeout)


def verify_archive(path, archive, sha_file, listing_file, bundle, state):
    name = os.path.basename(path)
    for remote in (archive, sha_file, listing_file) + ((bundle,) if bundle else ()):
        if ":" not in remote or remote.startswith("-"):
            raise ValueError("archive locations must be rclone remote paths")
    if not archive.endswith("/" + name + ".tar.gz"):
        raise ValueError("the archive must be <remote>/%s.tar.gz" % name)
    recorded = rclone("cat", "--", sha_file, timeout=120)
    want = recorded.stdout.decode("utf-8", "replace").split()[:1]
    if recorded.returncode != 0 or not want or len(want[0]) != 64:
        raise ValueError("the .sha256 file could not be read")
    # one download: the stream feeds the sha256 and `tar -tz`, so the member names come from the archive itself
    digest = hashlib.sha256()
    with tempfile.TemporaryFile() as names:
        with subprocess.Popen([RCLONE, "--tpslimit", TPS, "cat", "--", archive], stdout=subprocess.PIPE) as stream, \
                subprocess.Popen(["tar", "-tzf", "-"], stdin=subprocess.PIPE, stdout=names,
                                 stderr=subprocess.DEVNULL) as lister:
            try:
                for chunk in iter(lambda: stream.stdout.read(1 << 20), b""):
                    digest.update(chunk)
                    lister.stdin.write(chunk)
            except BrokenPipeError:
                pass
            finally:
                try:
                    lister.stdin.close()
                except BrokenPipeError:
                    pass
        if stream.returncode != 0 or digest.hexdigest() != want[0]:
            raise ValueError("the Dropbox archive does not match its sha256")
        if lister.returncode != 0:
            raise ValueError("the Dropbox archive is not a readable tar.gz")
        names.seek(0)
        members = [m.rstrip("/") for m in names.read().decode("utf-8", "replace").splitlines() if m.strip()]
    if not members or any(m != name and not m.startswith(name + "/") for m in members):
        raise ValueError("the archive holds members outside %s/" % name)
    listing = rclone("cat", "--", listing_file, timeout=600)
    if listing.returncode != 0 or len([x for x in listing.stdout.splitlines() if x.strip()]) != len(members):
        raise ValueError("the archive listing is missing or does not match the archive")
    result = {"sha256": want[0], "members": len(members), "bundle": False}
    git_state = state.get("git")
    if git_state and git_state["local_only"]:
        if not bundle:
            raise ValueError("the tree has commits no remote has, so a verified bundle is required")
        with tempfile.TemporaryDirectory(prefix="rdel-") as scratch:
            local = os.path.join(scratch, name + ".bundle")
            if rclone("copyto", "--", bundle, local).returncode != 0:
                raise ValueError("the bundle could not be downloaded")
            if subprocess.run(["git", "--git-dir", git_state["common"], "bundle", "verify", local],
                              capture_output=True).returncode != 0:
                raise ValueError("git bundle verify failed")
            heads = subprocess.run(["git", "bundle", "list-heads", local], capture_output=True, text=True).stdout
            if not any(line.split()[:1] == [git_state["head"]] for line in heads.splitlines()):
                raise ValueError("the bundle does not hold HEAD")
        result["bundle"] = True
    return result


def main(argv):
    if len(argv) < 5 or argv[0] not in ("check", "delete"):
        return out(ok=False, error="usage")
    mode, path, archive, sha_file, listing_file = argv[:5]
    expected = argv[5] if mode == "delete" and len(argv) > 5 else None
    bundle = (argv[6] if mode == "delete" else argv[5]) if len(argv) > (6 if mode == "delete" else 5) else None
    try:
        state = tree_state(path)
        if state["git"] and not state["git"]["clean"]:
            raise ValueError("the git tree has uncommitted or untracked changes")
        verified = verify_archive(path, archive, sha_file, listing_file, bundle, state)
        if mode == "check":
            audit({"event": "remote-check", "path": path, "identity": state["identity"], "archive": archive})
            return out(ok=True, path=path, home=state["home"], identity=state["identity"], git=state["git"],
                       archive=verified)
        if not expected or state["identity"] != expected:
            raise ValueError("the path identity changed since the check")
        git_state = state["git"]
        if git_state and git_state["linked"]:
            parent = os.path.dirname(git_state["common"].rstrip("/"))
            code, _ = git(parent, "worktree", "remove", "--force", path, timeout=600)
            if code != 0:
                raise ValueError("git worktree remove failed")
            git(parent, "worktree", "prune")
        else:
            shutil.rmtree(path)
        gone = not os.path.lexists(path)
        audit({"event": "remote-delete", "path": path, "identity": expected, "archive": archive, "gone": gone})
        return out(ok=gone, path=path, deleted=gone, archive=verified)
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        audit({"event": "remote-refused", "path": path, "reason": str(error)[:200]})
        return out(ok=False, path=path, error=str(error)[:300])


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
