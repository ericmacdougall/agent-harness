#!/usr/bin/env python3
"""LOWER-LEVEL TOOL: never run this directly; only remote_delete.py sends it, after the approval checks.

Remote half of `remote_delete.py` (goodqa#15251). It runs ON the target host, sent over ssh on stdin by the main
host's guard. It never trusts anything it is told except the literal arguments: it re-checks the path and the
Dropbox archive itself.

  check  PATH ARCHIVE SHA256_FILE LISTING_FILE [BUNDLE]          -> one JSON line: identity, git state, archive
  delete PATH ARCHIVE SHA256_FILE LISTING_FILE IDENTITY [BUNDLE] -> re-check, then remove the tree; one JSON line

Order (both modes): read the tree's git state, verify the archive (a long download), THEN walk the tree and compare
it with the archive, so the delete follows the comparison within seconds, not after the download.

Archive checks:
- the Dropbox tar.gz streams to the sha256 recorded in its .sha256 file, and the same stream is read as a tar;
- the archive equals the tree: the same set of entries under <name>/, and every regular file has the same size and
  mtime (seconds), every symlink the same target; the listing has one line per member;
- when HEAD has commits no remote has, the bundle downloads, `git bundle verify` passes against the tree's
  repository, and its heads include HEAD.

Tree rules: a real directory at least two levels below home, outside harness and credential folders, on one
filesystem (no mount point inside), and, when it is a git tree, a clean LINKED worktree (a checkout with its own
.git directory is refused: its branches would go with it). A worktree is removed with `git worktree remove --force`
from its repository (branches stay), then `git worktree prune`; any other directory with shutil.rmtree.
Every run appends to ~/.agent-harness/state/remote-delete-audit.jsonl on this host. Stdlib only.
"""
import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time

RCLONE = os.environ.get("REMOTE_DELETE_RCLONE", "rclone")  # tests point this at a fake
TPS = "2"  # the agent-bulk share of the Dropbox budget
PROTECTED = (".claude", ".codex", ".agent-harness", ".ssh", ".config", ".gnupg", ".aws", ".kube", ".docker",
             ".local", "Dropbox", ".dropbox", ".cache")


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


def check_path(path):
    home = os.path.realpath(os.path.expanduser("~"))
    if not os.path.isabs(path) or os.path.normpath(path) != path or os.path.realpath(path) != path:
        raise ValueError("not a literal real absolute path")
    if os.path.islink(path) or not os.path.isdir(path):
        raise ValueError("not a plain directory")
    if not path.startswith(home + "/") or path.count("/") - home.count("/") < 2:
        raise ValueError("only a directory at least two levels below the home directory")
    for protected in PROTECTED:
        if path.startswith(os.path.join(home, protected) + "/"):
            raise ValueError("a protected harness or credential location")
    return home


def git_state(path):
    """None for a non-git directory; refuses a checkout with its own .git directory and an unclean tree."""
    marker = os.path.join(path, ".git")
    if not os.path.lexists(marker):
        return None
    if os.path.islink(marker) or not os.path.isfile(marker):
        raise ValueError("a checkout with its own .git directory is not removed by this route (its branches and "
                         "stash would go with it); only linked worktrees")
    code, status = git(path, "status", "--porcelain=v1", "--untracked-files=all")
    if code != 0:
        raise ValueError("git status failed")
    if status.strip():
        raise ValueError("the git tree has uncommitted or untracked changes")
    _, head = git(path, "rev-parse", "HEAD")
    _, common = git(path, "rev-parse", "--path-format=absolute", "--git-common-dir")
    _, local_only = git(path, "rev-list", "-n1", "HEAD", "--not", "--remotes")
    return {"head": head.strip(), "common": common.strip(), "local_only": bool(local_only.strip())}


def walk_tree(path):
    """{relative name: (kind, size, mtime, target)} relative to the parent directory, without following links.
    Refuses a mount point inside the tree."""
    parent, root_dev = os.path.dirname(path), os.lstat(path).st_dev
    entries = {}
    for top, dirs, files in os.walk(path, followlinks=False):
        for name in dirs + files:
            full = os.path.join(top, name)
            info = os.lstat(full)
            if info.st_dev != root_dev:
                raise ValueError("a mount point is inside the tree (%s)" % os.path.relpath(full, parent)[:120])
            rel = os.path.relpath(full, parent)
            if stat.S_ISLNK(info.st_mode):
                entries[rel] = ("l", 0, 0, os.readlink(full))
            elif stat.S_ISDIR(info.st_mode):
                entries[rel] = ("d", 0, 0, "")
            elif stat.S_ISREG(info.st_mode):
                entries[rel] = ("f", info.st_size, int(info.st_mtime), "")
            else:
                entries[rel] = ("o", 0, 0, "")
    entries[os.path.basename(path)] = ("d", 0, 0, "")
    return entries


class HashingReader:
    def __init__(self, raw):
        self.raw, self.digest = raw, hashlib.sha256()

    def read(self, size=-1):
        chunk = self.raw.read(size)
        self.digest.update(chunk)
        return chunk


def rclone(*args, timeout=1800):
    return subprocess.run([RCLONE, "--tpslimit", TPS, *args], capture_output=True, timeout=timeout)


def read_archive(name, archive, sha_file, listing_file):
    for remote in (archive, sha_file, listing_file):
        if ":" not in remote or remote.startswith("-"):
            raise ValueError("archive locations must be rclone remote paths")
    if not archive.endswith("/" + name + ".tar.gz"):
        raise ValueError("the archive must be <remote>/%s.tar.gz" % name)
    recorded = rclone("cat", "--", sha_file, timeout=120)
    want = recorded.stdout.decode("utf-8", "replace").split()[:1]
    if recorded.returncode != 0 or not want or len(want[0]) != 64:
        raise ValueError("the .sha256 file could not be read")
    members = {}
    with subprocess.Popen([RCLONE, "--tpslimit", TPS, "cat", "--", archive], stdout=subprocess.PIPE) as stream:
        reader = HashingReader(stream.stdout)
        try:
            with tarfile.open(fileobj=reader, mode="r|gz") as tar:
                for m in tar:
                    rel = os.path.normpath(m.name)
                    if rel != name and not rel.startswith(name + "/"):
                        raise ValueError("the archive holds members outside %s/" % name)
                    if m.issym():
                        members[rel] = ("l", 0, 0, m.linkname)
                    elif m.isdir():
                        members[rel] = ("d", 0, 0, "")
                    elif m.isfile():
                        members[rel] = ("f", m.size, int(m.mtime), "")
                    elif m.islnk():
                        members[rel] = ("h", 0, 0, os.path.normpath(m.linkname))
                    else:
                        members[rel] = ("o", 0, 0, "")
        except (tarfile.TarError, EOFError, OSError) as error:
            raise ValueError("the Dropbox archive is not a readable tar.gz (%s)" % type(error).__name__)
        for chunk in iter(lambda: reader.read(1 << 20), b""):  # the tar end padding, so the hash covers the file
            pass
    if stream.returncode != 0 or reader.digest.hexdigest() != want[0]:
        raise ValueError("the Dropbox archive does not match its sha256")
    listing = rclone("cat", "--", listing_file, timeout=600)
    if listing.returncode != 0 or len([x for x in listing.stdout.splitlines() if x.strip()]) != len(members):
        raise ValueError("the archive listing is missing or does not match the archive")
    return {"sha256": want[0], "members": members}


def compare(tree, members):
    """'' when the archive holds exactly the tree, else the first difference."""
    for rel in sorted(set(tree) | set(members)):
        have, saved = tree.get(rel), members.get(rel)
        if have is None:
            return "the archive has %s, which the tree does not" % rel[:160]
        if saved is None:
            return "the tree has %s, which the archive does not" % rel[:160]
        if saved[0] == "h":  # a hard link in the tar: the tree holds a regular file of the linked member's size
            target = members.get(saved[3])
            if have[0] != "f" or not target or target[0] != "f" or target[1] != have[1]:
                return "%s differs from the archive" % rel[:160]
            continue
        if have[0] != saved[0] or (have[0] == "f" and have[1:3] != saved[1:3]) or (have[0] == "l" and have[3] != saved[3]):
            return "%s differs from the archive" % rel[:160]
    return ""


def verify_bundle(name, bundle, state):
    if not bundle or ":" not in bundle or bundle.startswith("-"):
        raise ValueError("HEAD has commits no remote has, so a verified bundle is required")
    with tempfile.TemporaryDirectory(prefix="rdel-") as scratch:
        local = os.path.join(scratch, name + ".bundle")
        if rclone("copyto", "--", bundle, local).returncode != 0:
            raise ValueError("the bundle could not be downloaded")
        if subprocess.run(["git", "--git-dir", state["common"], "bundle", "verify", local],
                          capture_output=True).returncode != 0:
            raise ValueError("git bundle verify failed")
        heads = subprocess.run(["git", "bundle", "list-heads", local], capture_output=True, text=True).stdout
        if not any(line.split()[:1] == [state["head"]] for line in heads.splitlines()):
            raise ValueError("the bundle does not hold HEAD")


def main(argv):
    if len(argv) < 5 or argv[0] not in ("check", "delete"):
        return out(ok=False, error="usage")
    mode, path, archive, sha_file, listing_file = argv[:5]
    expected = argv[5] if mode == "delete" and len(argv) > 5 else None
    bundle = (argv[6] if mode == "delete" else argv[5]) if len(argv) > (6 if mode == "delete" else 5) else None
    name = os.path.basename(path)
    try:
        home = check_path(path)
        before = git_state(path)
        saved = read_archive(name, archive, sha_file, listing_file)  # the long part, before the tree is compared
        if before and before["local_only"]:
            verify_bundle(name, bundle, before)
        # the tree, now: unchanged git state, the same files as the archive, the same directory
        check_path(path)
        state = git_state(path)
        if state != before:
            raise ValueError("the git state changed during the archive check")
        problem = compare(walk_tree(path), saved["members"])
        if problem:
            raise ValueError("the archive does not match the tree: " + problem)
        summary = {"sha256": saved["sha256"], "members": len(saved["members"]), "bundle": bool(state and state["local_only"])}
        if mode == "check":
            audit({"event": "remote-check", "path": path, "identity": identity(path), "archive": archive})
            return out(ok=True, path=path, home=home, identity=identity(path), git=state, archive=summary)
        if not expected or identity(path) != expected:
            raise ValueError("the path identity changed since the check")
        if state:
            repo = os.path.dirname(state["common"].rstrip("/"))  # a bare repository's worktree fails closed here
            code, _ = git(repo, "worktree", "remove", "--force", path, timeout=600)
            if code != 0:
                raise ValueError("git worktree remove failed")
            git(repo, "worktree", "prune")
        else:
            shutil.rmtree(path)
        gone = not os.path.lexists(path)
        audit({"event": "remote-delete", "path": path, "identity": expected, "archive": archive, "gone": gone})
        return out(ok=gone, path=path, deleted=gone, archive=summary)
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        audit({"event": "remote-refused", "path": path, "reason": str(error)[:200]})
        return out(ok=False, path=path, error=str(error)[:300])


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
