"""Verify an existing path before `ah lane start` accepts it as a lane's worktree (S1), without starting a process.

An existing path is accepted only when ALL of these hold, read from the .git files in Python:
* it is not a symlink and is not the repository's main checkout;
* it is a linked work tree of the intended repository: its `.git` file points at an admin directory under that
  repository's common git directory, and that admin directory's `gitdir` back-link names this very path (so a forged
  `.git` file pointing at someone else's admin directory is refused);
* its HEAD is the expected branch (a detached HEAD or another branch is refused).
"""
from __future__ import annotations

import os

from . import identity as ident
from .lanes import LaneRefusal


def _refuse(why):
    raise LaneRefusal("existing worktree path refused: %s" % why)


def verify_worktree(worktree: str, repo_path: str, branch: str) -> None:
    if os.path.islink(worktree):
        _refuse("it is a symlink")
    if not os.path.isdir(worktree):
        _refuse("it is not a directory")
    real = os.path.realpath(worktree)
    try:
        repo_common = ident._common_git_dir(repo_path)
    except ident.IdentityError:
        _refuse("the intended repository cannot be read")
    if real == os.path.realpath(repo_path) or real == os.path.dirname(repo_common):
        _refuse("it is the repository's main checkout")
    dot = os.path.join(worktree, ".git")
    if os.path.islink(dot) or not os.path.isfile(dot):
        _refuse("it is not a linked work tree (no .git file)")
    try:
        text = ident._read_text(dot).strip()
    except ident.IdentityError:
        _refuse("its .git file is unreadable")
    if not text.startswith("gitdir:"):
        _refuse("its .git file is not a gitdir pointer")
    target = text[len("gitdir:"):].strip()
    admin = os.path.realpath(target if os.path.isabs(target) else os.path.join(worktree, target))
    if os.path.dirname(admin) != os.path.join(repo_common, "worktrees"):
        _refuse("it belongs to another repository")
    try:
        back = ident._read_text(os.path.join(admin, "gitdir")).strip()
    except ident.IdentityError:
        _refuse("it is not registered in the repository")
    if os.path.realpath(os.path.dirname(back)) != real:
        _refuse("the repository's registration names a different path")
    try:
        head = ident._read_text(os.path.join(admin, "HEAD")).strip()
    except ident.IdentityError:
        _refuse("its HEAD is unreadable")
    if head != "ref: refs/heads/%s" % branch:
        _refuse("it is not on the expected branch %s" % branch)
