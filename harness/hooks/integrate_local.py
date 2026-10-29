#!/usr/bin/env python3
"""Merge a reviewed feature commit into the original clean checkout, with checks."""

import argparse
import json
import os
import shlex
import subprocess
import sys
from pathlib import Path


def run(repo, command):
    # Python test runners otherwise leave untracked __pycache__ after an aborted merge.
    return subprocess.run(command, cwd=repo, text=True, capture_output=True,
                          env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})


def git(repo, *args):
    return run(repo, ["git", *args])


def report(status, message, **extra):
    print(json.dumps({"status": status, "message": message, **extra}))


def approved_check(argv):
    if not argv:
        return False
    if argv[0] == "go" and len(argv) >= 2:
        if argv[1:] == ["vet", "./..."]:
            return True
        if argv[1] == "test":
            options = argv[2:]
            return options[-1:] == ["./..."] and all(item in {"-race", "-count=1", "-v"} for item in options[:-1])
    if argv[0] in {"npm", "pnpm", "yarn"}:
        return argv[1:] == ["test"] or (len(argv) == 3 and argv[1] == "run" and argv[2] in {"test", "typecheck", "build", "lint", "check"})
    if argv[0] in {"python", "python3"}:
        return argv[1:] in (
            ["-m", "unittest", "discover", "-s", "tests"],
            ["-m", "unittest", "discover", "-s", "tests", "-v"],
            ["-m", "unittest", "discover", "-s", "tests", "-t", "."],
            ["-m", "unittest", "discover", "-s", "tests", "-t", ".", "-v"],
            ["-m", "pytest"],
            ["-m", "pytest", "-q"],
        )
    if argv in (["pytest"], ["pytest", "-q"]):
        return True
    return False


def approved_prepare(argv):
    return argv in (
        ["pnpm", "install", "--frozen-lockfile"],
        ["npm", "ci", "--prefer-offline"],
        ["yarn", "install", "--immutable"],
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--original-branch", required=True)
    parser.add_argument("--expected-head", required=True)
    parser.add_argument("--source", required=True)
    parser.add_argument("--expected-source-head", required=True)
    parser.add_argument("--prepare", action="append", default=[], help="Lockfile install after merge, before checks")
    parser.add_argument("--check", action="append", required=True, help="One argv command, quoted as a single argument; no shell")
    args = parser.parse_args()
    preparations = [shlex.split(command) for command in args.prepare]
    checks = [shlex.split(command) for command in args.check]
    if not all(approved_prepare(argv) for argv in preparations) or not all(approved_check(argv) for argv in checks):
        report("BLOCKED_POLICY", "Verification command is outside the approved test/build set")
        return 2
    repo = args.repo.resolve()
    if not repo.is_dir() or git(repo, "rev-parse", "--is-inside-work-tree").stdout.strip() != "true":
        report("BLOCKED_POLICY", "Original checkout is not a Git worktree")
        return 2
    branch = git(repo, "symbolic-ref", "--quiet", "--short", "HEAD")
    head = git(repo, "rev-parse", "HEAD")
    status = git(repo, "status", "--porcelain")
    if branch.stdout.strip() != args.original_branch or head.stdout.strip() != args.expected_head or status.stdout.strip():
        report("BLOCKED_LOCAL", "Original checkout branch, HEAD, or cleanliness changed; no merge attempted")
        return 3
    # Resolve an actual local branch, not an arbitrary revision supplied through --source.
    if args.source.startswith("-") or git(repo, "check-ref-format", "--branch", args.source).returncode:
        report("BLOCKED_POLICY", "Source must be a valid local feature branch")
        return 2
    source = git(repo, "rev-parse", "--verify", f"refs/heads/{args.source}^{{commit}}")
    if source.returncode or source.stdout.strip() != args.expected_source_head or source.stdout.strip() == head.stdout.strip() or args.source == args.original_branch:
        report("BLOCKED_POLICY", "Source commit or branch is invalid")
        return 2
    ancestor = git(repo, "merge-base", "--is-ancestor", source.stdout.strip(), "HEAD")
    if ancestor.returncode == 0:
        report("ALREADY_INTEGRATED", "Source is already in the original checkout", head=head.stdout.strip())
        return 0
    merge = git(repo, "merge", "--no-ff", "--no-commit", source.stdout.strip())
    if merge.returncode:
        git(repo, "merge", "--abort")
        report("BLOCKED_LOCAL", "Merge conflict; original checkout restored", detail=merge.stderr.strip()[-1200:])
        return 3
    for argv in preparations:
        result = run(repo, argv)
        if result.returncode:
            git(repo, "merge", "--abort")
            report("BLOCKED_LOCAL", "Dependency preparation failed; source merge aborted", prepare=argv, detail=(result.stderr or result.stdout)[-1200:])
            return 3
    for argv in checks:
        result = run(repo, argv)
        if result.returncode:
            git(repo, "merge", "--abort")
            report("BLOCKED_LOCAL", "Post-merge verification failed; original checkout restored", check=argv, detail=(result.stderr or result.stdout)[-1200:])
            return 3
    committed = git(repo, "commit", "-m", f"Merge {args.source} into {args.original_branch}")
    if committed.returncode:
        git(repo, "merge", "--abort")
        report("BLOCKED_LOCAL", "Merge commit failed", detail=committed.stderr.strip()[-1200:])
        return 3
    final_head = git(repo, "rev-parse", "HEAD").stdout.strip()
    report("INTEGRATED", "Verified feature merged into original checkout", original_branch=args.original_branch, source=args.source, head=final_head, preparations=args.prepare, checks=args.check)
    return 0


if __name__ == "__main__":
    sys.exit(main())
