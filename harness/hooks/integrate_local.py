#!/usr/bin/env python3
"""Merge a reviewed feature commit into the original clean checkout, with checks."""

import argparse
import json
import os
import shlex
import subprocess
import sys
from functools import partial
from pathlib import Path

from process import run as run_process


def run(repo, command, *, timeout=None):
    # Python test runners otherwise leave untracked __pycache__ after an aborted merge.
    return run_process(command, cwd=repo, timeout=timeout,
                       env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})


def run_git(repo, *args, timeout=600):
    return run(repo, ["git", *args], timeout=timeout)


def report(status, message, **extra):
    print(json.dumps({"status": status, "message": message, **extra}))


def abort_merge(repo, message, *, timeout=600, **extra):
    try:
        result = run_git(repo, "merge", "--abort", timeout=timeout)
        aborted = result.returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        aborted = False
    if not aborted:
        message += "; merge abort failed; inspect the checkout before retrying"
    else:
        message += "; source merge aborted"
    report("BLOCKED_LOCAL", message, merge_aborted=aborted, **extra)
    return 3


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
    parser.add_argument("--timeout", type=int, default=600, help="Seconds allowed for each Git command, preparation, check, and abort")
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error("--timeout must be a positive number of seconds")
    try:
        preparations = [shlex.split(command) for command in args.prepare]
        checks = [shlex.split(command) for command in args.check]
    except ValueError as error:
        report("BLOCKED_POLICY", f"Verification command is not a parseable argv: {error}")
        return 2
    if not all(approved_prepare(argv) for argv in preparations) or not all(approved_check(argv) for argv in checks):
        report("BLOCKED_POLICY", "Verification command is outside the approved test/build set")
        return 2
    return integrate(args, preparations, checks)


def integrate(args, preparations, checks):
    repo = args.repo.resolve()
    git = partial(run_git, timeout=args.timeout)
    abort = partial(abort_merge, timeout=args.timeout)
    merge_attempted = False
    try:
        toplevel = git(repo, "rev-parse", "--show-toplevel") if repo.is_dir() else None
        # Checks run with cwd=repo, so a subdirectory would merge first and then fail them misleadingly.
        if toplevel is None or toplevel.returncode or Path(toplevel.stdout.strip()).resolve() != repo:
            report("BLOCKED_POLICY", "Original checkout must be the root of a Git worktree")
            return 2
        branch = git(repo, "symbolic-ref", "--quiet", "--short", "HEAD")
        head = git(repo, "rev-parse", "HEAD")
        status = git(repo, "status", "--porcelain")
        if branch.returncode or head.returncode or status.returncode or branch.stdout.strip() != args.original_branch or head.stdout.strip() != args.expected_head or status.stdout.strip():
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
        merge_attempted = True
        merge = git(repo, "merge", "--no-ff", "--no-commit", source.stdout.strip())
        if merge.returncode:
            return abort(repo, "Merge failed", detail=merge.stderr.strip()[-1200:])
        for kind, commands in (("prepare", preparations), ("check", checks)):
            for argv in commands:
                try:
                    result = run(repo, argv, timeout=args.timeout)
                except subprocess.TimeoutExpired:
                    return abort(repo, f"{kind.capitalize()} exceeded {args.timeout} seconds", **{kind: argv})
                except OSError:
                    return abort(repo, f"{kind.capitalize()} could not start", **{kind: argv})
                if result.returncode:
                    return abort(repo, f"{kind.capitalize()} failed", **{kind: argv},
                                       detail=(result.stderr or result.stdout)[-1200:])
        committed = git(repo, "commit", "-m", f"Merge {args.source} into {args.original_branch}")
        if committed.returncode:
            return abort(repo, "Merge commit failed", detail=committed.stderr.strip()[-1200:])
        final = git(repo, "rev-parse", "HEAD")
        if final.returncode:
            report("BLOCKED_LOCAL", "Merge commit returned success but final HEAD could not be read; inspect the checkout")
            return 3
        final_head = final.stdout.strip()
        report("INTEGRATED", "Verified feature merged into original checkout", original_branch=args.original_branch, source=args.source, head=final_head, preparations=args.prepare, checks=args.check)
        return 0
    except (subprocess.TimeoutExpired, OSError) as error:
        message = (f"Git command exceeded {args.timeout} seconds" if isinstance(error, subprocess.TimeoutExpired)
                   else "Git command could not start")
        if merge_attempted:
            return abort(repo, message)
        report("BLOCKED_LOCAL", message + "; no merge attempted")
        return 3


if __name__ == "__main__":
    sys.exit(main())
