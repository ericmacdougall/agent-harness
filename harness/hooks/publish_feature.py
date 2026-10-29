#!/usr/bin/env python3
"""Publish one clean feature branch without force or default-branch pushes."""

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

from process import run


def git(repo, *args, timeout=None):
    # Headless use: a missing credential must fail the push, not wait on a terminal prompt.
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
    return run(["git", "-C", str(repo), *args], env=env, timeout=timeout)


def report(status, message, **extra):
    print(json.dumps({"status": status, "message": message, **extra}))


def scrub(value):
    value = re.sub(r"(https?://)[^/@\s]+@", r"\1[redacted]@", value)
    value = re.sub(r"(?i)\b(token|password|secret|access[_-]?key)=([^\s&]+)", r"\1=[redacted]", value)
    value = re.sub(r"\b(gh[pousr]_[A-Za-z0-9]+|github_pat_[A-Za-z0-9_]+)\b", "[redacted]", value)
    return value.strip()[:1200]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--branch", required=True)
    parser.add_argument("--original-branch", required=True)
    parser.add_argument("--expected-head", required=True)
    parser.add_argument("--timeout", type=int, default=600, help="Seconds to wait for the push before reporting BLOCKED_REMOTE")
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error("--timeout must be a positive number of seconds")
    repo = args.repo.resolve()
    if not repo.is_dir() or git(repo, "rev-parse", "--is-inside-work-tree").stdout.strip() != "true":
        report("BLOCKED_POLICY", "Source is not a Git worktree")
        return 2
    valid = git(repo, "check-ref-format", "--branch", args.branch)
    if valid.returncode or args.branch in {"main", "master", "develop", args.original_branch}:
        report("BLOCKED_POLICY", "Refusing to publish a protected or invalid branch")
        return 2
    current = git(repo, "symbolic-ref", "--quiet", "--short", "HEAD")
    if current.returncode or current.stdout.strip() != args.branch:
        report("BLOCKED_POLICY", "Source worktree is not on the requested branch")
        return 2
    head = git(repo, "rev-parse", "HEAD").stdout.strip()
    if head != args.expected_head:
        report("BLOCKED_POLICY", "Source HEAD changed since final verification")
        return 2
    status = git(repo, "status", "--porcelain")
    if status.returncode or status.stdout.strip():
        report("BLOCKED_POLICY", "Commit or discard source changes before publishing")
        return 2
    remote = "origin"
    if remote not in git(repo, "remote").stdout.splitlines():
        report("BLOCKED_REMOTE", "Configured remote is unavailable", branch=args.branch, remote=remote)
        return 4
    # A repository may call its default branch trunk, release, or something else.
    # Refuse publication when the remote does not reveal a default branch.
    try:
        default = git(repo, "ls-remote", "--symref", remote, "HEAD", timeout=min(args.timeout, 30))
    except subprocess.TimeoutExpired:
        report("BLOCKED_REMOTE", "Could not determine the remote default branch in time; continue local integration", branch=args.branch, remote=remote)
        return 4
    if default.returncode:
        report("BLOCKED_REMOTE", "Could not determine the remote default branch; continue local integration",
               branch=args.branch, remote=remote, detail=scrub(default.stderr or default.stdout))
        return 4
    match = re.search(r"^ref: refs/heads/(\S+)\s+HEAD$", default.stdout, re.MULTILINE)
    if match is None:
        report("BLOCKED_REMOTE", "Remote default branch is not advertised; continue local integration",
               branch=args.branch, remote=remote)
        return 4
    if args.branch == match.group(1):
        report("BLOCKED_POLICY", "Refusing to publish the remote default branch", branch=args.branch, remote=remote)
        return 2
    ref = f"refs/heads/{args.branch}"
    try:
        result = git(repo, "push", "--porcelain", remote, f"{ref}:{ref}", timeout=args.timeout)
    except subprocess.TimeoutExpired:
        report("BLOCKED_REMOTE", f"Push did not finish within {args.timeout} seconds; continue local integration", branch=args.branch, remote=remote)
        return 4
    if result.returncode:
        detail = scrub(result.stderr or result.stdout)
        report("BLOCKED_REMOTE", "Feature branch could not be published; continue local integration", branch=args.branch, remote=remote, detail=detail)
        return 4
    report("PUSHED", "Feature branch published", branch=args.branch, remote=remote, head=head)
    return 0


if __name__ == "__main__":
    sys.exit(main())
