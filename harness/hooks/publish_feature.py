#!/usr/bin/env python3
"""Publish one clean feature branch without force or default-branch pushes."""

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path


def git(repo, *args):
    return subprocess.run(["git", "-C", str(repo), *args], text=True, capture_output=True)


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
    args = parser.parse_args()
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
    ref = f"refs/heads/{args.branch}"
    result = git(repo, "push", "--porcelain", remote, f"{ref}:{ref}")
    if result.returncode:
        detail = scrub(result.stderr or result.stdout)
        report("BLOCKED_REMOTE", "Feature branch could not be published; continue local integration", branch=args.branch, remote=remote, detail=detail)
        return 4
    report("PUSHED", "Feature branch published", branch=args.branch, remote=remote, head=head)
    return 0


if __name__ == "__main__":
    sys.exit(main())
