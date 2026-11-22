"""Authorize and consume an independent native PR review through signed main calls."""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shlex
import stat
import subprocess
import sys
import time

import caller_identity
import merge_gate
import native_pr_review as review
import spec_flow

PURPOSE = "native-pr-authorization"
HEX = re.compile(r"[0-9a-f]{64}")
FLAGS = {"--repo", "--github-repo", "--pr", "--head", "--base", "--packet", "--tests",
         "--bundle", "--context-sha256", "--bundle-sha256"}


def parser():
    result = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    result.add_argument("action", choices=("authorize", "merge", "reconcile"))
    review.add_context_args(result)
    result.add_argument("--bundle", type=Path, required=True)
    result.add_argument("--context-sha256", required=True)
    result.add_argument("--bundle-sha256", required=True)
    return result


def stamp_parts(args):
    paths = {key: str(getattr(args, key).expanduser().resolve()) for key in ("repo", "packet", "tests", "bundle")}
    return [args.action, args.github_repo, args.pr, args.head, args.base, args.context_sha256,
            args.bundle_sha256, review.digest(review.canonical(paths).encode())]


def direct_args(command, home=None):
    """Only the installed helper in one plain command can receive a main stamp."""
    if not isinstance(command, str) or re.search(r"[\n;&|`<>]|\$\(", command):
        return None
    try:
        words = shlex.split(command)
        if len(words) != 23 or words[0] not in {
                "/usr/bin/python3", "/opt/homebrew/bin/python3", "/opt/homebrew/bin/python3.13",
                "/opt/homebrew/bin/python3.14"}:
            return None
        home = Path.home() if home is None else Path(home)
        helper = Path(os.path.expanduser(words[1]))
        allowed = {home / ".claude/hooks/native_pr_dispatch.py", home / ".codex/agent-harness/native_pr_dispatch.py"}
        if helper not in allowed or helper.is_symlink() or not helper.is_file():
            return None
        if set(words[3::2]) != FLAGS or len(words[3::2]) != len(FLAGS):
            return None
        args = parser().parse_args(words[2:])
        if not HEX.fullmatch(args.context_sha256) or not HEX.fullmatch(args.bundle_sha256):
            return None
        return args
    except (ValueError, OSError, SystemExit):
        return None


def _private_directory(path):
    home = Path.home()
    if not path.is_relative_to(home):
        raise ValueError("native release state must be inside the current home")
    parents = [home]
    for part in path.relative_to(home).parts:
        parents.append(parents[-1] / part)
    for parent in parents:
        if not os.path.lexists(parent):
            parent.mkdir(mode=0o700)
        info = parent.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or info.st_mode & 0o022):
            raise ValueError("native release directory is not private or is aliased")
    if path.stat().st_mode & 0o077:
        raise ValueError("native release state is not private")


@contextmanager
def journal(repository, number):
    root = Path.home() / ".agent-harness/native-pr-releases"
    _private_directory(root)
    key = hashlib.sha256(f"{repository}|{number}".encode()).hexdigest()
    lock_path = root / (key + ".lock")
    fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        info = os.fstat(fd)
        if info.st_uid != os.getuid() or info.st_nlink != 1 or info.st_mode & 0o077:
            raise ValueError("native release lock is invalid")
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield root / (key + ".json")
    finally:
        os.close(fd)


def load(path):
    if not os.path.lexists(path):
        return None
    info = path.lstat()
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1
            or info.st_mode & 0o077):
        raise ValueError("native release journal is invalid")
    return spec_flow._native_json(spec_flow.read_regular(path, 65536), 65536)


def save(path, value):
    if path.exists() or path.is_symlink():
        load(path)
    temporary = path.with_name(path.name + "." + secrets.token_hex(8))
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write((review.canonical(value) + "\n").encode())
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if temporary.exists():
            temporary.unlink()


def _binding(args, client, root):
    context, no_ci = review.cli_context(args, client)
    if review.context_digest(context) != args.context_sha256:
        raise ValueError("candidate context changed")
    proof = review.verify_bundle(args.bundle, context, args.repo, root=root,
                                 expected_digest=args.bundle_sha256)
    return {"context": context, "proof": proof, "root": root, "no_ci": no_ci}


def send_merge(client, context, *, require_live):
    """Use the protected PR operation with a server-side expected-head check.

    GitHub supplies no expected-base parameter. Base freshness is checked
    before sending and actual merge parents afterward. A concurrent base move
    is detected after the irreversible operation and stays uncertain.
    """
    pull = client.json(["api", f"repos/{context['repo']}/pulls/{context['pr']}"], "merge readiness")
    if (pull.get("state") != "open" or pull.get("draft") is not False or pull.get("mergeable") is not True
            or (pull.get("base") or {}).get("sha") != context["base"]
            or (pull.get("base") or {}).get("ref") != context["base_ref"]
            or (pull.get("head") or {}).get("sha") != context["head"]
            or (pull.get("head") or {}).get("ref") != context["head_ref"]
            or ((pull.get("head") or {}).get("repo") or {}).get("full_name", "").lower() != context["repo"]):
        raise ValueError("the PR is not ready at the reviewed base and head")
    body = {"sha": context["head"], "merge_method": "merge"}
    require_live()
    result = subprocess.run(["/opt/homebrew/bin/gh", "api", "--hostname", "github.com", "--method", "PUT",
                             f"repos/{context['repo']}/pulls/{context['pr']}/merge", "--input", "-"], input=review.canonical(body),
                            capture_output=True, text=True, timeout=30)
    if result.returncode or len(result.stdout) > 65536:
        raise ValueError("remote update has uncertain or rejected outcome; reconcile the journal")
    response = spec_flow._native_json(result.stdout, 65536)
    if response.get("merged") is not True or not isinstance(response.get("sha"), str):
        raise ValueError("remote update was not confirmed; reconcile the journal")


def _live_for(args, root, binding):
    def matching(command):
        parsed = direct_args(command)
        return parsed is not None and stamp_parts(parsed) == stamp_parts(args)
    return (isinstance(binding, dict) and binding.get("session") == root
            and review.native_call_still_running(binding, match_command=matching))


def execute(args, client, root, *, clock=time.time, send=send_merge):
    def require_live():
        binding = getattr(args, "native_binding", None)
        if not _live_for(args, root, binding):
            raise ValueError("the authorizing native call is not running")
    require_live()
    with journal(args.github_repo, args.pr) as path:
        prior = load(path)
        if args.action == "reconcile":
            if (not prior or prior.get("phase") not in ("PENDING", "COMPLETE")
                    or prior.get("binding", {}).get("root") != root):
                raise ValueError("there is no matching submitted native release")
            context = prior["binding"]["context"]
            if (review.context_digest(context) != args.context_sha256 or context["repo"] != args.github_repo
                    or context["pr"] != args.pr or context["base"] != args.base or context["head"] != args.head):
                raise ValueError("reconciliation context does not match the submitted release")
            _confirm_remote(args, client, context)
            require_live()
            save(path, {**prior, "phase": "COMPLETE", "reconciled_at": clock()})
            return {"status": "MERGED", "head": args.head, "pr": args.pr, "repo": args.github_repo}
        if prior and prior.get("phase") in ("PENDING", "COMPLETE"):
            raise ValueError("release was submitted already; retain and reconcile its journal")
        binding = _binding(args, client, root)
        if args.action == "authorize":
            require_live()
            save(path, {"phase": "AUTHORIZED", "binding": binding, "expires_at": clock() + 1800})
            return {"status": "AUTHORIZED", "context_sha256": args.context_sha256}
        if (not prior or prior.get("phase") != "AUTHORIZED" or prior.get("binding") != binding
                or type(prior.get("expires_at")) not in (int, float) or prior["expires_at"] < clock()):
            raise ValueError("a fresh main-authorized matching native grant is required")
        # One final context/proof read before recording the irreversible send intent.
        if _binding(args, client, root) != binding:
            raise ValueError("release changed at consumption")
        pending = {**prior, "phase": "PENDING", "submitted_at": clock()}
        save(path, pending)
        require_live()
        send(client, binding["context"], require_live=require_live)
        _confirm_remote(args, client, binding["context"])
        save(path, {**pending, "phase": "COMPLETE", "completed_at": clock()})
        return {"status": "MERGED", "head": args.head, "pr": args.pr, "repo": args.github_repo}


def _confirm_remote(args, client, context):
    row = client.json(["api", f"repos/{args.github_repo}/pulls/{args.pr}"], "merged PR readback")
    merge_sha = row.get("merge_commit_sha")
    if not isinstance(merge_sha, str) or not re.fullmatch(r"[0-9a-f]{40}", merge_sha):
        raise ValueError("remote completion is uncertain; missing merge identity")
    commit = client.json(["api", f"repos/{args.github_repo}/git/commits/{merge_sha}"], "merge parent readback")
    if (row.get("merged") is not True or (row.get("head") or {}).get("sha") != args.head
            or (row.get("head") or {}).get("ref") != context["head_ref"]
            or ((row.get("head") or {}).get("repo") or {}).get("full_name", "").lower() != args.github_repo
            or (row.get("base") or {}).get("ref") != context["base_ref"]
            or ((row.get("base") or {}).get("repo") or {}).get("full_name", "").lower() != args.github_repo
            or commit.get("sha") != merge_sha
            or [parent.get("sha") for parent in commit.get("parents", [])] != [args.base, args.head]):
        raise ValueError("remote completion is uncertain; retain PENDING journal and reconcile")
    target = client.json(["api", f"repos/{args.github_repo}/git/ref/heads/{context['base_ref']}"],
                         "current target readback")
    target_sha = (target.get("object") or {}).get("sha")
    if not isinstance(target_sha, str) or not re.fullmatch(r"[0-9a-f]{40}", target_sha):
        raise ValueError("remote completion is uncertain; target identity unavailable")
    if target_sha != merge_sha:
        comparison = client.json(["api", f"repos/{args.github_repo}/compare/{merge_sha}...{target_sha}"],
                                 "current target merge ancestry")
        if ((comparison.get("base_commit") or {}).get("sha") != merge_sha
                or (comparison.get("merge_base_commit") or {}).get("sha") != merge_sha
                or comparison.get("status") != "ahead"):
            raise ValueError("remote completion is uncertain; target no longer contains the merge")


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        if (merge_gate.repo_key(args.github_repo) != args.github_repo
                or not HEX.fullmatch(args.context_sha256) or not HEX.fullmatch(args.bundle_sha256)):
            raise ValueError("invalid context or bundle digest")
        stamp = caller_identity.take_stamp(PURPOSE, stamp_parts(args))
        root = (stamp or {}).get("session")
        if not isinstance(root, str) or not re.fullmatch(spec_flow.UUID, root):
            raise ValueError("a fresh signed Desktop main command is required")
        args.native_binding = stamp.get("native_binding")
        if not _live_for(args, root, args.native_binding):
            raise ValueError("the native authority call has ended or cannot be verified")
        client = review.github_client(time.monotonic() + 120, str(args.repo))
        print(review.canonical(execute(args, client, root)))
        return 0
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError,
            spec_flow.SpecError, merge_gate.GateError):
        print("native PR operation refused; preserve its journal and inspect the current evidence", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
