#!/usr/bin/env python3
"""Merge a reviewed feature commit into the original clean checkout, with checks."""

import argparse
import json
import os
import selectors
import shlex
import subprocess
import sys
import time
from functools import partial
from pathlib import Path

from process import cleanup_discarded, run as run_process


# Git environment variables can redirect commands away from the named worktree
# or its normal index. Identity and test-isolation settings do not do that.
ALLOWED_GIT_ENV = {
    'GIT_AUTHOR_NAME', 'GIT_AUTHOR_EMAIL', 'GIT_AUTHOR_DATE',
    'GIT_COMMITTER_NAME', 'GIT_COMMITTER_EMAIL', 'GIT_COMMITTER_DATE',
    'GIT_CONFIG_GLOBAL', 'GIT_CONFIG_NOSYSTEM', 'GIT_TERMINAL_PROMPT',
}
INSPECTION_CONFIG = ('-c', 'core.fsmonitor=false', '-c', 'core.untrackedCache=false',
                     '-c', 'core.trustctime=true', '-c', 'core.checkStat=default',
                     '-c', 'core.filemode=true')
INDEX_MAX_BYTES = 40_000_000
INDEX_MAX_ENTRIES = 250_000
INDEX_MAX_RECORD_BYTES = 1_000_000
INDEX_MAX_SECONDS = 30
INDEX_HEADER_BYTES = 9  # tag, space, six-digit mode, space


class IndexInspectionError(Exception):
    def __init__(self, *, cleanup_incomplete=False):
        super().__init__('Index could not be verified')
        self.cleanup_incomplete = cleanup_incomplete


def index_unflagged(repo, timeout):
    """Check NUL records without retaining paths or trusting Git's fsmonitor cache."""
    command = ['git', *INSPECTION_CONFIG, 'ls-files', '-v', '-s', '-z']
    deadline = time.monotonic() + min(timeout, INDEX_MAX_SECONDS)
    try:
        process = subprocess.Popen(command, cwd=repo, env={**os.environ, 'PYTHONDONTWRITEBYTECODE': '1'},
                                   stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   start_new_session=True)
    except OSError as error:
        raise IndexInspectionError() from error
    bytes_seen = entries = record_bytes = 0
    prefix = b''
    reaped = False
    try:
        with selectors.DefaultSelector() as poller:
            poller.register(process.stdout, selectors.EVENT_READ)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not poller.select(remaining):
                    raise IndexInspectionError()
                chunk = os.read(process.stdout.fileno(), 65536)
                if not chunk:
                    break
                bytes_seen += len(chunk)
                if bytes_seen > INDEX_MAX_BYTES:
                    raise IndexInspectionError()
                offset = 0
                while offset < len(chunk):
                    end = chunk.find(b'\0', offset)
                    segment = chunk[offset:] if end < 0 else chunk[offset:end]
                    record_bytes += len(segment)
                    if record_bytes > INDEX_MAX_RECORD_BYTES:
                        raise IndexInspectionError()
                    if len(prefix) < INDEX_HEADER_BYTES:
                        prefix += segment[:INDEX_HEADER_BYTES - len(prefix)]
                    if end < 0:
                        break
                    if (len(prefix) != INDEX_HEADER_BYTES or prefix[:2] != b'H '
                            or prefix[2:8] not in {b'100644', b'100755', b'120000'}
                            or prefix[8:] != b' '):
                        # A gitlink has its own index, where hidden flags can
                        # conceal child edits from the superproject's status.
                        raise IndexInspectionError()
                    entries += 1
                    if entries > INDEX_MAX_ENTRIES:
                        raise IndexInspectionError()
                    prefix = b''
                    record_bytes = 0
                    offset = end + 1
        if record_bytes:
            raise IndexInspectionError()
        process.wait(timeout=max(0, deadline - time.monotonic()))
        reaped = True
        if process.returncode:
            raise IndexInspectionError()
    except BaseException as error:
        cleanup_incomplete = False
        if not reaped:
            try:
                cleanup_discarded(process)
            except (OSError, subprocess.TimeoutExpired):
                cleanup_incomplete = True
        if isinstance(error, (KeyboardInterrupt, SystemExit)):
            raise
        raise IndexInspectionError(cleanup_incomplete=cleanup_incomplete) from None
    finally:
        if process.stdout and not process.stdout.closed:
            process.stdout.close()


def inspect_git(repo, *args, timeout=600):
    return run_git(repo, *INSPECTION_CONFIG, *args, timeout=timeout)


def run(repo, command, *, timeout=None, discard_output=False):
    # Python test runners otherwise leave untracked __pycache__ after an aborted merge.
    output_options = {'discard_output': True} if discard_output else {}
    return run_process(command, cwd=repo, timeout=timeout,
                       env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
                       **output_options)


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
    if any(name.startswith('GIT_') and name not in ALLOWED_GIT_ENV for name in os.environ):
        report('BLOCKED_POLICY', 'Inherited Git routing or configuration override is unsupported')
        return 2
    repo = args.repo.resolve()
    git = partial(run_git, timeout=args.timeout)
    inspect = partial(inspect_git, timeout=args.timeout)
    abort = partial(abort_merge, timeout=args.timeout)
    merge_attempted = False
    commit_returned = False
    try:
        toplevel = git(repo, "rev-parse", "--show-toplevel") if repo.is_dir() else None
        # Checks run with cwd=repo, so a subdirectory would merge first and then fail them misleadingly.
        if toplevel is None or toplevel.returncode or Path(toplevel.stdout.strip()).resolve() != repo:
            report("BLOCKED_POLICY", "Original checkout must be the root of a Git worktree")
            return 2
        branch = git(repo, "symbolic-ref", "--quiet", "--short", "HEAD")
        head = git(repo, "rev-parse", "HEAD")
        index_unflagged(repo, args.timeout)
        status = inspect(repo, "status", "--porcelain", "--untracked-files=all",
                         "--ignore-submodules=none")
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
            return abort(repo, "Merge failed", phase="merge", exit_code=merge.returncode)
        intended = git(repo, "write-tree")
        if intended.returncode or not intended.stdout.strip():
            return abort(repo, "Could not record intended merge tree")
        intended_tree = intended.stdout.strip()
        for kind, commands in (("prepare", preparations), ("check", checks)):
            for argv in commands:
                try:
                    result = run(repo, argv, timeout=args.timeout, discard_output=True)
                except subprocess.TimeoutExpired as error:
                    if getattr(error, 'cleanup_incomplete', False):
                        report("BLOCKED_LOCAL", f"{kind.capitalize()} cleanup incomplete; inspect processes and checkout",
                               phase=kind, merge_aborted=False, **{kind: argv})
                        return 3
                    return abort(repo, f"{kind.capitalize()} exceeded {args.timeout} seconds", phase=kind,
                                 **{kind: argv})
                except OSError as error:
                    if getattr(error, 'cleanup_incomplete', False):
                        report("BLOCKED_LOCAL", f"{kind.capitalize()} cleanup incomplete; inspect processes and checkout",
                               phase=kind, merge_aborted=False, **{kind: argv})
                        return 3
                    return abort(repo, f"{kind.capitalize()} could not start", phase=kind,
                                 **{kind: argv})
                if result.returncode:
                    # Child output can contain arbitrary credentials. The approved argv
                    # and exit code tell the user which command to run locally.
                    return abort(repo, f"{kind.capitalize()} failed", phase=kind,
                                 exit_code=result.returncode, **{kind: argv})
        index_unflagged(repo, args.timeout)
        checked_tree = git(repo, "write-tree")
        unstaged = inspect(repo, "diff", "--quiet", "--exit-code", "--ignore-submodules=none")
        untracked = inspect(repo, "ls-files", "--others", "--exclude-standard")
        if (checked_tree.returncode or checked_tree.stdout.strip() != intended_tree
                or unstaged.returncode or untracked.returncode or untracked.stdout.strip()):
            return abort(repo, "Preparation or checks changed the intended merge; inspect and rerun from a clean checkout")
        before_commit_branch = git(repo, "symbolic-ref", "--quiet", "--short", "HEAD")
        if before_commit_branch.returncode or before_commit_branch.stdout.strip() != args.original_branch:
            return abort(repo, "Original branch changed during checks")
        committed = git(repo, "commit", "-m", f"Merge {args.source} into {args.original_branch}")
        if committed.returncode:
            return abort(repo, "Merge commit failed", phase="commit", exit_code=committed.returncode)
        commit_returned = True
        final = git(repo, "rev-parse", "HEAD")
        if final.returncode or not final.stdout.strip():
            report("BLOCKED_LOCAL", "Merge commit returned success but final HEAD could not be read; inspect the checkout")
            return 3
        final_head = final.stdout.strip()
        parents = git(repo, "rev-list", "--parents", "-n", "1", "HEAD")
        if parents.returncode or parents.stdout.split() != [final_head, head.stdout.strip(), source.stdout.strip()]:
            report("BLOCKED_LOCAL", "Final HEAD is not the verified two-parent merge; inspect the checkout",
                   head=final_head, merge_aborted=False)
            return 3
        final_tree = git(repo, "rev-parse", "HEAD^{tree}")
        if final_tree.returncode or final_tree.stdout.strip() != intended_tree:
            report("BLOCKED_LOCAL", "Merge commit contains changes outside the verified merge tree; inspect the checkout",
                   head=final_head, merge_aborted=False)
            return 3
        final_branch = git(repo, "symbolic-ref", "--quiet", "--short", "HEAD")
        original_ref = git(repo, "rev-parse", "--verify", f"refs/heads/{args.original_branch}")
        if (final_branch.returncode or final_branch.stdout.strip() != args.original_branch
                or original_ref.returncode or original_ref.stdout.strip() != final_head):
            report("BLOCKED_LOCAL", "Merge commit is not on the original branch; inspect branch refs",
                   head=final_head, merge_aborted=False)
            return 3
        index_unflagged(repo, args.timeout)
        final_status = inspect(repo, "status", "--porcelain", "--untracked-files=all",
                               "--ignore-submodules=none")
        if final_status.returncode or final_status.stdout.strip():
            report("BLOCKED_LOCAL", "Merge commit exists but final checkout is dirty or could not be inspected",
                   head=final_head, merge_aborted=False)
            return 3
        report("INTEGRATED", "Verified feature merged into original checkout", original_branch=args.original_branch, source=args.source, head=final_head, preparations=args.prepare, checks=args.check)
        return 0
    except IndexInspectionError as error:
        message = 'Index could not be verified'
        if error.cleanup_incomplete:
            report('BLOCKED_LOCAL', message + '; inspection cleanup incomplete; inspect processes and checkout',
                   merge_aborted=False)
            return 3
        if commit_returned:
            report('BLOCKED_LOCAL', message + '; merge commit may exist; inspect HEAD and checkout',
                   merge_aborted=False)
            return 3
        if merge_attempted:
            return abort(repo, message)
        report('BLOCKED_LOCAL', message + '; no merge attempted')
        return 3
    except (subprocess.TimeoutExpired, OSError) as error:
        message = (f"Git command exceeded {args.timeout} seconds" if isinstance(error, subprocess.TimeoutExpired)
                   else "Git command could not start")
        if commit_returned:
            report("BLOCKED_LOCAL", message + "; merge commit may exist; inspect HEAD and checkout",
                   merge_aborted=False)
            return 3
        if merge_attempted:
            return abort(repo, message)
        report("BLOCKED_LOCAL", message + "; no merge attempted")
        return 3


if __name__ == "__main__":
    sys.exit(main())
