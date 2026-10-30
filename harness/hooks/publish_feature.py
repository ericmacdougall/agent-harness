#!/usr/bin/env python3
"""Publish one clean feature branch without force or default-branch pushes."""

import argparse
import json
import os
import re
import secrets
import selectors
import signal
import subprocess
import sys
import tempfile
import time
from functools import partial
from pathlib import Path

from process import run, signal_group


def run_git(repo, *args, timeout=600, env_extra=None, text=True, input=None):
    # Headless use: a missing credential must fail the push, not wait on a terminal prompt.
    env = {**os.environ, "GIT_TERMINAL_PROMPT": "0"}
    if env_extra:
        env.update(env_extra)
    env["GIT_NO_REPLACE_OBJECTS"] = "1"
    return run(["git", "-C", str(repo), *args], env=env, timeout=timeout, text=text, input=input)


def report(status, message, **extra):
    print(json.dumps({"status": status, "message": message, **extra}))


def scrub(value):
    value = re.sub(r"(https?://)[^/@\s]+@", r"\1[redacted]@", value)
    value = re.sub(r"(?i)\b(token|password|secret|access[_-]?key)=([^\s&]+)", r"\1=[redacted]", value)
    value = re.sub(r"\b(gh[pousr]_[A-Za-z0-9]+|github_pat_[A-Za-z0-9_]+)\b", "[redacted]", value)
    return value.strip()[:1200]


def pinned_url(url, repo):
    # Git resolves a local relative remote against the current -C directory.
    # The isolated transport uses another directory, so make that target stable.
    colon = url.find(':')
    slash = url.find('/')
    if colon < 0 or (slash >= 0 and slash < colon):
        return str((repo / Path(url).expanduser()).resolve())
    return url


LFS_OBJECT_LIMIT = 300_000
LFS_ENUMERATION_BYTE_LIMIT = 19_500_000  # 300,000 SHA-256 IDs plus newlines


def reachable_oids(repo, head, timeout):
    """Read fixed-size ID records; never buffer unbounded rev-list output or paths."""
    command = ['git', '-C', str(repo), 'rev-list', '--objects', '--no-object-names',
               '--filter=blob:limit=1024', head]
    env = {**os.environ, 'GIT_TERMINAL_PROMPT': '0', 'GIT_NO_REPLACE_OBJECTS': '1'}
    process = subprocess.Popen(command, env=env, stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL, start_new_session=True)
    deadline = time.monotonic() + timeout
    oids, pending, total = [], b'', 0
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(command, timeout)
                if not selector.select(remaining):
                    raise subprocess.TimeoutExpired(command, timeout)
                chunk = os.read(process.stdout.fileno(), 65536)
                if not chunk:
                    break
                total += len(chunk)
                if total > LFS_ENUMERATION_BYTE_LIMIT:
                    raise ValueError('LFS enumeration byte budget exceeded')
                lines = (pending + chunk).split(b'\n')
                pending = lines.pop()
                for oid in lines:
                    if not re.fullmatch(rb'(?:[0-9a-f]{40}|[0-9a-f]{64})', oid):
                        raise ValueError('malformed reachable object ID')
                    if len(oids) >= LFS_OBJECT_LIMIT:
                        raise ValueError('LFS scan object budget exceeded')
                    oids.append(oid)
                if len(pending) > 64:
                    raise ValueError('oversized reachable object record')
        if pending:
            raise ValueError('truncated reachable object ID')
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise subprocess.TimeoutExpired(command, timeout)
        if process.wait(timeout=remaining):
            raise ValueError('cannot enumerate reachable objects')
        return oids
    finally:
        # Enumeration is read-only: stop immediately on refusal, including writers
        # blocked on the pipe. Never call communicate(), which would buffer output.
        signal_group(process.pid, signal.SIGKILL)
        process.stdout.close()
        process.wait()


def has_reachable_lfs_pointer(repo, head, git, timeout=600):
    """Scan small blobs in all history being published, with bounded work."""
    oids = reachable_oids(repo, head, timeout)
    if not oids:
        raise ValueError('no reachable objects')
    oid_set = set(oids)
    checked = git(repo, 'cat-file', '--batch-check=%(objectname) %(objecttype) %(objectsize)',
                  input=b'\n'.join(oids) + b'\n', text=False)
    if checked.returncode:
        raise ValueError('cannot inspect object sizes')
    blobs = []
    total = 0
    metadata = checked.stdout.splitlines()
    if len(metadata) != len(oids):
        raise ValueError('incomplete object metadata')
    for line in metadata:
        parts = line.split()
        if len(parts) != 3 or parts[0] not in oid_set or not parts[2].isdigit():
            raise ValueError('malformed object metadata')
        size = int(parts[2])
        if parts[1] == b'blob' and 0 < size < 1024:
            blobs.append(parts[0])
            total += size
    if total > 30_000_000:
        raise ValueError('LFS scan byte budget exceeded')
    if not blobs:
        return False
    scanned = git(repo, 'cat-file', '--batch', input=b'\n'.join(blobs) + b'\n', text=False)
    if scanned.returncode:
        raise ValueError('cannot read candidate blobs')
    versions = {'version https://git-lfs.github.com/spec/v1',
                'version https://hawser.github.com/spec/v1',
                'version http://git-media.io/v/2'}
    position = 0
    for oid in blobs:
        end = scanned.stdout.find(b'\n', position)
        if end < 0:
            raise ValueError('truncated blob stream')
        header = scanned.stdout[position:end].split()
        if len(header) != 3 or header[:2] != [oid, b'blob'] or not header[2].isdigit():
            raise ValueError('malformed blob stream')
        size = int(header[2])
        start = end + 1
        finish = start + size
        if scanned.stdout[finish:finish + 1] != b'\n':
            raise ValueError('truncated blob content')
        # Git LFS trims Unicode whitespace, accepts CRLF and legacy aliases,
        # and permits extension records before version. Conservatively refuse
        # any matching version line, even if the rest is not a valid pointer.
        content = scanned.stdout[start:finish].decode('utf-8', errors='replace').strip()
        if any(line in versions for line in content.splitlines()):
            return True
        position = finish + 1
    return False


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, required=True)
    parser.add_argument("--branch", required=True)
    parser.add_argument("--original-branch", required=True)
    parser.add_argument("--expected-head", required=True)
    parser.add_argument("--timeout", type=int, default=600, help="Seconds allowed for each Git command, including the push")
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error("--timeout must be a positive number of seconds")
    try:
        return publish(args)
    except subprocess.TimeoutExpired:
        report("BLOCKED_REMOTE", f"Local Git inspection exceeded {args.timeout} seconds; no push attempted")
        return 4
    except OSError:
        report("BLOCKED_REMOTE", "Git command could not start; publication incomplete")
        return 4


def publish(args):
    git = partial(run_git, timeout=args.timeout)
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
    # Fetch and push can target different repositories (including pushInsteadOf rewrites).
    destinations = git(repo, "remote", "get-url", "--push", "--all", remote)
    urls = destinations.stdout.splitlines()
    if destinations.returncode or not urls:
        report("BLOCKED_REMOTE", "Could not resolve the push destination", branch=args.branch, remote=remote)
        return 4
    if len(urls) != 1:
        report("BLOCKED_POLICY", "Publication requires exactly one push destination", branch=args.branch, remote=remote)
        return 2
    destination = pinned_url(urls[0], repo)
    # Keep credential-bearing URLs out of process arguments. The temporary
    # remote exists only in this command's environment and is never persisted.
    pinned_remote = "harness-push-" + secrets.token_hex(12)
    pinned_env = {
        "GIT_CONFIG_COUNT": "2",
        "GIT_CONFIG_KEY_0": f"remote.{pinned_remote}.url",
        "GIT_CONFIG_VALUE_0": destination,
        "GIT_CONFIG_KEY_1": f"remote.{pinned_remote}.pushurl",
        "GIT_CONFIG_VALUE_1": destination,
    }
    # get-url already expanded rewrites. Refuse a second expansion that would make
    # ls-remote inspect a different repository from the one `push origin` uses.
    inspected = git(repo, "ls-remote", "--get-url", "--", pinned_remote, env_extra=pinned_env)
    if inspected.returncode or inspected.stdout.strip() != destination:
        report("BLOCKED_POLICY", "Push destination cannot be inspected without another URL rewrite",
               branch=args.branch, remote=remote)
        return 2
    # A repository may call its default branch trunk, release, or something else.
    # Refuse publication when the remote does not reveal a default branch.
    try:
        default = git(repo, "ls-remote", "--symref", "--", pinned_remote, "HEAD", timeout=min(args.timeout, 30), env_extra=pinned_env)
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
    # The isolated transport omits source pre-push hooks. Git LFS uploads in
    # that hook, so reject any pointer in reachable history before pushing.
    try:
        contains_lfs = has_reachable_lfs_pointer(repo, head, git, timeout=args.timeout)
    except ValueError:
        report("BLOCKED_REMOTE", "Could not verify whether Git LFS content needs uploading; continue local integration",
               branch=args.branch, remote=remote)
        return 4
    if contains_lfs:
        report("BLOCKED_POLICY", "Git LFS pointer found; publish with an LFS-aware workflow",
               branch=args.branch, remote=remote)
        return 2
    ref = f"refs/heads/{args.branch}"
    # A concurrent edit to origin.pushurl must not redirect the push.
    try:
        # Source-local Git URL rewrites can change after inspection. Push from
        # an isolated bare repository that reads the source object store through
        # alternates; this avoids a second copy of the project's history and
        # avoids executing source-worktree pre-push hooks during delivery.
        with tempfile.TemporaryDirectory(prefix='harness-publish-') as temporary:
            transport = Path(temporary) / 'transport.git'
            template = Path(temporary) / 'empty-template'
            template.mkdir()
            object_format = git(repo, 'rev-parse', '--show-object-format=storage')
            format_name = object_format.stdout.strip()
            if object_format.returncode or format_name not in {'sha1', 'sha256'}:
                report('BLOCKED_REMOTE', 'Could not determine source object format', branch=args.branch, remote=remote)
                return 4
            initialized = git(temporary, 'init', '--bare', f'--object-format={format_name}', '--template', str(template), str(transport))
            if initialized.returncode:
                report('BLOCKED_REMOTE', 'Could not prepare isolated publication transport', branch=args.branch, remote=remote)
                return 4
            object_store = git(repo, 'rev-parse', '--path-format=absolute', '--git-path', 'objects')
            object_path = Path(object_store.stdout.rstrip('\n'))
            if object_store.returncode or not object_path.is_dir() or '\n' in str(object_path):
                report('BLOCKED_REMOTE', 'Could not locate source objects for publication', branch=args.branch, remote=remote)
                return 4
            (transport / 'objects/info/alternates').write_text(str(object_path) + '\n')
            commit_type = git(transport, 'cat-file', '-t', head)
            if commit_type.returncode or commit_type.stdout.strip() != 'commit':
                report('BLOCKED_REMOTE', 'Could not load verified commit for publication', branch=args.branch, remote=remote)
                return 4
            resolved = git(transport, 'ls-remote', '--get-url', '--', pinned_remote, env_extra=pinned_env)
            if resolved.returncode or resolved.stdout.strip() != destination:
                report('BLOCKED_POLICY', 'Isolated transport would rewrite the inspected destination', branch=args.branch, remote=remote)
                return 2
            result = git(transport, 'push', '--porcelain', pinned_remote,
                         f"{head}:{ref}", timeout=args.timeout, env_extra=pinned_env)
    except subprocess.TimeoutExpired:
        report("BLOCKED_REMOTE", f"Publication command exceeded {args.timeout} seconds; continue local integration", branch=args.branch, remote=remote)
        return 4
    if result.returncode:
        detail = scrub(result.stderr or result.stdout)
        report("BLOCKED_REMOTE", "Feature branch could not be published; continue local integration", branch=args.branch, remote=remote, detail=detail)
        return 4
    try:
        after = git(repo, "rev-parse", "HEAD", timeout=min(args.timeout, 30))
        source_changed = after.returncode != 0 or after.stdout.strip() != head
    except (subprocess.TimeoutExpired, OSError):
        source_changed = True
    message = ("Verified feature commit published; source branch changed or could not be rechecked"
               if source_changed else "Feature branch published")
    report("PUSHED", message, branch=args.branch, remote=remote, head=head, source_changed=source_changed)
    return 0


if __name__ == "__main__":
    sys.exit(main())
