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
from git_safety import git_environment, require_safe_source
from github_identity import github_repository, repository_name


def run_git(repo, *args, timeout=600, config_extra=(), text=True, input=None):
    # Headless use: a missing credential must fail the push, not wait on a terminal prompt.
    env = git_environment(settings=config_extra)
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
LFS_COMMIT_LIMIT = 100_000
LFS_REF_LIMIT = 200_000
LFS_REF_BYTE_LIMIT = 64_000_000  # streamed before parsing; refs are counted as they arrive
LFS_DIFF_BYTE_LIMIT = 256_000_000  # raw diff records are streamed; paths are discarded
OID = re.compile(rb'(?:[0-9a-f]{40}|[0-9a-f]{64})')
BLOB_MODES = {b'100644', b'100755', b'120000'}


def stream_records(repo, args, timeout, consume, *, separator, stdin_data=b'', byte_limit,
                   settings=()):
    """Stream one Git command's records to `consume`; never buffer unbounded output.

    Input is staged in an unlinked temporary file, so Git cannot block writing
    output while this process blocks writing input.
    """
    command = ['git', '-C', str(repo), *args]
    env = git_environment(settings=settings)
    deadline = time.monotonic() + timeout
    with tempfile.TemporaryFile() as source:
        source.write(stdin_data)
        source.seek(0)
        process = subprocess.Popen(command, env=env, stdin=source, stdout=subprocess.PIPE,
                                   stderr=subprocess.DEVNULL, start_new_session=True)
    pending, total = b'', 0
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
                if total > byte_limit:
                    raise ValueError('LFS enumeration byte budget exceeded')
                records = (pending + chunk).split(separator)
                pending = records.pop()
                for record in records:
                    consume(record)
                if len(pending) > 65536:
                    raise ValueError('oversized Git record')
        if pending:
            raise ValueError('truncated Git record')
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise subprocess.TimeoutExpired(command, timeout)
        if process.wait(timeout=remaining):
            raise ValueError('Git could not enumerate unpublished history')
    finally:
        # Enumeration is read-only: stop immediately on refusal, including writers
        # blocked on the pipe. Never call communicate(), which would buffer output.
        signal_group(process.pid, signal.SIGKILL)
        process.stdout.close()
        process.wait()


def bounded_ids(limit, message):
    found = []

    def consume(record):
        if not OID.fullmatch(record):
            raise ValueError('malformed object ID')
        if len(found) >= limit:
            raise ValueError(message)
        found.append(record)
    return found, consume


def time_left(deadline):
    left = deadline - time.monotonic()
    if left <= 0:
        raise subprocess.TimeoutExpired('LFS scan', 0)
    return left


def published_tips(transport, git, remote, config, deadline):
    """Return destination branch/tag tips that this object store already has.

    Only the destination's own advertisement is trusted. Local remote-tracking
    refs can be stale or rewritten, and excluding them could hide new pointers.
    """
    tips, count = set(), [0]

    def consume(line):
        count[0] += 1
        if count[0] > LFS_REF_LIMIT:
            raise ValueError('destination ref count exceeds LFS scan budget')
        fields = line.split(b'\t')
        if len(fields) != 2 or not OID.fullmatch(fields[0]) or not fields[1].startswith(b'refs/'):
            raise ValueError('malformed destination ref listing')
        if fields[1].startswith((b'refs/heads/', b'refs/tags/')):
            tips.add(fields[0])
    # Stream the destination advertisement so a huge or hostile listing is
    # refused by count and bytes before it is buffered.
    try:
        stream_records(transport, ['ls-remote', '--refs', '--', remote, 'refs/heads/*', 'refs/tags/*'],
                       time_left(deadline), consume, separator=b'\n',
                       byte_limit=LFS_REF_BYTE_LIMIT, settings=config)
    except ValueError as error:
        if str(error) == 'Git could not enumerate unpublished history':
            raise ValueError('cannot list destination refs') from None
        raise
    if not tips:
        return []
    ordered = sorted(tips)
    # Peel tags to commits; a tip that is absent here or names a tree or blob is
    # skipped, so it can only enlarge the scanned range.
    known = git(transport, 'cat-file', '--batch-check=%(objectname) %(objecttype)',
                input=b''.join(oid + b'^{commit}\n' for oid in ordered), text=False,
                timeout=time_left(deadline))
    rows = known.stdout.splitlines()
    if known.returncode or len(rows) != len(ordered):
        raise ValueError('cannot inspect destination tips locally')
    present = set()
    for oid, row in zip(ordered, rows):
        fields = row.split()
        if fields == [oid + b'^{commit}', b'missing']:
            continue
        if len(fields) != 2 or not OID.fullmatch(fields[0]) or fields[1] != b'commit':
            raise ValueError('malformed destination tip metadata')
        present.add(fields[0])
    return sorted(present)


def unpublished_blobs(transport, head, tips, deadline):
    """Blobs at paths changed by commits the destination does not have.

    The diff of each unpublished commit against every parent includes every new
    blob plus older blobs that the commit re-references, as Git LFS pre-push does.
    """
    def remaining():
        return time_left(deadline)
    revisions = b''.join([head.encode() + b'\n', *(b'^' + tip + b'\n' for tip in tips)])
    commits, consume = bounded_ids(LFS_COMMIT_LIMIT, 'LFS scan commit budget exceeded')
    stream_records(transport, ['rev-list', '--stdin'], remaining(), consume, separator=b'\n',
                   stdin_data=revisions, byte_limit=LFS_ENUMERATION_BYTE_LIMIT)
    blobs, expect_path = set(), [False]

    def collect(record):
        if expect_path[0]:
            expect_path[0] = False
            return
        fields = record.split(b' ')
        if (len(fields) != 5 or not fields[0].startswith(b':') or not OID.fullmatch(fields[3])
                or not fields[4][:1].isalpha()):
            raise ValueError('malformed unpublished diff record')
        expect_path[0] = True
        if fields[1] in BLOB_MODES and fields[3].strip(b'0'):
            blobs.add(fields[3])
            if len(blobs) > LFS_OBJECT_LIMIT:
                raise ValueError('LFS scan object budget exceeded')
    if commits:
        stream_records(transport, ['diff-tree', '--stdin', '-r', '-m', '--root', '--no-commit-id',
                                   '--raw', '-z', '--no-renames', '--no-abbrev'],
                       remaining(), collect, separator=b'\0',
                       stdin_data=b'\n'.join(commits) + b'\n', byte_limit=LFS_DIFF_BYTE_LIMIT)
        if expect_path[0]:
            raise ValueError('truncated unpublished diff record')
    return sorted(blobs), len(commits)


def has_reachable_lfs_pointer(repo, head, git, timeout=600, tips=(), deadline=None):
    """Scan small blobs introduced by unpublished commits, with bounded work."""
    deadline = time.monotonic() + timeout if deadline is None else deadline
    oids, commit_count = unpublished_blobs(repo, head, tips, deadline)
    if not commit_count:
        return False  # The destination already advertises a ref containing head.
    if not oids:
        return False
    oid_set = set(oids)
    checked = git(repo, 'cat-file', '--batch-check=%(objectname) %(objecttype) %(objectsize)',
                  input=b'\n'.join(oids) + b'\n', text=False, timeout=time_left(deadline))
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
    scanned = git(repo, 'cat-file', '--batch', input=b'\n'.join(blobs) + b'\n', text=False,
                  timeout=time_left(deadline))
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
    parser.add_argument("--expected-repository", help="Require the pinned GitHub destination to match OWNER/REPO")
    parser.add_argument("--timeout", type=int, default=600, help="Seconds allowed for each Git command, including the push")
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error("--timeout must be a positive number of seconds")
    return publish(args)


def publish(args):
    # Share one monotonic attempt fact across the body and its exception exits.
    # In particular, transport cleanup can fail after the push already succeeded.
    attempt = {'push_attempted': False}

    def reply(status, message, **facts):
        if getattr(args, 'expected_repository', None) is not None:
            facts.update(attempt)
        report(status, message, **facts)

    try:
        return _publish(args, attempt, reply)
    except subprocess.TimeoutExpired:
        phase = 'Publication command' if attempt['push_attempted'] else 'Local Git inspection'
        outcome = 'publication incomplete' if attempt['push_attempted'] else 'no push attempted'
        reply("BLOCKED_REMOTE", f"{phase} exceeded {args.timeout} seconds; {outcome}")
        return 4
    except OSError:
        reply("BLOCKED_REMOTE", "Publication could not complete because of a local operating-system error")
        return 4


def _publish(args, attempt, reply):
    expected_repository = getattr(args, 'expected_repository', None)
    if expected_repository is not None:
        try:
            expected_repository = repository_name(expected_repository)
        except ValueError:
            reply('BLOCKED_POLICY', 'Expected GitHub repository identity is invalid')
            return 2
    git = partial(run_git, timeout=args.timeout)
    repo = args.repo.resolve()
    if not repo.is_dir():
        reply("BLOCKED_POLICY", "Source must be the root of a Git worktree")
        return 2
    toplevel = git(repo, "rev-parse", "--show-toplevel")
    if (toplevel.returncode or not toplevel.stdout.strip()
            or Path(toplevel.stdout.strip()).resolve() != repo):
        reply("BLOCKED_POLICY", "Source must be the root of a Git worktree")
        return 2
    valid = git(repo, "check-ref-format", "--branch", args.branch)
    if valid.returncode or args.branch in {"main", "master", "develop", args.original_branch}:
        reply("BLOCKED_POLICY", "Refusing to publish a protected or invalid branch")
        return 2
    current = git(repo, "symbolic-ref", "--quiet", "--short", "HEAD")
    if current.returncode or current.stdout.strip() != args.branch:
        reply("BLOCKED_POLICY", "Source worktree is not on the requested branch")
        return 2
    head = git(repo, "rev-parse", "HEAD").stdout.strip()
    if head != args.expected_head:
        reply("BLOCKED_POLICY", "Source HEAD changed since final verification")
        return 2
    try:
        require_safe_source(repo, git_environment(), timeout=min(args.timeout, 5))
    except OSError:
        reply("BLOCKED_POLICY", "Source Git metadata has executable local filters, submodules, or could not be inspected safely")
        return 2
    status = git(repo, "status", "--porcelain", "--untracked-files=all")
    if status.returncode or status.stdout.strip():
        reply("BLOCKED_POLICY", "Commit or discard source changes before publishing")
        return 2
    remote = "origin"
    if remote not in git(repo, "remote").stdout.splitlines():
        reply("BLOCKED_REMOTE", "Configured remote is unavailable", branch=args.branch, remote=remote)
        return 4
    # Fetch and push can target different repositories (including pushInsteadOf rewrites).
    destinations = git(repo, "remote", "get-url", "--push", "--all", remote)
    urls = destinations.stdout.splitlines()
    if destinations.returncode or not urls:
        reply("BLOCKED_REMOTE", "Could not resolve the push destination", branch=args.branch, remote=remote)
        return 4
    if len(urls) != 1:
        reply("BLOCKED_POLICY", "Publication requires exactly one push destination", branch=args.branch, remote=remote)
        return 2
    destination = pinned_url(urls[0], repo)
    if expected_repository is not None:
        try:
            matches = github_repository(destination) == expected_repository
        except ValueError:
            matches = False
        if not matches:
            reply('BLOCKED_POLICY', 'Pinned push destination does not match the expected GitHub repository',
                   branch=args.branch, remote=remote)
            return 2
    # Keep credential-bearing URLs out of process arguments. The temporary
    # remote exists only in this command's environment and is never persisted.
    pinned_remote = "harness-push-" + secrets.token_hex(12)
    pinned_config = ((f"remote.{pinned_remote}.url", destination),
                     (f"remote.{pinned_remote}.pushurl", destination))
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
                reply('BLOCKED_REMOTE', 'Could not determine source object format', branch=args.branch, remote=remote)
                return 4
            initialized = git(temporary, 'init', '--bare', f'--object-format={format_name}', '--template', str(template), str(transport))
            if initialized.returncode:
                reply('BLOCKED_REMOTE', 'Could not prepare isolated publication transport', branch=args.branch, remote=remote)
                return 4
            object_store = git(repo, 'rev-parse', '--path-format=absolute', '--git-path', 'objects')
            object_path = Path(object_store.stdout.rstrip('\n'))
            if object_store.returncode or not object_path.is_dir() or '\n' in str(object_path):
                reply('BLOCKED_REMOTE', 'Could not locate source objects for publication', branch=args.branch, remote=remote)
                return 4
            (transport / 'objects/info/alternates').write_text(str(object_path) + '\n')
            commit_type = git(transport, 'cat-file', '-t', head)
            if commit_type.returncode or commit_type.stdout.strip() != 'commit':
                reply('BLOCKED_REMOTE', 'Could not load verified commit for publication', branch=args.branch, remote=remote)
                return 4
            # Only the isolated transport may contact the destination. Source-local
            # sshCommand and credential helpers must not run during inspection.
            inspected = git(transport, 'ls-remote', '--get-url', '--', pinned_remote,
                            config_extra=pinned_config)
            if inspected.returncode or inspected.stdout.strip() != destination:
                reply('BLOCKED_POLICY', 'Push destination cannot be inspected without another URL rewrite',
                       branch=args.branch, remote=remote)
                return 2
            if expected_repository is not None:
                try:
                    matches = github_repository(inspected.stdout.strip()) == expected_repository
                except ValueError:
                    matches = False
                if not matches:
                    reply('BLOCKED_POLICY', 'Isolated transport does not match the expected GitHub repository',
                           branch=args.branch, remote=remote)
                    return 2
            try:
                default = git(transport, 'ls-remote', '--symref', '--', pinned_remote, 'HEAD',
                              timeout=min(args.timeout, 30), config_extra=pinned_config)
            except subprocess.TimeoutExpired:
                reply('BLOCKED_REMOTE', 'Could not determine the remote default branch in time; continue local integration',
                       branch=args.branch, remote=remote)
                return 4
            if default.returncode:
                reply('BLOCKED_REMOTE', 'Could not determine the remote default branch; continue local integration',
                       branch=args.branch, remote=remote, detail=scrub(default.stderr or default.stdout))
                return 4
            match = re.search(r'^ref: refs/heads/(\S+)\s+HEAD$', default.stdout, re.MULTILINE)
            if match is None:
                reply('BLOCKED_REMOTE', 'Remote default branch is not advertised; continue local integration',
                       branch=args.branch, remote=remote)
                return 4
            if args.branch == match.group(1):
                reply('BLOCKED_POLICY', 'Refusing to publish the remote default branch', branch=args.branch, remote=remote)
                return 2
            # Scan the commits this push can add: everything reachable from head
            # except history the destination itself advertises. Source shallow
            # boundaries and grafts are not inherited by this transport, even when
            # hidden ancestor objects remain available through alternates. The
            # source LFS upload hook is bypassed, so refuse every pointer at a path
            # those commits change. One deadline bounds the whole scan.
            scan_deadline = time.monotonic() + args.timeout
            try:
                tips = published_tips(transport, git, pinned_remote, pinned_config, scan_deadline)
                contains_lfs = has_reachable_lfs_pointer(transport, head, git, tips=tips,
                                                         deadline=scan_deadline)
            except (ValueError, subprocess.TimeoutExpired) as error:
                # Reasons are fixed strings from this module; never echo paths or Git output.
                reason = (f'LFS scan exceeded {args.timeout} seconds'
                          if isinstance(error, subprocess.TimeoutExpired)
                          else str(error) if re.fullmatch(r'[A-Za-z ]{1,80}', str(error))
                          else 'LFS scan refused')
                reply("BLOCKED_REMOTE", "Could not verify whether Git LFS content needs uploading; continue local integration",
                       branch=args.branch, remote=remote, reason=reason)
                return 4
            if contains_lfs:
                reply("BLOCKED_POLICY", "Git LFS pointer found; publish with an LFS-aware workflow",
                       branch=args.branch, remote=remote)
                return 2
            attempt['push_attempted'] = True
            result = git(transport, 'push', '--porcelain', pinned_remote,
                         f"{head}:{ref}", timeout=args.timeout, config_extra=pinned_config)
    except subprocess.TimeoutExpired:
        reply("BLOCKED_REMOTE", f"Publication command exceeded {args.timeout} seconds; continue local integration", branch=args.branch, remote=remote)
        return 4
    if result.returncode:
        detail = scrub(result.stderr or result.stdout)
        rejected = any(len(fields := line.split('\t')) == 3 and fields[0] == '!'
                       and fields[1] == f"{head}:{ref}"
                       and fields[2].startswith(('[rejected]', '[remote rejected]'))
                       for line in result.stdout.splitlines())
        facts = {'push_rejected': rejected} if expected_repository is not None else {}
        reply("BLOCKED_REMOTE", "Feature branch could not be published; continue local integration",
              branch=args.branch, remote=remote, detail=detail, **facts)
        return 4
    try:
        after = git(repo, "rev-parse", "HEAD", timeout=min(args.timeout, 30))
        source_changed = after.returncode != 0 or after.stdout.strip() != head
    except (subprocess.TimeoutExpired, OSError):
        source_changed = True
    message = ("Verified feature commit published; source branch changed or could not be rechecked"
               if source_changed else "Feature branch published")
    identity = {} if expected_repository is None else {'repository': expected_repository}
    reply("PUSHED", message, branch=args.branch, remote=remote, head=head,
           source_changed=source_changed, **identity)
    return 0


if __name__ == "__main__":
    sys.exit(main())
