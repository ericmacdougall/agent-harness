#!/usr/bin/env python3
"""Merge a reviewed feature commit into the original clean checkout, with checks."""

import argparse
import hashlib
import json
import os
import secrets
import selectors
import shlex
import stat
import subprocess
import sys
import time
from pathlib import Path

from git_safety import _bounded_git, git_environment, require_safe_source
from process import cleanup_discarded, run as run_process


# Git environment variables can redirect commands away from the named worktree
# or its normal index. Identity and test-isolation settings do not do that.
# GIT_PAGER is stripped from helper-owned Git processes by git_environment().
ALLOWED_GIT_ENV = {
    'GIT_AUTHOR_NAME', 'GIT_AUTHOR_EMAIL', 'GIT_AUTHOR_DATE',
    'GIT_COMMITTER_NAME', 'GIT_COMMITTER_EMAIL', 'GIT_COMMITTER_DATE',
    'GIT_CONFIG_GLOBAL', 'GIT_CONFIG_NOSYSTEM', 'GIT_TERMINAL_PROMPT',
    'GIT_PAGER',
}
INSPECTION_CONFIG = ('-c', 'core.fsmonitor=false', '-c', 'core.untrackedCache=false',
                     '-c', 'core.trustctime=true', '-c', 'core.checkStat=default',
                     '-c', 'core.filemode=true', '-c', 'core.symlinks=true')
INDEX_MAX_BYTES = 40_000_000
INDEX_MAX_ENTRIES = 250_000
INDEX_MAX_RECORD_BYTES = 1_000_000
INDEX_MAX_SECONDS = 30
INDEX_HEADER_BYTES = 9  # tag, space, six-digit mode, space
NONEMPTY_UNITTEST = (
    'import sys, threading, unittest\n'
    'class NonemptyResult(unittest.TextTestResult):\n'
    '    def __init__(self, *args, **kwargs):\n'
    '        super().__init__(*args, **kwargs)\n'
    '        self.non_skipped = 0\n'
    '        self._lock = threading.RLock()\n'
    '        self._active_invocations = {}\n'
    '        self._callback_mismatch = False\n'
    '    def startTest(self, test):\n'
    '        with self._lock:\n'
    '            super().startTest(test)\n'
    '            self._active_invocations.setdefault(threading.current_thread(), []).append([test, False])\n'
    '            self.non_skipped += 1\n'
    '    def addSkip(self, test, reason):\n'
    '        with self._lock:\n'
    '            frames = self._active_invocations.get(threading.current_thread(), ())\n'
    '            if frames and frames[-1][0] is test:\n'
    '                if not frames[-1][1]:\n'
    '                    frames[-1][1] = True\n'
    '                    self.non_skipped -= 1\n'
    '            elif any(frame[0] is test for stack in self._active_invocations.values() for frame in stack):\n'
    '                self._callback_mismatch = True\n'
    '            super().addSkip(test, reason)\n'
    '    def stopTest(self, test):\n'
    '        with self._lock:\n'
    '            frames = self._active_invocations.get(threading.current_thread())\n'
    '            if not frames or frames[-1][0] is not test:\n'
    '                self._callback_mismatch = True\n'
    '            else:\n'
    '                frames.pop()\n'
    '                if not frames:\n'
    '                    del self._active_invocations[threading.current_thread()]\n'
    '            super().stopTest(test)\n'
    '    def merge_check_passed(self):\n'
    '        with self._lock:\n'
    '            return (self.non_skipped > 0 and not self._active_invocations\n'
    '                    and not self._callback_mismatch and self.wasSuccessful())\n'
    'class NonemptyRunner(unittest.TextTestRunner):\n'
    '    resultclass = NonemptyResult\n'
    "program = unittest.main(module=None, argv=['unittest', *sys.argv[1:]], "
    'testRunner=NonemptyRunner, exit=False)\n'
    'sys.exit(0 if program.result.merge_check_passed() else 1)\n'
)


class IndexInspectionError(Exception):
    def __init__(self, *, cleanup_incomplete=False):
        super().__init__('Index could not be verified')
        self.cleanup_incomplete = cleanup_incomplete


def index_unflagged(repo, timeout):
    """Check NUL records without retaining paths or trusting Git's fsmonitor cache."""
    command = ['git', *INSPECTION_CONFIG, 'ls-files', '-v', '-s', '-z']
    deadline = time.monotonic() + min(timeout, INDEX_MAX_SECONDS)
    try:
        process = subprocess.Popen(command, cwd=repo,
                                   env={**git_environment(), 'PYTHONDONTWRITEBYTECODE': '1'},
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


def run(repo, command, *, timeout=None, discard_output=False, env=None):
    # Python test runners otherwise leave untracked __pycache__ after an aborted merge.
    output_options = {'discard_output': True} if discard_output else {}
    executed = command
    if (discard_output and len(command) >= 4 and command[0] in {'python', 'python3'}
            and command[1:4] == ['-m', 'unittest', 'discover']):
        # Python before 3.12 exits zero when discovery finds no tests. Invoke
        # the same CLI parser once, then require its result to be nonempty.
        executed = [command[0], '-c', NONEMPTY_UNITTEST, *command[3:]]
    return run_process(executed, cwd=repo, timeout=timeout,
                       env={**(os.environ if env is None else env), "PYTHONDONTWRITEBYTECODE": "1"},
                       **output_options)


def run_git(repo, *args, timeout=600):
    return run(repo, ["git", *args], timeout=timeout,
               env=git_environment(allow_hooks=True, preserve_identity=True))


def run_git_discard(repo, *args, timeout=600):
    # Merge drivers and hooks are repository code. Never retain their output.
    return run(repo, ["git", *args], timeout=timeout, discard_output=True,
               env=git_environment(allow_hooks=True, preserve_identity=True))


def safe_source(repo, timeout, *, allow_unmerged=False):
    try:
        require_safe_source(repo, git_environment(), timeout=min(timeout, INDEX_MAX_SECONDS),
                            allow_unmerged=allow_unmerged)
    except OSError:
        raise IndexInspectionError() from None


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
    return integrate_scratch(args, preparations, checks)


def scratch_journal_root():
    parent = Path.home() / '.agent-harness'
    root = parent / 'delivery-scratch'
    for path in (parent, root):
        if path.is_symlink():
            raise OSError('private scratch path is a symlink')
        path.mkdir(mode=0o700, exist_ok=True)
        if not path.is_dir() or stat.S_IMODE(path.stat().st_mode) != 0o700:
            raise OSError('private scratch path is not owner-only')
    return root


def journal_key(repo, branch, base, source_branch, source):
    payload = '\0'.join((str(repo), branch, base, source_branch, source)).encode()
    return hashlib.sha256(payload).hexdigest()


def write_journal(directory, record, *, first=False):
    """Write only bounded metadata; fsync before any original-checkout apply."""
    path = directory / 'journal.json'
    data = (json.dumps(record, sort_keys=True, separators=(',', ':')) + '\n').encode()
    if len(data) > 8192:
        raise OSError('scratch journal exceeded size limit')
    temporary = directory / ('.journal-' + secrets.token_hex(8))
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with os.fdopen(fd, 'wb') as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        if first:
            os.link(temporary, path, follow_symlinks=False)
        else:
            if path.is_symlink() or not path.is_file():
                raise OSError('scratch journal changed')
            os.replace(temporary, path)
        directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def reserve_scratch(repo, branch, base, source_branch, source):
    root = scratch_journal_root()
    key = journal_key(repo, branch, base, source_branch, source)
    directory = root / key
    try:
        directory.mkdir(mode=0o700)
    except FileExistsError:
        return directory, None
    scratch = directory / 'worktree'
    record = {'schema': 1, 'phase': 'started', 'original': str(repo), 'branch': branch,
              'base': base, 'source_branch': source_branch, 'source': source,
              'scratch': str(scratch), 'key': key}
    write_journal(directory, record, first=True)
    return directory, record


def observed_head(repo):
    try:
        result = inspect_git(repo, 'rev-parse', 'HEAD', timeout=30)
        return result.stdout.strip() if result.returncode == 0 else None
    except (OSError, subprocess.TimeoutExpired):
        return None


def scratch_failure(repo, scratch, journal, message, *, phase, merge_aborted=None,
                    candidate=None, recovery_ref=None, original_head=None,
                    status='BLOCKED_LOCAL', exit_code=None, command=None):
    details = {'phase': phase, 'scratch': str(scratch), 'journal': str(journal),
               'recovery_required': True}
    if merge_aborted is not None:
        details['merge_aborted'] = merge_aborted
    if candidate:
        details['candidate'] = candidate
    if recovery_ref:
        details['recovery_ref'] = recovery_ref
    if original_head:
        details['head'] = original_head
    if exit_code is not None:
        details['exit_code'] = exit_code
    if command is not None:
        details[phase] = command
    report(status, message, **details)
    return 3


def scratch_abort(repo, scratch, journal, message, *, phase, exit_code=None,
                  command=None, timeout=30):
    # A check can install a local filter/driver. Refuse to let Git's abort
    # execute it in the scratch checkout when the source guard cannot prove it safe.
    try:
        safe_source(scratch, timeout, allow_unmerged=True)
    except IndexInspectionError:
        return scratch_failure(repo, scratch, journal,
                               message + '; scratch Git state is unsafe for automatic abort',
                               phase=phase, merge_aborted=False, exit_code=exit_code,
                               command=command, original_head=observed_head(repo))
    try:
        result = run_git_discard(scratch, 'merge', '--abort', timeout=timeout)
        aborted = result.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        aborted = False
    if not aborted:
        message += '; scratch abort failed, inspect retained worktree'
    return scratch_failure(repo, scratch, journal, message, phase=phase,
                           merge_aborted=aborted, exit_code=exit_code, command=command,
                           original_head=observed_head(repo))


def checked_original(repo, branch, base, timeout):
    safe_source(repo, timeout)
    index_unflagged(repo, timeout)
    current_branch = inspect_git(repo, 'symbolic-ref', '--quiet', '--short', 'HEAD', timeout=timeout)
    current_head = inspect_git(repo, 'rev-parse', 'HEAD', timeout=timeout)
    status = inspect_git(repo, 'status', '--porcelain', '--untracked-files=all',
                         '--ignore-submodules=none', timeout=timeout)
    return (current_branch.returncode == 0 and current_branch.stdout.strip() == branch
            and current_head.returncode == 0 and current_head.stdout.strip() == base
            and status.returncode == 0 and not status.stdout.strip())


def scratch_has_extra_files(scratch, timeout):
    for flags in (['ls-files', '--others', '--exclude-standard', '-z'],
                  ['ls-files', '--others', '--ignored', '--exclude-standard', '-z']):
        code, data = _bounded_git(scratch, flags, git_environment(),
                                  timeout=min(timeout, INDEX_MAX_SECONDS), limit=INDEX_MAX_BYTES)
        if code or data:
            return True
    return False


def scratch_is_clean_for_cleanup(scratch, candidate, timeout):
    """Do not let status config or hidden index flags hide scratch data."""
    safe_source(scratch, timeout)
    index_unflagged(scratch, timeout)
    head = inspect_git(scratch, 'rev-parse', 'HEAD', timeout=timeout)
    status = inspect_git(scratch, 'status', '--porcelain', '--untracked-files=all',
                         '--ignore-submodules=none', timeout=timeout)
    return (head.returncode == 0 and head.stdout.strip() == candidate
            and status.returncode == 0 and not status.stdout.strip()
            and not scratch_has_extra_files(scratch, timeout))


def scratch_identity(scratch, expected):
    observed = os.stat(scratch, follow_symlinks=False)
    return (stat.S_ISDIR(observed.st_mode)
            and (observed.st_dev, observed.st_ino) == (expected.st_dev, expected.st_ino))


def integrate_scratch(args, preparations, checks):
    if any(name.startswith('GIT_') and name not in ALLOWED_GIT_ENV for name in os.environ):
        report('BLOCKED_POLICY', 'Inherited Git routing or configuration override is unsupported')
        return 2
    repo = args.repo.resolve()
    directory = None
    phase = 'preflight'
    applied_candidate = None
    try:
        toplevel = inspect_git(repo, 'rev-parse', '--show-toplevel', timeout=args.timeout) if repo.is_dir() else None
        if toplevel is None or toplevel.returncode or Path(toplevel.stdout.strip()).resolve() != repo:
            report('BLOCKED_POLICY', 'Original checkout must be the root of a Git worktree')
            return 2
        if args.source.startswith('-') or inspect_git(repo, 'check-ref-format', '--branch', args.source,
                                                       timeout=args.timeout).returncode:
            report('BLOCKED_POLICY', 'Source must be a valid local feature branch')
            return 2
        # An unresolved attempt takes precedence even if its candidate already
        # advanced original HEAD or its source branch moved. Never silently
        # create a second merge/check.
        key = journal_key(repo, args.original_branch, args.expected_head,
                          args.source, args.expected_source_head)
        existing = scratch_journal_root() / key
        if os.path.lexists(existing):
            report('RECOVERY_REQUIRED', 'Existing scratch journal requires inspection before retry',
                   journal=str(existing / 'journal.json'), scratch=str(existing / 'worktree'),
                   head=observed_head(repo))
            return 3
        source = inspect_git(repo, 'rev-parse', '--verify', f'refs/heads/{args.source}^{{commit}}',
                             timeout=args.timeout)
        if (source.returncode or source.stdout.strip() != args.expected_source_head
                or source.stdout.strip() == args.expected_head or args.source == args.original_branch):
            report('BLOCKED_POLICY', 'Source commit or branch is invalid')
            return 2
        if not checked_original(repo, args.original_branch, args.expected_head, args.timeout):
            report('BLOCKED_LOCAL', 'Original checkout branch, HEAD, or cleanliness changed; no merge attempted')
            return 3
        already = inspect_git(repo, 'merge-base', '--is-ancestor', args.expected_source_head,
                              args.expected_head, timeout=args.timeout)
        if already.returncode == 0:
            report('ALREADY_INTEGRATED', 'Source is already in original checkout',
                   head=args.expected_head)
            return 0
        if already.returncode != 1:
            report('BLOCKED_LOCAL', 'Source ancestry could not be verified; no merge attempted')
            return 3
        directory, record = reserve_scratch(repo, args.original_branch, args.expected_head,
                                            args.source, args.expected_source_head)
        scratch = directory / 'worktree'
        if record is None:
            report('RECOVERY_REQUIRED', 'Existing scratch journal requires inspection before retry',
                   journal=str(directory / 'journal.json'), scratch=str(scratch), head=args.expected_head)
            return 3
        phase = 'scratch'
        # The journal exists before Git can run a merge driver, hook or test.
        added = run_process(['git', '-C', str(repo), 'worktree', 'add', '--detach', str(scratch),
                             args.expected_head], env=git_environment(), timeout=args.timeout,
                            discard_output=True)
        if added.returncode:
            return scratch_failure(repo, scratch, directory / 'journal.json',
                                   'Scratch worktree could not be created; inspect reservation',
                                   phase='scratch', original_head=args.expected_head)
        scratch_info = os.stat(scratch, follow_symlinks=False)
        record.update({'phase': 'scratch', 'scratch_dev': scratch_info.st_dev,
                       'scratch_ino': scratch_info.st_ino})
        write_journal(directory, record)
        phase = 'merge'
        merged = run_git_discard(scratch, 'merge', '--no-ff', '--no-commit',
                                 args.expected_source_head, timeout=args.timeout)
        if merged.returncode:
            return scratch_abort(repo, scratch, directory / 'journal.json', 'Scratch merge failed',
                                 phase='merge', exit_code=merged.returncode)
        intended = run_git(scratch, 'write-tree', timeout=args.timeout)
        if intended.returncode or not intended.stdout.strip():
            return scratch_abort(repo, scratch, directory / 'journal.json',
                                 'Scratch merge tree could not be recorded', phase='merge')
        intended_tree = intended.stdout.strip()
        for kind, commands in (('prepare', preparations), ('check', checks)):
            for command in commands:
                phase = kind
                try:
                    result = run(scratch, command, timeout=args.timeout, discard_output=True)
                except (OSError, subprocess.TimeoutExpired) as error:
                    if getattr(error, 'cleanup_incomplete', False):
                        return scratch_failure(repo, scratch, directory / 'journal.json',
                                               f'Scratch {kind} cleanup incomplete', phase=kind,
                                               merge_aborted=False, original_head=observed_head(repo),
                                               command=command)
                    reason = (f'Scratch {kind} exceeded {args.timeout} seconds'
                              if isinstance(error, subprocess.TimeoutExpired)
                              else f'Scratch {kind} could not start')
                    return scratch_abort(repo, scratch, directory / 'journal.json',
                                         reason, phase=kind, command=command, timeout=args.timeout)
                if result.returncode:
                    return scratch_abort(repo, scratch, directory / 'journal.json',
                                         f'Scratch {kind} failed', phase=kind,
                                         exit_code=result.returncode, command=command,
                                         timeout=args.timeout)
        try:
            safe_source(scratch, args.timeout)
            index_unflagged(scratch, args.timeout)
        except IndexInspectionError:
            return scratch_failure(repo, scratch, directory / 'journal.json',
                                   'Scratch index could not be verified safely', phase='check',
                                   merge_aborted=False, original_head=observed_head(repo))
        checked_tree = run_git(scratch, 'write-tree', timeout=args.timeout)
        unstaged = inspect_git(scratch, 'diff', '--quiet', '--exit-code', '--ignore-submodules=none',
                               timeout=args.timeout)
        untracked = inspect_git(scratch, 'ls-files', '--others', '--exclude-standard', timeout=args.timeout)
        if (checked_tree.returncode or checked_tree.stdout.strip() != intended_tree
                or unstaged.returncode or untracked.returncode or untracked.stdout.strip()):
            return scratch_abort(repo, scratch, directory / 'journal.json',
                                 'Scratch checks changed intended merge tree', phase='check',
                                 timeout=args.timeout)
        phase = 'commit'
        committed = run_git_discard(scratch, 'commit', '-m',
                                    f'Merge {args.source} into {args.original_branch}',
                                    timeout=args.timeout)
        if committed.returncode:
            return scratch_abort(repo, scratch, directory / 'journal.json',
                                 'Scratch merge commit failed', phase='commit',
                                 exit_code=committed.returncode, timeout=args.timeout)
        candidate = inspect_git(scratch, 'rev-parse', 'HEAD', timeout=args.timeout).stdout.strip()
        parents = inspect_git(scratch, 'rev-list', '--parents', '-n', '1', 'HEAD', timeout=args.timeout)
        tree = inspect_git(scratch, 'rev-parse', 'HEAD^{tree}', timeout=args.timeout)
        if (parents.returncode or parents.stdout.split() != [candidate, args.expected_head, args.expected_source_head]
                or tree.returncode or tree.stdout.strip() != intended_tree):
            return scratch_failure(repo, scratch, directory / 'journal.json',
                                   'Scratch candidate differs from verified merge tree or parents',
                                   phase='candidate', merge_aborted=False, candidate=candidate,
                                   original_head=observed_head(repo))
        ref = f'refs/agent-harness/delivery/{record["key"]}'
        zeros = '0' * len(candidate)
        pinned = run_git(repo, 'update-ref', ref, candidate, zeros, timeout=args.timeout)
        if pinned.returncode:
            return scratch_failure(repo, scratch, directory / 'journal.json',
                                   'Candidate ref could not be pinned', phase='candidate',
                                   candidate=candidate, original_head=args.expected_head)
        record.update({'phase': 'candidate', 'candidate': candidate, 'tree': intended_tree, 'ref': ref})
        write_journal(directory, record)
        phase = 'apply'
        if (not checked_original(repo, args.original_branch, args.expected_head, args.timeout)
                or inspect_git(repo, 'rev-parse', '--verify', f'refs/heads/{args.source}',
                               timeout=args.timeout).stdout.strip() != args.expected_source_head
                or inspect_git(repo, 'rev-parse', ref, timeout=args.timeout).stdout.strip() != candidate
                or not scratch_identity(scratch, scratch_info)):
            return scratch_failure(repo, scratch, directory / 'journal.json',
                                   'Original or candidate changed before apply', phase='apply',
                                   candidate=candidate, recovery_ref=ref,
                                   original_head=inspect_git(repo, 'rev-parse', 'HEAD', timeout=30).stdout.strip())
        advanced = run_git_discard(repo, 'merge', '--ff-only', '--no-overwrite-ignore',
                                   '--no-autostash', candidate, timeout=args.timeout)
        observed = inspect_git(repo, 'rev-parse', 'HEAD', timeout=30).stdout.strip()
        if advanced.returncode or observed != candidate:
            return scratch_failure(repo, scratch, directory / 'journal.json',
                                   'Protected fast-forward refused or changed state; inspect checkout',
                                   phase='apply', candidate=candidate, recovery_ref=ref,
                                   original_head=observed)
        applied_candidate = candidate
        phase = 'verify'
        if not checked_original(repo, args.original_branch, candidate, args.timeout):
            return scratch_failure(repo, scratch, directory / 'journal.json',
                                   'Original checkout advanced but is dirty or unverifiable',
                                   phase='verify', candidate=candidate, recovery_ref=ref,
                                   original_head=observed, status='DELIVERED_CHECK_FAILED')
        for kind, commands in (('prepare', preparations), ('check', checks)):
            for command in commands:
                phase = kind
                try:
                    result = run(repo, command, timeout=args.timeout, discard_output=True)
                except (OSError, subprocess.TimeoutExpired):
                    return scratch_failure(repo, scratch, directory / 'journal.json',
                                           'Delivered checkout check could not complete; HEAD advanced',
                                           phase=kind, candidate=candidate, recovery_ref=ref,
                                           original_head=observed_head(repo),
                                           status='DELIVERED_CHECK_FAILED', command=command)
                if result.returncode:
                    return scratch_failure(repo, scratch, directory / 'journal.json',
                                           'Delivered checkout check failed; HEAD advanced',
                                           phase=kind, candidate=candidate, recovery_ref=ref,
                                           original_head=observed_head(repo),
                                           status='DELIVERED_CHECK_FAILED', exit_code=result.returncode,
                                           command=command)
        if not checked_original(repo, args.original_branch, candidate, args.timeout):
            return scratch_failure(repo, scratch, directory / 'journal.json',
                                   'Delivered checkout changed during checks; HEAD advanced',
                                   phase='verify', candidate=candidate, recovery_ref=ref,
                                   original_head=observed_head(repo),
                                   status='DELIVERED_CHECK_FAILED')
        phase = 'finalize'
        record['phase'] = 'delivered'
        write_journal(directory, record)
        cleanup_pending = True
        try:
            if (scratch_identity(scratch, scratch_info)
                    and scratch_is_clean_for_cleanup(scratch, candidate, args.timeout)):
                removed = run_process(['git', '-C', str(repo), 'worktree', 'remove', str(scratch)],
                                      env=git_environment(), timeout=args.timeout, discard_output=True)
                if removed.returncode == 0:
                    deleted = run_git(repo, 'update-ref', '-d', ref, candidate, timeout=args.timeout)
                    cleanup_pending = deleted.returncode != 0
        except (IndexInspectionError, OSError, subprocess.TimeoutExpired):
            pass  # Keep the candidate and scratch for later inspection.
        report('INTEGRATED', 'Verified feature merged into original checkout',
               original_branch=args.original_branch, source=args.source, head=candidate,
               preparations=args.prepare, checks=args.check, cleanup_pending=cleanup_pending,
               journal=str(directory / 'journal.json'))
        return 0
    except (IndexInspectionError, OSError, subprocess.TimeoutExpired) as error:
        message = ('Git inspection could not complete' if isinstance(error, IndexInspectionError)
                   else 'Delivery operation could not complete')
        if getattr(error, 'cleanup_incomplete', False):
            message += '; child process cleanup is incomplete'
        if directory is None:
            report('BLOCKED_LOCAL', message + '; no merge attempted', head=observed_head(repo))
            return 3
        # The journal reserved before scratch work prevents an automatic
        # second merge after an uncertain timeout or interrupted hook.
        return scratch_failure(repo, directory / 'worktree', directory / 'journal.json',
                               message, phase=phase, merge_aborted=False,
                               original_head=observed_head(repo),
                               status=('DELIVERED_CHECK_FAILED' if applied_candidate and phase == 'verify'
                                       else 'RECOVERY_REQUIRED' if applied_candidate else 'BLOCKED_LOCAL'),
                               candidate=applied_candidate)


if __name__ == "__main__":
    sys.exit(main())
