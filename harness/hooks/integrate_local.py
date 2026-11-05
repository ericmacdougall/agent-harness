#!/usr/bin/env python3
"""Merge a reviewed feature commit into the original clean checkout, with checks."""

import argparse
import fcntl
import hashlib
import json
import math
import os
import secrets
import selectors
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
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
JOURNAL_MAX_ENTRIES = 4096
JOURNAL_SCAN_SECONDS = 30
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


MIN_CHECK_PYTHON = (3, 10)
CHECK_PYTHON_NAMES = {'python', 'python3'}
CHECK_LOG_LIMIT = 32 * 1024 * 1024
CHECK_TAIL_BYTES = 16384  # redacted as whole lines before the reported tail is cut
CHECK_LOGS_KEPT = 5
CHECK_TAIL_CHARS = 2000


class CheckInterpreterError(OSError):
    """A Python check would run an absent or unsupported interpreter."""


def resolve_check_interpreter(name, env=None, timeout=30):
    """Pin a check's `python`/`python3` to one absolute, supported executable.

    Bare names resolve through PATH at run time, so a system Python 3.9 could
    silently run a 3.10+ suite. Refuse that with a reason that names the fix.
    """
    search = (os.environ if env is None else env).get('PATH', os.defpath)
    found = shutil.which(name, path=search)
    if found is None:
        raise CheckInterpreterError(f'{name} is not on PATH; Python checks need Python 3.10 or newer')
    found = os.path.abspath(found)
    try:
        probe = run_process([found, '-I', '-c', 'import sys; print("%d.%d" % sys.version_info[:2])'],
                            timeout=timeout)
    except (OSError, subprocess.TimeoutExpired):
        raise CheckInterpreterError(f'{name} at {found} could not report its version') from None
    match = re.fullmatch(r'(\d+)\.(\d+)\s*', probe.stdout or '')
    if probe.returncode or match is None:
        raise CheckInterpreterError(f'{name} at {found} could not report its version')
    version = (int(match.group(1)), int(match.group(2)))
    if version < MIN_CHECK_PYTHON:
        raise CheckInterpreterError(
            f'{name} on PATH is Python {version[0]}.{version[1]} ({found}); Python checks need 3.10 or newer. '
            'Put a supported python3 first on PATH')
    return found


# The lookbehind anchors each key at a word start, keeping matching linear per line.
SECRET_WORD = (r"[A-Za-z0-9_.-]*"
               r"(?:token|passw(?:or)?d|pwd|secret|api[_-]?key|access[_-]?key|private[_-]?key|credential|session)"
               r"[A-Za-z0-9_.-]*")
SECRET_KEY = r"(?<![A-Za-z0-9_.-])" + SECRET_WORD
CHECK_TAIL_LINE_CHARS = 4000


def redact_output(text):
    """Best-effort redaction of the reported tail; the private log stays complete."""
    text = re.sub(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|\Z)",
                  "[redacted private key]", text, flags=re.S)
    text = re.sub(r"([A-Za-z][A-Za-z0-9+.-]*://)[^/@\s]+@", r"\1[redacted]@", text)
    text = re.sub(r"(?im)\b(authorization|proxy-authorization|cookie|set-cookie)(\s*[=:]\s*)[^\n]*", r"\1\2[redacted]", text)
    text = re.sub(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]+", "Bearer [redacted]", text)
    # Env, CLI, YAML and JSON forms: FOO_TOKEN=v, --password v, "secret": "v".
    text = re.sub(r"(?i)([\"']?" + SECRET_KEY + r"[\"']?)(\s*[=:]\s*)([\"'])[^\"'\n]*\3",
                  r"\1\2\3[redacted]\3", text)
    text = re.sub(r"(?i)([\"']?" + SECRET_KEY + r"[\"']?)(\s*[=:]\s*)(?![\"']\[redacted\])[^\s\"',}]+",
                  r"\1\2[redacted]", text)
    text = re.sub(r"(?i)(--" + SECRET_WORD + r")(\s+)[^\s\"',}]+", r"\1\2[redacted]", text)
    text = re.sub(r"\b(gh[pousr]_[A-Za-z0-9]+|github_pat_[A-Za-z0-9_]+|sk-[A-Za-z0-9_-]{16,}|xox[abprs]-[A-Za-z0-9-]+"
                  r"|(?:AKIA|ASIA)[A-Z0-9]{16}|AIza[0-9A-Za-z_-]{35})\b", "[redacted]", text)
    return text


class CheckLog:
    """Owner-only, size-bounded log of check output plus a redacted in-memory tail.

    Write failures only mark the log truncated: logging must never change a
    check's outcome or block the child on its output pipe.
    """
    def __init__(self, directory):
        private_directory(directory)
        # Keep the newest few attempts only; each log may approach the size cap.
        old = sorted(entry for entry in directory.iterdir()
                     if entry.name.endswith('.log') and not entry.is_symlink() and entry.is_file())
        for entry in old[:max(0, len(old) - (CHECK_LOGS_KEPT - 1))]:
            try:
                entry.unlink()
            except OSError:
                pass
        name = time.strftime('%Y%m%dT%H%M%SZ', time.gmtime()) + '-' + secrets.token_hex(4) + '.log'
        self.path = directory / name
        self.fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        self.written, self.truncated, self.tail = 0, False, bytearray()

    def _write(self, data):
        if self.fd is None:
            self.truncated = True
            return
        room = CHECK_LOG_LIMIT - self.written
        if len(data) > room:
            self.truncated = True
            data = data[:max(room, 0)]
        try:
            view = memoryview(data)
            while view:
                count = os.write(self.fd, view)
                self.written += count
                view = view[count:]
        except OSError:
            self.truncated = True
            self.close()

    def __call__(self, chunk):
        self.tail.extend(chunk)
        del self.tail[:-CHECK_TAIL_BYTES]
        self._write(chunk)

    def header(self, command):
        self._write(('$ ' + shlex.join(command) + '\n').encode('utf-8', 'replace'))

    def close(self):
        if self.fd is not None:
            fd, self.fd = self.fd, None
            os.close(fd)

    def facts(self):
        text = self.tail.decode('utf-8', 'replace')
        if len(self.tail) >= CHECK_TAIL_BYTES:
            # The window may start mid-line, after a secret's key name: drop it.
            text = text.partition('\n')[2]
            if not text:
                return {'check_log': str(self.path), 'check_tail': '[output tail omitted: one line exceeds the tail window]',
                        'check_log_truncated': self.truncated}
        # Very long lines are omitted: they bound redaction cost and rarely help diagnosis.
        text = '\n'.join(line if len(line) <= CHECK_TAIL_LINE_CHARS else '[long line omitted]'
                         for line in text.split('\n'))
        # Redact before trimming, so the cut cannot expose a value whose key it drops.
        tail = redact_output(text)[-CHECK_TAIL_CHARS:]
        return {'check_log': str(self.path), 'check_tail': tail, 'check_log_truncated': self.truncated}


def run(repo, command, *, timeout=None, discard_output=False, env=None, sink=None):
    # Python test runners otherwise leave untracked __pycache__ after an aborted merge.
    output_options = {'discard_output': True} if discard_output else {}
    if sink is not None:
        output_options['sink'] = sink
    environment = {**(os.environ if env is None else env), "PYTHONDONTWRITEBYTECODE": "1"}
    executed = command
    if command and command[0] in CHECK_PYTHON_NAMES:
        executed = [resolve_check_interpreter(command[0], environment), *command[1:]]
    if (discard_output and len(command) >= 4 and command[0] in CHECK_PYTHON_NAMES
            and command[1:4] == ['-m', 'unittest', 'discover']):
        # Python before 3.12 exits zero when discovery finds no tests. Invoke
        # the same CLI parser once, then require its result to be nonempty.
        executed = [executed[0], '-c', NONEMPTY_UNITTEST, *command[3:]]
    return run_process(executed, cwd=repo, timeout=timeout, env=environment, **output_options)


def check_timeout(args):
    """Checks may need far longer than Git commands; older callers share --timeout."""
    value = getattr(args, 'check_timeout', None)
    return args.timeout if value is None else value


def require_check_interpreters(commands):
    """Fail before any effect when a Python check would use an unsupported interpreter."""
    for command in commands:
        if command and command[0] in CHECK_PYTHON_NAMES:
            resolve_check_interpreter(command[0])


def run_git(repo, *args, timeout=600):
    return run(repo, ["git", *args], timeout=timeout,
               env=git_environment(allow_hooks=True, preserve_identity=True))


def run_git_discard(repo, *args, timeout=600):
    # Merge drivers and hooks are repository code. Never retain their output.
    return run(repo, ["git", *args], timeout=timeout, discard_output=True,
               env=git_environment(allow_hooks=True, preserve_identity=True))


def run_git_nohooks(repo, *args, timeout=600):
    # Harness bookkeeping must not run a repository reference-transaction
    # hook after the final delivered-check gate.
    return run(repo, ["git", *args], timeout=timeout, env=git_environment())


def run_git_discard_nohooks(repo, *args, timeout=600):
    # Scratch has already run merge/commit hooks. The original fast-forward
    # must not run post-merge hooks that can alter ignored user data.
    return run(repo, ["git", *args], timeout=timeout, discard_output=True,
               env=git_environment())


def safe_source(repo, timeout, *, allow_unmerged=False, deadline=None):
    try:
        require_safe_source(repo, git_environment(), timeout=min(timeout, INDEX_MAX_SECONDS),
                            allow_unmerged=allow_unmerged, deadline=deadline)
    except OSError:
        raise IndexInspectionError() from None


def report(status, message, **extra):
    print(json.dumps({"status": status, "message": message, **extra}))


FOCUSED_MODULE_RE = re.compile(r"tests\.test_[A-Za-z0-9_]+")  # used with fullmatch


def focused_unittest(argv):
    """The modules of `python3 -m unittest [-v] tests.test_x ...` (test modules only, no other argument), else None.
    This shape is only a syntax check: deliver.py accepts it after test_scope.py proves the scope and a full run."""
    if len(argv) >= 4 and argv[0] in {"python", "python3"} and argv[1:3] == ["-m", "unittest"]:
        modules = [item for item in argv[3:] if item != "-v"]
        if modules and len(modules) <= 60 and len(set(modules)) == len(modules) \
                and all(FOCUSED_MODULE_RE.fullmatch(item) for item in modules):
            return modules
    return None


def approved_check(argv, allow_focused=False):
    if not argv:
        return False
    if allow_focused and focused_unittest(argv) is not None:
        return True
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
    parser.add_argument("--source")
    parser.add_argument("--expected-source-head")
    parser.add_argument("--resolve-journal", help="Accept the tested current checkout as the recovery baseline; preserve artifacts")
    parser.add_argument("--baseline-compare", action="store_true",
                        help="With --resolve-journal: pass the whole-suite check when its failing ids are an exact subset of "
                             "the baseline recorded for the confirmed HEAD (test_scope.py run-baseline)")
    parser.add_argument("--pinned-head", help="With --baseline-compare: the generation's pinned original HEAD; when it differs "
                        "from --expected-head the result must also stay within that HEAD's baseline")
    parser.add_argument("--prepare", action="append", default=[], help="Lockfile install after merge, before checks")
    parser.add_argument("--check", action="append", required=True, help="One argv command, quoted as a single argument; no shell")
    parser.add_argument("--timeout", type=int, default=600, help="Seconds allowed for each Git command and abort")
    parser.add_argument("--allow-focused-checks", action="store_true",
                        help="deliver.py only: accept focused unittest checks it has already proven with test_scope.py")
    parser.add_argument("--check-timeout", type=int,
                        help="Seconds allowed for each preparation and check (default: --timeout)")
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error("--timeout must be a positive number of seconds")
    if args.check_timeout is not None and not 1 <= args.check_timeout <= 7200:
        parser.error("--check-timeout must be between 1 and 7200 seconds")
    if not args.resolve_journal and (not args.source or not args.expected_source_head):
        parser.error("--source and --expected-source-head are required for integration")
    if args.resolve_journal and (args.source or args.expected_source_head or args.prepare):
        parser.error("resolution uses checks only, without source or preparation")
    try:
        preparations = [shlex.split(command) for command in args.prepare]
        checks = [shlex.split(command) for command in args.check]
    except ValueError as error:
        report("BLOCKED_POLICY", f"Verification command is not a parseable argv: {error}")
        return 2
    if not all(approved_prepare(argv) for argv in preparations) or not all(approved_check(argv, args.allow_focused_checks) for argv in checks):
        report("BLOCKED_POLICY", "Verification command is outside the approved test/build set")
        return 2
    try:
        require_check_interpreters(checks)
    except CheckInterpreterError as error:
        report("BLOCKED_POLICY", str(error))
        return 2
    return integrate_scratch(args, preparations, checks)


def private_directory(path, *, create=True):
    if path.is_symlink():
        raise OSError('private scratch path is a symlink')
    created = False
    if create:
        try:
            path.mkdir(mode=0o700)
            created = True
        except FileExistsError:
            pass
    info = os.stat(path, follow_symlinks=False)
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o700):
        raise OSError('private scratch path is not owner-only')
    if created:
        fsync_directory(path.parent)
    return info


def git_common_directory(repo, timeout):
    result = inspect_git(repo, 'rev-parse', '--git-common-dir', timeout=timeout)
    value = result.stdout.strip()
    if result.returncode or not value or '\n' in value or '\0' in value:
        raise OSError('Git common directory is ambiguous')
    named = Path(value)
    if not named.is_absolute():
        named = repo / named
    if named.is_symlink():
        raise OSError('Git common directory is a symlink')
    common = named.resolve(strict=True)
    info = os.stat(common, follow_symlinks=False)
    if not stat.S_ISDIR(info.st_mode):
        raise OSError('Git common directory is invalid')
    return common, info


def scratch_journal_root(repo, timeout):
    # Git's common directory is independent of HOME and shared by linked
    # worktrees. An owner-only child keeps journals out of Git publications.
    common, common_info = git_common_directory(repo, timeout)
    private_directory(common / 'agent-harness')
    root = common / 'agent-harness' / 'delivery-scratch'
    root_info = private_directory(root)
    return root, common, common_info, root_info


def checkout_identity(repo):
    info = os.stat(repo, follow_symlinks=False)
    if not stat.S_ISDIR(info.st_mode):
        raise OSError('original checkout is not a directory')
    return info.st_dev, info.st_ino


def valid_identity_text(value):
    if not isinstance(value, str) or '\0' in value:
        return False
    try:
        value.encode('utf-8')
    except UnicodeError:
        return False
    return True


def journal_key(identity, branch, base, source_branch, source):
    payload = '\0'.join((str(identity[0]), str(identity[1]), branch, base,
                         source_branch, source)).encode()
    return hashlib.sha256(payload).hexdigest()


def candidate_ref(record):
    attempt = record.get('attempt')
    suffix = record['key'] + ('-' + attempt if attempt is not None else '')
    return 'refs/agent-harness/delivery/' + suffix


def scope_key(identity, branch):
    return hashlib.sha256(f'{identity[0]}\0{identity[1]}\0{branch}'.encode()).hexdigest()


def scope_directory(root, identity, branch, *, create=True):
    scopes = root / 'scopes'
    private_directory(scopes, create=create)
    key = scope_key(identity, branch)
    scope = scopes / key
    private_directory(scope, create=create)
    for name in ('active', 'archive'):
        private_directory(scope / name, create=create)
    return scope


def fsync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def archive_journal(directory):
    """Retire metadata without moving or deleting retained worktree data."""
    if directory.parent.name != 'active':
        return directory  # Legacy journals can contain their old worktree.
    target = directory.parent.parent / 'archive' / directory.name
    if os.path.lexists(target):
        raise OSError('archive destination already exists')
    os.rename(directory, target)
    fsync_directory(directory.parent)
    fsync_directory(target.parent)
    return target


def preserve_resolved_attempt(directory):
    """Leave the prior resolution intact before retrying the same tuple."""
    history = directory.parent / 'history'
    private_directory(history)
    generation = Path(tempfile.mkdtemp(prefix='attempt-', dir=history))
    os.rename(directory, generation / directory.name)
    fsync_directory(generation)
    fsync_directory(history)
    fsync_directory(directory.parent)


def remaining_budget(deadline, timeout):
    remaining = min(timeout, deadline - time.monotonic())
    if remaining <= 0:
        raise OSError('journal scan deadline exceeded')
    return remaining


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


def reserve_scratch(root, repo, identity, branch, base, source_branch, source):
    key = journal_key(identity, branch, base, source_branch, source)
    directory = scope_directory(root, identity, branch) / 'active' / key
    try:
        directory.mkdir(mode=0o700)
    except FileExistsError:
        return directory, None
    fsync_directory(directory.parent)
    container = Path(tempfile.mkdtemp(prefix='agent-harness-delivery-scratch-')).resolve()
    if set(container.parts) & {'.git', '.hg', '.sl'}:
        container.rmdir()
        raise OSError('scratch container is inside a VCS directory')
    container_info = private_directory(container)
    scratch = container / 'worktree'
    record = {'schema': 2, 'phase': 'started', 'original': str(repo),
              'original_dev': identity[0], 'original_ino': identity[1], 'branch': branch,
              'base': base, 'source_branch': source_branch, 'source': source,
              'scratch': str(scratch), 'key': key, 'container': str(container),
              'container_dev': container_info.st_dev, 'container_ino': container_info.st_ino,
              'attempt': secrets.token_hex(16)}
    write_journal(directory, record, first=True)
    return directory, record


def acquire_scope_lock(root, identity, branch):
    locks = root / 'locks'
    private_directory(locks)
    key = scope_key(identity, branch)
    fd = os.open(locks / key, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600):
            raise OSError('private integration lock is unsafe')
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(fd)
            return None
        return fd
    except BaseException:
        os.close(fd)
        raise


def hex_identity(value, length):
    return (isinstance(value, str) and len(value) == length
            and all(char in '0123456789abcdef' for char in value))


def external_key(record):
    values = ('external-apply', str(record['original_dev']), str(record['original_ino']),
              record['branch'], record['base'], record['target'], record['object_format'],
              record['task_digest'], record['attempt'])
    return hashlib.sha256('\0'.join(values).encode('utf-8')).hexdigest()


def external_ref(record):
    return 'refs/agent-harness/external-apply/' + record['key'] + '-' + record['attempt']


def validate_external_record(directory, record):
    """Schema3 is a baseline barrier, never a scratch merge delivery proof."""
    required = {'schema', 'kind', 'phase', 'key', 'original', 'original_dev', 'original_ino',
                'branch', 'base', 'target', 'object_format', 'task_digest', 'attempt', 'ref'}
    phase = record.get('phase')
    if not isinstance(phase, str) or phase not in {'reserved', 'applying', 'resolved'}:
        raise OSError('external apply phase is invalid')
    if phase == 'resolved':
        required |= {'resolved_head', 'resolved_by', 'previous_phase'}
    if set(record) != required or record.get('kind') != 'external_apply':
        raise OSError('external apply fields are invalid')
    if (any(not valid_identity_text(record[name]) for name in required
            if name not in {'schema', 'original_dev', 'original_ino'})
            or not all(type(record[name]) is int and record[name] > 0
                       for name in ('original_dev', 'original_ino'))
            or not Path(record['original']).is_absolute()
            or not record['branch'] or record['branch'].startswith('-')
            or record['object_format'] not in {'sha1', 'sha256'}
            or not hex_identity(record['task_digest'], 64)
            or not hex_identity(record['attempt'], 32)
            or not hex_identity(record['key'], 64)):
        raise OSError('external apply identity is invalid')
    oid_length = 40 if record['object_format'] == 'sha1' else 64
    if (not all(hex_identity(record[name], oid_length) for name in ('base', 'target'))
            or record['key'] != external_key(record) or record['ref'] != external_ref(record)):
        raise OSError('external apply target binding is invalid')
    if phase == 'resolved' and (not hex_identity(record['resolved_head'], oid_length)
            or record['resolved_by'] not in {'workflow', 'operator'}
            or record['previous_phase'] not in {'reserved', 'applying', 'resolved'}
            or record['resolved_by'] == 'workflow' and record['resolved_head'] != record['target']):
        raise OSError('external apply resolution is invalid')
    identity = (record['original_dev'], record['original_ino'])
    if (directory.parent.name not in {'active', 'archive'}
            or directory.parent.parent.parent.name != 'scopes'
            or directory.parent.parent.name != scope_key(identity, record['branch'])):
        raise OSError('external apply journal placement is invalid')
    return record


def read_journal(directory):
    info = os.stat(directory, follow_symlinks=False)
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o700):
        raise OSError('scratch journal directory is unsafe')
    fd = os.open(directory / 'journal.json', os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
                or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_size > 8192):
            raise OSError('scratch journal is unsafe')
        data = os.read(fd, 8193)
        if len(data) > 8192:
            raise OSError('scratch journal exceeds size limit')
    finally:
        os.close(fd)
    try:
        record = json.loads(data)
    except (ValueError, UnicodeDecodeError) as error:
        raise OSError('scratch journal is invalid') from error
    if (not isinstance(record, dict) or type(record.get('schema')) is not int
            or record.get('schema') not in (1, 2, 3)
            or record.get('key') != directory.name or not isinstance(record.get('phase'), str)):
        raise OSError('scratch journal is invalid')
    if record['schema'] == 3:
        return validate_external_record(directory, record)
    text_fields = ('key', 'phase', 'original', 'branch', 'base', 'source_branch', 'source',
                   'scratch', 'container', 'ref', 'attempt', 'previous_phase',
                   'resolved_head', 'candidate', 'tree')
    if any(name in record and not valid_identity_text(record[name]) for name in text_fields):
        raise OSError('scratch journal text identity is invalid')
    if (('ref' in record and not isinstance(record['ref'], str))
            or ('cleanup_pending' in record and type(record['cleanup_pending']) is not bool)
            or any(name in record and not full_oid(record[name]) for name in ('candidate', 'tree'))):
        raise OSError('scratch journal fields are invalid')
    if ('attempt' in record and (not isinstance(record['attempt'], str) or len(record['attempt']) != 32
                                or any(char not in '0123456789abcdef' for char in record['attempt']))):
        raise OSError('scratch attempt identity is invalid')
    identity = (record.get('original_dev'), record.get('original_ino'))
    if record.get('reservation_only') is True:
        if (record['schema'] != 2 or record.get('phase') != 'resolved'
                or not all(type(value) is int and value > 0 for value in identity)
                or not isinstance(record.get('branch'), str)
                or not full_oid(record.get('resolved_head'))
                or directory.parent.name not in {'active', 'archive'}):
            raise OSError('resolved reservation is invalid')
        return record
    if (not all(type(value) is int and value > 0 for value in identity)
            or not all(isinstance(record.get(name), str) for name in ('branch', 'base',
                                                                     'source_branch', 'source'))
            or not all(full_oid(record[name]) for name in ('base', 'source'))
            or journal_key(identity, record['branch'], record['base'],
                           record['source_branch'], record['source']) != directory.name):
        raise OSError('scratch journal identity is invalid')
    if record['schema'] == 1:
        if record.get('scratch') != str(directory / 'worktree'):
            raise OSError('legacy scratch path is invalid')
    else:
        if not isinstance(record.get('container'), str):
            raise OSError('scratch container path is invalid')
        container = Path(record['container'])
        if (not container.is_absolute() or set(container.parts) & {'.git', '.hg', '.sl'}
                or record.get('scratch') != str(container / 'worktree')
                or not all(type(record.get(name)) is int and record[name] > 0
                           for name in ('container_dev', 'container_ino'))):
            raise OSError('scratch container metadata is invalid')
    return record


def full_oid(value):
    return (isinstance(value, str) and len(value) in (40, 64)
            and all(char in '0123456789abcdef' for char in value))


def completed_journal_is_verified(repo, identity, branch, directory, record, timeout, *, deadline=None):
    """A completed journal is safe to skip only while its delivery remains real."""
    candidate, base, source, tree = (record.get('candidate'), record.get('base'),
                                     record.get('source'), record.get('tree'))
    if (record.get('original_dev'), record.get('original_ino')) != identity or record.get('branch') != branch:
        return False
    if not all(full_oid(value) for value in (candidate, base, source, tree)):
        return False
    if deadline is None:
        deadline = time.monotonic() + min(timeout, JOURNAL_SCAN_SECONDS)
    def inspect(*args):
        return inspect_git(repo, *args, timeout=remaining_budget(deadline, timeout))
    current_result = inspect('rev-parse', 'HEAD')
    current = current_result.stdout.strip() if not current_result.returncode else None
    if not current or not checked_original(repo, branch, current, timeout, deadline=deadline):
        return False
    parents = inspect('rev-list', '--parents', '-n', '1', candidate)
    actual_tree = inspect('rev-parse', f'{candidate}^{{tree}}')
    ancestor = inspect('merge-base', '--is-ancestor', candidate, current)
    if (parents.returncode or parents.stdout.split() != [candidate, base, source]
            or actual_tree.returncode or actual_tree.stdout.strip() != tree
            or ancestor.returncode != 0):
        return False
    ref = candidate_ref(record)
    if record.get('ref') != ref:
        return False
    pin = inspect('show-ref', '--verify', '--quiet', ref)
    if pin.returncode not in (0, 1):
        return False
    if pin.returncode == 0 and inspect('rev-parse', ref).stdout.strip() != candidate:
        return False
    scratch = Path(record['scratch'])
    present = os.path.lexists(scratch)
    if present:
        info = os.stat(scratch, follow_symlinks=False)
        if (not stat.S_ISDIR(info.st_mode)
                or (info.st_dev, info.st_ino) != (record.get('scratch_dev'), record.get('scratch_ino'))
                or pin.returncode != 0):
            return False
        if record['schema'] == 2 and not scratch_container_is_current(record):
            return False
        scratch_head = inspect_git(scratch, 'rev-parse', 'HEAD', timeout=remaining_budget(deadline, timeout))
        if scratch_head.returncode or scratch_head.stdout.strip() != candidate:
            return False
    if not isinstance(record.get('cleanup_pending'), bool):
        return False
    # A user may have finished cleanup since delivery. Do not recreate work or
    # make an obsolete pending flag a permanent recovery trap.
    record['cleanup_pending'] = (present or pin.returncode == 0
                                 or record['schema'] == 2 and os.path.lexists(record['container']))
    if not checked_original(repo, branch, current, timeout, deadline=deadline):
        return False
    record['_verified_head'] = current
    return True


def scan_journals(root, repo, identity, branch, key, timeout):
    """Recovery scans never exempt an active journal for ordinary callers."""
    return _scan_journals(root, repo, identity, branch, key, timeout)


def _scan_journals(root, repo, identity, branch, key, timeout, *, completing_guard=None,
                   archive_settled=True):
    """Inspect bounded active state; archived history is an exact-key lookup."""
    deadline = time.monotonic() + min(timeout, JOURNAL_SCAN_SECONDS)
    scope = scope_directory(root, identity, branch, create=archive_settled)
    exact = None
    count = 0
    # Schema 1 is a fixed legacy namespace: new attempts never add to it.
    legacy = (entry for entry in root.iterdir() if entry.name not in {'locks', 'scopes'})
    for entries in (legacy, (scope / 'active').iterdir()):
        for entry in entries:
            remaining_budget(deadline, timeout)
            count += 1
            if count > JOURNAL_MAX_ENTRIES or len(entry.name) != 64 or any(char not in '0123456789abcdef' for char in entry.name):
                return entry, None, None
            try:
                record = read_journal(entry)
                remaining_budget(deadline, timeout)
            except OSError:
                return entry, None, None
            if completing_guard is not None and entry == completing_guard.journal.parent:
                # Only complete_external supplies this capability, after full
                # ownership validation. Reread before excluding its own barrier.
                if record != completing_guard.record:
                    return entry, record, None
                continue
            same_scope = ((record.get('original_dev'), record.get('original_ino')) == identity
                          and record.get('branch') == branch)
            if not same_scope:
                continue
            if record.get('phase') not in {'delivered', 'resolved'}:
                return entry, record, None
            if entry.name == key and record['phase'] == 'delivered':
                exact = (entry, record)
            if archive_settled and record['schema'] in (2, 3):
                archived = archive_journal(entry)
                if exact is not None and exact[0] == entry:
                    exact = (archived, record)
    # Do this only after active recovery is checked, including other tuples.
    archived = scope / 'archive' / key
    if exact is None and os.path.lexists(archived):
        remaining_budget(deadline, timeout)
        record = read_journal(archived)
        remaining_budget(deadline, timeout)
        if completing_guard is not None and archived == completing_guard.journal.parent:
            if record != completing_guard.record:
                return archived, record, None
            return None, None, None
        if ((record.get('original_dev'), record.get('original_ino')) != identity
                or record.get('branch') != branch
                or record.get('phase') not in {'delivered', 'resolved'}):
            return archived, record, None
        if record['phase'] == 'delivered':
            exact = (archived, record)
        elif record['schema'] != 3:
            record['_resolved_journal'] = str(archived)
            return None, None, record
    if exact is not None:
        entry, record = exact
        try:
            valid = completed_journal_is_verified(repo, identity, branch, entry, record,
                                                   timeout, deadline=deadline)
        except (IndexInspectionError, OSError, subprocess.TimeoutExpired):
            valid = False
        if not valid:
            return entry, record, None
        record['_journal'] = str(entry / 'journal.json')
        return None, None, record
    remaining_budget(deadline, timeout)
    return None, None, None


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


def checked_original(repo, branch, base, timeout, *, deadline=None):
    def budget():
        return timeout if deadline is None else remaining_budget(deadline, timeout)
    safe_source(repo, budget(), deadline=deadline)
    index_unflagged(repo, budget())
    current_branch = inspect_git(repo, 'symbolic-ref', '--quiet', '--short', 'HEAD', timeout=budget())
    current_head = inspect_git(repo, 'rev-parse', 'HEAD', timeout=budget())
    status = inspect_git(repo, 'status', '--porcelain', '--untracked-files=all',
                         '--ignore-submodules=none', timeout=budget())
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


def scratch_container_is_current(record):
    if record['schema'] == 1:
        return True
    container = Path(record['container'])
    info = os.stat(container, follow_symlinks=False)
    return (stat.S_ISDIR(info.st_mode) and info.st_uid == os.geteuid()
            and stat.S_IMODE(info.st_mode) == 0o700
            and (info.st_dev, info.st_ino) == (record['container_dev'], record['container_ino']))


def resolve_journal(args, repo, identity, root, common, common_info, root_info, checks):
    """Accept an explicitly tested baseline; preserve every recovery artifact."""
    key = args.resolve_journal
    if len(key) != 64 or any(char not in '0123456789abcdef' for char in key):
        report('BLOCKED_POLICY', 'Journal key must be a full lowercase SHA-256')
        return 2
    scope = scope_directory(root, identity, args.original_branch)
    candidates = [root / key, scope / 'active' / key, scope / 'archive' / key]
    found = [path for path in candidates if os.path.lexists(path)]
    if len(found) != 1:
        report('RECOVERY_REQUIRED', 'Journal selection is missing or ambiguous')
        return 3
    directory = found[0]
    missing_record = False
    try:
        record = read_journal(directory)
    except FileNotFoundError:
        # The scoped reservation itself precedes the journal write. An explicit
        # resolution may retire that crash boundary without inventing a source
        # or claiming that any candidate was delivered.
        if directory.parent != scope / 'active' or os.path.lexists(directory / 'journal.json'):
            raise
        private_directory(directory)
        missing_record = True
        record = {'schema': 2, 'phase': 'reserved', 'key': key, 'reservation_only': True,
                  'original': str(repo), 'original_dev': identity[0], 'original_ino': identity[1],
                  'branch': args.original_branch}
    if ((record['original_dev'], record['original_ino']) != identity
            or record['branch'] != args.original_branch):
        report('BLOCKED_POLICY', 'Journal belongs to another original checkout or branch')
        return 2
    if record['schema'] == 3:
        storage = inspect_git(repo, 'rev-parse', '--show-object-format', timeout=args.timeout)
        if storage.returncode or storage.stdout.strip() != record['object_format']:
            report('RECOVERY_REQUIRED', 'External recovery journal object format does not match checkout',
                   journal=str(directory / 'journal.json'))
            return 3
    if not checked_original(repo, args.original_branch, args.expected_head, args.timeout):
        report('RECOVERY_REQUIRED', 'Confirmed recovery checkout is changed or dirty',
               journal=str(directory / 'journal.json'), head=observed_head(repo))
        return 3
    log = CheckLog(directory / 'checks')
    try:
        if getattr(args, 'baseline_compare', False):
            code = baseline_compare_gate(args, repo, directory, checks, log, record)
            if code:
                return code
            checks = []
        for command in checks:
            log.header(command)
            try:
                result = run(repo, command, timeout=check_timeout(args), discard_output=True, sink=log)
            except subprocess.TimeoutExpired:
                log.close()
                report('RECOVERY_REQUIRED',
                       f'Recovery baseline check exceeded {check_timeout(args)} seconds; journal remains unresolved',
                       journal=str(directory / 'journal.json'), head=observed_head(repo),
                       phase='check', **log.facts())
                return 3
            except OSError as error:
                log.close()
                reason = str(error) if isinstance(error, CheckInterpreterError) else 'Recovery baseline check could not start'
                report('RECOVERY_REQUIRED', reason + '; journal remains unresolved',
                       journal=str(directory / 'journal.json'), head=observed_head(repo),
                       phase='check', **log.facts())
                return 3
            if result.returncode:
                log.close()
                report('RECOVERY_REQUIRED', 'Recovery baseline check failed; journal remains unresolved',
                       journal=str(directory / 'journal.json'), head=observed_head(repo),
                       phase='check', exit_code=result.returncode, **log.facts())
                return 3
    finally:
        log.close()
    if (not common_state_is_current(repo, identity, common, common_info, root, root_info, args.timeout)
            or not checked_original(repo, args.original_branch, args.expected_head, args.timeout)):
        report('RECOVERY_REQUIRED', 'Recovery checkout changed during checks',
               journal=str(directory / 'journal.json'), head=observed_head(repo))
        return 3
    record.update({'previous_phase': record.get('phase'), 'phase': 'resolved',
                   'resolved_head': args.expected_head})
    pin_details = {}
    if record['schema'] == 3:
        record['resolved_by'] = 'operator'
        pin_state, verified = external_pin_state(repo, record, args.timeout)
        pin_details = {'pin_state': pin_state, 'target_pin_verified': verified}
    write_journal(directory, record, first=missing_record)
    directory = archive_journal(directory)
    finish_compare_evidence(args, directory)
    report('RESOLVED', 'Tested current checkout accepted as recovery baseline; artifacts retained',
           head=args.expected_head, journal=str(directory / 'journal.json'),
           scratch=record.get('scratch'), recovery_ref=record.get('ref'),
           artifacts_unknown=missing_record, baseline_compare=getattr(args, 'compare_result', None), **pin_details)
    return 0


def helper_identity():
    here = Path(__file__).resolve().parent
    out = {'tree': str(here), 'files': {}}
    for name in ('integrate_local.py', 'suite_compare.py', 'suite_report.py', 'test_scope.py'):
        try:
            out['files'][name] = hashlib.sha256((here / name).read_bytes()).hexdigest()
        except OSError:
            out['files'][name] = 'missing'
    return out


def write_compare_result(directory, result):
    path = Path(directory) / 'baseline-compare.json'
    tmp = path.with_name(path.name + f'.tmp.{os.getpid()}')
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as handle:
        json.dump(result, handle, indent=1, sort_keys=True)
    os.replace(tmp, path)


def resolve_pin(args, record):
    """(pinned HEAD, problem): the journal's own base is the generation's original HEAD, so the caller cannot choose a weaker
    pin. Only a reservation-only journal (no base) needs --pinned-head."""
    base = (record or {}).get('base')
    explicit = getattr(args, 'pinned_head', None)
    if base:
        if explicit and explicit != base:
            return None, '--pinned-head does not match the journal base ' + base
        return base, None
    if explicit:
        return explicit, None
    return None, 'the journal records no base commit; pass --pinned-head with the generation\'s pinned original HEAD'


def finish_compare_evidence(args, directory):
    """Persist the compare result only once the journal is resolved and archived, never earlier."""
    result = getattr(args, 'compare_result', None)
    if result:
        write_compare_result(directory, result)


def baseline_compare_gate(args, repo, directory, checks, log, record=None):
    """--resolve-journal --baseline-compare (GoodQA #14582): the whole suite passes when its failing ids are an exact subset
    of the complete suite baseline recorded for exactly the confirmed HEAD (args.expected_head); the rule deliver.py
    --baseline-compare applies. Returns 0 when it passed, otherwise the exit code after reporting."""
    import suite_compare
    if list(checks) != [suite_compare.WHOLE_SUITE_ARGV]:
        log.close()
        report('BLOCKED_POLICY', "--baseline-compare needs exactly one check, the whole suite "
               "'python3 -m unittest discover -s tests'")
        return 2
    suite_compare.scrub_store_env()  # the store comes from the policy, never from the caller's environment
    pinned, problem = resolve_pin(args, record)
    if problem:
        log.close()
        report('BLOCKED_POLICY', 'Baseline comparison cannot start: ' + problem, journal=str(directory / 'journal.json'))
        return 2
    try:
        result = suite_compare.run_compare(repo, args.expected_head, check_timeout(args), directory / 'checks', run, log,
                                           pinned_sha=pinned)
        result['helper'] = helper_identity()
        args.compare_result = result
    except suite_compare.CompareFailure as failure:
        log.close()
        report('RECOVERY_REQUIRED', 'Baseline comparison failed: ' + '; '.join(failure.problems[:4])
               + '; journal remains unresolved', journal=str(directory / 'journal.json'),
               head=observed_head(repo), phase='check', baseline_compare_problems=failure.problems[:20])
        return 3
    return 0


def common_state_is_current(repo, identity, common, common_info, root, root_info, timeout):
    if checkout_identity(repo) != identity:
        return False
    current, current_info = git_common_directory(repo, timeout)
    observed_root = os.stat(root, follow_symlinks=False)
    return (current == common
            and (current_info.st_dev, current_info.st_ino) == (common_info.st_dev, common_info.st_ino)
            and stat.S_ISDIR(observed_root.st_mode)
            and observed_root.st_uid == os.geteuid()
            and stat.S_IMODE(observed_root.st_mode) == 0o700
            and (observed_root.st_dev, observed_root.st_ino) == (root_info.st_dev, root_info.st_ino))


class ExternalApplyError(OSError):
    """Safe recovery information without Git output or caller-provided text."""

    def __init__(self, message, *, journal=None, ref=None, target=None, reservation_started=None):
        super().__init__(message)
        self.journal = journal
        self.ref = ref
        self.target = target
        self.reservation_started = reservation_started


class ExternalApplyGuard:
    """An immutable snapshot owned by one live OriginalScope context."""

    def __init__(self, owner, directory, record):
        self._owner = owner
        self._directory = directory
        self._record = dict(record)
        self._location = self._location_signature()

    def _location_signature(self):
        signature = []
        for path in (self._directory, self.journal):
            info = os.stat(path, follow_symlinks=False)
            signature.append((info.st_dev, info.st_ino, info.st_mode, info.st_uid,
                              info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns))
        return tuple(signature)

    def _location_is_current(self):
        try:
            return self._location_signature() == self._location
        except OSError:
            return False

    @property
    def key(self):
        return self._record['key']

    @property
    def journal(self):
        return self._directory / 'journal.json'

    @property
    def ref(self):
        return self._record['ref']

    @property
    def target(self):
        return self._record['target']

    @property
    def base(self):
        return self._record['base']

    @property
    def record(self):
        return dict(self._record)


def external_pin_state(repo, record, timeout):
    """Resolution preserves even missing/moved refs and reports observed truth."""
    try:
        present = inspect_git(repo, 'show-ref', '--verify', '--quiet', record['ref'], timeout=timeout)
        if present.returncode == 1:
            return 'missing', False
        if present.returncode != 0:
            return 'unverifiable', False
        value = inspect_git(repo, 'rev-parse', '--verify', record['ref'], timeout=timeout)
        length = 40 if record['object_format'] == 'sha1' else 64
        actual = value.stdout.strip()
        if value.returncode or not hex_identity(actual, length):
            return 'unverifiable', False
        return ('matches_target', True) if actual == record['target'] else ('moved', False)
    except (IndexInspectionError, OSError, subprocess.TimeoutExpired):
        return 'unverifiable', False


class OriginalScope:
    """Serialize external apply with the local helper's original-checkout lock.

    Callers retain the context through their durable workflow receipt. This API
    accepts a tested baseline; it cannot prove the caller's PR or checks passed.
    """

    def __init__(self, repo, branch, timeout=30):
        try:
            named = Path(repo)
        except (TypeError, ValueError):
            raise ExternalApplyError('Original checkout identity is invalid') from None
        if (not valid_identity_text(str(named)) or not valid_identity_text(branch)
                or not branch or branch.startswith('-') or type(timeout) not in (int, float)
                or not math.isfinite(timeout) or timeout <= 0):
            raise ExternalApplyError('Original scope arguments are invalid')
        self._repo = named.resolve()
        self._branch = branch
        self._timeout = timeout
        self._lock_fd = None
        self._entered = False

    @property
    def repo(self):
        return self._repo

    @property
    def branch(self):
        return self._branch

    @property
    def timeout(self):
        return self._timeout

    @property
    def root(self):
        return self._root

    @property
    def identity(self):
        return self._identity

    @property
    def object_format(self):
        return self._object_format

    def __enter__(self):
        if self._entered:
            raise ExternalApplyError('Original scope context cannot be reused')
        self._entered = True
        try:
            if any(name.startswith('GIT_') and name not in ALLOWED_GIT_ENV for name in os.environ):
                raise OSError('unsupported Git routing environment')
            top = inspect_git(self.repo, 'rev-parse', '--show-toplevel', timeout=self.timeout)
            if (top.returncode or not top.stdout.strip()
                    or not os.path.samefile(Path(top.stdout.strip()).resolve(), self.repo)
                    or inspect_git(self.repo, 'check-ref-format', 'refs/heads/' + self.branch,
                                   timeout=self.timeout).returncode):
                raise OSError('original checkout or branch is invalid')
            self._identity = checkout_identity(self.repo)
            self._root, self._common, self._common_info, self._root_info = scratch_journal_root(
                self.repo, self.timeout)
            self._lock_fd = acquire_scope_lock(self.root, self.identity, self.branch)
            if self._lock_fd is None:
                raise OSError('original scope is busy')
            self._lock_info = os.fstat(self._lock_fd)
            storage = inspect_git(self.repo, 'rev-parse', '--show-object-format', timeout=self.timeout)
            self._object_format = storage.stdout.strip()
            if storage.returncode or self.object_format not in {'sha1', 'sha256'}:
                raise OSError('unsupported object format')
            self._assert_current()
            return self
        except (IndexInspectionError, OSError, subprocess.TimeoutExpired):
            self.__exit__(None, None, None)
            raise ExternalApplyError('Original scope could not be safely acquired') from None
        except BaseException:
            # __exit__ is not called when __enter__ itself is interrupted.
            self.__exit__(None, None, None)
            raise

    def __exit__(self, exc_type, exc_value, traceback):
        if self._lock_fd is not None:
            os.close(self._lock_fd)
            self._lock_fd = None

    def _assert_current(self):
        if self._lock_fd is None:
            raise ExternalApplyError('Original scope context is closed')
        lock = self.root / 'locks' / scope_key(self.identity, self.branch)
        info = os.stat(lock, follow_symlinks=False)
        descriptor = os.fstat(self._lock_fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o600
                or (info.st_dev, info.st_ino) != (self._lock_info.st_dev, self._lock_info.st_ino)
                or (descriptor.st_dev, descriptor.st_ino) != (info.st_dev, info.st_ino)
                or not common_state_is_current(self.repo, self.identity, self._common,
                      self._common_info, self.root, self._root_info, self.timeout)):
            raise ExternalApplyError('Original scope identity changed')

    def reserve_external(self, *, base, target, task_digest):
        directory = None
        record = None
        reservation_started = False
        try:
            self._assert_current()
            length = 40 if self.object_format == 'sha1' else 64
            if (not hex_identity(base, length) or not hex_identity(target, length)
                    or not hex_identity(task_digest, 64)):
                raise OSError('invalid external apply inputs')
            blocking, blocked, _ = scan_journals(self.root, self.repo, self.identity,
                                                self.branch, '0' * 64, self.timeout)
            if blocking is not None:
                raise ExternalApplyError('Unresolved original recovery state requires inspection',
                                         journal=blocking / 'journal.json',
                                         ref=blocked.get('ref') if blocked else None,
                                         target=blocked.get('target') if blocked else None,
                                         reservation_started=False)
            commit = inspect_git(self.repo, 'cat-file', '-t', target, timeout=self.timeout)
            ancestry = inspect_git(self.repo, 'merge-base', '--is-ancestor', base, target,
                                   timeout=self.timeout)
            if (commit.returncode or commit.stdout.strip() != 'commit' or ancestry.returncode
                    or not checked_original(self.repo, self.branch, base, self.timeout)):
                raise OSError('external apply baseline or target is invalid')
            self._assert_current()
            record = {'schema': 3, 'kind': 'external_apply', 'phase': 'reserved',
                      'original': str(self.repo), 'original_dev': self.identity[0],
                      'original_ino': self.identity[1], 'branch': self.branch, 'base': base,
                      'target': target, 'object_format': self.object_format,
                      'task_digest': task_digest, 'attempt': secrets.token_hex(16)}
            record['key'] = external_key(record)
            record['ref'] = external_ref(record)
            directory = scope_directory(self.root, self.identity, self.branch) / 'active' / record['key']
            # Even mkdir failure may be ambiguous. Never derive this proof
            # from an absent path or a journal belonging to another attempt.
            reservation_started = True
            directory.mkdir(mode=0o700)
            fsync_directory(directory.parent)
            write_journal(directory, record, first=True)
            pinned = run_git_nohooks(self.repo, 'update-ref', record['ref'], target,
                                     '0' * length, timeout=self.timeout)
            if pinned.returncode:
                raise OSError('external target pin failed')
            record['phase'] = 'applying'
            write_journal(directory, record)
            return ExternalApplyGuard(self, directory, record)
        except ExternalApplyError as error:
            error.reservation_started = reservation_started
            raise
        except (IndexInspectionError, OSError, subprocess.TimeoutExpired):
            raise ExternalApplyError('External apply could not be reserved; inspect recovery state',
                                     journal=directory / 'journal.json' if directory else None,
                                     ref=record.get('ref') if record else None,
                                     target=record.get('target') if record else None,
                                     reservation_started=reservation_started) from None

    def load_external(self, key, task_digest, *, create=True):
        """Load a guard, optionally refusing missing namespaces without repair."""
        directory = None
        try:
            self._assert_current()
            if not hex_identity(key, 64) or not hex_identity(task_digest, 64):
                raise OSError('invalid guard selection')
            scope = scope_directory(self.root, self.identity, self.branch, create=create)
            found = [scope / area / key for area in ('active', 'archive')
                     if os.path.lexists(scope / area / key)]
            if len(found) != 1:
                raise OSError('external apply selection is missing or ambiguous')
            directory = found[0]
            record = read_journal(directory)
            if (record['schema'] != 3 or record['task_digest'] != task_digest
                    or (record['original_dev'], record['original_ino']) != self.identity
                    or record['branch'] != self.branch or record['object_format'] != self.object_format):
                raise OSError('external apply belongs to another scope or task')
            return ExternalApplyGuard(self, directory, record)
        except (IndexInspectionError, OSError, subprocess.TimeoutExpired):
            raise ExternalApplyError('External apply guard could not be verified',
                                     journal=directory / 'journal.json' if directory else None) from None

    def _validated_external(self, guard, *, archive_settled):
        if not isinstance(guard, ExternalApplyGuard) or guard._owner is not self:
            raise ExternalApplyError('External apply guard belongs to another context')
        directory = guard.journal.parent
        try:
            self._assert_current()
            record = read_journal(directory)
            scope = scope_directory(self.root, self.identity, self.branch, create=archive_settled)
            if (not guard._location_is_current() or record != guard.record or record.get('schema') != 3
                    or directory.parent not in {scope / 'active', scope / 'archive'}
                    or (record['original_dev'], record['original_ino']) != self.identity
                    or record['branch'] != self.branch or record['object_format'] != self.object_format
                    or record.get('phase') == 'resolved' and record.get('resolved_by') != 'workflow'
                    or not checked_original(self.repo, self.branch, guard.target, self.timeout)
                    or external_pin_state(self.repo, record, self.timeout) != ('matches_target', True)):
                raise OSError('external apply completion state changed')
            blocking, blocked, _ = _scan_journals(self.root, self.repo, self.identity,
                                                self.branch, guard.key, self.timeout,
                                                completing_guard=guard,
                                                archive_settled=archive_settled)
            if blocking is not None:
                raise ExternalApplyError('Another original recovery barrier requires inspection',
                                         journal=blocking / 'journal.json',
                                         ref=blocked.get('ref') if blocked else None,
                                         target=blocked.get('target') if blocked else None)
            self._assert_current()
            if (not guard._location_is_current() or read_journal(directory) != record
                    or not checked_original(self.repo, self.branch, guard.target, self.timeout)
                    or external_pin_state(self.repo, record, self.timeout) != ('matches_target', True)):
                raise OSError('external apply changed during recovery scan')
            return directory, record
        except ExternalApplyError:
            raise
        except (IndexInspectionError, OSError, subprocess.TimeoutExpired):
            raise ExternalApplyError('External apply remains subject to recovery inspection',
                                     journal=directory / 'journal.json', ref=guard.ref,
                                     target=guard.target) from None

    def validate_external(self, guard):
        """Verify a live guard without changing any journal content or placement."""
        self._validated_external(guard, archive_settled=False)
        return guard

    def complete_external(self, guard):
        directory, record = self._validated_external(guard, archive_settled=True)
        try:
            if record['phase'] != 'resolved':
                record.update(phase='resolved', previous_phase=record['phase'],
                              resolved_by='workflow', resolved_head=guard.target)
                write_journal(directory, record)
            directory = archive_journal(directory)
            return ExternalApplyGuard(self, directory, record)
        except ExternalApplyError:
            raise
        except (IndexInspectionError, OSError, subprocess.TimeoutExpired):
            raise ExternalApplyError('External apply remains subject to recovery inspection',
                                     journal=directory / 'journal.json', ref=guard.ref,
                                     target=guard.target) from None


def integrate_scratch(args, preparations, checks):
    if any(name.startswith('GIT_') and name not in ALLOWED_GIT_ENV for name in os.environ):
        report('BLOCKED_POLICY', 'Inherited Git routing or configuration override is unsupported')
        return 2
    identities = [str(args.repo), args.original_branch, args.expected_head]
    identities.extend(value for value in (args.source, args.expected_source_head,
                                          getattr(args, 'resolve_journal', None)) if value is not None)
    if not all(valid_identity_text(value) for value in identities):
        report('BLOCKED_POLICY', 'Checkout, ref, or journal identity text is invalid')
        return 2
    repo = args.repo.resolve()
    directory = None
    record = None
    phase = 'preflight'
    applied_candidate = None
    lock_fd = None
    try:
        toplevel = inspect_git(repo, 'rev-parse', '--show-toplevel', timeout=args.timeout) if repo.is_dir() else None
        if (toplevel is None or toplevel.returncode or not toplevel.stdout.strip()
                or not os.path.samefile(Path(toplevel.stdout.strip()).resolve(), repo)):
            report('BLOCKED_POLICY', 'Original checkout must be the root of a Git worktree')
            return 2
        resolving = getattr(args, 'resolve_journal', None)
        if not resolving and (args.source.startswith('-') or inspect_git(repo, 'check-ref-format', '--branch', args.source,
                                                       timeout=args.timeout).returncode):
            report('BLOCKED_POLICY', 'Source must be a valid local feature branch')
            return 2
        identity = checkout_identity(repo)
        root, common, common_info, root_info = scratch_journal_root(repo, args.timeout)
        lock_fd = acquire_scope_lock(root, identity, args.original_branch)
        if lock_fd is None:
            report('BLOCKED_LOCAL', 'Another integration is active for this checkout and branch')
            return 3
        if resolving:
            try:
                return resolve_journal(args, repo, identity, root, common, common_info, root_info, checks)
            except (IndexInspectionError, OSError, subprocess.TimeoutExpired):
                report('RECOVERY_REQUIRED', 'Resolution could not be verified; inspect retained recovery state',
                       head=observed_head(repo), journal_key=resolving)
                return 3
        # An unresolved attempt takes precedence even if its candidate already
        # advanced original HEAD, source branch moved, or HOME changed.
        key = journal_key(identity, args.original_branch, args.expected_head,
                          args.source, args.expected_source_head)
        phase = 'scan'
        blocking, blocking_record, completed = scan_journals(root, repo, identity,
                                               args.original_branch, key, args.timeout)
        if blocking is not None:
            report('RECOVERY_REQUIRED', 'Unresolved scratch journal requires inspection before new work',
                   journal=str(blocking / 'journal.json'),
                   scratch=(blocking_record.get('scratch') if blocking_record else None),
                   head=observed_head(repo))
            return 3
        phase = 'preflight'
        resolved_attempt = completed.get('_resolved_journal') if completed else None
        if completed is not None and resolved_attempt is None:
            candidate = completed['candidate']
            report('ALREADY_INTEGRATED', 'Completed local delivery remains verified',
                   head=completed['_verified_head'], candidate=candidate,
                   cleanup_pending=completed['cleanup_pending'],
                   journal=completed['_journal'])
            return 0
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
        if resolved_attempt is not None:
            prior = Path(resolved_attempt)
            if read_journal(prior).get('phase') != 'resolved':
                report('RECOVERY_REQUIRED', 'Prior resolution changed before retry')
                return 3
            preserve_resolved_attempt(prior)
        directory, record = reserve_scratch(root, repo, identity, args.original_branch, args.expected_head,
                                            args.source, args.expected_source_head)
        scratch = Path(record['scratch']) if record is not None else directory / 'worktree'
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
                    result = run(scratch, command, timeout=check_timeout(args), discard_output=True)
                except (OSError, subprocess.TimeoutExpired) as error:
                    if getattr(error, 'cleanup_incomplete', False):
                        return scratch_failure(repo, scratch, directory / 'journal.json',
                                               f'Scratch {kind} cleanup incomplete', phase=kind,
                                               merge_aborted=False, original_head=observed_head(repo),
                                               command=command)
                    reason = (f'Scratch {kind} exceeded {check_timeout(args)} seconds'
                              if isinstance(error, subprocess.TimeoutExpired)
                              else f'Scratch {kind} could not start')
                    return scratch_abort(repo, scratch, directory / 'journal.json',
                                         reason, phase=kind, command=command, timeout=check_timeout(args))
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
        ref = candidate_ref(record)
        zeros = '0' * len(candidate)
        pinned = run_git_nohooks(repo, 'update-ref', ref, candidate, zeros, timeout=args.timeout)
        if pinned.returncode:
            return scratch_failure(repo, scratch, directory / 'journal.json',
                                   'Candidate ref could not be pinned', phase='candidate',
                                   candidate=candidate, original_head=args.expected_head)
        record.update({'phase': 'candidate', 'candidate': candidate, 'tree': intended_tree, 'ref': ref})
        write_journal(directory, record)
        phase = 'apply'
        if (not common_state_is_current(repo, identity, common, common_info, root, root_info, args.timeout)
                or not checked_original(repo, args.original_branch, args.expected_head, args.timeout)
                or inspect_git(repo, 'rev-parse', '--verify', f'refs/heads/{args.source}',
                               timeout=args.timeout).stdout.strip() != args.expected_source_head
                or inspect_git(repo, 'rev-parse', ref, timeout=args.timeout).stdout.strip() != candidate
                or not scratch_container_is_current(record)
                or not scratch_identity(scratch, scratch_info)):
            return scratch_failure(repo, scratch, directory / 'journal.json',
                                   'Original or candidate changed before apply', phase='apply',
                                   candidate=candidate, recovery_ref=ref,
                                   original_head=inspect_git(repo, 'rev-parse', 'HEAD', timeout=30).stdout.strip())
        advanced = run_git_discard_nohooks(repo, 'merge', '--ff-only', '--no-overwrite-ignore',
                                           '--no-autostash', candidate, timeout=args.timeout)
        observed = observed_head(repo)
        if advanced.returncode or observed != candidate:
            return scratch_failure(repo, scratch, directory / 'journal.json',
                                   'Protected fast-forward refused or changed state; inspect checkout',
                                   phase='apply', candidate=candidate, recovery_ref=ref,
                                   original_head=observed,
                                   status=('BLOCKED_LOCAL' if observed == args.expected_head
                                           else 'RECOVERY_REQUIRED'))
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
                    result = run(repo, command, timeout=check_timeout(args), discard_output=True)
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
        record['phase'] = 'finalizing'
        write_journal(directory, record)
        cleanup_pending = True
        try:
            if (scratch_identity(scratch, scratch_info)
                    and scratch_is_clean_for_cleanup(scratch, candidate, args.timeout)):
                removed = run_process(['git', '-C', str(repo), 'worktree', 'remove', str(scratch)],
                                      env=git_environment(), timeout=args.timeout, discard_output=True)
                if removed.returncode == 0:
                    deleted = run_git_nohooks(repo, 'update-ref', '-d', ref, candidate,
                                              timeout=args.timeout)
                    cleanup_pending = deleted.returncode != 0
                    if record['schema'] == 2 and scratch_container_is_current(record):
                        Path(record['container']).rmdir()  # Only an empty owned container.
        except (IndexInspectionError, OSError, subprocess.TimeoutExpired):
            cleanup_pending = True  # Keep all uncertain artifacts for inspection.
        if (not common_state_is_current(repo, identity, common, common_info, root, root_info, args.timeout)
                or not checked_original(repo, args.original_branch, candidate, args.timeout)):
            return scratch_failure(repo, scratch, directory / 'journal.json',
                                   'Original checkout changed during cleanup; HEAD advanced',
                                   phase='finalize', candidate=candidate,
                                   original_head=observed_head(repo), status='RECOVERY_REQUIRED')
        record.update({'phase': 'delivered', 'cleanup_pending': cleanup_pending})
        write_journal(directory, record)
        directory = archive_journal(directory)
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
            report('RECOVERY_REQUIRED' if phase == 'scan' else 'BLOCKED_LOCAL',
                   message + '; no merge attempted', head=observed_head(repo))
            return 3
        # The journal reserved before scratch work prevents an automatic
        # second merge after an uncertain timeout or interrupted hook.
        current_head = observed_head(repo)
        candidate = record.get('candidate') if isinstance(record, dict) else None
        uncertain_apply = phase == 'apply' and (not current_head or current_head != args.expected_head)
        return scratch_failure(repo, Path(record['scratch']) if isinstance(record, dict) else directory / 'worktree',
                               directory / 'journal.json',
                               message, phase=phase, merge_aborted=False,
                               original_head=current_head,
                               status=('DELIVERED_CHECK_FAILED' if applied_candidate and phase == 'verify'
                                       else 'RECOVERY_REQUIRED' if applied_candidate or uncertain_apply
                                       else 'BLOCKED_LOCAL'),
                               candidate=candidate)
    finally:
        if lock_fd is not None:
            os.close(lock_fd)


if __name__ == "__main__":
    sys.exit(main())
