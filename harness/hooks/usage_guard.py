#!/usr/bin/env python3
"""Finite, opt-in command receipts and cooperative review budgets.

Receipts describe declared inputs. They are local evidence, not attestations or
global enforcement of native agents, accounts, or commands outside this helper.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import time

from git_safety import git_environment, require_safe_source
from process import run as run_process


SCHEMA = 1
MAX_JSON = 65536
MAX_MANIFEST = 32768
MAX_FILE = 2 * 1024 * 1024
LOCK_SECONDS = 2
# A dead owner is reconciled automatically only after its own timeout plus this grace (seconds).
# AGENT_HARNESS_DEADLINE_GRACE (0..3600) shortens it for live tests; death is still required.
DEADLINE_GRACE = 60
# Attempts that never launched a provider do not spend the two-launch repeat budget, but they are
# bounded (ZERO_LAUNCH_CAP per rolling ZERO_LAUNCH_WINDOW seconds, MAX_ATTEMPTS slots in all) so
# an infrastructure refusal cannot turn into an unbounded retry loop or lock a fingerprint forever.
ZERO_LAUNCH_CAP = 6
ZERO_LAUNCH_WINDOW = 3600
ZERO_LAUNCH_REASONS = {'TRANSIENT_INFRA', 'LOW_DISK', 'QUOTA', 'AUTH'}
MAX_ATTEMPTS = 32
PID_MAX = 2 ** 31 - 1
AUTO_ACTOR = 'usage_guard.auto'
RECONCILIATION_KINDS = {'manual_reconciliation', 'automatic_reconciliation'}
EXECUTIONS = {'NOT_STARTED', 'RUNNING', 'COMPLETED', 'INTERRUPTED', 'UNKNOWN'}
RESULTS = {'CHECK_OK', 'CHECK_FAILED', 'NO_RESULT'}
REASONS = {'NONE', 'CODE_FINDINGS', 'QUOTA', 'AUTH', 'TRANSIENT_INFRA', 'LOW_DISK',
           'TIMEOUT', 'INVALID_OUTPUT', 'INPUT_CHANGED', 'BUDGET_EXHAUSTED', 'ADVISORY', 'UNKNOWN'}
STAGES = {'PLAN', 'CODE_INSPECTION', 'PR'}
ENVIRONMENT_KEYS = {'CI', 'LANG', 'LC_ALL', 'TZ', 'PYTHONHASHSEED', 'NODE_ENV'}
HEX = re.compile(r'[0-9a-f]{64}\Z')
RUN_ID = re.compile(r'[0-9a-f]{32}\Z')
LABEL = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}\Z')
SECRET = re.compile(r'(?:ghp_|github_pat_|sk-ant-)[A-Za-z0-9_-]{16,}|-----BEGIN .*PRIVATE KEY-----|'
                    r'(?i:api[_-]?key|password|access[_-]?token|authorization)\s*[:=]\s*\S+')


class GuardError(Exception):
    def __init__(self, reason, message, reference=None):
        super().__init__(message)
        self.reason, self.message, self.reference = reason, message, reference


class PoolUnavailable(GuardError):
    """acquire_pool refused a provider pool (reserved by an unreleased run, or cooling down). No provider was
    launched. `holder` is the run id that holds the pool and `kind` is 'active' or 'cooldown'."""

    def __init__(self, reason, message, *, holder=None, kind='active', reference=None):
        super().__init__(reason, message, reference)
        self.holder, self.kind = holder, kind


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), allow_nan=False).encode('utf-8')


def digest(value):
    return hashlib.sha256(encoded(value)).hexdigest()


def safe_text(value, *, maximum=512):
    if (not isinstance(value, str) or not 1 <= len(value.strip()) <= maximum
            or any(ord(char) < 32 for char in value) or SECRET.search(value)):
        raise GuardError('INVALID_OUTPUT', 'Metadata must be bounded non-secret text')
    try:
        value.encode('utf-8')
    except UnicodeError:
        raise GuardError('INVALID_OUTPUT', 'Metadata text is not valid UTF-8') from None
    return value


def safe_label(value):
    if not isinstance(value, str) or not LABEL.fullmatch(value) or SECRET.search(value):
        raise GuardError('INVALID_OUTPUT', 'Expected a safe opaque label')
    return value


def finite_seconds(value):
    if type(value) not in (int, float) or not math.isfinite(value) or not 0 < value <= 86400:
        raise GuardError('INVALID_OUTPUT', 'Expected a finite positive time budget')
    return value


def file_bytes(path, limit=MAX_JSON, *, private=True):
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
    fd = os.open(path, flags)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or before.st_size > limit
                or private and (before.st_uid != os.geteuid() or stat.S_IMODE(before.st_mode) != 0o600)):
            raise OSError('Unsafe or oversized evidence file')
        body = bytearray()
        while len(body) <= limit:
            chunk = os.read(fd, min(65536, limit + 1 - len(body)))
            if not chunk:
                break
            body.extend(chunk)
        after = os.fstat(fd)
        named = os.stat(path, follow_symlinks=False)
        signature = lambda info: (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns,
                                  info.st_mode, info.st_nlink, info.st_uid)
        if len(body) > limit or signature(before) != signature(after) or signature(after) != signature(named):
            raise OSError('Evidence changed while reading')
        return bytes(body)
    finally:
        os.close(fd)


def read_json(path, *, limit=MAX_JSON):
    try:
        value = json.loads(file_bytes(path, limit), parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        if not isinstance(value, dict):
            raise ValueError
        return value
    except (OSError, ValueError, UnicodeError):
        raise GuardError('UNKNOWN', 'Evidence is missing, corrupt or unsafe') from None


def load_manifest(value=None):
    if value is None:
        return {'schema': SCHEMA, 'files': [], 'revisions': {}, 'complete': False, 'deterministic': False}
    if isinstance(value, (str, Path)):
        value = read_json(Path(value), limit=MAX_MANIFEST)
    if (not isinstance(value, dict) or value.get('schema') != SCHEMA or type(value.get('schema')) is not int
            or len(encoded(value)) > MAX_MANIFEST
            or set(value) - {'schema', 'files', 'revisions', 'complete', 'deterministic',
                              'public_arguments', 'target', 'unknown_inputs', 'toolchain', 'environment',
                              'command_revision'}):
        raise GuardError('INVALID_OUTPUT', 'Input manifest is unsupported or oversized')
    return json.loads(encoded(value))


def now_utc():
    return datetime.now(timezone.utc)


def deadline_grace():
    raw = os.environ.get('AGENT_HARNESS_DEADLINE_GRACE')
    if raw is None: return DEADLINE_GRACE
    try:
        value = int(raw)
    except ValueError:
        return DEADLINE_GRACE
    return value if 0 <= value <= 3600 else DEADLINE_GRACE


def valid_pid(value):
    return type(value) is int and 1 <= value <= PID_MAX


def pid_exists(pid):
    """True/False when the kernel answers, None when it cannot be asked safely."""
    if not valid_pid(pid): return None
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except (OSError, OverflowError, ValueError):
        return None


def host_identity():
    return socket.gethostname()[:255]


def boot_identity():
    """A boot identifier when the platform offers one cheaply; audit detail only."""
    # Tokens carry their scheme so an id from another build or platform is never compared.
    try:
        value = Path('/proc/sys/kernel/random/boot_id').read_text().strip()[:64]  # input-ok: 37-byte kernel file
        if value: return 'procboot:' + value
    except OSError:
        pass
    try:
        # kern.boottime moves when the wall clock is stepped; the boot session UUID does not.
        probe = subprocess.run(['sysctl', '-n', 'kern.bootsessionuuid'], capture_output=True, text=True, timeout=5)
        if probe.returncode == 0 and probe.stdout.strip():
            return 'bootsession:' + probe.stdout.strip()[:64]
    except (OSError, subprocess.SubprocessError, ValueError):
        pass
    return None


def same_scheme(recorded, current):
    return recorded.split(':', 1)[0] == current.split(':', 1)[0]


def process_start_token(pid):
    """A token naming one incarnation of `pid`, or None when the platform cannot say."""
    try:
        after_comm = Path('/proc/%d/stat' % pid).read_text().rsplit(')', 1)[1].split()  # input-ok: one-line kernel file
        return 'proc:' + after_comm[19]  # field 22, starttime in clock ticks since boot
    except (OSError, IndexError, ValueError):
        pass
    try:
        # Pin the zone and locale: ps prints the start time as local text, which must not vary
        # between the process that recorded the token and the one that checks it.
        probe = subprocess.run(['ps', '-p', str(pid), '-o', 'lstart='], capture_output=True, text=True, timeout=5,
                               env={**os.environ, 'TZ': 'UTC', 'LC_ALL': 'C', 'LANG': 'C'})
        if probe.returncode == 0 and probe.stdout.strip():
            return 'ps:' + ' '.join(probe.stdout.split())[:64]
    except (OSError, subprocess.SubprocessError, ValueError):
        pass
    return None


def group_empty(pid):
    """True when no process remains in the group led by pid (children start as session leaders)."""
    if not valid_pid(pid): return None
    try:
        os.killpg(pid, 0)
        return False
    except ProcessLookupError:
        return True
    except PermissionError:
        return False
    except (OSError, OverflowError, ValueError):
        return None


def incarnation_state(pid, recorded_token, recorded_boot, current_boot, *, whole_group=False):
    """DEAD, ALIVE or UNCERTAIN for one recorded (pid, start token) on this host."""
    if isinstance(recorded_boot, str) and isinstance(current_boot, str):
        if not same_scheme(recorded_boot, current_boot):
            return 'UNCERTAIN', 'boot identity scheme differs'
        if recorded_boot != current_boot:
            return 'DEAD', 'host rebooted since the reservation'
    if isinstance(recorded_boot, str) and current_boot is None:
        return 'UNCERTAIN', 'boot identity unavailable'
    exists = pid_exists(pid)
    if exists is None:
        return 'UNCERTAIN', 'pid probe failed'
    if not exists:
        if whole_group:
            empty = group_empty(pid)
            if empty is None: return 'UNCERTAIN', 'process group probe failed'
            if not empty: return 'UNCERTAIN', 'pid gone but its process group still has members'
        return 'DEAD', 'pid gone'
    current = process_start_token(pid)
    if not isinstance(recorded_token, str) or current is None:
        return 'UNCERTAIN', 'process start time unavailable'
    if not same_scheme(recorded_token, current):
        return 'UNCERTAIN', 'process start token scheme differs'
    if current != recorded_token:
        return 'DEAD', 'pid reused: start time differs'
    return 'ALIVE', 'process alive'


def owner_process_facts(pid=None):
    """Who holds a reservation: enough to prove death on the same host, never to prove success."""
    pid = os.getpid() if pid is None else pid
    return {'pid': pid, 'host': host_identity(), 'boot_id': boot_identity(),
            'process_started': process_start_token(pid)}


def owner_liveness(start, children=()):
    """DEAD only when the owner and every recorded child are provably gone on this host.

    ALIVE when the same incarnation answers; anything else (other host, malformed facts, a probe
    that cannot answer, a live or unknown child) is UNCERTAIN and leaves state untouched.
    """
    owner = start.get('owner_process') if isinstance(start, dict) else None
    facts = {'state': 'UNCERTAIN', 'past_deadline': False, 'why': 'owner facts missing or malformed'}
    if (not isinstance(owner, dict) or not valid_pid(owner.get('pid'))
            or not isinstance(owner.get('host'), str) or not 1 <= len(owner['host']) <= 255
            or not isinstance(owner.get('deadline'), str) or len(owner['deadline']) > 64):
        return facts
    try:
        deadline = datetime.fromisoformat(owner['deadline'])
    except ValueError:
        facts['why'] = 'deadline malformed'
        return facts
    if deadline.tzinfo is None:
        facts['why'] = 'deadline has no time zone'
        return facts
    facts.update(pid=owner['pid'], host=owner['host'], deadline=owner['deadline'],
                 past_deadline=now_utc() > deadline)
    if owner['host'] != host_identity():
        facts['why'] = 'other host'
        return facts
    current_boot = boot_identity()
    state, why = incarnation_state(owner['pid'], owner.get('process_started'), owner.get('boot_id'), current_boot)
    facts.update(state=state, why=why)
    if state != 'DEAD':
        return facts
    for child in children:
        if not isinstance(child, dict) or not valid_pid(child.get('pid')):
            facts.update(state='UNCERTAIN', why='child record malformed')
            return facts
        child_state, child_why = incarnation_state(child['pid'], child.get('process_started'),
                                                   owner.get('boot_id'), current_boot, whole_group=True)
        if child_state != 'DEAD':
            facts.update(state='UNCERTAIN', why='child pid %d %s: %s' % (child['pid'], child_state.lower(), child_why))
            return facts
    return facts


def incomplete_reboot_proven(start):
    """Without terminal launch evidence, only a typed same-host reboot covers unrecorded children."""
    owner = start.get('owner_process') if isinstance(start, dict) else None
    if not isinstance(owner, dict) or owner.get('host') != host_identity():
        return False
    identities = []
    for token in (owner.get('boot_id'), boot_identity()):
        if not isinstance(token, str):
            return False
        match = re.fullmatch(r'(procboot|bootsession):([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-'
                             r'[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})', token)
        if match is None:
            return False
        identities.append((match[1], match[2].lower()))
    return identities[0][0] == identities[1][0] and identities[0][1] != identities[1][1]


class Subject(dict):
    """Serializable metadata, with private in-memory inputs for a final reprobe."""
    def probe(self):
        return capture_subject(self.repo, self.manifest_source)


def runtime_identity(toolchain=None, environment=None):
    """Probe only explicitly declared public executables and non-secret settings."""
    if not isinstance(toolchain or {}, dict) or not isinstance(environment or {}, dict):
        raise GuardError('INVALID_OUTPUT', 'Runtime declarations must be objects')
    tools, settings, unknown = {}, {}, []
    if not toolchain: unknown.append('toolchain')
    for label, specification in (toolchain or {}).items():
        safe_label(label)
        if (not isinstance(specification, dict) or specification.get('public') is not True
                or set(specification) - {'path', 'executable', 'sha256', 'public'}):
            unknown.append('toolchain/' + label); continue
        selected = specification.get('path') or shutil.which(specification.get('executable', ''))
        try:
            path = Path(selected).resolve(strict=True)
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            try:
                before = os.fstat(fd)
                if (not stat.S_ISREG(before.st_mode) or not before.st_mode & 0o111
                        or before.st_size > 256 * 1024**2):
                    raise OSError
                sha = hashlib.sha256()
                consumed = 0
                while True:
                    body = os.read(fd, 65536)
                    if not body: break
                    consumed += len(body)
                    if consumed > 256 * 1024**2: raise OSError
                    sha.update(body)
                after = os.fstat(fd)
                named = path.stat()
                signature = lambda info: (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
                if signature(before) != signature(after) or signature(after) != signature(named): raise OSError
            finally:
                os.close(fd)
            tools[label] = {'resolved_path_digest': digest(str(path)), 'sha256': sha.hexdigest()}
            if specification.get('sha256') != sha.hexdigest(): unknown.append('toolchain/' + label)
        except (OSError, TypeError, ValueError):
            unknown.append('toolchain/' + label)
    for key, expected in (environment or {}).items():
        if key not in ENVIRONMENT_KEYS:
            raise GuardError('INVALID_OUTPUT', 'Environment names must be explicitly allowlisted')
        if expected is not None: safe_text(expected, maximum=128)
        actual = os.environ.get(key)
        if actual is not None: safe_text(actual, maximum=128)
        settings[key] = actual
        if actual != expected: unknown.append('environment/' + key)
    return {'toolchain': tools, 'environment': settings}, unknown


def capture_subject(repo, manifest=None):
    repo = Path(repo).resolve()
    source = manifest
    manifest = load_manifest(manifest)
    environment = git_environment(isolated=True)
    try:
        require_safe_source(repo, environment)
    except (OSError, subprocess.TimeoutExpired):
        raise GuardError('UNKNOWN', 'Subject Git safety could not be verified') from None
    def inspect(*args):
        result = run_process(['git', '-C', str(repo), *args], env=environment, timeout=30)
        if result.returncode:
            raise GuardError('UNKNOWN', 'Subject Git identity could not be verified')
        return result.stdout.strip()
    if Path(inspect('rev-parse', '--show-toplevel')).resolve() != repo:
        raise GuardError('UNKNOWN', 'Subject must be a repository root')
    head, tree = inspect('rev-parse', '--verify', 'HEAD^{commit}'), inspect('rev-parse', 'HEAD^{tree}')
    dirty = bool(inspect('status', '--porcelain=v1', '--untracked-files=all'))
    info = repo.stat()
    files = manifest.get('files', [])
    revisions = manifest.get('revisions', {})
    unknown = list(manifest.get('unknown_inputs', []))
    if not isinstance(files, list) or len(files) > 64 or not isinstance(revisions, dict) or len(revisions) > 64:
        raise GuardError('INVALID_OUTPUT', 'Input declarations exceeded their bounded shape')
    known = {}
    for item in files:
        if not isinstance(item, dict) or set(item) != {'label', 'path', 'public'}:
            raise GuardError('INVALID_OUTPUT', 'File declarations require label, path and public')
        label = safe_label(item['label'])
        if item['public'] is not True:
            unknown.append(label)
            continue
        try:
            body = file_bytes(Path(item['path']), MAX_FILE, private=False)
            if SECRET.search(body.decode('utf-8', 'replace')):
                unknown.append(label)
            else:
                known[label] = hashlib.sha256(body).hexdigest()
        except (OSError, TypeError, ValueError):
            unknown.append(label)
    for name in ('usage_guard.py', 'peer_review.py', 'review_diagnostics.py', 'review_policy.json', 'process.py', 'git_safety.py', 'report_file.py'):
        path = Path(__file__).resolve().with_name(name)
        if path.is_file():
            known['runtime/' + name] = hashlib.sha256(file_bytes(path, MAX_FILE, private=False)).hexdigest()
    for label, value in revisions.items():
        safe_label(label); safe_text(value)
    runtime, runtime_unknown = runtime_identity(manifest.get('toolchain'), manifest.get('environment'))
    unknown.extend(runtime_unknown)
    unknown = sorted({safe_label(value) for value in unknown})
    data = {'schema': SCHEMA, 'repository': digest([str(repo), info.st_dev, info.st_ino]),
            'head': head, 'tree': tree, 'dirty': dirty, 'files': known, 'revisions': revisions,
            'unknown_inputs': unknown, 'complete': manifest.get('complete') is True,
            'deterministic': manifest.get('deterministic') is True, 'runtime': runtime,
            'target': safe_label(manifest.get('target', 'local'))}
    data['reusable'] = data['complete'] and data['deterministic'] and not dirty and not unknown
    data['fingerprint'] = digest(data)
    subject = Subject(data)
    subject.repo, subject.manifest = repo, manifest
    subject.manifest_source = Path(source) if isinstance(source, (str, Path)) else load_manifest(manifest)
    return subject


class Invocation(dict):
    def probe(self):
        return invocation_identity(self.subject, **self.arguments)


def invocation_identity(subject, *, purpose, argv, cwd, stage=None, packet_digest=None,
                        provider=None, model=None, pool=None, toolchain=None, environment=None,
                        reusable=True, execution_executable=None):
    safe_label(purpose)
    if stage is not None and stage not in STAGES:
        raise GuardError('INVALID_OUTPUT', 'Unknown review stage')
    # Callers pass only declared public argv/settings; secrets use an opaque revision instead.
    if (not isinstance(argv, list) or not all(isinstance(value, str) and not SECRET.search(value) for value in argv)
            or len(encoded(argv)) > MAX_MANIFEST):
        raise GuardError('INVALID_OUTPUT', 'Invocation arguments are unsafe or oversized')
    for value in (provider, model, pool):
        if value is not None: safe_label(value)
    runtime, unknown = runtime_identity(toolchain, environment)
    selected = None
    if execution_executable is not None:
        selected_path = shutil.which(execution_executable)
        if selected_path is not None:
            selected = digest(str(Path(selected_path).resolve()))
        if selected is None or not any(tool['resolved_path_digest'] == selected for tool in runtime['toolchain'].values()):
            unknown.append('selected-executable')
    metadata = {'purpose': purpose, 'stage': stage, 'subject': subject['fingerprint'],
                'argv_digest': digest(argv), 'cwd_digest': digest(str(Path(cwd).resolve())),
                'packet_digest': packet_digest, 'provider': provider, 'model': model, 'pool': pool,
                'runtime': runtime,
                'selected_executable': selected,
                'platform': sys.platform, 'target': getattr(subject, 'manifest', {}).get('target', 'local'),
                'reusable': subject['reusable'] and reusable and not unknown}
    if len(encoded(metadata)) > MAX_MANIFEST or SECRET.search(encoded(metadata).decode()):
        raise GuardError('INVALID_OUTPUT', 'Invocation metadata is unsafe or oversized')
    metadata['fingerprint'] = digest(metadata)
    invocation = Invocation(metadata)
    invocation.subject = subject
    invocation.arguments = dict(purpose=purpose, argv=argv, cwd=cwd, stage=stage, packet_digest=packet_digest,
                                provider=provider, model=model, pool=pool, toolchain=toolchain,
                                environment=environment, reusable=reusable, execution_executable=execution_executable)
    return invocation


class UsageStore:
    """Immutable history plus locked, digest-bound current pool indices."""
    def __init__(self, root=None):
        named = Path(root or os.environ.get('AGENT_HARNESS_USAGE_DIR', Path.home() / '.agent-harness' / 'usage'))
        if named.is_symlink():
            raise GuardError('UNKNOWN', 'Usage state cannot be a symlink')
        self.root = named.expanduser().absolute()
        self.root.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        self._directory(self.root)
        self.identity = self._signature(self.root)
        self.namespaces = {}
        established = os.path.lexists(self.root / 'store.json')
        if not established and any(self.root.iterdir()):
            raise GuardError('UNKNOWN', 'Uninitialized nonempty state requires diagnosis')
        if established and read_json(self.root / 'store.json') != {'schema': SCHEMA, 'kind': 'usage_store'}:
            raise GuardError('UNKNOWN', 'Usage store schema is unsupported')
        for name in ('runs', 'purposes', 'pools'):
            self._directory(self.root / name, create=not established)
            self.namespaces[name] = self._signature(self.root / name)
        if not established:
            self._publish(self.root, 'store.json', {'schema': SCHEMA, 'kind': 'usage_store'})

    @staticmethod
    def _signature(path):
        info = os.stat(path, follow_symlinks=False)
        return info.st_dev, info.st_ino

    def _directory(self, path, *, create=True):
        if create:
            try:
                path.mkdir(mode=0o700)
                # Resolve only the parent for the durability fsync: a symlinked parent such as macOS /tmp made the
                # O_NOFOLLOW open raise NotADirectoryError. The leaf itself is never followed; the lstat check
                # below still refuses a symlinked leaf (a symlinked store root is refused earlier, in __init__).
                parent = os.open(os.path.realpath(path.parent), os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try: os.fsync(parent)
                finally: os.close(parent)
            except FileExistsError:
                pass
        info = os.stat(path, follow_symlinks=False)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise GuardError('UNKNOWN', 'Usage directory ownership or permissions are unsafe')
        return path

    def _current(self):
        try:
            self._directory(self.root, create=False)
            if self._signature(self.root) != self.identity:
                raise GuardError('UNKNOWN', 'Usage directory identity changed')
            for name, identity in getattr(self, 'namespaces', {}).items():
                self._directory(self.root / name, create=False)
                if self._signature(self.root / name) != identity:
                    raise GuardError('UNKNOWN', 'Usage namespace identity changed')
        except OSError:
            raise GuardError('UNKNOWN', 'Usage namespace is missing or unsafe') from None

    @contextmanager
    def _lock(self):
        self._current()
        fd = os.open(self.root / '.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1
                    or stat.S_IMODE(info.st_mode) != 0o600):
                raise GuardError('UNKNOWN', 'Usage lock is unsafe')
            deadline = time.monotonic() + LOCK_SECONDS
            while True:
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    if time.monotonic() >= deadline:
                        raise GuardError('TRANSIENT_INFRA', 'Metadata lock is busy; no command was launched') from None
                    time.sleep(min(.02, max(0, deadline - time.monotonic())))
            self._current()
            if self._signature(self.root / '.lock') != (info.st_dev, info.st_ino):
                raise GuardError('UNKNOWN', 'Usage lock changed')
            yield
        finally:
            os.close(fd)

    def _publish(self, directory, name, value, *, replace=False):
        self._current(); self._directory(directory)
        body = encoded(value)
        if len(body) > MAX_JSON:
            raise GuardError('INVALID_OUTPUT', 'Receipt metadata is oversized')
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        directory_identity = (os.fstat(fd).st_dev, os.fstat(fd).st_ino)
        temporary = '.stage-' + secrets.token_hex(16)
        prior = None
        if replace and os.path.lexists(directory / name):
            previous = file_bytes(directory / name)
            info = os.stat(directory / name, follow_symlinks=False)
            prior = ((info.st_dev, info.st_ino, info.st_mtime_ns, info.st_ctime_ns), previous)
        try:
            target = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
            with os.fdopen(target, 'wb') as output:
                output.write(body); output.flush(); os.fsync(output.fileno())
                written = os.fstat(output.fileno())
            if self._signature(directory) != directory_identity:
                raise GuardError('UNKNOWN', 'Receipt directory changed')
            if replace and prior is not None:
                info = os.stat(directory / name, follow_symlinks=False)
                if ((info.st_dev, info.st_ino, info.st_mtime_ns, info.st_ctime_ns) != prior[0]
                        or file_bytes(directory / name) != prior[1]):
                    raise GuardError('UNKNOWN', 'Current state index changed')
                os.replace(temporary, name, src_dir_fd=fd, dst_dir_fd=fd)
            else:
                os.link(temporary, name, src_dir_fd=fd, dst_dir_fd=fd, follow_symlinks=False)
            os.fsync(fd)
        finally:
            try: os.unlink(temporary, dir_fd=fd)
            except FileNotFoundError: pass
            os.close(fd)
        self._current()
        if self._signature(directory) != directory_identity:
            raise GuardError('UNKNOWN', 'Receipt directory changed during publication')
        visible = os.stat(directory / name, follow_symlinks=False)
        if (visible.st_dev, visible.st_ino) != (written.st_dev, written.st_ino):
            raise GuardError('UNKNOWN', 'Published receipt identity changed')
        actual = file_bytes(directory / name)
        if actual != body:
            raise GuardError('UNKNOWN', 'Receipt changed during publication')
        return hashlib.sha256(body).hexdigest()

    def _run_directory(self, run_id):
        if not isinstance(run_id, str) or not RUN_ID.fullmatch(run_id):
            raise GuardError('INVALID_OUTPUT', 'Invalid run identifier')
        return self.root / 'runs' / run_id

    def load_ref(self, reference):
        if (not isinstance(reference, dict) or set(reference) != {'run_id', 'record', 'sha256'}
                or reference['record'] not in {'start', 'final'}
                or not isinstance(reference.get('sha256'), str) or not HEX.fullmatch(reference['sha256'])):
            raise GuardError('UNKNOWN', 'Invalid receipt reference')
        self._current()
        directory = self._run_directory(reference['run_id'])
        path = directory / (reference['record'] + '.json')
        try:
            self._directory(directory, create=False)
            body = file_bytes(path)
            value = json.loads(body)
        except (OSError, ValueError, UnicodeError):
            raise GuardError('UNKNOWN', 'Referenced evidence is missing or unsafe') from None
        if (hashlib.sha256(body).hexdigest() != reference['sha256'] or not isinstance(value, dict)
                or type(value.get('schema')) is not int or value['schema'] != SCHEMA
                or value.get('kind') != reference['record'] or value.get('run_id') != reference['run_id']):
            raise GuardError('UNKNOWN', 'Evidence digest or schema does not match')
        if reference['record'] == 'final' and (
                not isinstance(value.get('execution'), str) or value['execution'] not in EXECUTIONS
                or not isinstance(value.get('result'), str) or value['result'] not in RESULTS
                or not isinstance(value.get('reason'), str) or value['reason'] not in REASONS
                or value.get('evidence') != 'EXECUTED' or not isinstance(value.get('subject'), dict)
                or not isinstance(value.get('invocation'), dict)):
            raise GuardError('UNKNOWN', 'Final evidence result schema is invalid')
        return value

    def inspect(self, reference):
        record = self.load_ref(reference)
        if reference['record'] == 'start':
            return {'execution': 'UNKNOWN', 'result': 'NO_RESULT', 'reference': reference,
                    'historical_start': record,
                    'note': 'START records intent; inspect a separately referenced FINAL to establish completion'}
        if record.get('review') is not None:
            return {**record, 'review_finalization': self._review_finalization(reference)}
        return record

    def _review_finalization(self, reference):
        directory = self._run_directory(reference['run_id'])
        for name, kind, state in (('invalidated.json', 'review_invalidation', 'INVALIDATED'),
                                  ('settled.json', 'review_settlement', 'SETTLED')):
            if not os.path.lexists(directory / name): continue
            value = read_json(directory / name)
            expected = {'schema', 'kind', 'reference', 'at'} | ({'reason'} if state == 'INVALIDATED' else set())
            if (set(value) != expected or type(value.get('schema')) is not int or value['schema'] != SCHEMA
                    or value.get('kind') != kind or value.get('reference') != reference):
                raise GuardError('UNKNOWN', 'Review finalization evidence is malformed', reference)
            return state
        return 'PENDING'

    def settle_review(self, reference):
        """Publish review eligibility only after the caller's final invariants pass."""
        with self._lock():
            record = self.load_ref(reference)
            if reference['record'] != 'final' or record.get('review') is None or record['execution'] != 'COMPLETED':
                raise GuardError('UNKNOWN', 'Only a completed typed review can be settled', reference)
            state = self._review_finalization(reference)
            if state == 'INVALIDATED':
                raise GuardError('UNKNOWN', 'An invalidated review cannot be settled', reference)
            if state == 'PENDING':
                self._publish(self._run_directory(reference['run_id']), 'settled.json',
                              {'schema': SCHEMA, 'kind': 'review_settlement', 'reference': reference,
                               'at': datetime.now(timezone.utc).isoformat()})
        return reference

    def invalidate_review(self, reference, *, reason):
        """Retain FINAL history while permanently revoking its gate/reuse eligibility."""
        safe_text(reason)
        with self._lock():
            self.load_ref(reference)
            if self._review_finalization(reference) != 'INVALIDATED':
                self._publish(self._run_directory(reference['run_id']), 'invalidated.json',
                              {'schema': SCHEMA, 'kind': 'review_invalidation', 'reference': reference,
                               'reason': reason, 'at': datetime.now(timezone.utc).isoformat()})
        return reference

    def check_gate(self, subject, reference):
        record = self.load_ref(reference)
        review = record.get('review') or {}
        if record.get('review') is not None and self._review_finalization(reference) != 'SETTLED':
            raise GuardError('UNKNOWN', 'Review FINAL is provisional or invalidated', reference)
        if (not subject['reusable'] or record.get('subject', {}).get('fingerprint') != subject['fingerprint']
                or record.get('execution') != 'COMPLETED' or record.get('result') != 'CHECK_OK'
                or record.get('reason') != 'NONE' or review.get('stage') != 'CODE_INSPECTION'
                or review.get('verdict') != 'ACCEPT' or review.get('findings') != []):
            raise GuardError('INPUT_CHANGED', 'Full validation needs current accepted code-inspection evidence', reference)
        return record

    def reuse(self, subject, invocation, reference):
        record = self.load_ref(reference)
        eligible = (subject['reusable'] and invocation['reusable']
                    and record.get('invocation', {}).get('fingerprint') == invocation['fingerprint']
                    and record.get('execution') == 'COMPLETED' and record.get('result') == 'CHECK_OK'
                    and record.get('reason') == 'NONE')
        if record.get('review') is not None:
            eligible = eligible and self._review_finalization(reference) == 'SETTLED'
        return {'evidence': 'REUSED', 'eligible': bool(eligible), 'reference': reference,
                'original_timestamp': record.get('ended_at'), 'original_result': record.get('result'),
                'scope': record.get('subject'), 'note': 'Historical evidence; no new check result or PR signoff'}

    def _attempt_start(self, entry):
        if (set(entry) != {'schema', 'run_id', 'start', 'timeout', 'aggregate_timeout'}
                or type(entry.get('schema')) is not int or entry['schema'] != SCHEMA):
            raise GuardError('UNKNOWN', 'Attempt history is malformed')
        reference = entry['start']
        started = self.load_ref(reference)
        if (reference['record'] != 'start' or entry['run_id'] != started['run_id']
                or entry['timeout'] != started.get('timeout')
                or entry['aggregate_timeout'] != started.get('aggregate_timeout')
                or not isinstance(started.get('subject'), dict)
                or not isinstance(started.get('invocation'), dict)):
            raise GuardError('UNKNOWN', 'Attempt index does not match its referenced START')
        finite_seconds(started['timeout']); finite_seconds(started['aggregate_timeout'])
        return started

    def _owned_start(self, run_id):
        directory = self._run_directory(run_id)
        raw = read_json(directory / 'start.json')
        identity = raw.get('invocation', {}).get('fingerprint') if isinstance(raw.get('invocation'), dict) else None
        if not isinstance(identity, str) or not HEX.fullmatch(identity):
            raise GuardError('UNKNOWN', 'Run START has no bounded invocation identity')
        purpose = self.root / 'purposes' / identity
        self._directory(purpose, create=False)
        matches = []
        for number in range(1, MAX_ATTEMPTS + 1):
            path = purpose / ('attempt-' + str(number) + '.json')
            if os.path.lexists(path):
                entry = read_json(path)
                if entry.get('run_id') == run_id: matches.append(self._attempt_start(entry))
        if len(matches) != 1 or matches[0] != raw:
            raise GuardError('UNKNOWN', 'Run START is not bound to exactly one attempt')
        return matches[0]

    def _reconciliation(self, directory, run_id):
        path = directory / 'reconciled.json'
        if not os.path.lexists(path): return False
        value = read_json(path)
        if (set(value) != {'schema', 'kind', 'run_id', 'actor', 'reason', 'evidence', 'at', 'execution', 'result'}
                or type(value.get('schema')) is not int or value['schema'] != SCHEMA
                or value.get('kind') not in RECONCILIATION_KINDS or value.get('run_id') != run_id
                or value.get('execution') != 'UNKNOWN' or value.get('result') != 'NO_RESULT'):
            raise GuardError('UNKNOWN', 'Manual reconciliation is malformed or belongs to another run')
        for field in ('actor', 'reason', 'evidence', 'at'): safe_text(value[field])
        if value['kind'] == 'automatic_reconciliation' and value['actor'] != AUTO_ACTOR:
            raise GuardError('UNKNOWN', 'Automatic reconciliation has an unexpected actor')
        return True

    def begin(self, subject, invocation, *, owner, label, timeout, kind='review', repeat_reason=None,
              gate=None, ungated_reason=None, minimum_bytes=None, aggregate_timeout=None):
        safe_label(owner); safe_label(label); finite_seconds(timeout)
        if kind not in {'review', 'focused', 'full', 'command'}:
            raise GuardError('INVALID_OUTPUT', 'Unsupported guarded command kind')
        if repeat_reason is not None: safe_text(repeat_reason)
        if ungated_reason is not None: safe_text(ungated_reason)
        aggregate_timeout = finite_seconds(timeout * 2 if aggregate_timeout is None else aggregate_timeout)
        if kind == 'full' and gate is None and not ungated_reason:
            raise GuardError('INPUT_CHANGED', 'Full validation needs a gate or explicit investigation/native reason')
        if kind == 'full' and gate is not None and not invocation['reusable']:
            raise GuardError('INPUT_CHANGED', 'Full gate requires verified declared execution inputs')
        if gate is not None: self.check_gate(subject, gate)
        repo = getattr(subject, 'repo', None)
        if repo and (self.root == repo or repo in self.root.parents):
            raise GuardError('UNKNOWN', 'Usage records must be outside the worktree')
        minimum = minimum_bytes if minimum_bytes is not None else (2 * 1024**3 if kind in {'focused', 'full'} else 256 * 1024**2)
        if type(minimum) is not int or minimum < 0:
            raise GuardError('INVALID_OUTPUT', 'Resource threshold must be a nonnegative integer')
        resources, resource_reason = [], 'NONE'
        for path in {str(self.root), tempfile.gettempdir(), str(repo or Path.cwd())}:
            try:
                free = shutil.disk_usage(path).free
                resources.append({'filesystem': digest(path), 'free_bytes': free, 'minimum_bytes': minimum})
                if free < minimum: resource_reason = 'LOW_DISK'
            except OSError:
                resource_reason = 'UNKNOWN'
        with self._lock():
            purpose = self._directory(self.root / 'purposes' / invocation['fingerprint'])
            previous, counted, zero_launch, spent = [], [], [], 0
            for number in range(1, MAX_ATTEMPTS + 1):
                path = purpose / ('attempt-' + str(number) + '.json')
                if not os.path.lexists(path): break
                entry = read_json(path)
                started = self._attempt_start(entry)
                if (started['subject'] != dict(subject) or started['invocation'] != dict(invocation)
                        or started.get('command_kind') != kind):
                    raise GuardError('UNKNOWN', 'Prior START belongs to different execution inputs')
                original_budget = started['aggregate_timeout']
                if aggregate_timeout > original_budget:
                    raise GuardError('BUDGET_EXHAUSTED', 'A repeat cannot enlarge its original aggregate budget')
                previous.append(entry)
                directory = self._run_directory(entry['run_id'])
                reconciled = self._reconciliation(directory, entry['run_id'])
                completion = directory / 'completion.json'
                if not os.path.lexists(completion):
                    if not reconciled:
                        reconciled = self._auto_reconcile_locked(entry['run_id'])['reconciled']
                    if not reconciled:
                        raise GuardError('UNKNOWN', 'Prior reservation has no final receipt; reconcile before retry', entry['start'])
                    # Launches are unknown for a run without a final, so it counts as a launch.
                    spent += started['timeout']; counted.append(entry)
                else:
                    completed = read_json(completion)
                    if set(completed) != {'schema', 'reference'} or completed.get('schema') != SCHEMA:
                        raise GuardError('UNKNOWN', 'Completion reference is malformed')
                    record = self.load_ref(completed['reference'])
                    if (completed['reference']['record'] != 'final' or record['run_id'] != started['run_id']
                            or record['subject'] != started['subject'] or record['invocation'] != started['invocation']
                            or record.get('started_at') != started.get('started_at')):
                        raise GuardError('UNKNOWN', 'Completion does not match its referenced START')
                    if record.get('reason') in {'UNKNOWN', 'TIMEOUT'} and not reconciled:
                        reconciled = self._auto_reconcile_locked(entry['run_id'])['reconciled']
                        if not reconciled:
                            raise GuardError('UNKNOWN', 'Uncertain prior result requires recorded reconciliation', entry['start'])
                    elapsed = record.get('elapsed_seconds')
                    if type(elapsed) not in (int, float) or not math.isfinite(elapsed) or elapsed < 0:
                        raise GuardError('UNKNOWN', 'Elapsed execution budget is invalid')
                    spent += elapsed
                    if zero_launch_attempt(record):
                        zero_launch.append((entry, started.get('started_at')))
                    else:
                        counted.append(entry)
            if counted and (repeat_reason is None or len(counted) >= 2):
                raise GuardError('BUDGET_EXHAUSTED', 'Identical invocation already reserved; use evidence or one justified repeat', counted[-1]['start'])
            recent = [entry for entry, at in zero_launch if within_window(at, ZERO_LAUNCH_WINDOW)]
            if len(recent) >= ZERO_LAUNCH_CAP:
                raise GuardError('BUDGET_EXHAUSTED', 'Repeated infrastructure refusals before any provider launch '
                                 '(%d in %d s); fix the infrastructure or wait for the window, do not change the packet'
                                 % (len(recent), ZERO_LAUNCH_WINDOW), recent[-1]['start'])
            if len(previous) >= MAX_ATTEMPTS:
                raise GuardError('BUDGET_EXHAUSTED', 'Attempt slots for this invocation are exhausted', previous[-1]['start'])
            remaining = aggregate_timeout - spent
            if remaining <= 0:
                raise GuardError('BUDGET_EXHAUSTED', 'Declared aggregate execution budget is exhausted')
            run_id = secrets.token_hex(16)
            directory = self._directory(self._run_directory(run_id))
            started_at = now_utc()
            owner_process = owner_process_facts()
            if owner_process is not None:
                owner_process = {**owner_process, 'deadline': (started_at + timedelta(
                    seconds=min(timeout, remaining) + deadline_grace())).isoformat()}
            started = {'schema': SCHEMA, 'kind': 'start', 'run_id': run_id, 'owner': owner, 'label': label,
                       'subject': dict(subject), 'invocation': invocation, 'command_kind': kind,
                       'timeout': min(timeout, remaining), 'aggregate_timeout': aggregate_timeout,
                       'started_at': started_at.isoformat(), 'resources': resources,
                       'repeat_reason': repeat_reason, 'gate': gate,
                       'ungated_reason': ungated_reason, 'execution': 'RUNNING',
                       'owner_process': owner_process}
            reference = {'run_id': run_id, 'record': 'start', 'sha256': hashlib.sha256(encoded(started)).hexdigest()}
            self._publish(purpose, 'attempt-' + str(len(previous) + 1) + '.json',
                          {'schema': SCHEMA, 'run_id': run_id, 'start': reference,
                           'timeout': min(timeout, remaining), 'aggregate_timeout': aggregate_timeout})
            self._publish(directory, 'start.json', started)
        run = Run(self, subject, started, reference)
        if resource_reason != 'NONE':
            final = run.finish(execution='NOT_STARTED', result='NO_RESULT', reason=resource_reason,
                               usage={'provider_launches': 0, 'reported': []})
            raise GuardError(resource_reason, 'Resource preflight prevented command launch', final)
        return run

    def _pool(self, provider, pool):
        safe_label(provider); safe_label(pool)
        directory = self.root / 'pools' / digest([provider, pool])
        new = not os.path.lexists(directory)
        self._directory(directory, create=new)
        self._directory(directory / 'events', create=new)
        index = directory / 'head.json'
        if not os.path.lexists(index):
            if any((directory / 'events').iterdir()):
                raise GuardError('UNKNOWN', 'Pool history has no current index; reconcile before use')
            return directory, {'provider': provider, 'pool': pool, 'active': None,
                               'cooldown': False, 'reason': 'NONE', 'reset_at': None}
        state = self._read_pool_state(directory)
        if state['provider'] != provider or state['pool'] != pool:
            raise GuardError('UNKNOWN', 'Pool reference belongs to another provider or alias')
        return directory, state

    def _read_pool_state(self, directory):
        """The single trusted current-history reader, including operator recovery."""
        self._directory(directory, create=False)
        self._directory(directory / 'events', create=False)
        ref = read_json(directory / 'head.json')
        if (set(ref) != {'event', 'sha256'} or not isinstance(ref.get('event'), str)
                or not RUN_ID.fullmatch(ref['event']) or not isinstance(ref.get('sha256'), str)
                or not HEX.fullmatch(ref['sha256'])):
            raise GuardError('UNKNOWN', 'Pool index is corrupt')
        body = file_bytes(directory / 'events' / (ref['event'] + '.json'))
        value = json.loads(body)
        if (hashlib.sha256(body).hexdigest() != ref['sha256'] or not isinstance(value, dict) or value.get('schema') != SCHEMA
                or type(value.get('schema')) is not int or not isinstance(value.get('state'), dict)):
            raise GuardError('UNKNOWN', 'Pool history digest is invalid')
        state = value['state']
        if (set(state) != {'provider', 'pool', 'active', 'cooldown', 'reason', 'reset_at'}
                or type(state['cooldown']) is not bool or not isinstance(state['reason'], str)
                or state['reason'] not in REASONS
                or state['active'] is not None and (not isinstance(state['active'], str) or not RUN_ID.fullmatch(state['active']))
                or state['reset_at'] is not None and (type(state['reset_at']) not in (int, float)
                    or not math.isfinite(state['reset_at']))):
            raise GuardError('UNKNOWN', 'Pool state is malformed')
        safe_label(state['provider']); safe_label(state['pool'])
        if directory.name != digest([state['provider'], state['pool']]):
            raise GuardError('UNKNOWN', 'Pool directory does not match its referenced identity')
        return state

    def _pool_event(self, directory, state, action, **facts):
        event = secrets.token_hex(16)
        value = {'schema': SCHEMA, 'action': action, 'at': datetime.now(timezone.utc).isoformat(),
                 'state': state, **facts}
        sha = self._publish(directory / 'events', event + '.json', value)
        self._publish(directory, 'head.json', {'event': event, 'sha256': sha}, replace=True)

    def _require_open(self, run_id):
        """A run that finished or was reconciled as dead may not launch providers or record children."""
        directory = self._run_directory(run_id)
        if os.path.lexists(directory / 'completion.json'):
            raise GuardError('UNKNOWN', 'Run already finished; it cannot acquire a pool or record a child')
        if self._reconciliation(directory, run_id):
            raise GuardError('UNKNOWN', 'Run was reconciled as dead; it cannot acquire a pool or record a child')

    def acquire_pool(self, provider, pool, run_id):
        with self._lock():
            self._owned_start(run_id)
            self._require_open(run_id)
            directory, state = self._pool(provider, pool)
            if state['active'] is not None and self._auto_reconcile_locked(state['active'])['reconciled']:
                directory, state = self._pool(provider, pool)
            if state['active'] is not None:
                raise PoolUnavailable('UNKNOWN' if state['reason'] in {'UNKNOWN', 'TIMEOUT'} else 'TRANSIENT_INFRA',
                                      'Provider pool has an active or unreconciled owner; no provider was launched',
                                      holder=state['active'], kind='active')
            if state['cooldown'] and (state['reset_at'] is None or time.time() < state['reset_at']):
                raise PoolUnavailable(state['reason'], 'Provider pool requires availability evidence or its reliable reset',
                                      kind='cooldown')
            state = {**state, 'active': run_id, 'cooldown': False, 'reason': 'NONE', 'reset_at': None}
            self._pool_event(directory, state, 'RESERVED')

    def release_pool(self, provider, pool, run_id, *, reason='NONE', account_cooldown=False, reset_at=None):
        if reason not in REASONS:
            raise GuardError('INVALID_OUTPUT', 'Unknown provider result reason')
        if reset_at is not None and (type(reset_at) not in (int, float) or not math.isfinite(reset_at) or reset_at <= time.time()):
            reset_at = None
        with self._lock():
            directory, state = self._pool(provider, pool)
            if state['active'] != run_id:
                raise GuardError('UNKNOWN', 'Provider pool ownership changed')
            cooldown = account_cooldown is True and reason in {'QUOTA', 'AUTH'}
            uncertain = reason in {'TIMEOUT', 'UNKNOWN'}
            state = {**state, 'active': run_id if uncertain else None, 'cooldown': cooldown,
                     'reason': reason if cooldown or uncertain else 'NONE', 'reset_at': reset_at if cooldown else None}
            self._pool_event(directory, state, 'FINISHED')

    def _affected_pools(self, run_id):
        # Validate every referenced current pool before publishing any
        # marker or deriving a replacement index from its state.
        affected = []
        for number, pool in enumerate((self.root / 'pools').iterdir()):
            if number >= 4096: raise GuardError('UNKNOWN', 'Pool reconciliation scan exceeded limit')
            state = self._read_pool_state(pool)
            if state['active'] == run_id: affected.append((pool, state))
        return affected

    def _publish_reconciliation(self, run_id, *, kind, actor, reason, evidence):
        directory = self._run_directory(run_id)
        affected = self._affected_pools(run_id)
        if self._reconciliation(directory, run_id):
            # A crash can leave the immutable marker ahead of one or more pool heads.
            # Resume only the remaining exact pointers, retaining the original authority/evidence.
            prior = read_json(directory / 'reconciled.json')
            actor, reason, evidence = prior['actor'], prior['reason'], prior['evidence']
        else:
            self._publish(directory, 'reconciled.json', {'schema': SCHEMA, 'kind': kind,
                          'run_id': run_id, 'actor': actor, 'reason': reason, 'evidence': evidence,
                          'at': now_utc().isoformat(), 'execution': 'UNKNOWN', 'result': 'NO_RESULT'})
        for pool, state in affected:
            self._pool_event(pool, {**state, 'active': None}, 'RECONCILED', actor=actor,
                             reason=reason, evidence=evidence)
        return len(affected)

    def _completion_final(self, directory, run_id, start):
        """Validate a completion through its indexed START and digest-bound FINAL before using it."""
        value = read_json(directory / 'completion.json')
        if (set(value) != {'schema', 'reference'} or type(value.get('schema')) is not int
                or value['schema'] != SCHEMA or not isinstance(value.get('reference'), dict)
                or value['reference'].get('run_id') != run_id or value['reference'].get('record') != 'final'):
            raise GuardError('UNKNOWN', 'Completion is malformed or belongs to another run')
        final = self.load_ref(value['reference'])
        if (final['subject'] != start['subject'] or final['invocation'] != start['invocation']
                or final.get('started_at') != start.get('started_at')):
            raise GuardError('UNKNOWN', 'Completion FINAL identity does not match its indexed START')
        return final

    def _completed_children_proven(self, start, final, children):
        """A completed uncertain run needs complete launch records, or independent reboot proof."""
        owner = start.get('owner_process') or {}
        recorded_boot, current_boot = owner.get('boot_id'), boot_identity()
        if (owner.get('host') == host_identity() and isinstance(recorded_boot, str)
                and isinstance(current_boot, str) and 0 < len(recorded_boot) <= 256
                and 0 < len(current_boot) <= 256 and same_scheme(recorded_boot, current_boot)
                and recorded_boot != current_boot):
            return True  # all prior-boot children are gone, including any unrecorded spawn
        usage = final.get('usage')
        launches = usage.get('provider_launches') if isinstance(usage, dict) else None
        if type(launches) is not int or not 0 <= launches <= 64 or len(children) != launches:
            return False
        if launches == 0:
            return final['execution'] == 'NOT_STARTED'
        identities = set()
        for child in children:
            if (not isinstance(child, dict) or set(child) != {'pid', 'process_started'}
                    or not valid_pid(child.get('pid')) or not isinstance(child.get('process_started'), str)
                    or not 0 < len(child['process_started']) <= 256):
                return False
            identities.add((child['pid'], child['process_started']))
        return len(identities) == launches

    def reconcile(self, run_id, *, actor, reason, evidence):
        for value in (actor, reason, evidence): safe_text(value)
        with self._lock():
            self._owned_start(run_id)
            self._publish_reconciliation(run_id, kind='manual_reconciliation', actor=actor,
                                         reason=reason, evidence=evidence)

    def _repair_interrupted_publish(self, directory):
        """A supervisor killed between link and unlink in _publish leaves a .stage-* twin, so the named
        record has two links and file_bytes refuses it forever. Under the lock, in our private run
        directory, drop such stage files; a dangling stage file is garbage from the same interruption."""
        try:
            entries = list(directory.iterdir())
        except OSError:
            return 0
        named = {}
        for entry in entries:
            if entry.name.startswith('.stage-'): continue
            try:
                info = os.stat(entry, follow_symlinks=False)
            except OSError:
                continue
            named[(info.st_dev, info.st_ino)] = entry.name
        removed = 0
        for entry in entries:
            if not entry.name.startswith('.stage-'): continue
            try:
                info = os.stat(entry, follow_symlinks=False)
                if not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid(): continue
                os.unlink(entry)
                removed += 1
            except OSError:
                continue
        return removed

    def _auto_reconcile_locked(self, run_id):
        """Reconcile one reservation only when its owner is provably dead on this host past its deadline.

        Never writes a FINAL or completion: the run stays UNKNOWN / NO_RESULT, exactly like a manual
        reconciliation, with the liveness facts as evidence. Cross-host owners stay uncertain.
        """
        directory = self._run_directory(run_id)
        report = {'run_id': run_id, 'reconciled': False, 'why': '', 'liveness': None}
        if not os.path.lexists(directory / 'start.json'):
            report['why'] = 'no start record'
            return report
        repaired = self._repair_interrupted_publish(directory)
        if repaired: report['repaired_stage_files'] = repaired
        start = self._owned_start(run_id)
        final = (self._completion_final(directory, run_id, start)
                 if os.path.lexists(directory / 'completion.json') else None)
        if self._reconciliation(directory, run_id):
            count = self._publish_reconciliation(run_id, kind='automatic_reconciliation', actor=AUTO_ACTOR,
                                                reason='Resume reconciliation', evidence='Existing immutable reconciliation')
            report.update(reconciled=bool(count), pools=count,
                          why='resumed reconciliation' if count else 'already reconciled')
            return report
        if final is not None:
            if (final['result'] != 'NO_RESULT' or final['reason'] not in {'TIMEOUT', 'UNKNOWN'}
                    or final['execution'] not in {'INTERRUPTED', 'UNKNOWN', 'COMPLETED', 'NOT_STARTED'}
                    or not self._affected_pools(run_id)):
                report['why'] = 'completed'
                return report
        children = self._children(directory)
        liveness = owner_liveness(start, children)
        report['liveness'] = liveness
        if liveness['state'] != 'DEAD':
            report['why'] = 'owner ' + liveness['state'].lower() + ': ' + liveness['why']
            return report
        if not liveness['past_deadline']:
            report['why'] = 'dead owner before deadline'
            return report
        if final is None and not incomplete_reboot_proven(start):
            report['why'] = 'incomplete launch/child evidence requires independent same-host reboot proof'
            return report
        if final is not None and not self._completed_children_proven(start, final, children):
            report['why'] = 'completed uncertain launch/child evidence is incomplete'
            return report
        evidence = ('pid %d on host %s: %s; deadline %s; checked %s' % (
            liveness['pid'], liveness['host'], liveness['why'], liveness['deadline'], now_utc().isoformat()))[:500]
        reason = 'Owner process provably dead on this host past its deadline'
        report['pools'] = self._publish_reconciliation(run_id, kind='automatic_reconciliation', actor=AUTO_ACTOR,
                                                       reason=reason, evidence=evidence)
        report.update(reconciled=True, why='owner dead past deadline')
        return report

    def auto_reconcile(self, run_id):
        with self._lock():
            return self._auto_reconcile_locked(run_id)

    def _children(self, directory):
        path = directory / 'children.json'
        if not os.path.lexists(path): return ()
        value = read_json(path)
        if (set(value) != {'schema', 'run_id', 'children'} or value.get('schema') != SCHEMA
                or value.get('run_id') != directory.name or not isinstance(value['children'], list)
                or len(value['children']) > 64):
            raise GuardError('UNKNOWN', 'Child process record is malformed')
        return tuple(value['children'])

    def record_child(self, run_id, pid):
        """Append the child a live supervisor just spawned, so death means the whole tree is gone."""
        if not valid_pid(pid): raise GuardError('INVALID_OUTPUT', 'Invalid child pid')
        with self._lock():
            directory = self._run_directory(run_id)
            self._owned_start(run_id)
            self._require_open(run_id)
            children = list(self._children(directory))
            if len(children) >= 64: raise GuardError('INVALID_OUTPUT', 'Too many recorded children')
            children.append({'pid': pid, 'process_started': process_start_token(pid)})
            self._publish(directory, 'children.json', {'schema': SCHEMA, 'run_id': run_id, 'children': children},
                          replace=True)

    def sweep(self):
        """Apply the automatic rule to every run; the report names each run and why it was or was not reconciled."""
        reports = []
        with self._lock():
            for number, directory in enumerate(sorted((self.root / 'runs').iterdir())):
                if number >= 65536: raise GuardError('UNKNOWN', 'Run sweep exceeded limit')
                try:
                    reports.append(self._auto_reconcile_locked(directory.name))
                except GuardError as error:
                    reports.append({'run_id': directory.name, 'reconciled': False,
                                    'why': 'error: ' + error.message, 'liveness': None})
                except (OSError, ValueError, TypeError, UnicodeError) as error:
                    reports.append({'run_id': directory.name, 'reconciled': False,
                                    'why': 'error: ' + type(error).__name__, 'liveness': None})
        return reports

    def ack_pool(self, provider, pool, *, actor, reason, evidence):
        for value in (actor, reason, evidence): safe_text(value)
        with self._lock():
            directory, state = self._pool(provider, pool)
            if state['active'] is not None:
                raise GuardError('UNKNOWN', 'Reconcile the active owner before acknowledging availability')
            self._pool_event(directory, {**state, 'cooldown': False, 'reason': 'NONE', 'reset_at': None},
                             'AVAILABILITY_ACK', actor=actor, reason=reason, evidence=evidence)


TICKETED_CATEGORIES = {'correctness', 'reliability', 'performance', 'maintainability', 'testing', 'documentation', 'ux'}
REVIEW_METADATA_KEYS = {'stage', 'verdict', 'findings', 'report_sha256', 'head', 'repo', 'pr', 'ticketed',
                        'reviewer', 'reviewer_harness', 'author_harness'}
REVIEWER_IDENTITY_KEYS = {'reviewer', 'reviewer_harness', 'author_harness'}
TICKETED_RECORD_KEYS = {'state', 'finding', 'category', 'ticket', 'head', 'report_sha256'}


def validate_review_metadata(review, *, result):
    """Validate optional PR identity and ticketed records without changing legacy receipts."""
    if (not isinstance(review, dict) or set(review) - REVIEW_METADATA_KEYS
            or not {'stage', 'verdict', 'findings'} <= set(review)
            or review['stage'] not in STAGES
            or review['verdict'] not in {'ACCEPT', 'BLOCK', 'ACCEPT_WITH_TICKETS'}
            or not isinstance(review['findings'], list) or len(review['findings']) > 128):
        raise GuardError('INVALID_OUTPUT', 'Review metadata is malformed')
    for finding in review['findings']:
        safe_label(finding)
    for key in ('report_sha256', 'head'):
        if key in review and (not isinstance(review[key], str)
                              or not re.fullmatch(r'[0-9a-f]{64}' if key == 'report_sha256'
                                                  else r'[0-9a-f]{40}|[0-9a-f]{64}', review[key])):
            raise GuardError('INVALID_OUTPUT', 'Review report or head binding is malformed')
    if ('repo' in review) != ('pr' in review):
        raise GuardError('INVALID_OUTPUT', 'Review repository and PR must be bound together')
    if 'repo' in review:
        if (review['stage'] != 'PR' or not isinstance(review['repo'], str)
                or not re.fullmatch(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+', review['repo'])
                or type(review['pr']) is not int or review['pr'] <= 0):
            raise GuardError('INVALID_OUTPUT', 'Review repository or PR binding is malformed')
    identity = REVIEWER_IDENTITY_KEYS & set(review)
    if identity:
        if (identity != REVIEWER_IDENTITY_KEYS or review['stage'] != 'PR'
                or not isinstance(review.get('reviewer'), str)
                or not 3 <= len(review['reviewer']) <= 160
                or review.get('reviewer_harness') not in {'claude', 'openai', 'unknown'}
                or review.get('author_harness') not in {'claude', 'openai', 'unknown'}):
            raise GuardError('INVALID_OUTPUT', 'Review author and actual reviewer identity are malformed')
        safe_text(review['reviewer'], maximum=160)
    ticketed = review.get('ticketed', [])
    if not isinstance(ticketed, list) or len(ticketed) > 128:
        raise GuardError('INVALID_OUTPUT', 'Ticketed review records are malformed')
    if ticketed and (review['stage'] != 'PR' or review['verdict'] != 'ACCEPT_WITH_TICKETS'
                     or not review.get('head') or not review.get('report_sha256')):
        raise GuardError('INVALID_OUTPUT', 'Ticketed review records need a PR report and head binding')
    if review['verdict'] == 'ACCEPT_WITH_TICKETS' and not ticketed:
        raise GuardError('INVALID_OUTPUT', 'PASS-with-tickets needs ticketed finding records')
    recorded = []
    for record in ticketed:
        if (not isinstance(record, dict) or set(record) != TICKETED_RECORD_KEYS
                or record.get('state') != 'ticketed' or record.get('category') not in TICKETED_CATEGORIES
                or record.get('head') != review.get('head')
                or record.get('report_sha256') != review.get('report_sha256')):
            raise GuardError('INVALID_OUTPUT', 'Ticketed finding record is malformed or not bound to this report')
        safe_label(record.get('finding'))
        safe_text(record.get('ticket'), maximum=100)
        if not re.fullmatch(r'GoodQA [a-z0-9][a-z0-9-]{0,62}#[1-9]\d{0,9}', record['ticket']):
            raise GuardError('INVALID_OUTPUT', 'Ticketed finding has a malformed ticket')
        recorded.append(record['finding'])
    if ((ticketed or review['verdict'] == 'ACCEPT_WITH_TICKETS')
            and (len(set(recorded)) != len(recorded) or set(recorded) != set(review['findings']))):
        raise GuardError('INVALID_OUTPUT', 'Every accepted finding must have exactly one ticketed record')
    if result == 'CHECK_OK' and not (
            review['verdict'] == 'ACCEPT' and not review['findings']
            or review['verdict'] == 'ACCEPT_WITH_TICKETS' and ticketed):
        raise GuardError('INVALID_OUTPUT', 'Blocked review findings cannot be successful evidence')
    if review['verdict'] != 'BLOCK' and result != 'CHECK_OK':
        raise GuardError('INVALID_OUTPUT', 'Accepted review evidence requires a successful result')


class Run:
    def __init__(self, store, subject, start, reference):
        self.store, self.subject, self.start, self.start_ref = store, subject, start, reference
        self.run_id, self.timeout = start['run_id'], start['timeout']
        self.began = time.monotonic()

    def note_child(self, process):
        """process.run on_spawn callback: a recorded child must also be dead before auto-reconciliation."""
        self.store.record_child(self.run_id, getattr(process, 'pid', process))

    def finish(self, *, execution, result, reason, exit_code=None, count=None, review=None,
               usage=None, current_subject=None, cleanup_incomplete=False):
        if execution not in EXECUTIONS or result not in RESULTS or reason not in REASONS:
            raise GuardError('INVALID_OUTPUT', 'Unknown execution result')
        if current_subject is None: current_subject = self.subject.probe()
        if current_subject['fingerprint'] != self.subject['fingerprint']:
            result, reason = 'NO_RESULT', 'INPUT_CHANGED'
        invocation = self.start['invocation']
        if isinstance(invocation, Invocation) and invocation.probe()['fingerprint'] != invocation['fingerprint']:
            result, reason = 'NO_RESULT', 'INPUT_CHANGED'
        if result == 'CHECK_OK' and (execution != 'COMPLETED' or reason != 'NONE' or exit_code != 0):
            raise GuardError('INVALID_OUTPUT', 'Success requires completed validated evidence')
        if self.start['command_kind'] in {'focused', 'full'} and result == 'CHECK_OK' and (type(count) is not int or count < 1):
            result, reason = 'NO_RESULT', 'INVALID_OUTPUT'
        if review is not None:
            validate_review_metadata(review, result=result)
        value = {'schema': SCHEMA, 'kind': 'final', 'run_id': self.run_id, 'evidence': 'EXECUTED',
                 'subject': dict(self.subject), 'invocation': self.start['invocation'],
                 'started_at': self.start['started_at'], 'ended_at': datetime.now(timezone.utc).isoformat(),
                 'elapsed_seconds': max(0, time.monotonic() - self.began), 'execution': execution,
                 'result': result, 'reason': reason, 'exit_code': exit_code, 'observed_count': count,
                 'cleanup_incomplete': bool(cleanup_incomplete), 'review': review, 'usage': usage or {}}
        with self.store._lock():
            self.store.load_ref(self.start_ref)
            if self.store._reconciliation(self.store._run_directory(self.run_id), self.run_id):
                raise GuardError('UNKNOWN', 'Run was reconciled as dead while running; the late result is discarded')
            sha = self.store._publish(self.store._run_directory(self.run_id), 'final.json', value)
            reference = {'run_id': self.run_id, 'record': 'final', 'sha256': sha}
            self.store._publish(self.store._run_directory(self.run_id), 'completion.json',
                                {'schema': SCHEMA, 'reference': reference})
        return reference


def zero_launch_attempt(final):
    """True only when the attempt provably launched no provider and was refused by infrastructure.

    Content outcomes (CODE_FINDINGS, INPUT_CHANGED, INVALID_OUTPUT) and uncertain ones (TIMEOUT,
    UNKNOWN) count as attempts even with zero launches.
    """
    usage = final.get('usage') if isinstance(final.get('usage'), dict) else {}
    launches = usage.get('provider_launches')
    if type(launches) is not int or launches != 0 or usage.get('reported', []) != []:
        return False
    return final.get('execution') == 'NOT_STARTED' and final.get('reason') in ZERO_LAUNCH_REASONS


def within_window(started_at, seconds):
    try:
        started = datetime.fromisoformat(started_at)
    except (TypeError, ValueError):
        return True  # unparseable history stays conservative: it counts toward the cap
    if started.tzinfo is None: return True
    return (now_utc() - started).total_seconds() < seconds


def command_result(adapter, code, stdout, stderr='', success_exit=None):
    """A zero exit is insufficient for tests; require a recognized terminal count."""
    text = stdout + '\n' + stderr
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    count, outcome = None, None
    if adapter == 'unittest':
        summaries = [(at, re.fullmatch(r'Ran (\d+) tests? in [0-9.]+s', line))
                     for at, line in enumerate(lines)]
        summaries = [(at, match) for at, match in summaries if match]
        terminals = [(at, re.fullmatch(r'(OK|FAILED)(?:\s*\(([^\n]*)\))?', line))
                     for at, line in enumerate(lines)]
        terminals = [(at, match) for at, match in terminals if match]
        if (len(summaries) == len(terminals) == 1 and summaries[0][0] == len(lines) - 2
                and terminals[0][0] == len(lines) - 1):
            found, terminal = summaries[0][1], terminals[0][1]
            skipped = re.search(r'skipped=(\d+)', terminal.group(2) or '')
            count = int(found.group(1)) - (int(skipped.group(1)) if skipped else 0)
            outcome = terminal.group(1)
            if re.search(r'errors=[1-9][0-9]*', terminal.group(2) or ''):
                return 'NO_RESULT', 'UNKNOWN', count
    elif adapter == 'pytest':
        # Pytest exits2/3/4/5 are interruption/internal/usage/no-collection,
        # independently of any earlier partial success printed by the process.
        if code not in {0, 1} or re.search(r'KeyboardInterrupt|INTERNALERROR', text):
            return 'NO_RESULT', 'UNKNOWN', None
        summary = re.compile(r'=*\s*((?:\d+ (?:passed|failed|errors?|skipped|deselected|xfailed|xpassed|warnings?)(?:, )?)+)'
                             r'\s+in\s+[0-9.]+s\s*=*')
        summaries = [(at, summary.fullmatch(line)) for at, line in enumerate(lines)]
        summaries = [(at, match) for at, match in summaries if match]
        if len(summaries) == 1 and summaries[0][0] == len(lines) - 1:
            counts = {name: int(number) for number, name in re.findall(r'(\d+) ([a-z]+)', summaries[0][1].group(1))}
            count = counts.get('passed', 0) + counts.get('failed', 0)
            if counts.get('error', 0) or counts.get('errors', 0):
                return 'NO_RESULT', 'UNKNOWN', count
            if code == 0 and counts.get('failed', 0) == 0: outcome = 'OK'
            elif code == 1 and counts.get('failed', 0) > 0: outcome = 'FAILED'
    elif adapter == 'go-json':
        packages, completed, failed_tests = {}, set(), set()
        try:
            for line in text.splitlines():
                if not line.strip(): continue
                event = json.loads(line)
                if not isinstance(event, dict): raise ValueError
                action, package, test = event.get('Action'), event.get('Package'), event.get('Test')
                if action in {'build-fail', 'build-output'}:
                    return 'NO_RESULT', 'UNKNOWN', len(completed)
                if not isinstance(package, str) or not package: raise ValueError
                if action == 'start':
                    if package in packages: raise ValueError
                    packages[package] = {'terminal': None, 'tests': {}}
                    continue
                if package not in packages:
                    if action == 'fail': return 'NO_RESULT', 'UNKNOWN', len(completed)
                    raise ValueError
                current = packages[package]
                if current['terminal'] is not None: raise ValueError
                if action == 'output': continue
                if test is not None:
                    if not isinstance(test, str) or not test: raise ValueError
                    tests = current['tests']
                    if action == 'run':
                        if test in tests: raise ValueError
                        tests[test] = 'running'
                    elif action in {'pause', 'cont'}:
                        expected = 'running' if action == 'pause' else 'paused'
                        if tests.get(test) != expected: raise ValueError
                        tests[test] = 'paused' if action == 'pause' else 'running'
                    elif action in {'pass', 'fail', 'skip'}:
                        if tests.get(test) != 'running': raise ValueError
                        tests[test] = action
                        if action != 'skip': completed.add((package, test))
                        if action == 'fail': failed_tests.add(package)
                    else: raise ValueError
                elif action in {'pass', 'fail', 'skip'}:
                    if any(state in {'running', 'paused'} for state in current['tests'].values()): raise ValueError
                    if action == 'fail' and package not in failed_tests:
                        return 'NO_RESULT', 'UNKNOWN', len(completed)
                    if action != 'fail' and package in failed_tests: raise ValueError
                    current['terminal'] = action
                else: raise ValueError
            count = len(completed)
            if not packages or any(value['terminal'] is None for value in packages.values()):
                return 'NO_RESULT', 'UNKNOWN', count
            outcome = 'FAILED' if failed_tests else 'OK'
        except (ValueError, TypeError):
            return 'NO_RESULT', 'INVALID_OUTPUT', len(completed)
    elif adapter == 'command' and type(success_exit) is int:
        return ('CHECK_OK', 'NONE', None) if code == success_exit else ('NO_RESULT', 'UNKNOWN', None)
    if not count or count < 0 or outcome is None:
        return 'NO_RESULT', 'UNKNOWN' if code else 'INVALID_OUTPUT', count
    if code == 0 and outcome == 'OK': return 'CHECK_OK', 'NONE', count
    if outcome == 'FAILED' and code != 0: return 'CHECK_FAILED', 'CODE_FINDINGS', count
    return 'NO_RESULT', 'UNKNOWN', count


def reference_argument(value):
    try:
        run_id, record, sha = value.split(':')
        if not RUN_ID.fullmatch(run_id) or record not in {'start', 'final'} or not HEX.fullmatch(sha): raise ValueError
        return {'run_id': run_id, 'record': record, 'sha256': sha}
    except ValueError:
        raise argparse.ArgumentTypeError('reference must be RUN_ID:start|final:SHA256') from None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state-dir', type=Path)
    sub = parser.add_subparsers(dest='action', required=True)
    for action in ('check', 'gate', 'reuse'):
        part = sub.add_parser(action)
        part.add_argument('--repo', type=Path, required=True)
        part.add_argument('--manifest', type=Path)
        if action in {'gate', 'reuse'}: part.add_argument('--reference', type=reference_argument, required=True)
        if action != 'gate':
            part.add_argument('--purpose', required=True)
            part.add_argument('--adapter', choices=('unittest', 'pytest', 'go-json', 'command'), default='unittest')
            part.add_argument('--kind', choices=('focused', 'full', 'command'), default='focused')
            part.add_argument('--success-exit', type=int)
            part.add_argument('command', nargs=argparse.REMAINDER)
    check = sub.choices['check']
    check.add_argument('--owner', required=True); check.add_argument('--label', required=True)
    check.add_argument('--timeout', type=float, required=True); check.add_argument('--aggregate-timeout', type=float)
    check.add_argument('--minimum-free-bytes', type=int)
    check.add_argument('--repeat-reason'); check.add_argument('--ungated-reason')
    check.add_argument('--gate', type=reference_argument)
    inspect = sub.add_parser('inspect'); inspect.add_argument('--reference', type=reference_argument, required=True)
    reconcile = sub.add_parser('reconcile'); reconcile.add_argument('--run', required=True)
    reconcile.add_argument('--auto', action='store_true',
                           help='reconcile only when the owner is provably dead on this host past its deadline')
    ack = sub.add_parser('ack-pool'); ack.add_argument('--provider', required=True); ack.add_argument('--pool', default='default')
    for part in (reconcile, ack):
        for flag in ('actor', 'reason', 'evidence'): part.add_argument('--' + flag)
    sub.add_parser('sweep', help='apply the automatic dead-owner rule to every run and report each one')
    args = parser.parse_args()
    run = None
    try:
        store = UsageStore(args.state_dir)
        if args.action == 'inspect': value = store.inspect(args.reference)
        elif args.action == 'reconcile' and args.auto:
            value = {'execution': 'UNKNOWN', 'result': 'NO_RESULT', 'automatic_reconciliation': store.auto_reconcile(args.run)}
        elif args.action == 'reconcile':
            if not all((args.actor, args.reason, args.evidence)):
                parser.error('reconcile needs --actor, --reason and --evidence unless --auto is given')
            store.reconcile(args.run, actor=args.actor, reason=args.reason, evidence=args.evidence)
            value = {'execution': 'UNKNOWN', 'result': 'NO_RESULT', 'manual_reconciliation': args.run}
        elif args.action == 'sweep':
            reports = store.sweep()
            value = {'result': 'NO_RESULT', 'runs': len(reports), 'reconciled': [r['run_id'] for r in reports if r['reconciled']],
                     'reports': reports}
        elif args.action == 'ack-pool':
            if not all((args.actor, args.reason, args.evidence)):
                parser.error('ack-pool needs --actor, --reason and --evidence')
            store.ack_pool(args.provider, args.pool, actor=args.actor, reason=args.reason, evidence=args.evidence)
            value = {'availability_acknowledged': True, 'result': 'NO_RESULT'}
        else:
            manifest = load_manifest(args.manifest)
            subject = capture_subject(args.repo, args.manifest)
            if args.action == 'gate': value = store.check_gate(subject, args.reference)
            else:
                command = args.command[1:] if args.command[:1] == ['--'] else args.command
                if not command: raise GuardError('INVALID_OUTPUT', 'A command is required')
                if args.adapter == 'command' and args.success_exit != 0:
                    raise GuardError('INVALID_OUTPUT', 'Non-test commands require the explicit supported --success-exit 0 predicate')
                public = manifest.get('public_arguments') is True
                declared = command if public else ['opaque-command', manifest.get('command_revision', 'unknown')]
                invocation = invocation_identity(subject, purpose=args.purpose,
                                                 argv=['guard-contract', args.kind, args.adapter, str(args.success_exit), *declared], cwd=args.repo,
                                                 toolchain=manifest.get('toolchain'), environment=manifest.get('environment'),
                                                 reusable=public and bool(manifest.get('toolchain')),
                                                 execution_executable=command[0])
                if args.action == 'reuse': value = store.reuse(subject, invocation, args.reference)
                else:
                    run = store.begin(subject, invocation, owner=args.owner, label=args.label,
                                      timeout=args.timeout, kind=args.kind, repeat_reason=args.repeat_reason,
                                      aggregate_timeout=args.aggregate_timeout, gate=args.gate,
                                      ungated_reason=args.ungated_reason, minimum_bytes=args.minimum_free_bytes)
                    print(json.dumps({'event': 'START', 'reference': run.start_ref}, sort_keys=True), file=sys.stderr, flush=True)
                    try:
                        completed = run_process(command, cwd=args.repo, timeout=run.timeout, on_spawn=run.note_child)
                        result, reason, count = command_result(args.adapter, completed.returncode,
                                                               completed.stdout, completed.stderr, args.success_exit)
                        reference = run.finish(execution='COMPLETED', result=result, reason=reason,
                                               exit_code=completed.returncode, count=count)
                    except subprocess.TimeoutExpired as error:
                        reference = run.finish(execution='INTERRUPTED', result='NO_RESULT', reason='TIMEOUT',
                                               cleanup_incomplete=getattr(error, 'cleanup_incomplete', False))
                    except (OSError, KeyboardInterrupt) as error:
                        reference = run.finish(execution='INTERRUPTED', result='NO_RESULT', reason='UNKNOWN',
                                               cleanup_incomplete=getattr(error, 'cleanup_incomplete', False))
                    value = {'reference': reference, **store.load_ref(reference)}
        print(json.dumps(value, sort_keys=True))
        return 0 if value.get('result') == 'CHECK_OK' or args.action in {'inspect', 'reuse', 'reconcile', 'ack-pool', 'gate', 'sweep'} else 3
    except (GuardError, OSError, ValueError, TypeError, UnicodeError) as error:
        facts = {'reason': error.reason, 'reference': error.reference} if isinstance(error, GuardError) else {'reason': 'UNKNOWN'}
        if run is not None and facts.get('reference') is None:
            facts['reference'] = run.start_ref
        print(json.dumps({'execution': 'UNKNOWN' if run is not None else 'NOT_STARTED', 'result': 'NO_RESULT',
                          'message': error.message if isinstance(error, GuardError) else 'Guard state or input could not be verified',
                          **facts}, sort_keys=True))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
