#!/usr/bin/env python3
"""Finite, opt-in command receipts and cooperative review budgets.

Receipts describe declared inputs. They are local evidence, not attestations or
global enforcement of native agents, accounts, or commands outside this helper.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import re
import secrets
import shutil
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
EXECUTIONS = {'NOT_STARTED', 'RUNNING', 'COMPLETED', 'INTERRUPTED', 'UNKNOWN'}
RESULTS = {'CHECK_OK', 'CHECK_FAILED', 'NO_RESULT'}
REASONS = {'NONE', 'CODE_FINDINGS', 'QUOTA', 'AUTH', 'TRANSIENT_INFRA', 'LOW_DISK',
           'TIMEOUT', 'INVALID_OUTPUT', 'INPUT_CHANGED', 'BUDGET_EXHAUSTED', 'UNKNOWN'}
STAGES = {'PLAN', 'CODE_INSPECTION', 'PR'}
HEX = re.compile(r'[0-9a-f]{64}\Z')
RUN_ID = re.compile(r'[0-9a-f]{32}\Z')
LABEL = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}\Z')
SECRET = re.compile(r'(?:ghp_|github_pat_|sk-ant-)[A-Za-z0-9_-]{16,}|-----BEGIN .*PRIVATE KEY-----|'
                    r'(?i:api[_-]?key|password|access[_-]?token|authorization)\s*[:=]\s*\S+')


class GuardError(Exception):
    def __init__(self, reason, message, reference=None):
        super().__init__(message)
        self.reason, self.message, self.reference = reason, message, reference


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
        value = json.loads(file_bytes(path, limit))
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
    return value


class Subject(dict):
    """Serializable metadata, with private in-memory inputs for a final reprobe."""
    def probe(self):
        return capture_subject(self.repo, self.manifest)


def capture_subject(repo, manifest=None):
    repo = Path(repo).resolve()
    manifest = load_manifest(manifest)
    environment = git_environment(isolated=True)
    require_safe_source(repo, environment)
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
    for name in ('usage_guard.py', 'peer_review.py', 'process.py', 'git_safety.py', 'report_file.py'):
        path = Path(__file__).resolve().with_name(name)
        if path.is_file():
            known['runtime/' + name] = hashlib.sha256(file_bytes(path, MAX_FILE, private=False)).hexdigest()
    for label, value in revisions.items():
        safe_label(label); safe_text(value)
    unknown = sorted({safe_label(value) for value in unknown})
    data = {'schema': SCHEMA, 'repository': digest([str(repo), info.st_dev, info.st_ino]),
            'head': head, 'tree': tree, 'dirty': dirty, 'files': known, 'revisions': revisions,
            'unknown_inputs': unknown, 'complete': manifest.get('complete') is True,
            'deterministic': manifest.get('deterministic') is True}
    data['reusable'] = data['complete'] and data['deterministic'] and not dirty and not unknown
    data['fingerprint'] = digest(data)
    subject = Subject(data)
    subject.repo, subject.manifest = repo, manifest
    return subject


def invocation_identity(subject, *, purpose, argv, cwd, stage=None, packet_digest=None,
                        provider=None, model=None, pool=None, toolchain=None, environment=None, reusable=True):
    safe_label(purpose)
    if stage is not None and stage not in STAGES:
        raise GuardError('INVALID_OUTPUT', 'Unknown review stage')
    # Callers pass only declared public argv/settings; secrets use an opaque revision instead.
    if (not isinstance(argv, list) or not all(isinstance(value, str) and not SECRET.search(value) for value in argv)
            or len(encoded(argv)) > MAX_MANIFEST):
        raise GuardError('INVALID_OUTPUT', 'Invocation arguments are unsafe or oversized')
    for value in (provider, model, pool):
        if value is not None: safe_label(value)
    metadata = {'purpose': purpose, 'stage': stage, 'subject': subject['fingerprint'],
                'argv_digest': digest(argv), 'cwd_digest': digest(str(Path(cwd).resolve())),
                'packet_digest': packet_digest, 'provider': provider, 'model': model, 'pool': pool,
                'toolchain': toolchain or {}, 'environment': environment or {},
                'platform': sys.platform, 'target': getattr(subject, 'manifest', {}).get('target', 'local'),
                'reusable': subject['reusable'] and reusable}
    if len(encoded(metadata)) > MAX_MANIFEST or SECRET.search(encoded(metadata).decode()):
        raise GuardError('INVALID_OUTPUT', 'Invocation metadata is unsafe or oversized')
    metadata['fingerprint'] = digest(metadata)
    return metadata


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
        for name in ('runs', 'purposes', 'pools'):
            self._directory(self.root / name)

    @staticmethod
    def _signature(path):
        info = os.stat(path, follow_symlinks=False)
        return info.st_dev, info.st_ino

    def _directory(self, path):
        try:
            path.mkdir(mode=0o700)
            parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try: os.fsync(parent)
            finally: os.close(parent)
        except FileExistsError:
            pass
        info = os.stat(path, follow_symlinks=False)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.geteuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise GuardError('UNKNOWN', 'Usage directory ownership or permissions are unsafe')
        return path

    def _current(self):
        self._directory(self.root)
        if self._signature(self.root) != self.identity:
            raise GuardError('UNKNOWN', 'Usage directory identity changed')

    @contextmanager
    def _lock(self):
        self._current()
        fd = os.open(self.root / '.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
        try:
            info = os.fstat(fd)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid() or info.st_nlink != 1
                    or stat.S_IMODE(info.st_mode) != 0o600):
                raise GuardError('UNKNOWN', 'Usage lock is unsafe')
            fcntl.flock(fd, fcntl.LOCK_EX)
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
        temporary = '.stage-' + secrets.token_hex(16)
        try:
            target = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
            with os.fdopen(target, 'wb') as output:
                output.write(body); output.flush(); os.fsync(output.fileno())
            if self._signature(directory) != (os.fstat(fd).st_dev, os.fstat(fd).st_ino):
                raise GuardError('UNKNOWN', 'Receipt directory changed')
            if replace:
                os.replace(temporary, name, src_dir_fd=fd, dst_dir_fd=fd)
            else:
                os.link(temporary, name, src_dir_fd=fd, dst_dir_fd=fd, follow_symlinks=False)
            os.fsync(fd)
        finally:
            try: os.unlink(temporary, dir_fd=fd)
            except FileNotFoundError: pass
            os.close(fd)
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
                or reference['record'] not in {'start', 'final'} or not HEX.fullmatch(reference['sha256'])):
            raise GuardError('UNKNOWN', 'Invalid receipt reference')
        self._current()
        directory = self._run_directory(reference['run_id']); self._directory(directory)
        path = directory / (reference['record'] + '.json')
        try:
            body = file_bytes(path)
            value = json.loads(body)
        except (OSError, ValueError, UnicodeError):
            raise GuardError('UNKNOWN', 'Referenced evidence is missing or unsafe') from None
        if (hashlib.sha256(body).hexdigest() != reference['sha256'] or not isinstance(value, dict)
                or type(value.get('schema')) is not int or value['schema'] != SCHEMA
                or value.get('kind') != reference['record'] or value.get('run_id') != reference['run_id']):
            raise GuardError('UNKNOWN', 'Evidence digest or schema does not match')
        return value

    def check_gate(self, subject, reference):
        record = self.load_ref(reference)
        review = record.get('review', {})
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
        return {'evidence': 'REUSED', 'eligible': bool(eligible), 'reference': reference,
                'original_timestamp': record.get('ended_at'), 'original_result': record.get('result'),
                'scope': record.get('subject'), 'note': 'Historical evidence; no new check result or PR signoff'}

    def begin(self, subject, invocation, *, owner, label, timeout, kind='review', repeat_reason=None,
              gate=None, ungated_reason=None, minimum_bytes=None, aggregate_timeout=None):
        safe_label(owner); safe_label(label); finite_seconds(timeout)
        if kind not in {'review', 'focused', 'full', 'command'}:
            raise GuardError('INVALID_OUTPUT', 'Unsupported guarded command kind')
        if repeat_reason is not None: safe_text(repeat_reason)
        if ungated_reason is not None: safe_text(ungated_reason)
        aggregate_timeout = finite_seconds(aggregate_timeout or timeout * 2)
        if kind == 'full' and gate is None and not ungated_reason:
            raise GuardError('INPUT_CHANGED', 'Full validation needs a gate or explicit investigation/native reason')
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
            previous, spent = [], 0
            for number in (1, 2):
                path = purpose / ('attempt-' + str(number) + '.json')
                if not os.path.lexists(path): break
                entry = read_json(path)
                previous.append(entry)
                directory = self._run_directory(entry['run_id'])
                reconciled = os.path.lexists(directory / 'reconciled.json')
                final = directory / 'final.json'
                if not os.path.lexists(final):
                    if not reconciled:
                        raise GuardError('UNKNOWN', 'Prior reservation has no final receipt; reconcile before retry', entry['start'])
                    read_json(directory / 'reconciled.json')
                    spent += entry['timeout']
                else:
                    record = read_json(final)
                    if record.get('reason') in {'UNKNOWN', 'TIMEOUT'} and not reconciled:
                        raise GuardError('UNKNOWN', 'Uncertain prior result requires recorded reconciliation', entry['start'])
                    spent += record.get('elapsed_seconds', entry['timeout'])
            if previous and (repeat_reason is None or len(previous) >= 2):
                raise GuardError('BUDGET_EXHAUSTED', 'Identical invocation already reserved; use evidence or one justified repeat', previous[-1]['start'])
            remaining = aggregate_timeout - spent
            if remaining <= 0:
                raise GuardError('BUDGET_EXHAUSTED', 'Declared aggregate execution budget is exhausted')
            run_id = secrets.token_hex(16)
            directory = self._directory(self._run_directory(run_id))
            started = {'schema': SCHEMA, 'kind': 'start', 'run_id': run_id, 'owner': owner, 'label': label,
                       'subject': dict(subject), 'invocation': invocation, 'command_kind': kind,
                       'timeout': min(timeout, remaining), 'aggregate_timeout': aggregate_timeout,
                       'started_at': datetime.now(timezone.utc).isoformat(), 'resources': resources,
                       'repeat_reason': repeat_reason, 'gate': gate,
                       'ungated_reason': ungated_reason, 'execution': 'RUNNING'}
            reference = {'run_id': run_id, 'record': 'start', 'sha256': hashlib.sha256(encoded(started)).hexdigest()}
            self._publish(purpose, 'attempt-' + str(len(previous) + 1) + '.json',
                          {'schema': SCHEMA, 'run_id': run_id, 'start': reference, 'timeout': min(timeout, remaining)})
            self._publish(directory, 'start.json', started)
        run = Run(self, subject, started, reference)
        if resource_reason != 'NONE':
            final = run.finish(execution='NOT_STARTED', result='NO_RESULT', reason=resource_reason)
            raise GuardError(resource_reason, 'Resource preflight prevented command launch', final)
        return run

    def _pool(self, provider, pool):
        safe_label(provider); safe_label(pool)
        directory = self._directory(self.root / 'pools' / digest([provider, pool]))
        self._directory(directory / 'events')
        index = directory / 'head.json'
        if not os.path.lexists(index):
            return directory, {'provider': provider, 'pool': pool, 'active': None,
                               'cooldown': False, 'reason': 'NONE', 'reset_at': None}
        ref = read_json(index)
        if set(ref) != {'event', 'sha256'} or not RUN_ID.fullmatch(ref['event']):
            raise GuardError('UNKNOWN', 'Pool index is corrupt')
        body = file_bytes(directory / 'events' / (ref['event'] + '.json'))
        value = json.loads(body)
        if hashlib.sha256(body).hexdigest() != ref['sha256'] or value.get('schema') != SCHEMA:
            raise GuardError('UNKNOWN', 'Pool history digest is invalid')
        return directory, value['state']

    def _pool_event(self, directory, state, action, **facts):
        event = secrets.token_hex(16)
        value = {'schema': SCHEMA, 'action': action, 'at': datetime.now(timezone.utc).isoformat(),
                 'state': state, **facts}
        sha = self._publish(directory / 'events', event + '.json', value)
        self._publish(directory, 'head.json', {'event': event, 'sha256': sha}, replace=True)

    def acquire_pool(self, provider, pool, run_id):
        self._run_directory(run_id)
        with self._lock():
            directory, state = self._pool(provider, pool)
            if state['active'] is not None:
                raise GuardError('UNKNOWN', 'Provider pool has an active or unreconciled owner')
            if state['cooldown'] and (state['reset_at'] is None or time.time() < state['reset_at']):
                raise GuardError(state['reason'], 'Provider pool requires availability evidence or its reliable reset')
            state = {**state, 'active': run_id, 'cooldown': False, 'reason': 'NONE', 'reset_at': None}
            self._pool_event(directory, state, 'RESERVED')

    def release_pool(self, provider, pool, run_id, *, reason='NONE', account_cooldown=False, reset_at=None):
        if reason not in REASONS:
            raise GuardError('INVALID_OUTPUT', 'Unknown provider result reason')
        if reset_at is not None and (type(reset_at) not in (int, float) or not math.isfinite(reset_at)):
            reset_at = None
        with self._lock():
            directory, state = self._pool(provider, pool)
            if state['active'] != run_id:
                raise GuardError('UNKNOWN', 'Provider pool ownership changed')
            cooldown = account_cooldown is True and reason in {'QUOTA', 'AUTH'}
            state = {**state, 'active': None, 'cooldown': cooldown,
                     'reason': reason if cooldown else 'NONE', 'reset_at': reset_at if cooldown else None}
            self._pool_event(directory, state, 'FINISHED')

    def reconcile(self, run_id, *, actor, reason, evidence):
        for value in (actor, reason, evidence): safe_text(value)
        with self._lock():
            directory = self._run_directory(run_id)
            if not directory.is_dir(): raise GuardError('UNKNOWN', 'Run to reconcile does not exist')
            self._publish(directory, 'reconciled.json', {'schema': SCHEMA, 'kind': 'manual_reconciliation',
                          'run_id': run_id, 'actor': actor, 'reason': reason, 'evidence': evidence,
                          'at': datetime.now(timezone.utc).isoformat(), 'execution': 'UNKNOWN', 'result': 'NO_RESULT'})
            # A bounded scan visits only current pool indices, never old event history.
            for number, pool in enumerate((self.root / 'pools').iterdir()):
                if number >= 4096: raise GuardError('UNKNOWN', 'Pool reconciliation scan exceeded limit')
                index = read_json(pool / 'head.json')
                event = read_json(pool / 'events' / (index['event'] + '.json'))
                if event['state']['active'] == run_id:
                    self._pool_event(pool, {**event['state'], 'active': None}, 'RECONCILED', actor=actor,
                                     reason=reason, evidence=evidence)

    def ack_pool(self, provider, pool, *, actor, reason, evidence):
        for value in (actor, reason, evidence): safe_text(value)
        with self._lock():
            directory, state = self._pool(provider, pool)
            if state['active'] is not None:
                raise GuardError('UNKNOWN', 'Reconcile the active owner before acknowledging availability')
            self._pool_event(directory, {**state, 'cooldown': False, 'reason': 'NONE', 'reset_at': None},
                             'AVAILABILITY_ACK', actor=actor, reason=reason, evidence=evidence)


class Run:
    def __init__(self, store, subject, start, reference):
        self.store, self.subject, self.start, self.start_ref = store, subject, start, reference
        self.run_id, self.timeout = start['run_id'], start['timeout']
        self.began = time.monotonic()

    def finish(self, *, execution, result, reason, exit_code=None, count=None, review=None,
               usage=None, current_subject=None, cleanup_incomplete=False):
        if execution not in EXECUTIONS or result not in RESULTS or reason not in REASONS:
            raise GuardError('INVALID_OUTPUT', 'Unknown execution result')
        if current_subject is None: current_subject = self.subject.probe()
        if current_subject['fingerprint'] != self.subject['fingerprint']:
            result, reason = 'NO_RESULT', 'INPUT_CHANGED'
        if result == 'CHECK_OK' and (execution != 'COMPLETED' or reason != 'NONE' or exit_code != 0):
            raise GuardError('INVALID_OUTPUT', 'Success requires completed validated evidence')
        if self.start['command_kind'] in {'focused', 'full'} and result == 'CHECK_OK' and (type(count) is not int or count < 1):
            result, reason = 'NO_RESULT', 'INVALID_OUTPUT'
        if review is not None:
            if (not isinstance(review, dict) or set(review) != {'stage', 'verdict', 'findings'}
                    or review['stage'] not in STAGES or review['verdict'] not in {'ACCEPT', 'BLOCK'}
                    or not isinstance(review['findings'], list) or len(review['findings']) > 128):
                raise GuardError('INVALID_OUTPUT', 'Review metadata is malformed')
            for finding in review['findings']: safe_label(finding)
        value = {'schema': SCHEMA, 'kind': 'final', 'run_id': self.run_id, 'evidence': 'EXECUTED',
                 'subject': dict(self.subject), 'invocation': self.start['invocation'],
                 'started_at': self.start['started_at'], 'ended_at': datetime.now(timezone.utc).isoformat(),
                 'elapsed_seconds': max(0, time.monotonic() - self.began), 'execution': execution,
                 'result': result, 'reason': reason, 'exit_code': exit_code, 'observed_count': count,
                 'cleanup_incomplete': bool(cleanup_incomplete), 'review': review, 'usage': usage or {}}
        with self.store._lock():
            self.store.load_ref(self.start_ref)
            sha = self.store._publish(self.store._run_directory(self.run_id), 'final.json', value)
        return {'run_id': self.run_id, 'record': 'final', 'sha256': sha}


def command_result(adapter, code, stdout, stderr='', success_exit=None):
    """A zero exit is insufficient for tests; require a recognized terminal count."""
    text = stdout + '\n' + stderr
    count, outcome = None, None
    if adapter == 'unittest':
        found = re.search(r'^Ran (\d+) tests? in [^\n]+$', text, re.M)
        terminal = re.search(r'^(OK|FAILED)(?:\s*\(([^\n]*)\))?\s*$', text, re.M)
        if found and terminal:
            skipped = re.search(r'skipped=(\d+)', terminal.group(2) or '')
            count = int(found.group(1)) - (int(skipped.group(1)) if skipped else 0)
            outcome = terminal.group(1)
    elif adapter == 'pytest':
        passed = re.search(r'(\d+) passed', text)
        failed = re.search(r'(\d+) failed', text)
        if passed or failed:
            count = int(passed.group(1)) if passed else 0
            count += int(failed.group(1)) if failed else 0
            outcome = 'OK' if code == 0 and passed and not failed else 'FAILED'
    elif adapter == 'go-json':
        completed = set(); failed = False
        try:
            for line in text.splitlines():
                if not line.strip(): continue
                event = json.loads(line)
                if event.get('Action') == 'pass' and event.get('Test'):
                    completed.add((event.get('Package'), event['Test']))
                if event.get('Action') == 'fail': failed = True
            count, outcome = len(completed), 'FAILED' if failed else 'OK'
        except (ValueError, AttributeError):
            pass
    elif adapter == 'command' and type(success_exit) is int:
        return ('CHECK_OK', 'NONE', None) if code == success_exit else ('NO_RESULT', 'UNKNOWN', None)
    if not count or outcome is None:
        return 'NO_RESULT', 'INVALID_OUTPUT', count
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
    ack = sub.add_parser('ack-pool'); ack.add_argument('--provider', required=True); ack.add_argument('--pool', default='default')
    for part in (reconcile, ack):
        for flag in ('actor', 'reason', 'evidence'): part.add_argument('--' + flag, required=True)
    args = parser.parse_args()
    try:
        store = UsageStore(args.state_dir)
        if args.action == 'inspect': value = store.load_ref(args.reference)
        elif args.action == 'reconcile':
            store.reconcile(args.run, actor=args.actor, reason=args.reason, evidence=args.evidence)
            value = {'execution': 'UNKNOWN', 'result': 'NO_RESULT', 'manual_reconciliation': args.run}
        elif args.action == 'ack-pool':
            store.ack_pool(args.provider, args.pool, actor=args.actor, reason=args.reason, evidence=args.evidence)
            value = {'availability_acknowledged': True, 'result': 'NO_RESULT'}
        else:
            manifest = load_manifest(args.manifest)
            subject = capture_subject(args.repo, manifest)
            if args.action == 'gate': value = store.check_gate(subject, args.reference)
            else:
                command = args.command[1:] if args.command[:1] == ['--'] else args.command
                if not command: raise GuardError('INVALID_OUTPUT', 'A command is required')
                public = manifest.get('public_arguments') is True
                declared = command if public else ['opaque-command', manifest.get('command_revision', 'unknown')]
                invocation = invocation_identity(subject, purpose=args.purpose, argv=declared, cwd=args.repo,
                                                 toolchain=manifest.get('toolchain'), environment=manifest.get('environment'),
                                                 reusable=public and bool(manifest.get('toolchain')))
                if args.action == 'reuse': value = store.reuse(subject, invocation, args.reference)
                else:
                    run = store.begin(subject, invocation, owner=args.owner, label=args.label,
                                      timeout=args.timeout, kind=args.kind, repeat_reason=args.repeat_reason,
                                      aggregate_timeout=args.aggregate_timeout, gate=args.gate,
                                      ungated_reason=args.ungated_reason, minimum_bytes=args.minimum_free_bytes)
                    try:
                        completed = run_process(command, cwd=args.repo, timeout=run.timeout)
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
        return 0 if value.get('result') == 'CHECK_OK' or args.action in {'inspect', 'reuse', 'reconcile', 'ack-pool', 'gate'} else 3
    except (GuardError, OSError, ValueError, TypeError, UnicodeError) as error:
        facts = {'reason': error.reason, 'reference': error.reference} if isinstance(error, GuardError) else {'reason': 'UNKNOWN'}
        print(json.dumps({'execution': 'NOT_STARTED', 'result': 'NO_RESULT', **facts}, sort_keys=True))
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
