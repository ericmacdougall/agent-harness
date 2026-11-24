"""Offline MC state safety. No service control, subprocesses, pruning or automatic activation.

All restore calls require an explicit quiesced=True from the maintenance operator.
The web app exposes no restore action. Snapshot and restore operate only on fixed basenames.
"""
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import secrets
import re
import shutil
import stat

DATA = 'fabric.jsonl'
CHECKPOINT = '.fabric-commit.json'
FENCE = '.fabric-restore-in-progress'
JOURNAL = '.fabric-operation.json'
POSTCOMMIT = ('REOPEN_COMMITTED', 'COMPLETE')


class Hold(OSError):
    pass


class Busy(Hold):
    pass


def maintenance_guard(root):
    if os.path.lexists(Path(root) / FENCE):
        raise Hold('Fabric maintenance fence active')


def _sync(root):
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _open(path, flags=os.O_RDONLY):
    fd = os.open(path, flags | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        os.close(fd)
        raise Hold('State file must be a regular single-link file')
    return fd


def _read(path, limit=16384):
    fd = _open(path)
    try:
        raw = os.read(fd, limit + 1)
    finally:
        os.close(fd)
    if len(raw) > limit:
        raise Hold('State metadata budget exceeded')
    return json.loads(raw)


def _json(path, value):
    from collectors import _write_all
    path = Path(path)
    temporary = path.with_name(path.name + '.' + secrets.token_hex(8) + '.tmp')
    fd = _open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
    try:
        _write_all(fd, (json.dumps(value, sort_keys=True) + '\n').encode())
        os.fsync(fd)
    finally:
        os.close(fd)
    os.replace(temporary, path)
    _sync(path.parent)


@contextmanager
def operation(root):
    root = Path(root)
    if root.is_symlink() or not root.is_dir() or root.parent.is_symlink():
        raise Hold('Unsafe state directory')
    lock = root.parent / '.fabric-operation.lock'
    fd = _open(lock, os.O_RDWR | os.O_CREAT)
    try:
        if os.fstat(fd).st_uid != os.getuid() or os.fstat(fd).st_mode & 0o077:
            raise Hold('Operation mutex is not private')
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise Busy('Another state helper owns the operation mutex') from exc
        pinned = os.fstat(fd)
        linked = os.stat(lock, follow_symlinks=False)
        if (pinned.st_dev, pinned.st_ino) != (linked.st_dev, linked.st_ino):
            raise Hold('Operation mutex identity changed')
        yield
    finally:
        os.close(fd)  # never unlink or replace the stable operation mutex


@contextmanager
def data_lock(root):
    fd = _open(Path(root) / DATA, os.O_RDWR)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise Busy('Fabric writer is busy') from exc
        yield fd
    finally:
        os.close(fd)


def _hash(path):
    fd = _open(path)
    digest, size = hashlib.sha256(), 0
    try:
        while True:
            raw = os.read(fd, 65536)
            if not raw:
                return {'bytes': size, 'sha256': digest.hexdigest()}
            digest.update(raw)
            size += len(raw)
    finally:
        os.close(fd)


def _prefix(fd, length):
    digest, offset = hashlib.sha256(), 0
    while offset < length:
        raw = os.pread(fd, min(65536, length - offset), offset)
        if not raw:
            raise Hold('Short accepted prefix')
        digest.update(raw)
        offset += len(raw)
    return digest.hexdigest()


def _copy(fd, start, length, destination):
    from collectors import _write_all
    out = _open(destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
    try:
        position = 0
        while position < length:
            raw = os.pread(fd, min(65536, length - position), start + position)
            if not raw:
                raise Hold('Short snapshot read')
            _write_all(out, raw)
            position += len(raw)
        os.fsync(out)
    finally:
        os.close(out)


def _pair(root, fd):
    from collectors import _fabric_offset
    info = os.fstat(fd)
    offset = _fabric_offset(Path(root) / DATA, info, fd)
    if offset is None:
        raise Hold('State is not managed; no checkpoint may be guessed')
    return info, offset


def _capture(root, fd, destination, max_bytes=2 * 1024 * 1024):
    """Caller owns BOTH locks. Preserve full physical data, splitting accepted prefix from pending tail."""
    root, destination = Path(root), Path(destination)
    if destination.is_symlink() or root.resolve() in destination.resolve().parents or destination.resolve() == root.resolve():
        raise Hold('Backup must be outside the active source directory')
    info, offset = _pair(root, fd)
    if info.st_size > max_bytes or shutil.disk_usage(destination.parent).free < 2 * info.st_size + 2 * 1024 * 1024:
        raise Hold('Snapshot exceeds approved capacity budget')
    checkpoint = _read(root / CHECKPOINT)
    destination.mkdir(mode=0o700)
    _copy(fd, 0, offset, destination / 'accepted.ndjson')
    _copy(fd, offset, info.st_size - offset, destination / 'unaccepted-tail.bin')
    checkpoint_fd = _open(root / CHECKPOINT)
    try:
        _copy(checkpoint_fd, 0, os.fstat(checkpoint_fd).st_size, destination / 'checkpoint.json')
    finally:
        os.close(checkpoint_fd)
    if os.fstat(fd).st_size != info.st_size or _read(root / CHECKPOINT) != checkpoint:
        raise Hold('Source changed during snapshot')
    manifest = {'schema': 'mc.fabric.snapshot/1', 'bundle_id': secrets.token_hex(16),
                'source': {'dev': info.st_dev, 'ino': info.st_ino}, 'physical_size': info.st_size,
                'accepted_offset': offset, 'files': {name: _hash(destination / name) for name in
                    ('accepted.ndjson', 'unaccepted-tail.bin', 'checkpoint.json')}}
    _json(destination / 'manifest.json', manifest)
    digest = _hash(destination / 'manifest.json')['sha256']
    _json(destination / 'COMPLETE', {'manifest': digest})
    _sync(destination)
    _sync(destination.parent)
    verify(destination, digest)
    return digest


def verify(bundle, expected=None):
    bundle = Path(bundle)
    if bundle.is_symlink() or not bundle.is_dir():
        raise Hold('Invalid bundle directory')
    digest = _hash(bundle / 'manifest.json')['sha256']
    if (expected is not None and digest != expected) or _read(bundle / 'COMPLETE') != {'manifest': digest}:
        raise Hold('Unsealed or unexpected snapshot')
    value = _read(bundle / 'manifest.json')
    names = {'accepted.ndjson', 'unaccepted-tail.bin', 'checkpoint.json'}
    if value.get('schema') != 'mc.fabric.snapshot/1' or set(value.get('files', {})) != names:
        raise Hold('Unsupported snapshot schema')
    for name in names:
        if _hash(bundle / name) != value['files'][name]:
            raise Hold('Mixed or corrupted snapshot payload')
    cp = _read(bundle / 'checkpoint.json')
    size = value['files']['accepted.ndjson']['bytes']
    if (cp.get('schema') != 'mc.fabric.commit/1' or type(cp.get('offset')) is not int
            or cp['offset'] != size or value.get('accepted_offset') != size
            or cp.get('dev') != value['source']['dev'] or cp.get('ino') != value['source']['ino']
            or value.get('physical_size') != size + value['files']['unaccepted-tail.bin']['bytes']):
        raise Hold('Inconsistent snapshot checkpoint')
    fd = _open(bundle / 'accepted.ndjson')
    try:
        if size and os.pread(fd, 1, size - 1) != b'\n':
            raise Hold('Snapshot accepted prefix is incomplete')
    finally:
        os.close(fd)
    return value, digest


def snapshot(root, destination, max_bytes=2 * 1024 * 1024):
    with operation(root), data_lock(root) as fd:
        maintenance_guard(root)
        return _capture(root, fd, destination, max_bytes)


def _fence(root, op):
    if _read(Path(root) / FENCE).get('operation') != op:
        raise Hold('Unexpected maintenance fence')


def _finish(root, journal, fd, fault):
    """POSTCOMMIT: NEVER writes, truncates, replaces or rebinds the data/checkpoint pair."""
    info, offset = _pair(root, fd)
    base = journal['baseline']
    if (not isinstance(base, dict) or type(base.get('length')) is not int or base['length'] < 0
            or not isinstance(base.get('sha256'), str) or not re.fullmatch('[0-9a-f]{64}', base['sha256'])):
        raise Hold('Invalid committed baseline')
    if ((info.st_dev, info.st_ino) != (base['dev'], base['ino']) or offset < base['length']
            or _prefix(fd, base['length']) != base['sha256']):
        raise Hold('Current generation is not an admissible post-commit extension')
    if os.path.lexists(Path(root) / FENCE):
        _fence(root, journal['operation'])
        (Path(root) / FENCE).unlink()
        _sync(root)
    fault('after_unfence')
    journal = {**journal, 'phase': 'COMPLETE', 'observed_offset': offset}
    _json(Path(root) / JOURNAL, journal)
    return journal


def _install(root, journal, bundle, digest, fault):
    root = Path(root)
    _precommit(journal)
    value, _ = verify(bundle, digest)
    _fence(root, journal['operation'])
    stage = root / ('.restore-data-' + secrets.token_hex(8))
    src = _open(Path(bundle) / 'accepted.ndjson')
    try:
        _copy(src, 0, value['accepted_offset'], stage)
    finally:
        os.close(src)
    fd = _open(stage)
    try:
        info = os.fstat(fd)
        cp = {'schema': 'mc.fabric.commit/1', 'dev': info.st_dev, 'ino': info.st_ino, 'offset': info.st_size}
    finally:
        os.close(fd)
    staged_cp = stage.with_name(stage.name + '.checkpoint')
    _json(staged_cp, cp)
    _json(root / JOURNAL, {**journal, 'phase': 'PRECOMMIT'})
    os.replace(stage, root / DATA)
    fault('after_data_replace')
    os.replace(staged_cp, root / CHECKPOINT)
    _sync(root)
    with data_lock(root) as fd:
        info, offset = _pair(root, fd)
        sha = _prefix(fd, offset)
        if offset != value['accepted_offset'] or sha != value['files']['accepted.ndjson']['sha256']:
            raise Hold('Restored pair verification failed')
        journal = {**journal, 'phase': 'REOPEN_COMMITTED', 'baseline':
                   {'dev': info.st_dev, 'ino': info.st_ino, 'length': offset, 'sha256': sha}}
        _json(root / JOURNAL, journal)  # durable irreversible point BEFORE un-fence
        fault('after_commit')
        return _finish(root, journal, fd, fault)


def restore(root, bundle, preimage, *, operation_id, expected, quiesced=False, fault=lambda stage: None):
    """Explicit offline maintenance API; callers/main must quiesce the service. Not exposed by the web app."""
    if not quiesced:
        raise Hold('Main-authorized quiesced maintenance required')
    if (not isinstance(operation_id, str) or not re.fullmatch('[A-Za-z0-9_-]{1,64}', operation_id)
            or not isinstance(expected, str) or not re.fullmatch('[0-9a-f]{64}', expected)):
        raise Hold('Explicit bounded operation ID and expected digest required')
    _, digest = verify(bundle, expected)
    root, bundle, preimage = Path(root), Path(bundle), Path(preimage)
    with operation(root):
        maintenance_guard(root)
        if (root / JOURNAL).exists() and _read(root / JOURNAL).get('phase') != 'COMPLETE':
            raise Hold('Prior operation must be reconciled first')
        fd = _open(root / FENCE, os.O_WRONLY | os.O_CREAT | os.O_EXCL)
        try:
            os.write(fd, json.dumps({'operation': operation_id}).encode())
            os.fsync(fd)
        finally:
            os.close(fd)
        _sync(root)
        journal = {'schema': 'mc.fabric.operation/1', 'operation': operation_id, 'phase': 'FENCED',
                   'selected': str(bundle), 'selected_sha256': digest, 'preimage': str(preimage)}
        _json(root / JOURNAL, journal)
        with data_lock(root) as fd:
            pre_sha = _capture(root, fd, preimage)
            journal = {**journal, 'phase': 'PRECOMMIT', 'preimage_sha256': pre_sha}
            _json(root / JOURNAL, journal)
            return _install(root, journal, bundle, digest, fault)


def recover(root, *, operation_id, abort=False, quiesced=False, fault=lambda stage: None):
    root = Path(root)
    with operation(root):
        journal = _read(root / JOURNAL)
        if not isinstance(journal, dict) or journal.get('schema') != 'mc.fabric.operation/1' or journal.get('operation') != operation_id:
            raise Hold('Unknown operation')
        if journal.get('phase') in POSTCOMMIT:
            if abort:
                raise Hold('COMMITTED_NEW_OPERATION_REQUIRED')
            with data_lock(root) as fd:
                return _finish(root, journal, fd, fault)
        if not quiesced:
            raise Hold('Quiesced precommit recovery required')
        _precommit(journal)
        _fence(root, operation_id)  # absence is HOLD, never permission to re-fence/rewind
        with data_lock(root):
            if not journal.get('preimage_sha256'):
                raise Hold('Preimage not verified; main must reconcile before recovery')
            field = 'preimage' if abort else 'selected'
            journal = {**journal, 'outcome': 'aborted' if abort else 'restored'}
            return _install(root, journal, journal[field], journal[field + '_sha256'], fault)


def _precommit(journal):
    """Destructive replacement has one explicit phase; unknown versions always HOLD."""
    if (not isinstance(journal, dict) or journal.get('schema') != 'mc.fabric.operation/1'
            or journal.get('phase') != 'PRECOMMIT' or not isinstance(journal.get('operation'), str)
            or not re.fullmatch('[A-Za-z0-9_-]{1,64}', journal['operation'])):
        raise Hold('Validated PRECOMMIT journal required for replacement')
    for field in ('selected', 'preimage'):
        digest = journal.get(field + '_sha256')
        if (not isinstance(journal.get(field), str) or not journal[field]
                or not isinstance(digest, str) or not re.fullmatch('[0-9a-f]{64}', digest)):
            raise Hold('Verified selected bundle and preimage required')
        verify(journal[field], digest)
