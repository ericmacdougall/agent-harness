"""Bounded source-Git preflight and controlled Git subprocess environment.

This is a fail-closed guard for known Git execution paths, not an OS sandbox.
User-global authentication and remote helpers remain trusted by delivery helpers.
"""

import os
import hashlib
import re
import selectors
import signal
import subprocess
import time
import stat
import tempfile
import json
from dataclasses import dataclass
from pathlib import Path

from process import signal_group


# Closed preservation policy. No CLI/environment budget overrides.
PRESERVE_ENTRIES = 4096
PRESERVE_VISITS = 20000
PRESERVE_DEPTH = 24
PRESERVE_NAMES = 2_000_000
PRESERVE_MANIFEST = 8_000_000
PRESERVE_SECONDS = 15


def _preserve_path(value):
    if (not isinstance(value, str) or not value or len(value) > 1024
            or not value.isascii() or any(ord(c) < 32 or ord(c) == 127 for c in value)
            or any(p in ('', '.', '..') for p in value.split('/')) or value.startswith('/')):
        raise OSError('preservation path policy refused')
    return value


def _preserve_json(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')


def _preserve_stat(info, *, ancestor=False):
    basic = [info.st_dev, info.st_ino, info.st_mode, info.st_uid]
    return basic if ancestor else basic + [info.st_nlink, info.st_size, info.st_mtime_ns, info.st_ctime_ns]


def _preserve_directory(path):
    """Open each path component without following aliases; caller owns returned FD."""
    path = Path(path)
    if not path.is_absolute() or '..' in path.parts:
        raise OSError('preservation directory is not canonical')
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:]:
            nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = nxt
        return fd
    except BaseException:
        os.close(fd)
        raise


def _preserve_git(repo, args, deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise OSError('preservation metadata deadline exceeded')
    code, raw = _bounded_git(repo, args, git_environment(), timeout=remaining, limit=PRESERVE_NAMES)
    if code:
        raise OSError('preservation Git metadata unavailable')
    return raw


def _preserve_scan(repo, *, anchors=None):
    """Enumerate metadata only, including ignored data and empty directories."""
    deadline = time.monotonic() + PRESERVE_SECONDS
    require_safe_source(repo, git_environment(), deadline=deadline)
    raw = _preserve_git(repo, ['ls-files', '-z'], deadline)
    try:
        tracked = {_preserve_path(p.decode('ascii')) for p in raw.split(b'\0') if p}
    except UnicodeError:
        raise OSError('preservation indexed path policy refused') from None
    shared = {''}
    for path in tracked:
        parts = path.split('/')
        shared.update('/'.join(parts[:i]) for i in range(1, len(parts)))
    if anchors is not None:
        shared.update(anchors)
    records, directories = [], []
    visits, names = 0, 0
    root_fd = _preserve_directory(repo)
    root_info = os.fstat(root_fd)

    def tick():
        if time.monotonic() > deadline:
            raise OSError('preservation metadata deadline exceeded')

    def safe(info):
        if (info.st_uid != os.getuid() or info.st_dev != root_info.st_dev
                or info.st_mode & 0o022):
            raise OSError('preservation ownership, mode or device refused')

    def walk(fd, prefix, depth):
        nonlocal visits, names
        tick()
        if depth > PRESERVE_DEPTH:
            raise OSError('preservation depth budget exceeded')
        before = os.fstat(fd)
        safe(before)
        directories.append([prefix, 'a' if prefix in shared else 'd', _preserve_stat(before)])
        if prefix and prefix not in shared and len(records) + len(directories) > PRESERVE_ENTRIES + len(shared):
            raise OSError('preservation entry budget exceeded')
        entries = []
        with os.scandir(fd) as scan:
            for entry in scan:
                tick()
                visits += 1
                if visits > PRESERVE_VISITS:
                    raise OSError('preservation visited-entry budget exceeded')
                entries.append(entry.name)
        for name in sorted(entries):
            tick()
            if not prefix and name == '.git':
                continue  # verified root Git administrative boundary only
            path = name if not prefix else prefix + '/' + name
            _preserve_path(path)
            names += len(path) + 1
            if names > PRESERVE_NAMES:
                raise OSError('preservation path-list budget exceeded')
            if path in tracked:
                continue
            if prefix in shared and name.lower() in ('.gitattributes', '.gitignore', '.gitmodules'):
                # Do not let a later Git inspection interpret an unknown
                # worktree control file as configuration/attribute content.
                raise OSError('preservation untracked Git control file refused')
            info = os.stat(name, dir_fd=fd, follow_symlinks=False)
            safe(info)
            if stat.S_ISDIR(info.st_mode):
                child = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
                try:
                    if _preserve_stat(os.fstat(child)) != _preserve_stat(info):
                        raise OSError('preservation directory changed before inspection')
                    walk(child, path, depth + 1)
                finally:
                    os.close(child)
            elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
                records.append([path, 'f', _preserve_stat(info)])
                if len(records) > PRESERVE_ENTRIES:
                    raise OSError('preservation entry budget exceeded')
            else:
                raise OSError('preservation file type or hardlink refused')
        if _preserve_stat(os.fstat(fd)) != _preserve_stat(before):
            raise OSError('preservation directory changed during inspection')

    try:
        walk(root_fd, '', 0)
        if _preserve_stat(os.fstat(root_fd)) != _preserve_stat(root_info):
            raise OSError('preservation root changed during inspection')
    finally:
        os.close(root_fd)
    if _preserve_git(repo, ['status', '--porcelain=v1', '-z', '--untracked-files=no'], deadline):
        raise OSError('preservation requires clean tracked files')
    full = records + [d for d in directories if d[1] == 'd']
    if len(full) > PRESERVE_ENTRIES:
        raise OSError('preservation entry budget exceeded')
    relevant = {''}
    for path, _, _ in full:
        parts = path.split('/')
        relevant.update('/'.join(parts[:i]) for i in range(1, len(parts)))
    result = full + [[p, 'a', meta[:4]] for p, kind, meta in directories if kind == 'a' and p in relevant]
    result.sort(key=lambda r: r[0])
    tick()
    return result


@dataclass(frozen=True)
class UntrackedPreservation:
    """Validated immutable metadata proof, never a generic allow-dirty capability."""
    raw: bytes

    def __post_init__(self):
        if type(self.raw) is not bytes or len(self.raw) > PRESERVE_MANIFEST:
            raise OSError('preservation manifest budget refused')
        try:
            d = json.loads(self.raw)
            fields = {'schema', 'policy', 'original', 'branch', 'baseline', 'source', 'source_head',
                      'original_layout', 'source_layout', 'entries'}
            if (type(d) is not dict or set(d) != fields or d['schema'] != 1 or type(d['schema']) is not int
                    or d['policy'] != 'metadata-ascii-v1' or _preserve_json(d) != self.raw
                    or any(not isinstance(d[k], str) or not Path(d[k]).is_absolute() for k in ('original', 'source'))
                    or not isinstance(d['branch'], str) or not d['branch'] or len(d['branch']) > 1024
                    or any(not isinstance(d[k], str) or not re.fullmatch(r'[0-9a-f]{40}|[0-9a-f]{64}', d[k])
                           for k in ('baseline', 'source_head'))
                    or any(not isinstance(d[k], str) or not (d[k] == 'ordinary' or re.fullmatch(r'[0-9a-f]{64}', d[k]))
                           for k in ('original_layout', 'source_layout'))
                    or type(d['entries']) is not list or len(d['entries']) > PRESERVE_VISITS):
                raise ValueError
            previous = None
            full = 0
            for record in d['entries']:
                if type(record) is not list or len(record) != 3:
                    raise ValueError
                path, kind, meta = record
                if path != '':
                    _preserve_path(path)
                if (not isinstance(path, str) or previous is not None and previous >= path
                        or kind not in ('a', 'd', 'f') or path == '' and kind != 'a'
                        or type(meta) is not list or len(meta) != (4 if kind == 'a' else 8)
                        or any(type(n) is not int or n < 0 or n > 2**64-1 for n in meta)
                        or meta[3] != os.getuid() or meta[2] & 0o022
                        or not (stat.S_ISREG(meta[2]) if kind == 'f' else stat.S_ISDIR(meta[2]))
                        or kind == 'f' and meta[4] != 1):
                    raise ValueError
                previous = path
                full += kind != 'a'
            if not d['entries'] or d['entries'][0][:2] != ['', 'a'] or full > PRESERVE_ENTRIES:
                raise ValueError
        except (ValueError, TypeError, KeyError, UnicodeError, RecursionError):
            raise OSError('preservation manifest schema refused') from None

    @property
    def data(self):
        return json.loads(self.raw)

    @property
    def digest(self):
        return hashlib.sha256(self.raw).hexdigest()

    @classmethod
    def capture(cls, original, branch, baseline, source, head):
        deadline = time.monotonic() + PRESERVE_SECONDS
        original, source = Path(original), Path(source)
        for repo, expected in ((original, baseline), (source, head)):
            if str(repo) != str(repo.resolve()) or _preserve_git(repo, ['rev-parse', 'HEAD'], deadline).decode().strip() != expected:
                raise OSError('preservation checkout identity refused')
        if _preserve_git(original, ['symbolic-ref', '--short', 'HEAD'], deadline).decode().strip() != branch:
            raise OSError('preservation branch refused')
        d = {'schema': 1, 'policy': 'metadata-ascii-v1', 'original': str(original), 'branch': branch,
             'baseline': baseline, 'source': str(source), 'source_head': head,
             'original_layout': require_safe_source(original, git_environment(), deadline=deadline),
             'source_layout': require_safe_source(source, git_environment(), deadline=deadline),
             'entries': _preserve_scan(original)}
        proof = cls(_preserve_json(d))
        proof.check_target(source, head)
        proof.verify(original, branch)
        return proof

    def binds(self, original, branch, baseline, source, head):
        d = self.data
        return (d['original'], d['branch'], d['baseline'], d['source'], d['source_head']) == (
            str(original), branch, baseline, str(source), head)

    def verify(self, original, branch):
        d = self.data
        if (str(original) != d['original'] or branch != d['branch']
                or require_safe_source(Path(original), git_environment(), timeout=PRESERVE_SECONDS) != d['original_layout']
                or _preserve_scan(Path(original), anchors={p for p, k, _ in d['entries'] if k == 'a'}) != d['entries']):
            raise OSError('preservation inventory changed')

    def check_target(self, repo, target):
        deadline = time.monotonic() + PRESERVE_SECONDS
        raw = _preserve_git(Path(repo), ['ls-tree', '-rz', target], deadline)
        paths, ancestors = set(), set()
        for record in raw.split(b'\0'):
            if not record:
                continue
            try:
                info, name = record.split(b'\t', 1)
                if info.split()[1] != b'blob':
                    raise OSError('preservation target type refused')
                p = _preserve_path(name.decode('ascii')).lower()
            except (ValueError, UnicodeError, IndexError):
                raise OSError('preservation target path refused') from None
            paths.add(p)
            parts = p.split('/')
            ancestors.update('/'.join(parts[:i]) for i in range(1, len(parts)))
        for p, kind, _ in self.data['entries']:
            if kind == 'a':
                continue
            p = p.lower()
            parts = p.split('/')
            if p in paths or p in ancestors or any('/'.join(parts[:i]) in paths for i in range(1, len(parts))):
                raise OSError('preservation target collision refused')
        if time.monotonic() > deadline:
            raise OSError('preservation target deadline exceeded')

    def write(self, path):
        path = Path(path)
        parent = _preserve_directory(path.parent)
        try:
            s = os.fstat(parent)
            if s.st_uid != os.getuid() or stat.S_IMODE(s.st_mode) != 0o700:
                raise OSError('preservation manifest directory is not private')
            fd = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=parent)
            with os.fdopen(fd, 'wb') as f:
                f.write(self.raw)
                f.flush()
                os.fsync(f.fileno())
            os.fsync(parent)
        finally:
            os.close(parent)

    @classmethod
    def load(cls, path, digest):
        if not isinstance(digest, str) or not re.fullmatch(r'[0-9a-f]{64}', digest):
            raise OSError('preservation manifest digest refused')
        path = Path(path)
        parent = _preserve_directory(path.parent)
        try:
            s = os.fstat(parent)
            if s.st_uid != os.getuid() or stat.S_IMODE(s.st_mode) != 0o700:
                raise OSError('preservation manifest directory is not private')
            fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=parent)
            with os.fdopen(fd, 'rb') as f:
                before = os.fstat(f.fileno())
                if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid() or before.st_nlink != 1
                        or stat.S_IMODE(before.st_mode) != 0o600 or before.st_size > PRESERVE_MANIFEST):
                    raise OSError('preservation manifest file refused')
                raw = f.read(PRESERVE_MANIFEST + 1)
                named = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
                if (_preserve_stat(os.fstat(f.fileno())) != _preserve_stat(before)
                        or _preserve_stat(named) != _preserve_stat(before)):
                    raise OSError('preservation manifest changed during read')
        finally:
            os.close(parent)
        result = cls(raw)
        if result.digest != digest:
            raise OSError('preservation manifest digest changed')
        return result


AUTH_GIT_ENV = {'GIT_ASKPASS', 'GIT_SSH', 'GIT_SSH_COMMAND', 'GIT_SSH_VARIANT',
                'GIT_CONFIG_GLOBAL', 'GIT_CONFIG_SYSTEM', 'GIT_CONFIG_NOSYSTEM'}
IDENTITY_GIT_ENV = {'GIT_AUTHOR_NAME', 'GIT_AUTHOR_EMAIL', 'GIT_AUTHOR_DATE',
                    'GIT_COMMITTER_NAME', 'GIT_COMMITTER_EMAIL', 'GIT_COMMITTER_DATE'}
BASE_SETTINGS = (('core.hooksPath', os.devnull), ('core.fsmonitor', 'false'),
                 ('core.filemode', 'true'), ('core.symlinks', 'true'),
                 ('core.untrackedCache', 'false'),
                 ('core.trustctime', 'true'), ('core.checkStat', 'default'),
                 ('commit.gpgsign', 'false'), ('tag.gpgsign', 'false'))
FILTER_PATTERN = r'^filter\..*\.(clean|process|smudge)$'
SITES_CONFIG_KEYS = frozenset(
    f'{section}.{scope}.{option}'
    for scope in ('https://chatgpt.com/backend-api/codex/sites/git/',
                  'https://chatgpt-staging.com/backend-api/codex/sites/git/')
    for section, option in (('credential', 'helper'), ('credential', 'useHttpPath'),
                            ('http', 'proactiveAuth'), ('http', 'followRedirects'))
)


def unsupported_git_environment(environment, allowed_names):
    """Admit only the complete, bounded official Sites metadata family.

    Indexed values may contain credentials or executable helpers: do not read
    them. Admission grants no configuration authority. git_environment drops
    this entire family before building helper-owned Git subprocess settings.
    """
    names = set(environment)
    if any(not isinstance(name, str) for name in names):
        return True
    git_names = {name for name in names if name.startswith('GIT_')}
    indexed = {name for name in git_names if name == 'GIT_CONFIG_COUNT'
               or name.startswith(('GIT_CONFIG_KEY_', 'GIT_CONFIG_VALUE_'))}
    if not indexed:
        return bool(git_names - set(allowed_names))
    count = environment.get('GIT_CONFIG_COUNT')
    if not isinstance(count, str) or not re.fullmatch(r'0|[1-9][0-9]?', count) or int(count) > 20:
        return True
    expected = {'GIT_CONFIG_COUNT'}
    for index in range(int(count)):
        expected.update((f'GIT_CONFIG_KEY_{index}', f'GIT_CONFIG_VALUE_{index}'))
    if indexed != expected or git_names - set(allowed_names) - expected:
        return True
    for index in range(int(count)):
        key = environment[f'GIT_CONFIG_KEY_{index}']
        if not isinstance(key, str) or key not in SITES_CONFIG_KEYS:
            return True
    return False


def git_environment(*, isolated=False, allow_hooks=False, preserve_identity=False,
                    settings=()):
    """Drop ambient Git routing/index state while composing deliberate settings.

    Scratch integration executes merge and commit hooks under a deadline and
    honors caller-provided commit identity. The original fast-forward and
    helper metadata updates keep hooks disabled.
    """
    retained = set() if isolated else AUTH_GIT_ENV | (IDENTITY_GIT_ENV if preserve_identity else set())
    env = {key: value for key, value in os.environ.items()
           if not key.startswith('GIT_') or key in retained}
    env['GIT_TERMINAL_PROMPT'] = '0'
    env['GIT_NO_REPLACE_OBJECTS'] = '1'
    env['GIT_NO_LAZY_FETCH'] = '1'
    if isolated:
        env['GIT_CONFIG_NOSYSTEM'] = '1'
        env['GIT_CONFIG_GLOBAL'] = os.devnull
    configured = (*(item for item in BASE_SETTINGS if not allow_hooks or item[0] != 'core.hooksPath'),
                  *settings)
    env['GIT_CONFIG_COUNT'] = str(len(configured))
    for index, (key, value) in enumerate(configured):
        env[f'GIT_CONFIG_KEY_{index}'] = key
        env[f'GIT_CONFIG_VALUE_{index}'] = value
    return env


def _bounded_git(repo: Path, args: list[str], env: dict[str, str], *, timeout: int,
                 limit: int, input_file=None, reject_stderr=False) -> tuple[int, bytes]:
    """Bound metadata output and time without exposing path/config values in errors."""
    command = ['git', '-C', str(repo), *args]
    process = subprocess.Popen(command, env=env, stdin=input_file or subprocess.DEVNULL,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE if reject_stderr else subprocess.DEVNULL,
                               start_new_session=True)
    data = bytearray()
    deadline = time.monotonic() + timeout
    finished = False
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            if reject_stderr:
                selector.register(process.stderr, selectors.EVENT_READ)
            open_streams = 2 if reject_stderr else 1
            while True:
                remaining = deadline - time.monotonic()
                ready = selector.select(max(0, remaining))
                if remaining <= 0 or not ready:
                    raise OSError('source Git metadata inspection timed out')
                for key, _ in ready:
                    chunk = os.read(key.fd, min(65536, limit + 1 - len(data)))
                    if not chunk:
                        selector.unregister(key.fileobj)
                        open_streams -= 1
                    elif key.fileobj is process.stderr:
                        raise OSError('source Git sparse metadata emitted a warning')
                    else:
                        data.extend(chunk)
                    if len(data) > limit:
                        raise OSError('source Git metadata exceeded size budget')
                if not open_streams:
                    break
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise OSError('source Git metadata inspection timed out')
        code = process.wait(timeout=remaining)
        finished = True
        return code, bytes(data)
    except subprocess.TimeoutExpired as error:
        raise OSError('source Git metadata inspection timed out') from error
    finally:
        if not finished:
            signal_group(process.pid, signal.SIGKILL)
            process.wait()
        process.stdout.close()
        if reject_stderr:
            process.stderr.close()


def _sparse_settings(repo, env, budget):
    values = []
    for key, default in (('core.sparseCheckout', b'false'),
                         ('core.sparseCheckoutCone', b'false'),
                         ('index.sparse', b'false'), ('core.ignoreCase', b'false')):
        code, data = _bounded_git(repo, ['config', '--type=bool', '--get', key], env,
                                  timeout=budget(), limit=32)
        if code == 1 and not data:
            data = default
        elif code or data not in (b'true\n', b'false\n'):
            raise OSError('source Git sparse configuration is invalid')
        values.append(data.strip())
    return tuple(values)


def _safe_components(path):
    parts = path.split(b'/')
    if not parts or any(p in (b'', b'.', b'..') or b'\0' in p for p in parts):
        raise OSError('source Git sparse path is unsafe')
    return parts


def _sparse_rules(repo, env, budget):
    code, name = _bounded_git(repo, ['rev-parse', '--git-path', 'info/sparse-checkout'],
                              env, timeout=budget(), limit=16384)
    if code or not name.endswith(b'\n') or b'\n' in name[:-1]:
        raise OSError('source Git sparse rules path is unverifiable')
    path = Path(os.fsdecode(name[:-1]))
    if not path.is_absolute(): path = repo / path
    # Metadata ancestors, as well as the leaf, must be physical directories.
    parent = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in path.parts[1:-1]:
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
            os.close(parent)
            parent = child
        fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    finally:
        os.close(parent)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > 1_000_000:
            raise OSError('source Git sparse rules exceed limits')
        data = os.read(fd, 1_000_001)
        after = os.fstat(fd)
        identity = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
        if identity(info) != identity(after) or len(data) != info.st_size:
            raise OSError('source Git sparse rules changed')
        return data, identity(info)
    finally:
        os.close(fd)


def _validate_sparse_rules(data, cone):
    if not data or not data.endswith(b'\n') or any(x < 32 and x != 10 for x in data):
        raise OSError('source Git sparse rules are unsupported')
    lines = data.splitlines()
    if cone:
        if lines[:2] != [b'/*', b'!/*/']:
            raise OSError('source Git cone rules are not canonical')
        positive, parent = set(), set()
        for line in lines[2:]:
            negative = line.startswith(b'!')
            value = line[1:] if negative else line
            if negative:
                if not value.endswith(b'/*/'):
                    raise OSError('source Git cone rules are not canonical')
                value = value[:-2]
            if not value.startswith(b'/') or not value.endswith(b'/'):
                raise OSError('source Git cone rules are not canonical')
            path = value[1:-1]
            _safe_components(path)
            if any(x in path for x in (b'*', b'?', b'[', b']', b'\\', b'!')):
                raise OSError('source Git cone rules are unsupported')
            (parent if negative else positive).add(path)
        recursive = positive - parent
        ancestors = set()
        for path in recursive:
            parts = path.split(b'/')
            ancestors.update(b'/'.join(parts[:i]) for i in range(1, len(parts)))
        if ancestors & recursive or parent != ancestors:
            raise OSError('source Git cone rules are not canonical')
        canonical = [b'/*', b'!/*/']
        for path in sorted(ancestors):
            canonical.append(b'/' + path + b'/')
            canonical.append(b'!/' + path + b'/*/')
        canonical.extend(b'/' + path + b'/' for path in sorted(recursive))
        if lines != canonical:
            raise OSError('source Git cone rules are not canonical')
    else:
        for line in lines:
            if not line.startswith(b'/'):
                raise OSError('source Git sparse rules are unsupported')
            path = line[1:].removesuffix(b'/')
            _safe_components(path)
            if any(x in path for x in (b'?', b'[', b']', b'\\', b'!', b'**')):
                raise OSError('source Git sparse rules are unsupported')
            if b'*' in path and (path.count(b'*') != 1 or
                    not re.fullmatch(rb'\*\.[A-Za-z0-9_-]+', path.split(b'/')[-1])):
                raise OSError('source Git sparse rules are unsupported')


def _absent_sparse_paths(repo, paths, budget):
    root = os.open(repo, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for path in paths:
            budget()
            parts = _safe_components(path)
            current = os.dup(root)
            try:
                for i, part in enumerate(parts):
                    try:
                        info = os.stat(part, dir_fd=current, follow_symlinks=False)
                    except FileNotFoundError:
                        break
                    if i == len(parts) - 1 or not stat.S_ISDIR(info.st_mode):
                        raise OSError('source Git skipped path is physically present or unsafe')
                    child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                                    dir_fd=current)
                    observed = os.fstat(child)
                    if (info.st_dev, info.st_ino) != (observed.st_dev, observed.st_ino):
                        os.close(child)
                        raise OSError('source Git skipped ancestor changed')
                    os.close(current)
                    current = child
            finally:
                os.close(current)
    finally:
        os.close(root)


def _prove_sparse(repo, env, budget, settings, index, flags):
    if settings[0] != b'true' or settings[2] != b'false':
        raise OSError('source Git sparse mode is unsupported')
    rules, identity = _sparse_rules(repo, env, budget)
    _validate_sparse_rules(rules, settings[1] == b'true')
    stages = {}
    for record in index.split(b'\0')[:-1]:
        header, path = record.split(b'\t', 1)
        if (len(record) > 1_000_000 or header.split()[0] not in (b'100644', b'100755', b'120000')
                or not re.fullmatch(rb'[0-9]{6} (?:[0-9a-f]{40}|[0-9a-f]{64}) 0', header)
                or path in stages):
            raise OSError('source Git sparse index is unsupported')
        _safe_components(path)
        stages[path] = header
    tagged = {}
    for record in flags.split(b'\0')[:-1]:
        if record[2:] in tagged:
            raise OSError('source Git sparse index flags are duplicated')
        tagged[record[2:]] = record[:1]
    if stages.keys() != tagged.keys():
        raise OSError('source Git sparse index listings disagree')
    skipped = {p for p, tag in tagged.items() if tag == b'S'}
    included = set(tagged) - skipped
    with tempfile.TemporaryFile() as input_file, tempfile.NamedTemporaryFile() as frozen:
        input_file.write(b'\0'.join(tagged) + (b'\0' if tagged else b''))
        frozen.write(rules)
        frozen.flush()
        for options in ([], ['--no-cone', '--rules-file', frozen.name]):
            input_file.seek(0)
            code, matched = _bounded_git(repo, ['sparse-checkout', 'check-rules', '-z', *options],
                env, timeout=budget(), limit=40_000_000, input_file=input_file, reject_stderr=True)
            records = matched.split(b'\0')[:-1] if matched.endswith(b'\0') else []
            if (code or (matched and not matched.endswith(b'\0')) or
                    len(records) != len(set(records)) or set(records) != included):
                raise OSError('source Git sparse rules and index disagree')
    _absent_sparse_paths(repo, skipped, budget)
    if _sparse_settings(repo, env, budget) != settings or _sparse_rules(repo, env, budget) != (rules, identity):
        raise OSError('source Git sparse configuration changed')
    for args, expected in ((['ls-files', '--stage', '-z'], index), (['ls-files', '-v', '-z'], flags)):
        code, observed = _bounded_git(repo, args, env, timeout=budget(), limit=40_000_000)
        if code or observed != expected:
            raise OSError('source Git sparse index changed')
    _absent_sparse_paths(repo, skipped, budget)
    return hashlib.sha256(b'\0'.join(settings) + b'\0' + rules).hexdigest()


def require_safe_source(repo: Path, env: dict[str, str], *, timeout: int = 5,
                        allow_unmerged: bool = False, deadline=None) -> str:
    """Refuse hidden index state, submodules and local filters before status/diff/add.

    Source configuration can still change after this preflight. Caller must repeat
    the guard at later worktree inspection boundaries and disclose that race.
    An abort may inspect unmerged (M-tagged) index entries after a failed merge.
    """
    deadline = min(deadline, time.monotonic() + timeout) if deadline is not None else time.monotonic() + timeout
    def budget():
        remaining = timeout if deadline is None else min(timeout, deadline - time.monotonic())
        if remaining <= 0:
            raise OSError('source Git metadata inspection deadline exceeded')
        return remaining
    settings = _sparse_settings(repo, env, budget)
    if settings[2] == b'true':
        raise OSError('source Git sparse directory index is unsupported')
    code, index = _bounded_git(repo, ['ls-files', '--stage', '-z'], env,
                               timeout=budget(), limit=40_000_000)
    if code or (index and not index.endswith(b'\0')):
        raise OSError('source Git index could not be inspected safely')
    count = 0
    for record in index.split(b'\0'):
        if not record:
            continue
        count += 1
        if count % 1024 == 0:
            budget()
        if count > 250_000 or not re.match(rb'^[0-9]{6} [0-9a-f]{40,64} [0-3]\t', record):
            raise OSError('source Git index is malformed or exceeds limits')
        if record.startswith(b'160000 '):
            raise OSError('source Git index contains a submodule')
    code, flags = _bounded_git(repo, ['ls-files', '-v', '-z'], env,
                               timeout=budget(), limit=40_000_000)
    if code or (flags and not flags.endswith(b'\0')):
        raise OSError('source Git index flags could not be inspected safely')
    count = 0
    for record in flags.split(b'\0'):
        if not record:
            continue
        count += 1
        if count % 1024 == 0:
            budget()
        if (count > 250_000 or len(record) < 3
                or record[:2] not in ((b'H ', b'M ', b'S ') if allow_unmerged else (b'H ', b'S '))):
            raise OSError('source Git index has hidden or unsupported flags (%r)' % record[:1].decode('ascii', 'replace'))
    code, config = _bounded_git(repo, ['config', '--includes', '--show-scope',
                                      '--name-only', '--null', '--get-regexp', FILTER_PATTERN],
                                env, timeout=budget(), limit=1_000_000)
    if code not in (0, 1) or (code == 1 and config) or (config and not config.endswith(b'\0')):
        raise OSError('source Git filter configuration could not be inspected safely')
    fields = config.split(b'\0')[:-1] if config else []
    if len(fields) % 2:
        raise OSError('source Git filter configuration was malformed')
    for scope, key in zip(fields[::2], fields[1::2]):
        budget()
        if not key.startswith(b'filter.'):
            raise OSError('source Git filter configuration was malformed')
        if scope in (b'local', b'worktree'):
            raise OSError('source Git has an executable local filter')
    if settings[0] == b'true' or any(r.startswith(b'S ') for r in flags.split(b'\0')):
        return _prove_sparse(repo, env, budget, settings, index, flags)
    budget()
    return 'ordinary'
