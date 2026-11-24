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
from pathlib import Path

from process import signal_group


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
