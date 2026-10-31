"""Bounded source-Git preflight and controlled Git subprocess environment.

This is a fail-closed guard for known Git execution paths, not an OS sandbox.
User-global authentication and remote helpers remain trusted by delivery helpers.
"""

import os
import re
import selectors
import signal
import subprocess
import time
from pathlib import Path

from process import signal_group


AUTH_GIT_ENV = {'GIT_ASKPASS', 'GIT_SSH', 'GIT_SSH_COMMAND', 'GIT_SSH_VARIANT',
                'GIT_CONFIG_GLOBAL', 'GIT_CONFIG_SYSTEM', 'GIT_CONFIG_NOSYSTEM'}
BASE_SETTINGS = (('core.hooksPath', os.devnull), ('core.fsmonitor', 'false'),
                 ('core.filemode', 'true'), ('core.untrackedCache', 'false'),
                 ('core.trustctime', 'true'), ('core.checkStat', 'default'),
                 ('commit.gpgsign', 'false'), ('tag.gpgsign', 'false'))
FILTER_PATTERN = r'^filter\..*\.(clean|process|smudge)$'


def git_environment(*, isolated=False, settings=()):
    """Drop ambient Git routing/index state while composing deliberate settings."""
    retained = set() if isolated else AUTH_GIT_ENV
    env = {key: value for key, value in os.environ.items()
           if not key.startswith('GIT_') or key in retained}
    env['GIT_TERMINAL_PROMPT'] = '0'
    env['GIT_NO_REPLACE_OBJECTS'] = '1'
    env['GIT_NO_LAZY_FETCH'] = '1'
    if isolated:
        env['GIT_CONFIG_NOSYSTEM'] = '1'
        env['GIT_CONFIG_GLOBAL'] = os.devnull
    configured = (*BASE_SETTINGS, *settings)
    env['GIT_CONFIG_COUNT'] = str(len(configured))
    for index, (key, value) in enumerate(configured):
        env[f'GIT_CONFIG_KEY_{index}'] = key
        env[f'GIT_CONFIG_VALUE_{index}'] = value
    return env


def _bounded_git(repo: Path, args: list[str], env: dict[str, str], *, timeout: int,
                 limit: int) -> tuple[int, bytes]:
    """Bound metadata output and time without exposing path/config values in errors."""
    command = ['git', '-C', str(repo), *args]
    process = subprocess.Popen(command, env=env, stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL, start_new_session=True)
    data = bytearray()
    deadline = time.monotonic() + timeout
    finished = False
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not selector.select(remaining):
                    raise OSError('source Git metadata inspection timed out')
                chunk = os.read(process.stdout.fileno(), min(65536, limit + 1 - len(data)))
                if not chunk:
                    break
                data.extend(chunk)
                if len(data) > limit:
                    raise OSError('source Git metadata exceeded size budget')
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


def require_safe_source(repo: Path, env: dict[str, str], *, timeout: int = 5) -> None:
    """Refuse hidden index state, submodules and local filters before status/diff/add.

    Source configuration can still change after this preflight. Caller must repeat
    the guard at later worktree inspection boundaries and disclose that race.
    """
    code, index = _bounded_git(repo, ['ls-files', '--stage', '-z'], env,
                               timeout=timeout, limit=40_000_000)
    if code or (index and not index.endswith(b'\0')):
        raise OSError('source Git index could not be inspected safely')
    count = 0
    for record in index.split(b'\0'):
        if not record:
            continue
        count += 1
        if count > 250_000 or not re.match(rb'^[0-9]{6} [0-9a-f]{40,64} [0-3]\t', record):
            raise OSError('source Git index is malformed or exceeds limits')
        if record.startswith(b'160000 '):
            raise OSError('source Git index contains a submodule')
    code, flags = _bounded_git(repo, ['ls-files', '-v', '-z'], env,
                               timeout=timeout, limit=40_000_000)
    if code or (flags and not flags.endswith(b'\0')):
        raise OSError('source Git index flags could not be inspected safely')
    count = 0
    for record in flags.split(b'\0'):
        if not record:
            continue
        count += 1
        if count > 250_000 or len(record) < 3 or record[:2] != b'H ':
            raise OSError('source Git index has hidden or unsupported flags')
    code, config = _bounded_git(repo, ['config', '--includes', '--show-scope',
                                      '--name-only', '--null', '--get-regexp', FILTER_PATTERN],
                                env, timeout=timeout, limit=1_000_000)
    if code not in (0, 1) or (code == 1 and config) or (config and not config.endswith(b'\0')):
        raise OSError('source Git filter configuration could not be inspected safely')
    fields = config.split(b'\0')[:-1] if config else []
    if len(fields) % 2:
        raise OSError('source Git filter configuration was malformed')
    for scope, key in zip(fields[::2], fields[1::2]):
        if not key.startswith(b'filter.'):
            raise OSError('source Git filter configuration was malformed')
        if scope in (b'local', b'worktree'):
            raise OSError('source Git has an executable local filter')
