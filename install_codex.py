#!/usr/bin/env python3
"""Install the Codex-native Agent Harness without replacing unrelated settings."""

from __future__ import annotations

import argparse
import copy
import json
import os
import secrets
import shlex
from datetime import datetime, timezone
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # Codex installer requires Python 3.11+.
    tomllib = None

from install import DirectoryPins, atomic_write, markdown_marker_lines, read_regular, safe_unlink


ROOT = Path(__file__).resolve().parent
SOURCE = ROOT / 'codex'
START = '<!-- agent-harness-codex:start -->'
END = '<!-- agent-harness-codex:end -->'
CONFIG_START = '# agent-harness-codex:profile-start'
CONFIG_END = '# agent-harness-codex:profile-end'
AGENTS = ('harness_owner.toml', 'harness_reviewer.toml', 'harness_red_team.toml',
          'harness_click_tester.toml', 'harness_fixer.toml', 'harness_rescue.toml')
SKILL_FILES = ('SKILL.md', 'references/owner-workflow.md',
               'references/testing-and-evals.md', 'references/delivery.md')
HOOK_EVENTS = ('SessionStart', 'UserPromptSubmit', 'PreToolUse', 'SubagentStart')


def merge_marked(existing: str, addition: str) -> str:
    block = f'{START}\n{addition.rstrip()}\n{END}'
    lines = existing.splitlines(keepends=True)
    starts, ends = markdown_marker_lines(lines, START, END)
    if starts or ends:
        if len(starts) != 1 or len(ends) != 1 or starts[0] >= ends[0]:
            raise ValueError('AGENTS.md has malformed Agent Harness markers')
        managed = ''.join(lines[starts[0] + 1:ends[0]]).lstrip()
        if not managed.startswith('# Agent Harness for Codex\n'):
            raise ValueError('AGENTS.md markers do not enclose a known Agent Harness block; resolve manually')
        ending = lines[ends[0]][len(END):]
        return ''.join(lines[:starts[0]]) + block + ending + ''.join(lines[ends[0] + 1:])
    return existing.rstrip() + ('\n\n' if existing.strip() else '') + block + '\n'


def managed_command(codex_home: Path) -> str:
    return 'python3 ' + shlex.quote(str(codex_home / 'agent-harness' / 'wal.py')) + ' hook'


def merge_hooks(existing: dict, codex_home: Path) -> dict:
    if not isinstance(existing, dict):
        raise ValueError('hooks.json must contain an object')
    result = json.loads(json.dumps(existing))
    hooks = result.setdefault('hooks', {})
    if not isinstance(hooks, dict):
        raise ValueError('hooks.json hooks must be an object')
    command = managed_command(codex_home)
    for event in HOOK_EVENTS:
        groups = hooks.setdefault(event, [])
        if not isinstance(groups, list):
            raise ValueError(f'hooks.json {event} must be a list')
        preserved = []
        for group in groups:
            if not isinstance(group, dict) or not isinstance(group.get('hooks'), list):
                raise ValueError(f'hooks.json {event} has an invalid hook group')
            handlers = [handler for handler in group['hooks']
                        if not (isinstance(handler, dict) and handler.get('type') == 'command'
                                and handler.get('command') == command)]
            if handlers:
                preserved.append({**group, 'hooks': handlers})
        preserved.append({'hooks': [{'type': 'command', 'command': command, 'timeout': 10}]})
        hooks[event] = preserved
    return result


def owned_root_line(text: str, key: str, value: str) -> int | None:
    """Locate an exact generated root assignment, never marker text in a TOML value."""
    parsed = tomllib.loads(text)
    if parsed.get(key) != value:
        return None
    expected = copy.deepcopy(parsed)
    del expected[key]
    generated = f'{key} = {json.dumps(value)} # agent-harness-codex'
    lines = text.splitlines(keepends=True)
    matches = []
    for index, line in enumerate(lines):
        if line.rstrip('\r\n') != generated:
            continue
        try:
            candidate = tomllib.loads(''.join(lines[:index] + lines[index + 1:]))
        except tomllib.TOMLDecodeError:
            continue
        if candidate == expected:
            matches.append(index)
    if len(matches) > 1:
        raise ValueError(f'config.toml has ambiguous managed {key} lines')
    return matches[0] if matches else None


def merge_config(existing: str, wal_dir: Path, *, default_full_access: bool = False) -> str:
    """Install the optional profile; change the default only on a fresh or opted-in install."""
    if tomllib is None:
        raise RuntimeError('Codex installer requires Python 3.11+ for TOML validation')
    profile = ('[permissions.agent-harness]\n'
               'description = "Workspace with private Agent Harness WAL and Git commits"\n'
               'extends = ":workspace"\n\n'
               '[permissions.agent-harness.filesystem]\n'
               f'{json.dumps(str(wal_dir))} = "write"\n\n'
               '[permissions.agent-harness.filesystem.":workspace_roots"]\n'
               '".git" = "write"')
    original_parsed = tomllib.loads(existing)
    lines = existing.splitlines(keepends=True)
    # A standalone-looking marker can be literal text inside a multiline
    # string. Removing a real TOML comment leaves parsed values unchanged.
    def comment_marker_indices(marker: str) -> list[int]:
        indices = []
        for i, line in enumerate(lines):
            if line.rstrip('\r\n') != marker:
                continue
            try:
                without_line = tomllib.loads(''.join(lines[:i] + lines[i + 1:]))
            except tomllib.TOMLDecodeError:
                continue
            if without_line == original_parsed:
                indices.append(i)
        return indices

    starts = comment_marker_indices(CONFIG_START)
    ends = comment_marker_indices(CONFIG_END)
    managed_profile = original_parsed.get('permissions', {}).get('agent-harness')
    managed_result = None
    if managed_profile is not None:
        if len(starts) != 1 or len(ends) != 1 or starts[0] >= ends[0]:
            raise ValueError('config.toml has ambiguous or malformed Agent Harness markers')
        inside = ''.join(lines[starts[0] + 1:ends[0]])
        generated = profile + '\n'
        if not inside.startswith(generated):
            raise ValueError('config.toml managed profile was edited; resolve manually')
        extra = inside[len(generated):]
        if extra.strip():
            first = next((line.strip() for line in extra.splitlines()
                          if line.strip() and not line.lstrip().startswith('#')), '')
            if not first.startswith('['):
                raise ValueError('config.toml has ambiguous text after the managed profile')
            extra_parsed = tomllib.loads(extra)
            if not extra_parsed or 'permissions' in extra_parsed:
                raise ValueError('config.toml has unsafe sections after the managed profile')
        elif extra:
            raise ValueError('config.toml has ambiguous text after the managed profile')
        prefix = ''.join(lines[:starts[0]])
        suffix = ''.join(lines[ends[0] + 1:])
        expected = copy.deepcopy(original_parsed)
        del expected['permissions']['agent-harness']
        if not expected['permissions']:
            del expected['permissions']
        candidate = prefix + extra + suffix
        if tomllib.loads(candidate) != expected:
            raise ValueError('config.toml managed profile collides with user data; resolve manually')
        managed_result = prefix + extra + lines[starts[0]] + generated + lines[ends[0]] + suffix
        if tomllib.loads(managed_result) != original_parsed:
            raise ValueError('config.toml unrelated sections would change meaning; resolve manually')
        existing = candidate
    elif starts or ends:
        raise ValueError('config.toml has stray Agent Harness comment markers; resolve manually')
    parsed = tomllib.loads(existing)
    if 'sandbox_mode' in parsed or 'sandbox_workspace_write' in parsed:
        raise ValueError('config.toml uses legacy sandbox settings; merge manually')
    if 'profile' in parsed:
        raise ValueError('config.toml selects a profile that may override sandbox settings; merge manually')
    for settings in parsed.get('profiles', {}).values():
        if isinstance(settings, dict) and ('sandbox_mode' in settings or 'sandbox_workspace_write' in settings):
            raise ValueError('config.toml has a profile with legacy sandbox settings; merge manually')
    if 'agent-harness' in parsed.get('permissions', {}):
        raise ValueError('config.toml already defines the agent-harness profile outside managed markers')
    result = (managed_result if managed_result is not None else
              existing.rstrip() + '\n\n' + CONFIG_START + '\n' + profile + '\n' + CONFIG_END + '\n')
    current = tomllib.loads(result)
    owned_default = owned_root_line(result, 'default_permissions', 'agent-harness')
    if default_full_access:
        selected = current.get('default_permissions')
        if (selected not in (None, ':danger-full-access')
                and not (selected == 'agent-harness' and owned_default is not None)):
            raise ValueError('config.toml selects a user-owned permission default; resolve manually')
        if current.get('approval_policy') not in (None, 'never'):
            raise ValueError('config.toml selects a user-owned approval policy; resolve manually')
        if owned_default is not None:
            lines = result.splitlines(keepends=True)
            lines[owned_default] = 'default_permissions = ":danger-full-access" # agent-harness-codex\n'
            result = ''.join(lines)
        elif selected is None:
            result = 'default_permissions = ":danger-full-access" # agent-harness-codex\n' + result
        if 'approval_policy' not in current:
            result = 'approval_policy = "never" # agent-harness-codex\n' + result
    elif 'default_permissions' not in current and managed_profile is None:
        result = 'default_permissions = "agent-harness" # agent-harness-codex\n' + result
    # A normal reinstall keeps explicit defaults and approval choices. Missing
    # root settings in an existing install are intentional.
    tomllib.loads(result)
    return result


def install(home: Path, apply: bool, *, default_full_access: bool = False) -> list[str]:
    home = home.expanduser().resolve()
    codex_home = home / '.codex'
    skill_dir = codex_home / 'skills' / 'agent-harness'
    harness_dir = codex_home / 'agent-harness'
    wal_parent = home / '.agent-harness'
    wal_dir = wal_parent / 'codex-wals'
    backup_root = harness_dir / 'backups'
    files = [(SOURCE / 'agents' / name, codex_home / 'agents' / name) for name in AGENTS]
    files += [(SOURCE / 'skills' / 'agent-harness' / name, skill_dir / name) for name in SKILL_FILES]
    files += [(SOURCE / 'hooks' / 'wal.py', harness_dir / 'wal.py')]
    instructions_path = codex_home / 'AGENTS.md'
    hooks_path = codex_home / 'hooks.json'
    config_path = codex_home / 'config.toml'
    managed = [destination for _, destination in files] + [instructions_path, hooks_path, config_path]
    directories = [home, codex_home, codex_home / 'agents', codex_home / 'skills', skill_dir,
                   skill_dir / 'references', harness_dir, backup_root, wal_parent, wal_dir]
    if any(path.is_symlink() for path in [*managed, *directories]):
        raise ValueError('Refusing a symlinked Codex destination or directory')
    if any(path.exists() and not path.is_file() for path in managed):
        raise ValueError('Each managed destination must be a regular file')
    if any(path.exists() and not path.is_dir() for path in directories):
        raise ValueError('Each managed directory must be a directory')
    pins = DirectoryPins()
    try:
        for directory in directories:
            pins.capture(directory)
        originals = {path: read_regular(path, pinned_parent=pins.fd(path.parent),
                                        retain_fd=pins.file_fds) for path in managed}
        existing_instructions = originals[instructions_path][0].decode() if originals[instructions_path] else ''
        existing_hooks = json.loads(originals[hooks_path][0].decode()) if originals[hooks_path] else {}
        existing_config = originals[config_path][0].decode() if originals[config_path] else ''
        instructions = merge_marked(existing_instructions, (SOURCE / 'AGENTS.md').read_text())
        hooks = merge_hooks(existing_hooks, codex_home)
        config = merge_config(existing_config, wal_dir, default_full_access=default_full_access)
        payloads = [(destination, source.read_bytes()) for source, destination in files]
        payloads += [(instructions_path, instructions.encode()),
                     (hooks_path, (json.dumps(hooks, indent=2) + '\n').encode()),
                     (config_path, config.encode())]
        changes = [str(path) for path in managed]
        if not apply:
            return changes
        for directory in directories[1:]:
            pins.create(directory)
        for directory in (codex_home, harness_dir, backup_root, wal_parent, wal_dir):
            if directory != codex_home:
                os.fchmod(pins.fd(directory), 0o700)
            pins.verify(directory)
        backups = backup_root / (datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
                                 + '-' + secrets.token_hex(4))
        pins.create(backups)
        os.fchmod(pins.fd(backups), 0o700)
        manifest = []
        for index, path in enumerate(managed):
            original = originals[path]
            if original is not None:
                saved = backups / f'{index:02d}-{path.name}'
                atomic_write(saved, original[0], original[1], pinned_parent=pins.fd(backups),
                             expected_target=None)
                manifest.append({'path': str(path), 'backup': saved.name, 'mode': original[1]})
        atomic_write(backups / 'manifest.json', (json.dumps(manifest, indent=2) + '\n').encode(),
                     pinned_parent=pins.fd(backups), expected_target=None)
        published = {}
        payload_by_path = dict(payloads)
        try:
            for destination, data in payloads:
                original = originals[destination]
                published[destination] = atomic_write(
                    destination, data, original[1] if original else 0o600,
                    pinned_parent=pins.fd(destination.parent),
                    expected_target=original[2] if original else None,
                    expected_data=original[0] if original else None,
                    expected_mode=original[1] if original else None,
                    published=published, retain_published_fd=pins.file_fds)
        except BaseException as error:
            failures = []
            for path in reversed(published):
                try:
                    original = originals[path]
                    expected = published[path]
                    published_mode = original[1] if original else 0o600
                    if original is None:
                        safe_unlink(path, pinned_parent=pins.fd(path.parent), expected_target=expected,
                                    expected_data=payload_by_path[path], expected_mode=published_mode)
                    else:
                        atomic_write(path, original[0], original[1],
                                     pinned_parent=pins.fd(path.parent), expected_target=expected,
                                     expected_data=payload_by_path[path], expected_mode=published_mode)
                except OSError:
                    failures.append(str(path.relative_to(codex_home)))
            if failures:
                raise RuntimeError(f'Codex install failed; rollback incomplete for {", ".join(failures)}; '
                                   f'restore from {backups}') from error
            raise
        return changes
    finally:
        pins.close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--default-full-access', action='store_true',
                        help='Explicitly select built-in Full Access and no approval prompts for new sessions')
    parser.add_argument('--home', type=Path, default=Path.home())
    args = parser.parse_args()
    try:
        changes = install(args.home, args.apply, default_full_access=args.default_full_access)
    except (ValueError, RuntimeError) as error:
        parser.exit(2, f'error: {error}\n')
    print(('Installed' if args.apply else 'Would install') + f' Codex Agent Harness in {args.home / ".codex"}')
    if args.default_full_access:
        print('Full Access default requested: unrestricted local filesystem and network; approval prompts disabled.')
    for path in changes:
        print(f'  {path}')
    if args.apply:
        print('Review and trust the new user hooks with /hooks in a new Codex session.')


if __name__ == '__main__':
    main()
