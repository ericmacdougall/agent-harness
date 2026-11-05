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

from install import (DirectoryPins, local_profile_status, migrate_local_profiles, netwatch_status, atomic_write, git_hook_status, markdown_marker_lines, read_regular,
                     safe_unlink)


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
DELIVERY_HELPERS = ('process.py', 'git_safety.py', 'github_identity.py', 'report_file.py',
                    'usage_guard.py', 'publish_feature.py', 'integrate_local.py', 'deliver.py',
                    'ticket_adapters.py', 'commit_policy.py', 'commit_policy.json',
                    # Spec flow commands work by hand in Codex; its done hook is Claude Code only.
                    'spec_flow.py', 'spec_policy.json', 'spec_template.md', 'provenance.py', 'provenance_policy.json',
                    'provenance_hooks.py', 'safe_input.py', 'domain_gates.py', 'domain_checklists.json',
                    'commit_policy.local.json.example', 'spec_policy.local.json.example',
                    'model_tiers.py', 'model_tiers.json', 'escalation.py', 'tier_gate.py',
                    # Destructive and config-dump command guard (GoodQA #14471): launcher plus analyser.
                    'command_guard.py', 'command_guard_hook.py', 'redact.py', 'merge_gate.py',
                    'work_assignments.py', 'work_assignments_policy.json', 'work_ledger.schema.json')
GIT_HOOK_KEY = 'agent-harness-commit-policy-codex'  # independent of the Claude install's key
HOOK_EVENTS = ('SessionStart', 'UserPromptSubmit', 'PreToolUse', 'SubagentStart', 'Stop', 'Interrupt')


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


def policy_command(codex_home: Path) -> str:
    return 'python3 ' + shlex.quote(str(codex_home / 'agent-harness' / 'commit_policy.py')) + ' hook'


WORK_ASSIGNMENT_HOOKS = (('SessionStart', None, 'session'), ('UserPromptSubmit', None, 'prompt'), ('Stop', None, 'stop'),
                         ('PostCompact', None, 'compact'), ('PostToolUse', 'AskUserQuestion|request_user_input', 'ask-answer'),
                         ('PreToolUse', None, 'guard'), ('SubagentStart', None, 'subagent-start'))


def work_assignment_command(codex_home: Path, name: str) -> str:
    return ('python3 ' + shlex.quote(str(codex_home / 'agent-harness' / 'work_assignments.py'))
            + ' hook ' + name + ' --runtime codex')


def merge_work_assignment_hooks(hooks: dict, codex_home: Path) -> None:
    prefix = 'python3 ' + shlex.quote(str(codex_home / 'agent-harness' / 'work_assignments.py')) + ' hook '
    for event, matcher, name in WORK_ASSIGNMENT_HOOKS:
        groups = hooks.setdefault(event, [])
        if not isinstance(groups, list):
            raise ValueError(f'hooks.json {event} must be a list')
        kept = []
        for group in groups:
            if not isinstance(group, dict) or not isinstance(group.get('hooks'), list):
                raise ValueError(f'hooks.json {event} has an invalid hook group')
            handlers = [h for h in group['hooks'] if not (isinstance(h, dict) and str(h.get('command', '')).startswith(prefix))]
            if handlers:
                kept.append({**group, 'hooks': handlers})
        entry = {'hooks': [{'type': 'command', 'command': work_assignment_command(codex_home, name), 'timeout': 10}]}
        if matcher:
            entry['matcher'] = matcher
        hooks[event] = kept + [entry]


def gate_command(codex_home: Path) -> str:
    """Merge gate; `|| exit 2` because a crash (exit 1) would otherwise count as allow."""
    return 'python3 ' + shlex.quote(str(codex_home / 'agent-harness' / 'merge_gate.py')) + ' hook || exit 2'


def guard_command(codex_home: Path, verb: str = ' hook') -> str:
    # The hook verb marks a fail-closed gate for the Go front door (cmd/harness/gates.json); the launcher ignores it.
    return 'python3 ' + shlex.quote(str(codex_home / 'agent-harness' / 'command_guard_hook.py')) + verb


def merge_hooks(existing: dict, codex_home: Path, command_guard: bool = True) -> dict:
    if not isinstance(existing, dict):
        raise ValueError('hooks.json must contain an object')
    result = json.loads(json.dumps(existing))
    hooks = result.setdefault('hooks', {})
    if not isinstance(hooks, dict):
        raise ValueError('hooks.json hooks must be an object')
    command = managed_command(codex_home)
    policy = policy_command(codex_home)
    guard = guard_command(codex_home)
    gate = gate_command(codex_home)
    for event in HOOK_EVENTS:
        lifecycle = event in {'Stop', 'Interrupt'}
        managed = {'hooks': [{'type': 'command', 'command': command,
                              'timeout': 1 if event == 'Interrupt' else 10}]}
        groups = hooks.setdefault(event, [])
        if not isinstance(groups, list):
            raise ValueError(f'hooks.json {event} must be a list')
        preserved = []
        for group in groups:
            if not isinstance(group, dict) or not isinstance(group.get('hooks'), list):
                raise ValueError(f'hooks.json {event} has an invalid hook group')
            handlers = [handler for handler in group['hooks']
                        if not (isinstance(handler, dict) and handler.get('type') == 'command'
                                and handler.get('command') in (command, policy, guard,
                                                               guard_command(codex_home, ''), gate))]
            if lifecycle and len(handlers) != len(group['hooks']) and group != managed:
                raise ValueError(f'hooks.json has a custom {event} hook invoking the managed command; '
                                 'reconcile that group explicitly before installing')
            if handlers:
                preserved.append({**group, 'hooks': handlers})
        preserved.append(managed)
        if event == 'PreToolUse':
            # Commit message policy for every tool (no matcher): shell argv, strings, stdin writes.
            preserved.append({'hooks': [{'type': 'command', 'command': policy, 'timeout': 60}]})
            preserved.append({'hooks': [{'type': 'command', 'command': gate, 'timeout': 60}]})
        if event == 'PreToolUse' and command_guard:
            # Command guard for every tool (no matcher): Codex fails open, so the launcher blocks by itself, and
            # write_stdin text typed into a running shell is never checked again by the host. Appended last:
            # Codex keys hook trust by position (hooks.state "<file>:pre_tool_use:<group>:<handler>"), so adding
            # it after the existing groups keeps their trusted hashes valid (GoodQA #14590). Codex runs every
            # matching hook, so position does not change whether the guard can block.
            preserved.append({'hooks': [{'type': 'command', 'command': guard, 'timeout': 30}]})
        hooks[event] = preserved
    merge_work_assignment_hooks(hooks, codex_home)
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


LEDGER_MODES = ('enforce', 'warn')
LEDGER_POLICY = 'work_assignments_policy.json'


def ledger_policy(mode: str) -> bytes:
    """The installed work-assignments policy. `warn` holds Codex in warn mode until the live Codex check passes;
    re-running the installer without the flag restores enforce."""
    source = (ROOT / 'harness' / 'hooks' / LEDGER_POLICY).read_bytes()
    if mode not in LEDGER_MODES:
        raise ValueError(f'--ledger-mode must be one of {", ".join(LEDGER_MODES)}')
    if mode == 'enforce':
        return source
    policy = json.loads(source)
    policy.update({key: mode for key in ('capture', 'stop', 'guard')})
    return (json.dumps(policy, indent=2) + '\n').encode()


def install(home: Path, apply: bool, *, default_full_access: bool = False, command_guard: bool = True,
            ledger_mode: str = 'enforce') -> list[str]:
    home = home.expanduser().resolve()
    codex_home = home / '.codex'
    skill_dir = codex_home / 'skills' / 'agent-harness'
    harness_dir = codex_home / 'agent-harness'
    wal_parent = home / '.agent-harness'
    wal_dir = wal_parent / 'codex-wals'
    backup_root = harness_dir / 'backups'
    files = [(SOURCE / 'agents' / name, codex_home / 'agents' / name) for name in AGENTS]
    files += [(SOURCE / 'skills' / 'agent-harness' / name, skill_dir / name) for name in SKILL_FILES]
    files += [(SOURCE / 'hooks' / 'wal.py', harness_dir / 'wal.py'),
              (SOURCE.parent / 'harness' / 'hooks' / 'ops_watch.py', harness_dir / 'ops_watch.py')]  # alert parity (goodqa#14613 M9)
    files += [(ROOT / 'harness' / 'hooks' / name, harness_dir / name)
              for name in DELIVERY_HELPERS]
    files += [(ROOT / 'harness' / 'tools' / 'watch-tests.py', harness_dir / 'watch-tests.py')]
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
        hooks = merge_hooks(existing_hooks, codex_home, command_guard)
        config = merge_config(existing_config, wal_dir, default_full_access=default_full_access)
        policy = ledger_policy(ledger_mode)
        payloads = [(destination, policy if source.name == LEDGER_POLICY else source.read_bytes())
                    for source, destination in files]
        payloads += [(instructions_path, instructions.encode()),
                     (hooks_path, (json.dumps(hooks, indent=2) + '\n').encode()),
                     (config_path, config.encode())]
        changes = [str(path) for path in managed]
        if not apply:
            return changes
        migrate_local_profiles(codex_home, harness_dir)  # before the generic policies overwrite personal values
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


def install_git_backstop(home: Path, apply: bool) -> str:
    home = home.expanduser().resolve()
    return git_hook_status(home, GIT_HOOK_KEY, home / '.codex' / 'agent-harness' / 'commit_policy.py', apply=apply)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--default-full-access', action='store_true',
                        help='Explicitly select built-in Full Access and no approval prompts for new sessions')
    parser.add_argument('--home', type=Path, default=Path.home())
    parser.add_argument('--ledger-mode', choices=LEDGER_MODES, default='enforce',
                        help='work-assignments capture, stop and guard mode for Codex (warn until the live Codex '
                             'check passes; a reinstall without this flag restores enforce)')
    netwatch = parser.add_mutually_exclusive_group()
    netwatch.add_argument('--no-netwatch', dest='netwatch', action='store_false', default=None,
                          help='do not install or upgrade the netwatch monitor (remembered)')
    netwatch.add_argument('--netwatch', dest='netwatch', action='store_true',
                          help='install or upgrade the pinned netwatch monitor (the default; remembered)')
    parser.add_argument('--no-command-guard', dest='command_guard', action='store_false',
                        help='do not register the command guard and remove an earlier registration (rollback); '
                             'the files stay installed; not remembered')
    args = parser.parse_args()
    try:
        changes = install(args.home, args.apply, default_full_access=args.default_full_access,
                          command_guard=args.command_guard, ledger_mode=args.ledger_mode)
    except (ValueError, RuntimeError) as error:
        parser.exit(2, f'error: {error}\n')
    print(('Installed' if args.apply else 'Would install') + f' Codex Agent Harness in {args.home / ".codex"}')
    if args.ledger_mode != 'enforce':
        print(f'Work-assignments ledger on Codex: {args.ledger_mode} (re-run without --ledger-mode to enforce).')
    if args.default_full_access:
        print('Full Access default requested: unrestricted local filesystem and network; approval prompts disabled.')
    for path in changes:
        print(f'  {path}')
    print(f'  {install_git_backstop(args.home, args.apply)}')
    print(f'  {netwatch_status(args.home, args.apply, args.netwatch)}')
    print(f'  {local_profile_status(args.home, args.home / ".codex" / "agent-harness")}')
    if args.apply:
        print('Review and trust the new user hooks with /hooks in a new Codex session.')


if __name__ == '__main__':
    main()
