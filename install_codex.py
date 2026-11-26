#!/usr/bin/env python3
"""Install the Codex-native Agent Harness without replacing unrelated settings."""

from __future__ import annotations

import argparse
import copy
import json
import os
import secrets
import shlex
import sys
from datetime import datetime, timezone
from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # Codex installer requires Python 3.11+.
    tomllib = None

from install import (HOOKS, REMOVED_IN, DirectoryPins, DowngradeRefused, atomic_write, markdown_marker_lines, netwatch_status,
                     read_regular, remove_git_backstop, removed_flag_message, safe_unlink, sandbox_module, switch_module)


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
# The Claude hooks directory's shipped set (install.HOOKS, the import closure of the entry points), minus what only
# Claude Code runs: Codex copies its own wal.py (codex/hooks/wal.py) and ops_watch.py by name below.
CLAUDE_ONLY = frozenset({'wal.py', 'ops_watch.py', 'prod_delete_guard.py'})
DELIVERY_HELPERS = tuple(name for name in HOOKS if name not in CLAUDE_ONLY)
GIT_HOOK_KEY = 'agent-harness-commit-policy-codex'  # independent of the Claude install's key
# Every event an earlier release registered a handler on: an upgrade strips those handlers wherever they are.
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


LAUNCHER = 'ah_hook.py'  # exits 0 at once while ~/.agent-harness/OFF exists (docs/off-switch.md)


def launch(codex_home: Path, script: str, rest: str = '', launcher: bool = True) -> str:
    """`python3 <harness>/ah_hook.py <script><rest>`; launcher=False gives the direct form old installers wrote."""
    harness = codex_home / 'agent-harness'
    if launcher:
        return 'python3 ' + shlex.quote(str(harness / LAUNCHER)) + ' ' + script + rest
    return 'python3 ' + shlex.quote(str(harness / script)) + rest


def managed_command(codex_home: Path, launcher: bool = True) -> str:
    return launch(codex_home, 'wal.py', ' hook', launcher)


# Handlers earlier releases registered for scripts release 1001 deleted (commit policy, merge gate, command guard,
# kill guard, heavy-job guard): recognised only, so an upgrade strips them. Nothing builds them for registration.
RETIRED_COMMANDS = (('commit_policy.py', ' hook'), ('merge_gate.py', ' hook'), ('merge_gate.py', ' hook || exit 2'),
                    ('command_guard_hook.py', ' hook'), ('command_guard_hook.py', ''), ('kill_guard.py', ' hook'),
                    ('heavy_job_guard.py', ''))


def owner_inbox_command(codex_home: Path, launcher: bool = True) -> str:
    return launch(codex_home, 'owner_inbox.py', ' hook', launcher)


def session_env_command(codex_home: Path, launcher: bool = True) -> str:
    return launch(codex_home, 'session_env.py', '', launcher)


def autosave_command(codex_home: Path, launcher: bool = True) -> str:
    return launch(codex_home, 'autosave.py', '', launcher)


def command_argv(command: str) -> list[str]:
    """[script path, *args] of a Codex command string, direct or through the launcher (shell words after python3)."""
    words = shlex.split(command)[1:]
    if len(words) > 1 and Path(words[0]).name == LAUNCHER:
        return [str(Path(words[0]).parent / words[1]), *words[2:]]
    return words


def known_commands(codex_home: Path) -> set[str]:
    """Every command string this installer owns, in the launcher form and in the direct form of older installs."""
    out = set()
    for launcher in (True, False):
        out |= {managed_command(codex_home, launcher), owner_inbox_command(codex_home, launcher),
                session_env_command(codex_home, launcher), autosave_command(codex_home, launcher)}
        out |= {launch(codex_home, script, rest, launcher) for script, rest in RETIRED_COMMANDS}
    return out


MANAGED_SCRIPTS = ('wal.py', 'commit_policy.py', 'command_guard_hook.py', 'merge_gate.py', 'kill_guard.py',
                   'heavy_job_guard.py', 'owner_inbox.py', 'session_env.py', 'autosave.py')


def managed_groups(codex_home: Path) -> dict:
    """The seven Codex handlers of release 1001, one group each, in order. No PreToolUse group at all: a shell call
    starts no harness hook (docs/direction.md). Codex keys hook trust by position, so this layout needs one review in
    /hooks after the upgrade (the installer says so)."""
    def group(command: str, timeout: int) -> dict:
        return {'hooks': [{'type': 'command', 'command': command, 'timeout': timeout}]}
    wal = managed_command(codex_home)
    inbox = owner_inbox_command(codex_home)
    return {
        'SessionStart': [group(wal, 10), group(inbox, 5), group(session_env_command(codex_home), 10)],
        'UserPromptSubmit': [group(inbox, 5)],
        'SubagentStart': [group(wal, 10)],
        # wal.py on Stop: the continuation checkpoint and the dropped-owner part; autosave saves the checkouts
        'Stop': [group(wal, 10), group(autosave_command(codex_home), 30)],
    }


def merge_hooks(existing: dict, codex_home: Path) -> dict:
    if not isinstance(existing, dict):
        raise ValueError('hooks.json must contain an object')
    result = json.loads(json.dumps(existing))
    hooks = result.setdefault('hooks', {})
    if not isinstance(hooks, dict):
        raise ValueError('hooks.json hooks must be an object')
    known = known_commands(codex_home)
    wanted = managed_groups(codex_home)

    def ours(group: dict, event: str) -> bool:
        """A lifecycle group exactly as this or an earlier installer wrote it (launcher or direct form)."""
        shapes = []
        for launcher in (True, False):
            shapes.append({'hooks': [{'type': 'command', 'command': managed_command(codex_home, launcher),
                                      'timeout': 1 if event == 'Interrupt' else 10}]})
            shapes.append({'hooks': [{'type': 'command', 'command': autosave_command(codex_home, launcher),
                                      'timeout': 30}]})
        return group in shapes

    for event in sorted(set(HOOK_EVENTS) | set(wanted), key=lambda e: (e not in HOOK_EVENTS, e)):
        if event not in hooks and event not in wanted:
            continue
        groups = hooks.setdefault(event, [])
        if not isinstance(groups, list):
            raise ValueError(f'hooks.json {event} must be a list')
        had = bool(groups)
        preserved = []
        for group in groups:
            if not isinstance(group, dict) or not isinstance(group.get('hooks'), list):
                raise ValueError(f'hooks.json {event} has an invalid hook group')
            handlers = [handler for handler in group['hooks']
                        if not (isinstance(handler, dict) and handler.get('type') == 'command'
                                and handler.get('command') in known)]
            if event in {'Stop', 'Interrupt'} and len(handlers) != len(group['hooks']) and not ours(group, event):
                raise ValueError(f'hooks.json has a custom {event} hook invoking the managed command; '
                                 'reconcile that group explicitly before installing')
            if handlers:
                preserved.append({**group, 'hooks': handlers})
        preserved.extend(json.loads(json.dumps(wanted.get(event, []))))
        if preserved:
            hooks[event] = preserved
        elif had or event not in wanted:
            del hooks[event]  # a retired event (PreToolUse, Interrupt) leaves nothing behind
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


LEGACY_PROFILE = 'agent-harness'  # the one profile releases before 1001 managed
ROLE_DEFAULTS = ('worker', 'supervisor')  # --default-role: a reviewer is launched for a review, never a default
OWNED = ' # agent-harness-codex'


def legacy_profile(wal_dir: Path) -> str:
    """The [permissions.agent-harness] text releases before 1001 wrote between the markers (recognised to upgrade it)."""
    return ('[permissions.agent-harness]\n'
            'description = "Workspace with private Agent Harness WAL and Git commits"\n'
            'extends = ":workspace"\n\n'
            '[permissions.agent-harness.filesystem]\n'
            f'{json.dumps(str(wal_dir))} = "write"\n\n'
            '[permissions.agent-harness.filesystem.":workspace_roots"]\n'
            '".git" = "write"')


def profile_names(profiles: str) -> set:
    parsed = tomllib.loads(profiles)
    names = set((parsed.get('permissions') or {}).keys())
    if not names or set(parsed) != {'permissions'}:
        raise ValueError('the generated Codex profiles must be [permissions.*] tables only')
    return names


def merge_config(existing: str, wal_dir: Path, profiles: str, *, default_role: str | None = None) -> str:
    """Put `profiles` (ah_sandbox.codex_profiles(): [permissions.ah-worker], ah-reviewer, ah-supervisor) between the
    managed markers, replacing this or an earlier release's managed text. Selects no role unless default_role:
    an owned `default_permissions = "agent-harness"` line (the retired profile) becomes "ah-worker"; an owned
    ":danger-full-access" line is kept as it is (install() prints a note); a user's own line is never changed."""
    if tomllib is None:
        raise RuntimeError('Codex installer requires Python 3.11+ for TOML validation')
    if default_role is not None and default_role not in ROLE_DEFAULTS:
        raise ValueError(f'--default-role must be one of {", ".join(ROLE_DEFAULTS)}')
    profiles = profiles.rstrip('\n')
    new_names = profile_names(profiles)
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
    permissions = original_parsed.get('permissions', {})
    if not isinstance(permissions, dict):
        raise ValueError('config.toml permissions must be a table')
    managed_names = (new_names | {LEGACY_PROFILE}) & set(permissions)
    prefix_suffix = None
    if starts or ends:
        if len(starts) != 1 or len(ends) != 1 or starts[0] >= ends[0]:
            raise ValueError('config.toml has ambiguous or malformed Agent Harness markers')
        inside = ''.join(lines[starts[0] + 1:ends[0]])
        known = [text + '\n' for text in (profiles, legacy_profile(wal_dir))]
        generated = next((text for text in known if inside.startswith(text)), None)
        if generated is None:
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
        owned_here = profile_names(generated)
        expected = copy.deepcopy(original_parsed)
        for name in owned_here:
            expected.get('permissions', {}).pop(name, None)
        if 'permissions' in expected and not expected['permissions']:
            del expected['permissions']
        candidate = prefix + extra + suffix
        if tomllib.loads(candidate) != expected:
            raise ValueError('config.toml managed profile collides with user data; resolve manually')
        check = prefix + extra + lines[starts[0]] + generated + lines[ends[0]] + suffix
        if tomllib.loads(check) != original_parsed:
            raise ValueError('config.toml unrelated sections would change meaning; resolve manually')
        managed_names -= owned_here
        prefix_suffix = (prefix + extra, lines[starts[0]], lines[ends[0]], suffix)
        existing = candidate
    parsed = tomllib.loads(existing)
    if 'sandbox_mode' in parsed or 'sandbox_workspace_write' in parsed:
        raise ValueError('config.toml uses legacy sandbox settings; merge manually')
    if 'profile' in parsed:
        raise ValueError('config.toml selects a profile that may override sandbox settings; merge manually')
    for settings in parsed.get('profiles', {}).values():
        if isinstance(settings, dict) and ('sandbox_mode' in settings or 'sandbox_workspace_write' in settings):
            raise ValueError('config.toml has a profile with legacy sandbox settings; merge manually')
    if managed_names:
        raise ValueError('config.toml already defines ' + ', '.join(sorted(managed_names))
                         + ' outside the managed markers; resolve manually')
    if prefix_suffix is not None:
        head, start_line, end_line, suffix = prefix_suffix
        result = head + start_line + profiles + '\n' + end_line + suffix
    else:
        result = existing.rstrip() + ('\n\n' if existing.strip() else '') + CONFIG_START + '\n' + profiles + '\n' + CONFIG_END + '\n'
    current = tomllib.loads(result)
    selected = current.get('default_permissions')
    owned = next((i for value in (LEGACY_PROFILE, ':danger-full-access', *('ah-' + r for r in ROLE_DEFAULTS))
                  for i in [owned_root_line(result, 'default_permissions', value)] if i is not None), None)
    wanted = None
    if default_role is not None:
        if selected is not None and owned is None:
            raise ValueError('config.toml selects a user-owned permission default; resolve manually')
        wanted = 'ah-' + default_role
    elif owned is not None and selected == LEGACY_PROFILE:
        wanted = 'ah-worker'  # the retired profile's successor: workspace writes, secrets unreadable
    if wanted is not None:
        line = f'default_permissions = {json.dumps(wanted)}{OWNED}\n'
        if owned is not None:
            lines = result.splitlines(keepends=True)
            lines[owned] = line
            result = ''.join(lines)
        else:
            result = line + result
    tomllib.loads(result)
    return result


def full_access_note(config: str) -> str | None:
    """An owned `default_permissions = ":danger-full-access"` line an earlier --default-full-access wrote is left
    alone (no silent change of a live default); one line says so and how to choose a role instead."""
    if tomllib is None or owned_root_line(config, 'default_permissions', ':danger-full-access') is None:
        return None
    return ('config.toml keeps default_permissions = ":danger-full-access" (written by an earlier --default-full-access); '
            'run with --default-role worker to select the ah-worker profile instead')


def install(home: Path, apply: bool, *, default_role: str | None = None, hooks_only: bool = False,
            allow_downgrade: bool = False, release: int | None = None) -> list[str]:
    """hooks_only: install the harness files only; AGENTS.md, hooks.json and config.toml are never read or written.

    Like install.py: refuses a release below the host's Codex floor unless allow_downgrade; while OFF the AGENTS.md
    block waits in the off stash; a successful --apply records the release and snapshots the files and hook groups."""
    home = home.expanduser().resolve()
    switch = switch_module()
    release = switch.read_release(ROOT) if release is None else release
    refusal = switch.downgrade_refusal(home, 'codex', release, allow_downgrade)
    if refusal:
        raise DowngradeRefused(refusal)
    stash_record = None
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
    user_files = [] if hooks_only else [instructions_path, hooks_path, config_path]
    managed = [destination for _, destination in files] + user_files
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
        payloads = [(destination, source.read_bytes()) for source, destination in files]
        if not hooks_only:
            existing_instructions = originals[instructions_path][0].decode() if originals[instructions_path] else ''
            existing_hooks = json.loads(originals[hooks_path][0].decode()) if originals[hooks_path] else {}
            existing_config = originals[config_path][0].decode() if originals[config_path] else ''
            addition = (SOURCE / 'AGENTS.md').read_text()
            if switch.is_off(home):  # files and wiring go in; the rules wait in the off stash until `harness on`
                instructions, stash_record = switch.plan_stash(home, 'codex', existing_instructions,
                                                               block=f'{START}\n{addition.rstrip()}\n{END}\n')
            else:
                instructions = merge_marked(existing_instructions, addition)
            hooks = merge_hooks(existing_hooks, codex_home)
            config = merge_config(existing_config, wal_dir, sandbox_module().codex_profiles(home=home),
                                  default_role=default_role)
            payloads += [(instructions_path, instructions.encode()),
                         (hooks_path, (json.dumps(hooks, indent=2) + '\n').encode()),
                         (config_path, config.encode())]
        changes = [str(path) for path in managed]
        note = None if hooks_only else full_access_note(config)
        if note:
            changes.append(note)
        if not apply:
            return changes
        for directory in directories[1:]:
            pins.create(directory)
        for directory in (codex_home, harness_dir, backup_root, wal_parent, wal_dir):
            if directory != codex_home:
                os.fchmod(pins.fd(directory), 0o700)
            pins.verify(directory)
        switch.mark_pending(home, 'codex', release)  # after ~/.agent-harness is created under its pin
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
            try:
                switch.clear_pending(home, 'codex')
            except OSError:
                pass
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
        if stash_record is not None:
            switch.save_stash(home, 'codex', stash_record)
            changes.append('harness is OFF: the AGENTS.md block is kept in ~/.agent-harness/off-stash until `harness on`')
        if hooks_only:
            prior = switch.latest_snapshot(home, 'codex') or {}
            settings_spec, instructions_spec = prior.get('settings'), prior.get('instructions')
        else:
            settings_spec = {'path': '.codex/hooks.json', 'hooks_dir': str(harness_dir), 'names': list(MANAGED_SCRIPTS),
                             'groups': managed_groups(codex_home)}
            instructions_spec = {'block': f'{START}\n{(SOURCE / "AGENTS.md").read_text().rstrip()}\n{END}\n'}
        commit = switch.source_commit(ROOT)
        switch.record_install(home, 'codex', release, commit, [d for _, d in files], settings_spec, instructions_spec,
                              backups.name)
        changes.append(f'release {release} ({commit[:12]}) recorded; floor snapshot in '
                       f'{home / ".agent-harness" / "releases" / str(release)}')
        return changes
    finally:
        pins.close()


def install_git_backstop(home: Path, apply: bool) -> str:
    """Release 1001 registers no git hook; an upgrade unsets the one earlier releases added."""
    return remove_git_backstop(home, GIT_HOOK_KEY, apply)


REMOVED_FLAGS = {
    '--no-command-guard': 'the command guard is deleted; no hook reads a shell command',
    '--default-full-access': 'choose a sandbox profile instead: --default-role worker|supervisor (docs/sandbox.md)',
}


def main(argv=None) -> None:
    argv = list(sys.argv[1:] if argv is None else argv)
    parser = argparse.ArgumentParser(description=__doc__)
    message = removed_flag_message('install_codex.py', argv, REMOVED_FLAGS)
    if message:
        parser.exit(2, message + '\n')
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--default-role', choices=ROLE_DEFAULTS,
                        help='write an owned default_permissions = "ah-<role>" line: new sessions run in that '
                             'sandbox profile (docs/sandbox.md); without it no role is selected')
    parser.add_argument('--home', type=Path, default=Path.home())
    parser.add_argument('--hooks-only', action='store_true',
                        help='install the harness files only; never read or write AGENTS.md, hooks.json or '
                             'config.toml, and skip netwatch (per-file backups are kept)')
    netwatch = parser.add_mutually_exclusive_group()
    netwatch.add_argument('--no-netwatch', dest='netwatch', action='store_false', default=None,
                          help='do not install or upgrade the netwatch monitor (remembered)')
    netwatch.add_argument('--netwatch', dest='netwatch', action='store_true',
                          help='install or upgrade the pinned netwatch monitor (the default; remembered)')
    parser.add_argument('--allow-downgrade', action='store_true',
                        help="install even though this checkout's harness/RELEASE is below the host's Codex floor "
                             '(~/.agent-harness/floor.json); the floor then moves down to this release')
    args = parser.parse_args(argv)
    try:
        if args.hooks_only and args.default_role:
            raise ValueError('--hooks-only cannot be combined with --default-role')
        changes = install(args.home, args.apply, default_role=args.default_role, hooks_only=args.hooks_only,
                          allow_downgrade=args.allow_downgrade)
    except DowngradeRefused as error:
        parser.exit(1, f'install_codex.py: {error}\n')
    except (ValueError, RuntimeError, ImportError) as error:
        parser.exit(2, f'error: {error}\n')
    print(('Installed' if args.apply else 'Would install') + f' Codex Agent Harness in {args.home / ".codex"}')
    for path in changes:
        print(f'  {path}')
    print(f'  {install_git_backstop(args.home, args.apply)}')
    if args.hooks_only:
        print('  AGENTS.md, hooks.json and config.toml: not touched (--hooks-only)')
        return
    print(f'  {netwatch_status(args.home, args.apply, args.netwatch)}')
    if args.apply:
        print('Review and trust the new user hooks with /hooks in a new Codex session (release '
              f'{REMOVED_IN} changed the hook layout, so the trust hashes changed).')


if __name__ == '__main__':
    main()
