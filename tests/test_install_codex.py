"""Codex-native installer and WAL behavior in disposable user homes."""

import io
import json
import os
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from codex.hooks import wal
from install_codex import (AGENTS, CONFIG_END, CONFIG_START, HOOK_EVENTS, SKILL_FILES, SOURCE, install,
                           managed_command, merge_config, merge_marked, tomllib)


ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(tomllib is not None, 'Codex installer requires Python 3.11+')
class CodexInstallerTests(unittest.TestCase):
    def test_inline_marker_text_is_preserved(self):
        original = 'Keep <!-- agent-harness-codex:start --> this example <!-- agent-harness-codex:end --> intact.\n'
        merged = merge_marked(original, 'Managed.')
        self.assertIn(original.rstrip(), merged)

    def test_fenced_marker_example_is_preserved(self):
        example = ('```md\n<!-- agent-harness-codex:start -->\n'
                   '# Agent Harness for Codex\nExample.\n<!-- agent-harness-codex:end -->\n```\n')
        merged = merge_marked(example, 'Managed.')
        self.assertIn(example, merged)
        self.assertIn('Managed.', merged)

    def test_replacement_preserves_end_marker_newline_and_suffix(self):
        start = '<!-- agent-harness-codex:start -->'
        end = '<!-- agent-harness-codex:end -->'
        existing = (f'{start}\n# Agent Harness for Codex\nOld.\n{end}\n'
                    'User instructions after block.\n')
        merged = merge_marked(existing, '# Agent Harness for Codex\nNew.')
        self.assertIn(f'{end}\nUser instructions after block.\n', merged)
        self.assertEqual(merge_marked(merged, '# Agent Harness for Codex\nNew.'), merged)

    def test_toml_multiline_marker_text_is_preserved(self):
        original = 'note = """literal # agent-harness-codex:profile-start data # agent-harness-codex:profile-end retained"""\n'
        merged = merge_config(original, Path('/tmp/private-wals'))
        self.assertEqual(tomllib.loads(merged)['note'], tomllib.loads(original)['note'])

    def test_toml_marker_lines_inside_value_survive_reinstallation(self):
        original = ('note = """before\n# agent-harness-codex:profile-start\n'
                    'user value\n# agent-harness-codex:profile-end\nafter"""\n')
        first = merge_config(original, Path('/tmp/private-wals'))
        second = merge_config(first, Path('/tmp/private-wals'))
        self.assertEqual(tomllib.loads(first)['note'], tomllib.loads(original)['note'])
        self.assertEqual(tomllib.loads(second)['note'], tomllib.loads(original)['note'])
        self.assertEqual(first, second)

    def test_toml_profile_comment_collision_refuses_without_erasure(self):
        original = merge_config('note = "preserve"\n', Path('/tmp/private-wals'))
        modified = original.replace('[permissions.agent-harness]\n',
                                    '[permissions.agent-harness]\n# user comment that must survive\n')
        with self.assertRaisesRegex(ValueError, 'managed profile was edited'):
            merge_config(modified, Path('/tmp/private-wals'))
        extra_marker = original + '\n# agent-harness-codex:profile-start\n'
        with self.assertRaisesRegex(ValueError, 'ambiguous or malformed'):
            merge_config(extra_marker, Path('/tmp/private-wals'))

    def test_reinstall_moves_unrelated_sections_out_of_managed_profile(self):
        wal_dir = Path('/tmp/private-wals')
        original = merge_config('model = "gpt-6-sol"\n', wal_dir)
        extra = ('\n[tui]\nanimations = false\n\n[hooks.state]\n'
                 'trusted_hash = "synthetic-value"  # retained spaces  \n\n')
        with_inside = original.replace(CONFIG_END, extra + CONFIG_END, 1)
        merged = merge_config(with_inside, wal_dir)
        self.assertEqual(tomllib.loads(merged), tomllib.loads(with_inside))
        self.assertIn(extra, merged)
        self.assertLess(merged.index(extra), merged.index(CONFIG_START))
        self.assertEqual(merged.count(CONFIG_START), 1)
        self.assertEqual(merged.count(CONFIG_END), 1)
        self.assertEqual(merge_config(merged, wal_dir), merged)

    def test_reinstall_preserves_mixed_endings_and_multiline_user_value(self):
        wal_dir = Path('/tmp/private-wals')
        original = merge_config('model = "gpt-6-sol"\n', wal_dir)
        extra = ('\r\n[tui]\r\nnote = """before\n'
                 '# agent-harness-codex:profile-end\n[permissions.agent-harness]\n'
                 'after"""\r\n\r\n[[hooks.plugins]]\r\nname = "synthetic"\r\n')
        with_inside = original.replace(CONFIG_END, extra + CONFIG_END, 1)
        merged = merge_config(with_inside, wal_dir)
        self.assertIn(extra, merged)
        self.assertEqual(tomllib.loads(merged), tomllib.loads(with_inside))
        self.assertEqual(merge_config(merged, wal_dir), merged)

    def test_reinstall_preserves_quoted_unrelated_tables_and_outer_suffix(self):
        wal_dir = Path('/tmp/private-wals')
        original = merge_config('model = "gpt-6-sol"\n', wal_dir)
        extra = ('\n["hooks"."state.v2"]\ntrusted_hash = "synthetic"\n'
                 '\n[permissionsExtra]\nflag = true\n')
        outside = '\n[features]\nforeign = true\n'
        with_inside = original.replace(CONFIG_END, extra + CONFIG_END, 1) + outside
        merged = merge_config(with_inside, wal_dir)
        self.assertIn(extra, merged)
        self.assertTrue(merged.endswith(outside))
        self.assertEqual(tomllib.loads(merged), tomllib.loads(with_inside))
        self.assertEqual(merge_config(merged, wal_dir), merged)

    def test_reinstall_refuses_managed_edits_and_ambiguous_suffix(self):
        wal_dir = Path('/tmp/private-wals')
        original = merge_config('model = "gpt-6-sol"\n', wal_dir)
        extra = '\n[tui]\nanimations = false\n'
        with_inside = original.replace(CONFIG_END, extra + CONFIG_END, 1)
        cases = (
            with_inside.replace('extends = ":workspace"', 'extends = ":unsafe"'),
            original.replace(CONFIG_END, '\n# ambiguous\nrogue = true\n' + CONFIG_END, 1),
            original.replace(CONFIG_END, '\n[permissions.other]\nrogue = true\n' + CONFIG_END, 1),
            original.replace(CONFIG_END, '\n["permis\\u0073ions".other]\nrogue = true\n' + CONFIG_END, 1),
            original.replace('".git" = "write"', '".git" = "write" # changed'),
            original.replace('\n', '\r\n'),
            with_inside + 'late_key = "binds to prior table"\n',
        )
        for text in cases:
            with self.subTest(text=text[:35]), self.assertRaises(ValueError):
                merge_config(text, wal_dir)

    def test_reinstall_preserves_removed_root_default_without_changing_unrelated(self):
        wal_dir = Path('/tmp/private-wals')
        original = merge_config('model = "gpt-6-sol"\n', wal_dir)
        without_default = original.replace('default_permissions = "agent-harness" # agent-harness-codex\n', '', 1)
        extra = '\n[tui]\nanimations = false\n'
        with_inside = without_default.replace(CONFIG_END, extra + CONFIG_END, 1)
        merged = merge_config(with_inside, wal_dir)
        parsed = tomllib.loads(merged)
        self.assertNotIn('default_permissions', parsed)
        self.assertEqual(parsed['tui']['animations'], False)
        self.assertNotIn('default_permissions = "agent-harness"', merged)
        self.assertEqual(merge_config(merged, wal_dir), merged)

    def test_explicit_full_access_default_and_unflagged_reinstall(self):
        wal_dir = Path('/tmp/private-wals')
        original = merge_config('model = "gpt-6-sol"\n', wal_dir)
        full = merge_config(original, wal_dir, default_full_access=True)
        parsed = tomllib.loads(full)
        self.assertEqual(parsed['default_permissions'], ':danger-full-access')
        self.assertEqual(parsed['approval_policy'], 'never')
        self.assertIn('agent-harness', parsed['permissions'])
        self.assertEqual(full.count('default_permissions = ":danger-full-access" # agent-harness-codex'), 1)
        self.assertEqual(full.count('approval_policy = "never" # agent-harness-codex'), 1)
        self.assertEqual(merge_config(full, wal_dir), full)
        self.assertEqual(merge_config(full, wal_dir, default_full_access=True), full)

    def test_full_access_reinstall_preserves_independently_removed_owned_settings(self):
        wal_dir = Path('/tmp/private-wals')
        original = merge_config('', wal_dir)
        full = merge_config(original, wal_dir, default_full_access=True)
        no_default = full.replace('default_permissions = ":danger-full-access" # agent-harness-codex\n', '', 1)
        no_approval = full.replace('approval_policy = "never" # agent-harness-codex\n', '', 1)
        edited_approval = full.replace('approval_policy = "never" # agent-harness-codex\n',
                                       'approval_policy = "on-request" # agent-harness-codex\n', 1)
        self.assertNotIn('default_permissions', tomllib.loads(merge_config(no_default, wal_dir)))
        self.assertNotIn('approval_policy', tomllib.loads(merge_config(no_approval, wal_dir)))
        self.assertEqual(tomllib.loads(merge_config(edited_approval, wal_dir))['approval_policy'],
                         'on-request')
        with self.assertRaisesRegex(ValueError, 'approval policy'):
            merge_config(edited_approval, wal_dir, default_full_access=True)

    def test_full_access_owned_line_detection_ignores_multiline_and_nested_spoofs(self):
        wal_dir = Path('/tmp/private-wals')
        original = ('note = """before\n'
                    'default_permissions = ":danger-full-access" # agent-harness-codex\n'
                    'approval_policy = "never" # agent-harness-codex\n'
                    'after"""\n'
                    '[view]\n'
                    'default_permissions = ":danger-full-access" # agent-harness-codex\n'
                    'approval_policy = "never" # agent-harness-codex\n')
        merged = merge_config(original, wal_dir, default_full_access=True)
        parsed = tomllib.loads(merged)
        self.assertIn('default_permissions = ":danger-full-access"', parsed['note'])
        self.assertEqual(parsed['view']['default_permissions'], ':danger-full-access')
        self.assertEqual(parsed['view']['approval_policy'], 'never')
        self.assertEqual(parsed['default_permissions'], ':danger-full-access')
        self.assertEqual(parsed['approval_policy'], 'never')

    def test_rejected_apply_leaves_synthetic_config_unchanged(self):
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary).resolve()
            codex_home = home / '.codex'
            codex_home.mkdir()
            wal_dir = home / '.agent-harness' / 'codex-wals'
            original = merge_config('model = "gpt-6-sol"\n', wal_dir)
            tampered = original.replace('extends = ":workspace"', 'extends = ":unsafe"')
            config_path = codex_home / 'config.toml'
            config_path.write_text(tampered)
            with self.assertRaisesRegex(ValueError, 'managed profile was edited'):
                install(home, apply=True)
            self.assertEqual(config_path.read_text(), tampered)
            self.assertFalse((codex_home / 'agent-harness').exists())

    def test_apply_preserves_extra_sections_and_exact_backup(self):
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary).resolve()
            codex_home = home / '.codex'
            codex_home.mkdir()
            wal_dir = home / '.agent-harness' / 'codex-wals'
            original = merge_config('model = "gpt-6-sol"\n', wal_dir)
            extra = '\n[tui]\nanimations = false\n\n[hooks.state]\ntrusted_hash = "synthetic"\n'
            with_inside = original.replace(CONFIG_END, extra + CONFIG_END, 1)
            config_path = codex_home / 'config.toml'
            config_path.write_text(with_inside)
            install(home, apply=True)
            self.assertEqual(tomllib.loads(config_path.read_text()), tomllib.loads(with_inside))
            self.assertIn(extra, config_path.read_text())
            backup = next((codex_home / 'agent-harness' / 'backups').rglob('*-config.toml'))
            self.assertEqual(backup.read_bytes(), with_inside.encode())
            first = config_path.read_bytes()
            install(home, apply=True)
            self.assertEqual(config_path.read_bytes(), first)

    def test_same_inode_edit_during_backup_is_preserved(self):
        from install_codex import atomic_write
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary).resolve()
            codex_home = home / '.codex'
            codex_home.mkdir()
            target = codex_home / 'AGENTS.md'
            target.write_text('original\n')
            changed = False

            def edit_during_backup(path, data, mode=0o600, **kwargs):
                nonlocal changed
                if not changed and 'backups' in path.parts:
                    changed = True
                    target.write_text('concurrent user edit\n')
                return atomic_write(path, data, mode, **kwargs)

            with patch('install_codex.atomic_write', side_effect=edit_during_backup):
                with self.assertRaises(OSError):
                    install(home, apply=True)
            self.assertTrue(changed)
            self.assertEqual(target.read_text(), 'concurrent user edit\n')

    def test_rollback_preserves_same_inode_edit_to_published_file(self):
        from install_codex import atomic_write
        for existed in (False, True):
            with self.subTest(existed=existed), tempfile.TemporaryDirectory() as temporary:
                home = Path(temporary).resolve()
                agents = home / '.codex' / 'agents'
                agents.mkdir(parents=True)
                owner = agents / 'harness_owner.toml'
                if existed:
                    owner.write_text('original owner\n')
                changed = False

                def edit_then_fail(path, data, mode=0o600, **kwargs):
                    nonlocal changed
                    if path == agents / 'harness_reviewer.toml' and not changed:
                        changed = True
                        owner.write_text('concurrent published edit\n')
                        raise OSError('fixture: stop after edit')
                    return atomic_write(path, data, mode, **kwargs)

                with patch('install_codex.atomic_write', side_effect=edit_then_fail):
                    with self.assertRaisesRegex(RuntimeError, 'rollback incomplete'):
                        install(home, apply=True)
                self.assertTrue(changed)
                self.assertEqual(owner.read_text(), 'concurrent published edit\n')
    def test_preview_apply_idempotence_and_foreign_settings(self):
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary).resolve()
            codex_home = home / '.codex'
            codex_home.mkdir()
            (codex_home / 'AGENTS.md').write_text('Existing user instructions.\n')
            (codex_home / 'config.toml').write_text('model = "gpt-6-sol"\n\n[features]\nexample = true\n')
            foreign = {'type': 'command', 'command': 'python3 /other/hook.py'}
            (codex_home / 'hooks.json').write_text(json.dumps({
                'custom': {'keep': True},
                'hooks': {'PreToolUse': [{'matcher': 'Bash', 'hooks': [foreign]}],
                          'Stop': [{'hooks': [foreign]}]},
            }))
            preview = install(home, apply=False)
            self.assertEqual(len(preview), len(AGENTS) + len(SKILL_FILES) + 4)
            self.assertFalse((codex_home / 'agent-harness').exists())
            self.assertEqual((codex_home / 'AGENTS.md').read_text(), 'Existing user instructions.\n')
            install(home, apply=True)
            install(home, apply=True)
            instructions = (codex_home / 'AGENTS.md').read_text()
            self.assertIn('Existing user instructions.', instructions)
            self.assertEqual(instructions.count('<!-- agent-harness-codex:start -->'), 1)
            self.assertEqual(instructions.count('<!-- agent-harness-codex:end -->'), 1)
            for name in AGENTS:
                self.assertEqual((codex_home / 'agents' / name).read_bytes(), (SOURCE / 'agents' / name).read_bytes())
            for name in SKILL_FILES:
                self.assertEqual((codex_home / 'skills' / 'agent-harness' / name).read_bytes(),
                                 (SOURCE / 'skills' / 'agent-harness' / name).read_bytes())
            self.assertEqual((codex_home / 'agent-harness' / 'wal.py').read_bytes(),
                             (SOURCE / 'hooks' / 'wal.py').read_bytes())
            config = (codex_home / 'config.toml').read_text()
            self.assertEqual(tomllib.loads(config)['default_permissions'], 'agent-harness')
            self.assertIn('model = "gpt-6-sol"', config)
            self.assertIn('example = true', config)
            self.assertEqual(config.count('default_permissions = "agent-harness"'), 1)
            self.assertEqual(config.count('[permissions.agent-harness]'), 1)
            self.assertIn('".git" = "write"', config)
            self.assertIn(str(home / '.agent-harness' / 'codex-wals'), config)
            self.assertEqual(stat.S_IMODE((home / '.agent-harness' / 'codex-wals').stat().st_mode), 0o700)
            hooks = json.loads((codex_home / 'hooks.json').read_text())
            self.assertEqual(hooks['custom'], {'keep': True})
            self.assertEqual(hooks['hooks']['Stop'], [{'hooks': [foreign]}])
            for event in HOOK_EVENTS:
                commands = [item['command'] for group in hooks['hooks'][event]
                            for item in group['hooks'] if item['type'] == 'command']
                self.assertEqual(commands.count(managed_command(codex_home)), 1)
            backups = sorted((codex_home / 'agent-harness' / 'backups').iterdir())
            self.assertEqual(len(backups), 2)
            self.assertTrue(all(stat.S_IMODE(path.stat().st_mode) == 0o700 for path in backups))
            first = json.loads((backups[0] / 'manifest.json').read_text())
            self.assertEqual({Path(item['path']).name for item in first}, {'AGENTS.md', 'hooks.json', 'config.toml'})

    def test_existing_policy_is_not_overridden(self):
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary).resolve()
            codex_home = home / '.codex'
            codex_home.mkdir()
            (codex_home / 'config.toml').write_text('default_permissions = "custom"\n\n[permissions.custom]\nextends = ":workspace"\n')
            install(home, apply=True)
            installed = tomllib.loads((codex_home / 'config.toml').read_text())
            self.assertEqual(installed['default_permissions'], 'custom')
            self.assertEqual(installed['permissions']['custom']['extends'], ':workspace')
            self.assertIn('agent-harness', installed['permissions'])
        with self.assertRaisesRegex(ValueError, 'legacy sandbox'):
            merge_config('sandbox_mode = "read-only"\n', Path('/tmp/example'))
        for legacy in ('"sandbox_mode" = "danger-full-access"\n',
                       '[profiles.locked]\nsandbox_mode = "read-only"\n',
                       '[profiles.locked.sandbox_workspace_write]\nwritable_roots = []\n'):
            with self.subTest(legacy=legacy), self.assertRaisesRegex(ValueError, 'legacy sandbox'):
                merge_config(legacy, Path('/tmp/example'))
        quoted = merge_config('"default_permissions" = "custom"\n', Path('/tmp/example'))
        self.assertEqual(tomllib.loads(quoted)['default_permissions'], 'custom')
        with self.assertRaisesRegex(ValueError, 'selects a profile'):
            merge_config('profile = "locked"\n', Path('/tmp/example'))

    def test_full_access_refuses_conflicting_user_owned_settings_before_any_write(self):
        for text in ('default_permissions = "custom"\n[permissions.custom]\nextends = ":workspace"\n',
                     '"approval_policy" = "on-request"\n',
                     'default_permissions = "agent-harness"\n'):
            with self.subTest(text=text[:30]), tempfile.TemporaryDirectory() as temporary:
                home = Path(temporary).resolve()
                codex_home = home / '.codex'
                codex_home.mkdir()
                config = codex_home / 'config.toml'
                config.write_text(text)
                with self.assertRaises(ValueError):
                    install(home, apply=True, default_full_access=True)
                self.assertEqual(config.read_text(), text)
                self.assertFalse((codex_home / 'agent-harness').exists())

    def test_full_access_preserves_matching_user_owned_policy(self):
        wal_dir = Path('/tmp/private-wals')
        original = ('"default_permissions" = ":danger-full-access"\n'
                    '"approval_policy" = "never"\n')
        merged = merge_config(original, wal_dir, default_full_access=True)
        self.assertTrue(merged.startswith(original))
        self.assertEqual(tomllib.loads(merged)['default_permissions'], ':danger-full-access')
        self.assertEqual(tomllib.loads(merged)['approval_policy'], 'never')
        self.assertEqual(merge_config(merged, wal_dir), merged)

    def test_full_access_cli_preview_apply_and_unflagged_reinstall(self):
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary).resolve()
            codex_home = home / '.codex'
            codex_home.mkdir()
            original = 'model = "gpt-6-sol"\n'
            (codex_home / 'config.toml').write_text(original)
            command = [sys.executable, str(ROOT / 'install_codex.py'), '--home', str(home),
                       '--default-full-access']
            preview = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(preview.returncode, 0, preview.stderr)
            self.assertIn('Full Access default requested', preview.stdout)
            self.assertEqual((codex_home / 'config.toml').read_text(), original)
            applied = subprocess.run([*command, '--apply'], capture_output=True, text=True)
            self.assertEqual(applied.returncode, 0, applied.stderr)
            config = (codex_home / 'config.toml').read_text()
            self.assertEqual(tomllib.loads(config)['default_permissions'], ':danger-full-access')
            self.assertEqual(tomllib.loads(config)['approval_policy'], 'never')
            backup = next((codex_home / 'agent-harness' / 'backups').rglob('*-config.toml'))
            self.assertEqual(backup.read_text(), original)
            install(home, apply=True)
            self.assertEqual((codex_home / 'config.toml').read_text(), config)

    def test_reinstall_preserves_settings_appended_after_profile(self):
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary).resolve()
            (home / '.codex').mkdir()
            install(home, apply=True)
            config_path = home / '.codex' / 'config.toml'
            with config_path.open('a') as handle:
                handle.write('\n[features]\nforeign_feature = true\n')
            install(home, apply=True)
            parsed = tomllib.loads(config_path.read_text())
            self.assertEqual(parsed['features']['foreign_feature'], True)
            self.assertEqual(parsed['default_permissions'], 'agent-harness')
            self.assertIn('agent-harness', parsed['permissions'])

    def test_symlinked_destination_is_refused_without_touching_outside(self):
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary).resolve()
            codex_home = home / '.codex'
            codex_home.mkdir()
            outside = home / 'outside'
            outside.write_text('unrelated')
            (codex_home / 'AGENTS.md').symlink_to(outside)
            with self.assertRaisesRegex(ValueError, 'symlinked'):
                install(home, apply=True)
            self.assertEqual(outside.read_text(), 'unrelated')

    def test_each_managed_write_failure_rolls_back_existing_files(self):
        from install_codex import atomic_write
        for boundary in range(len(AGENTS) + len(SKILL_FILES) + 4):
            with self.subTest(boundary=boundary), tempfile.TemporaryDirectory() as temporary:
                home = Path(temporary).resolve()
                codex_home = home / '.codex'
                codex_home.mkdir()
                (codex_home / 'AGENTS.md').write_text('Original instructions.\n')
                (codex_home / 'hooks.json').write_text('{"hooks":{}}\n')
                (codex_home / 'config.toml').write_text('model = "gpt-6-sol"\n')
                original = {name: (codex_home / name).read_bytes() for name in ('AGENTS.md', 'hooks.json', 'config.toml')}
                writes = 0
                fired = False

                def fail_once(path, data, mode=0o600, **kwargs):
                    nonlocal writes, fired
                    if 'backups' not in path.parts and not fired:
                        if writes == boundary:
                            fired = True
                            raise OSError('fixture: managed write interrupted')
                        writes += 1
                    return atomic_write(path, data, mode, **kwargs)

                with patch('install_codex.atomic_write', side_effect=fail_once):
                    with self.assertRaisesRegex(OSError, 'managed write interrupted'):
                        install(home, apply=True)
                self.assertTrue(fired)
                for name, contents in original.items():
                    self.assertEqual((codex_home / name).read_bytes(), contents)
                self.assertEqual(list((codex_home / 'agents').glob('harness_*.toml')), [])
                self.assertFalse((codex_home / 'skills' / 'agent-harness' / 'SKILL.md').exists())


class CodexWalTests(unittest.TestCase):
    def test_hook_metadata_and_notes_omit_prompt_and_tool_arguments(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(wal.Path, 'home', return_value=Path(temporary)):
            (Path(temporary) / '.agent-harness').mkdir()
            secret = 'sk-' + 'x' * 20
            events = [
                {'hook_event_name': 'SessionStart', 'session_id': 'fixture', 'source': 'startup'},
                {'hook_event_name': 'UserPromptSubmit', 'session_id': 'fixture', 'prompt': secret},
                {'hook_event_name': 'PreToolUse', 'session_id': 'fixture', 'tool_name': 'Bash',
                 'tool_use_id': 'tool-1', 'tool_input': {'command': f'echo {secret}'}},
                {'hook_event_name': 'SubagentStart', 'session_id': 'fixture', 'agent_id': 'owner-1',
                 'agent_type': 'harness_owner'},
            ]
            for event in events:
                with patch.object(wal.sys, 'stdin', io.StringIO(json.dumps(event))), \
                     patch.object(wal.sys, 'stdout', new_callable=io.StringIO) as output:
                    wal.hook()
                if event['hook_event_name'] != 'PreToolUse':
                    context = json.loads(output.getvalue())['hookSpecificOutput']
                    self.assertEqual(context['hookEventName'], event['hook_event_name'])
                    self.assertIn('WAL:', context['additionalContext'])
            root = wal.wal_root()
            main = root / 'fixture' / 'main.jsonl'
            agent = root / 'fixture' / 'agent-owner-1.jsonl'
            records = [json.loads(line) for line in main.read_text().splitlines()]
            self.assertEqual(len(records), 4)
            self.assertEqual(records[1]['prompt_chars'], len(secret))
            self.assertEqual(records[2]['input_chars'], len(json.dumps({'command': f'echo {secret}'})))
            self.assertNotIn(secret, main.read_text())
            self.assertTrue(agent.exists())
            self.assertEqual(stat.S_IMODE(root.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(agent.parent.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE(agent.stat().st_mode), 0o600)
            with self.assertRaisesRegex(ValueError, 'credential'):
                wal.note(main, 'intent', f'Bearer {secret}')
            with patch.object(wal.sys, 'stdout', new_callable=io.StringIO):
                wal.note(main, 'intent', 'Scope and expected result without private values')
            self.assertEqual(json.loads(main.read_text().splitlines()[-1])['event'], 'intent')

    def test_crash_tail_and_symlink_refusal(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(wal.Path, 'home', return_value=Path(temporary)):
            (Path(temporary) / '.agent-harness').mkdir()
            path = wal.wal_root() / 'fixture' / 'main.jsonl'
            wal.append(path, {'event': 'first'})
            with path.open('ab') as handle:
                handle.write(b'{"interrupted":')
            wal.append(path, {'event': 'second'})
            self.assertEqual([json.loads(line)['event'] for line in path.read_text().splitlines()],
                             ['first', 'second'])
            outside = Path(temporary) / 'outside'
            outside.write_text('preserve')
            path.unlink()
            path.symlink_to(outside)
            with self.assertRaises(OSError):
                wal.append(path, {'event': 'blocked'})
            self.assertEqual(outside.read_text(), 'preserve')

    def test_eight_processes_write_complete_records(self):
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary).resolve()
            (home / '.agent-harness').mkdir()
            path = home / '.agent-harness' / 'codex-wals' / 'fixture' / 'main.jsonl'
            code = ('import sys\nfrom pathlib import Path\n'
                    f'sys.path.insert(0,{str(SOURCE / "hooks")!r})\n'
                    'from wal import append\n'
                    'for i in range(25): append(Path(sys.argv[1]), {"worker":sys.argv[2],"i":i})\n')
            workers = [subprocess.Popen([sys.executable, '-c', code, str(path), str(i)],
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                        env={**os.environ, 'HOME': str(home)})
                       for i in range(8)]
            for worker in workers:
                stdout, stderr = worker.communicate(timeout=15)
                self.assertEqual(worker.returncode, 0, (stdout, stderr))
            records = [json.loads(line) for line in path.read_text().splitlines()]
            self.assertEqual(len(records), 200)
            self.assertEqual(len({(record['worker'], record['i']) for record in records}), 200)


if __name__ == '__main__':
    unittest.main()
