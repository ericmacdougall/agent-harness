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
from install_codex import (AGENTS, CONFIG_END, CONFIG_START, DELIVERY_HELPERS, SKILL_FILES, SOURCE, install,
                           legacy_profile, managed_command, managed_groups, merge_config, merge_marked, sandbox_module,
                           tomllib)


ROOT = Path(__file__).resolve().parents[1]


def profiles(home=Path('/nonexistent-ah-home')):
    """The three sandbox profiles the installer writes for this home (ah_sandbox.codex_profiles)."""
    return sandbox_module().codex_profiles(home=home)


P = profiles()


@unittest.skipUnless(tomllib is not None, 'Codex installer requires Python 3.11+')
class CodexInstallerTests(unittest.TestCase):
    def test_task_recovery_survives_reinstall(self):
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary).resolve()
            for _ in range(2):
                install(home, apply=True)
                helper = home / ".codex/agent-harness/task_recovery.py"
                self.assertEqual(helper.read_bytes(), (ROOT / "harness/hooks/task_recovery.py").read_bytes())
                result = subprocess.run([sys.executable, str(helper), "--help"], cwd=home,
                                        capture_output=True, text=True, timeout=10)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn("enroll", result.stdout)

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
        merged = merge_config(original, Path('/tmp/private-wals'), P)
        self.assertEqual(tomllib.loads(merged)['note'], tomllib.loads(original)['note'])

    def test_toml_marker_lines_inside_value_survive_reinstallation(self):
        original = ('note = """before\n# agent-harness-codex:profile-start\n'
                    'user value\n# agent-harness-codex:profile-end\nafter"""\n')
        first = merge_config(original, Path('/tmp/private-wals'), P)
        second = merge_config(first, Path('/tmp/private-wals'), P)
        self.assertEqual(tomllib.loads(first)['note'], tomllib.loads(original)['note'])
        self.assertEqual(tomllib.loads(second)['note'], tomllib.loads(original)['note'])
        self.assertEqual(first, second)

    def test_toml_profile_comment_collision_refuses_without_erasure(self):
        original = merge_config('note = "preserve"\n', Path('/tmp/private-wals'), P)
        modified = original.replace('[permissions.ah-worker]\n',
                                    '[permissions.ah-worker]\n# user comment that must survive\n')
        with self.assertRaisesRegex(ValueError, 'managed profile was edited'):
            merge_config(modified, Path('/tmp/private-wals'), P)
        extra_marker = original + '\n# agent-harness-codex:profile-start\n'
        with self.assertRaisesRegex(ValueError, 'ambiguous or malformed'):
            merge_config(extra_marker, Path('/tmp/private-wals'), P)

    def test_reinstall_moves_unrelated_sections_out_of_managed_profile(self):
        wal_dir = Path('/tmp/private-wals')
        original = merge_config('model = "gpt-6-sol"\n', wal_dir, P)
        extra = ('\n[tui]\nanimations = false\n\n[hooks.state]\n'
                 'trusted_hash = "synthetic-value"  # retained spaces  \n\n')
        with_inside = original.replace(CONFIG_END, extra + CONFIG_END, 1)
        merged = merge_config(with_inside, wal_dir, P)
        self.assertEqual(tomllib.loads(merged), tomllib.loads(with_inside))
        self.assertIn(extra, merged)
        self.assertLess(merged.index(extra), merged.index(CONFIG_START))
        self.assertEqual(merged.count(CONFIG_START), 1)
        self.assertEqual(merged.count(CONFIG_END), 1)
        self.assertEqual(merge_config(merged, wal_dir, P), merged)

    def test_reinstall_preserves_mixed_endings_and_multiline_user_value(self):
        wal_dir = Path('/tmp/private-wals')
        original = merge_config('model = "gpt-6-sol"\n', wal_dir, P)
        extra = ('\r\n[tui]\r\nnote = """before\n'
                 '# agent-harness-codex:profile-end\n[permissions.agent-harness]\n'
                 'after"""\r\n\r\n[[hooks.plugins]]\r\nname = "synthetic"\r\n')
        with_inside = original.replace(CONFIG_END, extra + CONFIG_END, 1)
        merged = merge_config(with_inside, wal_dir, P)
        self.assertIn(extra, merged)
        self.assertEqual(tomllib.loads(merged), tomllib.loads(with_inside))
        self.assertEqual(merge_config(merged, wal_dir, P), merged)

    def test_reinstall_preserves_quoted_unrelated_tables_and_outer_suffix(self):
        wal_dir = Path('/tmp/private-wals')
        original = merge_config('model = "gpt-6-sol"\n', wal_dir, P)
        extra = ('\n["hooks"."state.v2"]\ntrusted_hash = "synthetic"\n'
                 '\n[permissionsExtra]\nflag = true\n')
        outside = '\n[features]\nforeign = true\n'
        with_inside = original.replace(CONFIG_END, extra + CONFIG_END, 1) + outside
        merged = merge_config(with_inside, wal_dir, P)
        self.assertIn(extra, merged)
        self.assertTrue(merged.endswith(outside))
        self.assertEqual(tomllib.loads(merged), tomllib.loads(with_inside))
        self.assertEqual(merge_config(merged, wal_dir, P), merged)

    def test_reinstall_refuses_managed_edits_and_ambiguous_suffix(self):
        wal_dir = Path('/tmp/private-wals')
        original = merge_config('model = "gpt-6-sol"\n', wal_dir, P)
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
                merge_config(text, wal_dir, P)

    def test_a_fresh_install_selects_no_role_and_a_reinstall_keeps_the_users_choice(self):
        wal_dir = Path('/tmp/private-wals')
        original = merge_config('model = "gpt-6-sol"\n', wal_dir, P)
        parsed = tomllib.loads(original)
        self.assertNotIn('default_permissions', parsed)  # turning the boundary on is the owner's step
        self.assertEqual(set(parsed['permissions']), {'ah-worker', 'ah-reviewer', 'ah-supervisor'})
        extra = '\n[tui]\nanimations = false\n'
        with_inside = original.replace(CONFIG_END, extra + CONFIG_END, 1)
        merged = merge_config(with_inside, wal_dir, P)
        self.assertEqual(tomllib.loads(merged)['tui']['animations'], False)
        self.assertEqual(merge_config(merged, wal_dir, P), merged)
        chosen = 'default_permissions = "ah-supervisor"\n' + merged  # the user's own line, not an owned one
        self.assertEqual(merge_config(chosen, wal_dir, P), chosen)

    def test_the_retired_profile_is_replaced_and_its_owned_default_becomes_ah_worker(self):
        wal_dir = Path('/tmp/private-wals')
        old = ('default_permissions = "agent-harness" # agent-harness-codex\nmodel = "gpt-6-sol"\n\n'
               + CONFIG_START + '\n' + legacy_profile(wal_dir) + '\n' + CONFIG_END + '\n')
        merged = merge_config(old, wal_dir, P)
        parsed = tomllib.loads(merged)
        self.assertEqual(parsed['default_permissions'], 'ah-worker')
        self.assertNotIn('agent-harness', parsed['permissions'])
        self.assertEqual(set(parsed['permissions']), {'ah-worker', 'ah-reviewer', 'ah-supervisor'})
        self.assertEqual(parsed['model'], 'gpt-6-sol')
        self.assertEqual(merged.count(CONFIG_START), 1)
        self.assertEqual(merge_config(merged, wal_dir, P), merged)

    def test_an_owned_full_access_line_is_kept_with_a_note(self):
        from install_codex import full_access_note
        wal_dir = Path('/tmp/private-wals')
        old = ('approval_policy = "never" # agent-harness-codex\n'
               'default_permissions = ":danger-full-access" # agent-harness-codex\n'
               + CONFIG_START + '\n' + legacy_profile(wal_dir) + '\n' + CONFIG_END + '\n')
        merged = merge_config(old, wal_dir, P)
        parsed = tomllib.loads(merged)
        self.assertEqual(parsed['default_permissions'], ':danger-full-access')  # no silent change of a live default
        self.assertEqual(parsed['approval_policy'], 'never')
        self.assertIn('--default-role worker', full_access_note(merged))
        self.assertIsNone(full_access_note(merge_config('', wal_dir, P)))
        role = merge_config(merged, wal_dir, P, default_role='worker')  # the owner chooses a role instead
        self.assertEqual(tomllib.loads(role)['default_permissions'], 'ah-worker')
        self.assertEqual(role.count('default_permissions'), 1)

    def test_owned_line_detection_ignores_multiline_and_nested_spoofs(self):
        wal_dir = Path('/tmp/private-wals')
        original = ('note = """before\n'
                    'default_permissions = "agent-harness" # agent-harness-codex\n'
                    'after"""\n'
                    '[view]\n'
                    'default_permissions = "agent-harness" # agent-harness-codex\n')
        merged = merge_config(original, wal_dir, P)
        parsed = tomllib.loads(merged)
        self.assertIn('default_permissions = "agent-harness"', parsed['note'])
        self.assertEqual(parsed['view']['default_permissions'], 'agent-harness')
        self.assertNotIn('default_permissions', parsed)

    def test_permissions_scalar_is_refused_cleanly(self):
        # permissions = "..." is malformed for Codex too; refuse it like the other
        # config problems instead of crashing on str.get.
        for text in ('permissions = "oops"\n',
                     'permissions = "x agent-harness y"\n'):
            with self.subTest(text=text), self.assertRaisesRegex(ValueError, 'permissions must be a table'):
                merge_config(text, Path('/tmp/example'), P)

    def test_rejected_apply_leaves_synthetic_config_unchanged(self):
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary).resolve()
            codex_home = home / '.codex'
            codex_home.mkdir()
            wal_dir = home / '.agent-harness' / 'codex-wals'
            original = merge_config('model = "gpt-6-sol"\n', wal_dir, profiles(home))
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
            original = merge_config('model = "gpt-6-sol"\n', wal_dir, profiles(home))
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
    def test_custom_same_command_lifecycle_hook_refuses_without_writes(self):
        for event, options in (
            ('Stop', {'matcher': 'custom', 'timeout': 10}),
            ('Interrupt', {'timeout': 3}),
            ('Stop', {'timeout': 10, 'statusMessage': 'Operator customization'}),
        ):
            with self.subTest(event=event, options=options), tempfile.TemporaryDirectory() as temporary:
                home = Path(temporary).resolve()
                codex_home = home / '.codex'
                codex_home.mkdir()
                agents = codex_home / 'AGENTS.md'
                config = codex_home / 'config.toml'
                hooks = codex_home / 'hooks.json'
                agents.write_text('Operator instructions.')
                config.write_text('model = "gpt-6-sol"\n')
                handler = {'type': 'command', 'command': managed_command(codex_home),
                           'timeout': options['timeout']}
                group = {'hooks': [handler]}
                if 'matcher' in options:
                    group['matcher'] = options['matcher']
                if 'statusMessage' in options:
                    handler['statusMessage'] = options['statusMessage']
                hooks.write_text(json.dumps({'hooks': {event: [group]}}))
                before = {path: path.read_bytes() for path in (agents, config, hooks)}
                with self.assertRaisesRegex(ValueError, f'custom {event}'):
                    install(home, apply=True)
                self.assertEqual({path: path.read_bytes() for path in before}, before)
                self.assertFalse((codex_home / 'agent-harness').exists())

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
            self.assertEqual(len(preview), len(set(preview)))
            self.assertTrue({str(codex_home / 'agent-harness' / name) for name in DELIVERY_HELPERS} <= set(preview))
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
            self.assertNotIn('default_permissions', tomllib.loads(config))
            self.assertIn('model = "gpt-6-sol"', config)
            self.assertIn('example = true', config)
            self.assertEqual(config.count('[permissions.ah-worker]'), 1)
            self.assertEqual(config.count(CONFIG_START), 1)
            self.assertIn(P.rstrip('\n'), config)
            self.assertEqual(stat.S_IMODE((home / '.agent-harness' / 'codex-wals').stat().st_mode), 0o700)
            hooks = json.loads((codex_home / 'hooks.json').read_text())
            self.assertEqual(hooks['custom'], {'keep': True})
            self.assertEqual(hooks['hooks']['Stop'][0], {'hooks': [foreign]})
            self.assertEqual(hooks['hooks']['PreToolUse'], [{'matcher': 'Bash', 'hooks': [foreign]}])  # the user's only
            for event, groups in managed_groups(codex_home).items():
                self.assertEqual([g for g in hooks['hooks'][event] if g in groups], groups)
            backups = sorted((codex_home / 'agent-harness' / 'backups').iterdir())
            self.assertEqual(len(backups), 2)
            self.assertTrue(all(stat.S_IMODE(path.stat().st_mode) == 0o700 for path in backups))
            first = json.loads((backups[0] / 'manifest.json').read_text())
            self.assertEqual({Path(item['path']).name for item in first}, {'AGENTS.md', 'hooks.json', 'config.toml'})

    def test_delivery_workflow_dependency_closure_starts_without_claude_or_source_imports(self):
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary).resolve()
            install(home, apply=True)
            harness = home / '.codex' / 'agent-harness'
            required = ('deliver.py', 'github_identity.py', 'process.py', 'git_safety.py',
                        'report_file.py', 'publish_feature.py', 'integrate_local.py')
            for name in required:
                target = harness / name
                self.assertTrue(target.is_file(), f'{name} was not installed')
                self.assertEqual(target.read_bytes(), (ROOT / 'harness' / 'hooks' / name).read_bytes())
            self.assertFalse((home / '.claude').exists())
            environment = {key: value for key, value in os.environ.items() if key != 'PYTHONPATH'}
            environment.update(HOME=str(home), PYTHONNOUSERSITE='1')
            result = subprocess.run([sys.executable, str(harness / 'deliver.py'), '--help'],
                                    cwd=home, env=environment, text=True, capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn('prepare', result.stdout)
            self.assertIn('finish', result.stdout)

    def test_installed_usage_guard_starts_without_claude_or_source_imports(self):
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary).resolve()
            install(home, apply=True)
            helper = home / '.codex/agent-harness/usage_guard.py'
            self.assertTrue(helper.is_file(), 'Usage guard was not installed')
            self.assertEqual(helper.read_bytes(), (ROOT / 'harness/hooks/usage_guard.py').read_bytes())
            self.assertFalse((home / '.claude').exists())
            state = home / 'owned-usage-state'
            environment = {key: value for key, value in os.environ.items() if key != 'PYTHONPATH'}
            environment.update(HOME=str(home), PYTHONNOUSERSITE='1', AGENT_HARNESS_USAGE_DIR=str(state))
            result = subprocess.run([sys.executable, str(helper), '--help'], cwd=home,
                                    env=environment, text=True, capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn('reconcile', result.stdout)
            self.assertFalse(state.exists(), 'Help must not create usage state')

    def test_installed_watcher_runs_without_claude_or_source_imports(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            home = root / 'home'
            project = root / 'project'
            elsewhere = root / 'elsewhere'
            for directory in (home, project, elsewhere):
                directory.mkdir()
            watcher = home / '.codex' / 'agent-harness' / 'watch-tests.py'
            self.assertIn(str(watcher), install(home, apply=False))
            self.assertFalse(watcher.exists())
            install(home, apply=True)
            self.assertEqual(watcher.read_bytes(), (ROOT / 'harness' / 'tools' / 'watch-tests.py').read_bytes())
            self.assertFalse((home / '.claude').exists())
            poison_marker = root / 'foreign-process-imported'
            poison = (f'from pathlib import Path; Path({str(poison_marker)!r}).touch(); '
                      'raise RuntimeError("foreign watcher helper imported")\n')
            foreign_hooks = home / '.codex' / 'hooks'
            foreign_hooks.mkdir()
            (foreign_hooks / 'process.py').write_text(poison)
            (elsewhere / 'process.py').write_text(poison)
            environment = {key: value for key, value in os.environ.items()
                           if key not in ('PYTHONPATH', 'PYTHONHOME')}
            environment.update(HOME=str(home), PYTHONNOUSERSITE='1', PYTHONPATH=str(elsewhere))
            help_result = subprocess.run([sys.executable, str(watcher), '--help'],
                                         cwd=elsewhere, env=environment, text=True,
                                         capture_output=True, timeout=10)
            self.assertEqual(help_result.returncode, 0, help_result.stdout + help_result.stderr)
            self.assertIn('--once', help_result.stdout)
            self.assertIn('--root', help_result.stdout)
            command = ('import json, os, sys; from pathlib import Path; '
                       'Path(sys.argv[1]).write_text(json.dumps({"cwd": str(Path.cwd()), "home": os.environ["HOME"]})); '
                       'raise SystemExit(int(sys.argv[2]))')
            for exit_code in (0, 7):
                with self.subTest(exit_code=exit_code):
                    marker = project / f'run-{exit_code}.json'
                    result = subprocess.run(
                        [sys.executable, str(watcher), '--root', str(project), '--once', '--',
                         sys.executable, '-c', command, str(marker), str(exit_code)],
                        cwd=elsewhere, env=environment, text=True, capture_output=True, timeout=10)
                    self.assertEqual(result.returncode, exit_code, result.stdout + result.stderr)
                    self.assertIn(f'[watch] exit {exit_code}', result.stdout)
                    self.assertEqual(json.loads(marker.read_text()), {'cwd': str(project), 'home': str(home)})
            self.assertFalse(poison_marker.exists(), 'watcher imported a foreign process helper')
            self.assertFalse((home / '.claude').exists())

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
            self.assertIn('ah-worker', installed['permissions'])
        with self.assertRaisesRegex(ValueError, 'legacy sandbox'):
            merge_config('sandbox_mode = "read-only"\n', Path('/tmp/example'), P)
        for legacy in ('"sandbox_mode" = "danger-full-access"\n',
                       '[profiles.locked]\nsandbox_mode = "read-only"\n',
                       '[profiles.locked.sandbox_workspace_write]\nwritable_roots = []\n'):
            with self.subTest(legacy=legacy), self.assertRaisesRegex(ValueError, 'legacy sandbox'):
                merge_config(legacy, Path('/tmp/example'), P)
        quoted = merge_config('"default_permissions" = "custom"\n', Path('/tmp/example'), P)
        self.assertEqual(tomllib.loads(quoted)['default_permissions'], 'custom')
        with self.assertRaisesRegex(ValueError, 'selects a profile'):
            merge_config('profile = "locked"\n', Path('/tmp/example'), P)
        with self.assertRaisesRegex(ValueError, 'outside the managed markers'):
            merge_config('[permissions.ah-worker]\nextends = ":workspace"\n', Path('/tmp/example'), P)

    def test_default_role_refuses_a_user_owned_default_before_any_write(self):
        for text in ('default_permissions = "custom"\n[permissions.custom]\nextends = ":workspace"\n',
                     'default_permissions = "agent-harness"\n'):
            with self.subTest(text=text[:30]), tempfile.TemporaryDirectory() as temporary:
                home = Path(temporary).resolve()
                codex_home = home / '.codex'
                codex_home.mkdir()
                config = codex_home / 'config.toml'
                config.write_text(text)
                with self.assertRaisesRegex(ValueError, 'user-owned permission default'):
                    install(home, apply=True, default_role='worker')
                self.assertEqual(config.read_text(), text)
                self.assertFalse((codex_home / 'agent-harness').exists())
        with self.assertRaisesRegex(ValueError, 'default-role'):
            merge_config('', Path('/tmp/example'), P, default_role='reviewer')

    def test_default_role_writes_one_owned_line_and_a_plain_reinstall_keeps_it(self):
        wal_dir = Path('/tmp/private-wals')
        merged = merge_config('model = "gpt-6-sol"\n', wal_dir, P, default_role='supervisor')
        self.assertEqual(tomllib.loads(merged)['default_permissions'], 'ah-supervisor')
        self.assertEqual(merged.count('default_permissions = "ah-supervisor" # agent-harness-codex'), 1)
        self.assertEqual(merge_config(merged, wal_dir, P), merged)
        worker = merge_config(merged, wal_dir, P, default_role='worker')
        self.assertEqual(tomllib.loads(worker)['default_permissions'], 'ah-worker')
        self.assertEqual(worker.count('default_permissions'), 1)

    def test_removed_flags_fail_loudly_and_default_role_cli_applies(self):
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary).resolve()
            codex_home = home / '.codex'
            codex_home.mkdir()
            original = 'model = "gpt-6-sol"\n'
            (codex_home / 'config.toml').write_text(original)
            for flag in ('--default-full-access', '--no-command-guard'):
                done = subprocess.run([sys.executable, str(ROOT / 'install_codex.py'), '--home', str(home), '--apply',
                                       flag], capture_output=True, text=True, timeout=120)
                self.assertNotEqual(done.returncode, 0)
                self.assertIn(f'install_codex.py: {flag} was removed in release 1001:', done.stderr)
                self.assertEqual((codex_home / 'config.toml').read_text(), original)
                self.assertFalse((codex_home / 'agent-harness').exists())
            command = [sys.executable, str(ROOT / 'install_codex.py'), '--home', str(home), '--default-role', 'worker',
                       '--no-netwatch']
            applied = subprocess.run([*command, '--apply'], capture_output=True, text=True, timeout=120)
            self.assertEqual(applied.returncode, 0, applied.stderr)
            self.assertIn('/hooks', applied.stdout)
            config = (codex_home / 'config.toml').read_text()
            self.assertEqual(tomllib.loads(config)['default_permissions'], 'ah-worker')
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
            self.assertNotIn('default_permissions', parsed)
            self.assertIn('ah-worker', parsed['permissions'])

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

        # Observe the real payload publication sequence, not an arithmetic
        # estimate that can silently miss writes when helper closure grows.
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary).resolve()
            codex_home = home / '.codex'
            codex_home.mkdir()
            planned = [Path(path) for path in install(home, apply=False)]
            observed = []

            def record_write(path, data, mode=0o600, **kwargs):
                if 'backups' not in path.relative_to(codex_home).parts:
                    observed.append(path)
                return atomic_write(path, data, mode, **kwargs)

            with patch('install_codex.atomic_write', side_effect=record_write):
                install(home, apply=True)
            self.assertEqual(observed, planned)
            self.assertEqual(len(observed), len(set(observed)))
            relative_plan = [path.relative_to(codex_home) for path in observed]
        fired_boundaries = set()
        for existing in (False, True):
            for boundary, failed_destination in enumerate(relative_plan):
                with self.subTest(existing=existing, boundary=boundary, destination=str(failed_destination)), \
                        tempfile.TemporaryDirectory() as temporary:
                    home = Path(temporary).resolve()
                    codex_home = home / '.codex'
                    codex_home.mkdir()
                    if existing:
                        for index, relative in enumerate(relative_plan):
                            path = codex_home / relative
                            path.parent.mkdir(parents=True, exist_ok=True)
                            path.write_text('Original managed file: ' + str(relative) + '\n')
                            path.chmod(0o600 if index % 2 else 0o640)
                    (codex_home / 'AGENTS.md').write_text('Original instructions.\n')
                    (codex_home / 'hooks.json').write_text('{"hooks":{}}\n')
                    (codex_home / 'config.toml').write_text('model = "gpt-6-sol"\n')
                    foreign = codex_home / 'foreign.txt'
                    foreign.write_text('unrelated user data\n')
                    foreign.chmod(0o640)

                    def snapshot():
                        return {str(path.relative_to(codex_home)):
                                (path.read_bytes(), stat.S_IMODE(path.stat().st_mode))
                                for path in codex_home.rglob('*')
                                if path.is_file() and 'backups' not in path.relative_to(codex_home).parts}

                    before = snapshot()
                    writes = []
                    fired = False

                    def fail_once(path, data, mode=0o600, **kwargs):
                        nonlocal fired
                        if 'backups' not in path.relative_to(codex_home).parts and not fired:
                            relative = path.relative_to(codex_home)
                            self.assertEqual(relative, relative_plan[len(writes)])
                            if len(writes) == boundary:
                                fired = True
                                fired_boundaries.add((existing, relative))
                                raise OSError('fixture: managed write interrupted')
                            writes.append(relative)
                        return atomic_write(path, data, mode, **kwargs)

                    with patch('install_codex.atomic_write', side_effect=fail_once):
                        with self.assertRaisesRegex(OSError, 'managed write interrupted'):
                            install(home, apply=True)
                    self.assertTrue(fired, 'planned failure boundary never executed')
                    self.assertEqual(len(writes), boundary)
                    self.assertEqual(snapshot(), before)
        self.assertEqual(fired_boundaries,
                         {(existing, relative) for existing in (False, True) for relative in relative_plan})


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
                if event['hook_event_name'] in ('UserPromptSubmit', 'PreToolUse'):
                    self.assertEqual(output.getvalue(), '')  # no longer registered: a stale call writes nothing
                else:
                    context = json.loads(output.getvalue())['hookSpecificOutput']
                    self.assertEqual(context['hookEventName'], event['hook_event_name'])
                    self.assertIn('WAL:', context['additionalContext'])
            root = wal.wal_root()
            main = root / 'fixture' / 'main.jsonl'
            agent = root / 'fixture' / 'agent-owner-1.jsonl'
            records = [json.loads(line) for line in main.read_text().splitlines()]
            self.assertEqual([r['event'] for r in records], ['SessionStart', 'SubagentStart'])
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


class CodexCopiesTheDropboxBudget(unittest.TestCase):
    def test_budget_file_ships_and_the_heavy_guard_does_not(self):
        import install_codex
        self.assertNotIn('heavy_job_guard.py', install_codex.DELIVERY_HELPERS)  # deleted in release 1001
        self.assertIn('dropbox_budget.conf', install_codex.DELIVERY_HELPERS)  # log-backup.sh still reads it
