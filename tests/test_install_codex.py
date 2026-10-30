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
from install_codex import (AGENTS, HOOK_EVENTS, SKILL_FILES, SOURCE, install,
                           managed_command, merge_config, tomllib)


ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(tomllib is not None, 'Codex installer requires Python 3.11+')
class CodexInstallerTests(unittest.TestCase):
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
            (codex_home / 'config.toml').write_text('default_permissions = "custom"\n')
            with self.assertRaisesRegex(ValueError, 'different permission profile'):
                install(home, apply=True)
            self.assertEqual((codex_home / 'config.toml').read_text(), 'default_permissions = "custom"\n')
        with self.assertRaisesRegex(ValueError, 'legacy sandbox'):
            merge_config('sandbox_mode = "read-only"\n', Path('/tmp/example'))
        for legacy in ('"sandbox_mode" = "danger-full-access"\n',
                       '[profiles.locked]\nsandbox_mode = "read-only"\n',
                       '[profiles.locked.sandbox_workspace_write]\nwritable_roots = []\n'):
            with self.subTest(legacy=legacy), self.assertRaisesRegex(ValueError, 'legacy sandbox'):
                merge_config(legacy, Path('/tmp/example'))
        with self.assertRaisesRegex(ValueError, 'different permission profile'):
            merge_config('"default_permissions" = "custom"\n', Path('/tmp/example'))
        with self.assertRaisesRegex(ValueError, 'selects a profile'):
            merge_config('profile = "locked"\n', Path('/tmp/example'))

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
