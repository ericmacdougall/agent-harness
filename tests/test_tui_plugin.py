"""Local TUI plugin contracts; no provider accounts or model calls required."""

import base64
import hashlib
import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import install_tui_plugin


ROOT = Path(__file__).resolve().parents[1]
PLUGIN = ROOT / 'plugins' / 'harness-tui'
LAUNCHER = PLUGIN / 'launcher.py'
SPEC = importlib.util.spec_from_file_location('tui_launcher', LAUNCHER)
launcher = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(launcher)


def reference(**changes):
    value = {'schema': 1, 'client': 'test', 'captured_at': '2026-11-02T00:00:00Z',
             'title': 'Current conversation', 'kind': 'summary',
             'body': 'Reference only: $(touch DO_NOT_EXECUTE)\nUnicode: café 🦆',
             'truncated': False}
    value.update(changes)
    return value


class TuiPluginEntryTests(unittest.TestCase):
    def test_reference_preparation_is_private_and_inert(self):
        with tempfile.TemporaryDirectory() as folder:
            env = {**os.environ, 'HOME': folder, 'PYTHONDONTWRITEBYTECODE': '1'}
            result = subprocess.run([sys.executable, str(LAUNCHER), 'prepare'],
                                    input=json.dumps(reference()), text=True,
                                    capture_output=True, cwd=folder, env=env, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            prepared = json.loads(result.stdout)
            self.assertEqual(prepared['status'], 'PREPARED')
            path = Path(prepared['reference_file'])
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(path.parent.stat().st_mode & 0o777, 0o700)
            self.assertEqual(json.loads(path.read_text())['body'], reference()['body'])
            self.assertFalse((Path(folder) / 'DO_NOT_EXECUTE').exists())
            self.assertNotIn(reference()['body'], result.stdout + result.stderr)

    def test_shared_vectors(self):
        vectors = json.loads((PLUGIN / 'schema/reference-v1-vectors.json').read_text())
        self.assertGreater(len(vectors['cases']), 20)
        for item in vectors['cases']:
            with self.subTest(case=item['id']):
                raw = (base64.b64decode(item['utf8_base64']) if 'utf8_base64' in item
                       else item['json'].encode('utf-8'))
                if item['valid']:
                    self.assertEqual(launcher.read_reference(raw)['schema'], 1)
                else:
                    with self.assertRaises(launcher.InvalidReference):
                        launcher.read_reference(raw)

    def test_limits_are_encoded_bytes(self):
        launcher.validate_reference(reference(body='x' * 131072))
        with self.assertRaises(launcher.InvalidReference):
            launcher.validate_reference(reference(body='x' * 131073))
        with self.assertRaises(launcher.InvalidReference):
            launcher.validate_reference(reference(body='🦆' * 32769))
        with self.assertRaises(launcher.InvalidReference):
            launcher.validate_reference(reference(body='\x01' * 50000))
        with self.assertRaises(launcher.InvalidReference):
            launcher.read_reference(b' ' * 262145)

    def test_huge_number_and_deep_json_fail_without_echo(self):
        for raw in (b'{"x":' + b'9' * 10000 + b'}', b'[' * 1500 + b'0' + b']' * 1500):
            with self.assertRaises(launcher.InvalidReference):
                launcher.read_reference(raw)

    def test_redaction_and_source_url(self):
        with tempfile.TemporaryDirectory() as folder, patch.dict(os.environ, HOME=folder):
            prepared = launcher.prepare_reference(reference(
                body='api_key="example-secret-value" Bearer aaaaBBBBccccDDDD sk-exampleKey123456789',
                source_url='https://chatgpt.com/c/current?token=private#secret'))
            saved = json.loads(Path(prepared['reference_file']).read_text())
            self.assertIn('[REDACTED]', saved['body'])
            for secret in ('example-secret-value', 'aaaaBBBBccccDDDD', 'sk-exampleKey123456789'):
                self.assertNotIn(secret, saved['body'])
            self.assertEqual(saved['source_url'], 'https://chatgpt.com/c/current')

    def test_symlinked_storage_refused(self):
        with tempfile.TemporaryDirectory() as folder, tempfile.TemporaryDirectory() as target:
            (Path(folder) / '.agent-harness').symlink_to(target, target_is_directory=True)
            with patch.dict(os.environ, HOME=folder), self.assertRaises(OSError):
                launcher.prepare_reference(reference())
            self.assertEqual(list(Path(target).iterdir()), [])

    def test_insecure_existing_storage_refused(self):
        with tempfile.TemporaryDirectory() as folder, patch.dict(os.environ, HOME=folder):
            root = Path(folder) / '.agent-harness'
            root.mkdir(mode=0o755)
            root.chmod(0o755)
            with self.assertRaises(launcher.InvalidReference):
                launcher.prepare_reference(reference())
            self.assertEqual(list(root.iterdir()), [])

    def configured(self, folder):
        root = Path(folder) / '.agent-harness'
        root.mkdir(mode=0o700, exist_ok=True)
        binary = Path(folder) / 'fake-tui'
        binary.write_text('#!' + sys.executable + '\nimport json,os,sys\n'
                          'open(os.path.join(os.environ["HOME"],"argv.json"),"w").write(json.dumps(sys.argv[1:]))\n')
        binary.chmod(0o700)
        config = root / 'tui-launcher.json'
        config.write_text(json.dumps({'schema': 1, 'binary': str(binary)}))
        config.chmod(0o600)
        return binary

    def test_missing_config_retains_reference_without_open(self):
        with tempfile.TemporaryDirectory() as folder, patch.dict(os.environ, HOME=folder):
            with patch.object(launcher.subprocess, 'run') as dispatch:
                result = launcher.open_reference(reference())
            dispatch.assert_not_called()
            self.assertEqual(result['status'], 'NOT_LAUNCHED')
            self.assertTrue(Path(result['reference_file']).is_file())

    def test_terminal_request_has_no_body_or_shell_interpolation(self):
        with tempfile.TemporaryDirectory(prefix="tui space ' ") as folder, patch.dict(os.environ, HOME=folder):
            self.configured(folder)
            with patch.object(launcher.sys, 'platform', 'darwin'), patch.object(
                    launcher.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0)) as dispatch:
                result = launcher.open_reference(reference())
            self.assertEqual(result['status'], 'LAUNCH_REQUESTED')
            self.assertIn('not confirmed', result['note'])
            args = dispatch.call_args.args[0]
            self.assertEqual(args[:3], ['/usr/bin/open', '-a', 'Terminal'])
            command = Path(args[3]).read_text()
            self.assertNotIn(reference()['body'], command)
            self.assertNotIn('touch DO_NOT_EXECUTE', command)
            self.assertEqual(Path(args[3]).stat().st_mode & 0o777, 0o700)
            self.assertNotIn('shell', dispatch.call_args.kwargs)
            child_env = dispatch.call_args.kwargs.get('env')
            self.assertIsInstance(child_env, dict)
            self.assertEqual(child_env['HOME'], folder)
            self.assertEqual(set(child_env), {'HOME', 'TERM', 'PATH', 'LANG'})

    def test_timeout_is_unknown_and_never_automatically_retried(self):
        with tempfile.TemporaryDirectory() as folder, patch.dict(os.environ, HOME=folder):
            self.configured(folder)
            with patch.object(launcher.sys, 'platform', 'darwin'), patch.object(
                    launcher.subprocess, 'run', side_effect=subprocess.TimeoutExpired('open', 10)) as dispatch:
                result = launcher.open_reference(reference())
            self.assertEqual(result['status'], 'UNKNOWN')
            self.assertEqual(dispatch.call_count, 1)

    def test_foreground_passes_only_private_path_and_digest(self):
        with tempfile.TemporaryDirectory() as folder, patch.dict(os.environ, HOME=folder):
            self.configured(folder)
            prepared = launcher.prepare_reference(reference())
            self.assertEqual(launcher.run_reference(prepared['reference_id'], prepared['sha256']), 0)
            argv = json.loads((Path(folder) / 'argv.json').read_text())
            self.assertEqual(argv, ['tui', '--reference-only', '--reference-file',
                                    prepared['reference_file'], '--reference-sha256', prepared['sha256']])
            self.assertNotIn(reference()['body'], ' '.join(argv))
            self.assertFalse((Path(folder) / 'DO_NOT_EXECUTE').exists())

    def test_go_child_environment_excludes_credentials_and_startup_variables(self):
        forbidden = ('CONTROL_PLANE_API_KEY', 'ANTHROPIC_API_KEY', 'OPENAI_API_KEY',
                     'GITHUB_TOKEN', 'SSH_AUTH_SOCK', 'BASH_ENV', 'PYTHONPATH', 'HTTP_PROXY')
        sentinel = 'synthetic-control-only'
        with tempfile.TemporaryDirectory() as folder, patch.dict(
                os.environ, {**dict.fromkeys(forbidden, sentinel),
                             'HOME': folder, 'TERM': 'xterm-256color'}):
            binary = self.configured(folder)
            binary.write_text('#!' + sys.executable + '\nimport json,os\nfrom pathlib import Path\n'
                              'names=' + repr(forbidden + ('HOME', 'TERM', 'PATH', 'LANG')) + '\n'
                              'Path(os.environ["HOME"],"environment.json").write_text('
                              'json.dumps({name:os.environ.get(name) for name in names}))\n')
            prepared = launcher.prepare_reference(reference())
            self.assertEqual(launcher.run_reference(prepared['reference_id'], prepared['sha256']), 0)
            observed = (Path(folder) / 'environment.json').read_text()
            child_env = json.loads(observed)
            self.assertNotIn(sentinel, observed)
            for name in forbidden:
                self.assertIsNone(child_env[name], name)
            self.assertEqual(child_env['HOME'], folder)
            self.assertEqual(child_env['TERM'], 'xterm-256color')
            self.assertEqual(child_env['PATH'], '/usr/bin:/bin:/usr/sbin:/sbin')
            self.assertEqual(child_env['LANG'], 'en_US.UTF-8')

    def test_child_environment_preserves_safe_terminal_and_replaces_unsafe_values(self):
        for term in ('screen-256color', 'dumb', '', 'xterm\nunsafe', 'x' * 65):
            with self.subTest(term=term), patch.dict(os.environ, TERM=term):
                result = launcher.child_environment()
                expected = term if term in {'screen-256color', 'dumb'} else 'xterm-256color'
                self.assertEqual(result['TERM'], expected)
                self.assertEqual(set(result), {'HOME', 'TERM', 'PATH', 'LANG'})
        with patch.dict(os.environ, {'HOME': '/tmp'}, clear=True):
            self.assertEqual(launcher.child_environment()['TERM'], 'xterm-256color')

    def test_digest_mismatch_and_hardlink_never_spawn(self):
        with tempfile.TemporaryDirectory() as folder, patch.dict(os.environ, HOME=folder):
            self.configured(folder)
            prepared = launcher.prepare_reference(reference())
            with patch.object(launcher.subprocess, 'Popen') as child:
                with self.assertRaises(launcher.InvalidReference):
                    launcher.run_reference(prepared['reference_id'], '0' * 64)
                os.link(prepared['reference_file'], str(Path(folder) / 'linked.json'))
                with self.assertRaises(launcher.InvalidReference):
                    launcher.run_reference(prepared['reference_id'], prepared['sha256'])
            child.assert_not_called()

    def test_native_protocol_origin_shape_and_length(self):
        import struct
        payload = json.dumps({'action': 'open_tui', 'reference': reference()}).encode()
        frame = struct.pack('<I', len(payload)) + payload
        with patch.object(launcher, 'open_reference', return_value={'status': 'LAUNCH_REQUESTED'}) as opened:
            output = io.BytesIO()
            launcher.native_host(launcher.NATIVE_ORIGIN, io.BytesIO(frame), output)
            raw = output.getvalue()
            size = struct.unpack('<I', raw[:4])[0]
            self.assertEqual(size, len(raw) - 4)
            self.assertEqual(json.loads(raw[4:])['status'], 'LAUNCH_REQUESTED')
            opened.assert_called_once()
        for origin, raw in [('chrome-extension://' + 'a' * 32 + '/', frame),
                            (launcher.NATIVE_ORIGIN, struct.pack('<I', 262145)),
                            (launcher.NATIVE_ORIGIN, frame[:-1]),
                            (launcher.NATIVE_ORIGIN, b'\x01')]:
            with patch.object(launcher, 'open_reference') as opened, self.assertRaises(launcher.InvalidReference):
                launcher.native_host(origin, io.BytesIO(raw), io.BytesIO())
            opened.assert_not_called()

    def test_native_arbitrary_command_and_extra_fields_refused(self):
        import struct
        for value in ({'action': 'exec', 'reference': reference()},
                      {'action': 'open_tui', 'reference': reference(), 'command': 'touch NEVER'}):
            payload = json.dumps(value).encode()
            with patch.object(launcher, 'open_reference') as opened, self.assertRaises(launcher.InvalidReference):
                launcher.native_host(launcher.NATIVE_ORIGIN,
                                     io.BytesIO(struct.pack('<I', len(payload)) + payload), io.BytesIO())
            opened.assert_not_called()

    def rpc(self, requests):
        output = io.BytesIO()
        source = b''.join(json.dumps(item).encode() + b'\n' for item in requests)
        launcher.mcp_server(io.BytesIO(source), output)
        return [json.loads(line) for line in output.getvalue().splitlines()]

    def test_mcp_handshake_list_and_duplicate_effect_refusal(self):
        init = {'jsonrpc': '2.0', 'id': 1, 'method': 'initialize',
                'params': {'protocolVersion': '2025-11-25'}}
        call = {'jsonrpc': '2.0', 'id': 3, 'method': 'tools/call',
                'params': {'name': 'open_tui', 'arguments': {'reference': reference()}}}
        with patch.object(launcher, 'open_reference', return_value={'status': 'LAUNCH_REQUESTED'}) as opened:
            results = self.rpc([init, {'jsonrpc': '2.0', 'method': 'notifications/initialized'},
                                {'jsonrpc': '2.0', 'id': 2, 'method': 'tools/list'}, call, call])
        self.assertEqual(results[0]['result']['protocolVersion'], '2025-11-25')
        self.assertEqual(results[1]['result']['tools'][0]['name'], 'open_tui')
        self.assertEqual(results[2], results[3])
        opened.assert_called_once()

    def test_mcp_no_init_and_notifications_never_launch(self):
        call = {'jsonrpc': '2.0', 'method': 'tools/call',
                'params': {'name': 'open_tui', 'arguments': {'reference': reference()}}}
        with patch.object(launcher, 'open_reference') as opened:
            result = self.rpc([call, {**call, 'id': 1}])
        opened.assert_not_called()
        self.assertIn('error', result[0])

    def test_mcp_omitted_timestamp_uses_local_receipt_time(self):
        value = reference()
        del value['captured_at']
        init = {'jsonrpc': '2.0', 'id': 1, 'method': 'initialize',
                'params': {'protocolVersion': '2025-11-25'}}
        call = {'jsonrpc': '2.0', 'id': 2, 'method': 'tools/call',
                'params': {'name': 'open_tui', 'arguments': {'reference': value}}}
        with patch.object(launcher, 'open_reference', return_value={'status': 'LAUNCH_REQUESTED'}) as opened:
            result = self.rpc([init, call])
        self.assertFalse(result[-1]['result']['isError'])
        captured = opened.call_args.args[0]['captured_at']
        self.assertRegex(captured, r'Z$')
        self.assertEqual(launcher.validate_reference(opened.call_args.args[0])['captured_at'], captured)

    def test_mcp_malformed_and_oversized_frames_do_not_echo(self):
        for raw in (b'{invalid-secret-content}\n', b'x' * 262145 + b'\n',
                    b'{"jsonrpc":"2.0","id":1,"method":"initialize","params":[]}\n'):
            output = io.BytesIO()
            with patch.object(launcher, 'open_reference') as opened:
                launcher.mcp_server(io.BytesIO(raw), output)
            opened.assert_not_called()
            self.assertIn('error', json.loads(output.getvalue()))
            self.assertNotIn(b'invalid-secret-content', output.getvalue())

    def test_generated_command_quotes_real_paths(self):
        with tempfile.TemporaryDirectory(prefix="tui ' $(touch NO_EXEC) ") as folder:
            with patch.dict(os.environ, HOME=folder):
                self.configured(folder)
                with patch.object(launcher.sys, 'platform', 'darwin'), patch.object(
                        launcher.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0)):
                    prepared = launcher.open_reference(reference())
                script = Path(prepared['reference_file']).parent / 'open.command'
                child = subprocess.run(['/bin/sh', str(script)], env=os.environ.copy(),
                                       cwd=folder, capture_output=True, timeout=10)
                self.assertEqual(child.returncode, 0, child.stderr)
                self.assertEqual(json.loads((Path(folder) / 'argv.json').read_text())[0], 'tui')
                self.assertFalse((Path(folder) / 'NO_EXEC').exists())


class TuiPluginInstallerTests(unittest.TestCase):
    def test_incompatible_binary_refused_before_writes(self):
        with tempfile.TemporaryDirectory() as folder:
            home = Path(folder)
            binary = home / 'old-tui'
            binary.write_text('#!/bin/sh\necho "old tui help"\n')
            binary.chmod(0o700)
            with self.assertRaisesRegex(ValueError, 'reference'):
                install_tui_plugin.install(home, binary, True)
            self.assertFalse((home / '.agent-harness').exists())

    def binary(self, home):
        binary = Path(home) / 'example-tui'
        binary.write_text('#!/bin/sh\nprintf "%s\\n" "--reference-only --reference-file --reference-sha256"\n')
        binary.chmod(0o700)
        return binary

    def test_preview_is_read_only(self):
        with tempfile.TemporaryDirectory() as folder:
            binary = self.binary(folder)
            paths = install_tui_plugin.install(Path(folder), binary, False, browsers=['chrome'])
            self.assertGreater(len(paths), 10)
            self.assertFalse((Path(folder) / '.agent-harness').exists())

    def test_install_preserves_agent_settings_and_pins_native_origin(self):
        with tempfile.TemporaryDirectory() as folder:
            home = Path(folder)
            binary = self.binary(home)
            sentinels = {}
            for name in ('.codex/config.toml', '.codex/AGENTS.md', '.claude/settings.json', '.claude/CLAUDE.md'):
                path = home / name
                path.parent.mkdir(exist_ok=True)
                sentinels[path] = b'preserve existing permissions and disabled bridge\n'
                path.write_bytes(sentinels[path])
            install_tui_plugin.install(home, binary, True, browsers=['chrome'])
            for path, data in sentinels.items():
                self.assertEqual(path.read_bytes(), data)
            root = home / '.agent-harness'
            config = root / 'tui-launcher.json'
            self.assertEqual(config.stat().st_mode & 0o777, 0o600)
            self.assertEqual(json.loads(config.read_text())['binary'], str(binary.resolve()))
            plugin = (root / 'tui-plugin/plugin').resolve()
            mcp = json.loads((plugin / '.mcp.json').read_text())['mcpServers']['harness-tui']
            self.assertEqual(mcp, {'command': sys.executable, 'args': [str(plugin / 'launcher.py'), 'serve']})
            hosts = list(home.rglob('com.agentharness.tui.json'))
            self.assertEqual(len(hosts), 1)
            host = json.loads(hosts[0].read_text())
            self.assertEqual(host['allowed_origins'], [launcher.NATIVE_ORIGIN])
            self.assertEqual(Path(host['path']).stat().st_mode & 0o777, 0o700)

    def test_desktop_merge_preserves_other_servers_and_collision(self):
        server = {'command': 'python', 'args': ['/private/plugin/launcher.py', 'serve']}
        source = {'theme': 'dark', 'mcpServers': {'existing': {'command': 'keep'}}}
        merged = json.loads(install_tui_plugin.merge_desktop(json.dumps(source).encode(), server))
        self.assertEqual(merged['theme'], source['theme'])
        self.assertEqual(merged['mcpServers']['existing'], source['mcpServers']['existing'])
        source['mcpServers']['harness-tui'] = {'command': 'some-other-user-tool'}
        with self.assertRaisesRegex(ValueError, 'different harness-tui'):
            install_tui_plugin.merge_desktop(json.dumps(source).encode(), server)

    def test_same_args_do_not_authorize_overwriting_user_desktop_fields(self):
        server = {'command': sys.executable, 'args': ['/private/plugin/launcher.py', 'serve']}
        for changes in ({'env': {'HOME': '/private/isolated'}}, {'disabled': True},
                        {'command': '/trusted/custom-wrapper'}):
            source = {'mcpServers': {'harness-tui': {**server, **changes}}}
            with self.assertRaisesRegex(ValueError, 'different harness-tui'):
                install_tui_plugin.merge_desktop(json.dumps(source).encode(), server)

    def test_desktop_user_edits_refused_without_apply_side_effects(self):
        with tempfile.TemporaryDirectory() as folder:
            home = Path(folder).resolve()
            binary = self.binary(home)
            config = home / 'Library/Application Support/Claude/claude_desktop_config.json'
            config.parent.mkdir(parents=True)
            server = {'command': sys.executable,
                      'args': [str(home / '.agent-harness/tui-plugin/plugin/launcher.py'), 'serve'],
                      'env': {'HOME': '/private/isolated'}, 'disabled': True}
            original = json.dumps({'mcpServers': {'harness-tui': server}}).encode()
            config.write_bytes(original)
            with patch.object(install_tui_plugin.sys, 'platform', 'darwin'):
                with self.assertRaisesRegex(ValueError, 'different harness-tui'):
                    install_tui_plugin.install(home, binary, True, claude_desktop=True)
            self.assertEqual(config.read_bytes(), original)
            self.assertFalse((home / '.agent-harness').exists())

    def test_binary_help_time_and_output_are_bounded(self):
        with tempfile.TemporaryDirectory() as folder:
            home = Path(folder)
            noisy = home / 'noisy'
            noisy.write_text('#!' + sys.executable + '\nimport os\nwhile True: os.write(1,b"x"*4096)\n')
            noisy.chmod(0o700)
            with self.assertRaisesRegex(ValueError, 'output limit'):
                install_tui_plugin.check_binary_contract(noisy, timeout=1, limit=256)
            hung = home / 'hung'
            hung.write_text('#!' + sys.executable + '\nimport time\ntime.sleep(10)\n')
            hung.chmod(0o700)
            with self.assertRaisesRegex(ValueError, 'deadline'):
                install_tui_plugin.check_binary_contract(hung, timeout=0.05)

    def test_symlink_destination_refused_without_target_writes(self):
        with tempfile.TemporaryDirectory() as folder, tempfile.TemporaryDirectory() as elsewhere:
            home = Path(folder)
            binary = self.binary(home)
            (home / '.agent-harness').symlink_to(elsewhere, target_is_directory=True)
            with self.assertRaises(ValueError):
                install_tui_plugin.install(home, binary, True)
            self.assertEqual(list(Path(elsewhere).iterdir()), [])

    def test_failed_reinstall_restores_original_bytes(self):
        with tempfile.TemporaryDirectory() as folder:
            home = Path(folder)
            binary = self.binary(home)
            install_tui_plugin.install(home, binary, True)
            root = home / '.agent-harness'
            tracked = {p: p.read_bytes() for p in (root / 'tui-plugin').rglob('*') if p.is_file()}
            tracked[root / 'tui-launcher.json'] = (root / 'tui-launcher.json').read_bytes()
            real = install_tui_plugin.atomic_write
            count = 0
            def fail_once(path, data, *args, **kwargs):
                nonlocal count
                if 'tui-plugin-backups' not in path.parts:
                    count += 1
                    if count == 3:
                        raise OSError('controlled publication failure')
                return real(path, data, *args, **kwargs)
            with patch.object(install_tui_plugin, 'atomic_write', side_effect=fail_once):
                with self.assertRaisesRegex(OSError, 'controlled'):
                    install_tui_plugin.install(home, binary, True)
            self.assertEqual({p: p.read_bytes() for p in tracked}, tracked)

    def test_installed_stdio_real_subprocess_handshake(self):
        with tempfile.TemporaryDirectory() as folder:
            home = Path(folder)
            install_tui_plugin.install(home, self.binary(home), True)
            installed = home / '.agent-harness/tui-plugin/plugin/launcher.py'
            requests = [
                {'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': {'protocolVersion': '2025-11-25'}},
                {'jsonrpc': '2.0', 'method': 'notifications/initialized'},
                {'jsonrpc': '2.0', 'id': 2, 'method': 'tools/list'}]
            result = subprocess.run([sys.executable, str(installed), 'serve'],
                                    input=''.join(json.dumps(r) + '\n' for r in requests),
                                    env={**os.environ, 'HOME': folder}, text=True, capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            responses = [json.loads(line) for line in result.stdout.splitlines()]
            self.assertEqual(len(responses), 2)
            self.assertEqual(responses[1]['result']['tools'][0]['name'], 'open_tui')
