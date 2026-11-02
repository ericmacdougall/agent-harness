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

    def test_mcp_malformed_and_oversized_frames_do_not_echo(self):
        for raw in (b'{invalid-secret-content}\n', b'x' * 262145 + b'\n',
                    b'{"jsonrpc":"2.0","id":1,"method":"initialize","params":[]}\n'):
            output = io.BytesIO()
            with patch.object(launcher, 'open_reference') as opened:
                launcher.mcp_server(io.BytesIO(raw), output)
            opened.assert_not_called()
            self.assertIn('error', json.loads(output.getvalue()))
            self.assertNotIn(b'invalid-secret-content', output.getvalue())
