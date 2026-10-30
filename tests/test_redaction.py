"""Credential guard and process-output controls for helper diagnostics."""

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
CLAUDE_NOTE = ROOT / 'harness' / 'hooks' / 'wal_note.py'
CODEX_WAL = ROOT / 'codex' / 'hooks' / 'wal.py'
PROCESS = ROOT / 'harness' / 'hooks' / 'process.py'


def load(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class HumanWalNoteGuards(unittest.TestCase):
    NOTES = (
        'AWS_SECRET_ACCESS_KEY=synthetic_value',
        'ANTHROPIC_API_KEY: synthetic_value',
        'ToKeN=synthetic_value',
        'Password: synthetic_value',
        '{"client_secret": "synthetic_value"}',
        '{"clientSecret": "synthetic_value"}',
        '{"accessToken": "synthetic_value"}',
        'secretAccessKey=synthetic_value',
    )
    ORDINARY_NOTES = (
        'Review token validation flow',
        'token_count=178',
        'token_budget=1000',
        'credential_check=passed',
        'secret_scanning=enabled',
    )

    def test_claude_rejects_compound_credential_names_before_writing(self):
        with tempfile.TemporaryDirectory() as temporary:
            home = Path(temporary)
            for index, note in enumerate(self.NOTES):
                with self.subTest(note=note.split('=')[0]):
                    path = home / '.claude' / 'wals' / f'fixture-{index}' / 'main.jsonl'
                    path.parent.mkdir(parents=True)
                    original = b'{"event":"fixture"}\n'
                    path.write_bytes(original)
                    result = subprocess.run([sys.executable, str(CLAUDE_NOTE), '--wal', str(path),
                                             '--event', 'intent', '--note', note],
                                            env={**os.environ, 'HOME': str(home)},
                                            text=True, capture_output=True, timeout=5)
                    self.assertNotEqual(result.returncode, 0, result.stdout)
                    self.assertEqual(path.read_bytes(), original)
            fresh = home / '.claude' / 'wals' / 'fresh' / 'main.jsonl'
            result = subprocess.run([sys.executable, str(CLAUDE_NOTE), '--wal', str(fresh),
                                     '--event', 'intent', '--note', self.NOTES[0]],
                                    env={**os.environ, 'HOME': str(home)},
                                    text=True, capture_output=True, timeout=5)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(fresh.exists())
            accepted = home / '.claude' / 'wals' / 'accepted' / 'main.jsonl'
            for note in self.ORDINARY_NOTES:
                with self.subTest(accepted=note):
                    result = subprocess.run([sys.executable, str(CLAUDE_NOTE), '--wal', str(accepted),
                                             '--event', 'intent', '--note', note],
                                            env={**os.environ, 'HOME': str(home)},
                                            text=True, capture_output=True, timeout=5)
                    self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual([json.loads(line)['note'] for line in accepted.read_text().splitlines()],
                             list(self.ORDINARY_NOTES))

    def test_codex_rejects_compound_credential_names_before_writing(self):
        wal = load(CODEX_WAL, 'redaction_codex_wal')
        with tempfile.TemporaryDirectory() as temporary, patch.object(wal.Path, 'home', return_value=Path(temporary)):
            for index, note in enumerate(self.NOTES):
                with self.subTest(note=note.split('=')[0]):
                    path = wal.wal_root() / f'fixture-{index}' / 'main.jsonl'
                    wal.append(path, {'event': 'fixture'})
                    original = path.read_bytes()
                    with self.assertRaisesRegex(ValueError, 'credential'):
                        wal.note(path, 'intent', note)
                    self.assertEqual(path.read_bytes(), original)
            fresh = wal.wal_root() / 'fresh' / 'main.jsonl'
            with self.assertRaisesRegex(ValueError, 'credential'):
                wal.note(fresh, 'intent', self.NOTES[0])
            self.assertFalse(fresh.exists())
            accepted = wal.wal_root() / 'accepted' / 'main.jsonl'
            for note in self.ORDINARY_NOTES:
                with self.subTest(accepted=note), patch.object(wal.sys, 'stdout', new_callable=io.StringIO):
                    wal.note(accepted, 'intent', note)
            self.assertEqual([json.loads(line)['note'] for line in accepted.read_text().splitlines()],
                             list(self.ORDINARY_NOTES))


class ProcessTextDecoding(unittest.TestCase):
    def test_malformed_text_is_replaced_but_binary_mode_is_exact(self):
        process = load(PROCESS, 'redaction_process')
        command = [sys.executable, '-c',
                   'import os; os.write(1, b"\\xff"); os.write(2, b"\\xfe")']
        text_result = process.run(command, text=True, timeout=5)
        self.assertEqual((text_result.stdout, text_result.stderr), ('\ufffd', '\ufffd'))
        binary_result = process.run(command, text=False, timeout=5)
        self.assertEqual((binary_result.stdout, binary_result.stderr), (b'\xff', b'\xfe'))


if __name__ == '__main__':
    unittest.main()
