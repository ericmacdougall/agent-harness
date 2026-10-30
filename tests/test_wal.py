import errno
import importlib.util
import json
import hashlib
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch


WAL = Path(__file__).resolve().parents[1] / "harness/hooks/wal.py"


class WalTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.home = Path(self.temp.name)

    def invoke(self, event, data):
        return subprocess.run(
            [sys.executable, str(WAL), event],
            input=json.dumps(data),
            text=True,
            capture_output=True,
            env={**os.environ, "HOME": str(self.home)},
        )

    def test_prompt_writes_length_without_prompt(self):
        data = {"session_id": "test-session", "cwd": "/tmp/project", "prompt": "private request"}
        result = self.invoke("prompt", data)
        self.assertEqual(result.returncode, 0, result.stderr)
        output = json.loads(result.stdout)
        self.assertEqual(output["hookSpecificOutput"]["hookEventName"], "UserPromptSubmit")
        path = self.home / ".claude/wals/test-session/main.jsonl"
        record = json.loads(path.read_text().strip())
        self.assertEqual(record["prompt_chars"], len(data["prompt"]))
        self.assertNotIn("private request", path.read_text())
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_short_prompt_has_no_dictionary_reversible_digest(self):
        result = self.invoke('prompt', {'session_id': 'short', 'prompt': 'yes'})
        self.assertEqual(result.returncode, 0, result.stderr)
        record = json.loads((self.home / '.claude/wals/short/main.jsonl').read_text())
        self.assertNotIn(hashlib.sha256(b'yes').hexdigest(), json.dumps(record))
        self.assertNotIn('yes', json.dumps(record))

    def test_short_tool_target_has_no_dictionary_reversible_digest(self):
        result = self.invoke('pretool', {'session_id': 'tool', 'tool_name': 'Bash',
                                        'tool_input': {'command': 'secret fixture'}})
        self.assertEqual(result.returncode, 0, result.stderr)
        record = json.loads((self.home / '.claude/wals/tool/main.jsonl').read_text())
        self.assertEqual(record['target_chars'], len('secret fixture'))
        self.assertNotIn(hashlib.sha256(b'secret fixture').hexdigest(), json.dumps(record))
        self.assertNotIn('secret fixture', json.dumps(record))

    def test_dot_session_ids_stay_inside_the_wal_directory(self):
        for session_id in ("..", "."):
            result = self.invoke("prompt", {"session_id": session_id, "cwd": "/tmp/project", "prompt": "x"})
            self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((self.home / ".claude/main.jsonl").exists())
        self.assertFalse((self.home / ".claude/wals/main.jsonl").exists())
        written = sorted(str(path.relative_to(self.home / ".claude/wals")) for path in (self.home / ".claude/wals").rglob("*.jsonl"))
        self.assertEqual(len(written), 2)
        for relative in written:
            self.assertEqual(len(Path(relative).parts), 2, relative)

    def test_long_dot_id_can_receive_a_note(self):
        result = self.invoke("prompt", {"session_id": "." * 120, "prompt": "fixture"})
        self.assertEqual(result.returncode, 0, result.stderr)
        path, = (self.home / ".claude/wals").glob("*/main.jsonl")
        result = subprocess.run([sys.executable, str(WAL.with_name("wal_note.py")),
                                 "--wal", str(path), "--event", "check", "--note", "fixture"],
                                env={**os.environ, "HOME": str(self.home)}, capture_output=True, text=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len(path.read_text().splitlines()), 2)

    def append_with(self, writer):
        if writer == "hook":
            return self.invoke("prompt", {"session_id": "test-session", "prompt": "fixture"})
        return subprocess.run([sys.executable, str(WAL.with_name("wal_note.py")),
                               "--wal", str(self.home / ".claude/wals/test-session/main.jsonl"),
                               "--event", "check", "--note", "fixture"],
                              env={**os.environ, "HOME": str(self.home)}, capture_output=True, text=True, timeout=5)

    def test_writers_refuse_symlinked_directories_and_files(self):
        for writer in ("hook", "note"):
            for component in (".claude", ".claude/wals", ".claude/wals/test-session",
                              ".claude/wals/test-session/main.jsonl"):
                with self.subTest(writer=writer, component=component), tempfile.TemporaryDirectory() as temp:
                    self.home = Path(temp)
                    outside = self.home / "outside"
                    link = self.home / component
                    link.parent.mkdir(parents=True, exist_ok=True)
                    if link.suffix == ".jsonl":
                        outside.write_text("preserve\n")
                    else:
                        outside.mkdir(mode=0o755)
                    link.symlink_to(outside)
                    result = self.append_with(writer)
                    self.assertNotEqual(result.returncode, 0, result.stdout)
                    if outside.is_file():
                        self.assertEqual(outside.read_text(), "preserve\n")
                    else:
                        self.assertEqual(list(outside.iterdir()), [])
                        self.assertEqual(outside.stat().st_mode & 0o777, 0o755)

    def test_writers_refuse_hardlinks_and_fifos(self):
        for writer in ("hook", "note"):
            for kind in ("hardlink", "fifo"):
                with self.subTest(writer=writer, kind=kind), tempfile.TemporaryDirectory() as temp:
                    self.home = Path(temp)
                    path = self.home / ".claude/wals/test-session/main.jsonl"
                    path.parent.mkdir(parents=True)
                    outside = self.home / "outside"
                    outside.write_text("preserve\n")
                    reader = None
                    if kind == "hardlink":
                        os.link(outside, path)
                    else:
                        os.mkfifo(path)
                        reader = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
                    try:
                        result = self.append_with(writer)
                        self.assertNotEqual(result.returncode, 0, result.stdout)
                        self.assertEqual(outside.read_text(), "preserve\n")
                    finally:
                        if reader is not None:
                            os.close(reader)

    def test_existing_wal_and_directories_become_private(self):
        for writer in ("hook", "note"):
            with self.subTest(writer=writer):
                path = self.home / ".claude/wals/test-session/main.jsonl"
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text('{"event":"existing"}\n')
                path.chmod(0o644)
                path.parent.chmod(0o755)
                path.parent.parent.chmod(0o755)
                result = self.append_with(writer)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
                self.assertEqual(path.parent.stat().st_mode & 0o777, 0o700)
                self.assertEqual(path.parent.parent.stat().st_mode & 0o777, 0o700)
                self.assertEqual(len(path.read_text().splitlines()), 2)

    def test_missing_session_refuses_shared_wal(self):
        result = self.invoke("prompt", {"prompt": "hello"})
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.home / ".claude/wals").exists())

    def test_sanitized_ids_do_not_alias_distinct_sessions(self):
        for session_id in ('a/b', 'a_b', 'x' * 120 + 'A', 'x' * 120 + 'B'):
            result = self.invoke('session', {'session_id': session_id})
            self.assertEqual(result.returncode, 0, result.stderr)
        paths = list((self.home / '.claude/wals').glob('*/main.jsonl'))
        self.assertEqual(len(paths), 4, 'different session IDs were merged into one WAL')

    def test_escaped_id_cannot_alias_an_explicit_identifier(self):
        first = self.invoke('session', {'session_id': 'a/b'})
        self.assertEqual(first.returncode, 0, first.stderr)
        encoded, = (self.home / '.claude/wals').iterdir()
        second = self.invoke('session', {'session_id': encoded.name})
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual(len(list((self.home / '.claude/wals').iterdir())), 2)

    def test_case_variants_and_uppercase_escape_cannot_alias_on_casefolded_disks(self):
        for session_id in ('Foo', 'foo', 'a/b'):
            result = self.invoke('session', {'session_id': session_id})
            self.assertEqual(result.returncode, 0, result.stderr)
        directories = list((self.home / '.claude/wals').iterdir())
        self.assertEqual(len(directories), 3)
        escaped = next(path.name for path in directories if path.name.startswith('z-a_b-'))
        result = self.invoke('session', {'session_id': escaped.upper()})
        self.assertEqual(result.returncode, 0, result.stderr)
        names = [path.name.casefold() for path in (self.home / '.claude/wals').iterdir()]
        self.assertEqual(len(set(names)), 4)
        for agent_id in ('Task', 'task'):
            result = self.invoke('subagent', {'session_id': 'agents', 'agent_id': agent_id})
            self.assertEqual(result.returncode, 0, result.stderr)
        files = list((self.home / '.claude/wals/agents').glob('agent-*.jsonl'))
        self.assertEqual(len({path.name.casefold() for path in files}), 2)

    def test_agent_named_main_cannot_alias_the_main_wal(self):
        result = self.invoke('subagent', {'session_id': 'session', 'agent_id': 'main', 'agent_type': 'task-owner'})
        self.assertEqual(result.returncode, 0, result.stderr)
        session = self.home / '.claude/wals/session'
        self.assertEqual(len((session / 'main.jsonl').read_text().splitlines()), 1)
        self.assertEqual(len((session / 'agent-main.jsonl').read_text().splitlines()), 1)

    def test_concurrent_writers_leave_parseable_complete_records(self):
        session = 'concurrent'
        tasks = []
        for worker in range(8):
            code = ('import json,sys\nfrom wal import append\nfrom pathlib import Path\n'
                    'root=Path.home()/".claude"/"wals"/"concurrent"/"main.jsonl"\n'
                    f'for index in range(25): append(root, {{"worker":{worker}, "index":index, "note":"x"*3500}})\n')
            tasks.append(subprocess.Popen([sys.executable, '-c', code], env={**os.environ, 'HOME': str(self.home),
                              'PYTHONPATH': str(WAL.parent)}, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE))
        for task in tasks:
            _, stderr = task.communicate(timeout=30)
            self.assertEqual(task.returncode, 0, stderr)
        lines = (self.home / '.claude/wals/concurrent/main.jsonl').read_text().splitlines()
        records = [json.loads(line) for line in lines]
        self.assertEqual(len(records), 200)
        self.assertEqual(len({(row['worker'], row['index']) for row in records}), 200)

    def test_transient_missing_file_during_create_retries_without_losing_record(self):
        spec = importlib.util.spec_from_file_location('wal_retry_test', WAL)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        target = self.home / '.claude/wals/concurrent/main.jsonl'
        original_open = os.open
        attempts = []

        def fail_once(path, flags, *args, **kwargs):
            if path == 'main.jsonl':
                attempts.append(path)
                if len(attempts) == 1:
                    raise FileNotFoundError(errno.ENOENT, 'transient create race', path)
            return original_open(path, flags, *args, **kwargs)

        with patch.dict(os.environ, {'HOME': str(self.home)}), patch.object(module.os, 'open', side_effect=fail_once):
            module.append(target, {'event': 'fixture'})
        self.assertEqual(len(attempts), 2)
        self.assertEqual(json.loads(target.read_text()), {'event': 'fixture'})

    def test_retry_refuses_replaced_session_directory(self):
        spec = importlib.util.spec_from_file_location('wal_retry_test', WAL)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        session = self.home / '.claude/wals/concurrent'
        session.mkdir(parents=True)
        target = session / 'main.jsonl'
        original_open = os.open

        def replace_directory(path, flags, *args, **kwargs):
            if path == 'main.jsonl':
                session.rename(session.with_name('moved'))
                session.mkdir()
                raise FileNotFoundError(errno.ENOENT, 'directory replaced', path)
            return original_open(path, flags, *args, **kwargs)

        with patch.dict(os.environ, {'HOME': str(self.home)}), patch.object(module.os, 'open', side_effect=replace_directory):
            with self.assertRaises(FileNotFoundError):
                module.append(target, {'event': 'fixture'})
        self.assertFalse(target.exists())
        self.assertFalse((session.with_name('moved') / 'main.jsonl').exists())

    def test_repeated_missing_file_is_bounded(self):
        spec = importlib.util.spec_from_file_location('wal_retry_test', WAL)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        target = self.home / '.claude/wals/concurrent/main.jsonl'
        original_open = os.open
        attempts = []

        def never_create(path, flags, *args, **kwargs):
            if path == 'main.jsonl':
                attempts.append(path)
                raise FileNotFoundError(errno.ENOENT, 'persistent create failure', path)
            return original_open(path, flags, *args, **kwargs)

        with patch.dict(os.environ, {'HOME': str(self.home)}), patch.object(module.os, 'open', side_effect=never_create):
            with self.assertRaises(FileNotFoundError):
                module.append(target, {'event': 'fixture'})
        self.assertEqual(len(attempts), 4)
        self.assertFalse(target.exists())

    def test_retry_refuses_directory_moved_during_backoff(self):
        spec = importlib.util.spec_from_file_location('wal_retry_test', WAL)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        session = self.home / '.claude/wals/concurrent'
        session.mkdir(parents=True)
        target = session / 'main.jsonl'
        moved = session.with_name('moved')
        original_open = os.open
        attempts = []

        def fail_first(path, flags, *args, **kwargs):
            if path == 'main.jsonl':
                attempts.append(path)
                if len(attempts) == 1:
                    raise FileNotFoundError(errno.ENOENT, 'transient create race', path)
            return original_open(path, flags, *args, **kwargs)

        def move_during_sleep(_):
            session.rename(moved)
            session.mkdir()

        with patch.dict(os.environ, {'HOME': str(self.home)}), \
             patch.object(module.os, 'open', side_effect=fail_first), \
             patch.object(module.time, 'sleep', side_effect=move_during_sleep):
            with self.assertRaises((OSError, ValueError)):
                module.append(target, {'event': 'fixture'})
        self.assertFalse(target.exists())
        self.assertFalse((moved / 'main.jsonl').exists())

    def test_open_refuses_directory_moved_before_write(self):
        spec = importlib.util.spec_from_file_location('wal_retry_test', WAL)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        session = self.home / '.claude/wals/concurrent'
        session.mkdir(parents=True)
        target = session / 'main.jsonl'
        moved = session.with_name('moved')
        original_open = os.open

        def move_after_open(path, flags, *args, **kwargs):
            fd = original_open(path, flags, *args, **kwargs)
            if path == 'main.jsonl':
                session.rename(moved)
                session.mkdir()
            return fd

        with patch.dict(os.environ, {'HOME': str(self.home)}), \
             patch.object(module.os, 'open', side_effect=move_after_open):
            with self.assertRaises((OSError, ValueError)):
                module.append(target, {'event': 'fixture'})
        self.assertFalse(target.exists())
        self.assertEqual((moved / 'main.jsonl').read_text(), '')

    def test_write_refuses_directory_moved_before_success(self):
        spec = importlib.util.spec_from_file_location('wal_retry_test', WAL)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        session = self.home / '.claude/wals/concurrent'
        session.mkdir(parents=True)
        target = session / 'main.jsonl'
        moved = session.with_name('moved')
        original_fsync = os.fsync

        def move_after_fsync(fd):
            original_fsync(fd)
            session.rename(moved)
            session.mkdir()

        with patch.dict(os.environ, {'HOME': str(self.home)}), \
             patch.object(module.os, 'fsync', side_effect=move_after_fsync):
            with self.assertRaises((OSError, ValueError)):
                module.append(target, {'event': 'fixture'})
        self.assertFalse(target.exists())
        self.assertEqual(json.loads((moved / 'main.jsonl').read_text()), {'event': 'fixture'})

    def test_open_refuses_log_file_replacement_before_write(self):
        spec = importlib.util.spec_from_file_location('wal_retry_test', WAL)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        session = self.home / '.claude/wals/concurrent'
        session.mkdir(parents=True)
        target = session / 'main.jsonl'
        moved = session / 'moved.jsonl'
        original_open = os.open

        def replace_after_open(path, flags, *args, **kwargs):
            fd = original_open(path, flags, *args, **kwargs)
            if path == 'main.jsonl':
                target.rename(moved)
                target.write_text('replacement')
            return fd

        with patch.dict(os.environ, {'HOME': str(self.home)}), \
             patch.object(module.os, 'open', side_effect=replace_after_open):
            with self.assertRaises((OSError, ValueError)):
                module.append(target, {'event': 'fixture'})
        self.assertEqual(target.read_text(), 'replacement')
        self.assertEqual(moved.read_text(), '')

    def test_write_refuses_log_file_replacement_before_success(self):
        spec = importlib.util.spec_from_file_location('wal_retry_test', WAL)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        session = self.home / '.claude/wals/concurrent'
        session.mkdir(parents=True)
        target = session / 'main.jsonl'
        moved = session / 'moved.jsonl'
        original_fsync = os.fsync

        def replace_after_fsync(fd):
            original_fsync(fd)
            target.rename(moved)
            target.write_text('replacement')

        with patch.dict(os.environ, {'HOME': str(self.home)}), \
             patch.object(module.os, 'fsync', side_effect=replace_after_fsync):
            with self.assertRaises((OSError, ValueError)):
                module.append(target, {'event': 'fixture'})
        self.assertEqual(target.read_text(), 'replacement')
        self.assertEqual(json.loads(moved.read_text()), {'event': 'fixture'})

    def test_retry_refuses_wals_ancestor_symlink_during_backoff(self):
        spec = importlib.util.spec_from_file_location('wal_retry_test', WAL)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        wals = self.home / '.claude/wals'
        session = wals / 'concurrent'
        session.mkdir(parents=True)
        target = session / 'main.jsonl'
        moved = wals.with_name('wals-moved')
        original_open = os.open
        attempts = []

        def fail_first(path, flags, *args, **kwargs):
            if path == 'main.jsonl':
                attempts.append(path)
                if len(attempts) == 1:
                    raise FileNotFoundError(errno.ENOENT, 'transient create race', path)
            return original_open(path, flags, *args, **kwargs)

        def redirect_during_sleep(_):
            wals.rename(moved)
            wals.symlink_to(moved, target_is_directory=True)

        with patch.dict(os.environ, {'HOME': str(self.home)}), \
             patch.object(module.os, 'open', side_effect=fail_first), \
             patch.object(module.time, 'sleep', side_effect=redirect_during_sleep):
            with self.assertRaises((OSError, ValueError)):
                module.append(target, {'event': 'fixture'})
        self.assertFalse((moved / 'concurrent/main.jsonl').exists())

    def test_open_refuses_claude_ancestor_symlink_before_write(self):
        spec = importlib.util.spec_from_file_location('wal_retry_test', WAL)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        claude = self.home / '.claude'
        session = claude / 'wals/concurrent'
        session.mkdir(parents=True)
        target = session / 'main.jsonl'
        moved = self.home / '.claude-moved'
        original_open = os.open

        def redirect_after_open(path, flags, *args, **kwargs):
            fd = original_open(path, flags, *args, **kwargs)
            if path == 'main.jsonl':
                claude.rename(moved)
                claude.symlink_to(moved, target_is_directory=True)
            return fd

        with patch.dict(os.environ, {'HOME': str(self.home)}), \
             patch.object(module.os, 'open', side_effect=redirect_after_open):
            with self.assertRaises((OSError, ValueError)):
                module.append(target, {'event': 'fixture'})
        self.assertEqual((moved / 'wals/concurrent/main.jsonl').read_text(), '')

    def test_write_refuses_wals_ancestor_symlink_before_success(self):
        spec = importlib.util.spec_from_file_location('wal_retry_test', WAL)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        wals = self.home / '.claude/wals'
        session = wals / 'concurrent'
        session.mkdir(parents=True)
        target = session / 'main.jsonl'
        moved = wals.with_name('wals-moved')
        original_fsync = os.fsync

        def redirect_after_fsync(fd):
            original_fsync(fd)
            wals.rename(moved)
            wals.symlink_to(moved, target_is_directory=True)

        with patch.dict(os.environ, {'HOME': str(self.home)}), \
             patch.object(module.os, 'fsync', side_effect=redirect_after_fsync):
            with self.assertRaises((OSError, ValueError)):
                module.append(target, {'event': 'fixture'})
        self.assertEqual(json.loads((moved / 'concurrent/main.jsonl').read_text()),
                         {'event': 'fixture'})

    def test_common_secret_formats_are_rejected_in_human_notes(self):
        path = self.home / '.claude/wals/test-session/main.jsonl'
        examples = ('Authorization: Bearer abc123', 'postgres://alice:hunter2@example.invalid/db',
                    'xoxb-1234567890-abcdef', '-----BEGIN PRIVATE KEY-----',
                    'password=hunter2', 'api_key: fixture-secret')
        for note in examples:
            with self.subTest(note=note.split()[0]):
                result = subprocess.run([sys.executable, str(WAL.with_name('wal_note.py')),
                                         '--wal', str(path), '--event', 'status', '--note', note],
                                        env={**os.environ, 'HOME': str(self.home)}, capture_output=True, text=True, timeout=5)
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(path.exists())


if __name__ == "__main__":
    unittest.main()
