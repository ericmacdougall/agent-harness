import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


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

    def test_prompt_writes_digest_without_prompt(self):
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


if __name__ == "__main__":
    unittest.main()
