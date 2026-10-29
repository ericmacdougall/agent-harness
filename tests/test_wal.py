import json
import os
import subprocess
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
            ["python3", str(WAL), event],
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

    def test_missing_session_refuses_shared_wal(self):
        result = self.invoke("prompt", {"prompt": "hello"})
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.home / ".claude/wals").exists())


if __name__ == "__main__":
    unittest.main()
