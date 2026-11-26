"""`ah --help` names every command that dispatches (the release 1001 e2e: doctor, sandbox, repo, review-status, reap,
secret, co, log-push and approvals were missing) and none of the deleted parts."""
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

HOOKS = Path(__file__).resolve().parents[1] / "harness" / "hooks"


class Help(unittest.TestCase):
    def test_help_lists_the_dispatched_commands_and_no_deleted_part(self):
        with tempfile.TemporaryDirectory() as home:
            done = subprocess.run([sys.executable, "-I", str(HOOKS / "ah.py"), "--help"], capture_output=True,
                                  text=True, timeout=60, env={"HOME": home, "PATH": os.environ.get("PATH", "")})
        self.assertEqual(done.returncode, 0, done.stderr)
        for word in ("doctor", "sandbox", "repo", "review-status", "reap", "secret", "co", "log-push", "approvals",
                     "approve", "supervisor", "off, on"):
            self.assertIn(word, done.stdout, word)
        for gone in ("ahd", "Slice 1"):
            self.assertNotIn(gone, done.stdout, gone)


if __name__ == "__main__":
    unittest.main()
