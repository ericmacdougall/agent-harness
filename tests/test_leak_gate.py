"""leak_gate (GoodQA #14538). Hermetic: private HOME, a PATH holding only git (plus a fake gitleaks
where a test wants one), and no AGENT_HARNESS_* variables, so a developer's own setup cannot change results."""
import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

GATE = Path(__file__).resolve().parents[1] / "scripts" / "leak_gate.py"
GIT = shutil.which("git")


def ip(*octets):
    return ".".join(octets)  # built at runtime so this file holds no address


class LeakGate(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.bin = self.tmp / "bin"
        self.bin.mkdir()
        (self.bin / "git").symlink_to(GIT)
        self.env = {"HOME": str(self.tmp), "PATH": str(self.bin), "GIT_CONFIG_GLOBAL": os.devnull,
                    "GIT_CONFIG_SYSTEM": os.devnull}
        self.deny = self.tmp / "deny.txt"
        self.deny.write_text("zzz-never-matches-zzz\n")

    def repo(self, second="hello\n"):
        repo = self.tmp / "repo"
        repo.mkdir()
        git = lambda *a: subprocess.run([GIT, "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@example.invalid", *a],
                                        check=True, capture_output=True, env=self.env)
        git("init", "-q")
        (repo / "a.txt").write_text("first\n")
        git("add", "-A")
        git("commit", "-qm", "one")
        (repo / "a.txt").write_text(second)
        git("commit", "-qam", "two")
        return repo

    def gate(self, repo, *extra, env=None):
        args = [sys.executable, str(GATE), "--repo", str(repo), *extra]
        return subprocess.run(args, capture_output=True, text=True, env=env or self.env)

    def fake_gitleaks(self, exit_code=0):
        exe = self.bin / "gitleaks"
        exe.write_text(f"#!/bin/sh\nexit {exit_code}\n")
        exe.chmod(0o755)
        return hashlib.sha256(exe.read_bytes()).hexdigest()

    def test_clean_repo_passes_and_gitleaks_absence_is_loud(self):
        r = self.gate(self.repo(), "--range", "HEAD~1..HEAD", "--denylist", str(self.deny))
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("gitleaks: SKIPPED", r.stdout)

    def test_range_is_required(self):
        r = self.gate(self.repo(), "--denylist", str(self.deny))
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)

    def test_dirty_tree_is_refused(self):
        repo = self.repo()
        (repo / "a.txt").write_text("edited after commit\n")
        r = self.gate(repo, "--range", "HEAD~1..HEAD", "--denylist", str(self.deny))
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)

    def test_missing_denylist_refuses_unless_explicitly_waived(self):
        repo = self.repo()
        r = self.gate(repo, "--range", "HEAD~1..HEAD")
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)
        r = self.gate(repo, "--range", "HEAD~1..HEAD", "--no-denylist")
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn("generic rules only", r.stdout)

    def test_tailnet_address_in_pushed_commit_fails_without_echoing_value(self):
        addr = ip("100", "64", "1", "2")
        r = self.gate(self.repo(second=f"host {addr}\n"), "--range", "HEAD~1..HEAD", "--denylist", str(self.deny))
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)
        self.assertNotIn(addr, r.stdout + r.stderr)

    def test_unpinned_gitleaks_is_refused(self):
        self.fake_gitleaks()
        r = self.gate(self.repo(), "--range", "HEAD~1..HEAD", "--denylist", str(self.deny))
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)

    def test_gitleaks_hash_mismatch_is_refused(self):
        self.fake_gitleaks()
        r = self.gate(self.repo(), "--range", "HEAD~1..HEAD", "--denylist", str(self.deny),
                      "--gitleaks-sha256", "0" * 64)
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)

    def test_pinned_gitleaks_runs_and_its_failure_fails_the_gate(self):
        pin = self.fake_gitleaks(exit_code=0)
        r = self.gate(self.repo(), "--range", "HEAD~1..HEAD", "--denylist", str(self.deny), "--gitleaks-sha256", pin)
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        pin = self.fake_gitleaks(exit_code=1)
        r = self.gate(self.tmp / "repo", "--range", "HEAD~1..HEAD", "--denylist", str(self.deny),
                      "--gitleaks-sha256", pin)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)

    def test_required_gitleaks_missing_refuses(self):
        r = self.gate(self.repo(), "--range", "HEAD~1..HEAD", "--denylist", str(self.deny), "--require-gitleaks")
        self.assertEqual(r.returncode, 2, r.stdout + r.stderr)


if __name__ == "__main__":
    unittest.main()
