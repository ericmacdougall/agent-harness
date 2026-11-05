"""`harness tickets sync-state` and commit_policy.py must agree on which repositories GoodQA tracks."""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "harness" / "hooks"))
import commit_policy  # noqa: E402

POLICY = {"ticket_systems": {
    "goodqa": {"adapter": "goodqa", "repos": [r"github\.com[:/]acme-corp/", r"gitlab\.example\.org/team/(?:alpha|beta)\b"]},
    "ledger": {"adapter": "ledger", "repos": [r"never-matches-ledger"], "allowed_repos": []}}}

URLS = [
    "git@github.com:acme-corp/widgets.git",
    "git@GitHub.com:Acme-Corp/widgets.git",
    "https://github.com/acme-corp/widgets",
    "https://github.com./acme-corp/widgets.git",
    "ssh://git@ssh.github.com:443/acme-corp/widgets.git",
    "https://github.com//acme-corp//widgets.git",
    "https://github.com/foo/../acme-corp/widgets.git",
    "https://github.com/%61cme-corp/widgets.git",
    "git@github.com:someone/else.git",
    "https://github.com/acme-corporation/x",
    "https://gitlab.example.org/team/alpha/repo.git",
    "https://gitlab.example.org/team/gamma/repo.git",
    "git@example.net:acme-corp/widgets.git",
    "/srv/git/acme-corp/widgets.git",
    "never-matches-ledger",
]


@unittest.skipUnless(shutil.which("go") and shutil.which("git"), "needs go and git")
class Parity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = Path(tempfile.mkdtemp(prefix="tracked-parity-"))
        cls.bin = cls.tmp / "harness"
        build = subprocess.run(["go", "build", "-o", str(cls.bin), "github.com/ericmacdougall/agent-harness/cmd/harness"],
                               cwd=ROOT, capture_output=True, text=True)
        if build.returncode != 0:
            raise unittest.SkipTest("go build failed: " + build.stderr[-300:])
        cls.policy = cls.tmp / "policy.json"
        cls.policy.write_text(json.dumps(POLICY))
        cls.home = cls.tmp / "home"
        cls.home.mkdir()

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def repo_with(self, url):
        repo = Path(tempfile.mkdtemp(dir=self.tmp))
        env = {"HOME": str(self.home), "PATH": os.environ["PATH"], "GIT_CONFIG_GLOBAL": os.devnull}
        subprocess.run(["git", "init", "-q"], cwd=repo, check=True, env=env)
        subprocess.run(["git", "remote", "add", "origin", url], cwd=repo, check=True, env=env)
        return repo, env

    def test_same_answer_for_every_url(self):
        mismatches = []
        for url in URLS:
            repo, env = self.repo_with(url)
            want = commit_policy.repo_ticket_context(str(repo), POLICY)["tracked"]
            out = subprocess.run([str(self.bin), "tickets", "sync-state", "--json"], cwd=repo, capture_output=True, text=True,
                                 env={**env, "HARNESS_COMMIT_POLICY_FILE": str(self.policy)}, timeout=60)
            got = json.loads(out.stdout)
            if got["tracked"] != want:
                mismatches.append((url, want, got["tracked"]))
        self.assertEqual(mismatches, [], "Go and Python disagree (url, python, go)")
        self.assertTrue(any(commit_policy.repo_ticket_context(str(self.repo_with(u)[0]), POLICY)["tracked"] for u in URLS))

    def test_uncompilable_pattern_is_unknown_not_tracked(self):
        policy = self.tmp / "bad.json"
        policy.write_text(json.dumps({"ticket_systems": {"goodqa": {"adapter": "goodqa", "repos": ["(?=lookahead)x"]}}}))
        repo, env = self.repo_with("git@github.com:acme-corp/widgets.git")
        out = subprocess.run([str(self.bin), "tickets", "sync-state", "--json"], cwd=repo, capture_output=True, text=True,
                             env={**env, "HARNESS_COMMIT_POLICY_FILE": str(policy)}, timeout=60)
        got = json.loads(out.stdout)
        self.assertFalse(got["tracked"])
        self.assertFalse(got["tracked_known"])


if __name__ == "__main__":
    unittest.main()
