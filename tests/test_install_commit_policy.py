"""Installers register the commit policy hook once and the git backstop only on Git 2.54+."""

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

from test_commit_policy import HOOKS, cp


class Installers(unittest.TestCase):
    def test_install_twice_registers_one_handler_and_one_git_key(self):
        sys.path.insert(0, str(HOOKS.parents[1]))
        import install
        home = Path(tempfile.mkdtemp(prefix="cp-install-"))
        self.addCleanup(shutil.rmtree, home, True)
        for _ in range(2):
            install.install(home, True)
            status = install.install_git_backstop(home, True)
        settings = json.loads((home / ".claude" / "settings.json").read_text())
        handlers = [hook for group in settings["hooks"]["PreToolUse"] for hook in group["hooks"]
                    if (hook.get("args") or [""])[0].endswith("commit_policy.py")]
        self.assertEqual(len(handlers), 1)
        self.assertEqual(handlers[0]["onFailure"], "block")
        self.assertTrue((home / ".claude" / "hooks" / "commit_policy.json").exists())
        if cp.git_version() and cp.git_version() >= (2, 54):
            self.assertIn("registered", status)
            config = (home / ".gitconfig").read_text()
            self.assertEqual(config.count("[hook \"agent-harness-commit-policy\"]"), 1, config)
            self.assertEqual(config.count("commit-msg"), 1)
        else:
            self.assertIn("inactive", status)
        self.assertNotIn("commit_policy.py waive", json.dumps(settings["permissions"]))

    def test_old_git_reports_inactive_backstop(self):
        sys.path.insert(0, str(HOOKS.parents[1]))
        import install
        fake = Path(tempfile.mkdtemp(prefix="cp-oldgit-"))
        self.addCleanup(shutil.rmtree, fake, True)
        (fake / "git").write_text("#!/bin/sh\necho 'git version 2.43.0'\n")
        (fake / "git").chmod(0o755)
        status = install.git_hook_status(fake, "k", fake / "x.py", apply=True, git=str(fake / "git"))
        self.assertIn("backstop inactive", status)
        self.assertFalse((fake / ".gitconfig").exists())


if __name__ == '__main__':
    unittest.main()
