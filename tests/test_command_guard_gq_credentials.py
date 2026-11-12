"""goodqa#15785: the GoodQA user token and the gq-browser lease keys are credential files; a shell read of either is refused
(secret_dump) like any other credential path, while in-process reads by the client are not shell commands and stay untouched."""
import sys
import unittest
from pathlib import Path

HOOKS = Path(__file__).resolve().parents[1] / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
import command_guard as cg  # noqa: E402


def check(command):
    compiled = cg.Compiled(cg.load_policy())
    return cg.decide(command, compiled, marker=cg.Approvals(compiled=compiled))


TOKEN = "~/.config/goodqa/user-token"
KEY = "~/.agent-harness/gq-browser/0123456789abcdef/key"
READERS = ["cat {p}", "head -c 5 {p}", "base64 {p}", "tail -n 1 {p}", "strings {p}", "less {p}", "xxd {p}",
           "cat $HOME/{q}", "cat /Users/eric/{q}", "cat '/Users/eric/{q}'", "grep . {p}", "sed -n 1p {p}", "awk 1 {p}"]
GLOBS = ["cat ~/.agent-harness/gq-browser/*/key", "cat ~/.config/goodqa/*", "cat ~/.config/goodqa/user-tok*",
         "cat ~/.agent-harness/gq-browser/*/k*",
         "base64 ~/.config/goodqa/user-to?en", "cat ~/.config/goodqa/user-token*"]
OTHER = ["ls ~/.agent-harness/gq-browser/*", "cat ~/.config/goodqa/config.json", "ls ~/.config/goodqa", "ls ~/.agent-harness/gq-browser",
         "cat ~/.agent-harness/gq-browser/0123456789abcdef/lease.json", "cat ~/.agent-harness/gq-browser/short/key",
         "cat ~/.agent-harness/gq-browser/0123456789abcdef/keys", "echo user-token", "cat docs/user-token.md",
         "grep -n user-token docs/gq-browser.md", "cat ~/.config/goodqa/user-token.md"]


class GoodqaCredentialPaths(unittest.TestCase):
    def verdict(self, command):
        result = check(command)
        return result[0] if isinstance(result, tuple) else result

    def test_a_shell_read_of_the_user_token_or_a_lease_key_is_blocked(self):
        for path, rel in ((TOKEN, ".config/goodqa/user-token"), (KEY, ".agent-harness/gq-browser/0123456789abcdef/key")):
            for template in READERS:
                command = template.format(p=path, q=rel)
                with self.subTest(command):
                    self.assertEqual(self.verdict(command), "block", command)

    def test_a_glob_that_would_expand_to_either_file_is_blocked(self):
        for command in GLOBS:
            with self.subTest(command):
                self.assertEqual(self.verdict(command), "block", command)

    def test_neighbouring_files_and_viewers_that_do_not_read_the_value_stay_allowed(self):
        for command in OTHER:
            with self.subTest(command):
                self.assertNotEqual(self.verdict(command), "block", command)


if __name__ == "__main__":
    unittest.main()
