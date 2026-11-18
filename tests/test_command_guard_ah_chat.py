"""goodqa#16396 AC-3: `ah chat ...` needs no guard allowance (the command reads the user token in-process, a shell command never
does), and every ad hoc read of the token file stays refused, also when it is chained to an `ah chat` command."""
import sys
import unittest
from pathlib import Path

HOOKS = Path(__file__).resolve().parents[1] / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
import command_guard as cg  # noqa: E402


def check(command):
    compiled = cg.Compiled(cg.load_policy())
    return cg.decide(command, compiled, marker=cg.Approvals(compiled=compiled))[0]


AH = "python3 ~/.claude/hooks/ah.py"
USER = "11111111-1111-4111-8111-111111111111"
CONV = "0d4e18ae-4ba0-4d2f-a599-66e882c5f7a4"
ALLOWED = [AH + " chat probe", AH + " chat history --with " + USER + " --limit 20",
           AH + " chat history --conversation " + CONV + " --org " + USER + " --no-text",
           AH + " chat files --conversation " + CONV,
           AH + " chat send --with " + USER + " --org " + USER + " --body-file /tmp/reply.txt --client-msg-id 7d1c9a2e-0001"]
BLOCKED = ["cat ~/.config/goodqa/user-token", "head -c 8 ~/.config/goodqa/user-token",
           "python3 -c \"print(open('/Users/eric/.config/goodqa/user-token').read())\"",
           AH + " chat history --with " + USER + " | cat ~/.config/goodqa/user-token",
           AH + " chat probe && base64 ~/.config/goodqa/user-token",
           "curl -s -H \"Authorization: Bearer $(cat ~/.config/goodqa/user-token)\" https://goodqa.app/v1/mcp"]


class AhChatGuard(unittest.TestCase):
    def test_ah_chat_commands_are_allowed(self):
        for command in ALLOWED:
            self.assertEqual(check(command), "allow", command)

    def test_ad_hoc_reads_of_the_token_file_stay_blocked(self):
        for command in BLOCKED:
            self.assertEqual(check(command), "block", command)


if __name__ == "__main__":
    unittest.main()
