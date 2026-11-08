"""HARNESS.md and codex/AGENTS.md are the sources of the installed instruction blocks (goodqa#14527, goodqa#15253
step 4). They must carry the user's model ladder with Fable and Astra disabled except for a named task, never an
automatic or session-wide top-rung path, never a narrowing of the goodqa-remote secure-login route, and the nine
rules the Fable-high review said the rewrite must not drop."""

from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
HARNESS = ROOT / 'HARNESS.md'
CODEX = ROOT / 'codex' / 'AGENTS.md'
FORBIDDEN = (r'asks headless Codex `gpt-6-astra`', r'falling back to Claude Code `fable`', r'gpt-6-astra` to finish',
             r'automatically (?:use|launch|escalate|switch)\w* .{0,30}(fable|astra)',
             r'spawn from the granted session', r'session-wide grant(?! is)(?!\.)',
             r'never the unverified-focus mode for production', r'unverified-focus mode is not for production')
# One phrase per restored review line (REVIEW-fable-high.md, "CLAUDE.md.proposed: dropped or weakened rules").
RESTORED = {
    'shortcut push-back': r'[Pp]ush back on a (?:requested )?shortcut',
    'incomplete starting points': r'incomplete starting points',
    'silence is not approval': r'never treat silence as approval',
    'spec flow two reviews': r'two,? from different models or agents',
    'final PR gate': r'peer_review\.py pr` receipt',
    'performance under load': r'representative load',
    'disposable click-test accounts': r'disposable accounts only in owned local or staging',
    'releases': r'[Nn]ever deploy merely because tests pass',
    'password list': r'[Nn]ever put a password in a command, environment variable, WAL, ticket, screenshot description or log',
}


class InstructionText(unittest.TestCase):
    def check(self, path, restored):
        text = path.read_text(encoding='utf-8')
        for forbidden in FORBIDDEN:
            with self.subTest(path=path.name, forbidden=forbidden):
                self.assertIsNone(re.search(forbidden, text, re.I))
        for name, pattern in restored.items():
            with self.subTest(path=path.name, rule=name):
                self.assertRegex(text, pattern)
        self.assertRegex(text, r'Fable and Astra (?:stay )?(?:DISABLED|disabled)')
        self.assertIn('approve-top --task T', text)
        self.assertRegex(text, r'Opus medium, (?:Opus )?high, (?:Opus )?xhigh')
        self.assertIn('goodqa-remote', text)
        self.assertNotIn('## User-authorized secure login', text)  # the user's own section lives outside the block
        return text

    def test_claude_block(self):
        text = self.check(HARNESS, RESTORED)
        self.assertTrue(text.startswith('# Agent Harness engineering workflow\n'))  # install.py's known-block check
        self.assertIn('Infrastructure failures and zero-launch attempts never count', text)
        for kind in ('`uuid:`', '`answer:`', '`queue:`', '`pasted:', '`inferred:`'):
            self.assertIn(kind, text)

    def test_codex_block(self):
        restored = {k: v for k, v in RESTORED.items() if k not in ('disposable click-test accounts',)}
        text = self.check(CODEX, restored)
        self.assertTrue(text.startswith('# Agent Harness for Codex\n'))
        self.assertIn('~/.codex/agent-harness/installer_scan.py', text)


if __name__ == '__main__':
    unittest.main()
