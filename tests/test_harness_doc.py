"""HARNESS.md is the source of the CLAUDE.md managed block; it must carry the user's model ladder, never the old
automatic Astra-then-Fable rescue (goodqa#14527)."""

from pathlib import Path
import re
import unittest

HARNESS = Path(__file__).resolve().parents[1] / 'HARNESS.md'


class LadderText(unittest.TestCase):
    def setUp(self):
        self.text = HARNESS.read_text(encoding='utf-8')

    def test_no_automatic_astra_or_fable_rescue(self):
        for forbidden in (r'asks headless Codex `gpt-6-astra`', r'falling back to Claude Code `fable`',
                          r'gpt-6-astra` to finish', r'automatically .{0,40}(fable|astra)'):
            self.assertIsNone(re.search(forbidden, self.text, re.I), forbidden)

    def test_ladder_rules_are_present(self):
        for required in ('Model ladder and escalation', 'Writing rungs', 'Review-only rungs',
                         'Never launch Fable or Astra automatically', 'Infrastructure failures and zero-launch attempts do not count',
                         'reset to the lowest rung'):
            self.assertIn(required, self.text, required)


if __name__ == '__main__':
    unittest.main()
