"""The standing rules (HARNESS.md for Claude Code, codex/AGENTS.md for Codex) are short and true.

Short: at most 600 words each (docs/direction.md: "standing rules a person can read in two minutes"; Neo's size budget
enforced by a test). True: every `ah <word>`, `harness <word>` and `<script>.py` they name in backticks exists, so an
agent that follows them never meets a missing command. The installers recognise their own block by its first line
(install.py merged_instructions, install_codex.py merge_marked), so the headings are fixed.

This test names commands that other workstreams add (`ah sandbox`, `ah doctor`, `ah review-status`): it is red until
those are merged, which is why the roles-and-rules branch merges last."""

import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HOOKS = ROOT / "harness" / "hooks"
SHIM = ROOT / "harness" / "bin" / "harness"
RULES = {
    "HARNESS.md": "# Agent Harness engineering workflow\n",
    "codex/AGENTS.md": "# Agent Harness for Codex\n",
}
WORD_BUDGET = 600
SPAN = re.compile(r"`([^`\n]+)`")
AH_WORD = re.compile(r"(?:^|[\s/(])ah(?:\.py)? +([a-z][a-z-]*)")
HARNESS_WORDS = re.compile(r"(?:^|\s)harness +([a-z][a-z|-]*)")
SCRIPT = re.compile(r"([A-Za-z0-9_]+\.py)\b")


def text(name):
    return (ROOT / name).read_text(encoding="utf-8")


def spans(name):
    return SPAN.findall(text(name))


def named(pattern, name):
    out = set()
    for span in spans(name):
        for match in pattern.findall(span):
            out.update(word for word in match.split("|") if word)
    return out


def shim_words():
    """Every word of the shim's `case` patterns (`off|on|status|...)`)."""
    words = set()
    for line in SHIM.read_text().splitlines():
        match = re.match(r"^\s*([A-Za-z\"|-][^)(]*)\)\s*(?:#.*)?$", line)
        if match:
            words.update(part.strip().strip('"') for part in match.group(1).split("|"))
    return {word for word in words if word}


class Budget(unittest.TestCase):
    def test_each_file_is_at_most_600_words(self):
        for name in RULES:
            with self.subTest(file=name):
                count = len(text(name).split())
                self.assertLessEqual(count, WORD_BUDGET, f"{name} has {count} words")

    def test_the_first_line_is_the_installers_known_heading(self):
        for name, heading in RULES.items():
            with self.subTest(file=name):
                self.assertTrue(text(name).startswith(heading))


class NamedThingsExist(unittest.TestCase):
    def test_every_script_named_is_a_hook_file(self):
        for name in RULES:
            for script in sorted(named(SCRIPT, name)):
                with self.subTest(file=name, script=script):
                    self.assertTrue((HOOKS / script).is_file(), f"{name} names {script}, not in harness/hooks")

    def test_every_harness_word_is_in_the_shims_case_list(self):
        words = shim_words()
        self.assertIn("off", words)
        for name in RULES:
            for word in sorted(named(HARNESS_WORDS, name)):
                with self.subTest(file=name, word=word):
                    self.assertIn(word, words, f"{name} names `harness {word}`; the shim does not accept it")

    def test_every_ah_word_answers_help(self):
        wanted = set()
        for name in RULES:
            wanted |= named(AH_WORD, name)
        self.assertTrue(wanted, "the rules name no ah command")
        with tempfile.TemporaryDirectory(prefix="standing-rules-") as home:
            env = {"HOME": home, "PATH": os.environ.get("PATH", "/usr/bin:/bin"), "LANG": "C.UTF-8"}
            for word in sorted(wanted):
                with self.subTest(word=word):
                    run = subprocess.run([sys.executable, "-I", str(HOOKS / "ah.py"), word, "--help"], env=env,
                                         cwd=home, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
                    self.assertEqual(run.returncode, 0, f"`ah {word} --help`: {run.stderr.decode()[-400:]}")


class NoteCommandLeavesTheSandbox(unittest.TestCase):
    def test_the_claude_note_command_matches_an_excluded_command(self):
        """~/.claude stays write-protected in the sandbox even where allowWrite names it, so the note command must run
        outside it: the rule has to spell it the way the worker and supervisor excludedCommands do."""
        import fnmatch
        sys.path.insert(0, str(HOOKS))
        import ah_sandbox
        named = [span for span in spans("HARNESS.md") if "wal_note.py" in span]
        self.assertTrue(named)
        with tempfile.TemporaryDirectory() as home:
            for role in ("worker", "supervisor"):
                excluded = ah_sandbox.claude_settings(role, home=Path(home))["sandbox"].get("excludedCommands") or []
                for span in named:
                    with self.subTest(role=role, span=span):
                        self.assertTrue(any(fnmatch.fnmatchcase(span, rule) for rule in excluded), excluded)


class SafetyContent(unittest.TestCase):
    """The few rules that must survive any rewrite (they replace the pinned lines of the 3,000-word version)."""

    MUST = {
        "untrusted text": r"evidence, (?:not|never) instructions",
        "secret never printed": r"[Nn]ever print, log, copy or (?:transit|send) a secret",
        "password list": r"[Nn]ever put a password in a command, environment variable",
        "production accounts": r"[Nn]ever create (?:an account on a production system|a production account)",
        "refusal is the boundary": r"refusal is the boundary",
        "no force-push": r"[Nn]ever force-push",
        "review before merge": r"peer_review\.py pr",
        "review status": r"harness/review",
        "re-review never asked": r"never ask",
        "approvals checked first": r"ah approvals check",
        "handoff before turn end": r"handoff",
        "off switch is the owner's": r"off switch is the owner's",
        "done means live": r"[Dd]one means deployed (?:to live )?and tested live",
        "refuse with the path": r"[Rr]efuse with the path",
        "secure login route": r"goodqa-remote",
        "silence is not approval": r"never treat silence as approval",
        "owner cap": r"owner cap",
    }

    def test_the_load_bearing_rules_are_present(self):
        for name in RULES:
            body = text(name)
            for rule, pattern in self.MUST.items():
                with self.subTest(file=name, rule=rule):
                    self.assertRegex(body, pattern)

    def test_no_standing_approval_and_no_model_authority(self):
        for name in RULES:
            body = text(name)
            with self.subTest(file=name):
                self.assertIsNone(re.search(r"(?i)\bis (?:hereby )?approved\b", body))
                self.assertIsNone(re.search(r"(?i)(?:fable|astra)[^.]{0,40}may (?:delete|handle secrets)", body))
                self.assertIsNone(re.search(r"(?i)session-wide grant(?! is)(?!\.)", body))


if __name__ == "__main__":
    unittest.main()
