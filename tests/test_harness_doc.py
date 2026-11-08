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



# Red-team M1 (PR 144): the phrase checks above cannot see a reworded safety rule, so the user-approved text of the
# hard rules, the secure-login item and the Fable/Astra and ladder rules is pinned line by line. Changing one of these
# lines is a rule change: it needs the user's approval, and then a new pin here.
PINNED = {
    "HARNESS.md": {
        "1. Never print": "939a3c095ad2eb8c6062bf741714897eded5d51409147678ffb198a0ea2031e0",
        "2. Never create": "8cd3f24c92b36a73274684ba8f98e6644705ddf47fe92bdef4fe99e158b45af9",
        "3. Never evade": "b43469f9c679f606751d20ccbb50b5c25ff15bce7cb1ca3db828c02776973b7d",
        "4. Never force-push": "aa10404b12f608ca5018816a706b533dc5fda925a8f3362301ab52f754aeda6f",
        "5. My memory rules": "a8273b5e4b8b356f4c076a8f7499d35f7e10c00c9d0ecf08f139ca3aa100f6ac",
        "6. Done means": "08bb5709368971e89d7ded878498b2c9302152440c0dc78a04861ffb06c41420",
        "3. **Vault-typed login": "741937859e1e1b2158d8be05cbd6e517af67a9479b3748127995db0000a71266",
        "- Fable and Astra stay DISABLED": "67d5295defc7cca4d8caef4222c83ce1f9934ac335407c94445bf29a6c5d21e5",
        "- Model ladder": "0a8f202f2807461cef8e04660a6ac1035b5970dd6f65f536ecd97b4b48d1847a"
    },
    "codex/AGENTS.md": {
        "1. Never print": "70b5f6faf9f6b4d4566e004c3ecef0f7496a9719eafca5798b8cdedb88f235ba",
        "2. Never create": "ac3685e3c3b13ef5f313280b4a9c81096a14255e805c9a2c031ee7ceff1f2f97",
        "3. Never evade": "23b962ecde20f4f7e4a852401d90968b3127c1eba6744cafc47424644b10a649",
        "4. Never force-push": "0f3ecc48705a01b9c6f9f194e94639af2bf7c295037ba8b23ce818b0d07336ea",
        "5. The user's memory rules": "b1b778c03644989e42ece1463c5db0cebd0b3fafb573111b8722c30988a0eba2",
        "6. Done means": "8786cf6840c24aaadbef8799dc3550f54cdb68768eabc30b33992da63179bc99",
        "The first refusal names the path": "08bab5fbff53624062a824af880e9946ce5b4cb67bd875ef6333210c9e2f55d4",
        "- Model ladder": "52026b466675244aa910551b7b0597bfd684b6d978a1663bc3bdea89de2d85d9"
    }
}


class PinnedSafetyLines(unittest.TestCase):
    def test_safety_lines_match_the_approved_text(self):
        import hashlib  # noqa: PLC0415
        for name, prefixes in PINNED.items():
            lines = (ROOT / name).read_text(encoding='utf-8').splitlines()
            for prefix, digest in prefixes.items():
                with self.subTest(file=name, line=prefix):
                    hits = [line for line in lines if line.startswith(prefix)]
                    self.assertEqual(len(hits), 1, 'expected exactly one line starting %r' % prefix)
                    self.assertEqual(hashlib.sha256(hits[0].encode()).hexdigest(), digest,
                                     'approved line changed: %r' % hits[0][:120])

    def test_session_grant_is_only_ever_denied(self):
        for path in (HARNESS, CODEX):
            text = path.read_text(encoding='utf-8')
            with self.subTest(file=path.name):
                mentions = re.findall(r'[^.]*session[- ]wide[^.]*', text, re.I)
                self.assertTrue(mentions, 'the no-session-grant rule is missing')
                for sentence in mentions:
                    self.assertRegex(sentence, r'(?i)\b(?:there is )?no session-wide grant')
                self.assertIsNone(re.search(r'(?i)enable (?:them|fable|astra) for the session', text))


if __name__ == '__main__':
    unittest.main()
