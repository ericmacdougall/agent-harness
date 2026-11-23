"""takeover_rules.py and its two callers (command_guard.decide, kill_guard.decide): the literal `ah.py takeover` form (W2)
and the user-only enable entry points (G5). No rule reads an identity from command text any more (review rounds 1-2:
every text rule invited a new spelling); identity comes from the hook payload only (test_takeover_identity). Command
text is data here: nothing is run."""
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

HOOKS = Path(__file__).resolve().parents[1] / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
import command_guard as cg  # noqa: E402
import kill_guard as kg  # noqa: E402
import takeover_rules as rules  # noqa: E402

ME = "6df7b63f-b062-4fa8-834a-f6bd857d0c54"
OLD = "01a2012f-bca0-78b0-8fc7-162587de5ee7"
CLAUDE = "python3 -I ~/.claude/hooks/ah.py takeover"
CODEX = "python3 -I ~/.codex/agent-harness/ah.py takeover"
TICKET = "'GoodQA goodqa#16441'"


class W2Form(unittest.TestCase):
    def ok(self, command):
        self.assertIsNone(rules.refusal(command, ME), command)

    def bad(self, command, part="takeover"):
        text = rules.refusal(command, ME)
        self.assertIsNotNone(text, command)
        self.assertIn(part, text)
        return text

    def test_the_documented_literal_forms_are_allowed_on_both_paths(self):
        for base in (CLAUDE, CODEX):
            self.ok("%s status --from %s" % (base, OLD))
            self.ok("%s status --from %s --action processes --json" % (base, OLD))
            self.ok("%s plan --from %s --action worktrees" % (base, OLD))
            self.ok("%s claim --from %s --reason 'old thread stopped' --ticket %s" % (base, OLD, TICKET))
            self.ok("%s cleanup --from %s --action worktrees --reason r --ticket %s --path /a/b --path /a/c --apply" % (base, OLD, TICKET))
            self.ok("%s cleanup --from %s --action processes --reason r --ticket %s --pid 12 --pid 13" % (base, OLD, TICKET))

    def test_variables_substitutions_chains_pipes_redirects_and_assignments_are_refused(self):
        for tail in ("status --from $S", "status --from `id`", "status --from $(id)", "status --from %s && ls" % OLD,
                     "status --from %s ; ls" % OLD, "status --from %s | tail" % OLD, "status --from %s > /tmp/x" % OLD,
                     "status --from %s --via x" % OLD, "status --from %s --evil" % OLD, "bogus --from %s" % OLD,
                     "cleanup --from %s --action worktrees --reason r" % OLD,
                     "cleanup --from %s --action worktrees --reason r --ticket 'GoodQA x#1 $(id)'" % OLD,
                     "cleanup --from %s --action worktrees --reason $R --ticket %s" % (OLD, TICKET),
                     "cleanup --from %s --action worktrees --reason r --ticket %s --path ../x" % (OLD, TICKET),
                     "status --from %s --from %s" % (OLD, OLD), "claim --from %s --reason r" % OLD):
            self.bad("%s %s" % (CLAUDE, tail))
        self.bad("FOO=1 %s status --from %s" % (CLAUDE, OLD))
        self.bad("env FOO=1 %s status --from %s" % (CLAUDE, OLD))
        self.bad("bash -c '%s status --from %s'" % (CLAUDE, OLD))
        self.bad("python3 ~/.claude/hooks/ah.py takeover status --from %s" % OLD)
        self.bad("python3 -I ./ah.py takeover status --from %s" % OLD)
        self.bad("python3 -I /tmp/ah.py takeover status --from %s" % OLD)

    def test_over_ssh_only_the_evidence_read_exists(self):
        ok = "ssh t2-dev 'python3 -I .claude/hooks/ah.py takeover status --from %s --evidence-only --json'" % OLD
        self.ok(ok)
        quoted = '"GoodQA goodqa#16441"'  # inside the single-quoted remote command
        for tail in ("cleanup --from %s --action worktrees --reason r --ticket %s --apply" % (OLD, quoted),
                     "status --from %s" % OLD, "claim --from %s --reason r --ticket %s" % (OLD, quoted)):
            self.bad("ssh t2-dev 'python3 -I .claude/hooks/ah.py takeover %s'" % tail, "over ssh")

    def test_text_that_only_mentions_the_command_is_not_judged(self):
        self.ok("git commit -m 'document ah.py takeover cleanup'")
        self.ok("grep -rn takeover harness/hooks")
        self.ok("ls ~/.agent-harness/takeover")


class NoIdentityTextRules(unittest.TestCase):
    """G2, G3 and G4 are gone: the strings they matched are no longer the rules' business, because no tool reads an
    identity from a flag, a variable or the ancestry. test_takeover_identity proves each one is harmless (foreign)."""

    def test_identity_spellings_are_not_judged_by_text(self):
        for command in ("CLAUDE_CODE_SESSION_ID=abc python3 -I ~/.claude/hooks/ah.py worktree-remove --host local --path /x --reason r",
                        "CODEX_THREAD_ID=abc python3 -I ~/.codex/agent-harness/ah.py kill --pid 5 --reason r",
                        "python3 -I ~/.codex/agent-harness/wal.py continuation --wal /Users/u/.agent-harness/codex-wals/%s/main.jsonl handoff" % OLD):
            with self.subTest(command=command[:50]):
                self.assertIsNone(rules.refusal(command, ME))
        self.assertFalse(hasattr(rules, "safe_id"))
        self.assertFalse(hasattr(cg, "verifier_caller"))


class G5EnableScript(unittest.TestCase):
    S = "scripts/enable-takeover-cleanup.sh"

    P = "scripts/enable_takeover_cleanup.py"

    def test_apply_and_undo_are_refused_in_every_form_and_dry_run_and_verify_pass(self):
        for command in ("bash %s --apply" % self.S, "sh %s --undo --hooks" % self.S, "./%s --apply --ref abc" % self.S,
                        "/Users/u/kit/%s --apply" % self.S, "env X=1 bash %s --apply" % self.S,
                        "ssh t2-dev 'bash enable-takeover-cleanup.sh --undo'", "bash -c '%s --apply'" % self.S,
                        "nohup bash %s --apply" % self.S, "bash %s --ref abc --repo r --apply" % self.S,
                        # m1: the Python entry, prefixes, `env -u` and any other option outside the read-only allowlist
                        "python3 %s --apply" % self.P, "python3 -I %s --ref x --repo y --undo" % self.P,
                        "bash %s --app" % self.S, "bash %s --a" % self.S, "bash %s --und" % self.S,
                        "python3 %s --appl" % self.P, "env -u CLAUDECODE bash %s --apply" % self.S,
                        "bash %s --hooks" % self.S, "bash %s --dry-run; bash %s --apply" % (self.S, self.S)):
            with self.subTest(command=command[:50]):
                self.assertIn("user", rules.refusal(command, ME) or "", command)
        for command in ("bash %s --dry-run --ref abc" % self.S, "bash %s --verify" % self.S, "bash %s" % self.S,
                        "git add %s" % self.S, "git commit -m 'script %s --apply'" % self.S, "cat %s" % self.S):
            with self.subTest(command=command[:50]):
                self.assertIsNone(rules.refusal(command, ME))


class ThroughTheGuards(unittest.TestCase):
    """The rules are wired into command_guard.decide and kill_guard.decide, on the payload session."""

    def cg_verdict(self, command, session=ME):
        with mock.patch.object(cg, "HOOK_SESSION", session):
            return cg.decide(command, cg.Compiled(cg.load_policy(), cwd="/tmp"), cwd="/tmp")

    def kg_verdict(self, command, session=ME):
        with tempfile.TemporaryDirectory() as tmp:
            return kg.decide(command, cwd=tmp, policy=kg.load_policy(), home=tmp, main=True, session=session)

    def test_command_guard_blocks_the_shortcuts_and_allows_the_literal_form(self):
        verdict, text = self.cg_verdict("%s cleanup --from %s --action worktrees --reason r --ticket %s --apply && echo" % (CLAUDE, OLD, TICKET))
        self.assertEqual(verdict, "block")
        self.assertIn("Form:", text)
        self.assertEqual(self.cg_verdict("CODEX_THREAD_ID=x python3 -I ~/.claude/hooks/ah.py takeover status --from %s" % OLD)[0], "block",
                         "W2: an assignment before the takeover command is not the literal form")
        self.assertEqual(self.cg_verdict("bash scripts/enable-takeover-cleanup.sh --apply")[0], "block")
        self.assertEqual(self.cg_verdict("python3 scripts/enable_takeover_cleanup.py --apply")[0], "block")
        self.assertEqual(self.cg_verdict("%s status --from %s" % (CLAUDE, OLD))[0], "allow")

    def test_kill_guard_blocks_the_identity_and_the_script_and_allows_the_literal_forms(self):
        self.assertEqual(self.kg_verdict("CODEX_THREAD_ID=x python3 -I ~/.claude/hooks/ah.py takeover status --from %s" % OLD)[0], "block")
        self.assertEqual(self.kg_verdict("bash scripts/enable-takeover-cleanup.sh --undo")[0], "block")
        for base in (CLAUDE, CODEX):
            self.assertEqual(self.kg_verdict("%s status --from %s" % (base, OLD))[0], "allow", base)
            # a reason that says "kill" is a reason, not interpreter code
            self.assertEqual(self.kg_verdict("%s cleanup --from %s --action processes --reason 'kill old codex helpers' --ticket %s" % (base, OLD, TICKET))[0], "allow", base)
        self.assertEqual(self.kg_verdict("%s cleanup --from %s --action processes --reason 'kill it' --ticket %s ; ls" % (CLAUDE, OLD, TICKET))[0], "block")


class ReviewBypasses(unittest.TestCase):
    """The takeover strings the review used at db950737 still meet the W2 grammar; the identity strings it used (G2, G3,
    G4) carry no identity any more and are covered by test_takeover_identity instead of a text rule."""

    def blocked(self, command, session=ME):
        self.assertIsNotNone(rules.refusal(command, session), command)

    def bypasses(self):
        return ["python3 -IB ~/.claude/hooks/ah.py takeover cleanup --from %s --action worktrees --reason r --ticket %s "
                "--apply" % (OLD, TICKET),
                "export CODEX_THREAD_ID=%s && python3 -X utf8 ~/.codex/agent-harness/ah.py takeover status --from %s" % (OLD, OLD),
                "python3 -I ~/.claude/hooks/ah.py takeover status --from %s # it's" % OLD]

    def test_every_review_bypass_is_refused(self):
        for command in self.bypasses():
            with self.subTest(command=command[:70]):
                self.blocked(command)

    def test_the_ssh_wrapped_forms_are_refused(self):
        for command in self.bypasses():
            remote = command.replace("~/", "").replace("'", "")
            with self.subTest(command=remote[:70]):
                self.blocked("ssh t2-dev '%s'" % remote)

    def test_an_unparsable_command_that_names_a_harness_tool_and_a_takeover_word_is_refused(self):
        self.blocked("python3 -I ~/.claude/hooks/ah.py takeover status --from %s 'unterminated" % OLD)
        # an unparsable command that names no harness tool is not this module's business
        self.assertIsNone(rules.refusal("echo takeover it's", ME))

    def test_reading_the_tools_is_not_judged(self):
        for command in ("grep -n remove-worktree harness/hooks/command_guard.py", "git diff -- harness/hooks/takeover_rules.py",
                        "sed -n 1,20p harness/hooks/wal.py", "grep -rn continuation codex/hooks/wal.py",
                        "grep -n apply scripts/enable-takeover-cleanup.sh"):
            self.assertIsNone(rules.refusal(command, ME), command)


class FailClosed(unittest.TestCase):
    """A missing or broken takeover_rules.py blocks the takeover words next to a harness tool instead of allowing them."""
    TEXT = "python3 -I ~/.claude/hooks/ah.py takeover cleanup --from %s --action worktrees --reason r --ticket %s --apply" % (OLD, TICKET)

    def test_command_guard_blocks_when_the_rules_cannot_be_loaded(self):
        for error in (FileNotFoundError("gone"), SyntaxError("broken"), RuntimeError("x")):
            with self.subTest(error=type(error).__name__), mock.patch.object(cg, "_load_takeover_rules", side_effect=error):
                self.assertIn("could not be loaded", cg.takeover_rules_refusal(self.TEXT, ME))
                self.assertIsNone(cg.takeover_rules_refusal("git status", ME))
                self.assertIsNone(cg.takeover_rules_refusal("grep takeover notes.txt", ME))

    def test_kill_guard_blocks_when_the_rules_cannot_be_loaded(self):
        with mock.patch.object(kg, "takeover_rules", side_effect=FileNotFoundError("gone")), \
                tempfile.TemporaryDirectory() as tmp:
            verdict = kg.decide("CODEX_THREAD_ID=x python3 -I ~/.claude/hooks/ah.py takeover status --from %s" % OLD,
                                cwd=tmp, policy=kg.load_policy(), home=tmp, main=True, session=ME)
        self.assertEqual(verdict[0], "block")

    def test_the_guards_prefilter_quote_flattened_text(self):
        with mock.patch.object(cg, "HOOK_SESSION", ME):
            verdict, _text = cg.decide("bash scripts/enable-takeover-clean''up.sh --apply",
                                       cg.Compiled(cg.load_policy(), cwd="/tmp"), cwd="/tmp")
        self.assertEqual(verdict, "block")
        with tempfile.TemporaryDirectory() as tmp:
            verdict = kg.decide("CLAUDE_SESSION_ID=x python3 -I ~/.claude/hooks/ah.py take''over status --from %s" % OLD,
                                cwd=tmp, policy=kg.load_policy(), home=tmp, main=True, session=ME)
        self.assertEqual(verdict[0], "block")


class SessionRecordWrites(unittest.TestCase):
    """~/.claude/sessions/<pid>.json is what proves the caller now: creating one is refused like a guard file."""

    def test_creating_or_replacing_a_session_record_is_refused(self):
        compiled = cg.Compiled(cg.load_policy(), cwd="/tmp")
        for command in ("echo {} > ~/.claude/sessions/4242424.json", "cp /tmp/a.json ~/.claude/sessions/4242424.json",
                        "tee ~/.claude/sessions/4242424.json < /tmp/a"):
            with self.subTest(command=command), mock.patch.object(cg, "HOOK_SESSION", ME):
                self.assertEqual(cg.decide(command, compiled, cwd="/tmp")[0], "block", command)
        with mock.patch.object(cg, "HOOK_SESSION", ME):
            self.assertEqual(cg.decide("ls ~/.claude/sessions", compiled, cwd="/tmp")[0], "allow")


class KillGuardFlags(unittest.TestCase):
    A = "python3 -I ~/.claude/hooks/ah.py kill --pid 4242 --reason probe"
    C = "python3 -I ~/.codex/agent-harness/ah.py kill --pid 4242 --reason probe"

    def verdict(self, command, main=False):
        with tempfile.TemporaryDirectory() as tmp:
            return kg.decide(command, cwd=tmp, policy=kg.load_policy(), home=tmp, main=main)[0]

    def test_dry_run_is_allowed_for_any_agent_on_both_paths(self):
        for base in (self.A, self.C):
            self.assertEqual(self.verdict(base + " --dry-run"), "allow", base)
            self.assertEqual(self.verdict(base + " --dry-run --foreign"), "allow", base)

    def test_dry_run_must_be_a_bare_flag_used_once(self):
        for tail in (" --dry-run=1", " --dry-run --dry-run", " --dry-run --bogus", " --dry-run=true"):
            self.assertEqual(self.verdict(self.A + tail), "block", tail)

    def test_expect_start_and_takeover_of_only_narrow(self):
        ok = self.A + " --foreign --expect-start 4242:1700000000 --expect-start 4243:1700000001 --takeover-of " + OLD
        self.assertEqual(self.verdict(ok), "allow")
        for tail in (" --expect-start 4242", " --expect-start 4242:12", " --takeover-of Bad_ID", " --takeover-of x $(id)"):
            self.assertEqual(self.verdict(self.A + tail), "block", tail)

    def test_the_codex_path_keeps_the_main_only_flags(self):
        for flag in (" --approved-by ask-1234", " --session-scope"):
            self.assertEqual(self.verdict(self.C + flag, main=False), "block", flag)


if __name__ == "__main__":
    unittest.main()
