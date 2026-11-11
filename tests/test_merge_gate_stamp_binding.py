"""The hook-sourced merge waiver stamp is bound to a proven main caller and to ONE plain command (goodqa#15565, #15684).

Before: merge_gate.decide minted the stamp for any payload without an agent_id (Codex hook payloads never carry one),
so a payload that is not provably main could mint it and consume it with `merge_gate.py waive` to obtain a
hook-sourced, single-use merge waiver. It also minted for an unquoted echo or printf that merely contained the words,
and for a command whose quoted `;` the tokenizer had split.

Every command string here is DATA handed to merge_gate.decide in memory with a scratch state dir; nothing runs."""
import io
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_merge_gate import HEAD, SCENARIOS, Base, FakeGh, bash, mg  # noqa: E402

import caller_identity  # noqa: E402
import native_main  # noqa: E402

TICKET = "GoodQA #14502"
REASON = "approved by main after review"
PLAIN = ("python3 ~/.claude/hooks/merge_gate.py waive --repo o/r --pr 5 --head " + HEAD + " --ticket 'GoodQA #14502' "
         "--reason 'approved by main after review'")


class StampBinding(Base):
    def decide_as(self, command, *, main, root=False, **extra):
        """main: what caller_identity.is_main says; root: what native_main.is_desktop_review_root says."""
        with mock.patch.object(caller_identity, "is_main", return_value=main), \
                mock.patch.object(native_main, "is_desktop_review_root", return_value=root):
            return mg.decide(bash(command, **extra), FakeGh(SCENARIOS["green"]), self.state)

    def test_a_codex_desktop_root_session_may_record_but_a_codex_child_may_not(self):
        # The current user-driven Codex Desktop root (is_main is false for every Codex payload) works ...
        code, text = self.decide_as(PLAIN, main=False, root=True)
        self.assertEqual(code, 0, text)
        self.assertEqual(len(self.stamps()), 1)
        done, message = self.record()
        self.assertEqual(done, 0, message)
        self.assertIn("(hook)", message)

    def test_a_codex_child_or_standalone_cli_is_refused(self):
        code, text = self.decide_as(PLAIN, main=False, root=False)
        self.assertEqual(code, 2, text)
        self.assertEqual(self.stamps(), [])

    def test_an_agent_id_always_wins_over_root_proof(self):
        code, text = self.decide_as(PLAIN, main=False, root=True, agent_id="child-1")
        self.assertEqual(code, 2, text)
        self.assertEqual(self.stamps(), [])

    def test_root_proof_must_be_exactly_true_and_errors_are_not_proof(self):
        for value in ("yes", 1, object(), None):
            with self.subTest(value=repr(value)[:20]):
                code, _ = self.decide_as(PLAIN, main=False, root=value)
                self.assertEqual(code, 2)
                self.assertEqual(self.stamps(), [])
        with mock.patch.object(caller_identity, "is_main", return_value=False), \
                mock.patch.object(native_main, "is_desktop_review_root", side_effect=RuntimeError("boom")):
            code, _ = mg.decide(bash(PLAIN), FakeGh(SCENARIOS["green"]), self.state)
        self.assertEqual(code, 2)
        self.assertEqual(self.stamps(), [])

    def test_the_cli_error_text_documents_the_no_stamp_rule(self):
        done, message = self.record()
        self.assertEqual(done, 3)
        for needle in ("--approved-by", "ONE plain command", "backtick", "--reason", "no stamp"):
            self.assertIn(needle, message)

    def record(self):
        out, err = io.StringIO(), io.StringIO()
        argv = ["waive", "--state-dir", str(self.state), "--repo", "o/r", "--pr", "5", "--head", HEAD, "--ticket",
                TICKET, "--reason", REASON]
        code = mg.main(argv, runner=FakeGh(SCENARIOS["green"]), stdout=out, stderr=err)
        return code, out.getvalue() + err.getvalue()

    def stamps(self):
        return sorted(p.name for p in self.state.rglob("*.json"))

    def test_a_proven_main_plain_command_mints_the_stamp_and_the_cli_records_a_hook_waiver(self):
        code, text = self.decide_as(PLAIN, main=True)
        self.assertEqual(code, 0, text)
        self.assertEqual(len(self.stamps()), 1)
        done, message = self.record()
        self.assertEqual(done, 0, message)
        self.assertIn("(hook)", message)

    def test_a_payload_that_is_not_provably_main_mints_nothing_and_cannot_record(self):
        # The shape of a Codex hook payload: no agent_id, no transcript proof.
        code, text = self.decide_as(PLAIN, main=False)
        self.assertEqual(code, 2, text)
        self.assertIn("only the main agent may record a waiver", text)
        self.assertEqual(self.stamps(), [])
        done, message = self.record()
        self.assertEqual(done, 3, message)
        self.assertNotIn("recorded", message)

    def test_a_subagent_is_still_refused_even_when_the_payload_claims_main(self):
        code, text = self.decide_as(PLAIN, main=True, agent_id="agent-sub-1", agent_type="task-owner")
        self.assertEqual(code, 2, text)
        self.assertEqual(self.stamps(), [])

    def test_text_that_merely_contains_the_command_mints_no_stamp_even_for_main(self):
        forms = [
            "echo python3 ~/.claude/hooks/merge_gate.py waive --repo o/r --pr 5 --head " + HEAD + " --ticket T --reason x",
            "printf %s merge_gate.py waive --repo o/r --pr 5 --head " + HEAD + " --ticket T",
            PLAIN + " > /tmp/log",
            PLAIN + " | tail -1",
            PLAIN + " &",
            PLAIN + "; echo done",
            "true && " + PLAIN,
            "(" + PLAIN + ")",
            PLAIN + " --reason ';'",
            "bash -c \"" + PLAIN.replace('"', "'") + "\"",
            "cat <<'EOF'\n" + PLAIN + "\nEOF",
            "echo $(" + PLAIN + ")",
            "echo `" + PLAIN + "`",
        ]
        for command in forms:
            with self.subTest(command=command[:70]):
                self.decide_as(command, main=True)
                self.assertEqual(self.stamps(), [])
                self.assertEqual(self.record()[0], 3)

    def test_no_stamp_is_left_behind_by_a_command_the_cli_would_refuse(self):
        # red-team m-1: the CLI exits before it takes the stamp when a required option is missing or malformed.
        no_reason = ("python3 ~/.claude/hooks/merge_gate.py waive --repo o/r --pr 5 --head " + HEAD +
                     " --ticket 'GoodQA #14502'")
        upper = PLAIN.replace(HEAD, HEAD.upper())
        short = PLAIN.replace(HEAD, HEAD[:20])
        not_digit = PLAIN.replace("--pr 5", "--pr five")
        for label, command in (("no reason", no_reason), ("uppercase head", upper), ("short head", short),
                               ("pr not a number", not_digit)):
            with self.subTest(label):
                self.decide_as(command, main=True)
                self.assertEqual(self.stamps(), [])

    def test_the_hook_and_the_cli_read_the_arguments_identically_or_nothing_is_minted(self):
        # red-team r3 F1: each of these made the old hook stamp one key while argparse used another.
        other_head = "b" * 40
        other_state = tempfile.mkdtemp()
        cases = {
            "state-dir after the subcommand": PLAIN.replace("waive ", "waive --state-dir " + other_state + " ", 1),
            "state-dir equals form": PLAIN.replace("waive ", "waive --state-dir=" + other_state + " ", 1),
            "repeated repo": PLAIN + " --repo x/y",
            "repeated head": PLAIN + " --head " + other_head,
            "equals form overrides head": PLAIN + " --head=" + other_head,
            "equals form overrides ticket": PLAIN + " --ticket='GoodQA #1'",
            "abbreviated option": PLAIN.replace("--reason", "--reas"),
            "pr with a plus sign and a space": PLAIN.replace("--pr 5", "--pr ' +5'"),
            "unicode digit pr": PLAIN.replace("--pr 5", "--pr ٥"),
            "superscript pr": PLAIN.replace("--pr 5", "--pr ²"),
            "head with a trailing newline": PLAIN.replace("--head " + HEAD, "--head '" + HEAD + "\n'"),
            "head longer than 40 and not 64": PLAIN.replace(HEAD, HEAD + "ab"),
            "extra unknown option": PLAIN + " --force",
        }
        for label, command in cases.items():
            with self.subTest(label):
                for leftover in self.state.rglob("*.json"):
                    leftover.unlink()
                self.decide_as(command, main=True)
                self.assertEqual(self.stamps(), [])

    def test_a_state_dir_equal_to_the_hooks_own_still_mints(self):
        command = PLAIN.replace("waive ", "waive --state-dir " + str(self.state) + " ", 1)
        self.decide_as(command, main=True)
        self.assertEqual(len(self.stamps()), 1)
        self.assertEqual(self.record()[0], 0)

    def test_a_sixty_four_hex_head_still_mints(self):
        long_head = "a" * 64
        self.decide_as(PLAIN.replace(HEAD, long_head), main=True)
        self.assertEqual(len(self.stamps()), 1)

    def test_a_codex_child_payload_is_refused_by_the_real_root_check(self):
        # red-team r3 F4: nothing mocked except main (false): a Codex child payload through the real
        # native_main.is_desktop_review_root must not be proof.
        child = bash(PLAIN, session_id="01a1c3fd-aaaa-bbbb-cccc-000000000000", parent_thread_id="01a1c3fd-0000-0000-0000-000000000001",
                     agent_type="worker")
        self.assertIs(native_main.is_desktop_review_root(child), False)
        self.assertFalse(mg._may_record_waiver(child))
        with mock.patch.object(caller_identity, "is_main", return_value=False):
            code, text = mg.decide(child, FakeGh(SCENARIOS["green"]), self.state)
        self.assertEqual(code, 2, text)
        self.assertEqual(self.stamps(), [])

    def test_the_documented_isolated_python_form_mints(self):
        for command in (PLAIN.replace("python3 ", "python3 -I ", 1), PLAIN.replace("python3 ", "python3 -I -B ", 1),
                        PLAIN.replace("python3 ", "python3.12 ", 1)):
            with self.subTest(command=command[:40]):
                self.decide_as(command, main=True)
                self.assertEqual(len(self.stamps()), 1)
                self.record()

    def test_other_programs_subcommands_and_unbalanced_quotes_mint_nothing(self):
        for command in (PLAIN.replace("merge_gate.py", "other.py"),
                        # the program is not merge_gate.py although the words merge_gate and waive follow each other
                        PLAIN.replace("~/.claude/hooks/merge_gate.py waive", "/tmp/x.py merge_gate waive"),
                        PLAIN.replace("~/.claude/hooks/merge_gate.py waive", "/tmp/x.py waive") + " merge_gate waive",
                        # an option before the subcommand is not the documented one-command form
                        PLAIN.replace("merge_gate.py waive", "merge_gate.py --state-dir /tmp/s waive"),
                        PLAIN.replace("merge_gate.py waive", "merge_gate.py report waive"),
                        PLAIN + " 'unbalanced",
                        PLAIN.replace("python3 ", "node ", 1)):
            with self.subTest(command=command[:50]):
                self.decide_as(command, main=True)
                self.assertEqual(self.stamps(), [])

    def test_an_error_while_deciding_main_is_not_proof(self):
        with mock.patch.object(caller_identity, "is_main", side_effect=RuntimeError("boom")):
            code, text = mg.decide(bash(PLAIN), FakeGh(SCENARIOS["green"]), self.state)
        self.assertEqual(code, 2, text)
        self.assertEqual(self.stamps(), [])

    def test_the_stamp_covers_only_the_exact_repo_pr_head_and_ticket_typed(self):
        self.decide_as(PLAIN, main=True)
        out, err = io.StringIO(), io.StringIO()
        other = ["waive", "--state-dir", str(self.state), "--repo", "o/r", "--pr", "6", "--head", HEAD, "--ticket",
                 TICKET, "--reason", REASON]
        self.assertEqual(mg.main(other, runner=FakeGh(SCENARIOS["green"]), stdout=out, stderr=err), 3)

    def test_the_stamp_is_single_use(self):
        self.decide_as(PLAIN, main=True)
        self.assertEqual(self.record()[0], 0)
        self.assertEqual(self.record()[0], 3)

    def test_a_non_main_payload_that_does_not_mention_the_waiver_command_is_untouched(self):
        for command in ("gh pr view 5", "git status", "python3 -m unittest tests.test_x", "echo hello"):
            with self.subTest(command=command):
                code, text = self.decide_as(command, main=False)
                self.assertEqual(code, 0, text)

    def test_codex_shaped_payloads_are_not_main(self):
        # The real is_main, not a patch: a transcript path under ~/.codex, or a Codex thread marker, is never main.
        with tempfile.TemporaryDirectory() as home, mock.patch.dict(os.environ, {"HOME": home}):
            transcript = Path(home) / ".codex" / "sessions" / "t.jsonl"
            transcript.parent.mkdir(parents=True)
            transcript.write_text("{}\n")
            payload = bash(PLAIN, transcript_path=str(transcript), session_id="01a1c3fd-aaaa-bbbb-cccc-000000000000")
            code, text = mg.decide(payload, FakeGh(SCENARIOS["green"]), self.state)
            self.assertEqual(code, 2, text)
            self.assertEqual(self.stamps(), [])
            with mock.patch.dict(os.environ, {"CODEX_THREAD_ID": "t-1"}):
                code, text = mg.decide(bash(PLAIN), FakeGh(SCENARIOS["green"]), self.state)
                self.assertEqual(code, 2, text)
                self.assertEqual(self.stamps(), [])

    def test_real_main_proof_still_mints_for_a_plain_command(self):
        sid = "11111111-2222-3333-4444-555555555555"
        with tempfile.TemporaryDirectory() as home, mock.patch.dict(os.environ, {"HOME": home}, clear=False), \
                mock.patch.object(caller_identity, "native_deny_reason", return_value=None):
            os.environ.pop("CODEX_THREAD_ID", None)
            transcript = Path(home) / ".claude" / "projects" / "-x" / (sid + ".jsonl")
            transcript.parent.mkdir(parents=True)
            transcript.write_text("{}\n")
            payload = bash(PLAIN, session_id=sid, transcript_path=str(transcript))
            code, text = mg.decide(payload, FakeGh(SCENARIOS["green"]), self.state)
            self.assertEqual(code, 0, text)
            self.assertEqual(len(self.stamps()), 1)


if __name__ == "__main__":
    unittest.main()
