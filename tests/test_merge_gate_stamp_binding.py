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
        # python3.N mints only when this host can find it (rescue PR 207 M1: python3.99 left an orphan stamp), so the
        # python3.12 case pretends it is on PATH; python3 itself is the real lookup.
        real_which = mg.shutil.which
        found = lambda name, *a, **k: "/usr/bin/python3.12" if name == "python3.12" else real_which(name, *a, **k)  # noqa: E731
        for command in (PLAIN.replace("python3 ", "python3 -I ", 1), PLAIN.replace("python3 ", "python3 -I -B ", 1),
                        PLAIN.replace("python3 ", "python3.12 ", 1)):
            with self.subTest(command=command[:40]), mock.patch.object(mg.shutil, "which", side_effect=found):
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


class OrphanedStamps(Base):
    """Red-team PR 207 M1/L1 (rescue): the hook mints before the shell runs, so a command the shell runs differently,
    or not at all, must mint nothing. Each negative case here left a live stamp on 587627b."""

    decide_as = StampBinding.decide_as
    record = StampBinding.record
    stamps = StampBinding.stamps

    def assert_no_stamp(self, command, expect_code=None):
        for leftover in self.state.rglob("*.json"):
            leftover.unlink()
        code, text = self.decide_as(command, main=True)
        if expect_code is not None:
            self.assertEqual(code, expect_code, text)
        self.assertEqual(self.stamps(), [])
        return code, text

    def test_m1_shell_rewrites_mint_nothing(self):
        other_head = "b" * 40
        cases = {
            "comment hides the head": PLAIN.replace(" --head " + HEAD, "") + " --approved-by # --head " + HEAD,
            "brace expansion adds a second head": PLAIN + " --approved-by {main:x,--head=" + other_head + "}",
            "ANSI-C quoting": PLAIN + " --approved-by $'\\x2d\\x2dhead'",
            "carriage return inside a word": PLAIN.replace(" --head " + HEAD, " --head " + HEAD + "\r--approved-by\rx"),
            "zsh unmatched glob": PLAIN + " --approved-by x*zzqq",
            "question-mark glob": PLAIN + " --approved-by x?zzqq",
            "bracket glob": PLAIN + " --approved-by x[a]zzqq",
            "zsh equals expansion": PLAIN + " --approved-by =nosuchcmdzzqq",
            "tilde unknown user": PLAIN + " --approved-by ~nosuchuserzzqq",
            "dollar variable": PLAIN + " --approved-by main:$USER",
            "tab control character": PLAIN + "\t--approved-by x",
            "zsh glob qualifier parenthesis": PLAIN + " --approved-by x(N)",
        }
        for label, command in cases.items():
            with self.subTest(label):
                self.assert_no_stamp(command)

    def test_m1_wrong_program_mints_nothing(self):
        cases = {
            "missing script path": PLAIN.replace("~/.claude/hooks/merge_gate.py", "/nonexistent/dir/merge_gate.py"),
            "relative script path": PLAIN.replace("~/.claude/hooks/merge_gate.py", "merge_gate.py"),
            "missing interpreter": PLAIN.replace("python3 ", "python3.99 ", 1),
            "interpreter path that does not exist": PLAIN.replace("python3 ", "/nonexistent/bin/python3 ", 1),
        }
        for label, command in cases.items():
            with self.subTest(label):
                self.assert_no_stamp(command)

    def test_m1_a_command_the_hook_itself_blocks_mints_nothing(self):
        # The reason text reads as a merge to find_merges, so decide() blocks the command; it never runs.
        command = PLAIN.replace("'approved by main after review'", "'gh pr merge 7 -R o/r needs this'")
        self.assert_no_stamp(command, expect_code=2)

    def test_l1_help_flag_does_not_end_the_hook_and_mints_nothing(self):
        for flag in ("-h", "--help"):
            with self.subTest(flag):
                out = io.StringIO()
                with mock.patch("sys.stdout", out):
                    self.assert_no_stamp(PLAIN + " " + flag, expect_code=0)
                self.assertEqual(out.getvalue(), "")

    def test_the_documented_forms_still_mint(self):
        install = Path(os.path.expanduser("~")) / ".codex" / "agent-harness" / "merge_gate.py"
        for label, command in (("claude install", PLAIN),
                               ("literal home", PLAIN.replace("~/", os.path.expanduser("~") + "/", 1)),
                               ("codex install", PLAIN.replace("~/.claude/hooks/merge_gate.py", str(install))),
                               ("the running gate", PLAIN.replace("~/.claude/hooks/merge_gate.py", mg.__file__)),
                               ("quoted reason with glob characters",
                                PLAIN.replace("'approved by main after review'", "'ok? [x] {y} *z ~w =v #u (t)'"))):
            with self.subTest(label):
                for leftover in self.state.rglob("*.json"):
                    leftover.unlink()
                code, text = self.decide_as(command, main=True)
                self.assertEqual(code, 0, text)
                self.assertEqual(len(self.stamps()), 1)

    def test_an_absolute_interpreter_path_mints_only_when_it_is_an_executable_python(self):
        with tempfile.TemporaryDirectory() as folder:
            interpreter = Path(folder) / "python3.12"
            interpreter.write_text("#!/bin/sh\n")
            interpreter.chmod(0o700)
            code, text = self.decide_as(PLAIN.replace("python3 ", str(interpreter) + " ", 1), main=True)
            self.assertEqual(code, 0, text)
            self.assertEqual(len(self.stamps()), 1)
            interpreter.chmod(0o600)
            self.assert_no_stamp(PLAIN.replace("python3 ", str(interpreter) + " ", 1))

    def test_a_waive_stamp_lives_at_most_120_seconds(self):
        self.assertEqual(mg.STAMP_TTL_SECONDS, 120)
        import time as _time  # noqa: PLC0415
        for age, expected in ((60, 0), (300, 3)):
            with self.subTest(age=age):
                with mock.patch.object(caller_identity, "is_main", return_value=True):
                    mg.decide(bash(PLAIN), FakeGh(SCENARIOS["green"]), self.state, now=_time.time() - age)
                self.assertEqual(len(self.stamps()), 1)
                self.assertEqual(self.record()[0], expected)


if __name__ == "__main__":
    unittest.main()
