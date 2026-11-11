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
