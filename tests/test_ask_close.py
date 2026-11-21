"""goodqa#16599: answering an ask's question card closes the ask; nothing waits for an agent to remember.

Fixtures are synthetic: a transcript with an AskUserQuestion tool_use and its answer record, and WAL rows written the
way wal_note writes them. The c89a184a/76b72de0 shape (answer in session A, decisions in session B, reminder still due) is
`test_answer_in_a_closes_the_ask_even_if_a_stops_right_after`."""
import json
import os
import subprocess
import sys
import unittest
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import test_provenance as base  # noqa: E402
from test_provenance import HOOKS, HUMAN, QUOTE, SID  # noqa: E402

sys.path.insert(0, str(HOOKS))
import ask_reminders  # noqa: E402

USE = "toolu_ASKCARD"
ANSWER = str(uuid.UUID(int=500))
OTHER = "99999999-8888-7777-6666-555555555555"
FIXED = "w0aaaaaaaaa1"   # an id that exists in two sessions at once (NEG-2)


def row(**fields):
    return json.dumps(dict({"at": "2026-11-21T10:00:00+00:00"}, **fields), separators=(",", ":")) + "\n"


class Cards(base.Env):
    def setUp(self):
        super().setUp()
        # the detached closer a test may start gives up after 2 s (the delayed-record test raises it)
        self.env = dict(os.environ, HOME=str(self.home), HARNESS_PROVENANCE_OFFLINE="1", HARNESS_ASK_CLOSE_WAIT="2")
        self.main = self.wals / "main.jsonl"
        self.main.write_text(row(event="status", note="start"))

    # -- fixtures
    def ask(self, ident, wal=None, note="Which option for the staging rollout"):
        with open(wal or self.main, "a") as handle:
            handle.write(row(event="ask", id=ident, note=note, reason="needs the user to decide", source=self.user(HUMAN, QUOTE)))

    def card(self, answers, use=USE, uid=ANSWER, error=False, extra_questions=()):
        """Transcript: the user's lines, the assistant's AskUserQuestion tool_use, then its answer record."""
        questions = [{"question": q, "header": "h", "options": [], "multiSelect": False} for q in list(answers) + list(extra_questions)]
        asked = {"type": "assistant", "uuid": str(uuid.uuid4()), "message": {"content": [
            {"type": "tool_use", "id": use, "name": "AskUserQuestion", "input": {"questions": questions}}]}}
        result = {"type": "user", "uuid": uid, "timestamp": "2026-11-21T10:05:00Z",
                  "toolUseResult": {"questions": questions, "answers": answers},
                  "message": {"role": "user", "content": [dict({"type": "tool_result", "tool_use_id": use,
                                                                 "content": "answered"}, **({"is_error": True} if error else {}))]}}
        self.write_transcript(base.transcript_lines() + [asked, result])

    def hook(self, name, payload):
        run = subprocess.run([sys.executable, str(HOOKS / "provenance_hooks.py"), name], input=json.dumps(payload),
                             capture_output=True, text=True, env=self.env)
        self.assertEqual(run.returncode, 0, run.stderr)
        return json.loads(run.stdout) if run.stdout.strip() else {}

    def close_hook(self, session=SID):
        return self.hook("ask-close", {"session_id": session, "tool_name": "AskUserQuestion", "tool_use_id": USE})

    def rows(self, wal=None):
        return [json.loads(line) for line in (wal or self.main).read_text().splitlines()]

    def open_ids(self, wal=None):
        rows = self.rows(wal)   # independent of the code under test: an ask row with no ask_resolved row naming it
        return {r["id"] for r in rows if r.get("event") == "ask"} - {r["ref"] for r in rows if r.get("event") == "ask_resolved"}

    def wal_note(self, *args, wal=None):
        return subprocess.run([sys.executable, str(HOOKS / "wal_note.py"), "--wal", str(wal or self.main), *args],
                              capture_output=True, text=True, env=self.env)

    # -- AC-1
    def test_answer_closes_the_ask_named_in_the_card(self):
        self.ask("w00000000001")
        self.card({"Pick the rollout [ask:w00000000001]": "Ship it on Friday afternoon"})
        out = self.close_hook()
        self.assertEqual(self.open_ids(), set())
        closing = [r for r in self.rows() if r.get("event") == "ask_resolved"]
        self.assertEqual(len(closing), 1)
        self.assertEqual(closing[0]["ref"], "w00000000001")
        self.assertTrue(closing[0]["source"].startswith(f"answer:{SID}/{ANSWER}"))
        self.assertEqual(closing[0]["by"], "ask-close")
        self.assertNotIn("decision", closing[0])        # escalation.py reads this field as an approval: never set from a card
        self.assertIn("closed [ask:w00000000001]", out["hookSpecificOutput"]["additionalContext"])
        self.assertEqual(ask_reminders.open_asks(self.main, lambda v: 1.0), [])   # the reminder list is empty

    def test_answer_in_a_closes_the_ask_even_if_a_stops_right_after(self):
        """The 2026-11-21 shape: four asks on one card, the session stops, a successor writes decision rows in its own WAL."""
        ids = ["w00000000001", "w00000000002", "w00000000003", "w00000000004"]
        for ident in ids:
            self.ask(ident)
        self.card({"One card, four questions [ask:%s] [ask:%s] [ask:%s] [ask:%s]" % tuple(ids): "Option B for all four"})
        self.close_hook()
        successor = self.home / ".claude" / "wals" / OTHER
        successor.mkdir()
        (successor / "main.jsonl").write_text(row(event="decision", note="recorded the answer", source="answer:x/y"))
        self.assertEqual(self.open_ids(), set())
        self.assertEqual(ask_reminders.open_asks(self.main, lambda v: 1.0), [])

    def test_stop_lint_closes_an_answer_the_post_hook_could_not_see(self):
        self.ask("w00000000001")
        self.card({"Pick [ask:w00000000001]": "Ship it on Friday afternoon"})
        self.assertEqual(self.open_ids(), {"w00000000001"})
        self.hook("stop-lint", {"session_id": SID, "last_assistant_message": "Nothing needs you."})
        self.assertEqual(self.open_ids(), set())

    def test_ask_in_an_owner_wal_is_closed_from_main_and_the_owner_wal_is_untouched(self):
        owner = self.wals / "agent-abc.jsonl"
        self.ask("w00000000001", wal=owner)
        before = owner.read_bytes()
        self.card({"Pick [ask:w00000000001]": "Ship it on Friday afternoon"})
        self.close_hook()
        closing = [r for r in self.rows(self.main) if r.get("event") == "ask_resolved"]
        self.assertEqual([(r["ref"], r["ask_wal"]) for r in closing], [("w00000000001", "agent-abc")])
        self.assertEqual(owner.read_bytes(), before)          # liveness reads owner WALs: nothing is added there
        import provenance
        records, _ = provenance.ledger_read(SID, self.home / ".claude")
        self.assertEqual([r for r in records if r.get("_closed") is None], [])   # the session ledger reads it closed
        import ah
        self.assertEqual(ah.ask_states(self.main)["w00000000001"], "resolved")
        run = subprocess.run([sys.executable, str(HOOKS / "wal.py"), "session"], capture_output=True, text=True, env=self.env,
                             input=json.dumps({"session_id": SID, "source": "resume"}))
        self.assertNotIn("w00000000001", json.loads(run.stdout)["hookSpecificOutput"]["additionalContext"])

    def test_hook_returns_before_the_answer_is_written_and_a_detached_closer_closes_it_later(self):
        """PostToolUse runs before Claude Code writes the tool_result record, and the session may stop right after."""
        import time
        self.ask("w00000000001")
        self.card({"Pick [ask:w00000000001]": "Ship it on Friday afternoon"}, use="toolu_LATER")
        lines = [json.loads(line) for line in self.transcript.read_text().splitlines()]
        answer = lines.pop()                                  # the transcript the hook sees has the tool_use, not its answer
        self.write_transcript(lines)
        self.env["HARNESS_ASK_CLOSE_WAIT"] = "40"
        started = time.monotonic()
        out = self.hook("ask-close", {"session_id": SID, "tool_name": "AskUserQuestion", "tool_use_id": "toolu_LATER"})
        self.assertEqual(out, {})
        self.assertLess(time.monotonic() - started, 5)         # the hook did not wait for the record
        self.assertEqual(self.open_ids(), {"w00000000001"})
        self.write_transcript(lines + [answer])                # Claude Code writes the record afterwards
        for _ in range(60):
            if not self.open_ids():
                break
            time.sleep(0.5)
        self.assertEqual(self.open_ids(), set())

    # -- the decision field: auto-close must not lock out an approval, nor fake one
    def test_auto_closed_ask_takes_one_typed_decision_and_escalation_reads_only_that(self):
        import escalation
        from unittest import mock
        patch = mock.patch.dict(os.environ, {"AGENT_HARNESS_WALS_DIR": str(self.home / ".claude" / "wals")})
        patch.start()
        self.addCleanup(patch.stop)
        self.ask("w00000000001", note="Approve top rung for [task:T1]")
        self.card({"Approve [ask:w00000000001]": "Ship it on Friday afternoon"})
        self.close_hook()
        with self.assertRaises(escalation.LedgerError) as raised:
            escalation.verify_ask_pair(self.main, "w00000000001", "T1", allow_env_root=True)
        self.assertIn("no decision=approved", str(raised.exception))     # the hook's row is never an approval
        src = f'answer:{SID}/{ANSWER} "Ship it on Friday afternoon"'
        plain = self.resolve("w00000000001", src)                         # no decision: refused, with the way forward
        self.assertEqual(plain.returncode, 2)
        self.assertIn("--decision", plain.stderr)
        done = self.resolve("w00000000001", src, "--decision", "approved")
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(self.rows()[-1]["supersedes"], [r for r in self.rows() if r.get("by") == "ask-close"][0]["id"])
        escalation.verify_ask_pair(self.main, "w00000000001", "T1", allow_env_root=True)   # passes now
        again = self.resolve("w00000000001", src, "--decision", "approved")                 # only one such follow-up
        self.assertEqual(again.returncode, 2)

    def test_ah_kill_refuses_an_auto_closed_ask_and_a_declined_one(self):
        import ah_kill

        class Stub:
            def __init__(self, resolved):
                self.resolved = resolved

            def ledger(self, session, claude):
                return [{"id": "w00000000001", "_closed": self.resolved}]
        with self.assertRaises(ah_kill.KillError) as raised:
            ah_kill.resolve_approval("w00000000001", SID, self.home, prov=Stub({"id": "w1", "source": "x", "by": "ask-close"}))
        self.assertIn("ask-close hook", str(raised.exception))
        with self.assertRaises(ah_kill.KillError) as raised:
            ah_kill.resolve_approval("w00000000001", SID, self.home, prov=Stub({"source": "x", "decision": "declined"}))
        self.assertIn("declined", str(raised.exception))

    # -- AC-4: the card must be the ask's own session's
    def test_an_answer_card_of_another_session_does_not_bind(self):
        import provenance
        self.card({"Pick [ask:w00000000001]": "Ship it on Friday afternoon"})
        src = f'answer:{SID}/{ANSWER} "Ship it on Friday afternoon"'
        self.assertIsNone(provenance.answer_names_ask(src, "w00000000001", session=SID))
        self.assertIn("belongs to session", provenance.answer_names_ask(src, "w00000000001", session=OTHER))

    # -- AC-2 across sessions: the successor's decision row cites the predecessor's answer
    def test_hint_finds_the_open_ask_in_the_session_the_source_names(self):
        self.ask("w00000000001")
        successor = self.home / ".claude" / "wals" / OTHER
        successor.mkdir()
        (successor / "main.jsonl").write_text(row(event="status", note="start"))
        done = self.wal_note("--event", "decision", "--note", "Recorded the answer to [ask:w00000000001]",
                             "--source", self.user(HUMAN, QUOTE), wal=successor / "main.jsonl")
        self.assertEqual(done.returncode, 0, done.stderr)
        hint = json.loads(done.stdout)["hint"]
        self.assertIn(f"--wal {self.main}", hint)          # the command targets the predecessor's WAL, not the successor's
        self.assertEqual(self.open_ids(), {"w00000000001"})

    def test_closing_twice_writes_one_row(self):
        self.ask("w00000000001")
        self.card({"Pick [ask:w00000000001]": "Ship it on Friday afternoon"})
        self.close_hook()
        self.close_hook()
        self.assertEqual(len([r for r in self.rows() if r.get("event") == "ask_resolved"]), 1)

    def test_only_the_answered_question_of_a_card_closes(self):
        self.ask("w00000000001")
        self.ask("w00000000002")
        self.card({"First [ask:w00000000001]": "Ship it on Friday afternoon", "Second [ask:w00000000002]": ""})
        self.close_hook()
        self.assertEqual(self.open_ids(), {"w00000000002"})

    def test_long_multi_question_answers_still_close(self):
        self.ask("w00000000001")
        self.ask("w00000000002")
        self.card({"First [ask:w00000000001]": "yes", "Second [ask:w00000000002]": "x" * 400})
        self.close_hook()
        self.assertEqual(self.open_ids(), {"w00000000001"})   # "yes" is too short to quote beside a 400 character answer: left open, said so

    # -- NEG-1
    def test_neg_dismissed_card_and_empty_other_do_not_close(self):
        self.ask("w00000000001")
        self.card({"Pick [ask:w00000000001]": "Ship it on Friday afternoon"}, error=True)   # dismissed / rejected
        self.close_hook()
        self.assertEqual(self.open_ids(), {"w00000000001"})
        self.card({"Pick [ask:w00000000001]": ""})                                           # "Other" with no text
        self.close_hook()
        self.assertEqual(self.open_ids(), {"w00000000001"})
        self.card({"Pick [ask:w00000000001]": "   "})
        self.close_hook()
        self.assertEqual(self.open_ids(), {"w00000000001"})

    def test_neg_another_tools_result_is_not_an_answer(self):
        self.ask("w00000000001")
        self.card({"Pick [ask:w00000000001]": "Ship it on Friday afternoon"}, use="toolu_OTHER")
        self.assertEqual(self.close_hook(), {})   # no answer record for this tool_use id (the poll gives up)
        self.assertEqual(self.open_ids(), {"w00000000001"})

    # -- NEG-2
    def test_neg_a_same_id_ask_of_another_session_stays_open(self):
        other = self.home / ".claude" / "wals" / OTHER / "main.jsonl"
        other.parent.mkdir()
        self.ask(FIXED, wal=other)
        self.ask(FIXED)
        self.card({"Pick [ask:%s]" % FIXED: "Ship it on Friday afternoon"})
        self.close_hook()
        self.assertEqual(self.open_ids(), set())
        self.assertEqual(self.open_ids(other), {FIXED})

    def test_neg_an_id_only_another_session_holds_closes_nothing(self):
        other = self.home / ".claude" / "wals" / OTHER / "main.jsonl"
        other.parent.mkdir()
        self.ask(FIXED, wal=other)
        self.card({"Pick [ask:%s]" % FIXED: "Ship it on Friday afternoon"})
        self.close_hook()
        self.assertEqual(self.open_ids(other), {FIXED})

    def test_policy_off_disables_the_hook(self):
        sandbox = self.sandbox(ask_close="off")
        self.ask("w00000000001")
        self.card({"Pick [ask:w00000000001]": "Ship it on Friday afternoon"})
        subprocess.run([sys.executable, str(sandbox / "provenance_hooks.py"), "ask-close"], capture_output=True, text=True, env=self.env,
                       input=json.dumps({"session_id": SID, "tool_name": "AskUserQuestion", "tool_use_id": USE}))
        self.assertEqual(self.open_ids(), {"w00000000001"})

    def test_installer_registers_the_post_tool_hook(self):
        import install
        groups = install.provenance_hook_groups(Path("/x/.claude"))["PostToolUse"]
        self.assertEqual(groups[0]["matcher"], "AskUserQuestion")
        self.assertEqual(groups[0]["hooks"][0]["args"][1], "ask-close")

    # -- AC-4
    def resolve(self, ref, source, *extra):
        return self.wal_note("--event", "ask_resolved", "--ref", ref, "--note", "answered", "--source", source, *extra)

    def test_answer_source_must_come_from_the_card_that_names_the_ask(self):
        self.ask("w00000000001")
        self.card({"A different question [ask:w00000000009]": "Ship it on Friday afternoon"})
        src = f'answer:{SID}/{ANSWER} "Ship it on Friday afternoon"'
        refused = self.resolve("w00000000001", src)
        self.assertEqual(refused.returncode, 2, refused.stdout + refused.stderr)
        self.assertIn("does not name [ask:w00000000001]", refused.stderr)
        self.assertIn("--unbound-reason", refused.stderr)
        self.assertEqual(self.open_ids(), {"w00000000001"})

    def test_answer_source_from_the_named_card_closes(self):
        self.ask("w00000000001")
        self.card({"Pick [ask:w00000000001]": "Ship it on Friday afternoon"})
        done = self.resolve("w00000000001", f'answer:{SID}/{ANSWER} "Ship it on Friday afternoon"')
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertNotIn("answer_unbound", self.rows()[-1])

    def test_unbound_reason_is_the_audited_escape_for_a_free_text_answer(self):
        self.ask("w00000000001")
        self.card({"A different question [ask:w00000000009]": "Ship it on Friday afternoon"})
        src = f'answer:{SID}/{ANSWER} "Ship it on Friday afternoon"'
        short = self.resolve("w00000000001", src, "--unbound-reason", "because")
        self.assertEqual(short.returncode, 2)
        done = self.resolve("w00000000001", src, "--unbound-reason", "typed into Other on the next card, which covers this ask")
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn("typed into Other", self.rows()[-1]["answer_unbound"])
        self.assertEqual(self.open_ids(), set())

    def test_unbound_reason_is_for_ask_resolved_only(self):
        refused = self.wal_note("--event", "status", "--note", "x", "--unbound-reason", "a reason that is long enough")
        self.assertNotEqual(refused.returncode, 0)

    def test_a_typed_row_cannot_claim_to_be_the_hooks_row(self):
        self.ask("w00000000001")
        refused = self.resolve("w00000000001", self.user(HUMAN, QUOTE), "--by", "ask-close")
        self.assertNotEqual(refused.returncode, 0)
        self.assertEqual(self.open_ids(), {"w00000000001"})

    def test_a_typed_user_source_still_closes_without_a_card(self):
        self.ask("w00000000001")
        done = self.resolve("w00000000001", self.user(HUMAN, QUOTE))
        self.assertEqual(done.returncode, 0, done.stderr)

    # -- AC-2 and NEG-3
    def test_a_user_sourced_row_naming_an_open_ask_gets_the_close_command_and_never_closes_it(self):
        self.ask("w00000000001")
        src = self.user(HUMAN, QUOTE)
        done = self.wal_note("--event", "decision", "--note", "The user answered [ask:w00000000001]: go ahead", "--source", src)
        self.assertEqual(done.returncode, 0, done.stderr)
        hint = json.loads(done.stdout)["hint"]
        self.assertIn("--event ask_resolved --ref w00000000001", hint)
        self.assertIn("--source", hint)
        self.assertEqual(self.open_ids(), {"w00000000001"})      # NEG-3: a mention closes nothing
        bare = self.wal_note("--event", "status", "--note", "w00000000001 is answered by the user", "--source", src)
        self.assertIn("w00000000001", json.loads(bare.stdout)["hint"])

    def test_no_hint_for_a_closed_ask_an_unsourced_row_or_an_unrelated_note(self):
        self.ask("w00000000001")
        self.card({"Pick [ask:w00000000001]": "Ship it on Friday afternoon"})
        self.close_hook()
        src = self.user(HUMAN, QUOTE)
        for args in (("--event", "decision", "--note", "answered [ask:w00000000001]", "--source", src),
                     ("--event", "status", "--note", "nothing about asks here", "--source", src)):
            self.assertNotIn("hint", json.loads(self.wal_note(*args).stdout))
        self.ask("w00000000002")
        self.assertNotIn("hint", json.loads(self.wal_note("--event", "status", "--note", "see w00000000002").stdout))   # no answer source

    # -- AC-3 (same session: a resume or compaction keeps the session id)
    def test_session_start_lists_open_asks_with_the_close_command(self):
        self.ask("w00000000001")
        self.ask("w00000000002")
        self.card({"Pick [ask:w00000000002]": "Ship it on Friday afternoon"})
        self.close_hook()
        run = subprocess.run([sys.executable, str(HOOKS / "wal.py"), "session"], capture_output=True, text=True, env=self.env,
                             input=json.dumps({"session_id": SID, "source": "resume"}))
        self.assertEqual(run.returncode, 0, run.stderr)
        text = json.loads(run.stdout)["hookSpecificOutput"]["additionalContext"]
        self.assertIn("[ask:w00000000001]", text)
        self.assertNotIn("w00000000002", text)
        self.assertIn("--event ask_resolved --ref w00000000001", text)


if __name__ == "__main__":
    unittest.main()
