"""status_truth.py (GoodQA goodqa#15754, P0-2/P0-3): status questions get the goal ledger, compaction re-injects it,
and the Stop lint catches a goal-status answer that contradicts the ledger.

Evidence: main's 07:01:02Z answer on 2026-11-12 said prod move could not be called done, nobody worked on the leads and
self-update had no work, while the WALs held live proofs of all three; six Stop hooks passed it. On main 4f9f4a39
there is no status_truth.py, so every test here fails there (ImportError).
"""
import io
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
HOOKS = ROOT / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
import mission_coverage as mc  # noqa: E402
import status_truth as st  # noqa: E402

NOW = time.time()
SESSION = "11111111-2222-4333-8444-555555555555"
OTHER = "99999999-2222-4333-8444-555555555555"
RECALL = json.loads((ROOT / "tests" / "data" / "status_truth_recall.json").read_text())
WRONG = """Very little of the four goals is done by your standard (deployed and tested live).

**1. Prod move:** GoodQA is now deployed to the self-hosted production. I haven't re-checked this session whether every service has moved, so I can't call the move done.

**2. GoodQA lead finding, user tokens, self-update, 1000 leads:**
- **Self-update:** the harness tool that installs files on another machine (#15742) has its tests written. GoodQA's own self-update has had no work this stretch.
- **1000 leads in the CRM view: nobody is working on it right now.** It waits on the browser."""
RIGHT = """You're right, my last answer was wrong.

**1. Prod move: done.** dev2 was powered off on Nov 10, and every service checked healthy on t2 right after.

**2. GoodQA lead finding, user tokens, self-update, 1000 leads: mostly done, with one real gap.**
- **1000 leads: the count is met.** On Nov 9 the CRM had 1416 people, and the saved view showed 1415.
- **User tokens:** minting keys with a user token is built and tested. The refusal above is the part still open.
- **Self-update: done and tested live.** On Nov 9 the desktop app updated itself to 0.2.57."""


def iso(ts):
    return time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime(ts))


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name)
        env = mock.patch.dict(os.environ, {"AH_HOME": str(self.home), "HOME": str(self.home),
                                           "CLAUDE_CONFIG_DIR": str(self.home / ".claude")})
        env.start()
        self.addCleanup(env.stop)
        self.wal = self.home / ".claude" / "wals" / SESSION
        self.wal.mkdir(parents=True)
        (self.wal / "main.jsonl").write_text("")
        rows = [("w16dc0f5dd6b", "REALLY_TESTED dev2-powered-off: stopped; t2 healthy"),
                ("w53ff16565a1", "REALLY_TESTED crm-count-and-provenance: 1416 people, view 1415"),
                ("wa6c1d52d985", "REALLY_TESTED mini-self-update-0.2.57: updated itself")]
        with open(self.wal / "agent-aowner00000000001.jsonl", "w") as fh:
            for wid, note in rows:
                fh.write(json.dumps({"at": iso(NOW - 3 * 86400), "event": "check", "id": wid, "note": note}) + "\n")
        mode = mock.patch.object(st, "_policy_mode", return_value="enforce")
        mode.start()
        self.addCleanup(mode.stop)

    def seed(self):
        aliases = {"prod-move": ["prod move"], "leads": ["leads", "1000 leads", "crm"],
                   "self-update": ["self-update", "self update"], "user-tokens": ["user tokens", "user token"],
                   "harness-asks": ["harness asks"], "parentproof": ["parentproof"]}
        ev = {"prod-move": "w16dc0f5dd6b", "leads": "w53ff16565a1", "self-update": "wa6c1d52d985"}

        def change(doc):
            doc["mission_session"] = SESSION
            for gid, al in aliases.items():
                g = {"id": gid, "title": gid, "ticket": "", "priority": 3, "status": "imported", "aliases": al}
                if gid in ev:
                    g["evidence"] = [{"id": ev[gid], "session": SESSION, "wal": "agent-aowner00000000001.jsonl",
                                      "kind": "live_test", "at": iso(NOW), "by": "main"}]
                doc["goals"].append(g)
            return doc
        mc._mutate(self.home, "fixture", "*", change, {})

    def transcript(self, prompt, answer, tool_cmds=(), session=SESSION):
        path = self.home / ".claude" / "projects" / "p" / f"{session}.jsonl"
        path.parent.mkdir(parents=True, exist_ok=True)
        recs = [{"type": "user", "uuid": "u-prompt-1", "message": {"role": "user", "content": prompt}}]
        for c in tool_cmds:
            recs.append({"type": "assistant", "message": {"content": [{"type": "tool_use", "input": {"command": c}}]}})
        recs.append({"type": "assistant", "uuid": "a1", "message": {"content": [{"type": "text", "text": answer}]}})
        path.write_text("\n".join(json.dumps(r) for r in recs) + "\n")
        return str(path)

    def stop(self, prompt, answer, tool_cmds=(), session=SESSION, **extra):
        with mock.patch.object(st, "_read_tail", side_effect=lambda p: Path(p).read_bytes()):
            return st.cmd_stop(dict({"session_id": session, "transcript_path": self.transcript(prompt, answer,
                                                                                               tool_cmds, session),
                                     "hook_event_name": "Stop"}, **extra))


class Lint(Base):
    def test_wrong_answer_is_flagged_and_corrected_answer_is_not(self):
        self.seed()
        doc = st.goals_doc()
        wrong = st.classify(WRONG, doc)
        self.assertEqual({c["goal"] for c in wrong["contradictions"]}, {"prod-move", "leads", "self-update"})
        self.assertEqual(st.classify(RIGHT, doc)["contradictions"], [])

    def test_pre_registered_recall_set(self):
        self.seed()
        doc = st.goals_doc()
        caught = [line for line in RECALL["positive"] if st.classify(line, doc)["contradictions"]]
        self.assertGreaterEqual(len(caught), 11, set(RECALL["positive"]) - set(caught))
        flagged = [line for line in RECALL["clean"] if st.classify(line, doc)["contradictions"]]
        self.assertEqual(flagged, [])

    def test_stop_blocks_once_per_turn(self):
        self.seed()
        out = self.stop("whats left", WRONG)
        self.assertEqual(out.get("decision"), "block")
        self.assertIn("prod-move", out["reason"])
        again = self.stop("whats left", WRONG, stop_hook_active=True)
        self.assertNotEqual(again.get("decision"), "block")  # never twice in one turn

    def test_block_is_not_skipped_when_another_hook_blocked_first(self):
        self.seed()
        out = self.stop("whats left", WRONG, stop_hook_active=True)
        self.assertEqual(out.get("decision"), "block")  # own per-turn counter, not the shared flag

    def test_status_answer_without_ah_goals_is_flagged_unless_consulted(self):
        self.seed()
        out = self.stop("whats left", RIGHT)
        self.assertIn("`ah goals` was not run", out.get("reason", ""))
        self.assertEqual(self.stop("whats left", RIGHT, tool_cmds=["python3 ~/.claude/hooks/ah.py goals"]), {})

    def test_done_about_a_file_edit_is_not_flagged(self):
        self.seed()
        self.assertEqual(self.stop("fix the readme", "Done: I fixed the typo in README.md and the tests pass."), {})

    def test_other_session_is_out_of_scope(self):
        self.seed()
        self.assertEqual(self.stop("whats left", WRONG, session=OTHER), {})

    def test_user_pasted_status_text_is_not_linted(self):
        self.seed()
        self.assertEqual(self.stop("here is what I see:\n" + WRONG, "Thanks, noted the file path."), {})

    def test_missing_ledger_says_unknown_and_never_blocks(self):
        out = self.stop("whats left", WRONG)
        self.assertNotEqual(out.get("decision"), "block")
        self.assertIn("GOALS UNAVAILABLE", out.get("systemMessage", ""))

    def test_turn_id_comes_from_the_user_prompt_and_a_new_turn_resets_the_counter(self):
        import stop_blocks  # noqa: PLC0415
        self.assertTrue(stop_blocks.allow(SESSION, "u-prompt-1", "status_truth"))
        self.assertFalse(stop_blocks.allow(SESSION, "u-prompt-1", "status_truth"))
        self.assertTrue(stop_blocks.allow(SESSION, "u-prompt-2", "status_truth"))  # next user turn
        with mock.patch.object(st, "_read_tail", side_effect=lambda p: Path(p).read_bytes()):
            turn = st.current_turn({"session_id": SESSION, "transcript_path": self.transcript("whats left", WRONG)})
        self.assertEqual(turn["prompt_id"], "u-prompt-1")  # the user record's uuid, not the Stop payload

    # Spec delta C1: real record shapes from the incident transcript. The 06:59:45Z "whats left" was an attachment of
    # type queued_command with origin human; the turn also carried task-notification user records (origin
    # task-notification), which are not human prompts.
    def raw_transcript(self, recs):
        path = self.home / ".claude" / "projects" / "p" / f"{SESSION}.jsonl"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("\n".join(json.dumps(r) for r in recs) + "\n")
        return str(path)

    QUEUED = {"type": "attachment", "uuid": "att-1", "timestamp": iso(NOW),
              "attachment": {"type": "queued_command", "prompt": "whats left", "source_uuid": "src-whats-left",
                             "commandMode": "prompt", "origin": {"kind": "human"}, "humanTurn": True}}
    NOTE_USER = {"type": "user", "uuid": "u-note", "origin": {"kind": "task-notification", "producer": "session-task"},
                 "message": {"role": "user", "content": "<task-notification>\n<task-id>x</task-id>\n"
                                                        "<status>completed</status>\n</task-notification>"}}
    NOTE_QUEUED = {"type": "attachment", "uuid": "att-2",
                   "attachment": {"type": "queued_command", "prompt": "<task-notification>\n<status>completed</status>",
                                  "origin": {"kind": "task-notification", "producer": "session-task"}}}

    def answer(self, text, uuid="a9"):
        return {"type": "assistant", "uuid": uuid, "message": {"content": [{"type": "text", "text": text}]}}

    def stop_raw(self, recs):
        with mock.patch.object(st, "_read_tail", side_effect=lambda p: Path(p).read_bytes()):
            return st.cmd_stop({"session_id": SESSION, "transcript_path": self.raw_transcript(recs),
                                "hook_event_name": "Stop"})

    def test_queued_human_prompt_opens_the_turn_and_a_task_notification_does_not(self):
        self.seed()
        recs = [{"type": "user", "uuid": "u-old", "origin": {"kind": "human"},
                 "message": {"role": "user", "content": "fix the readme"}},
                self.QUEUED, self.NOTE_USER, self.answer(RIGHT)]
        out = self.stop_raw(recs)
        self.assertIn("`ah goals` was not run", out.get("reason", ""))  # asked: the queued prompt is the question
        with mock.patch.object(st, "_read_tail", side_effect=lambda p: Path(p).read_bytes()):
            turn = st.current_turn({"session_id": SESSION, "transcript_path": self.raw_transcript(recs)})
        self.assertEqual((turn["prompt"], turn["prompt_id"]), ("whats left", "src-whats-left"))

    def test_queued_status_question_with_absent_ledger_says_unavailable(self):
        out = self.stop_raw([self.QUEUED, self.NOTE_USER, self.answer(WRONG)])
        self.assertIn("GOALS UNAVAILABLE", out.get("systemMessage", ""))

    def test_queued_task_notification_is_not_a_human_prompt(self):
        self.seed()
        one_goal = "Self-update is not live yet, the installer still needs work."  # one goal: needs `asked`
        recs = [{"type": "user", "uuid": "u-old", "origin": {"kind": "human"},
                 "message": {"role": "user", "content": "fix the readme"}},
                self.NOTE_QUEUED, self.NOTE_USER, self.answer(one_goal)]
        with mock.patch.object(st, "_read_tail", side_effect=lambda p: Path(p).read_bytes()):
            turn = st.current_turn({"session_id": SESSION, "transcript_path": self.raw_transcript(recs)})
        self.assertEqual(turn["prompt"], "fix the readme")
        self.assertNotIn("was not run", self.stop_raw(recs).get("reason", ""))

    def test_calibrate_counts_the_skip_rule_with_the_contradictions(self):
        self.seed()
        two_goals = "Prod move and self-update both remain in progress; nothing more to report on the leads."
        path = self.raw_transcript([
            {"type": "user", "uuid": "u-old", "origin": {"kind": "human"}, "timestamp": iso(NOW),
             "message": {"role": "user", "content": "fix the readme"}},
            dict(self.answer(two_goals, "a-unasked"), timestamp=iso(NOW)),
            self.QUEUED, self.NOTE_USER, dict(self.answer(RIGHT, "a-asked"), timestamp=iso(NOW))])
        rows = {r["uuid"]: r for r in st.calibrate(path)}
        self.assertTrue(rows["a-unasked"]["skipped"] and rows["a-unasked"]["flagged"])  # states status, no ah goals
        self.assertFalse(rows["a-asked"]["skipped"])  # a status question gets the injection once installed
        bare = {r["uuid"]: r for r in st.calibrate(path, simulate_injection=False)}
        self.assertTrue(bare["a-asked"]["asked"] and bare["a-asked"]["skipped"])

    def test_off_mode_does_nothing(self):
        self.seed()
        with mock.patch.object(st, "_policy_mode", return_value="off"):
            self.assertEqual(self.stop("whats left", WRONG), {})


class Inject(Base):
    def ctx(self, out):
        return out["hookSpecificOutput"]["additionalContext"]

    def test_status_question_gets_goal_ids_without_note_text(self):
        self.seed()
        text = self.ctx(st.cmd_prompt({"session_id": SESSION, "prompt": "whats left"}))
        self.assertIn("w16dc0f5dd6b", text)
        self.assertIn("LIVE_TESTED", text)
        self.assertNotIn("t2 healthy", text)  # no agent-written note text
        self.assertLessEqual(len(text.encode()), 4096)

    def test_status_question_forms_and_non_questions(self):
        for q in ("whats left", "what's left?", "where are we", "status update please", "status", "how far are we"):
            self.assertTrue(st.is_status_question(q), q)
        for q in ("run `git status` and commit", "git status", "fix the status code in api.py",
                  "add a status field to the form"):
            self.assertFalse(st.is_status_question(q), q)

    def test_other_session_gets_nothing(self):
        self.seed()
        self.assertEqual(st.cmd_prompt({"session_id": OTHER, "prompt": "whats left"}), {})

    def test_missing_ledger_injects_unavailable(self):
        text = self.ctx(st.cmd_prompt({"session_id": SESSION, "prompt": "whats left"}))
        self.assertIn("GOALS UNAVAILABLE (absent)", text)

    def test_error_injects_unavailable(self):
        self.seed()
        with mock.patch.object(st, "goals_doc", side_effect=RuntimeError("boom")):
            text = self.ctx(st.cmd_prompt({"session_id": SESSION, "prompt": "whats left"}))
        self.assertIn("GOALS UNAVAILABLE (error RuntimeError)", text)

    def test_compact_start_reinjects_and_other_starts_do_not(self):
        self.seed()
        text = self.ctx(st.cmd_session_start({"session_id": SESSION, "source": "compact"}))
        self.assertIn("self-update", text)
        self.assertEqual(st.cmd_session_start({"session_id": SESSION, "source": "startup"}), {})

    def test_cli_fails_open_and_still_injects_on_crash(self):
        self.seed()
        out, err = io.StringIO(), io.StringIO()
        with mock.patch.object(sys, "stdin", io.StringIO(json.dumps({"session_id": SESSION, "prompt": "whats left"}))), \
                mock.patch.object(st, "_watchdog"), mock.patch.object(st, "cmd_prompt", side_effect=KeyError("x")), \
                mock.patch.object(sys, "stdout", out), mock.patch.object(sys, "stderr", err):
            import safe_input  # noqa: PLC0415
            with mock.patch.object(safe_input, "read_stdin_bounded",
                                   return_value=json.dumps({"session_id": SESSION, "prompt": "whats left"})):
                rc = st.main(["prompt"])
        self.assertEqual(rc, 0)
        self.assertIn("GOALS UNAVAILABLE (error KeyError)", out.getvalue())


if __name__ == "__main__":
    unittest.main()
