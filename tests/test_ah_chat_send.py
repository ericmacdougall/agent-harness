"""ah chat send (goodqa#16399): one short DM, main agent only, never retried.

The real `ah.py chat send` CLI runs as a subprocess against the loopback GoodQA stub of tests.test_ah_chat, with sentinel
tokens in a temporary HOME. The main-agent stamp is minted by the real mission_gate PreToolUse hook (cmd_pretool) from a
payload that caller_identity.is_main accepts (a transcript at <HOME>/.claude/projects/<p>/<session>.jsonl), exactly as Claude
Code would call it, or not minted for a sub-agent payload.

Run: python3 -I -m unittest tests.test_ah_chat_send
"""
import json
import os
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_ah_chat import (AH, CONV, DM_SENTINEL, HOOKS, ME, ORG, PEER, USER_SENTINEL, SCHEME, Base, ok,  # noqa: E402
                          tool_error)

sys.path.insert(0, str(HOOKS))
import ah_chat_send  # noqa: E402
import mission_gate  # noqa: E402

SESSION = "0b0b0b0b-1111-4222-8333-444455556666"
PREFIX = "Claude (Eric's bot). "
SENT = {"message": {"id": "77777777-7777-4777-8777-777777777777", "senderId": ME, "recipientId": PEER},
        "conversationId": CONV, "seq": 9}
DM_LIST = {"conversations": [{"id": CONV, "kind": "dm", "participants": [{"id": ME, "name": "Me"}, {"id": PEER, "name": "Pat"}]}],
           "hasMore": False}


class SendBase(Base):
    def setUp(self):
        super().setUp()
        self.stub.tools["send_direct_message"] = lambda a: ok(SENT)
        self.stub.tools["whoami"] = lambda a: ok({"user": {"id": ME, "name": "Me"}})
        self.stub.tools["list_direct_conversations"] = lambda a: ok(DM_LIST)
        proj = self.home / ".claude" / "projects" / "p"
        proj.mkdir(parents=True)
        self.transcript = proj / (SESSION + ".jsonl")
        self.transcript.write_text('{"type":"user"}\n')
        (self.home / ".claude" / "wals" / SESSION).mkdir(parents=True)
        self.text = self.home / "msg.txt"
        self.write("Thanks Tisha, the fix is on staging now.")
        self.calls = 0

    def write(self, text, path=None):
        (path or self.text).write_text(text + "\n")

    def argv(self, *extra, target=("--with", PEER)):
        return ["send", *target, "--org", ORG, "--text-file", str(self.text), *extra]

    def hook(self, argv, agent=None):
        """Run mission_gate's PreToolUse hook on the Bash line Claude Code would show it."""
        self.calls += 1
        line = " ".join(["python3", str(AH), "chat", *argv, "--base", self.stub.base])
        payload = {"tool_name": "Bash", "tool_input": {"command": line}, "session_id": SESSION,
                   "transcript_path": str(self.transcript), "tool_use_id": "toolu_%08d" % self.calls,
                   "hook_event_name": "PreToolUse"}
        if agent:
            payload.update(agent_id=agent, agent_type="task-owner")
        env = {"HOME": str(self.home), "AH_HOME": str(self.home), "CLAUDE_CONFIG_DIR": str(self.home / ".claude")}
        with mock.patch.dict(os.environ, env):
            mission_gate.cmd_pretool(payload)

    def send(self, *extra, target=("--with", PEER), agent=None, stamp=True):
        argv = self.argv(*extra, target=target)
        if stamp:
            self.hook(argv, agent=agent)
        return self.ah(*argv)

    def result(self, p):
        try:
            return json.loads(p.stdout)
        except ValueError:
            self.fail("stdout was not JSON: %r stderr=%r" % (p.stdout[:300], p.stderr[:300]))

    def sends(self):
        return self.stub.sent("send_direct_message")

    def wal_rows(self):
        path = self.home / ".claude" / "wals" / SESSION / "main.jsonl"
        return [json.loads(x) for x in path.read_text().splitlines()] if path.exists() else []


class MainAgentSends(SendBase):
    def test_main_sends_once_with_the_prefix_and_the_user_token_and_records_only_a_hash(self):
        p = self.send()
        data = self.result(p)
        self.assertEqual((data["ok"], data["status"], data["peer"]), (True, "sent", PEER), data)
        (name, args, auth), = self.sends()
        self.assertEqual(args, {"orgId": ORG, "userId": PEER, "body": PREFIX + "Thanks Tisha, the fix is on staging now."})
        self.assertEqual(auth, SCHEME + USER_SENTINEL)  # the user token sends; the dm-read token never does
        row, = [r for r in self.wal_rows() if r["event"] == "chat_send"]
        self.assertEqual((row["peer"], row["status"], row["text_sha256"]), (PEER, "sent", data["text_sha256"]))
        for path in self.home.rglob("*"):  # the text is in no file the command wrote: WAL, ledger, audit
            if path.is_file() and path != self.text and path not in self.token_files:
                self.assertNotIn("staging now", path.read_text(errors="replace"), str(path))
        self.assert_no_token(p)

    def test_the_prefix_is_one_constant(self):
        self.assertEqual(ah_chat_send.PREFIX, PREFIX)

    def test_dry_run_prints_the_exact_body_and_reads_no_token(self):
        self.user_file.chmod(0o644)  # a token read would now be refused: the dry run must not read one
        self.dm_file.chmod(0o644)
        p = self.ah(*self.argv("--dry-run"))
        data = self.result(p)
        self.assertEqual((data["ok"], data["dry_run"], data["body"]), (True, True, PREFIX + "Thanks Tisha, the fix is on staging now."))
        self.assertEqual(self.stub.hits, [])
        self.assertFalse((self.home / ".agent-harness" / "state" / "ah" / "store" / "chat-send.jsonl").exists())

    def test_conversation_resolves_to_the_one_other_person(self):
        data = self.result(self.send(target=("--conversation", CONV)))
        self.assertEqual((data["status"], data["peer"], data["sent_conversation"]), ("sent", PEER, CONV), data)
        self.assertEqual(self.sends()[0][1]["userId"], PEER)
        dm_calls = [c for c in self.stub.calls if c[0] == "list_direct_conversations"]
        self.assertTrue(dm_calls and all(c[2] == SCHEME + DM_SENTINEL for c in dm_calls))

    def test_a_group_dm_is_refused(self):
        group = dict(DM_LIST["conversations"][0], kind="group_dm",
                     participants=DM_LIST["conversations"][0]["participants"] + [{"id": CONV, "name": "Third"}])
        self.stub.tools["list_direct_conversations"] = lambda a: ok({"conversations": [group]})
        p = self.send(target=("--conversation", CONV))
        self.assertEqual(self.result(p)["code"], "refused")
        self.assertEqual(self.sends(), [])


class MainOnly(SendBase):
    def test_a_subagent_gets_no_stamp_and_sends_nothing(self):
        p = self.send(agent="a1234567890abcdef")
        self.assertEqual(self.result(p)["code"], "main_only")
        self.assertEqual(self.stub.hits, [])
        self.assert_no_token(p)

    def test_without_the_hook_nobody_sends(self):
        p = self.send(stamp=False)
        self.assertEqual(self.result(p)["code"], "main_only")
        self.assertEqual(self.stub.hits, [])

    def test_a_replay_of_the_same_process_finds_no_stamp(self):
        argv = self.argv()
        self.hook(argv)
        self.assertEqual(self.result(self.ah(*argv))["status"], "sent")
        p = self.ah(*argv)  # the same command again with no new hook call: the stamp was single use
        self.assertEqual(self.result(p)["code"], "main_only")
        self.assertEqual(len(self.sends()), 1)

    def test_a_text_file_edited_after_the_hook_ran_finds_no_stamp(self):
        argv = self.argv()
        self.hook(argv)
        self.write("Something the hook never saw.")
        p = self.ah(*argv)
        self.assertEqual(self.result(p)["code"], "main_only")
        self.assertEqual(self.sends(), [])

    def test_a_stamp_for_another_person_does_not_cover_this_one(self):
        self.hook(self.argv(target=("--with", "Pat Peer")))
        p = self.ah(*self.argv())
        self.assertEqual(self.result(p)["code"], "main_only")

    def test_echoed_text_and_dry_run_mint_nothing(self):
        line = "echo python3 %s chat send --with %s --org %s --text-file %s" % (AH, PEER, ORG, self.text)
        self.assertEqual(mission_gate.chat_send_stamps(line), [])
        self.assertEqual(mission_gate.chat_send_stamps(" ".join(["python3", str(AH), "chat", *self.argv("--dry-run")])), [])
        self.assertEqual(len(mission_gate.chat_send_stamps(" ".join(["python3", str(AH), "chat", *self.argv()]))), 1)


class Refusals(SendBase):
    def test_over_600_characters_is_refused_and_600_is_accepted(self):
        self.write("x" * 601)
        p = self.send()
        data = self.result(p)
        self.assertEqual(data["code"], "too_long")
        self.assertIn("600", data["message"])
        self.assertEqual(self.stub.hits, [])
        self.write("x" * 600)
        self.assertEqual(self.result(self.send())["status"], "sent")

    def test_an_unlisted_base_is_refused_before_anything_is_read(self):
        argv = self.argv()
        self.hook(argv)
        p = self.ah(*argv, base="https://goodqa.example.test/v1")
        self.assertEqual(self.result(p)["code"], "refused")
        self.assertEqual(self.stub.hits, [])
        self.assert_no_token(p)

    def test_a_secret_shape_or_a_token_piece_is_never_sent(self):
        for text in ("my key is sk-ant-api03-" + "a" * 40, "token " + USER_SENTINEL[3:20], "dm " + DM_SENTINEL):
            self.write(text)
            p = self.send()
            self.assertEqual(self.result(p)["code"], "secret_refused", text[:12])
            self.text.unlink()  # the test's own input holds the sentinel; every file the command wrote must not
            self.assert_no_token(p)
        self.assertEqual(self.sends(), [])

    def test_a_relative_path_a_symlink_and_control_characters_are_refused(self):
        p = self.ah("send", "--with", PEER, "--org", ORG, "--text-file", "msg.txt")
        self.assertEqual(self.result(p)["code"], "bad_request")
        link = self.home / "link.txt"
        link.symlink_to(self.text)
        p = self.ah("send", "--with", PEER, "--org", ORG, "--text-file", str(link))
        self.assertEqual(self.result(p)["code"], "bad_request")
        self.write("bell \x07 here")
        self.assertEqual(self.result(self.send())["code"], "bad_request")
        self.assertEqual(self.sends(), [])


class NoRetry(SendBase):
    def test_the_same_text_is_refused_after_a_send(self):
        self.assertEqual(self.result(self.send())["status"], "sent")
        p = self.send()
        self.assertEqual(self.result(p)["code"], "duplicate")
        self.assertEqual(len(self.sends()), 1)

    def test_a_lost_answer_is_uncertain_and_the_same_text_is_never_resent(self):
        self.stub.tools["send_direct_message"] = lambda a: "drop"
        data = self.result(self.send())
        self.assertEqual((data["ok"], data["status"]), (False, "uncertain"))
        self.assertIn("Do NOT resend", data["next"])
        self.stub.tools["send_direct_message"] = lambda a: ok(SENT)
        self.assertEqual(self.result(self.send())["code"], "duplicate")
        self.assertEqual(len(self.sends()), 1)

    def test_any_other_refusal_code_is_uncertain_too(self):
        self.stub.tools["send_direct_message"] = lambda a: tool_error("validation_error")
        self.assertEqual(self.result(self.send())["status"], "uncertain")
        self.assertEqual(self.result(self.send())["code"], "duplicate")

    def test_approval_required_is_the_one_outcome_that_allows_the_same_text_again(self):
        self.stub.tools["send_direct_message"] = lambda a: tool_error("human_approval_required")
        self.assertEqual(self.result(self.send())["status"], "approval_required")
        self.stub.tools["send_direct_message"] = lambda a: ok(SENT)
        self.assertEqual(self.result(self.send())["status"], "sent")
        self.assertEqual(self.result(self.send())["code"], "duplicate")

    def test_at_most_six_per_person_per_hour(self):
        for n in range(6):
            self.write("message number %d" % n)
            self.assertEqual(self.result(self.send())["status"], "sent", n)
        self.write("message number 7")
        self.assertEqual(self.result(self.send())["code"], "rate_limited")
        self.assertEqual(len(self.sends()), 6)

    def test_a_damaged_ledger_refuses_every_send(self):
        ledger = self.home / ".agent-harness" / "state" / "ah" / "store" / "chat-send.jsonl"
        ledger.parent.mkdir(parents=True, exist_ok=True)
        for damage in ('{"id": "x", "kind": "pending"', "not json\n"):
            ledger.write_text(damage)
            self.assertEqual(self.result(self.send())["code"], "ledger_damaged", damage)
        self.assertEqual(self.sends(), [])

    def test_a_crash_after_the_pending_row_still_blocks_the_same_text(self):
        rows = ah_chat_send._rows  # the pending row is all that a crash between the request and the outcome leaves
        self.assertEqual(rows(self.home / "missing.jsonl"), [])
        ledger = self.home / ".agent-harness" / "state" / "ah" / "store" / "chat-send.jsonl"
        ledger.parent.mkdir(parents=True, exist_ok=True)
        import hashlib
        digest = hashlib.sha256(self.text.read_bytes()).hexdigest()
        import time
        ledger.write_text(json.dumps({"id": "a" * 32, "kind": "pending", "peer": PEER, "sha": digest, "at": time.time()}) + "\n")
        self.assertEqual(self.result(self.send())["code"], "duplicate")
        self.assertEqual(self.sends(), [])


if __name__ == "__main__":
    unittest.main()
