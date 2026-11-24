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
                          ok_bare, tool_error)

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

    def test_a_group_dm_down_to_two_members_is_still_refused(self):
        group = dict(DM_LIST["conversations"][0], kind="group_dm")  # the third member left; it is still a group conversation
        self.stub.tools["list_direct_conversations"] = lambda a: ok({"conversations": [group]})
        data = self.result(self.send(target=("--conversation", CONV)))
        self.assertEqual(data["code"], "refused")
        self.assertIn("one-to-one", data["message"])
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

    def test_a_stamp_of_a_call_that_already_ended_is_dead(self):
        """The hook ran, but Claude Code already recorded that call's result (the call was denied, or it ended): a later
        process with the same argv is not that call and finds no live stamp."""
        argv = self.argv()
        self.hook(argv)
        with self.transcript.open("a") as out:
            out.write(json.dumps({"type": "user", "message": {"content": [
                {"type": "tool_result", "tool_use_id": "toolu_%08d" % self.calls, "content": "denied"}]}}) + "\n")
        p = self.ah(*argv)
        self.assertEqual(self.result(p)["code"], "main_only")
        self.assertEqual(self.sends(), [])

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

    def test_the_base_is_refused_before_the_text_file_is_even_looked_at(self):
        p = self.ah("send", "--with", PEER, "--org", ORG, "--text-file", "msg.txt", base="https://goodqa.example.test/v1")
        self.assertEqual(self.result(p)["code"], "refused")  # the base refusal, not the text file's bad_request
        self.assertEqual(self.stub.hits, [])

    def test_a_relative_path_is_refused_even_when_it_names_a_real_file(self):
        cwd = os.getcwd()
        os.chdir(str(self.home))
        self.addCleanup(os.chdir, cwd)
        self.assertTrue(Path("msg.txt").is_file())
        with self.assertRaises(ah_chat_send.ChatError) as caught:
            ah_chat_send.read_text("msg.txt")
        self.assertEqual(caught.exception.code, "bad_request")
        self.assertEqual(ah_chat_send.read_text(str(self.text))[0], "Thanks Tisha, the fix is on staging now.")

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
        # an unfinished record that happens to be valid JSON (the write stopped before its line break), a torn record and
        # a malformed one: each refuses every send
        for damage in ('{"id": "x", "kind": "pending"}', '{"id": "x", "kind": "pending"', "not json\n"):
            ledger.write_text(damage)
            self.assertEqual(self.result(self.send())["code"], "ledger_damaged", damage)
        self.assertEqual(self.sends(), [])

    def test_a_timeout_is_uncertain_is_never_retried_and_holds_the_text_back(self):
        """The server stores the message but answers after the client gave up (20 s): one request, status uncertain, and the
        same text refused afterwards even though the server now answers at once."""
        import time as _time

        def slow(a):
            _time.sleep(ah_chat_send.chat.Client.__init__.__defaults__[1] + 4)
            return ok_bare(SENT)
        self.stub.tools["send_direct_message"] = slow
        data = self.result(self.send())
        self.assertEqual((data["ok"], data["status"]), (False, "uncertain"), data)
        self.assertEqual(len(self.sends()), 1)  # the one request; nothing was sent again after the timeout
        self.stub.tools["send_direct_message"] = lambda a: ok_bare(SENT)
        self.assertEqual(self.result(self.send())["code"], "duplicate")
        self.assertEqual(len(self.sends()), 1)
        self.assert_no_token()

    def test_the_same_text_window_is_24_hours_whatever_the_outcome(self):
        for status in ("sent", "uncertain", "pending"):
            rows = [{"id": "a", "kind": "pending", "peer": PEER, "sha": "d", "at": 1000.0}]
            if status != "pending":
                rows.append({"id": "b", "kind": "outcome", "ref": "a", "status": status})
            with self.assertRaises(ah_chat_send.ChatError, msg=status):
                ah_chat_send.check_ledger(rows, PEER, "d", 1000.0 + 86400 - 1)
            ah_chat_send.check_ledger(rows, PEER, "d", 1000.0 + 86400 + 1)  # a day later it may go again
            ah_chat_send.check_ledger(rows, PEER, "other text", 1000.0 + 1)  # other text, or another person, is not held
            ah_chat_send.check_ledger(rows, "someone-else", "d", 1000.0 + 1)


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


class Approval(SendBase):
    APPROVAL = "88888888-8888-4888-8888-888888888888"

    def gate(self, code):
        return lambda a: (200, {"jsonrpc": "2.0", "id": 1, "result": {"isError": True, "content": [{"type": "text", "text": json.dumps(
            {"error": {"code": code, "message": "needs approval", "details": {"approvalId": self.APPROVAL}}})}]}})

    def test_approval_required_prints_the_id_and_the_approved_send_carries_it(self):
        self.stub.tools["send_direct_message"] = self.gate("human_approval_required")
        data = self.result(self.send())
        self.assertEqual((data["status"], data["approval_id"]), ("approval_required", self.APPROVAL), data)
        self.assertIn("--approval-id " + self.APPROVAL, data["next"])
        self.stub.tools["send_direct_message"] = self.gate("human_approval_pending")  # not approved yet: nothing stored
        self.assertEqual(self.result(self.send("--approval-id", self.APPROVAL))["status"], "approval_pending")
        self.stub.tools["send_direct_message"] = lambda a: ok_bare(SENT)
        data = self.result(self.send("--approval-id", self.APPROVAL))
        self.assertEqual(data["status"], "sent", data)
        bodies = [c[1] for c in self.sends()]
        self.assertEqual([b.get("approvalId") for b in bodies], [None, self.APPROVAL, self.APPROVAL])
        self.assertEqual(len({b["body"] for b in bodies}), 1)  # the permit is bound to the exact body: it never changes
        self.assertEqual(self.result(self.send("--approval-id", self.APPROVAL))["code"], "duplicate")

    def test_a_refused_approval_frees_the_text_but_any_other_refusal_does_not(self):
        for code in ("approval_expired", "approval_denied", "approval_mismatch"):
            self.stub.tools["send_direct_message"] = self.gate(code)
            self.assertEqual(self.result(self.send())["status"], "approval_refused", code)
        self.stub.tools["send_direct_message"] = self.gate("forbidden")
        self.assertEqual(self.result(self.send())["status"], "uncertain")
        self.assertEqual(self.result(self.send())["code"], "duplicate")

    def test_a_stamp_without_the_approval_id_does_not_cover_a_send_with_it(self):
        self.hook(self.argv())
        p = self.ah(*self.argv("--approval-id", self.APPROVAL))
        self.assertEqual(self.result(p)["code"], "main_only")
        self.assertEqual(self.sends(), [])

    def test_a_malformed_approval_id_is_refused_before_anything_is_read(self):
        p = self.send("--approval-id", "not-an-id")
        self.assertEqual(self.result(p)["code"], "bad_request")
        self.assertEqual(self.stub.hits, [])


class OneRead(SendBase):
    def test_the_stamp_is_matched_against_the_text_that_is_sent(self):
        """A file swapped between the sender's read and a second read cannot pair the stamped text's stamp with another body:
        the sender matches the stamp against the digest of the one read whose text it sends."""
        argv = self.argv()
        self.hook(argv)  # stamped for the original text
        original = self.text.read_text()
        calls = []
        real = ah_chat_send.read_text

        def swapping(path):  # the first read sees other text; any later read would see the stamped text again
            calls.append(path)
            if len(calls) == 1:
                self.write("Text the hook never saw.")
                try:
                    return real(path)
                finally:
                    self.text.write_text(original)
            return real(path)
        with mock.patch.object(ah_chat_send, "read_text", swapping), \
                mock.patch.dict(os.environ, {"HOME": str(self.home), "AH_HOME": str(self.home), "GQ_BROWSER_TEST_LOOPBACK": "1"}):
            with self.assertRaises(ah_chat_send.ChatError) as caught:
                ah_chat_send.send(Path(str(self.home)), None, PEER, ORG, str(self.text), base=self.stub.base)
        self.assertEqual(caught.exception.code, "main_only")
        self.assertEqual(self.sends(), [])
        # the positive control on the same in-process path: no swap, the stamp is found and the stamped text is sent
        self.hook(argv)
        with mock.patch.dict(os.environ, {"HOME": str(self.home), "AH_HOME": str(self.home), "GQ_BROWSER_TEST_LOOPBACK": "1"}):
            data = ah_chat_send.send(Path(str(self.home)), None, PEER, ORG, str(self.text), base=self.stub.base)
        self.assertEqual(data["status"], "sent", data)
        self.assertEqual([c[1]["body"] for c in self.sends()], [PREFIX + original.rstrip("\n")])


if __name__ == "__main__":
    unittest.main()
