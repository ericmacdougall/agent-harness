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
from test_ah_chat import (AH, CONV, DM_SENTINEL, HOOKS, ME, ORG, OTHER, PEER, USER_SENTINEL, SCHEME, Base, ok,  # noqa: E402
                          ok_bare, tool_error)

sys.path.insert(0, str(HOOKS))
import ah_chat_send  # noqa: E402
import mission_gate  # noqa: E402

SESSION = "0b0b0b0b-1111-4222-8333-444455556666"
HEX_PEER = "abcdef01-2345-4abc-8def-0123456789ab"  # ids with letters, so a letter-case test can fail
HEX_ME = "fedcba98-7654-4fed-8cba-9876543210fe"
HEX_CONV = "c0ffee00-1234-4abc-8def-c0ffee001234"
USER_UUID = "9a9a9a9a-1111-4222-8333-444455556666"
WORDS = "pat peer runs the staging checks with sam.. communicate with pat via goodqa"
GOOD_SOURCE = 'user:%s/%s "communicate with pat via goodqa"' % (SESSION, USER_UUID)
SAM_SOURCE = 'user:%s/%s "staging checks with sam"' % (SESSION, USER_UUID)
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
        with self.transcript.open("a") as out:  # a real human turn naming Pat, which a decision row can cite
            out.write(json.dumps({"type": "user", "uuid": USER_UUID, "origin": {"kind": "human"},
                                  "timestamp": "2026-11-23T00:00:00Z",
                                  "message": {"role": "user", "content": WORDS}}) + "\n")
        self.stub.tools["list_org_members"] = lambda a: ok({"members": [
            {"userId": PEER, "name": "Pat Peer"}, {"userId": OTHER, "name": "Sam Other"},
            {"userId": HEX_PEER, "name": "Pat Hex"}]})
        self.allow_file = self.home / ".config" / "goodqa" / "chat-send-recipients"
        self.rows = 0
        self.allow_list("# people main may message\n" + self.entry(PEER) + self.entry(OTHER, name="Sam", source=SAM_SOURCE)
                        + self.entry(HEX_PEER))

    def allow_list(self, content, mode=0o600):
        self.allow_file.write_text(content)
        self.allow_file.chmod(mode)

    def entry(self, uid, source=GOOD_SOURCE, name="Pat", org=ORG, peer=None, line_id=None, **row):
        """One list line and its decision row in main's WAL, as `ah chat allow` writes them."""
        self.rows += 1
        wid = "w%011x" % self.rows
        record = dict({"id": wid, "event": "decision", "actor": "main", "choice": "add", "peer": (peer or uid).lower(),
                       "org": org, "name": name, "source": source, "at": "2026-11-23T00:00:00Z"}, **row)
        with (self.home / ".claude" / "wals" / SESSION / "main.jsonl").open("a") as out:
            out.write(json.dumps(record, separators=(",", ":")) + "\n")
        return "%s wal:%s/%s\n" % (uid, SESSION, line_id or wid)

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
        self.hook(self.argv(target=("--with", OTHER)))
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
        complete = '{"id": "x", "kind": "pending", "peer": "%s", "sha": "d", "at": 1.0}' % OTHER  # every field: only the
        for damage in (complete, '{"id": "x", "kind": "pending"', "not json\n"):  # missing line break makes it damage
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
        digest = hashlib.sha256((PREFIX + "Thanks Tisha, the fix is on staging now.").encode()).hexdigest()  # the body key
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


class CanonicalKey(SendBase):
    """PR 337 review F1, adversarial 1: ONE ledger key (_identity) for every representation of one message to one person."""

    def lost(self):
        self.stub.tools["send_direct_message"] = lambda a: "drop"
        self.assertEqual(self.result(self.send())["status"], "uncertain")
        self.stub.tools["send_direct_message"] = lambda a: ok_bare(SENT)

    def test_trailing_line_breaks_and_crlf_do_not_make_a_new_message(self):
        self.text.write_bytes(b"x\n")
        self.lost()
        for raw in (b"x", b"x\n\n", b"x\r\n", b"x\r\n\r\n"):
            self.text.write_bytes(raw)
            self.assertEqual(self.result(self.send())["code"], "duplicate", raw)
        self.assertEqual(len(self.sends()), 1)

    def test_inner_crlf_is_sent_as_lf_and_keys_the_same(self):
        self.text.write_bytes(b"one\r\ntwo\n")
        self.assertEqual(self.result(self.send())["status"], "sent")
        self.assertEqual(self.sends()[0][1]["body"], PREFIX + "one\ntwo")
        self.text.write_bytes(b"one\ntwo")
        self.assertEqual(self.result(self.send())["code"], "duplicate")

    def test_an_upper_case_id_is_the_same_person(self):
        self.stub.tools["send_direct_message"] = lambda a: "drop"
        self.assertEqual(self.result(self.send(target=("--with", HEX_PEER)))["status"], "uncertain")
        self.stub.tools["send_direct_message"] = lambda a: ok_bare(SENT)
        self.assertNotEqual(HEX_PEER.upper(), HEX_PEER)  # the ids hold letters, so this test is not vacuous
        self.assertEqual(self.result(self.send(target=("--with", HEX_PEER.upper())))["code"], "duplicate")
        self.assertEqual(len(self.sends()), 1)

    def test_conversation_and_with_are_the_same_person(self):
        self.lost()
        self.assertEqual(self.result(self.send(target=("--conversation", CONV)))["code"], "duplicate")
        self.assertEqual(len(self.sends()), 1)


class IdsOnly(SendBase):
    def test_a_name_is_refused_before_anything_is_read(self):
        p = self.send(target=("--with", "Pat Peer"))
        data = self.result(p)
        self.assertEqual(data["code"], "bad_request")
        self.assertIn("never a name", data["message"])
        self.assertEqual(self.stub.hits, [])

    def test_send_needs_an_explicit_org(self):
        argv = ["send", "--with", PEER, "--text-file", str(self.text)]
        self.hook(argv)
        data = self.result(self.ah(*argv))
        self.assertEqual(data["code"], "bad_request")
        self.assertIn("--org", data["message"])
        self.assertEqual(self.stub.hits, [])


class Participants(SendBase):
    """The server lists EVERY participant, the caller included, and appends an API-key persona with isBot (dms.ts:66,
    598-640 at a70289c7)."""

    def listing(self, participants, kind="dm"):
        row = dict(DM_LIST["conversations"][0], kind=kind, participants=participants)
        self.stub.tools["list_direct_conversations"] = lambda a: ok({"conversations": [row], "hasMore": False})

    def test_a_dm_row_with_three_people_or_without_the_caller_or_with_a_bot_is_refused(self):
        for people in ([{"id": ME}, {"id": PEER}, {"id": OTHER}], [{"id": PEER}, {"id": OTHER}], [{"id": PEER}],
                       [{"id": ME}, {"id": PEER, "isBot": True}], [{"id": ME}, {"id": ME}],
                       [{"id": ME}, {"id": ME}, {"id": PEER}]):
            self.listing(people)
            data = self.result(self.send(target=("--conversation", CONV)))
            self.assertEqual(data["code"], "refused", people)
        self.assertEqual(self.sends(), [])

    def test_ids_in_another_letter_case_still_resolve(self):
        self.stub.tools["whoami"] = lambda a: ok({"user": {"id": HEX_ME.upper()}})
        row = dict(DM_LIST["conversations"][0], id=HEX_CONV,
                   participants=[{"id": HEX_ME, "name": "Me"}, {"id": HEX_PEER.upper(), "name": "Pat"}])
        self.stub.tools["list_direct_conversations"] = lambda a: ok({"conversations": [row], "hasMore": False})
        data = self.result(self.send(target=("--conversation", HEX_CONV.upper())))
        self.assertEqual((data["status"], data["peer"]), ("sent", HEX_PEER), data)
        self.assertEqual(self.sends()[0][1]["userId"], HEX_PEER)


class Characters(SendBase):
    def test_invisible_format_and_c1_characters_are_refused(self):
        for ch in ("​", "‮", "⁦", "﻿", "\u0085", " ", " ", "‍", "\x1b", "\t"):
            self.write("look" + ch + "here")
            self.assertEqual(self.result(self.send())["code"], "bad_request", repr(ch))
        self.assertEqual(self.sends(), [])

    def test_visible_unicode_and_line_breaks_are_sent(self):
        self.write("Café \U0001F44D\nnext line")
        self.assertEqual(self.result(self.send())["status"], "sent")
        self.assertEqual(self.sends()[0][1]["body"], PREFIX + "Café \U0001F44D\nnext line")


class Recording(SendBase):
    """PR 337 F2, F4, F5 and adversarial 2: the pending row exists when the request arrives, any failure of the request is
    uncertain with its outcome recorded, a WAL failure is reported, and the lock admits one sender at a time."""

    def ledger(self):
        return self.home / ".agent-harness" / "state" / "ah" / "store" / "chat-send.jsonl"

    def test_the_pending_row_is_on_disk_when_the_request_arrives(self):
        seen = []

        def check(a):
            rows = [json.loads(x) for x in self.ledger().read_text().splitlines()]
            seen.append([r["kind"] for r in rows])
            return ok_bare(SENT)
        self.stub.tools["send_direct_message"] = check
        self.assertEqual(self.result(self.send())["status"], "sent")
        self.assertEqual(seen, [["pending"]])

    def in_process(self, **patches):
        self.hook(self.argv())
        env = {"HOME": str(self.home), "AH_HOME": str(self.home), "GQ_BROWSER_TEST_LOOPBACK": "1"}
        with mock.patch.dict(os.environ, env):
            ctx = [mock.patch.object(*target) for target in patches.values()]
            for c in ctx:
                c.start()
            try:
                return ah_chat_send.send(Path(str(self.home)), None, PEER, ORG, str(self.text), base=self.stub.base)
            finally:
                for c in ctx:
                    c.stop()

    def test_any_failure_of_the_request_is_uncertain_and_recorded(self):
        import http.client
        real = ah_chat_send.chat.Client.tool
        for n, error in enumerate((http.client.IncompleteRead(b"par"), RuntimeError("bug"))):
            self.write("message %d" % n)

            def tool(client, name, arguments, error=error):
                if name == "send_direct_message":
                    raise error
                return real(client, name, arguments)
            data = self.in_process(tool=(ah_chat_send.chat.Client, "tool", tool))
            self.assertEqual((data["ok"], data["status"]), (False, "uncertain"), data)
            self.assertIn("Do NOT resend", data["next"])
            self.assertTrue(data["wal"])
            kinds = [json.loads(x)["kind"] for x in self.ledger().read_text().splitlines()]
            self.assertEqual(kinds[-2:], ["pending", "outcome"])
            self.assertEqual(self.result(self.send())["code"], "duplicate")

    def test_a_wal_failure_after_the_request_is_reported_not_hidden(self):
        def broken(*a, **k):
            raise OSError("disk full")
        data = self.in_process(wal=(ah_chat_send, "_wal", broken))
        self.assertEqual((data["status"], data["wal"]), ("sent", None))
        self.assertIn("ledger still records", data["wal_warning"])

    def test_a_failed_outcome_row_still_holds_the_text_back(self):
        real = ah_chat_send._append
        calls = []

        def append(path, row):
            calls.append(row["kind"])
            if row["kind"] == "outcome":
                raise OSError("disk full")
            return real(path, row)
        data = self.in_process(append=(ah_chat_send, "_append", append))
        self.assertEqual(data["status"], "sent")
        self.assertEqual(calls, ["pending", "outcome"])
        self.assertEqual(self.result(self.send())["code"], "duplicate")  # the pending row alone counts

    def test_two_senders_at_once_deliver_once(self):
        import subprocess
        import time as _time

        def slow(a):
            _time.sleep(3)
            return ok_bare(SENT)
        self.stub.tools["send_direct_message"] = slow
        env = {"PATH": os.environ.get("PATH", ""), "HOME": str(self.home), "AH_HOME": str(self.home),
               "GQ_BROWSER_TEST_LOOPBACK": "1", "CLAUDE_CODE_SESSION_ID": "test-session-1"}
        procs = []
        for name in ("a.txt", "b.txt"):  # two main calls, two files with the same text: one message, two stamps
            path = self.home / name
            path.write_text(self.text.read_text())
            argv = ["send", "--with", PEER, "--org", ORG, "--text-file", str(path)]
            self.hook(argv)
            procs.append(subprocess.Popen([sys.executable, "-I", str(AH), "chat", *argv, "--base", self.stub.base], env=env,
                                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True))
        outs = [json.loads(p.communicate(timeout=90)[0]) for p in procs]
        self.assertEqual(sorted(o.get("status") or o.get("code") for o in outs), ["duplicate", "sent"], outs)
        self.assertEqual(len(self.sends()), 1)

    def test_a_pending_row_missing_a_field_is_damage(self):
        self.ledger().parent.mkdir(parents=True, exist_ok=True)
        for row in ({"id": "a", "kind": "pending", "peer": PEER, "sha": "d"},
                    {"id": "a", "kind": "pending", "peer": PEER, "at": 1.0},
                    {"id": "a", "kind": "pending", "sha": "d", "at": 1.0},
                    {"id": "a", "kind": "pending", "peer": PEER, "sha": "d", "at": True},
                    {"id": "a", "kind": "outcome", "status": "sent"},
                    {"id": "a", "kind": "other"}):
            self.ledger().write_text(json.dumps(row) + "\n")
            self.assertEqual(self.result(self.send())["code"], "ledger_damaged", row)
        self.assertEqual(self.sends(), [])


class Limits(unittest.TestCase):
    def test_at_most_twenty_attempts_an_hour_to_everyone(self):
        rows = [{"id": str(n), "kind": "pending", "peer": "p%d" % n, "sha": "s", "at": 1000.0} for n in range(19)]
        ah_chat_send.check_ledger(rows, "new", "s", 1000.0 + 10)
        rows.append({"id": "19", "kind": "pending", "peer": "p19", "sha": "s", "at": 1000.0})
        with self.assertRaises(ah_chat_send.ChatError) as caught:
            ah_chat_send.check_ledger(rows, "new", "s", 1000.0 + 10)
        self.assertEqual(caught.exception.code, "rate_limited")
        ah_chat_send.check_ledger(rows, "new", "s", 1000.0 + 3601)  # an hour later


class FileTiming(SendBase):
    def test_a_file_written_in_the_same_call_gets_no_stamp_and_the_refusal_says_why(self):
        argv = self.argv()
        self.text.unlink()  # the hook runs before the call writes the file
        self.hook(argv)
        self.write("Thanks Tisha, the fix is on staging now.")
        data = self.result(self.ah(*argv))
        self.assertEqual(data["code"], "main_only")
        self.assertIn("earlier, separate call", data["message"])
        self.assertEqual(self.sends(), [])


class AllowList(SendBase):
    """Main's decision (2026-11-23) and the PR 337 spec reviews: send goes only to a person whose allow-list line names a
    decision row in main's WAL that adds exactly them in this org, on the user's own words naming them. A missing list
    allows nobody, a damaged one refuses every send, and a line appended by hand allows nobody."""

    def ledger(self):
        return self.home / ".agent-harness" / "state" / "ah" / "store" / "chat-send.jsonl"

    def refused(self, code, target=("--with", PEER)):
        data = self.result(self.send(target=target))
        self.assertEqual(data.get("code"), code, data)
        self.assertEqual(self.sends(), [])
        self.assertFalse(self.ledger().exists() and self.ledger().read_text().strip())
        return data

    def test_a_person_not_listed_is_refused_by_id_with_a_hint_that_works(self):
        self.allow_list(self.entry(OTHER, name="Sam", source=SAM_SOURCE))
        self.assertIn("ah chat allow --with USER_ID --org ORG --name NAME --source", self.refused("not_allowed")["message"])

    def test_words_naming_one_person_with_another_persons_id_prove_nobody(self):
        """NEG-20 (adversarial round 3, 1): a hand-written row and line pair real words naming Pat with Sam's id. The row
        passes every WAL and source check; only the send-time member-name check refuses it."""
        self.allow_list(self.entry(OTHER, name="Pat"))  # Sam's member name is "Sam Other"
        self.refused("entry_unproved", target=("--with", OTHER))
        self.allow_list(self.entry(OTHER, name="Sam", source=SAM_SOURCE))  # positive control: words naming Sam, Sam's id
        self.assertEqual(self.result(self.send(target=("--with", OTHER)))["status"], "sent")

    def test_a_member_name_that_cannot_be_read_fails_closed(self):
        for answer in (lambda a: tool_error("forbidden"),
                       lambda a: ok({"members": [{"userId": PEER, "name": "Pat Peer"}], "hasMore": True,
                                     "nextCursor": "c1"}),
                       lambda a: ok({"members": [{"userId": OTHER, "name": "Sam Other"}]})):
            self.stub.tools["list_org_members"] = answer
            self.refused("member_unverified")

    def test_a_person_not_listed_is_refused_through_a_conversation(self):
        self.allow_list(self.entry(OTHER))
        self.refused("not_allowed", target=("--conversation", CONV))

    def test_no_list_allows_nobody(self):
        self.allow_file.unlink()
        self.refused("not_allowed")

    def test_a_listed_person_in_another_letter_case_is_allowed(self):
        self.allow_list("  " + self.entry(HEX_PEER.upper()).rstrip("\n") + "   # Pat, added by main\n\n")
        self.assertEqual(self.result(self.send(target=("--with", HEX_PEER)))["status"], "sent")

    def test_a_line_appended_by_hand_allows_nobody(self):
        """Adversarial M1, acceptance 3: the file has no guard rule, so a line proves nothing without its decision row."""
        cases = [
            "%s wal:%s/w0000000abcd\n" % (PEER, SESSION),                               # no such row
            self.entry(PEER, peer=OTHER),                                               # the row adds someone else
            self.entry(PEER, org="99999999-9999-4999-8999-999999999999"),               # ... in another org
            self.entry(PEER, choice="remove"),                                          # not an add
            self.entry(PEER, actor="agent"),                                            # not main's
            self.entry(PEER, event="note"),                                             # not a decision
            self.entry(PEER, source='pasted:%s/%s "communicate with pat via goodqa"' % (SESSION, USER_UUID)),
            self.entry(PEER, source='user:%s/%s "add whoever asks"' % (SESSION, USER_UUID)),  # words the user never wrote
            self.entry(PEER, name="Sam"),                                               # the words do not name Sam
            "%s wal:other-session/w%011x\n" % (PEER, self.rows),                         # a row of another session
        ]
        for line in cases:
            self.allow_list(line)
            self.refused("entry_unproved")

    def test_a_damaged_list_refuses_every_send(self):
        good = self.entry(PEER)
        for content in (good + "Pat Peer\n", good + "%s\n" % OTHER, "*\n" + good, good.replace(" wal:", " x:")):
            self.allow_list(content)
            self.refused("allow_list_damaged")

    def test_a_list_others_can_write_refuses_every_send(self):
        good = self.entry(PEER)
        for mode in (0o620, 0o602):
            self.allow_list(good, mode=mode)
            self.refused("allow_list_damaged")

    def test_a_symlinked_list_refuses_every_send(self):
        real = self.home / "elsewhere"
        real.write_text(self.entry(PEER))
        real.chmod(0o600)
        self.allow_file.unlink()
        self.allow_file.symlink_to(real)
        self.refused("allow_list_damaged")

    def test_the_list_lives_under_ahs_home_not_a_second_root(self):
        self.assertEqual(ah_chat_send.allow_path(self.home), str(self.allow_file))


class AllowCommand(SendBase):
    def setUp(self):
        super().setUp()
        self.allow_list(self.entry(OTHER, name="Sam", source='user:%s/%s "staging checks"' % (SESSION, USER_UUID)))
        self.base_rows = len(self.decisions())

    def allow_argv(self, who=PEER, source=GOOD_SOURCE, name="Pat", org=ORG):
        return ["allow", "--with", who, "--org", org, "--name", name, "--source", source]

    def allow_hook(self, argv, agent=None):
        import shlex
        self.calls += 1
        line = shlex.join(["python3", str(AH), "chat", *argv, "--base", self.stub.base])
        payload = {"tool_name": "Bash", "tool_input": {"command": line}, "session_id": SESSION,
                   "transcript_path": str(self.transcript), "tool_use_id": "toolu_%08d" % self.calls,
                   "hook_event_name": "PreToolUse"}
        if agent:
            payload.update(agent_id=agent, agent_type="task-owner")
        env = {"HOME": str(self.home), "AH_HOME": str(self.home), "CLAUDE_CONFIG_DIR": str(self.home / ".claude")}
        with mock.patch.dict(os.environ, env):
            mission_gate.cmd_pretool(payload)

    def run_allow(self, agent=None, stamp=True, hooked=None, **kw):
        argv = self.allow_argv(**kw)
        if stamp:
            self.allow_hook(hooked or argv, agent=agent)
        return self.result(self.ah(*argv))

    def listed(self):
        return set(ah_chat_send.read_allowed(str(self.allow_file)))

    def decisions(self):
        return [r for r in self.wal_rows() if r.get("event") == "decision"]

    def test_main_adds_a_person_on_the_users_words_and_then_sends(self):
        self.allow_list("")  # PEER is not on the list
        self.assertEqual(self.result(self.send())["code"], "not_allowed")
        data = self.run_allow()
        self.assertEqual((data["ok"], data["status"], data["peer"], data["member"]), (True, "added", PEER, "Pat Peer"), data)
        self.assertEqual(self.listed(), {PEER})
        row = self.decisions()[-1]
        self.assertEqual((row["peer"], row["org"], row["name"], row["source"], row["id"], row["source_kind"]),
                         (PEER, ORG, "Pat", GOOD_SOURCE, data["wal"], "user"))
        self.assertNotIn("confirmed_by_user", row)  # adversarial M3: the user confirmed nothing for this add
        self.assertEqual(oct(self.allow_file.stat().st_mode & 0o777), "0o600")
        self.assertEqual(self.result(self.send())["status"], "sent")

    def test_a_queued_message_of_the_user_is_a_source(self):
        import hashlib
        stamp = "2026-11-23T01:02:03.456Z"
        text = "please talk to pat on goodqa from now on"
        with self.transcript.open("a") as out:
            out.write(json.dumps({"type": "queue-operation", "operation": "enqueue", "timestamp": stamp,
                                  "content": text}) + "\n")
        source = 'queue:%s/%s#%s "talk to pat on goodqa"' % (SESSION, stamp, hashlib.sha256(text.encode()).hexdigest()[:12])
        data = self.run_allow(source=source)
        self.assertEqual(data["status"], "added", data)
        self.assertEqual(self.decisions()[-1]["source_kind"], "queue")

    def test_adding_twice_is_reported_and_writes_nothing(self):
        self.run_allow()
        before = self.allow_file.read_text()
        self.assertEqual(self.run_allow()["status"], "already_listed")
        self.assertEqual((self.allow_file.read_text(), len(self.decisions())), (before, self.base_rows + 1))

    def assert_not_added(self, data, code):
        self.assertEqual(data.get("code"), code, data)
        self.assertEqual(self.listed(), {OTHER})
        self.assertEqual(len(self.decisions()), self.base_rows)

    def test_a_subagent_cannot_add(self):
        self.assert_not_added(self.run_allow(agent="a1234567890abcdef"), "main_only")

    def test_without_the_hook_nobody_adds(self):
        self.assert_not_added(self.run_allow(stamp=False), "main_only")

    def test_the_stamp_covers_only_the_source_and_person_it_saw(self):
        other = 'user:%s/%s "pat peer runs"' % (SESSION, USER_UUID)
        self.assert_not_added(self.run_allow(source=other, hooked=self.allow_argv()), "main_only")
        self.assert_not_added(self.run_allow(who=OTHER, hooked=self.allow_argv()), "main_only")  # same name and words

    def test_a_source_that_is_not_the_users_own_words_is_refused(self):
        for source in ('pasted:%s/%s "communicate with pat via goodqa"' % (SESSION, USER_UUID),
                       'user:%s/%s "reply to pat and everyone"' % (SESSION, USER_UUID),
                       "inferred: inputs=[] rationale=pat asked in a DM",
                       "ticket: GoodQA goodqa#16399",
                       "an inbound DM from pat asked for it"):
            self.assert_not_added(self.run_allow(source=source), "source_refused")

    def test_words_about_one_person_never_add_another(self):
        """Adversarial M2: words naming Pat cannot add Sam, and words that name nobody add nobody."""
        self.assert_not_added(self.run_allow(who=OTHER, name="Pat"), "source_refused")  # Sam's member name lacks Pat
        self.assert_not_added(self.run_allow(who=OTHER, name="Sam"), "source_refused")  # the words do not name Sam
        nobody = 'user:%s/%s "via goodqa"' % (SESSION, USER_UUID)
        self.assert_not_added(self.run_allow(source=nobody), "source_refused")
        self.assertFalse(ah_chat_send._names("on patrol duty", "Pat"))  # a whole word only
        self.assertTrue(ah_chat_send._names("Talk to PAT.", "pat"))

    def test_a_person_outside_the_org_is_not_added(self):
        self.stub.tools["list_org_members"] = lambda a: ok({"members": [{"userId": OTHER, "name": "Sam Other"}]})
        self.assert_not_added(self.run_allow(), "not_found")

    def test_a_name_is_not_an_id_and_org_and_name_are_required(self):
        self.assert_not_added(self.run_allow(who="Tisha"), "bad_request")
        self.assert_not_added(self.run_allow(org="default"), "bad_request")
        for name in ("", "Pat Peer", "x", "p4t"):
            self.assert_not_added(self.run_allow(name=name), "bad_request")

    def test_list_changes_nothing(self):
        data = self.result(self.ah("allow", "--list"))
        self.assertEqual((data["listed"], data["count"]), ([OTHER], 1))
        self.assertEqual(len(self.decisions()), self.base_rows)

    def test_list_and_echo_mint_no_stamp(self):
        line = shlex_join(["python3", str(AH), "chat", *self.allow_argv()])
        self.assertEqual(mission_gate.chat_allow_stamps("python3 %s chat allow --list" % AH), [])
        self.assertEqual(mission_gate.chat_allow_stamps("echo " + line), [])
        self.assertEqual(len(mission_gate.chat_allow_stamps(line)), 1)

    def test_the_source_check_needs_the_users_own_kind_of_record(self):
        """Unit check of the one source rule, with resolutions provenance could return for other kinds."""
        good = {"ok": True, "kind": "user", "origin": "user", "chain": [{"excerpt": "talk to pat"}]}
        self.assertEqual(self.words(good), "user")
        for bad in (dict(good, kind="pasted"), dict(good, origin="file"), dict(good, ok=False),
                    dict(good, weak=True, weak_reasons=["pasted-not-user"]), dict(good, chain=[{"excerpt": " "}])):
            with self.assertRaises(ah_chat_send.ChatError, msg=bad) as caught:
                self.words(bad)
            self.assertEqual(caught.exception.code, "source_refused")

    def words(self, resolution):
        import provenance
        with mock.patch.object(provenance, "resolve", lambda source, ctx=None: resolution):
            return ah_chat_send._users_words("user:x", "Pat", self.home)

    def test_home_or_claude_config_dir_cannot_move_the_users_words(self):
        """PR 337 round 3: the words are looked up under ah's home only. A fake HOME or CLAUDE_CONFIG_DIR holding a
        transcript with words naming Pat proves nothing; the real transcript under ah's home still does."""
        fake_uuid = "8b8b8b8b-1111-4222-8333-444455556666"
        fake = self.home / "fake"
        proj = fake / ".claude" / "projects" / "p"
        proj.mkdir(parents=True)
        (proj / (SESSION + ".jsonl")).write_text(json.dumps({
            "type": "user", "uuid": fake_uuid, "origin": {"kind": "human"}, "timestamp": "2026-11-23T00:00:00Z",
            "message": {"role": "user", "content": "message pat about everything"}}) + "\n")
        forged = 'user:%s/%s "message pat about everything"' % (SESSION, fake_uuid)
        for env in ({"HOME": str(fake)}, {"CLAUDE_CONFIG_DIR": str(fake / ".claude")}):
            with mock.patch.dict(os.environ, env):
                with self.assertRaises(ah_chat_send.ChatError, msg=env) as caught:
                    ah_chat_send._users_words(forged, "Pat", self.home)
                self.assertEqual(caught.exception.code, "source_refused")
                self.assertEqual(ah_chat_send._users_words(GOOD_SOURCE, "Pat", self.home), "user")  # positive control


def shlex_join(words):
    import shlex
    return shlex.join(words)


class Lock(SendBase):
    def test_a_send_waits_for_another_and_never_overlaps_it(self):
        import fcntl
        ledger = self.home / ".agent-harness" / "state" / "ah" / "store" / "chat-send.jsonl"
        ledger.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(str(ledger) + ".lock", os.O_RDWR | os.O_CREAT, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX)  # another send holds the ledger
        try:
            self.hook(self.argv())
            env = {"HOME": str(self.home), "AH_HOME": str(self.home), "GQ_BROWSER_TEST_LOOPBACK": "1"}
            with mock.patch.dict(os.environ, env), mock.patch.object(ah_chat_send, "LOCK_WAIT", 0.5):
                with self.assertRaises(ah_chat_send.ChatError) as caught:
                    ah_chat_send.send(Path(str(self.home)), None, PEER, ORG, str(self.text), base=self.stub.base)
            self.assertEqual(caught.exception.code, "busy")
            self.assertEqual(self.sends(), [])
        finally:
            os.close(fd)


if __name__ == "__main__":
    unittest.main()
