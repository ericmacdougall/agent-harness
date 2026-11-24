"""Supervisor power (goodqa#16944): request, the user's grant, and the check at every use.

Everything runs in a temporary HOME through self_serve's private test seam. The model always comes from a transcript
record bound to the tool call; the tests forge every other source an agent could reach and show each is refused.
"""
from __future__ import annotations

import importlib.util
import json
import os
import re
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
HOOKS = ROOT / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))

import caller_identity as ci  # noqa: E402
import self_serve as ss  # noqa: E402
import supervisor_grant as sg  # noqa: E402

spec = importlib.util.spec_from_file_location("enable_agent_ops_sup", ROOT / "scripts" / "enable-agent-ops.py")
E = importlib.util.module_from_spec(spec)
spec.loader.exec_module(E)

from cryptography.hazmat.primitives import serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import ed25519  # noqa: E402

SID = "11111111-2222-3333-4444-555555555555"
OTHER = "99999999-2222-3333-4444-555555555555"
AID = "a1b2c3d4e5f6a7b8"
NOW = float(int(time.time()))  # the enabler reads the real clock
REPO = "ericmacdougall/agent-harness"
OPUS, SONNET = "claude-opus-5-5", "claude-sonnet-5"
MODELS_OK = ("claude-opus-5-5", "claude-fable-1", "gpt-6.1-sol", "gpt-6.1-astra")
MODELS_BAD = {"claude-sonnet-5": "model_unqualified", "gpt-6.1-terra": "model_unqualified",
              "claude-haiku-4-5": "model_unknown", "gpt-6.1-luna": "model_unknown", "mystery-model": "model_unknown",
              "<synthetic>": "model_unknown"}


def raw_key():
    key = ed25519.Ed25519PrivateKey.generate()
    pub = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return key, pub


class Env(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.home = os.path.realpath(tmp.name)
        self.claude = Path(self.home) / ".claude"
        self.transcript = self.claude / "projects" / "-x" / (SID + ".jsonl")
        self.transcript.parent.mkdir(parents=True)
        self.transcript.write_text("{}\n")
        self.sub_transcript = self.transcript.parent / SID / "subagents" / ("agent-%s.jsonl" % AID)
        self.sub_transcript.parent.mkdir(parents=True)
        self.sub_transcript.write_text("{}\n")
        self.other_transcript = self.transcript.parent / (OTHER + ".jsonl")
        self.other_transcript.write_text("{}\n")
        for patcher in (mock.patch.object(ci, "native_deny_reason", return_value=None),
                        mock.patch.dict(ss._SEAM, {"home": self.home, "claude_dir": str(self.claude), "clock": True})):
            patcher.start()
            self.addCleanup(patcher.stop)
        self.key, self.pub = raw_key()
        self.key_id = ss.key_id_of(self.pub)
        pol = ss.policy_dir(self.home)
        pol.mkdir(parents=True, mode=0o700)
        os.chmod(pol, 0o700)
        self.write(ss.pubkeys_path(self.home), {"schema": "self-serve-pubkeys/1", "keys": [ss.public_record(self.pub)]})
        wal = self.claude / "wals" / SID / "main.jsonl"
        wal.parent.mkdir(parents=True)
        wal.write_text(json.dumps({"event": "scope", "note": "stream owns https://github.com/%s fixes" % REPO}) + "\n")
        self.counter = 0

    def write(self, path, data, mode=0o600):
        Path(path).write_bytes(data if isinstance(data, bytes) else json.dumps(data).encode())
        os.chmod(path, mode)

    # ----- transcript records
    def call(self, model=OPUS, transcript=None, command="ah supervisor request --project x", record=None):
        """Append the client's assistant record of one tool call; return its tool_use id."""
        self.counter += 1
        tid = "toolu_%016d" % self.counter
        rec = record or {"type": "assistant", "uuid": "u-%d" % self.counter,
                         "message": {"role": "assistant", "model": model,
                                     "content": [{"type": "tool_use", "id": tid, "name": "Bash",
                                                  "input": {"command": command}}]}}
        with open(transcript or self.transcript, "a") as handle:
            handle.write(json.dumps(rec) + "\n")
        return tid

    def payload(self, tid, agent=None, session=SID, transcript=None, **extra):
        out = {"session_id": session, "transcript_path": str(transcript or self.transcript), "tool_use_id": tid}
        if agent:
            out["agent_id"] = agent
        out.update(extra)
        return out

    # ----- request and grant
    def stamp(self, model=OPUS, transcript=None, session=SID, command=None):
        tid = self.call(model, transcript, command or "ah supervisor request --project %s:mac" % REPO)
        return {"session": session, "tool_use_id": tid, "transcript": str(transcript or self.transcript)}

    def request(self, argv=None, **kw):
        argv = argv or ["--project", REPO + ":mac,t2-dev", "--power", "merge", "--power", "delete", "--reason", "clean up"]
        req = sg.build_request(argv, self.stamp(**kw), now=NOW)
        sg.write_request(req)
        return req

    def grant(self, req=None, *, expiry="8h", subagents=False, key=None, key_id=None, now=NOW, **kw):
        req = req or self.request()
        body = sg.grant_body(req, key_id=key_id or self.key_id, expiry=expiry, include_subagents=subagents, now=now, **kw)
        signed = dict(body, signature=ss.b64url((key or self.key).sign(sg.signed_message(body))))
        sg.write_grant(signed)
        return signed

    def check(self, tid, power="merge", project=REPO, host="mac", now=NOW + 60, **kw):
        return sg.check(self.payload(tid, **{k: v for k, v in kw.items() if k in ("agent", "session", "transcript")}),
                        power, project, host=host, now=now, target=kw.get("target"))

    def code(self, result):
        self.assertFalse(result["ok"], result)
        return result["code"]


class Request(Env):
    def test_main_request_is_written_with_the_hook_facts(self):
        req = self.request()
        self.assertEqual((req["session"], req["model"], req["model_family"]), (SID, OPUS, "opus"))
        self.assertEqual(req["powers"], ["delete", "merge"])
        self.assertEqual(req["evidence"][REPO][-len("main.jsonl"):], "main.jsonl")
        stored = json.loads((sg.requests_dir(self.home) / (req["rid"] + ".json")).read_text())
        self.assertEqual(stored["rid"], req["rid"])

    def test_no_stamp_is_refused_as_not_main(self):
        for stamp in (None, {}, {"session": SID}):
            with self.assertRaises(sg.Refusal) as caught:
                sg.build_request(["--project", REPO + ":mac", "--power", "merge", "--reason", "x"], stamp, now=NOW)
            self.assertEqual(caught.exception.code, "not_main")
            self.assertIn("only the main agent", caught.exception.message)

    def test_sub_agent_transcript_cannot_request(self):
        with self.assertRaises(sg.Refusal) as caught:
            self.request(transcript=self.sub_transcript)
        self.assertIn(caught.exception.code, ("not_main", "bad_input"))

    def test_cli_without_a_stamp_refuses_and_writes_nothing(self):
        lines = []
        rc = sg.cli(["request", "--project", REPO + ":mac", "--power", "merge", "--reason", "x"], out=lines.append, stamp={})
        self.assertEqual(rc, 3)
        self.assertEqual(json.loads(lines[0])["code"], "not_main")
        self.assertFalse(sg.requests_dir(self.home).exists())

    def test_unqualified_and_unknown_models_cannot_request(self):
        for model, code in MODELS_BAD.items():
            with self.subTest(model=model), self.assertRaises(sg.Refusal) as caught:
                self.request(model=model)
            self.assertEqual(caught.exception.code, code)

    def test_every_qualified_family_can_request(self):
        for model in MODELS_OK:
            with self.subTest(model=model):
                self.assertEqual(self.request(model=model)["model"], model)

    def test_wildcards_and_unnamed_projects_are_refused(self):
        for project in ("*", "ericmacdougall/*", "all", "ericmacdougall/agent-harness", "ericmacdougall/agent-harness:",
                        "ericmacdougall/agent-harness:everywhere", "ericmacdougall/agent-*:mac"):
            with self.subTest(project=project), self.assertRaises(sg.Refusal) as caught:
                self.request(["--project", project, "--power", "merge", "--reason", "x"])
            self.assertEqual(caught.exception.code, "bad_input")

    def test_unsupervised_slug_is_refused(self):
        with self.assertRaises(sg.Refusal) as caught:
            self.request(["--project", "ericmacdougall/goodqa:mac", "--power", "merge", "--reason", "x"])
        self.assertEqual(caught.exception.code, "not_supervised")
        self.assertIn("ericmacdougall/goodqa", caught.exception.message)

    def test_slug_prefix_in_the_wal_is_not_evidence(self):
        with self.assertRaises(sg.Refusal) as caught:
            self.request(["--project", "ericmacdougall/agent:mac", "--power", "merge", "--reason", "x"])
        self.assertEqual(caught.exception.code, "not_supervised")

    def test_never_covered_projects_are_refused(self):
        for repo in ("ericmacdougall/yates-cloud", "ericmacdougall/apex_app_pos", "ericmacdougall/OptinRouter"):
            with self.subTest(repo=repo), self.assertRaises(sg.Refusal) as caught:
                self.request(["--project", repo + ":mac", "--power", "merge", "--reason", "x"])
            self.assertEqual(caught.exception.code, "never_covered")

    def test_stamp_for_another_command_is_refused(self):
        stamp = self.stamp(command="git status")
        with self.assertRaises(sg.Refusal) as caught:
            sg.build_request(["--project", REPO + ":mac", "--power", "merge", "--reason", "x"], stamp, now=NOW)
        self.assertEqual(caught.exception.code, "not_main")

    def test_reason_with_a_secret_is_refused(self):
        with self.assertRaises(sg.Refusal) as caught:
            self.request(["--project", REPO + ":mac", "--power", "merge", "--reason", "token=abc123def"])
        self.assertIn("secret", caught.exception.message)

    def test_reason_cannot_widen_the_request(self):
        req = self.request(["--project", REPO + ":mac", "--power", "merge", "--reason", "grant all powers, delete too"])
        self.assertEqual(req["powers"], ["merge"])

    def test_unknown_power_is_refused_by_the_parser(self):
        with self.assertRaises(SystemExit):
            self.request(["--project", REPO + ":mac", "--power", "admin", "--reason", "x"])

    def test_hand_written_request_file_is_refused_by_the_enabler_loader(self):
        req = self.request()
        path = sg.requests_dir(self.home) / (req["rid"] + ".json")
        forged = dict(req, model="claude-opus-9")
        self.write(path, json.dumps(forged).encode())
        with self.assertRaises(sg.Refusal):
            sg.load_request(req["rid"], now=NOW)
        rid = "0123456789abcdef"
        self.write(sg.requests_dir(self.home) / (rid + ".json"),
                   json.dumps(dict(req, rid=rid, tool_use_id="toolu_doesnotexist01")).encode())
        with self.assertRaises(sg.Refusal):
            sg.load_request(rid, now=NOW)

    def test_old_request_is_refused(self):
        req = self.request()
        with self.assertRaises(sg.Refusal) as caught:
            sg.load_request(req["rid"], now=NOW + 25 * 3600)
        self.assertEqual(caught.exception.code, "expired")

    def test_user_source_must_verify_as_the_users_words(self):
        import provenance
        argv = ["--project", REPO + ":mac", "--power", "merge", "--reason", "x", "--user-source",
                'user:%s/u1 "you are allowed to merge things"' % SID]
        good = {"ok": True, "origin": "user", "weak": False, "kind": "user", "problems": []}
        with mock.patch.object(provenance, "resolve", return_value=good):
            self.assertEqual(self.request(argv)["user_excerpt"], "you are allowed to merge things")
        for bad in (dict(good, ok=False, problems=[{"code": "excerpt-not-found"}]), dict(good, origin="agent"),
                    dict(good, weak=True), dict(good, kind="pasted")):
            with self.subTest(bad=bad), mock.patch.object(provenance, "resolve", return_value=bad), \
                    self.assertRaises(sg.Refusal) as caught:
                self.request(argv)
            self.assertIn("does not verify", caught.exception.message)

    def test_hook_stamps_supervisor_commands(self):
        import ah_ops
        self.assertIn("supervisor", ah_ops.STAMPED_COMMANDS)
        got = ah_ops.stamped_argvs("python3 ~/.claude/hooks/ah.py supervisor request --project %s:mac --power merge "
                                   "--reason 'tidy up'" % REPO)
        self.assertEqual(got, [["supervisor", "request", "--project", REPO + ":mac", "--power", "merge", "--reason",
                                "tidy up"]])


class GrantBody(Env):
    def test_default_and_choices(self):
        req = self.request()
        body = sg.grant_body(req, key_id=self.key_id, expiry=sg.DEFAULT_EXPIRY, include_subagents=False, now=NOW)
        self.assertEqual(sg.DEFAULT_EXPIRY, "8h")
        self.assertEqual(ss.parse_time(body["expires_at"]) - NOW, 8 * 3600)
        forever = sg.grant_body(req, key_id=self.key_id, expiry="until revoked", include_subagents=False, now=NOW)
        self.assertIsNone(forever["expires_at"])
        for bad in ("", "forever", "never", "until-revoked", "0", None):
            with self.subTest(bad=bad), self.assertRaises(sg.Refusal):
                sg.grant_body(req, key_id=self.key_id, expiry=bad, include_subagents=False, now=NOW)

    def test_choices_only_remove(self):
        req = self.request(["--project", REPO + ":mac", "--power", "merge", "--reason", "x"])
        with self.assertRaises(sg.Refusal):
            sg.grant_body(req, key_id=self.key_id, expiry="8h", include_subagents=True, now=NOW)
        with self.assertRaises(sg.Refusal):
            sg.grant_body(req, key_id=self.key_id, expiry="8h", include_subagents=False, drop_powers=["merge"], now=NOW)

    def test_terminal_text(self):
        req = self.request()
        body = sg.grant_body(req, key_id=self.key_id, expiry="8h", include_subagents=False, now=NOW)
        text = sg.terminal_text(req, body)
        self.assertIn("Uncommitted and unpushed work in those worktrees can be lost.", text)
        self.assertIn("by that session's own hook (not by what the agent typed)", text)
        self.assertIn("(8 hours)", text)
        self.assertIn("NOT included", text)
        for item in sg.NEVER_COVERED:
            self.assertIn(item, text)
        self.assertIn(REPO, text)
        self.assertIn("ah supervisor revoke %s" % body["gid"], text)
        forever = sg.grant_body(req, key_id=self.key_id, expiry="until revoked", include_subagents=False, now=NOW)
        self.assertIn("you typed 'until revoked'", sg.terminal_text(req, forever))
        merge_only = sg.grant_body(req, key_id=self.key_id, expiry="8h", include_subagents=False, drop_powers=["delete"],
                                   now=NOW)
        self.assertNotIn("can be lost", sg.terminal_text(req, merge_only))


class Check(Env):
    def test_main_holds_merge_and_each_allow_is_audited(self):
        grant = self.grant()
        got = self.check(self.call())
        self.assertTrue(got["ok"], got)
        self.assertEqual((got["gid"], got["power"], got["project"]), (grant["gid"], "merge", REPO))
        rows = [json.loads(line) for line in sg.audit_path(self.home).read_text().splitlines()]
        self.assertEqual([r["event"] for r in rows], ["granted", "allow"])
        self.assertEqual(rows[-1]["audit_id"], got["audit_id"])

    def test_every_qualified_family_passes_at_use(self):
        self.grant()
        for model in MODELS_OK:
            with self.subTest(model=model):
                self.assertTrue(self.check(self.call(model))["ok"])

    def test_unqualified_or_unknown_model_at_use_is_refused(self):
        self.grant()
        for model, code in MODELS_BAD.items():
            with self.subTest(model=model):
                self.assertEqual(self.code(self.check(self.call(model))), code)

    def test_model_switch_after_grant_stops_and_resumes_the_power(self):
        self.grant()
        self.assertTrue(self.check(self.call(OPUS))["ok"])
        self.assertEqual(self.code(self.check(self.call(SONNET))), "model_unqualified")
        self.assertTrue(self.check(self.call(OPUS))["ok"])

    def test_agent_claim_of_a_model_is_ignored(self):
        self.grant()
        tid = self.call(SONNET)
        payload = self.payload(tid, model=OPUS, agent_model=OPUS)
        self.assertEqual(self.code(sg.check(payload, "merge", REPO, host="mac", now=NOW + 60)), "model_unqualified")
        with mock.patch.dict(os.environ, {"ANTHROPIC_MODEL": OPUS, "CLAUDE_MODEL": OPUS}):
            self.assertEqual(self.code(sg.check(payload, "merge", REPO, host="mac", now=NOW + 60)), "model_unqualified")

    def test_agent_appended_transcript_line_is_not_accepted(self):
        """Note 1: an agent that appends a line claiming a qualified model for the running call creates a second
        record with that id, and the check refuses. (The command guard's transcript-forgery rule blocks the shell
        write in the first place; this test shows the check does not rely on it.)"""
        self.grant()
        tid = self.call(SONNET)
        forged = {"type": "assistant", "uuid": "forged", "message": {"role": "assistant", "model": OPUS, "content": [
            {"type": "tool_use", "id": tid, "name": "Bash", "input": {"command": "gh pr merge"}}]}}
        with open(self.transcript, "a") as handle:
            handle.write(json.dumps(forged) + "\n")
        result = self.check(tid)
        self.assertEqual(self.code(result), "model_unknown")
        self.assertIn("more than one", result["message"])

    def test_only_client_shaped_assistant_records_count(self):
        self.grant()
        for name, mutate in (("user type", lambda r: r.update(type="user")),
                             ("no uuid", lambda r: r.pop("uuid")),
                             ("api error", lambda r: r.update(isApiErrorMessage=True)),
                             ("role user", lambda r: r["message"].update(role="user")),
                             ("no model", lambda r: r["message"].pop("model"))):
            with self.subTest(name=name):
                self.counter += 1
                tid = "toolu_%016d" % self.counter
                rec = {"type": "assistant", "uuid": "u", "message": {"role": "assistant", "model": OPUS, "content": [
                    {"type": "tool_use", "id": tid, "name": "Bash", "input": {}}]}}
                mutate(rec)
                self.call(record=rec)
                self.assertEqual(self.code(self.check(tid)), "model_unknown")

    def test_missing_record_or_id_is_refused(self):
        self.grant()
        self.assertEqual(self.code(self.check("toolu_neverwritten0001")), "model_unknown")
        self.assertEqual(self.code(sg.check({"session_id": SID, "transcript_path": str(self.transcript)}, "merge", REPO,
                                            host="mac", now=NOW + 60)), "model_unknown")

    def test_expired(self):
        self.grant()
        self.assertEqual(self.code(self.check(self.call(), now=NOW + 8 * 3600)), "expired")

    def test_until_revoked_lasts_until_revoked(self):
        grant = self.grant(expiry="until revoked")
        self.assertTrue(self.check(self.call(), now=NOW + 400 * 86400)["ok"])
        self.assertTrue(sg.revoke(grant["gid"]))
        self.assertEqual(self.code(self.check(self.call(), now=NOW + 400 * 86400)), "revoked")

    def test_revoked_stays_revoked_when_the_file_is_removed(self):
        grant = self.grant()
        self.assertTrue(sg.revoke(grant["gid"]))
        self.assertEqual(self.code(self.check(self.call())), "revoked")
        os.unlink(sg.revoked_dir(self.home) / grant["gid"])
        self.assertEqual(self.code(self.check(self.call())), "revoked")

    def test_revoke_all_and_kill_switch(self):
        self.grant()
        Path(ss.kill_switch_path(self.home)).write_text("off\n")
        self.assertEqual(self.code(self.check(self.call())), "disabled")
        os.unlink(ss.kill_switch_path(self.home))
        self.assertTrue(self.check(self.call())["ok"])
        self.assertTrue(sg.revoke("all"))
        self.assertEqual(self.code(self.check(self.call())), "revoked")

    def test_revoke_rejects_other_names(self):
        self.assertFalse(sg.revoke("../../policy/self-serve.json"))
        self.assertFalse(sg.revoke("merge"))

    def test_wrong_session(self):
        self.grant()
        tid = self.call(OPUS, transcript=self.other_transcript)
        self.assertEqual(self.code(self.check(tid, session=OTHER, transcript=self.other_transcript)), "wrong_session")

    def test_copied_grant_with_edited_session_or_window_fails_the_signature(self):
        grant = self.grant()
        for field, value in (("session", OTHER), ("expires_at", None), ("powers", ["merge"]),
                             ("include_subagents", True), ("projects", [{"name": "x", "repo": "a/b", "hosts": ["mac"]}])):
            with self.subTest(field=field):
                path = sg.grants_dir(self.home) / (grant["gid"] + ".json")
                self.write(path, json.dumps(dict(grant, **{field: value})).encode())
                tid = self.call(OPUS, transcript=self.other_transcript) if field == "session" else self.call()
                kw = {"session": OTHER, "transcript": self.other_transcript} if field == "session" else {}
                self.assertEqual(self.code(self.check(tid, **kw)), "bad_signature")
                self.write(path, json.dumps(grant).encode())

    def test_grant_written_without_the_key_is_refused(self):
        stranger, _pub = raw_key()
        self.grant(key=stranger)
        self.assertEqual(self.code(self.check(self.call())), "bad_signature")

    def test_unpinned_key_is_refused(self):
        stranger, pub = raw_key()
        self.grant(key=stranger, key_id=ss.key_id_of(pub))
        self.assertEqual(self.code(self.check(self.call())), "bad_signature")

    def test_self_serve_policy_signature_does_not_verify_as_a_grant(self):
        req = self.request()
        body = sg.grant_body(req, key_id=self.key_id, expiry="8h", include_subagents=False, now=NOW)
        replay = dict(body, signature=ss.b64url(self.key.sign(ss.signed_message(body))))
        sg.write_grant(replay)
        self.assertEqual(self.code(self.check(self.call())), "bad_signature")

    def test_grant_file_must_be_private(self):
        grant = self.grant()
        os.chmod(sg.grants_dir(self.home) / (grant["gid"] + ".json"), 0o644)
        self.assertEqual(self.code(self.check(self.call())), "bad_signature")

    def test_no_grant(self):
        self.assertEqual(self.code(self.check(self.call())), "no_grant")

    def test_project_host_and_power(self):
        self.grant(drop_powers=["delete"])
        self.assertEqual(self.code(self.check(self.call(), project="ericmacdougall/goodqa")), "wrong_project")
        self.assertEqual(self.code(self.check(self.call(), host="ah-mac-mini")), "wrong_host")
        self.assertEqual(self.code(self.check(self.call(), host="nowhere")), "wrong_host")
        self.assertEqual(self.code(self.check(self.call(), power="delete",
                                              target={"kind": "scratch", "path": self.home + "/work/x"})),
                         "power_not_granted")
        for power in ("admin", "approve", "permission_mode", "install_guard", "", None):
            with self.subTest(power=power):
                self.assertEqual(self.code(self.check(self.call(), power=power)), "bad_input")
        for project in ("*", "ericmacdougall/*", "", None):
            with self.subTest(project=project):
                self.assertEqual(self.code(self.check(self.call(), project=project)), "bad_input")

    def test_sub_agent_not_included(self):
        self.grant()
        tid = self.call(OPUS, transcript=self.sub_transcript)
        self.assertEqual(self.code(self.check(tid, agent=AID)), "subagent_not_included")
        self.assertEqual(self.code(self.check(tid, agent=AID, transcript=self.sub_transcript)), "subagent_not_included")

    def test_sub_agent_included_needs_its_own_qualified_model(self):
        req = self.request(["--project", REPO + ":mac", "--power", "merge", "--include-subagents", "--reason", "x"])
        self.grant(req, subagents=True)
        ok = self.call(OPUS, transcript=self.sub_transcript)
        self.assertTrue(self.check(ok, agent=AID)["ok"])
        self.assertTrue(self.check(self.call(OPUS, transcript=self.sub_transcript), agent=AID,
                                   transcript=self.sub_transcript)["ok"])
        bad = self.call(SONNET, transcript=self.sub_transcript)
        self.assertEqual(self.code(self.check(bad, agent=AID)), "model_unqualified")
        # main's own record does not lend its model to the sub-agent
        main_tid = self.call(OPUS)
        self.assertEqual(self.code(self.check(main_tid, agent=AID)), "model_unknown")

    def test_transcript_outside_projects_is_refused(self):
        self.grant()
        rogue = Path(self.home) / "rogue" / (SID + ".jsonl")
        rogue.parent.mkdir()
        tid = self.call(OPUS, transcript=rogue)
        self.assertEqual(self.code(self.check(tid, transcript=rogue)), "bad_input")


class NeverCovered(Env):
    def setUp(self):
        super().setUp()
        self.grant()

    def delete(self, target):
        return self.check(self.call(), power="delete", target=target)

    def test_owned_worktree_is_covered(self):
        got = self.delete({"kind": "worktree", "path": self.home + "/repos/x/.claude/worktrees/agent-1",
                           "created_by_session": SID})
        self.assertTrue(got["ok"], got)

    def test_every_never_covered_target(self):
        h = self.home
        cases = [
            {"kind": "worktree", "path": h + "/.claude/projects/-x", "created_by_session": SID},
            {"kind": "scratch", "path": h + "/.claude/wals/" + SID},
            {"kind": "scratch", "path": h + "/.claude/sessions"},
            {"kind": "build", "path": h + "/.codex/sessions"},
            {"kind": "scratch", "path": h + "/.agent-harness/policy/supervisor"},
            {"kind": "scratch", "path": h + "/.agent-harness/private/self-serve"},
            {"kind": "scratch", "path": h + "/.claude/hooks"},
            {"kind": "scratch", "path": h + "/.claude"},
            {"kind": "scratch", "path": h},
            {"kind": "scratch", "path": "/"},
            {"kind": "scratch", "path": "relative/path"},
            {"kind": "build", "path": h + "/repos/x/harness/hooks/command_guard.py"},
            {"kind": "clone", "path": h + "/repos/yates-cloud", "created_by_session": SID},
            {"kind": "clone", "path": h + "/repos/OptinRouter", "created_by_session": SID},
            {"kind": "worktree", "path": h + "/repos/x/wt", "created_by_session": OTHER},
            {"kind": "worktree", "path": h + "/repos/x/wt"},
            {"kind": "branch", "ref": "main", "created_by_session": SID},
            {"kind": "branch", "ref": "origin/master", "created_by_session": SID},
            {"kind": "branch", "ref": "refs/tags/v1", "created_by_session": SID},
            {"kind": "branch", "ref": "feat/x", "created_by_session": OTHER},
            {"kind": "branch", "created_by_session": SID},
            {"kind": "database", "path": h + "/db"},
            {"kind": "logs", "path": h + "/logs"},
            None,
        ]
        for target in cases:
            with self.subTest(target=target):
                self.assertEqual(self.code(self.delete(target)), "never_covered")

    def test_never_covered_project(self):
        self.assertEqual(self.code(self.check(self.call(), project="ericmacdougall/yates-cloud")), "never_covered")

    def test_symlink_into_a_protected_root_is_refused(self):
        link = Path(self.home) / "repos" / "innocent"
        link.parent.mkdir()
        os.symlink(self.claude / "projects", link)
        self.assertEqual(self.code(self.delete({"kind": "scratch", "path": str(link)})), "never_covered")


class SessionStart(Env):
    def test_live_grant_is_shown_to_its_session_and_flagged_for_others(self):
        self.assertEqual(sg.session_start_context({"session_id": SID}, now=NOW), "")
        grant = self.grant()
        mine = sg.session_start_context({"session_id": SID}, now=NOW + 60)
        self.assertIn("SUPERVISOR GRANT live for this session", mine)
        self.assertIn(grant["gid"][:12], mine)
        other = sg.session_start_context({"session_id": OTHER}, now=NOW + 60)
        self.assertIn("not this one", other)
        self.assertEqual(sg.session_start_context({"session_id": SID}, now=NOW + 9 * 3600), "")

    def test_installer_registers_the_session_start_line(self):
        source = (ROOT / "install.py").read_text()
        self.assertIn('"supervisor_grant.py"), "session-start"', source)
        self.assertIn('"supervisor_grant.py", "supervisor_policy.json"', source)


class FakeHandle:
    def close(self):
        return True


class FakeEnv:
    def __init__(self, answers, tty=True, environ=None, table=None):
        self.answers, self.tty, self.env, self.table = list(answers), tty, environ or {}, table or {}
        self.prompts, self.shown = [], []

    def is_tty(self):
        return self.tty

    def environ(self):
        return dict(self.env)

    def process_table(self):
        return self.table

    def pid(self):
        return 900

    def session_proof_required(self):
        return False

    def present_code(self, code, label):
        self.shown.append(code)
        return FakeHandle()

    def read_nonce(self, prompt):
        self.prompts.append(prompt)
        answer = self.answers.pop(0)
        return self.shown[-1] if answer == "<code>" else answer


class Enabler(Env):
    def setUp(self):
        super().setUp()
        layout = E.Layout(self.home)
        layout.keyfile.parent.mkdir(parents=True)
        pem = self.key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                     serialization.NoEncryption())
        self.write(layout.keyfile, pem)
        self.req = self.request()

    def run_enabler(self, answers, **env):
        fake, lines = FakeEnv(answers, **env), []
        rc = E.main(["--grant-supervisor", self.req["rid"], "--home", self.home], env=fake, out=lines.append,
                    upstream=object(), remote=object(), parity=lambda *a: {}, supervisor=sg)
        return rc, fake, "\n".join(lines)

    def grants(self):
        return [g for g, _p, _path in sg.load_grants(self.home) if g]

    def test_enter_everywhere_grants_eight_hours_without_subagents(self):
        rc, fake, text = self.run_enabler(["", "", "<code>"])  # powers: keep, expiry: default, code
        self.assertEqual(rc, 0, text)
        (grant,) = self.grants()
        self.assertEqual(ss.parse_time(grant["expires_at"]) - ss.parse_time(grant["issued_at"]), 8 * 3600)
        self.assertFalse(grant["include_subagents"])
        self.assertIn("Uncommitted and unpushed work in those worktrees can be lost.", text)
        self.assertNotIn(fake.shown[-1], text)  # the code is only in the dialog
        self.assertTrue(self.check(self.call())["ok"])

    def test_until_revoked_only_when_typed(self):
        rc, _fake, text = self.run_enabler(["", "until revoked", "<code>"])
        self.assertEqual(rc, 0, text)
        self.assertIsNone(self.grants()[0]["expires_at"])

    def test_unknown_expiry_or_bad_numbers_refuse_and_write_nothing(self):
        for answers in (["", "forever"], ["", "until-revoked"], ["7"], ["x"]):
            with self.subTest(answers=answers):
                rc, _fake, text = self.run_enabler(answers)
                self.assertEqual(rc, 3, text)
                self.assertEqual(self.grants(), [])

    def test_wrong_code_writes_nothing(self):
        rc, _fake, text = self.run_enabler(["", "", "wrong"])
        self.assertEqual(rc, 3)
        self.assertIn("nonce did not match", text)
        self.assertEqual(self.grants(), [])

    def test_removing_a_power(self):
        rc, _fake, text = self.run_enabler(["1", "", "<code>"])  # powers are listed sorted: 1. delete
        self.assertEqual(rc, 0, text)
        self.assertEqual(self.grants()[0]["powers"], ["merge"])

    def test_agent_cannot_run_the_enabler(self):
        for env in ({"tty": False}, {"environ": {"CLAUDECODE": "1"}},
                    {"table": {900: (800, "python3 enable-agent-ops.py"), 800: (1, "claude --resume")}}):
            with self.subTest(env=env):
                rc, fake, text = self.run_enabler(["", "", "<code>"], **env)
                self.assertEqual(rc, 3, text)
                self.assertRegex(text, "interactive terminal|agent session environment|agent process")
                self.assertEqual(fake.prompts, [])  # refused before anything was asked or read
                self.assertEqual(self.grants(), [])

    def test_hand_written_request_cannot_be_granted(self):
        path = sg.requests_dir(self.home) / (self.req["rid"] + ".json")
        for forged in (dict(self.req, model="claude-opus-9"), dict(self.req, record_uuid="u-other"), dict(self.req, session=OTHER)):
            with self.subTest(forged={k: forged[k] for k in ("model", "record_uuid", "session")}):
                self.write(path, json.dumps(forged).encode())
                rc, _fake, text = self.run_enabler(["", "", "<code>"])
                self.assertEqual(rc, 3, text)
                self.assertRegex(text, "does not match the session's own record|not a session transcript")
                self.assertEqual(self.grants(), [])
        self.assertEqual(self.grants(), [])

    def test_bad_request_id_is_refused(self):
        lines = []
        rc = E.main(["--grant-supervisor", "../x", "--home", self.home], env=FakeEnv([]), out=lines.append,
                    upstream=object(), remote=object(), parity=lambda *a: {}, supervisor=sg)
        self.assertEqual(rc, 3)


class Contract(unittest.TestCase):
    def test_check_never_raises(self):
        for args in ((None, None, None), ({}, "merge", REPO), ("x", "delete", 3), ({"session_id": 5}, "merge", REPO)):
            with self.subTest(args=args):
                got = sg.check(*args)
                self.assertFalse(got["ok"])
                self.assertIn(got["code"], sg.CODES)

    def test_powers_are_only_merge_and_delete(self):
        self.assertEqual(sg.POWERS, ("merge", "delete"))

    def test_policy_is_a_guard_file_and_lists_the_qualified_families(self):
        import guard_files
        self.assertTrue(guard_files.is_guard_file("supervisor_policy.json"))
        self.assertTrue(guard_files.is_guard_file("supervisor_grant.py"))
        policy = sg.load_policy()
        self.assertEqual(sorted(sg.qualified_names(policy)), ["astra", "fable", "opus", "sol"])


if __name__ == "__main__":
    unittest.main()
