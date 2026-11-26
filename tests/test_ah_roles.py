"""Roles come from the launch, not from the model name (docs/roles.md, ah_roles.py).

The launch profile puts AH_ROLE in the session's environment (the generated --settings file's `env` block, the managed
drop-in, or Codex's shell_environment_policy). Without it: no agent marker is the owner at a terminal; an agent is a
supervisor only when the owner recorded its session in roles.json, else a worker. No authority ever reads a model."""

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

HOOKS = Path(__file__).resolve().parents[1] / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
import ah_approvals  # noqa: E402
import ah_roles  # noqa: E402

SID = "11111111-2222-3333-4444-555555555555"
OTHER = "99999999-2222-3333-4444-555555555555"
FABLE = "claude-fable-5-20261101"


class Base(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="roles-")
        self.addCleanup(tmp.cleanup)
        self.home = Path(tmp.name).resolve()
        self.proj = self.home / "proj"
        self.proj.mkdir()
        self.elsewhere = self.home / "elsewhere" / "file.txt"
        self.elsewhere.parent.mkdir()
        self.elsewhere.write_text("x")
        self.transcript = self.home / ".claude" / "projects" / "p" / (SID + ".jsonl")
        self.transcript.parent.mkdir(parents=True)
        self.transcript.write_text(json.dumps({"type": "assistant", "message": {"model": FABLE}}) + "\n")

    def env(self, **values):
        """Run with exactly these environment variables (plus HOME pointing at the temp home)."""
        values.setdefault("HOME", str(self.home))
        patcher = mock.patch.dict(os.environ, values, clear=True)
        patcher.start()
        self.addCleanup(patcher.stop)

    def payload(self, **extra):
        return dict({"session_id": SID, "transcript_path": str(self.transcript)}, **extra)

    def own(self, name="a.txt"):
        root = self.home / ".agent-harness" / "work" / SID
        root.mkdir(parents=True, exist_ok=True)
        (root / name).write_text("x")
        return root / name


class LaunchRole(Base):
    def test_ah_role_worker_with_a_fable_transcript_is_a_worker(self):
        self.env(AH_ROLE="worker", AH_ROLE_SOURCE="ah-sandbox:worker", CLAUDECODE="1", CLAUDE_CODE_SESSION_ID=SID)
        payload = self.payload()
        self.assertEqual(ah_roles.caller_model(payload), FABLE)  # display still works
        self.assertEqual(ah_roles.launch_role(home=self.home), "worker")
        self.assertFalse(ah_roles.may_handle_secrets(payload))
        self.assertFalse(ah_roles.is_top_rung(payload))
        self.assertFalse(ah_roles.is_supervisor(payload, home=self.home))
        self.assertFalse(ah_roles.may_delete(payload, self.elsewhere, home=self.home)[0])
        self.assertTrue(ah_roles.may_delete(payload, self.own(), home=self.home)[0])

    def test_the_launch_wins_over_roles_json(self):
        ah_roles.set_supervisor(SID, [str(self.proj)], home=self.home)
        self.env(AH_ROLE="worker", CLAUDECODE="1", CLAUDE_CODE_SESSION_ID=SID)
        self.assertEqual(ah_roles.launch_role(home=self.home), "worker")
        self.assertEqual(ah_roles.supervised_roots(self.payload(), home=self.home), [])

    def test_no_ah_role_and_no_agent_marker_is_the_owner(self):
        self.assertEqual(ah_roles.launch_role(environ={}, home=self.home), "owner")
        self.env()
        self.assertEqual(ah_roles.launch_role(home=self.home), "owner")
        self.assertTrue(ah_roles.is_top_rung({}))
        self.assertTrue(ah_roles.may_handle_secrets({}))
        self.assertTrue(ah_roles.may_delete({}, self.elsewhere, home=self.home)[0])
        self.assertFalse(ah_roles.is_supervisor({}, home=self.home))

    def test_every_agent_marker_makes_a_caller_an_agent(self):
        for marker in ah_approvals.AGENT_MARKERS:
            with self.subTest(marker=marker):
                self.assertEqual(ah_roles.launch_role(environ={marker: "1"}, home=self.home), "worker")

    def test_a_session_variable_alone_marks_an_agent(self):
        for name in ah_roles.SESSION_VARS:
            with self.subTest(name=name):
                self.assertEqual(ah_roles.launch_role(environ={name: SID}, home=self.home), "worker")
                self.assertTrue(ah_approvals.in_agent({name: SID}))

    def test_an_agent_without_ah_role_is_a_worker_or_a_recorded_supervisor(self):
        environ = {"CLAUDECODE": "1", "CLAUDE_CODE_SESSION_ID": SID}
        self.assertEqual(ah_roles.launch_role(environ=environ, home=self.home), "worker")
        ah_roles.set_role_default([str(self.proj)], home=self.home)  # a default entry names no session
        self.assertEqual(ah_roles.launch_role(environ=environ, home=self.home), "worker")
        ah_roles.set_supervisor(SID, [str(self.proj)], home=self.home)
        self.assertEqual(ah_roles.launch_role(environ=environ, home=self.home), "supervisor")
        codex = {"CODEX_THREAD_ID": SID}
        self.assertEqual(ah_roles.launch_role(environ=codex, home=self.home), "supervisor")
        self.assertEqual(ah_roles.launch_role(environ={"CLAUDECODE": "1", "CLAUDE_CODE_SESSION_ID": OTHER},
                                              home=self.home), "worker")

    def test_an_unknown_ah_role_value_is_a_worker(self):
        for value in ("admin", "owner", "Owner", "", "supervisor;rm", "top-rung"):
            with self.subTest(value=value):
                self.assertEqual(ah_roles.launch_role(environ={"AH_ROLE": value}, home=self.home), "worker")
        for value in ah_roles.LAUNCH_ROLES:
            with self.subTest(value=value):
                self.assertEqual(ah_roles.launch_role(environ={"AH_ROLE": value}, home=self.home), value)
        self.assertEqual(ah_roles.launch_role(environ={"AH_ROLE": " Reviewer "}, home=self.home), "reviewer")

    def test_a_hook_payload_is_an_agent_even_without_markers(self):
        self.env()
        self.assertFalse(ah_roles.is_top_rung(self.payload(tool_name="Bash")))  # a tool call is an agent's
        payload = self.payload(hook_event_name="PreToolUse")
        self.assertFalse(ah_roles.is_top_rung(payload))
        self.assertFalse(ah_roles.may_delete(payload, self.elsewhere, home=self.home)[0])
        ah_roles.set_supervisor(SID, [str(self.proj)], home=self.home)
        self.assertTrue(ah_roles.is_supervisor(payload, home=self.home))

    def test_a_sub_agent_payload_is_never_the_owner(self):
        self.env()  # a hook process that sees no agent marker
        for key in ("agent_id", "agent_type"):
            with self.subTest(key=key):
                sub = self.payload(**{key: "abcd1234"})
                self.assertFalse(ah_roles.is_top_rung(sub))
                self.assertFalse(ah_roles.may_handle_secrets(sub))
                self.assertFalse(ah_roles.may_delete(sub, self.elsewhere, home=self.home)[0])
                self.assertEqual(ah_roles.describe(sub, home=self.home)["role"], "worker")

    def test_a_supervisors_sub_agent_is_not_a_supervisor(self):
        ah_roles.set_supervisor(SID, [str(self.proj)], home=self.home)
        self.env(AH_ROLE="supervisor", CLAUDECODE="1", CLAUDE_CODE_SESSION_ID=SID)
        self.assertTrue(ah_roles.is_supervisor(self.payload(), home=self.home))
        for key in ("agent_id", "agent_type"):
            with self.subTest(key=key):
                sub = self.payload(**{key: "abcd1234"})
                self.assertFalse(ah_roles.is_supervisor(sub, home=self.home))
                self.assertEqual(ah_roles.supervised_roots(sub, home=self.home), [])
                self.assertFalse(ah_roles.may_handle_secrets(sub))


class Predicates(Base):
    def test_supervisor_by_launch_uses_its_own_entry_else_the_role_default(self):
        self.env(AH_ROLE="supervisor", CLAUDECODE="1", CLAUDE_CODE_SESSION_ID=SID)
        payload = self.payload()
        self.assertTrue(ah_roles.is_supervisor(payload, home=self.home))
        self.assertEqual(ah_roles.supervised_roots(payload, home=self.home), [])
        ah_roles.set_role_default([str(self.proj)], home=self.home)
        self.assertEqual(ah_roles.supervised_roots(payload, home=self.home), [self.proj])
        inside = self.proj / "build" / "x"
        self.assertTrue(ah_roles.may_delete(payload, inside, home=self.home)[0])
        self.assertFalse(ah_roles.may_delete(payload, self.elsewhere, home=self.home)[0])
        other = self.home / "other"
        ah_roles.set_supervisor(SID, [str(other)], home=self.home)  # its own entry replaces the default
        self.assertEqual(ah_roles.supervised_roots(payload, home=self.home), [other])
        self.assertTrue(ah_roles.may_handle_secrets(payload))
        self.assertTrue(ah_roles.is_top_rung(payload))

    def test_worker_and_reviewer_delete_only_their_own_roots(self):
        ah_roles.set_role_default([str(self.proj)], home=self.home)
        made = self.home / "checkout"
        made.mkdir()
        for role in ("worker", "reviewer"):
            with self.subTest(role=role):
                self.env(AH_ROLE=role, CLAUDECODE="1", CLAUDE_CODE_SESSION_ID=SID)
                payload = self.payload()
                self.assertTrue(ah_roles.may_delete(payload, self.own(), home=self.home)[0])
                self.assertFalse(ah_roles.may_delete(payload, self.proj / "x", home=self.home)[0])
                self.assertTrue(ah_roles.may_delete(payload, made / "y", extra_own_roots=[made], home=self.home)[0])
                root = self.home / ".agent-harness" / "work" / SID
                self.assertFalse(ah_roles.may_delete(payload, root.parent, home=self.home)[0])

    def test_may_edit_harness_needs_the_flag_and_an_owner_approval(self):
        ah_roles.set_supervisor(SID, [str(self.proj)], home=self.home)
        self.env(AH_ROLE="supervisor", CLAUDECODE="1", CLAUDE_CODE_SESSION_ID=SID)
        payload = self.payload()
        self.assertFalse(ah_roles.may_edit_harness(payload, home=self.home))  # no flag, no approval
        data = ah_roles.load_roles(self.home)
        data["supervisors"][SID]["harness"] = True
        ah_roles.save_roles(data, self.home)
        self.assertFalse(ah_roles.may_edit_harness(payload, home=self.home))  # flag, no approval
        record = ah_approvals.grant("harness", {"what": "sandbox_base.json"}, "user", "tune", home=self.home)
        self.assertTrue(ah_roles.may_edit_harness(payload, home=self.home))
        ah_approvals.revoke(record["id"], "user", home=self.home)
        self.assertFalse(ah_roles.may_edit_harness(payload, home=self.home))
        ah_approvals.grant("harness", {}, "user", "standing", home=self.home)
        self.assertTrue(ah_roles.may_edit_harness(payload, home=self.home))
        os.environ["AH_ROLE"] = "worker"  # same session, same flag, launched as a worker
        self.assertFalse(ah_roles.may_edit_harness(payload, home=self.home))

    def test_no_authority_reads_a_model_or_a_transcript(self):
        self.env(CLAUDECODE="1", CLAUDE_CODE_SESSION_ID=SID)
        ah_roles.set_supervisor(SID, [str(self.proj)], home=self.home)
        boom = mock.Mock(side_effect=AssertionError("an authority read the model"))
        with mock.patch.object(ah_roles, "caller_model", boom), mock.patch.object(ah_roles, "_last_model", boom):
            for payload in (self.payload(), self.payload(transcript_path=str(self.home / "missing.jsonl")),
                            {"session_id": SID}):
                with self.subTest(payload=payload):
                    self.assertTrue(ah_roles.is_top_rung(payload))
                    self.assertTrue(ah_roles.is_supervisor(payload, home=self.home))
                    self.assertTrue(ah_roles.may_handle_secrets(payload))
                    self.assertTrue(ah_roles.may_delete(payload, self.proj / "x", home=self.home)[0])
                    self.assertFalse(ah_roles.may_edit_harness(payload, home=self.home))

    def test_is_top_rung_gives_the_same_answer_with_or_without_a_fable_transcript(self):
        missing = self.payload(transcript_path=str(self.home / "missing.jsonl"))
        for environ in ({}, {"CLAUDECODE": "1"}, {"AH_ROLE": "worker"}, {"AH_ROLE": "supervisor", "CLAUDECODE": "1"}):
            with self.subTest(environ=environ):
                self.env(**environ)
                self.assertEqual(ah_roles.is_top_rung(self.payload()), ah_roles.is_top_rung(missing))

    def test_describe_names_the_role_and_its_source(self):
        self.env(AH_ROLE="worker", AH_ROLE_SOURCE="ah-sandbox:worker", CLAUDECODE="1")
        facts = ah_roles.describe(self.payload(), home=self.home)
        self.assertEqual((facts["role"], facts["role_source"]), ("worker", "ah-sandbox:worker"))
        self.assertEqual(facts["model"], FABLE)
        self.assertFalse(facts["top_rung"])
        self.env(AH_ROLE="supervisor", CLAUDECODE="1")
        self.assertEqual(ah_roles.describe({}, home=self.home)["role_source"], "AH_ROLE (no AH_ROLE_SOURCE)")
        self.env()
        self.assertEqual(ah_roles.describe({}, home=self.home)["role"], "owner")
        self.assertIn("no agent marker", ah_roles.describe({}, home=self.home)["role_source"])
        self.env(CLAUDECODE="1", CLAUDE_CODE_SESSION_ID=SID)
        ah_roles.set_supervisor(SID, [str(self.proj)], home=self.home)
        self.assertEqual(ah_roles.describe(self.payload(), home=self.home)["role_source"], "roles.json")
        self.env(CLAUDECODE="1", CLAUDE_CODE_SESSION_ID=OTHER)
        self.assertIn("least privilege", ah_roles.describe({}, home=self.home)["role_source"])


class RolesFile(Base):
    def test_the_role_default_entry_survives_load_and_save(self):
        entry = ah_roles.set_role_default([str(self.proj), str(self.proj)], harness=True, home=self.home)
        self.assertEqual((entry["projects"], entry["harness"]), ([str(self.proj)], True))
        ah_roles.set_supervisor(SID, [str(self.proj)], home=self.home)
        data = ah_roles.load_roles(self.home)
        self.assertEqual(data["supervisor"]["projects"], [str(self.proj)])
        self.assertIn(SID, data["supervisors"])
        self.assertEqual(ah_roles.supervisor_entry(OTHER, self.home)["projects"], [str(self.proj)])
        self.assertEqual(ah_roles.supervisor_entry(SID, self.home)["projects"], [str(self.proj)])
        self.assertEqual(oct(os.stat(self.home / ".agent-harness" / "roles.json").st_mode & 0o777), "0o600")

    def test_a_broken_roles_file_is_least_privilege(self):
        path = self.home / ".agent-harness" / "roles.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        for text in ("{", "[]", '{"supervisors": [1]}', '{"supervisor": "x"}'):
            with self.subTest(text=text):
                path.write_text(text)
                data = ah_roles.load_roles(self.home)
                self.assertEqual(data["supervisors"], {})
                self.assertEqual(ah_roles.supervisor_entry(SID, self.home), {})
                self.assertEqual(ah_roles.launch_role({"CLAUDECODE": "1", "CLAUDE_CODE_SESSION_ID": SID},
                                                      self.home), "worker")
        path.write_text('{"supervisor": {"projects": ["/p"]}}')  # a default entry without the sessions map
        self.assertEqual(ah_roles.load_roles(self.home)["supervisor"]["projects"], ["/p"])

    def test_signatures_other_modules_call_are_kept(self):
        import inspect
        expected = {
            "harness_off": ["home"], "caller_model": ["payload"], "is_top_rung": ["payload"],
            "is_supervisor": ["payload", "home"], "supervised_roots": ["payload", "home"],
            "own_roots": ["payload", "home"], "may_delete": ["payload", "path", "extra_own_roots", "home"],
            "may_handle_secrets": ["payload"], "may_edit_harness": ["payload", "home"],
            "cli_payload": ["environ", "home", "session", "agent"], "caller_transcript": ["payload"],
            "describe": ["payload", "home"], "launch_role": ["environ", "home"],
        }
        for name, params in expected.items():
            with self.subTest(name=name):
                self.assertEqual(list(inspect.signature(getattr(ah_roles, name)).parameters), params)


if __name__ == "__main__":
    unittest.main()
