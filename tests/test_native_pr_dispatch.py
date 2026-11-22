"""Refusal and transaction contracts for direct native PR operations."""
from pathlib import Path
from types import SimpleNamespace
import json
import os
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "harness/hooks"))
import native_pr_dispatch as dispatch
import merge_gate


class Dispatch(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.home = Path(self.temporary.name)
        self.home.chmod(0o700)
        self.home_patch = patch.object(Path, "home", return_value=self.home)
        self.home_patch.start()
        self.addCleanup(self.home_patch.stop)
        self.args = SimpleNamespace(action="authorize", github_repo="owner/repo", pr=17,
                                    head="a" * 40, base="b" * 40, native_binding={"session": "native-root"})
        self.live_patch = patch.object(dispatch.review, "native_call_still_running", return_value=True)
        self.live_patch.start()
        self.addCleanup(self.live_patch.stop)
        self.binding = {"context": {"repo": "owner/repo", "pr": 17, "head": "a" * 40,
                                    "base": "b" * 40, "base_ref": "main", "head_ref": "codex/candidate"},
                        "root": "native-root", "proof": {"verified": True}, "no_ci": False}
        self.binding_patch = patch.object(dispatch, "_binding", return_value=self.binding)
        self.binding_patch.start()
        self.addCleanup(self.binding_patch.stop)
        self.client = Mock()

    def read_journal(self):
        with dispatch.journal(self.args.github_repo, self.args.pr) as path:
            return dispatch.load(path)

    def authorize(self):
        self.args.context_sha256 = "c" * 64
        return dispatch.execute(self.args, self.client, "native-root", clock=lambda: 100)

    def merged_readback(self):
        return {"merged": True, "merge_commit_sha": "e" * 40,
                "base": {"ref": "main", "repo": {"full_name": "owner/repo"}},
                "head": {"sha": self.args.head, "ref": "codex/candidate",
                                         "repo": {"full_name": "owner/repo"}}}

    def test_requires_prior_grant_before_any_send(self):
        self.args.action = "merge"
        sender = Mock()
        with self.assertRaisesRegex(ValueError, "grant"):
            dispatch.execute(self.args, self.client, "native-root", send=sender)
        sender.assert_not_called()

    def test_ended_call_cannot_authorize_or_send(self):
        with patch.object(dispatch.review, "native_call_still_running", return_value=False):
            with self.assertRaisesRegex(ValueError, "not running"):
                self.authorize()
        self.assertIsNone(self.read_journal())
        self.authorize()
        self.args.action = "merge"
        sender = Mock()
        with patch.object(dispatch.review, "native_call_still_running", side_effect=[True, False]):
            with self.assertRaisesRegex(ValueError, "not running"):
                dispatch.execute(self.args, self.client, "native-root", clock=lambda: 101, send=sender)
        sender.assert_not_called()
        self.assertEqual(self.read_journal()["phase"], "PENDING")

    def test_authorize_merge_readback_and_replay(self):
        self.assertEqual(self.authorize()["status"], "AUTHORIZED")
        self.args.action = "merge"
        self.client.json.side_effect = [self.merged_readback(),
                                        {"sha": "e" * 40, "parents": [{"sha": self.args.base}, {"sha": self.args.head}]},
                                        {"object": {"sha": "e" * 40}}]
        def send(client, context, *, require_live):
            # Inspect the fsynced journal directly, without taking its held lock.
            files = list((self.home / ".agent-harness/native-pr-releases").glob("*.json"))
            self.assertEqual(json.loads(files[0].read_text())["phase"], "PENDING")
        self.assertEqual(dispatch.execute(self.args, self.client, "native-root", clock=lambda: 101,
                                          send=send)["status"], "MERGED")
        self.assertEqual(self.read_journal()["phase"], "COMPLETE")
        with self.assertRaisesRegex(ValueError, "submitted already"):
            dispatch.execute(self.args, self.client, "native-root", clock=lambda: 102, send=Mock())

    def test_failed_or_uncertain_send_cannot_be_retried(self):
        self.authorize()
        self.args.action = "merge"
        with self.assertRaisesRegex(ValueError, "uncertain"):
            dispatch.execute(self.args, self.client, "native-root", clock=lambda: 101,
                             send=Mock(side_effect=ValueError("uncertain")))
        self.assertEqual(self.read_journal()["phase"], "PENDING")
        with self.assertRaisesRegex(ValueError, "submitted already"):
            dispatch.execute(self.args, self.client, "native-root", clock=lambda: 102, send=Mock())

    def test_expired_changed_or_drifted_grant_never_sends(self):
        self.authorize()
        self.args.action = "merge"
        sender = Mock()
        with self.assertRaisesRegex(ValueError, "fresh"):
            dispatch.execute(self.args, self.client, "native-root", clock=lambda: 2000, send=sender)
        sender.assert_not_called()
        changed = {**self.binding, "root": "other"}
        with patch.object(dispatch, "_binding", side_effect=[self.binding, changed]):
            with self.assertRaisesRegex(ValueError, "changed at consumption"):
                dispatch.execute(self.args, self.client, "native-root", clock=lambda: 101, send=sender)
        sender.assert_not_called()

    def test_post_send_readback_mismatch_preserves_pending(self):
        self.authorize()
        self.args.action = "merge"
        self.client.json.side_effect = [{"merged": False, "head": {"sha": self.args.head}},
                                        {"object": {"sha": self.args.base}}]
        with self.assertRaisesRegex(ValueError, "completion is uncertain"):
            dispatch.execute(self.args, self.client, "native-root", clock=lambda: 101, send=Mock())
        self.assertEqual(self.read_journal()["phase"], "PENDING")

    def test_uncertain_release_can_only_reconcile_observed_completion(self):
        self.authorize()
        self.args.action = "merge"
        with self.assertRaises(ValueError):
            dispatch.execute(self.args, self.client, "native-root", clock=lambda: 101,
                             send=Mock(side_effect=ValueError("uncertain")))
        self.args.action = "reconcile"
        self.client.json.side_effect = [self.merged_readback(),
                                       {"sha": "e" * 40, "parents": [{"sha": self.args.base}, {"sha": self.args.head}]},
                                       {"object": {"sha": "e" * 40}}]
        with patch.object(dispatch.review, "context_digest", return_value=self.args.context_sha256), \
             patch.object(dispatch, "send_merge") as sender:
            self.assertEqual(dispatch.execute(self.args, self.client, "native-root", clock=lambda: 102)["status"],
                             "MERGED")
            sender.assert_not_called()
        self.assertEqual(self.read_journal()["phase"], "COMPLETE")

    def test_main_cli_without_hook_stamp_has_no_authority(self):
        arguments = ["authorize", "--repo", "/fixture", "--github-repo", "owner/repo", "--pr", "17",
                     "--head", "a" * 40, "--base", "b" * 40, "--packet", "/packet", "--tests", "/tests",
                     "--bundle", "/bundle", "--context-sha256", "c" * 64, "--bundle-sha256", "d" * 64]
        with patch.object(dispatch.caller_identity, "take_stamp", return_value=None), \
             patch.object(dispatch, "execute") as execute:
            self.assertEqual(dispatch.main(arguments), 3)
            execute.assert_not_called()

    def test_state_symlink_and_world_writable_state_refuse(self):
        root = self.home / ".agent-harness/native-pr-releases"
        root.parent.mkdir(mode=0o700)
        elsewhere = self.home / "elsewhere"
        elsewhere.mkdir()
        root.symlink_to(elsewhere, target_is_directory=True)
        with self.assertRaises(ValueError):
            self.authorize()
        self.assertEqual(list(elsewhere.iterdir()), [])

    def test_normal_pr_operation_pins_head_without_bypass(self):
        self.client.json.return_value = {"state": "open", "draft": False, "mergeable": True,
                                        "base": {"sha": self.args.base, "ref": "main"},
                                        "head": {"sha": self.args.head, "ref": "codex/candidate",
                                                 "repo": {"full_name": "owner/repo"}}}
        completed = SimpleNamespace(returncode=0, stdout='{"merged":true,"sha":"' + 'e' * 40 + '"}')
        with patch.object(dispatch.subprocess, "run", return_value=completed) as run:
            dispatch.send_merge(self.client, self.binding["context"], require_live=Mock())
        call = run.call_args
        self.assertEqual(call.args[0], ["/opt/homebrew/bin/gh", "api", "--hostname", "github.com", "--method", "PUT",
                                       "repos/owner/repo/pulls/17/merge", "--input", "-"])
        body = json.loads(call.kwargs["input"])
        self.assertEqual(body, {"sha": self.args.head, "merge_method": "merge"})
        self.client.json.return_value = {"state": "open", "draft": False, "mergeable": True,
            "base": {"sha": self.args.base, "ref": "main"},
            "head": {"sha": self.args.head, "ref": "codex/candidate", "repo": {"full_name": "owner/repo"}}}
        with patch.object(dispatch.subprocess, "run") as run:
            with self.assertRaisesRegex(ValueError, "call ended during read"):
                dispatch.send_merge(self.client, self.binding["context"],
                                    require_live=Mock(side_effect=ValueError("call ended during read")))
            run.assert_not_called()

    def test_base_race_is_detected_and_never_completed(self):
        self.authorize()
        self.args.action = "merge"
        self.client.json.side_effect = [self.merged_readback(),
            {"sha": "e" * 40, "parents": [{"sha": "f" * 40}, {"sha": self.args.head}]}]
        with self.assertRaisesRegex(ValueError, "completion is uncertain"):
            dispatch.execute(self.args, self.client, "native-root", clock=lambda: 101, send=Mock())
        self.assertEqual(self.read_journal()["phase"], "PENDING")

    def test_target_must_still_contain_the_verified_merge(self):
        for status in ("ahead", "diverged"):
            self.client.json.side_effect = [self.merged_readback(),
                {"sha": "e" * 40, "parents": [{"sha": self.args.base}, {"sha": self.args.head}]},
                {"object": {"sha": "f" * 40}},
                {"base_commit": {"sha": "e" * 40}, "merge_base_commit": {"sha": "e" * 40}, "status": status}]
            if status == "ahead":
                dispatch._confirm_remote(self.args, self.client, self.binding["context"])
            else:
                with self.assertRaisesRegex(ValueError, "no longer contains"):
                    dispatch._confirm_remote(self.args, self.client, self.binding["context"])

    def test_draft_or_changed_base_cannot_use_transport(self):
        for row in ({"state": "open", "draft": True, "mergeable": True},
                    {"state": "open", "draft": False, "mergeable": None}):
            self.client.json.return_value = row
            with patch.object(dispatch.subprocess, "run") as run:
                with self.assertRaisesRegex(ValueError, "not ready"):
                    dispatch.send_merge(self.client, self.binding["context"], require_live=Mock())
                run.assert_not_called()


class DirectCommand(unittest.TestCase):
    def test_closed_command_shape(self):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            helper = home / ".codex/agent-harness/native_pr_dispatch.py"
            helper.parent.mkdir(parents=True)
            helper.write_text("# fixture helper\n")
            command = (f"/usr/bin/python3 {helper} authorize --repo /fixture --github-repo owner/repo --pr 17 "
                       f"--head {'a' * 40} --base {'b' * 40} --packet /packet --tests /tests --bundle /bundle "
                       f"--context-sha256 {'c' * 64} --bundle-sha256 {'d' * 64}")
            self.assertIsNotNone(dispatch.direct_args(command, home))
            for broken in (command + " --pr 18", command + "; true", "env " + command,
                           command.replace("--tests /tests", "--unknown /tests")):
                self.assertIsNone(dispatch.direct_args(broken, home))

    def test_hook_refuses_child_and_unproven_root(self):
        command = "python3 /fixture/native_pr_dispatch.py authorize --fixture value"
        for actor in ({"agent_id": "child"}, {}):
            payload = {"tool_name": "Bash", "tool_input": {"command": command}, **actor}
            with patch.object(dispatch, "direct_args", return_value=Mock()), \
                 patch("native_main.is_desktop_review_root", return_value=False):
                code, message = merge_gate.decide(payload, Mock(), Path("/unused"))
            self.assertEqual(code, 2)
            self.assertIn("verified Desktop main", message)


if __name__ == "__main__":
    unittest.main()
