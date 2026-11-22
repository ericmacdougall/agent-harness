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
                        "root": "native-root", "proof": {"verified": True, "not_after": 5000}, "no_ci": False}
        self.binding_patch = patch.object(dispatch, "_binding", return_value=self.binding)
        self.binding_patch.start()
        self.addCleanup(self.binding_patch.stop)
        self.client = Mock()
        self.client.json.side_effect = self.read_ref

    def ref_rows(self, *, base=None, head=None):
        return [
            {"ref": "refs/heads/main", "object": {"type": "commit", "sha": base or self.args.base}},
            {"ref": "refs/heads/codex/candidate", "object": {"type": "commit", "sha": head or self.args.head}},
        ]

    def read_ref(self, arguments, _description):
        for row in self.ref_rows():
            if arguments == ["api", f"repos/owner/repo/git/ref/{row['ref'].removeprefix('refs/')}"]:
                return row
        raise AssertionError(f"unexpected ref read: {arguments}")

    def merge_projection(self):
        repository = {"full_name": "owner/repo"}
        return {"number": 17, "state": "open", "draft": False, "mergeable": True,
                "base": {"sha": self.args.base, "ref": "main", "repo": repository},
                "head": {"sha": self.args.head, "ref": "codex/candidate", "repo": repository}}

    @staticmethod
    def record_send_intent(_client, _context, *, require_live, before_send):
        before_send()
        require_live()

    def uncertain_send(self, client, context, **callbacks):
        self.record_send_intent(client, context, **callbacks)
        raise ValueError("uncertain")

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
        sender = Mock(side_effect=self.record_send_intent)
        with patch.object(dispatch.review, "native_call_still_running", side_effect=[True, False]):
            with self.assertRaisesRegex(ValueError, "not running"):
                dispatch.execute(self.args, self.client, "native-root", clock=lambda: 101, send=sender)
        sender.assert_called_once()
        self.assertEqual(self.read_journal()["phase"], "AUTHORIZED")

    def test_authorize_merge_readback_and_replay(self):
        self.assertEqual(self.authorize()["status"], "AUTHORIZED")
        self.args.action = "merge"
        self.client.json.side_effect = [self.merged_readback(),
                                        {"sha": "e" * 40, "parents": [{"sha": self.args.base}, {"sha": self.args.head}]},
                                        {"object": {"sha": "e" * 40}}]
        def send(client, context, *, require_live, before_send):
            # Inspect the fsynced journal directly, without taking its held lock.
            files = list((self.home / ".agent-harness/native-pr-releases").glob("*.json"))
            self.assertEqual(json.loads(files[0].read_text())["phase"], "AUTHORIZED")
            self.record_send_intent(client, context, require_live=require_live, before_send=before_send)
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
                             send=self.uncertain_send)
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
            dispatch.execute(self.args, self.client, "native-root", clock=lambda: 101, send=self.record_send_intent)
        self.assertEqual(self.read_journal()["phase"], "PENDING")

    def test_uncertain_release_can_only_reconcile_observed_completion(self):
        self.authorize()
        self.args.action = "merge"
        with self.assertRaises(ValueError):
            dispatch.execute(self.args, self.client, "native-root", clock=lambda: 101,
                             send=self.uncertain_send)
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
        self.client.json.side_effect = [self.merge_projection(), *self.ref_rows()]
        completed = SimpleNamespace(returncode=0, stdout='{"merged":true,"sha":"' + 'e' * 40 + '"}')
        with patch.object(dispatch.subprocess, "run", return_value=completed) as run:
            before_send, require_live = Mock(), Mock()
            dispatch.send_merge(self.client, self.binding["context"], require_live=require_live,
                                before_send=before_send)
        before_send.assert_called_once()
        require_live.assert_called_once()
        call = run.call_args
        self.assertEqual(call.args[0], ["/opt/homebrew/bin/gh", "api", "--hostname", "github.com", "--method", "PUT",
                                       "repos/owner/repo/pulls/17/merge", "--input", "-"])
        body = json.loads(call.kwargs["input"])
        self.assertEqual(body, {"sha": self.args.head, "merge_method": "merge"})
        self.client.json.side_effect = [self.merge_projection(), *self.ref_rows()]
        with patch.object(dispatch.subprocess, "run") as run:
            with self.assertRaisesRegex(ValueError, "call ended during read"):
                dispatch.send_merge(self.client, self.binding["context"],
                                    require_live=Mock(side_effect=ValueError("call ended during read")),
                                    before_send=Mock())
            run.assert_not_called()

    def test_base_race_is_detected_and_never_completed(self):
        self.authorize()
        self.args.action = "merge"
        self.client.json.side_effect = [self.merged_readback(),
            {"sha": "e" * 40, "parents": [{"sha": "f" * 40}, {"sha": self.args.head}]}]
        with self.assertRaisesRegex(ValueError, "completion is uncertain"):
            dispatch.execute(self.args, self.client, "native-root", clock=lambda: 101, send=self.record_send_intent)
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
            self.client.json.side_effect = [row]
            with patch.object(dispatch.subprocess, "run") as run:
                with self.assertRaisesRegex(ValueError, "not ready"):
                    dispatch.send_merge(self.client, self.binding["context"], require_live=Mock(), before_send=Mock())
                run.assert_not_called()

    def test_authorize_rechecks_live_refs_after_proof(self):
        for refs in (self.ref_rows(base="f" * 40), self.ref_rows(head="f" * 40)):
            self.client.json.side_effect = refs
            with self.assertRaisesRegex(ValueError, "authoritative GitHub"):
                self.authorize()
            self.assertIsNone(self.read_journal())

    def test_final_projection_cannot_mask_changed_live_refs(self):
        self.authorize()
        self.args.action = "merge"
        for refs in (self.ref_rows(base="f" * 40), self.ref_rows(head="f" * 40)):
            self.client.json.side_effect = [self.merge_projection(), *refs]
            with patch.object(dispatch.subprocess, "run") as run:
                with self.assertRaisesRegex(ValueError, "authoritative GitHub"):
                    dispatch.execute(self.args, self.client, "native-root", clock=lambda: 101)
                run.assert_not_called()
            self.assertEqual(self.read_journal()["phase"], "AUTHORIZED")

    def test_liveness_after_refs_and_after_fsync_precedes_transport(self):
        self.authorize()
        self.args.action = "merge"
        for states, phase in (([True, False], "AUTHORIZED"), ([True, True, False], "PENDING")):
            self.client.json.side_effect = [self.merge_projection(), *self.ref_rows()]
            with patch.object(dispatch.review, "native_call_still_running", side_effect=states), \
                 patch.object(dispatch.subprocess, "run") as run:
                with self.assertRaisesRegex(ValueError, "not running"):
                    dispatch.execute(self.args, self.client, "native-root", clock=lambda: 101)
                run.assert_not_called()
            self.assertEqual(self.read_journal()["phase"], phase)

    def test_proof_deadline_limits_the_grant_and_expiry_during_ref_reads_is_unsent(self):
        self.binding["proof"]["not_after"] = 110
        self.authorize()
        self.assertEqual(self.read_journal()["expires_at"], 110)
        self.args.action = "merge"
        current = [101]
        statuses = iter([self.merge_projection(), *self.ref_rows()])

        def read_then_expire(_args, description):
            row = next(statuses)
            if description == "the authoritative source ref":
                current[0] = 110
            return row

        self.client.json.side_effect = read_then_expire
        with patch.object(dispatch.subprocess, "run") as run:
            with self.assertRaisesRegex(ValueError, "expired"):
                dispatch.execute(self.args, self.client, "native-root", clock=lambda: current[0])
            run.assert_not_called()
        self.assertEqual(self.read_journal()["phase"], "AUTHORIZED")

    def test_invalid_proof_deadlines_cannot_create_a_lease(self):
        for invalid in (None, "110", True, float("inf"), float("-inf"), float("nan"), 100):
            self.binding["proof"]["not_after"] = invalid
            with self.subTest(deadline=invalid), self.assertRaisesRegex(ValueError, "proof expired"):
                self.authorize()
            self.assertIsNone(self.read_journal())

    def test_expiry_after_fsync_leaves_pending_and_refuses_send(self):
        self.binding["proof"]["not_after"] = 110
        self.authorize()
        self.args.action = "merge"
        self.client.json.side_effect = [self.merge_projection(), *self.ref_rows()]
        current = [101]
        original_save = dispatch.save

        def save_then_expire(path, value):
            original_save(path, value)
            if value["phase"] == "PENDING":
                current[0] = 110

        with patch.object(dispatch, "save", side_effect=save_then_expire), \
             patch.object(dispatch.subprocess, "run") as run:
            with self.assertRaisesRegex(ValueError, "expired"):
                dispatch.execute(self.args, self.client, "native-root", clock=lambda: current[0])
            run.assert_not_called()
        self.assertEqual(self.read_journal()["phase"], "PENDING")
        with self.assertRaisesRegex(ValueError, "submitted already"):
            dispatch.execute(self.args, self.client, "native-root", clock=lambda: 111)

    def test_expiry_while_refreshing_proof_cannot_record_send_intent(self):
        self.binding["proof"]["not_after"] = 110
        self.authorize()
        self.args.action = "merge"
        current = [101]
        refreshes = 0

        def expire_during_second_proof(*_args):
            nonlocal refreshes
            refreshes += 1
            if refreshes == 2:
                current[0] = 110
            return self.binding

        self.client.json.side_effect = [self.merge_projection(), *self.ref_rows()]
        with patch.object(dispatch, "_binding", side_effect=expire_during_second_proof), \
             patch.object(dispatch.subprocess, "run") as run:
            with self.assertRaisesRegex(ValueError, "expired"):
                dispatch.execute(self.args, self.client, "native-root", clock=lambda: current[0])
            run.assert_not_called()
        self.assertEqual(refreshes, 2)
        self.assertEqual(self.read_journal()["phase"], "AUTHORIZED")

    def test_sender_must_record_exactly_one_durable_intent(self):
        self.authorize()
        self.args.action = "merge"
        with self.assertRaisesRegex(ValueError, "without recording"):
            dispatch.execute(self.args, self.client, "native-root", clock=lambda: 101, send=Mock())
        self.assertEqual(self.read_journal()["phase"], "AUTHORIZED")

        def duplicate(_client, _context, *, require_live, before_send):
            before_send()
            before_send()

        with self.assertRaisesRegex(ValueError, "already recorded"):
            dispatch.execute(self.args, self.client, "native-root", clock=lambda: 101, send=duplicate)
        self.assertEqual(self.read_journal()["phase"], "PENDING")


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
