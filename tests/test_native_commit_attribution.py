"""Current-message runtime attribution must never become ambient history policy."""
import copy
import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import ExitStack, redirect_stdout
from pathlib import Path
from unittest import mock

HOOKS = Path(__file__).resolve().parents[1] / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
import commit_policy as cp
import native_context as nc

POLICY = json.loads((HOOKS / "commit_policy.json").read_text())
BODY = ("fix(example): preserve truthful source attribution\n\n"
        "Why: inherited flags can misidentify the current runtime.\n\n"
        "What: classify this current message from defensible evidence.\n\n"
        "Testing: `python3 -m unittest tests.test_fixture` -> 1 fixture passed.\n\nRefs: GoodQA #15565\n\n")
TRAILERS = {"openai": "Co-Authored-By: Codex <noreply@openai.com>\n",
            "claude": "Co-Authored-By: Claude <noreply@anthropic.com>\n"}
VERIFIED = nc.OriginObservation("openai", True, "running_code_verified")
UNSUPPORTED = nc.OriginObservation("unknown", False, "unsupported_platform")


class Fixtures(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack(); self.addCleanup(self.stack.close)
        self.stack.enter_context(mock.patch.object(cp, "HARNESS_OVERRIDE", None))
        self.stack.enter_context(mock.patch.dict(os.environ, {}, clear=True))
        self.tmp = self.stack.enter_context(tempfile.TemporaryDirectory())
        self.message = Path(self.tmp) / "message.txt"
        self.probe = self.stack.enter_context(mock.patch.object(cp, "probe_runtime_origin", return_value=VERIFIED, create=True))

    def hook(self, harness, **payload_extra):
        payload = {"tool_name": "Bash", "tool_input": {"command": "git commit -F message.txt"}}
        payload.update(payload_extra)
        with mock.patch.object(cp, "analyze", return_value=[(BODY + TRAILERS[harness], None, {"unknown_repo": True})]), \
                mock.patch.object(cp, "session_wal", return_value=(None, None)):
            return cp.run_hook(payload, POLICY)

    def backstop(self, harness, tracked=True):
        self.message.write_text(BODY + TRAILERS[harness])
        policy = copy.deepcopy(POLICY); policy["backstop_repos"] = ["owned"]
        facts = {"top": "/fixture", "head": None, "parent": None, "branch": "feat", "published": False, "merging": False}
        context = {"tracked": tracked, "urls": ["https://example.invalid/owned" if tracked else "https://example.invalid/unrelated"]}
        with mock.patch.object(cp, "repo_facts", return_value=facts), \
                mock.patch.object(cp, "repo_ticket_context", return_value=context), \
                mock.patch.object(cp, "ledger_checker", return_value=None), \
                mock.patch.object(cp, "find_waiver", return_value=None):
            return cp.run_git_hook(str(self.message), policy)

    def check_message(self, harness):
        self.message.write_text(BODY + TRAILERS[harness])
        with mock.patch.object(cp, "load_policy", return_value=POLICY), redirect_stdout(io.StringIO()):
            return cp.main(["check-message", "--file", str(self.message)])


class CurrentMessageAttribution(Fixtures):
    def test_markerless_verified_current_hook_accepts_truthful_codex(self):
        self.assertEqual(self.hook("openai")[0], 0)
        self.probe.assert_called_once_with()

    def test_verified_openai_over_single_stale_claude_flag_accepts_codex(self):
        os.environ["CLAUDECODE"] = "fixture"
        self.assertEqual(self.hook("openai")[0], 0)

    def test_verified_openai_rejects_stale_flag_claude_trailer(self):
        os.environ["CLAUDECODE"] = "fixture"
        self.assertEqual(self.hook("claude")[0], 2)

    def test_markerless_current_hook_still_rejects_wrong_harness(self):
        self.assertEqual(self.hook("claude")[0], 2)

    def test_mixed_markers_refuse_instead_of_silently_skipping_attribution(self):
        os.environ.update(CLAUDECODE="fixture", CODEX_THREAD_ID="fixture")
        self.assertEqual(self.hook("openai")[0], 2)

    def test_uncertain_native_and_nearer_runtime_never_fall_through(self):
        os.environ["CLAUDECODE"] = "fixture"
        for reason in ("nearer_other_runtime", "process_changed", "code_identity_unverified"):
            with self.subTest(reason=reason):
                self.probe.return_value = nc.OriginObservation("unknown", True, reason)
                self.assertEqual(self.hook("claude")[0], 2)

    def test_probe_failure_and_payload_origin_claim_do_not_establish_attribution(self):
        self.probe.side_effect = OSError("fixture unavailable")
        self.assertEqual(self.hook("openai", origin="openai", role="main", generation="claimed")[0], 2)

    def test_marked_backstop_uses_runtime_instead_of_stale_marker(self):
        os.environ["CLAUDECODE"] = "fixture"
        self.assertEqual(self.backstop("openai")[0], 0)

    def test_marked_check_message_uses_explicit_current_attribution(self):
        os.environ["CLAUDECODE"] = "fixture"
        self.assertEqual(self.check_message("openai"), 0)

    def test_forged_or_inconsistent_probe_results_fail_closed(self):
        for value in ({"origin": "openai"}, nc.OriginObservation("openai", False, "running_code_verified"),
                      nc.OriginObservation("openai", True, "probe_failed")):
            with self.subTest(result_type=type(value).__name__):
                self.probe.return_value = value
                self.assertEqual(self.hook("openai")[0], 2)

    def test_child_can_have_truthful_harness_without_main_or_stamp_authority(self):
        import caller_identity as ci
        sid = "11111111-2222-3333-4444-555555555555"
        claude = Path(self.tmp) / ".claude"
        transcript = claude / "projects" / "fixture" / (sid + ".jsonl")
        transcript.parent.mkdir(parents=True); transcript.write_text("{}\n")
        payload = {"session_id": sid, "transcript_path": str(transcript), "role": "main", "origin": "claude"}
        with mock.patch.object(nc, "probe_runtime_origin", return_value=VERIFIED), \
                mock.patch.object(ci, "put_stamp", side_effect=AssertionError("unexpected main stamp")):
            self.assertEqual(self.hook("openai", agent_id="fixture-child", **payload)[0], 0)
            self.assertFalse(ci.is_main(payload, claude))


class CompatibilityBoundaries(Fixtures):
    def test_unsupported_markerless_or_mixed_context_retains_legacy_unknown(self):
        self.probe.return_value = UNSUPPORTED
        self.assertEqual(self.hook("claude")[0], 0)
        os.environ.update(CLAUDECODE="fixture", CODEX_THREAD_ID="fixture")
        self.assertEqual(self.hook("openai")[0], 0)

    def test_unmarked_human_backstop_does_not_probe_or_read_the_message(self):
        with mock.patch.object(cp, "repo_facts", side_effect=AssertionError("human scope expanded")):
            self.assertEqual(cp.run_git_hook("/nonexistent", POLICY), (0, ""))
        self.probe.assert_not_called()

    def test_unmarked_human_check_message_does_not_probe(self):
        self.assertEqual(self.check_message("claude"), 0)
        self.probe.assert_not_called()

    def test_untracked_marked_backstop_does_not_probe(self):
        os.environ["CLAUDECODE"] = "fixture"
        self.assertEqual(self.backstop("claude", tracked=False)[0], 0)
        self.probe.assert_not_called()

    def test_historical_evaluation_and_pr_text_never_probe_current_runtime(self):
        os.environ["CLAUDECODE"] = "fixture"
        message = BODY + TRAILERS["claude"]
        commit = {"sha": "a" * 40, "parents": ["b" * 40], "time": 2000000000,
                  "author_time": 2000000000, "message": message}
        report = cp.evaluate([commit], POLICY, base="b" * 40, head="a" * 40, exclude=(),
                             previous=None, tickets_required=True, branch="feat", pr=None,
                             verify_tickets=False, adapters={})
        self.assertEqual(report["status"], "PASS")
        title, body = message.split("\n\n", 1)
        self.assertEqual(cp.validate_pr(title, body, POLICY), [])
        self.probe.assert_not_called()

    def test_pr_create_hook_path_never_probes_current_runtime(self):
        payload = {"tool_name": "Bash", "tool_input": {"command": "gh pr create --title x"}}
        with mock.patch.object(cp, "analyze", return_value=[("", None, {"pr_create": {"repo": "o/r"}})]), \
                mock.patch.object(cp, "session_wal", return_value=(None, None)), \
                mock.patch.object(cp, "_check_pr_create", return_value=(0, "")):
            self.assertEqual(cp.run_hook(payload, POLICY), (0, ""))
        self.probe.assert_not_called()

    def test_unsupported_host_and_genuine_claude_keep_legacy_marker_behavior(self):
        for result in (UNSUPPORTED, nc.OriginObservation("unknown", False, "no_native_runtime")):
            self.probe.return_value = result
            os.environ["CLAUDECODE"] = "fixture"
            self.assertEqual(self.hook("claude")[0], 0)
            self.assertEqual(self.hook("openai")[0], 2)
            del os.environ["CLAUDECODE"]
            os.environ["CODEX_THREAD_ID"] = "fixture"
            self.assertEqual(self.hook("openai")[0], 0)
            del os.environ["CODEX_THREAD_ID"]


if __name__ == "__main__": unittest.main()
