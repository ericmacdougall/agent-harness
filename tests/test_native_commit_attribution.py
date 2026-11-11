"""Current-message runtime attribution must never become ambient history policy."""
import copy
import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import ExitStack, redirect_stdout
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
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
            "claude": "Co-Authored-By: Claude <noreply@anthropic.com>\n",
            "person": "Co-Authored-By: Test Person <person@example.invalid>\n",
            None: ""}
VERIFIED = nc.OriginObservation("openai", True, "running_code_verified")
UNSUPPORTED = nc.OriginObservation("unknown", False, "unsupported_platform")


class Fixtures(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack(); self.addCleanup(self.stack.close)
        self.stack.enter_context(mock.patch.object(cp, "HARNESS_OVERRIDE", None))
        self.stack.enter_context(mock.patch.dict(os.environ, {}, clear=True))
        self.tmp = self.stack.enter_context(tempfile.TemporaryDirectory())
        self.message = Path(self.tmp) / "message.txt"
        self.probe = self.stack.enter_context(mock.patch.object(cp, "probe_commit_runtime_origin", return_value=VERIFIED))

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
    def test_uncertain_origin_only_blocks_messages_that_claim_a_harness(self):
        os.environ["CLAUDECODE"] = "fixture"
        for reason, native in (("probe_failed", False), ("nearer_other_runtime", True)):
            self.probe.return_value = nc.OriginObservation("unknown", native, reason)
            for entry, refusal in ((self.hook, 2), (self.backstop, 1), (self.check_message, 2)):
                for claim in (None, "person", "claude", "openai"):
                    with self.subTest(reason=reason, entry=entry.__name__, claim=claim):
                        result = entry(claim)
                        code = result[0] if isinstance(result, tuple) else result
                        self.assertEqual(code, refusal if claim in ("claude", "openai") else 0, result)

    def test_verified_claude_admits_its_own_claim_only(self):
        self.probe.return_value = nc.OriginObservation("claude", False, "running_claude_code_verified")
        self.assertEqual(self.hook("claude")[0], 0)
        os.environ["CLAUDECODE"] = "fixture"
        self.assertEqual(self.hook("claude")[0], 0)
        self.assertEqual(self.hook("openai")[0], 2)
        self.assertEqual(self.backstop("claude")[0], 0)
        self.assertEqual(self.check_message("claude"), 0)
        os.environ["CODEX_THREAD_ID"] = "fixture"
        self.assertEqual(self.hook("claude")[0], 2)
        self.assertEqual(self.hook(None)[0], 0)
        del os.environ["CLAUDECODE"]
        self.assertEqual(self.hook("claude")[0], 2)

    def test_trailer_free_still_needs_ticket_and_ordinary_policy(self):
        self.probe.return_value = nc.OriginObservation("unknown", False, "probe_failed")
        attribution = cp.current_commit_attribution()
        self.assertTrue(attribution.blocked)
        no_ticket = BODY.replace("GoodQA #15565", "none (fixture)")
        self.assertTrue(any("Refs: fix commits must reference a ticket" in problem for problem in
                            cp.validate(no_ticket, policy=POLICY, attribution=attribution)))
        misplaced = BODY.replace("Refs:", TRAILERS["claude"] + "Refs:")
        self.assertTrue(any("move Co-Authored-By" in problem for problem in
                            cp.validate(misplaced, policy=POLICY, attribution=attribution)))

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


class CommitRuntimeProbe(unittest.TestCase):
    class Chain:
        def __init__(self):
            self.processes = {
                10: nc.ProcessIdentity(10, 20, 1000, 1, "/usr/bin/python3"),
                20: nc.ProcessIdentity(20, 30, 1000, 2, "/bin/claude"),
            }
            self.codes = {20: nc.CodeIdentity("com.anthropic.claude-code", "Q6L2SF6YDW",
                                               "a" * 40, "/bin/claude")}

        def process(self, pid):
            if pid not in self.processes:
                raise OSError("unreadable ancestor")
            return self.processes[pid]

        def signature(self, pid):
            return self.codes.get(pid)

        def terminal_login_identity(self, pid):
            raise OSError("not a login boundary")

        def outer_codex(self):
            self.processes[30] = nc.ProcessIdentity(30, 1, 1000, 3, "/bin/codex")
            self.codes[30] = nc.CodeIdentity("codex", nc.OPENAI_TEAM, "b" * 40, "/bin/codex")

    def test_proven_nearest_claude_does_not_need_outer_ancestor(self):
        for outer in (False, True):
            with self.subTest(outer_codex=outer):
                chain = self.Chain()
                if outer:
                    chain.outer_codex()
                with mock.patch.object(chain, "process", wraps=chain.process) as process:
                    result = nc.probe_commit_runtime_origin(10, backend=chain)
                self.assertEqual((result.origin, result.reason, result.runtime_pid),
                                 ("claude", "running_claude_code_verified", 20))
                self.assertFalse(result.main_authority)
                self.assertFalse(result.strong_user_source)
                self.assertNotIn(mock.call(30), process.call_args_list)
                generic = nc.probe_runtime_origin(10, backend=chain)
                self.assertEqual(generic.reason, "nearer_other_runtime" if outer else "probe_failed")
                self.assertEqual(generic.native_lineage, outer)

    def test_renamed_claude_and_lower_signed_codex(self):
        chain = self.Chain()
        chain.processes[20] = replace(chain.processes[20], executable="/bin/renamed")
        chain.codes[20] = replace(chain.codes[20], executable="/bin/renamed")
        self.assertEqual(nc.probe_commit_runtime_origin(10, backend=chain).origin, "claude")
        chain.processes[10] = replace(chain.processes[10], executable="/bin/codex")
        chain.codes[10] = nc.CodeIdentity("codex", nc.OPENAI_TEAM, "b" * 40, "/bin/codex")
        self.assertEqual(nc.probe_commit_runtime_origin(10, backend=chain).origin, "openai")

    def test_nearer_unverified_names_never_establish_origin(self):
        for name in ("claude", "kimi", "codex"):
            with self.subTest(name=name):
                chain = self.Chain()
                chain.processes[10] = replace(chain.processes[10], executable="/bin/" + name)
                self.assertEqual(nc.probe_commit_runtime_origin(10, backend=chain).origin, "unknown")
                chain.codes.clear()
                chain.outer_codex()
                result = nc.probe_commit_runtime_origin(10, backend=chain)
                self.assertEqual(result.origin, "unknown")
                self.assertTrue(result.native_lineage)

    def test_invalid_identity_and_late_changes_do_not_prove_claude(self):
        for fields in ({"identifier": "other"}, {"team": "other"}, {"cdhash": "invalid"},
                       {"executable": "/bin/different"}):
            with self.subTest(fields=fields):
                chain = self.Chain()
                chain.processes[20] = replace(chain.processes[20], parent=1)
                chain.codes[20] = replace(chain.codes[20], **fields)
                self.assertEqual(nc.probe_commit_runtime_origin(10, backend=chain).reason, "code_identity_unverified")
        chain = self.Chain()
        with mock.patch.object(chain, "signature", side_effect=OSError("unavailable guest")):
            self.assertEqual(nc.probe_commit_runtime_origin(10, backend=chain).reason, "probe_failed")
        for kind in ("code", "process"):
            with self.subTest(kind=kind):
                chain = self.Chain()
                original = chain.signature

                def change(pid):
                    code = original(pid)
                    if pid == 20 and kind == "process":
                        chain.processes[20] = replace(chain.processes[20], started=99)
                    if pid == 20 and kind == "code":
                        chain.codes[20] = replace(chain.codes[20], cdhash="c" * 40)
                    return code

                chain.signature = change
                result = nc.probe_commit_runtime_origin(10, backend=chain)
                self.assertEqual(result.reason, "process_changed" if kind == "process" else "code_identity_unverified")

    def test_checked_login_edges_remain_required_before_claude_proof(self):
        from tests.test_native_context import TerminalLoginEndsTheWalk

        chain = TerminalLoginEndsTheWalk.Chain()
        chain.processes[40] = replace(chain.processes[40], executable="/bin/claude")
        claude = self.Chain().codes[20]
        chain.signature = lambda pid: claude if pid == 40 else None
        self.assertEqual(nc.probe_commit_runtime_origin(10, backend=chain).origin, "claude")
        self.assertEqual(nc.probe_runtime_origin(10, backend=chain).reason, "no_native_runtime")
        original = chain.process_generation

        def wrong_parent_link(pid):
            generation = original(pid)
            return replace(generation, unique_id=999) if pid == 40 else generation

        chain.process_generation = wrong_parent_link
        self.assertEqual(nc.probe_commit_runtime_origin(10, backend=chain).reason, "probe_failed")

    def test_only_commit_backend_tries_second_fixed_requirement_on_mismatch(self):
        def pointer(*args):
            args[-1]._obj.value = 1
            return 0

        claude = ('anchor apple generic and identifier "com.anthropic.claude-code" '
                  'and certificate leaf[subject.OU] = "Q6L2SF6YDW"')
        cases = ((nc.DarwinBackend, [-67050], [nc.CODE_REQUIREMENT], False),
                 (nc._CommitDarwinBackend, [-67050, -67062], [nc.CODE_REQUIREMENT, claude], False),
                 (nc._CommitDarwinBackend, [-1], [nc.CODE_REQUIREMENT], True))
        for backend_type, statuses, requirements, raises in cases:
            with self.subTest(backend=backend_type.__name__, statuses=statuses):
                backend = backend_type.__new__(backend_type)
                backend._constant = lambda _name: 1
                backend.cf = SimpleNamespace(CFNumberCreate=mock.Mock(return_value=1),
                                             CFDictionaryCreate=mock.Mock(return_value=1),
                                             CFStringCreateWithCString=mock.Mock(return_value=1),
                                             CFRelease=mock.Mock())
                backend.sec = SimpleNamespace(SecCodeCopyGuestWithAttributes=pointer,
                                              SecRequirementCreateWithString=pointer,
                                              SecCodeCheckValidity=mock.Mock(side_effect=statuses))
                if raises:
                    with self.assertRaisesRegex(OSError, "running code verification refused"):
                        backend.signature(20)
                else:
                    self.assertIsNone(backend.signature(20))
                self.assertEqual([call.args[1].decode() for call in backend.cf.CFStringCreateWithCString.call_args_list],
                                 requirements)


if __name__ == "__main__": unittest.main()
