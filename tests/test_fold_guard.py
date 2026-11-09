"""Fold guard (GoodQA #15565): wont_fix / duplicate / archive of a ticket with unfinished work is refused.

The tracker is an in-process fake behind sf.resolve_issue, so the focused suite never touches the network.
"""

import json
import os
import sys
import tempfile
import time
import unittest
import uuid
from pathlib import Path
from unittest import mock

HOOKS = Path(__file__).resolve().parents[1] / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
import fold_guard  # noqa: E402
import spec_flow as sf  # noqa: E402

PROJECT = "00000000-0000-4000-8000-0000000000a1"
SRC = "4e8e73fb-72e2-4604-bff5-56b75e4420f5"
UMB = "5e8e73fb-72e2-4604-bff5-56b75e4420f6"


class FakeAdapter:
    def __init__(self, issues, comments):
        self.issues, self.comments = issues, comments
        self.lookups = []

    def lookup(self, slug, number):
        self.lookups.append((slug, number))
        return next((i for i in self.issues.values() if i["number"] == number and slug == "harness"), None)

    def all_comments(self, issue_id):
        return self.comments.get(issue_id, [])

    def attachments(self, issue_id):
        return []


def issue(number, **kw):
    base = {"id": SRC if number == 14518 else UMB, "number": number, "status": "in_progress", "projectId": PROJECT,
            "description": "", "closedAt": None, "priority": "medium"}
    base.update(kw)
    return base


class FoldCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.home = Path(self.tmp)
        self.src = issue(14518)
        self.umb = issue(15529, description="Umbrella")
        self.comments = {SRC: [], UMB: []}
        self.adapter = FakeAdapter({SRC: self.src, UMB: self.umb}, self.comments)
        self.patches = [
            mock.patch.object(sf, "ticket_config", lambda _p: (None, None, {})),
            mock.patch.object(sf, "resolve_issue", lambda iid, *a, **k: (self.adapter, self.adapter.issues.get(iid))),
            mock.patch.dict(os.environ, {"HOME": self.tmp}),
        ]
        for p in self.patches:
            p.start()
        self.policy = {"mode": "off", "fold_guard": "enforce", "projects": {"harness": {"project_id": PROJECT}}}

    def tearDown(self):
        for p in reversed(self.patches):
            p.stop()

    def hook(self, tool, tool_input, **policy):
        pol = dict(self.policy, **policy)
        return sf.run_hook({"tool_name": f"mcp__plugin_goodqa_goodqa__{tool}", "tool_input": tool_input}, pol)

    def wont_fix(self, note="superseded by the umbrella ticket for the whole stream", **policy):
        return self.hook("close_issue_wont_fix", {"issueId": SRC, "note": note}, **policy)

    def comment(self, issue_id, body):
        self.comments[issue_id].append({"id": str(uuid.uuid4()), "body": body})

    # ---- AC1: the three unfinished-work signals block

    def test_p0_without_done_live_is_refused(self):
        self.src["priority"] = "immediate"
        code, text = self.wont_fix()
        self.assertEqual(code, 2, text)
        self.assertIn("priority is immediate", text)

    def test_unchecked_acceptance_item_is_refused(self):
        self.src["description"] = "## Acceptance\n- [x] a done thing\n- [ ] the thing that never shipped\n"
        code, text = self.wont_fix()
        self.assertEqual(code, 2, text)
        self.assertIn("the thing that never shipped", text)

    def test_open_pending_real_test_in_a_comment_is_refused_and_closed_one_is_not(self):
        self.comment(SRC, "PENDING_REAL_TEST RT7: the live call works")
        code, text = self.wont_fix()
        self.assertEqual(code, 2, text)
        self.assertIn("RT7", text)
        self.comment(SRC, "REALLY_TESTED RT7: ran it live, result ok, commit abc1234")
        self.assertEqual(self.wont_fix(), (0, ""))

    def test_open_pending_in_a_wal_that_names_the_ticket_is_refused(self):
        wal = self.home / ".claude" / "wals" / "s1"
        wal.mkdir(parents=True)
        (wal / "main.jsonl").write_text(json.dumps({"note": "PENDING_REAL_TEST live-1: dialer works on #14518"}) + "\n")
        code, text = self.wont_fix()
        self.assertEqual(code, 2, text)
        self.assertIn("live-1", text)
        (wal / "agent-x.jsonl").write_text(json.dumps({"note": "REALLY_TESTED live-1: live ok"}) + "\n")
        self.assertEqual(self.wont_fix(), (0, ""))

    def test_clean_ticket_closes_as_before(self):
        self.assertEqual(self.wont_fix(), (0, ""))

    # ---- AC2: every tool agents close tickets with is covered

    def test_all_close_paths_are_covered(self):
        self.src["priority"] = "urgent"
        cases = [
            ("update_issue", {"issueId": SRC, "patch": {"status": "duplicate"}}),
            ("update_issue", {"issueId": SRC, "patch": {"status": "wont_fix"}}),
            ("bulk_update_issues", {"items": [{"issueId": SRC, "status": "duplicate", "note": "n" * 40}]}),
            ("archive_issue", {"issueId": SRC, "reason": "tidy"}),
            ("call_api", {"method": "PATCH", "path": f"/v1/issues/{SRC}", "body": {"patch": {"status": "wont_fix"}}}),
        ]
        for tool, tool_input in cases:
            with self.subTest(tool=tool, input=str(tool_input)[:50]):
                code, text = self.hook(tool, tool_input)
                self.assertEqual(code, 2, text)
                self.assertIn("fold guard", text.lower())

    def test_non_closing_updates_and_done_are_not_this_guards_business(self):
        self.src["priority"] = "urgent"
        self.assertEqual(self.hook("update_issue", {"issueId": SRC, "patch": {"status": "in_review"}}), (0, ""))
        self.assertEqual(self.hook("update_issue", {"issueId": SRC, "patch": {"priority": "low"}}), (0, ""))

    def test_already_closed_ticket_is_left_alone(self):
        self.src.update(priority="immediate", status="wont_fix")
        self.assertEqual(self.wont_fix(), (0, ""))

    # ---- AC3: Carried-to must be real and complete

    def carried(self, target="harness#15529"):
        return f"folded into the umbrella, nothing lost\nCarried-to: GoodQA {target}"

    def test_carry_into_umbrella_that_lists_the_ticket_and_items_is_allowed(self):
        self.src["priority"] = "immediate"
        self.umb["priority"] = "immediate"
        self.src["description"] = "- [ ] dial back the P0 call\n"
        self.comment(UMB, "Carried from #14518: dial back the p0 call")
        self.assertEqual(self.wont_fix(self.carried()), (0, ""))

    def test_a_p0_cannot_be_carried_to_a_lower_priority_umbrella(self):
        self.src["priority"] = "immediate"
        self.comment(UMB, "Carried from #14518")
        for low in ("medium", None, "urgent"):
            self.umb["priority"] = low
            code, text = self.wont_fix(self.carried())
            self.assertEqual(code, 2, (low, text))
            self.assertIn("lower than this ticket", text)
        self.umb["priority"] = "immediate"
        self.assertEqual(self.wont_fix(self.carried()), (0, ""))

    def test_item_ids_match_as_whole_tokens_and_crlf_notes_work(self):
        self.src["priority"] = "medium"
        self.src["description"] = "- [ ] AC-1\n1. [ ] AC-2\n- [  ] AC-3\n"
        self.comment(UMB, "carried from #14518: AC-10 and AC-20 and AC-30")
        code, text = self.wont_fix(self.carried())
        self.assertEqual(code, 2, text)
        self.assertIn("does not list these unfinished items", text)
        self.comment(UMB, "carried from #14518: AC-1, AC-2, AC-3.")
        note = self.carried().replace("\n", "\r\n")
        self.assertEqual(self.wont_fix(note), (0, ""))

    def test_carry_target_that_omits_an_item_or_the_ticket_is_refused(self):
        self.src["description"] = "- [ ] dial back the P0 call\n"
        code, text = self.wont_fix(self.carried())  # umbrella names nothing
        self.assertEqual(code, 2, text)
        self.assertIn("does not mention #14518", text)
        self.comment(UMB, "see #14518")
        code, text = self.wont_fix(self.carried())
        self.assertEqual(code, 2, text)
        self.assertIn("dial back the p0 call", text)

    def test_carry_target_must_exist_be_open_and_not_be_self(self):
        self.src["priority"] = "immediate"
        self.comment(UMB, "#14518")
        for target, why in (("harness#999", "does not exist"), ("harness#14518", "being closed")):
            code, text = self.wont_fix(self.carried(target))
            self.assertEqual(code, 2, text)
            self.assertIn(why, text)
        self.umb["status"] = "duplicate"
        code, text = self.wont_fix(self.carried())
        self.assertEqual(code, 2, text)
        self.assertIn("not an open ticket", text)

    # ---- AC4: override needs the user's own sourced words

    def test_override_needs_a_resolving_user_source(self):
        self.src["priority"] = "immediate"
        note = "dropped on purpose\nFold-Override: user:%s/%s \"drop it\"" % (uuid.uuid4(), uuid.uuid4())
        bad = {"ok": False, "kind": "user", "problems": [{"code": "not-found"}]}
        with mock.patch("provenance.resolve", lambda s, *a, **k: bad):
            code, text = self.wont_fix(note)
        self.assertEqual(code, 2, text)
        self.assertIn("user's own words", text)
        agent = {"ok": True, "kind": "wal", "weak": False}
        with mock.patch("provenance.resolve", lambda s, *a, **k: agent):
            self.assertEqual(self.wont_fix(note)[0], 2)  # a wal: source is the agent's own note
        good = {"ok": True, "kind": "user", "weak": False}
        with mock.patch("provenance.resolve", lambda s, *a, **k: good):
            self.assertEqual(self.wont_fix(note), (0, ""))

    def test_override_must_be_about_this_ticket_or_folding(self):
        self.src["priority"] = "immediate"
        good = {"ok": True, "kind": "user", "weak": False}
        unrelated = "x\nFold-Override: answer:%s/%s \"Allow it (Recommended) Yes, send the link\"" % (uuid.uuid4(), uuid.uuid4())
        about = "x\nFold-Override: user:%s/%s \"close 14518, it is replaced by the umbrella #14518\"" % (uuid.uuid4(), uuid.uuid4())
        with mock.patch("provenance.resolve", lambda s, *a, **k: good):
            code, text = self.wont_fix(unrelated)
            self.assertEqual(code, 2, text)
            self.assertIn("do not mention this ticket", text)
            self.assertEqual(self.wont_fix(about), (0, ""))

    # ---- hostile shapes: nothing is skipped quietly

    def test_odd_status_shapes_are_checked_not_skipped(self):
        self.src["priority"] = "urgent"
        cases = [("update_issue", {"issueId": SRC, "patch": {"status": ["duplicate"]}}),
                 ("update_issue", {"issueId": SRC, "patch": {"status": "Duplicate "}}),
                 ("update_issue", {"issueId": SRC, "patch": {"status": None}}),
                 ("update_issue", {"issueId": SRC, "patch": {"status": "done", "resolution": "duplicate"}}),
                 ("update_issue", {"issueId": SRC, "patch": {"archived": True}}),
                 ("call_api", {"method": "PATCH", "path": f"/v1/issues/{SRC}", "body": '{"status": "duplicate"}'}),
                 ("call_api", {"method": "POST", "path": f"/v1/issues/{SRC}/archive", "body": {}}),
                 ("call_api", {"method": "DELETE", "path": f"/v1/issues/{SRC}"}),
                 ("call_api", {"method": "PATCH", "path": f"/v1/projects/{PROJECT}/issues/{SRC}", "body": {"status": "wont_fix"}}),
                 ("bulk_update_issues", {"items": [{"issueId": SRC, "status": "Wont_Fix"}]})]
        for tool, tool_input in cases:
            with self.subTest(tool=tool, input=str(tool_input)[:70]):
                code, text = self.hook(tool, tool_input)
                self.assertEqual(code, 2, text)
        self.src["priority"] = "medium"
        self.assertEqual(self.hook("update_issue", {"issueId": SRC, "patch": {"status": ["duplicate"]}}), (0, ""))

    def test_a_payload_the_guard_cannot_read_fails_closed(self):
        with mock.patch.object(sf, "fold_targets", mock.Mock(side_effect=TypeError("boom"))):
            code, text = self.wont_fix()
        self.assertEqual(code, 2, text)
        self.assertIn("could not read this call", text)

    def test_a_bulk_close_over_the_limit_is_refused_whole(self):
        items = [{"issueId": str(uuid.uuid4()), "status": "duplicate", "note": "n" * 30} for _ in range(51)]
        code, text = self.hook("bulk_update_issues", {"items": items})
        self.assertEqual(code, 2, text)
        self.assertIn("smaller batches", text)

    def test_wal_scan_is_shared_and_a_late_scan_blocks(self):
        wal = self.home / ".claude" / "wals" / "s1"
        wal.mkdir(parents=True)
        (wal / "main.jsonl").write_text(json.dumps({"note": "PENDING_REAL_TEST p1: x on #14518"}) + "\n")
        index, complete = fold_guard.wal_pending_index({14518: "harness"}, self.home, deadline=time.monotonic() - 1)
        self.assertFalse(complete)
        index, complete = fold_guard.wal_pending_index({14518: "harness"}, self.home, deadline=time.monotonic() + 60)
        self.assertTrue(complete)
        self.assertEqual(index, {14518: ["p1"]})
        with mock.patch.object(fold_guard, "wal_pending_index", lambda *a, **k: ({14518: []}, False)):
            code, text = self.wont_fix()
        self.assertEqual(code, 2, text)
        self.assertIn("did not finish", text)

    # ---- pending ids: cleared anywhere, matched by project

    def test_a_comment_or_another_session_clears_a_wal_pending_and_another_project_does_not_count(self):
        w1 = self.home / ".claude" / "wals" / "s1"
        w2 = self.home / ".claude" / "wals" / "s2"
        w1.mkdir(parents=True)
        w2.mkdir(parents=True)
        (w1 / "main.jsonl").write_text(json.dumps({"note": "PENDING_REAL_TEST p1: x on #14518"}) + "\n"
                                       + json.dumps({"note": "PENDING_REAL_TEST p2: y on bugtracker#14518"}) + "\n")
        code, text = self.wont_fix()
        self.assertEqual(code, 2, text)
        self.assertIn("p1", text)
        self.assertNotIn("p2", text)  # bugtracker#14518 is another project's ticket
        self.comment(SRC, "REALLY_TESTED p1: ran live, ok, commit abc1234")
        self.assertEqual(self.wont_fix(), (0, ""))  # a comment clears the WAL pending
        self.comments[SRC].clear()
        (w2 / "main.jsonl").write_text(json.dumps({"note": "REALLY_TESTED p1: live ok"}) + "\n")
        self.assertEqual(self.wont_fix(), (0, ""))  # so does another session's WAL

    def test_unmet_acs_come_from_the_verified_spec_and_evidence(self):
        core = "c" * 64
        spec = {"ac": ["AC-1", "AC-2"], "spec_core_sha": core}
        proof = {"spec_core_sha": core, "ac": ["AC-1"], "really_tested": {"id": "RT1"}}
        stale = {"spec_core_sha": "d" * 64, "ac": ["AC-2"], "really_tested": {"id": "RT2"}}

        def fake(records, index, kind):
            return ([spec], []) if kind == "spec" else ([proof, stale], [])
        with mock.patch.object(sf, "verified", fake):
            self.assertEqual(sf.unmet_acs([], {}), ["AC-2"])
        with mock.patch.object(sf, "verified", lambda r, i, k: ([], [])):
            self.assertIsNone(sf.unmet_acs([], {}))
        done = {"spec_core_sha": core, "ac": ["AC-2"], "commits": ["abc"], "note": "tested"}
        with mock.patch.object(sf, "verified", lambda r, i, k: ([spec], []) if k == "spec" else ([proof, done], [])):
            self.assertEqual(sf.unmet_acs([], {}), [])

    # ---- AC5: modes and fail-closed behavior

    def test_warn_and_off_modes(self):
        self.src["priority"] = "immediate"
        code, text = self.wont_fix(fold_guard="warn")
        self.assertEqual(code, 0)
        self.assertIn("warn mode", text)
        self.assertEqual(self.wont_fix(fold_guard="off"), (0, ""))

    def test_unreadable_ticket_and_tracker_outage_fail_closed(self):
        with mock.patch.object(sf, "resolve_issue", lambda *a, **k: (None, None)):
            code, text = self.wont_fix()
        self.assertEqual(code, 2, text)
        with mock.patch.object(sf, "ticket_config", mock.Mock(side_effect=OSError("down"))):
            code, text = self.wont_fix()
        self.assertEqual(code, 2, text)
        code, text = self.hook("close_issue_wont_fix", {"issueId": "harness#14518", "note": "x" * 30})
        self.assertEqual(code, 2, text)

    def test_default_policy_enforces(self):
        pol = sf.load_spec_policy(HOOKS / "spec_policy.json")
        self.assertEqual(pol["fold_guard"], "enforce")


class ReplayAudit(unittest.TestCase):
    """The 11-09 folds named in the audit: #14518 (P0) into #15529 and #15279 into #15496."""

    def test_audited_shapes_are_unmet(self):
        p0 = issue(14518, priority="immediate", description="- [ ] call quality AC")
        items = fold_guard.unmet_items(p0, [{"body": "PENDING_REAL_TEST q1: calls"}])
        self.assertEqual({i["kind"] for i in items}, {"checklist", "pending", "priority"})
        spec_ticket = fold_guard.unmet_items(issue(15279), [], spec_view=["AC-2"])
        self.assertEqual([i["id"] for i in spec_ticket], ["AC-2"])


if __name__ == "__main__":
    unittest.main()
