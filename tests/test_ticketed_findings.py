"""Ticketed review findings are explicit, verified, and bound to report/FINAL bytes."""
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

HOOKS = Path(__file__).resolve().parents[1] / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
import peer_review as review  # noqa: E402
import usage_guard as guard  # noqa: E402

HEAD = "a" * 40
OTHER_HEAD = "b" * 40
REPORT_SHA = "c" * 64
TICKET = "GoodQA goodqa#42"
RELATED = {("goodqa", "goodqa", 42)}


def open_ticket(ref):
    system, project, number = ref
    return SimpleNamespace(system="GoodQA", project=project, number=number, status="open", closed=False)


def resolve(report, verifier=open_ticket):
    return review.resolve_ticketed_findings("pr", report, head=HEAD, related=RELATED, verifier=verifier)


def declaration(finding="F1", category="maintainability", ticket=TICKET):
    return f"TICKETED: {finding} | category: {category} | ticket: {ticket}"


class TicketedFindingTests(unittest.TestCase):
    def test_valid_ticketed_finding_has_distinct_pass_with_tickets_outcome(self):
        report = "VERDICT: BLOCK\nF1: low maintainability issue\n" + declaration()
        transformed, records, errors = resolve(report)
        self.assertEqual(errors, [])
        self.assertTrue(transformed.startswith("VERDICT: PASS-WITH-TICKETS\n"), transformed)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0], {
            "state": "ticketed", "finding": "F1", "category": "maintainability",
            "ticket": TICKET, "head": HEAD})

    def test_correctness_finding_can_be_ticketed_when_properly_verified(self):
        report = "VERDICT: BLOCK\nF1: wrong boundary check\n" + declaration(category="correctness")
        transformed, records, errors = resolve(report)
        self.assertEqual(errors, [])
        self.assertTrue(transformed.startswith("VERDICT: PASS-WITH-TICKETS\n"))
        self.assertEqual(records[0]["category"], "correctness")

    def test_mixed_labelled_and_unlabelled_security_finding_stays_block_verbatim(self):
        report = ("VERDICT: BLOCK\nF1: minor\n"
                  "Unlabelled security finding: account takeover remains\n" + declaration())
        transformed, records, errors = resolve(report)
        self.assertEqual(transformed, report)
        self.assertEqual(records, [])
        self.assertTrue(errors)
        self.assertIn("account takeover remains", transformed)

    def test_unparsed_or_extra_text_in_ticketed_mode_stays_block(self):
        variants = (
            "VERDICT: BLOCK\nUnlabelled issue\nF1: minor\n" + declaration(),
            "VERDICT: BLOCK\nF1: minor\n  Unlabelled continuation\n" + declaration(),
            "VERDICT: BLOCK\nF1: minor\n" + declaration() + "\nTrailing security finding",
            "VERDICT: BLOCK\nF1: minor\nProse between finding and declaration\n" + declaration(),
        )
        for report in variants:
            with self.subTest(report=report):
                transformed, records, errors = resolve(report)
                self.assertEqual(transformed, report)
                self.assertEqual(records, [])
                self.assertTrue(errors)

    def test_ordinary_report_prose_outside_ticketed_mode_is_unchanged(self):
        report = "VERDICT: BLOCK\nF1: minor\nUnlabelled security finding: account takeover remains"
        self.assertEqual(resolve(report), (report, [], []))
        self.assertEqual(review.finding_ids(report), ["F1"])

    def test_malformed_missing_unrelated_closed_duplicate_and_unknown_stay_block(self):
        cases = {
            "malformed": ("VERDICT: BLOCK\nF1: issue\nTICKETED: F1 maintainability " + TICKET, open_ticket),
            "missing-ticket": ("VERDICT: BLOCK\nF1: issue\n" + declaration(ticket="GoodQA goodqa#43"), open_ticket),
            "unrelated": ("VERDICT: BLOCK\nF1: issue\n" + declaration(ticket="GoodQA other#42"), open_ticket),
            "closed": ("VERDICT: BLOCK\nF1: issue\n" + declaration(),
                       lambda ref: SimpleNamespace(project="goodqa", number=42, status="done", closed=True)),
            "duplicate": ("VERDICT: BLOCK\nF1: issue\n" + declaration(),
                          lambda ref: SimpleNamespace(project="goodqa", number=42, status="duplicate", closed=True)),
            "unknown-category": ("VERDICT: BLOCK\nF1: issue\n" + declaration(category="cosmetic"), open_ticket),
            "security": ("VERDICT: BLOCK\nF1: security hole\n" + declaration(category="security"), open_ticket),
            "data-loss": ("VERDICT: BLOCK\nF1: deletes user data\n" + declaration(category="data-loss"), open_ticket),
            "missing-finding": ("VERDICT: BLOCK\nF1: issue\nF2: unfixed issue\n" + declaration(), open_ticket),
            "unknown-finding": ("VERDICT: BLOCK\nF1: issue\n" + declaration("F2"), open_ticket),
            "unlabelled-finding": ("VERDICT: BLOCK\nUnlabelled issue\n" + declaration(), open_ticket),
            "duplicate-declaration": ("VERDICT: BLOCK\nF1: issue\n" + declaration() + "\n" + declaration(), open_ticket),
            "plain-pass-cannot-hide-tickets": ("VERDICT: PASS\nF1: issue\n" + declaration(), open_ticket),
            "missing-tracker": ("VERDICT: BLOCK\nF1: issue\n" + declaration(), lambda ref: None),
            "wrong-tracker-answer": ("VERDICT: BLOCK\nF1: issue\n" + declaration(),
                                     lambda ref: SimpleNamespace(project="other", number=42, status="open", closed=False)),
            "unknown-tracker-state": ("VERDICT: BLOCK\nF1: issue\n" + declaration(),
                                      lambda ref: SimpleNamespace(project="goodqa", number=42,
                                                                  status="mystery", closed=False)),
        }
        for name, (report, verifier) in cases.items():
            with self.subTest(name=name):
                transformed, records, errors = resolve(report, verifier)
                self.assertTrue(transformed.startswith("VERDICT: BLOCK"), transformed)
                self.assertEqual(records, [])
                self.assertTrue(errors)

    def test_provider_cannot_self_declare_pass_with_tickets(self):
        outcome = review.normalize_provider("codex", 0, "VERDICT: PASS-WITH-TICKETS\nF1: issue",
                                            requested_stage="pr")
        self.assertEqual(outcome["result"], "NO_RESULT")

    def test_ticket_declaration_cannot_accept_another_review_stage(self):
        for stage, marker in (("plan", "PLAN_RESULT"), ("code-inspection", "CODE_INSPECTION_RESULT")):
            with self.subTest(stage=stage):
                transformed, records, errors = review.resolve_ticketed_findings(
                    stage, marker + ": ACCEPT\nF1: issue\n" + declaration(),
                    head=HEAD, related=RELATED, verifier=open_ticket)
                self.assertTrue(transformed.startswith(marker + ": BLOCK"), transformed)
                self.assertEqual(records, [])
                self.assertTrue(errors)

    def test_tracker_failure_stays_block(self):
        def unavailable(_):
            raise OSError("fake tracker unavailable")
        transformed, records, errors = resolve("VERDICT: BLOCK\nF1: issue\n" + declaration(), unavailable)
        self.assertTrue(transformed.startswith("VERDICT: BLOCK"))
        self.assertEqual(records, [])
        self.assertTrue(errors)

    def test_final_metadata_binds_every_ticket_to_report_and_head(self):
        record = {"state": "ticketed", "finding": "F1", "category": "maintainability",
                  "ticket": TICKET, "head": HEAD, "report_sha256": REPORT_SHA}
        metadata = {"stage": "PR", "verdict": "ACCEPT_WITH_TICKETS", "findings": ["F1"],
                    "head": HEAD, "report_sha256": REPORT_SHA, "ticketed": [record]}
        guard.validate_review_metadata(metadata, result="CHECK_OK")
        for field, value in (("head", OTHER_HEAD), ("report_sha256", "d" * 64),
                             ("category", "security"), ("ticket", "GoodQA other#")):
            with self.subTest(field=field):
                changed = dict(metadata, ticketed=[dict(record, **{field: value})])
                with self.assertRaises(guard.GuardError):
                    guard.validate_review_metadata(changed, result="CHECK_OK")
        with self.assertRaises(guard.GuardError):
            guard.validate_review_metadata(dict(metadata, report_sha256="d" * 64), result="CHECK_OK")
        with self.assertRaises(guard.GuardError):
            guard.validate_review_metadata(dict(metadata, head=OTHER_HEAD), result="CHECK_OK")
        with self.assertRaises(guard.GuardError):
            guard.validate_review_metadata(metadata, result="CHECK_FAILED")

    def test_legacy_block_and_advisory_shapes_are_unchanged(self):
        guard.validate_review_metadata({"stage": "PR", "verdict": "BLOCK", "findings": ["F1"]},
                                       result="CHECK_FAILED")
        with self.assertRaises(guard.GuardError):
            guard.validate_review_metadata({"stage": "PR", "verdict": "ACCEPT", "findings": []},
                                           result="CHECK_FAILED")


class OwnTicketAndUnticketable(unittest.TestCase):
    """#134 red-team P3."""

    def test_a_data_loss_finding_labelled_reliability_is_not_ticketed(self):
        for text in ("migration drops the users table on rollback (data loss)", "token leaks into the log",
                     "the auth check can be skipped", "deletes the user's worktree"):
            with self.subTest(text=text):
                report = "VERDICT: BLOCK\nF1: " + text + "\n" + declaration(category="reliability")
                out, records, errors = resolve(report)
                self.assertTrue(out.startswith("VERDICT: BLOCK"), out)
                self.assertEqual(records, [])
                self.assertIn("cannot be ticketed", " ".join(errors))

    def test_the_red_teams_missed_wordings_are_not_ticketed(self):
        # step-1 red-team B3: each of these was ticketed as reliability
        for text in ("unauthenticated callers can read every tenant's invoices", "OAuth callback skips state check",
                     "stored XSS in the profile page", "rm -rf of the archive dir erases the only copy",
                     "TRUNCATE on deploy empties the orders table", "IDOR: any user id can be fetched",
                     "SSRF via the webhook URL", "the sign-in form accepts an expired JWT"):
            with self.subTest(text=text):
                report = "VERDICT: BLOCK\nF1: " + text + "\n" + declaration(category="reliability")
                out, records, errors = resolve(report)
                self.assertTrue(out.startswith("VERDICT: BLOCK"), out)
                self.assertIn("cannot be ticketed", " ".join(errors))

    def test_an_ordinary_finding_is_still_ticketable(self):
        report = "VERDICT: BLOCK\nF1: the retry helper's name hides that it sleeps\n" + declaration(category="maintainability")
        out, records, errors = resolve(report)
        self.assertEqual(errors, [])
        self.assertEqual(len(records), 1)

    def test_the_branchs_own_work_ticket_is_refused(self):
        own = {("goodqa", "goodqa", 42)}
        out, records, errors = review.resolve_ticketed_findings(
            "pr", "VERDICT: BLOCK\nF1: minor naming issue\n" + declaration(), head=HEAD, related=RELATED,
            verifier=open_ticket, own=own)
        self.assertTrue(out.startswith("VERDICT: BLOCK"), out)
        self.assertIn("own work ticket", " ".join(errors))

    def test_commit_refs_are_own_and_follow_up_lines_are_related(self):
        import subprocess
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            repo = Path(d)
            subprocess.run(["git", "init", "-q", str(repo)], check=True)
            for args in (["config", "user.email", "x@example.invalid"], ["config", "user.name", "x"],
                         ["commit", "-q", "--allow-empty", "-m", "base"]):
                subprocess.run(["git", "-C", str(repo)] + args, check=True)
            base = subprocess.check_output(["git", "-C", str(repo), "rev-parse", "HEAD"], text=True).strip()
            subprocess.run(["git", "-C", str(repo), "commit", "-q", "--allow-empty", "-m",
                            "fix: x\n\nRefs: GoodQA goodqa#7\nFollow-up: GoodQA goodqa#7\nFollow-up: GoodQA goodqa#8"],
                           check=True)
            related, own = review.related_ticket_refs(repo, base)
        self.assertEqual(own, {("goodqa", "goodqa", 7)})
        self.assertEqual(related, {("goodqa", "goodqa", 8)})


class TicketedMainIntegrationTests(unittest.TestCase):
    def setUp(self):
        import subprocess
        import tempfile

        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        subprocess.run(["git", "init", "-q", "-b", "main", str(self.repo)], check=True)
        subprocess.run(["git", "-C", str(self.repo), "config", "user.name", "Fixture"], check=True)
        subprocess.run(["git", "-C", str(self.repo), "config", "user.email", "fixture@example.invalid"], check=True)
        (self.repo / "app.txt").write_text("baseline\n")
        subprocess.run(["git", "-C", str(self.repo), "add", "app.txt"], check=True)
        subprocess.run(["git", "-C", str(self.repo), "commit", "-qm", "baseline"], check=True)
        self.base = subprocess.check_output(["git", "-C", str(self.repo), "rev-parse", "HEAD"], text=True).strip()
        (self.repo / "app.txt").write_text("changed\n")
        subprocess.run(["git", "-C", str(self.repo), "add", "app.txt"], check=True)
        subprocess.run(["git", "-C", str(self.repo), "commit", "-qm",
                        "change\n\nRefs: GoodQA goodqa#41\nFollow-up: GoodQA goodqa#42"], check=True)
        self.head = subprocess.check_output(["git", "-C", str(self.repo), "rev-parse", "HEAD"], text=True).strip()
        self.packet = self.root / "packet.md"
        self.packet.write_text("Scope and evidence.\nReviewed HEAD " + self.head +
                               "\n$ python3 -m unittest discover tests\nRan 1 test in 0.1s\nOK\nexit 0\n")
        self.output = self.root / "review.md"

    def test_main_publishes_ticketed_report_and_binds_final_metadata(self):
        import contextlib
        import hashlib
        import io
        import json
        import os
        from unittest.mock import patch

        report = "VERDICT: BLOCK\nF1: low maintainability issue\n" + declaration()

        def discovered(name, **kwargs):
            return {"name": name, "path": sys.executable, "source": "fixture", "rejected": [], "searched": []}

        argv = ["peer_review.py", "pr", "--repo", str(self.repo), "--packet", str(self.packet),
                "--output", str(self.output), "--expected-head", self.head, "--base", self.base]
        stdout, stderr = io.StringIO(), io.StringIO()
        environment = {"HOME": str(self.root), "AGENT_HARNESS_USAGE_DIR": str(self.root / "usage")}
        with patch.object(sys, "argv", argv), \
             patch.dict(os.environ, environment), \
             patch.object(review, "commit_policy_gate", return_value=(0, "")), \
             patch.object(review.diagnostics, "discover_executable", side_effect=discovered), \
             patch.object(review, "review_snapshot", return_value=("fixture", report, "")), \
             patch.object(review, "default_ticket_verifier",
                          return_value=open_ticket(("goodqa", "goodqa", 42))) as verifier, \
             contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            result = review.main()

        self.assertEqual(result, 0, stdout.getvalue() + stderr.getvalue())
        verifier.assert_called_once_with(("goodqa", "goodqa", 42))
        self.assertIn("VERDICT: PASS-WITH-TICKETS", self.output.read_text())
        final = json.loads(next((self.root / "usage" / "runs").glob("*/final.json")).read_text())
        report_sha = hashlib.sha256(self.output.read_bytes()).hexdigest()
        self.assertEqual(final["result"], "CHECK_OK")
        self.assertEqual(final["review"]["verdict"], "ACCEPT_WITH_TICKETS")
        self.assertEqual(final["review"]["findings"], ["F1"])
        self.assertEqual(final["review"]["head"], self.head)
        self.assertEqual(final["review"]["report_sha256"], report_sha)
        self.assertEqual(final["review"]["ticketed"], [{
            "state": "ticketed", "finding": "F1", "category": "maintainability",
            "ticket": TICKET, "head": self.head, "report_sha256": report_sha}])


if __name__ == "__main__":
    unittest.main()
