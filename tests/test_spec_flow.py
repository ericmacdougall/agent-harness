"""Spec-driven ticket flow: spec lint, reviews, evidence, click-tests, sign-off, the done gate and hooks.

GoodQA is a loopback fake that speaks the MCP JSON-RPC shape and the presigned PUT upload, and
computes attachment sha256 server-side like the real service (verified live on 2026-11-04).
"""

import contextlib
import hashlib
import http.server
import io
import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import uuid
from pathlib import Path
from unittest import mock

HOOKS = Path(__file__).resolve().parents[1] / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
import commit_policy as cp  # noqa: E402
import spec_flow as sf  # noqa: E402
import ticket_adapters as ta  # noqa: E402

ISSUE = "4e8e73fb-72e2-4604-bff5-56b75e4420f5"
PROJECT = "75ebadd3-9b4c-4b8c-bc86-9a4c1cbd3a53"
SPEC = """# Spec: Done gate

Ticket: GoodQA harness#168
Author: agent:owner1 (claude-opus-5-5)
Click-test: required
Sign-off: main

## Outcome

An agent cannot mark a harness ticket done without proof.

## Scope

- In: the done gate.
- Out: the GoodQA UI.

## Acceptance criteria

- AC-1: done refuses a ticket without evidence. Verify by: tests.test_spec_flow DoneGate.
- AC-2: done passes a complete ticket. Verify by: live check RT2.

## Negative cases

- NEG-1 (AC-1): a tampered attachment is not accepted.

## Risks

- Hook breaks MCP calls: narrow matcher, warn first.
"""


def report_text(packet_sha, verdict="ACCEPT", reviewer="Blind Claude Opus fallback"):
    return (f"Reviewer: {reviewer}\nStage: plan\nReviewed HEAD: {'a' * 40}\nReviewed packet SHA-256: {packet_sha}\n"
            "Review input: isolated committed snapshot (ancestor history available)\nWorktree status: clean\n"
            "Fallback reason: Primary reviewer unavailable (TRANSIENT_INFRA); used authorized independent fallback.\n\n"
            f"PLAN_RESULT: {verdict}\n\nFindings follow.\n")


class FakeGoodQA:
    def __init__(self):
        self.issues = {ISSUE: {"id": ISSUE, "number": 168, "title": "Spec flow", "status": "in_progress",
                               "projectId": PROJECT, "description": "", "closedAt": None}}
        self.comments, self.attachments, self.calls = {ISSUE: []}, {}, []
        self.delay, self.refuse_done, self.clock = 0, False, 0
        outer = self

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def _send(self, status, payload=b"", ctype="application/json"):
                self.send_response(status)
                self.send_header("content-type", ctype)
                self.send_header("content-length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def do_PUT(self):
                data = self.rfile.read(int(self.headers["content-length"]))
                attachment = outer.attachments.get(self.path.rsplit("/", 1)[-1])
                if attachment is None or self.headers.get("Content-Type") != attachment["mime"]:
                    return self._send(403)
                attachment["bytes"] = data
                self._send(200)

            def do_POST(self):
                request = json.loads(self.rfile.read(int(self.headers["content-length"])))
                if outer.delay:
                    time.sleep(outer.delay)
                if self.headers.get("authorization") != "Bearer test-key":
                    return self._send(401)
                name, args = request["params"]["name"], request["params"]["arguments"]
                outer.calls.append(name)
                result, error = outer.handle(name, args)
                text = json.dumps(result if error is None else {"error": {"code": error}})
                body = json.dumps({"jsonrpc": "2.0", "id": 1, "result": {
                    "content": [{"type": "text", "text": text}], "isError": error is not None}})
                self._send(200, ("event: message\ndata: " + body + "\n\n").encode(), "text/event-stream")

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.url = self.base + "/v1/mcp"

    def now(self):
        self.clock += 1
        return f"2026-11-04T04:{self.clock // 60:02d}:{self.clock % 60:02d}.000Z"

    def handle(self, name, args):
        if name == "list_orgs":
            return {"orgs": [{"id": "org-1"}]}, None
        if name == "get_issue_by_number":
            for issue in self.issues.values():
                if issue["number"] == args["number"] and args["projectSlug"] == "harness":
                    return {"issue": issue}, None
            return None, "not_found"
        if name == "get_issue":
            issue = self.issues.get(args["issueId"])
            return ({"issue": issue}, None) if issue else (None, "not_found")
        if name == "get_issue_comments":
            items = self.comments.get(args["issueId"], [])
            start = int(args.get("cursor") or 0)
            page = items[start:start + args.get("limit", 100)]
            more = start + len(page) < len(items)
            return {"comments": page, "hasMore": more, "nextCursor": str(start + len(page)) if more else None}, None
        if name == "issue_attachments_list":
            ids = {c["id"] for c in self.comments.get(args["issueId"], [])}
            return {"attachments": [{k: v for k, v in a.items() if k != "bytes"}
                                    for a in self.attachments.values() if a["commentId"] in ids]}, None
        if name == "file_upload_start":
            aid = str(uuid.uuid4())
            self.attachments[aid] = {"id": aid, "projectId": args["id"], "commentId": None, "mime": args["mime"],
                                     "sizeBytes": args["sizeBytes"], "completionState": "uploading", "sha256": None,
                                     "metadata": {"filename": args["filename"]}}
            return {"dataTrust": "untrusted", "data": {"attachment": dict(self.attachments[aid]), "upload": {
                "method": "PUT", "url": f"{self.base}/upload/{aid}", "headers": {"Content-Type": args["mime"]}}}}, None
        if name == "file_upload_complete":
            attachment = self.attachments[args["id"]]
            digest = hashlib.sha256(attachment.get("bytes", b"")).hexdigest()
            if digest != args.get("expectedSha256"):
                return None, "sha256_mismatch"
            attachment.update(completionState="completed", sha256=digest)
            return {"data": {"attachment": {k: v for k, v in attachment.items() if k != "bytes"}}}, None
        if name == "comment_on_issue":
            for comment in self.comments[args["issueId"]]:
                if comment.get("operationId") == args.get("operationId"):
                    return {"comment": comment}, None
            comment = {"id": str(uuid.uuid4()), "issueId": args["issueId"], "body": args["body"],
                       "createdAt": self.now(), "operationId": args.get("operationId")}
            for aid in args.get("attachmentIds") or []:
                if self.attachments[aid]["completionState"] == "completed":
                    self.attachments[aid]["commentId"] = comment["id"]
            self.comments[args["issueId"]].append(comment)
            return {"comment": comment}, None
        if name == "close_issue_done":
            if self.refuse_done:
                return None, "independent_acceptance_required"
            self.issues[args["issueId"]]["status"] = args["status"]
            return {"issue": self.issues[args["issueId"]]}, None
        if name == "get_project":
            return {"project": {"id": args["projectId"]}, "permissions": ["attachment:create", "comment:add",
                                                                          "issue:transition"]}, None
        return None, "unknown_tool"


class SpecFlowCase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.home = self.tmp / "home"
        (self.home / ".claude" / "wals" / "sess1").mkdir(parents=True)
        self.patches = [mock.patch.dict(os.environ, {"HOME": str(self.home)})]
        self.fake = FakeGoodQA()
        key = self.tmp / "key"
        key.write_text("test-key")
        key.chmod(0o600)
        self.policy = cp.load_policy(HOOKS / "commit_policy.json")
        self.config = dict(self.policy["ticket_systems"]["goodqa"], endpoint=self.fake.url, key_file=str(key),
                           org_id="org-1", timeout_seconds=5, total_deadline_seconds=30)
        self.policy["ticket_systems"]["goodqa"] = self.config
        self.spec_policy = sf.load_spec_policy(HOOKS / "spec_policy.json")
        loader = lambda _sp: (cp, self.policy, self.config)  # noqa: E731
        self.patches.append(mock.patch.object(sf, "ticket_config", loader))
        self.patches.append(mock.patch.object(sf, "load_spec_policy", lambda *a: self.spec_policy))
        for item in self.patches:
            item.start()
        self.wal_dir = self.home / ".claude" / "wals" / "sess1"
        self.main_wal = self.wal_dir / "main.jsonl"

    def tearDown(self):
        for item in reversed(self.patches):
            item.stop()
        if not getattr(self.fake, "closed", False):
            self.fake.server.shutdown()

    def run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = sf.main(list(argv))
        return code, out.getvalue(), err.getvalue()

    def wal(self, path, *entries):
        with open(path, "a") as handle:
            for entry in entries:
                handle.write(json.dumps(entry) + "\n")

    def write_spec(self, text=SPEC):
        path = self.tmp / "spec.md"
        path.write_text(text)
        return path

    def reviewed_spec(self, text=SPEC):
        """A spec with a helper adversarial review and a WAL-verified native acceptance review."""
        spec = self.write_spec(text)
        report = self.tmp / "adv-report.md"
        report.write_text(report_text(sf.core_sha(text)))
        self.assertEqual(self.run_cli("review", str(spec), "--role", "adversarial", "--report", str(report))[0], 0)
        self.wal(self.main_wal, {"at": "2026-11-04T04:00:00+00:00", "event": "subagent", "agent_id": "acc1",
                                 "agent_type": "red-team"})
        acc = self.tmp / "acc-report.md"
        acc.write_text("ACCEPT: every criterion is testable.\n")
        code, _, err = self.run_cli("review", str(spec), "--role", "acceptance", "--agent", "acc1", "--wal",
                                    str(self.main_wal), "--verdict", "ACCEPT", "--report-file", str(acc))
        self.assertEqual(code, 0, err)
        return spec

    def attached(self):
        spec = self.reviewed_spec()
        code, out, err = self.run_cli("attach", str(spec), "--actor", "agent:owner1")
        self.assertEqual(code, 0, err)
        return spec

    def evaluate(self):
        adapter = sf.make_adapter(self.config, self.spec_policy, "harness", time.monotonic() + 30)
        records, ignored = sf.ticket_records(adapter.all_comments(ISSUE), 65536)
        index = {row["id"]: row for row in adapter.attachments(ISSUE)}
        return sf.evaluate(records, index, dict(self.fake.issues[ISSUE], _label="GoodQA harness#168"), ignored)


class Lint(SpecFlowCase):
    def test_packet_refuses_a_spec_that_fails_lint(self):
        spec = self.tmp / "bad.md"
        spec.write_text(SPEC.replace("Verify by:", "Check:", 1))
        out = self.tmp / "bad.packet.md"
        self.assertEqual(self.run_cli("packet", str(spec), "--out", str(out))[0], 2)
        self.assertFalse(out.exists())

    def test_good_spec_passes_and_template_fails(self):
        self.assertEqual(sf.lint(SPEC, self.config), [])
        template = (HOOKS / "spec_template.md").read_text().format(
            title="x", project="harness", number=1, author="agent:a1 (m)", signoff="main")
        problems = sf.lint(template, self.config)
        self.assertTrue(any("placeholder" in p for p in problems), problems)

    def test_vacuous_and_malformed_specs_fail(self):
        cases = {
            "no AC": SPEC.replace("- AC-1: done refuses a ticket without evidence. Verify by: tests.test_spec_flow DoneGate.\n", "")
                         .replace("- AC-2: done passes a complete ticket. Verify by: live check RT2.\n", "")
                         .replace("NEG-1 (AC-1)", "NEG-1 (AC-9)"),
            "duplicate": SPEC.replace("AC-2:", "AC-1:"),
            "no verify": SPEC.replace("Verify by: live check RT2.", "it works."),
            "neg unknown": SPEC.replace("NEG-1 (AC-1)", "NEG-1 (AC-7)"),
            "no neg": SPEC.replace("- NEG-1 (AC-1): a tampered attachment is not accepted.\n", ""),
            "bare ticket": SPEC.replace("GoodQA harness#168", "GoodQA #168"),
            "bad click": SPEC.replace("Click-test: required", "Click-test: maybe"),
            "stray": SPEC.replace("- AC-2:", "- AC2:"),
        }
        for name, text in cases.items():
            with self.subTest(name):
                self.assertNotEqual(sf.lint(text, self.config), [], name)

    def test_core_hash_ignores_reviews_and_normalizes(self):
        base = sf.core_sha(SPEC)
        self.assertEqual(sf.core_sha(SPEC + "\n## Reviews\n\n| x |\n"), base)
        self.assertEqual(sf.core_sha(SPEC.replace("\n", "\r\n")), base)
        self.assertNotEqual(sf.core_sha(SPEC.replace("proof", "proofs")), base)

    def test_ticket_ref_requires_project_and_lowercases(self):
        with self.assertRaises(sf.SpecError):
            sf.parse_ticket_ref("GoodQA #168", self.config)
        self.assertEqual(sf.parse_ticket_ref("goodqa Harness#168", self.config), ("harness", 168))


class Reviews(SpecFlowCase):
    def test_helper_report_must_review_exact_core(self):
        spec = self.write_spec()
        report = self.tmp / "r.md"
        report.write_text(report_text("0" * 64))
        code, _, err = self.run_cli("review", str(spec), "--role", "adversarial", "--report", str(report))
        self.assertEqual(code, 2)
        self.assertIn("different packet", err)
        packet = self.tmp / "packet.md"
        self.assertEqual(self.run_cli("packet", str(spec), "--out", str(packet))[0], 0)
        self.assertEqual(hashlib.sha256(packet.read_bytes()).hexdigest(), sf.core_sha(SPEC))

    def test_verdict_comes_from_body_after_header(self):
        report = self.tmp / "r.md"
        report.write_text(report_text("1" * 64, "BLOCK"))
        header, verdict, _ = sf.parse_review_report(report)
        self.assertEqual((header["Stage"], verdict), ("plan", "BLOCK"))

    def test_same_model_twice_and_author_as_reviewer_are_refused(self):
        spec = self.write_spec()
        for role in sf.ROLES:
            report = self.tmp / f"{role}.md"
            report.write_text(report_text(sf.core_sha(SPEC)))
            self.assertEqual(self.run_cli("review", str(spec), "--role", role, "--report", str(report))[0], 0)
        problems = sf.review_problems(sf.load_reviews(spec), sf.core_sha(SPEC), sf.parse_author("agent:owner1"))
        self.assertTrue(any("same reviewer" in p for p in problems), problems)
        entries = [{"role": r, "verdict": "ACCEPT", "core_sha": "c", "key": "agent:owner1"} for r in sf.ROLES]
        entries[1]["key"] = "human:eric"
        self.assertTrue(any("spec author" in p for p in sf.review_problems(entries, "c", "agent:owner1")))

    def test_agent_review_is_wal_verified_and_adversarial_needs_red_team(self):
        spec = self.write_spec()
        report = self.tmp / "n.md"
        report.write_text("ok")
        args = ["review", str(spec), "--agent", "x9", "--wal", str(self.main_wal), "--verdict", "ACCEPT",
                "--report-file", str(report)]
        self.assertEqual(self.run_cli(*args, "--role", "acceptance")[0], 2)  # not in the WAL
        self.wal(self.main_wal, {"at": "t", "event": "subagent", "agent_id": "x9", "agent_type": "fixer"})
        self.assertEqual(self.run_cli(*args, "--role", "adversarial")[0], 2)
        self.assertEqual(self.run_cli(*args, "--role", "acceptance")[0], 0)

    def test_edit_after_review_makes_reviews_stale_and_attach_refuses(self):
        spec = self.reviewed_spec()
        spec.write_text(spec.read_text().replace("cannot mark", "can never mark"))
        code, _, err = self.run_cli("attach", str(spec), "--actor", "agent:owner1")
        self.assertEqual(code, 2)
        self.assertIn("stale", err)
        self.assertEqual(self.fake.comments[ISSUE], [])

    def test_later_block_supersedes_accept(self):
        spec = self.reviewed_spec()
        report = self.tmp / "block.md"
        report.write_text(report_text(sf.core_sha(SPEC), "BLOCK"))
        self.run_cli("review", str(spec), "--role", "adversarial", "--report", str(report))
        self.assertEqual(self.run_cli("attach", str(spec), "--actor", "agent:owner1")[0], 2)


class Attach(SpecFlowCase):
    def test_attach_uploads_spec_reviews_and_reports_once(self):
        spec = self.attached()
        [comment] = self.fake.comments[ISSUE]
        names = sorted(a["metadata"]["filename"] for a in self.fake.attachments.values()
                       if a["commentId"] == comment["id"])
        self.assertEqual(names, ["acceptance-review-acc-report.md", "adversarial-review-adv-report.md",
                                 "spec.md", "spec.md.reviews.json"])
        self.assertIn("## Reviews", spec.read_text())
        self.assertIn("Blind Claude Opus fallback", spec.read_text())
        code, out, _ = self.run_cli("attach", str(spec), "--actor", "agent:owner1")
        self.assertEqual((code, json.loads(out)["status"]), (0, "ALREADY_RECORDED"))
        self.assertEqual(len(self.fake.comments[ISSUE]), 1)

    def test_report_changed_after_review_is_refused(self):
        spec = self.reviewed_spec()
        (self.tmp / "acc-report.md").write_text("edited later")
        self.assertEqual(self.run_cli("attach", str(spec), "--actor", "agent:owner1")[0], 2)


class Evidence(SpecFlowCase):
    def setUp(self):
        super().setUp()
        self.attached()
        self.owner_wal = self.wal_dir / "agent-owner1.jsonl"

    def ev(self, *extra):
        return self.run_cli("evidence", "--ticket", "GoodQA harness#168", "--actor", "agent:owner1", *extra)

    def test_unknown_ac_and_note_only_are_refused(self):
        self.assertEqual(self.ev("--ac", "AC-9", "--note", "x")[0], 3)
        self.assertEqual(self.ev("--ac", "AC-1", "--note", "I checked it")[0], 3)

    def test_pending_only_real_test_is_refused_and_really_tested_accepted(self):
        self.wal(self.owner_wal, {"at": "2026-11-04T01:00:00+00:00", "event": "check",
                                  "note": "PENDING_REAL_TEST RT1: gate refuses"})
        args = ("--ac", "AC-1", "--really-tested", "RT1", "--wal", str(self.owner_wal))
        self.assertEqual(self.ev(*args)[0], 2)
        self.wal(self.owner_wal, {"at": "2026-11-04T02:00:00+00:00", "event": "check",
                                  "note": "REALLY_TESTED RT1: python3 -m unittest -> exit 0, 12 tests"})
        code, out, err = self.ev(*args)
        self.assertEqual(code, 0, err)
        record = json.loads(sf.RECORD_BLOCK.search(self.fake.comments[ISSUE][-1]["body"]).group(1))
        self.assertIn("exit 0", record["really_tested"]["note"])

    def test_real_test_reopened_by_a_later_pending_is_refused(self):
        self.wal(self.owner_wal, {"at": "2026-11-04T01:00:00+00:00", "event": "check",
                                  "note": "REALLY_TESTED RT2: first run exit 0"},
                 {"at": "2026-11-04T03:00:00+00:00", "event": "check",
                  "note": "PENDING_REAL_TEST RT2: rerun needed after fix"})
        self.assertEqual(self.ev("--ac", "AC-1", "--really-tested", "RT2", "--wal", str(self.owner_wal))[0], 2)

    def test_logs_are_redacted_and_key_cut_is_refused(self):
        log = self.tmp / "run.log"
        log.write_text("API_TOKEN=supersecretvalue123\nAuthorization: Bearer abc.def\n"
                       "Cookie: session=cookievalue987\nGET https://bob:urlpassword55@example.test/x\nresult ok\n")
        code, _, err = self.ev("--ac", "AC-1", "--log", str(log))
        self.assertEqual(code, 0, err)
        uploaded = [a["bytes"] for a in self.fake.attachments.values() if a["metadata"]["filename"] == "run.log"][0]
        for secret in (b"supersecretvalue123", b"abc.def", b"cookievalue987", b"urlpassword55"):
            self.assertNotIn(secret, uploaded)
        self.assertIn(b"result ok", uploaded)
        whole = self.tmp / "key.log"
        whole.write_text("start\n-----BEGIN OPENSSH PRIVATE KEY-----\n" + "B" * 64 + "\n-----END OPENSSH PRIVATE KEY-----\n")
        self.assertEqual(self.ev("--ac", "AC-1", "--log", str(whole))[0], 0)
        uploaded = [a["bytes"] for a in self.fake.attachments.values() if a["metadata"]["filename"] == "key.log"][0]
        self.assertNotIn(b"B" * 64, uploaded)
        self.assertIn(b"[redacted private key]", uploaded)
        cut = self.tmp / "cut.log"
        body = "".join("A" * 64 + "\n" for _ in range(40)) + "-----END RSA PRIVATE KEY-----\nafter\n"
        cut.write_text("x" * 5000 + "\n-----BEGIN RSA PRIVATE KEY-----\n" + body)
        self.spec_policy["max_log_bytes"] = len(body) + 10
        self.assertEqual(self.ev("--ac", "AC-1", "--log", str(cut))[0], 2)

    def test_symlinked_log_is_refused(self):
        real = self.tmp / "real.log"
        real.write_text("ok\n")
        link = self.tmp / "link.log"
        link.symlink_to(real)
        self.assertEqual(self.ev("--ac", "AC-1", "--log", str(link))[0], 3)

    def test_commit_plus_note_counts_and_missing_commit_is_refused(self):
        repo = self.tmp / "repo"
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        subprocess.run(["git", "-C", str(repo), "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q",
                        "--allow-empty", "-m", "test: add empty"], check=True)
        sha = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
        self.assertEqual(self.ev("--ac", "AC-2", "--commit", "f" * 40, "--repo", str(repo), "--note", "n")[0], 2)
        code, _, err = self.ev("--ac", "AC-2", "--commit", sha, "--repo", str(repo), "--note", "unit tests ran")
        self.assertEqual(code, 0, err)


def git_repo(path, *subjects):
    """A throwaway repo with one empty commit per subject, on a straight line; returns the shas in order."""
    subprocess.run(["git", "init", "-q", str(path)], check=True)
    shas = []
    for subject in subjects:
        subprocess.run(["git", "-C", str(path), "-c", "user.name=t", "-c", "user.email=t@t", "commit", "-q",
                        "--allow-empty", "-m", subject], check=True)
        shas.append(subprocess.run(["git", "-C", str(path), "rev-parse", "HEAD"], capture_output=True,
                                   text=True).stdout.strip())
    return shas


class ClickTest(SpecFlowCase):
    def setUp(self):
        super().setUp()
        self.attached()
        self.wal(self.main_wal, {"at": "2026-11-04T05:00:00+00:00", "event": "subagent", "agent_id": "ct1",
                                 "agent_type": "click-tester"})
        self.agent_wal = self.wal_dir / "agent-ct1.jsonl"
        self.wal(self.agent_wal, {"at": "2026-11-04T05:03:00+00:00", "event": "pretool"})
        self.report = self.tmp / "click-report.md"
        self.report.write_text("CLICK_TEST_RESULT: PASS\n\nOpened http://127.0.0.1:3000, clicked Done.\n")
        self.repo_dir = self.tmp / "deployed"
        self.shas = git_repo(self.repo_dir, "feat: one", "feat: two")

    def ct(self, *extra):
        return self.run_cli("click-test", "--ticket", "GoodQA harness#168", "--actor", "agent:owner1",
                            "--url", "http://127.0.0.1:3000", "--agent-id", "ct1", "--wal-dir", str(self.wal_dir),
                            "--repo", str(self.repo_dir), "--deployed-commit", self.shas[-1], *extra)

    def test_pass_without_logs_is_refused(self):
        self.assertEqual(self.ct("--result", "pass")[0], 3)

    def test_pass_without_click_tester_output_is_refused(self):
        log = self.tmp / "c.log"
        log.write_text("clicked\n")
        code, _, err = self.ct("--result", "pass", "--log", str(log))
        self.assertEqual(code, 2)
        self.assertIn("must come from the click-tester", err)
        code, _, _ = self.ct("--result", "pass", "--report", str(self.report))  # report, but no sha note
        self.assertEqual(code, 2)

    def test_report_contradicting_result_is_refused(self):
        self.report.write_text("CLICK_TEST_RESULT: FAIL\nbroken\n")
        self.assertEqual(self.ct("--result", "pass", "--report", str(self.report))[0], 2)

    def test_pass_from_click_tester_report_records_identity_and_time(self):
        digest = hashlib.sha256(self.report.read_bytes()).hexdigest()
        self.wal(self.agent_wal, {"at": "2026-11-04T05:04:00+00:00", "event": "result",
                                  "note": f"CLICK_TEST_REPORT sha256={digest}"},
                 {"at": "2026-11-04T05:05:00+00:00", "event": "subagent_stop", "agent_id": "ct1"})
        code, _, err = self.ct("--result", "pass", "--report", str(self.report))
        self.assertEqual(code, 0, err)
        record = json.loads(sf.RECORD_BLOCK.search(self.fake.comments[ISSUE][-1]["body"]).group(1))
        self.assertEqual(record["tester"]["started_at"], "2026-11-04T05:00:00+00:00")
        self.assertEqual(record["tester"]["ended_at"], "2026-11-04T05:05:00+00:00")
        self.assertEqual(record["pass_source"], "report+agent-wal-sha256")

    def test_no_stop_event_records_last_activity_only(self):
        self.wal(self.agent_wal, {"at": "2026-11-04T05:06:00+00:00", "event": "check",
                                  "note": "REALLY_TESTED CT1: clicked through Done flow, status 200"})
        code, _, err = self.ct("--result", "pass", "--report", str(self.report), "--really-tested", "CT1")
        self.assertEqual(code, 0, err)
        record = json.loads(sf.RECORD_BLOCK.search(self.fake.comments[ISSUE][-1]["body"]).group(1))
        self.assertIsNone(record["tester"]["ended_at"])
        self.assertEqual(record["tester"]["last_activity_at"], "2026-11-04T05:06:00+00:00")

    def test_deployed_commit_must_contain_the_evidence_commits(self):
        self.wal(self.agent_wal, {"at": "2026-11-04T05:06:00+00:00", "event": "check",
                                  "note": "REALLY_TESTED CT1: clicked through Done flow, status 200"})
        code, _, err = self.run_cli("evidence", "--ticket", "GoodQA harness#168", "--actor", "agent:owner1",
                                    "--ac", "AC-2", "--commit", self.shas[1], "--repo", str(self.repo_dir),
                                    "--note", "unit tests ran")
        self.assertEqual(code, 0, err)
        code, _, err = self.run_cli("click-test", "--ticket", "GoodQA harness#168", "--actor", "agent:owner1",
                                    "--url", "u", "--agent-id", "ct1", "--wal-dir", str(self.wal_dir),
                                    "--repo", str(self.repo_dir), "--deployed-commit", self.shas[0],
                                    "--result", "pass", "--report", str(self.report), "--really-tested", "CT1")
        self.assertEqual(code, 2)
        self.assertIn("not reachable from", err)
        code, _, err = self.ct("--result", "pass", "--report", str(self.report), "--really-tested", "CT1")
        self.assertEqual(code, 0, err)
        record = json.loads(sf.RECORD_BLOCK.search(self.fake.comments[ISSUE][-1]["body"]).group(1))
        self.assertEqual(record["deployed_commit"]["sha"], self.shas[1])
        self.assertEqual(record["covers_commits"], [self.shas[1]])

    def test_non_click_tester_agent_is_refused(self):
        self.wal(self.main_wal, {"at": "t", "event": "subagent", "agent_id": "fx1", "agent_type": "fixer"})
        code, _, _ = self.run_cli("click-test", "--ticket", "GoodQA harness#168", "--actor", "agent:owner1",
                                  "--url", "u", "--agent-id", "fx1", "--wal-dir", str(self.wal_dir),
                                  "--repo", str(self.repo_dir), "--deployed-commit", self.shas[-1],
                                  "--result", "pass", "--report", str(self.report))
        self.assertEqual(code, 2)


class DoneGate(SpecFlowCase):
    def complete(self, signer=("main1", "agent"), tester="ct1"):
        self.attached()
        owner_wal = self.wal_dir / "agent-owner1.jsonl"
        self.wal(owner_wal, {"at": "2026-11-04T02:00:00+00:00", "event": "check", "note": "REALLY_TESTED RT1: ok exit 0"})
        for ac in ("AC-1", "AC-2"):
            code, _, err = self.run_cli("evidence", "--ticket", "GoodQA harness#168", "--actor", "agent:owner1",
                                        "--ac", ac, "--really-tested", "RT1", "--wal", str(owner_wal))
            self.assertEqual(code, 0, err)
        self.wal(self.main_wal, {"at": "2026-11-04T05:00:00+00:00", "event": "subagent", "agent_id": tester,
                                 "agent_type": "click-tester"})
        report = self.tmp / "click.md"
        report.write_text("CLICK_TEST_RESULT: PASS\nok\n")
        self.wal(self.wal_dir / f"agent-{tester}.jsonl", {"at": "2026-11-04T05:01:00+00:00", "event": "result",
                                                    "note": "CLICK_TEST_REPORT sha256=" + hashlib.sha256(report.read_bytes()).hexdigest()})
        self.repo_dir = self.tmp / "deployed"
        self.shas = git_repo(self.repo_dir, "feat: one", "feat: later")
        code, _, err = self.run_cli("click-test", "--ticket", "GoodQA harness#168", "--actor", "agent:owner1",
                                    "--url", "http://127.0.0.1:3000", "--agent-id", tester, "--wal-dir",
                                    str(self.wal_dir), "--repo", str(self.repo_dir), "--deployed-commit",
                                    self.shas[0], "--result", "pass", "--report", str(report))
        self.assertEqual(code, 0, err)
        if signer:
            code, _, err = self.run_cli("signoff", "--ticket", "GoodQA harness#168", "--actor", f"agent:{signer[0]}",
                                        "--by", signer[0], "--kind", signer[1], "--source", "main review of #168")
            self.assertEqual(code, 0, err)

    def test_click_test_by_the_owner_does_not_count(self):
        self.complete(tester="owner1")
        result = self.evaluate()
        self.assertFalse(result["ready"])
        self.assertTrue(any("independent click-tester" in m for m in result["missing"]), result["missing"])

    def test_declared_deployed_commit_is_listed_as_self_attested(self):
        self.complete()
        result = self.evaluate()
        self.assertTrue(result["ready"], result["missing"])
        self.assertTrue(any("deployed commit" in a for a in result["self_attested"]), result["self_attested"])

    def test_evidence_commit_after_the_click_test_needs_a_new_click_test(self):
        self.complete()
        self.assertTrue(self.evaluate()["ready"])
        code, _, err = self.run_cli("evidence", "--ticket", "GoodQA harness#168", "--actor", "agent:owner1",
                                    "--ac", "AC-1", "--commit", self.shas[1], "--repo", str(self.repo_dir),
                                    "--note", "fix after click-test")
        self.assertEqual(code, 0, err)
        result = self.evaluate()
        self.assertFalse(result["ready"])
        self.assertTrue(any("came after the deployed commit" in m for m in result["missing"]), result["missing"])

    def test_missing_items_are_listed_with_fixes(self):
        self.attached()
        code, out, _ = self.run_cli("done", "--ticket", "GoodQA harness#168")
        self.assertEqual(code, 2)
        for needle in ("AC-1: no evidence", "AC-2: no evidence", "click-test: none recorded", "sign-off: none valid",
                       "Fix:"):
            self.assertIn(needle, out)
        self.assertEqual(self.run_cli("done", "--ticket", "GoodQA harness#168")[0], 2)

    def test_no_spec_is_not_ready(self):
        code, out, _ = self.run_cli("status", "--ticket", "GoodQA harness#168")
        self.assertEqual(code, 2)
        self.assertIn("No verified spec", out)

    def test_complete_ticket_is_ready_and_lists_self_attested(self):
        self.complete()
        code, out, _ = self.run_cli("done", "--ticket", "GoodQA harness#168")
        self.assertEqual(code, 0, out)
        self.assertIn("READY", out)
        self.assertIn("Self-attested", out)

    def test_tampered_attachment_is_not_accepted(self):
        self.complete()
        spec_row = next(a for a in self.fake.attachments.values() if a["metadata"]["filename"] == "spec.md")
        spec_row["sha256"] = "0" * 64
        result = self.evaluate()
        self.assertFalse(result["ready"])
        self.assertIn("No verified spec", result["missing"][0])

    def test_signoff_by_owner_or_reviewer_is_refused(self):
        self.complete(signer=None)
        for who in ("owner1", "acc1"):
            code, _, err = self.run_cli("signoff", "--ticket", "GoodQA harness#168", "--actor", "agent:main1",
                                        "--by", who, "--kind", "agent", "--source", "x")
            self.assertEqual(code, 2, who)

    def test_gate_itself_rejects_a_signoff_record_from_the_owner(self):
        self.complete(signer=None)
        record = {"v": 1, "kind": "signoff", "spec_core_sha": sf.core_sha(SPEC), "by": "agent:owner1",
                  "signer_kind": "agent", "source": "self", "key": "signoff:forged", "actor": "agent:owner1"}
        adapter = sf.make_adapter(self.config, self.spec_policy, "harness", time.monotonic() + 30)
        adapter.comment_with_files(ISSUE, sf.record_body("sign-off", record), str(uuid.uuid4()))
        result = self.evaluate()
        self.assertFalse(result["ready"])
        self.assertTrue(any("owner, author or a spec reviewer" in m for m in result["missing"]), result["missing"])

    def test_evidence_for_an_older_spec_is_stale(self):
        self.complete()
        revised = SPEC.replace("cannot mark", "can never mark")
        spec = self.tmp / "spec.md"
        spec.write_text(revised)
        (self.tmp / "spec.md.reviews.json").unlink()
        report = self.tmp / "adv2.md"
        report.write_text(report_text(sf.core_sha(revised)))
        self.run_cli("review", str(spec), "--role", "adversarial", "--report", str(report))
        self.run_cli("review", str(spec), "--role", "acceptance", "--agent", "acc1", "--wal", str(self.main_wal),
                     "--verdict", "ACCEPT", "--report-file", str(self.tmp / "acc-report.md"))
        self.assertEqual(self.run_cli("attach", str(spec), "--actor", "agent:owner1")[0], 0)
        result = self.evaluate()
        self.assertFalse(result["ready"])
        self.assertTrue(any("AC-1" in m and "stale" in m for m in result["missing"]), result["missing"])

    def test_human_required_rejects_agent_signoff(self):
        self.fake.issues[ISSUE]["description"] = "Needs human sign-off before close."
        self.complete()
        result = self.evaluate()
        self.assertFalse(result["ready"])
        self.assertTrue(any("requires a human sign-off" in item for item in result["missing"]))

    def test_apply_reports_tracker_refusal(self):
        self.complete()
        self.fake.refuse_done = True
        code, out, _ = self.run_cli("done", "--ticket", "GoodQA harness#168", "--apply")
        self.assertEqual(code, 5)
        self.assertIn("TRACKER_REFUSED", out)
        self.assertEqual(self.fake.issues[ISSUE]["status"], "in_progress")
        self.fake.refuse_done = False
        self.assertEqual(self.run_cli("done", "--ticket", "GoodQA harness#168", "--apply")[0], 0)
        self.assertEqual(self.fake.issues[ISSUE]["status"], "done")

    def test_comment_page_budget_fails_closed(self):
        self.attached()
        self.fake.comments[ISSUE] += [{"id": str(uuid.uuid4()), "body": "x", "createdAt": self.fake.now()}
                                      for _ in range(500)]
        self.config["max_comment_pages"] = 2
        code, _, err = self.run_cli("done", "--ticket", "GoodQA harness#168")
        self.assertEqual(code, 4)
        self.assertIn("too many records", err)


class Hook(SpecFlowCase):
    def hook(self, tool, tool_input, **policy):
        self.spec_policy.update(policy)
        return sf.run_hook({"tool_name": f"mcp__plugin_goodqa_goodqa__{tool}", "tool_input": tool_input},
                           self.spec_policy)

    def enforce(self):
        return {"mode": "enforce", "enforced_projects": ["harness"]}

    def test_other_tools_and_open_statuses_need_no_network(self):
        self.assertEqual(sf.run_hook({"tool_name": "Bash", "tool_input": {}}, self.spec_policy), (0, ""))
        self.assertEqual(self.hook("update_issue", {"issueId": ISSUE, "patch": {"priority": "high"}}, **self.enforce()),
                         (0, ""))
        self.assertEqual(self.hook("close_issue_done", {"issueId": ISSUE, "note": "x"}, **self.enforce()), (0, ""))
        self.assertEqual(self.fake.calls, [])

    def test_done_without_spec_blocks_in_enforce_and_warns_in_warn(self):
        code, text = self.hook("close_issue_done", {"issueId": ISSUE, "status": "done", "note": "x"}, **self.enforce())
        self.assertEqual(code, 2)
        self.assertIn("No verified spec", text)
        code, text = self.hook("close_issue_done", {"issueId": ISSUE, "status": "done", "note": "x"},
                               mode="warn", enforced_projects=["harness"])
        self.assertEqual(code, 0)
        self.assertIn("not blocking", text)

    def test_issue_no_routed_key_can_read_warns_even_in_enforce(self):
        other = str(uuid.uuid4())
        code, text = self.hook("update_issue", {"issueId": other, "patch": {"status": "done"}}, **self.enforce())
        self.assertEqual(code, 0)
        self.assertIn("not in an enforced project", text)
        code, text = self.hook("update_issue", {"issueId": "not-a-uuid", "patch": {"status": "done"}}, **self.enforce())
        self.assertEqual(code, 0)
        self.assertIn("malformed", text)

    def test_unenforced_project_only_warns(self):
        code, text = self.hook("update_issue", {"issueId": ISSUE, "patch": {"status": "done"}},
                               mode="enforce", enforced_projects=[])
        self.assertEqual(code, 0)
        self.assertIn("No verified spec", text)

    def test_reason_unknown_archive_stage_delete_and_bulk(self):
        policy = self.enforce()
        cases = [
            ("close_issue_wont_fix", {"issueId": ISSUE, "note": "no"}),
            ("update_issue", {"issueId": ISSUE, "patch": {"status": "shipped"}}),
            ("update_issue", {"issueId": ISSUE, "patch": {"status": "duplicate"}}),
            ("archive_issue", {"issueId": ISSUE}),
            ("reassign_issue", {"issueId": ISSUE, "stageId": str(uuid.uuid4())}),
            ("call_api", {"method": "DELETE", "path": f"/v1/issues/{ISSUE}"}),
            ("call_api", {"method": "PATCH", "path": f"/v1/issues/{ISSUE}", "body": {"status": "done"}}),
            ("bulk_update_issues", {"items": [{"issueId": ISSUE, "status": "todo"},
                                              {"issueId": ISSUE, "status": "done"}]}),
            ("call_api", {"method": "POST", "path": f"/v1/projects/{PROJECT}/issues/bulk", "body": {}}),
        ]
        for tool, tool_input in cases:
            with self.subTest(tool=tool, tool_input=tool_input):
                self.assertEqual(self.hook(tool, tool_input, **policy)[0], 2)
        allowed = [("close_issue_wont_fix", {"issueId": ISSUE, "note": "superseded by #170, same scope there"}),
                   ("bulk_update_issues", {"items": [{"issueId": ISSUE, "status": "in_review"}]}),
                   ("call_api", {"method": "GET", "path": f"/v1/issues/{ISSUE}"})]
        for tool, tool_input in allowed:
            with self.subTest(tool=tool):
                self.assertEqual(self.hook(tool, tool_input, **policy)[0], 0)

    def test_complete_ticket_passes_enforced_done(self):
        DoneGate.complete(self)
        self.assertEqual(self.hook("close_issue_done", {"issueId": ISSUE, "status": "done", "note": "x"},
                                   **self.enforce())[0], 0)

    def test_unreachable_fails_closed_only_in_enforce(self):
        self.fake.server.shutdown()
        self.fake.server.server_close()
        self.fake.closed = True
        self.config["attempts"] = 1
        args = ("close_issue_done", {"issueId": ISSUE, "status": "done", "note": "x"})
        self.assertEqual(self.hook(*args, **self.enforce())[0], 2)
        self.assertEqual(self.hook(*args, mode="warn")[0], 0)

    def test_hook_cli_ignores_other_tools_before_reading_policy(self):
        with mock.patch.object(sf, "load_spec_policy", side_effect=AssertionError("policy read")), \
                mock.patch("sys.stdin", io.StringIO(json.dumps({"tool_name": "Bash", "tool_input": {}}))):
            self.assertEqual(sf.main(["hook"]), 0)


@unittest.skipUnless(os.environ.get("SPEC_FLOW_SLOW_TESTS") == "1", "slow deadline test; set SPEC_FLOW_SLOW_TESTS=1")
class HookDeadline(SpecFlowCase):
    def test_slow_tracker_with_default_budget_blocks_before_hook_timeout(self):
        defaults = cp.load_policy(HOOKS / "commit_policy.json")["ticket_systems"]["goodqa"]
        for key in ("timeout_seconds", "total_deadline_seconds", "attempts", "max_comment_pages"):
            self.config[key] = defaults[key]
        self.fake.delay = 100
        start = time.monotonic()
        code, text = sf.run_hook({"tool_name": "mcp__goodqa__close_issue_done",
                                  "tool_input": {"issueId": ISSUE, "status": "done", "note": "x"}},
                                 dict(self.spec_policy, mode="enforce", enforced_projects=["harness"]))
        elapsed = time.monotonic() - start
        self.assertEqual(code, 2, text)
        self.assertLess(elapsed, 55, elapsed)


class PlanGate(SpecFlowCase):
    def repo(self, origin="https://github.com/ericmacdougall/agent-harness.git"):
        repo = Path(tempfile.mkdtemp(dir=self.tmp))
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        subprocess.run(["git", "-C", str(repo), "remote", "add", "origin", origin], check=True)
        return repo

    def gate(self, packet, mode, origin=None):
        return sf.plan_ticket_gate(self.repo(*(origin and [origin] or [])), packet,
                                   spec_policy=dict(self.spec_policy, plan_ticket_gate=mode),
                                   config_loader=lambda _sp: (cp, self.policy, self.config))

    def test_missing_ticket_warns_or_blocks(self):
        code, text = self.gate("# Plan\nno ticket here\n", "warn")
        self.assertEqual(code, 0)
        self.assertIn("no `Ticket:", text)
        self.assertEqual(self.gate("# Plan\n", "enforce")[0], 2)

    def test_valid_ticket_passes_and_bare_or_unknown_fail(self):
        self.assertEqual(self.gate("Ticket: GoodQA harness#168\n", "enforce"), (0, ""))
        self.assertEqual(self.gate("Ticket: GoodQA Harness#168\n", "enforce"), (0, ""))
        self.assertEqual(self.gate("Ticket: GoodQA #168\n", "enforce")[0], 2)
        self.assertEqual(self.gate("Ticket: GoodQA harness#999\n", "enforce")[0], 2)

    def test_untracked_repo_and_spec_packet(self):
        self.assertEqual(self.gate("# no ticket\n", "enforce", origin="https://gitlab.com/other/x.git"), (0, ""))
        self.assertEqual(self.gate(sf.spec_core(SPEC), "enforce"), (0, ""))

    def test_unreachable_is_unverified(self):
        self.fake.server.shutdown()
        self.fake.server.server_close()
        self.fake.closed = True
        self.config["attempts"] = 1
        code, text = self.gate("Ticket: GoodQA harness#168\n", "enforce")
        self.assertEqual(code, 6)
        self.assertIn("TICKETS_UNVERIFIED", text)


class WalStop(unittest.TestCase):
    def test_subagent_stop_recorded_only_for_logged_agents(self):
        home = Path(tempfile.mkdtemp())
        env = dict(os.environ, HOME=str(home))

        def run(event, payload):
            return subprocess.run([sys.executable, str(HOOKS / "wal.py"), event], input=json.dumps(payload),
                                  capture_output=True, text=True, env=env)
        self.assertEqual(run("subagent", {"session_id": "s1", "agent_id": "ct1", "agent_type": "click-tester"}).returncode, 0)
        self.assertEqual(run("subagent_stop", {"session_id": "s1", "agent_id": "ct1", "agent_type": "click-tester"}).returncode, 0)
        self.assertEqual(run("subagent_stop", {"session_id": "s1", "agent_id": "ghost", "agent_type": ""}).returncode, 0)
        main = (home / ".claude" / "wals" / "s1" / "main.jsonl").read_text().splitlines()
        events = [(json.loads(line)["event"], json.loads(line).get("agent_id")) for line in main]
        self.assertEqual(events, [("subagent", "ct1"), ("subagent_stop", "ct1")])
        self.assertFalse((home / ".claude" / "wals" / "s1" / "agent-ghost.jsonl").exists())


class Install(unittest.TestCase):
    def test_reinstall_keeps_one_spec_gate_and_one_stop_hook(self):
        sys.path.insert(0, str(HOOKS.parents[1]))
        import install
        claude = Path("/tmp/claude-home/.claude")
        settings = install.merged_settings(install.merged_settings({}, claude), claude)
        pre = [h for entry in settings["hooks"]["PreToolUse"] for h in entry["hooks"]
               if (h.get("args") or [""])[0].endswith("spec_flow.py")]
        stops = [h for entry in settings["hooks"]["SubagentStop"] for h in entry["hooks"]]
        self.assertEqual(len(pre), 1)
        self.assertEqual((pre[0]["timeout"], pre[0]["onFailure"]), (60, "block"))
        self.assertEqual(len(stops), 1)
        self.assertEqual(settings["hooks"]["SubagentStop"][0]["matcher"], install.SUBAGENT_MATCHER)
        self.assertIn("spec_flow.py", install.HOOKS)
        self.assertGreater(60, json.loads((HOOKS / "spec_policy.json").read_text())["hook_deadline_seconds"])


if __name__ == "__main__":
    unittest.main()


class DocumentedCommands(unittest.TestCase):
    def test_every_documented_example_parses(self):
        import re
        import shlex
        doc = (HOOKS.parents[1] / "docs" / "operations.md").read_text()
        lines = [line.split("  #")[0] for line in doc.splitlines() if line.startswith("python3 $S ")]
        self.assertGreaterEqual(len(lines), 10)
        parser = sf.build_parser()
        for line in lines:
            # Optional parts are shown in [brackets]; check the line with them included.
            # A <placeholder> stands for one argument even when it contains spaces.
            line = re.sub(r"<[^<>]*>", lambda m: "PLACEHOLDER", line)
            words = shlex.split(line.replace("[", " ").replace("]", " "))[2:]
            with self.subTest(line=line):
                parser.parse_args(words)

