"""ah ticket create (harness/hooks/ah_ticket.py): idempotency, lost responses, redaction, input limits."""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

HOOKS = Path(__file__).resolve().parents[1] / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
import ah  # noqa: E402
import ah_ticket as at  # noqa: E402


class Unavailable(Exception):
    pass


class FakeMod:
    TicketSystemUnavailable = Unavailable


class FakeAdapter:
    def __init__(self):
        self.calls = []
        self.issues = {}  # operationId -> issue (server-side dedupe)
        self.lose_response_once = False
        self.next_number = 14900

    def org_id(self):
        return "org-1"

    def call(self, tool, args):
        self.calls.append((tool, dict(args)))
        if tool == "list_projects":
            return {"projects": [{"id": "pid-goodqa", "slug": "goodqa"}, {"id": "pid-other", "slug": "other"}]}
        if tool == "create_issue":
            op = args["operationId"]
            if op not in self.issues:
                self.next_number += 1
                self.issues[op] = {"id": "iss-%d" % self.next_number, "number": self.next_number}
            if self.lose_response_once:
                self.lose_response_once = False
                raise Unavailable("GoodQA unreachable for create_issue (timeout)")
            return {"issue": self.issues[op]}
        raise AssertionError(tool)

    def creates(self):
        return [a for t, a in self.calls if t == "create_issue"]


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.home = Path(self.tmp.name)
        self.body = self.home / "body.md"
        self.body.write_text("Why: x\nWhat: y\n")
        self.adapter = FakeAdapter()

    def create(self, **kw):
        kw.setdefault("project", "goodqa")
        kw.setdefault("title", "Runaway process stop command")
        kw.setdefault("body_file", str(self.body))
        return at.create(home=self.home, adapter=self.adapter, mod=FakeMod, **kw)


class Create(Base):
    def test_creates_with_resolved_project_and_operation_id(self):
        out = self.create(type_="bug", priority="high")
        self.assertEqual(out["ticket"], "GoodQA goodqa#14901")
        self.assertFalse(out["deduplicated"])
        args = self.adapter.creates()[0]
        self.assertEqual((args["projectId"], args["type"], args["priority"]), ("pid-goodqa", "bug", "high"))
        self.assertEqual(args["description"], "Why: x\nWhat: y\n")
        self.assertRegex(args["operationId"], r"^[0-9a-f-]{36}$")

    def test_retry_finds_its_row_past_eight_mib_of_ledger(self):
        """goodqa#14999: the lookup has no total budget. A created row after (or before) more than 8 MiB of other
        rows is still found, so a retry never files a second ticket. A quiet stop at a byte budget would miss it."""
        ledger = at._ledger(self.home)
        filler = (json.dumps({"at": 1, "key": "tc-other-%06d" % 0, "status": "pending", "title": "x" * 200}) + "\n")
        with open(ledger, "w") as f:
            for i in range(9 * 1024 * 1024 // len(filler) + 10):
                f.write(filler.replace("%06d" % 0, "%06d" % i))
        a = self.create(key="owner-task-big")
        self.assertFalse(a["deduplicated"])
        with open(ledger, "a") as f:
            f.write("[1, 2]\n" + "{" * 70000 + "\n" + "not json\n")  # wrong shape, over-long and junk rows are skipped
        b = self.create(key="owner-task-big")
        self.assertTrue(b["deduplicated"])
        self.assertEqual(a["number"], b["number"])
        self.assertEqual(len(self.adapter.creates()), 1)

    def test_read_error_after_a_match_keeps_the_match(self):
        """Code inspection (N12): an OSError mid-read must not discard a created row already found."""
        from unittest import mock
        import safe_input
        a = self.create(key="owner-task-err")
        real = safe_input.iter_jsonl_lines

        def failing(path, **kwargs):
            for item in real(path, **kwargs):
                yield item
            raise OSError("read failed")
        with mock.patch.object(safe_input, "iter_jsonl_lines", side_effect=failing):
            b = self.create(key="owner-task-err")
        self.assertTrue(b["deduplicated"])
        self.assertEqual(len(self.adapter.creates()), 1)
        self.assertEqual(a["number"], b["number"])

    def test_same_key_twice_files_one_ticket(self):
        a = self.create(key="owner-task-1")
        b = self.create(key="owner-task-1")
        self.assertEqual(a["number"], b["number"])
        self.assertTrue(b["deduplicated"])
        self.assertEqual(len(self.adapter.creates()), 1)

    def test_default_key_dedupes_identical_requests_and_not_different_ones(self):
        a, b = self.create(), self.create()
        self.assertEqual(a["number"], b["number"])
        c = self.create(title="A different title")
        self.assertNotEqual(a["number"], c["number"])

    def test_lost_response_then_retry_returns_the_same_ticket(self):
        self.adapter.lose_response_once = True
        with self.assertRaises(at.TicketCreateError) as cm:
            self.create(key="lost-response-1")
        self.assertEqual(cm.exception.code, "ticket_unavailable")
        self.assertIn("lost-response-1", str(cm.exception))
        out = self.create(key="lost-response-1")
        ops = {c["operationId"] for c in self.adapter.creates()}
        self.assertEqual(len(ops), 1, "the retry must reuse the operationId so the server dedupes")
        self.assertEqual(len(self.adapter.issues), 1, "exactly one ticket exists server-side")
        self.assertEqual(out["number"], 14901)

    def test_secrets_are_redacted_from_title_and_body(self):
        self.body.write_text("token=sk-live-ABCDEF123456SECRETVALUE\n")
        self.create(title="found sk-live-ABCDEF123456SECRETVALUE in log")
        sent = json.dumps(self.adapter.creates()[0])
        self.assertNotIn("SECRETVALUE", sent)

    def test_unknown_project_and_bad_inputs_create_nothing(self):
        for kw in ({"project": "nope"}, {"project": "Bad Slug"}, {"title": "   "}, {"title": "x" * 300},
                   {"type_": "epicc"}, {"priority": "p0"}, {"key": "short"}, {"body_file": str(self.home / "missing")}):
            with self.subTest(kw=kw):
                with self.assertRaises(at.TicketCreateError):
                    self.create(**kw)
        self.assertEqual(self.adapter.creates(), [])

    def test_body_must_be_a_small_regular_file(self):
        link = self.home / "link.md"
        link.symlink_to(self.body)
        with self.assertRaises(at.TicketCreateError):
            self.create(body_file=str(link))
        big = self.home / "big.md"
        big.write_text("x" * (at.MAX_BODY + 1))
        with self.assertRaises(at.TicketCreateError):
            self.create(body_file=str(big))
        with self.assertRaises(at.TicketCreateError):
            self.create(body_file=str(self.home))

    def test_ledger_is_private(self):
        self.create()
        mode = os.stat(self.home / ".agent-harness" / "state" / "ah" / "ticket-create.jsonl").st_mode & 0o777
        self.assertEqual(mode, 0o600)


class Cli(Base):
    def test_cli_reports_a_bad_type_as_json_and_exit_2(self):
        import contextlib
        import io
        out = io.StringIO()
        old = os.environ.get("HOME")
        os.environ["HOME"] = str(self.home)
        self.addCleanup(lambda: os.environ.__setitem__("HOME", old))
        with contextlib.redirect_stdout(out):
            code = ah.main(["ticket", "create", "--project", "goodqa", "--title", "t", "--body-file", str(self.body),
                            "--type", "nonsense"])
        self.assertEqual(code, 2)
        self.assertEqual(json.loads(out.getvalue())["code"], "bad_request")


if __name__ == "__main__":
    unittest.main()
