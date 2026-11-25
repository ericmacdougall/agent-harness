"""ah ticket edit (harness/hooks/ah_ticket.py edit, ticket_adapters GoodQA update_fields): a title or priority change is
one update_issue call carrying only the fields given. No network: the adapter is a fake, and the GoodQA adapter's own
method is checked against a fake `call`."""
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

HOOKS = Path(__file__).resolve().parents[1] / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
import ah  # noqa: E402
import ah_ticket as at  # noqa: E402
import ticket_adapters as ta  # noqa: E402


class Unavailable(Exception):
    pass


class FakeMod:
    TicketSystemUnavailable = Unavailable
    TicketOutOfScope = type("OutOfScope", (Exception,), {})


class FakeAdapter:
    def __init__(self, fail=False):
        self.updates, self.fail = [], fail

    def lookup(self, project, number):
        return SimpleNamespace(id="iss-%d" % number, project=project, number=number)

    def update_fields(self, ticket, patch):
        if self.fail:
            raise Unavailable("GoodQA unreachable for update_issue (timeout)")
        self.updates.append((ticket.id, dict(patch)))
        return {"issue": dict({"id": ticket.id}, **patch)}


class Edit(unittest.TestCase):
    def edit(self, *a, adapter=None, **kw):
        self.adapter = adapter or FakeAdapter()
        return at.edit(*a, adapter=self.adapter, mod=FakeMod, redactor=lambda t: t, **kw)

    def test_title_and_priority_in_one_call_with_only_those_fields(self):
        out = self.edit("GoodQA goodqa#17013", title="  DM reply   for user tokens ", priority="high")
        self.assertEqual(self.adapter.updates, [("iss-17013", {"title": "DM reply for user tokens", "priority": "high"})])
        self.assertEqual((out["ticket"], out["changed"]), ("GoodQA goodqa#17013", ["priority", "title"]))
        self.edit("42", priority="low")
        self.assertEqual(self.adapter.updates, [("iss-42", {"priority": "low"})])

    def test_bad_input_sends_nothing(self):
        for kw in ({}, {"priority": "huge"}, {"title": "   "}, {"title": "x" * 201}):
            with self.subTest(kw=kw):
                adapter = FakeAdapter()
                with self.assertRaises(at.TicketCreateError):
                    self.edit("42", adapter=adapter, **kw)
                self.assertEqual(adapter.updates, [])
        with self.assertRaises(ah.AhError):
            self.edit("not a ref", priority="low")

    def test_unavailable_is_reported_as_retryable(self):
        with self.assertRaises(at.TicketCreateError) as caught:
            self.edit("42", priority="low", adapter=FakeAdapter(fail=True))
        self.assertEqual(caught.exception.code, "ticket_unavailable")

    def test_goodqa_adapter_uses_update_issue_with_a_patch(self):
        calls = []
        adapter = ta.GoodQAAdapter.__new__(ta.GoodQAAdapter)
        adapter.call = lambda tool, args: calls.append((tool, args)) or {"issue": {"id": "iss-1", "priority": "high"}}
        ticket = ta.Ticket("GoodQA", "goodqa", 1, "iss-1", "t", "open")
        adapter.update_fields(ticket, {"priority": "high"})
        self.assertEqual(calls, [("update_issue", {"issueId": "iss-1", "patch": {"priority": "high"}})])
        adapter.call = lambda tool, args: {"__error__": "forbidden"}
        with self.assertRaises(ta.TicketSystemUnavailable):
            adapter.update_fields(ticket, {"title": "x"})

    def test_cli_wiring(self):
        args = ah.build_parser().parse_args(["ticket", "edit", "goodqa#5", "--title", "T", "--priority", "low"])
        self.assertEqual((args.sub, args.number, args.title, args.priority), ("edit", "goodqa#5", "T", "low"))


if __name__ == "__main__":
    unittest.main()
