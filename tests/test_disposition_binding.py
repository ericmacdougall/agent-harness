"""GoodQA #15565 (never-drop 16.1): a disposition binds to a live holder or it does not count.

`resumed`, `reassigned` and `waiting` are claims that someone holds the work. They excuse a DROPPED or SILENT-HIGH owner
only while the thing they name is live. The replay fixture is the real `ah owners` output of 2026-11-09, where every
flagged owner was "disposed" and ownerless."""

import json
import sys
import unittest
from pathlib import Path

HOOKS = Path(__file__).resolve().parents[1] / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
import liveness  # noqa: E402

FIXTURE = Path(__file__).resolve().parent / "data" / "owners_2026-11-09.json"


def row(agent, state="live", idle=30, ticket=None, owner=True):
    return {"agent_id": agent, "state": state, "idle_s": idle, "ticket": ticket, "owner": owner}


class Binding(unittest.TestCase):
    def bound(self, disp, me, others=(), asks=None, covered=None):
        rows = [me, *others]
        return liveness.disposition_bound(disp, me, {r["agent_id"]: r for r in rows}, rows, asks or {}, covered)

    def test_holds_work_means_active_in_the_last_ten_minutes(self):
        self.assertTrue(liveness.holds_work(row("a")))
        self.assertTrue(liveness.holds_work(row("a", "quiet", 599)))
        self.assertFalse(liveness.holds_work(row("a", "quiet", 601)))
        for state in ("SILENT", "SILENT-HIGH", "DROPPED", "done", "returned", "handoff"):
            self.assertFalse(liveness.holds_work(row("a", state, 5)), state)
        self.assertFalse(liveness.holds_work(None))

    def test_resumed_and_reassigned_need_a_live_named_agent(self):
        me = row("dropped", "DROPPED", 90000)
        live, dead = row("alive00000000"), row("dead000000000", "returned", 4000)
        for kind in ("resumed", "reassigned"):
            self.assertTrue(self.bound({"kind": kind, "ref": "alive00000000"}, me, [live]), kind)
            self.assertTrue(self.bound({"kind": kind, "ref": "alive000"}, me, [live]), kind + " prefix of 8")
            self.assertFalse(self.bound({"kind": kind, "ref": "dead000000000"}, me, [dead]), kind)
            self.assertFalse(self.bound({"kind": kind, "ref": "nobody0000000"}, me, [live]), kind)
            self.assertFalse(self.bound({"kind": kind}, me, [live]), kind + " without a ref")
            self.assertFalse(self.bound({"kind": kind, "ref": "dropped"}, me), kind + " naming itself")
            self.assertFalse(self.bound({"kind": kind, "ref": "alive"}, me, [live]), kind + " short prefix")

    def test_reassigned_may_chain_through_a_covered_target(self):
        me, mid = row("dropped", "DROPPED", 9e4), row("middle000000", "returned", 4000)
        self.assertTrue(self.bound({"kind": "reassigned", "ref": "middle000000"}, me, [mid], covered=lambda ref: True))
        self.assertFalse(self.bound({"kind": "reassigned", "ref": "middle000000"}, me, [mid], covered=lambda ref: False))

    def test_waiting_binds_to_an_open_ask_a_live_agent_or_a_ticket_a_live_owner_holds(self):
        me = row("dropped", "DROPPED", 9e4, ticket="GoodQA goodqa#14553")
        ask = "wa5b00000001"
        self.assertTrue(self.bound({"kind": "waiting", "ref": ask}, me, asks={ask: "open"}))
        self.assertFalse(self.bound({"kind": "waiting", "ref": ask}, me, asks={ask: "resolved"}))
        self.assertFalse(self.bound({"kind": "waiting", "ref": ask}, me))
        holder = row("holder0000000", ticket="goodqa#14553")
        self.assertTrue(self.bound({"kind": "waiting", "ref": "GoodQA goodqa#14553"}, me, [holder]))
        self.assertFalse(self.bound({"kind": "waiting", "ref": "GoodQA goodqa#14553"}, me), "ownerless ticket")
        stale = row("stale00000000", "SILENT-HIGH", 9e4, ticket="goodqa#14553")
        self.assertFalse(self.bound({"kind": "waiting", "ref": "goodqa#14553"}, me, [stale]), "holder not live")
        self.assertFalse(self.bound({"kind": "waiting", "ref": "goodqa#14553"}, me, [row("h", ticket="goodqa#9999")]))
        self.assertTrue(self.bound({"kind": "waiting", "ref": "holder0000000"}, me, [holder]))

    def test_a_reviewer_or_other_helper_never_holds_a_stream(self):
        # red-team a5fc13ab D2: a live red-team agent is not a successor
        me = row("dropped", "DROPPED", 9e4, ticket="goodqa#14553")
        helper = dict(row("rt0000000001"), type="red-team", ticket="goodqa#14553")
        for kind in ("resumed", "reassigned", "waiting"):
            self.assertFalse(self.bound({"kind": kind, "ref": "rt0000000001"}, me, [helper]), kind)
        self.assertFalse(self.bound({"kind": "waiting", "ref": "goodqa#14553"}, me, [helper]))

    def test_a_live_agent_that_is_not_an_owner_and_holds_another_ticket_is_not_a_holder(self):
        # red-team a5fc13ab R3: a reviewer spawned as general-purpose is live but is not an owner (ah owners flags none)
        me = row("dropped", "DROPPED", 9e4, ticket="goodqa#14553")
        stranger = dict(row("stranger00001", ticket="goodqa#999"), type="general-purpose", owner=False)
        same = dict(row("samestream0001", ticket="goodqa#14553"), type="general-purpose", owner=False)
        for kind in ("resumed", "reassigned", "waiting"):
            self.assertFalse(self.bound({"kind": kind, "ref": "stranger00001"}, me, [stranger]), kind)
            self.assertTrue(self.bound({"kind": kind, "ref": "samestream0001"}, me, [same]), kind + " same ticket")
        flagged = dict(row("flagged000001"), decision_required=True)
        self.assertFalse(self.bound({"kind": "reassigned", "ref": "flagged000001"}, me, [flagged]))

    def test_ticket_waits_match_project_and_number(self):
        me = row("dropped", "DROPPED", 9e4)
        holder = row("holder0000000", ticket="GoodQA goodqa#665")
        self.assertTrue(self.bound({"kind": "waiting", "ref": "GoodQA goodqa#665"}, me, [holder]))
        self.assertFalse(self.bound({"kind": "waiting", "ref": "GoodQA parent-proof#665"}, me, [holder]))
        self.assertTrue(self.bound({"kind": "waiting", "ref": "GoodQA #665"}, me, [holder]), "no project named: number only")
        self.assertEqual(liveness.ticket_key("see #5 and goodqa#123"), ("", "5"))

    def test_a_successor_parked_in_a_named_wait_still_holds_the_work(self):
        # acceptance review abe6da04 D2: `ah owners` already demotes a wait on a closed ask to DROPPED
        me = row("dropped", "DROPPED", 9e4)
        parked = row("parked0000000", "waiting-on-wa5b00000001", 4000)
        self.assertTrue(self.bound({"kind": "reassigned", "ref": "parked0000000"}, me, [parked]))

    def test_a_row_cannot_hold_its_own_ticket_wait(self):
        me = row("me0000000000", "live", 5, ticket="goodqa#1")
        self.assertFalse(self.bound({"kind": "waiting", "ref": "goodqa#1"}, me))

    def test_permanent_kinds_are_not_binding_kinds(self):
        me = row("dropped", "DROPPED", 9e4)
        for kind in ("closed", "superseded", "wontdo", "legacy"):
            self.assertTrue(self.bound({"kind": kind, "ref": "x"}, me), kind)
        self.assertNotIn("reassigned", liveness.ENDING_DISPOSITIONS)

    def test_row_disposed_follows_the_bound_flag(self):
        base = {"decision_required": False, "state": "SILENT-HIGH"}
        self.assertFalse(liveness.row_disposed(dict(base, disposition={"kind": "reassigned", "live": False})))
        self.assertTrue(liveness.row_disposed(dict(base, disposition={"kind": "reassigned", "live": True})))
        self.assertTrue(liveness.row_disposed(dict(base, disposition={"kind": "closed", "live": True})))
        self.assertFalse(liveness.row_disposed(dict(base, disposition={"kind": "waiting", "live": False})))


class Replay(unittest.TestCase):
    """The flagged rows of 2026-11-09, evaluated with the new rule (no asks open, no WAL access needed)."""

    def test_every_flagged_row_without_a_live_holder_comes_back_undisposed(self):
        rows = json.loads(FIXTURE.read_text())["owners"]
        by_id = {r["agent_id"]: r for r in rows}
        flagged = [r for r in rows if r["state"] in ("DROPPED", "SILENT-HIGH") and r["disposition"]]
        self.assertGreaterEqual(len(flagged), 10)
        bound, permanent = [], []
        for r in flagged:
            d = r["disposition"]
            if d["kind"] not in liveness.BINDING_KINDS:
                permanent.append(r["agent_id"][:9])
                continue
            if liveness.disposition_bound(d, r, by_id, rows, {}):
                bound.append(r["agent_id"][:9])
        self.assertEqual(bound, [], "a flagged owner was excused by a holder that is not live")
        self.assertEqual(permanent, ["a2ee995ed"], "only the verified `closed` disposition is permanent")

    def test_the_one_reassignment_to_a_live_agent_still_holds(self):
        rows = json.loads(FIXTURE.read_text())["owners"]
        by_id = {r["agent_id"]: r for r in rows}
        quiet = next(r for r in rows if r["agent_id"].startswith("ad2d873e5"))
        self.assertTrue(liveness.holds_work(by_id[quiet["disposition"]["ref"]]))
        self.assertTrue(liveness.disposition_bound(quiet["disposition"], quiet, by_id, rows, {}))


if __name__ == "__main__":
    unittest.main()
