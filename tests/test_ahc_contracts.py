"""ahc_contracts: Review, Grant and Operation transitions per design v3 3.3, 3.9a and 2.5 (goodqa#16049 M-1)."""
import json
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path

HOOKS = Path(__file__).resolve().parent.parent / "harness" / "hooks"
sys.path.insert(0, str(HOOKS))
import ahc_contracts as C  # noqa: E402

H1, H2, BASE = "a" * 40, "b" * 40, "c" * 40
PKT = "d" * 64
POLICY = "policy-r1"


class Clock:
    def __init__(self):
        self.t = 1_800_000_000.0

    def __call__(self):
        return self.t


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.db = sqlite3.connect(":memory:", isolation_level=None)
        C.apply_schema(self.db)
        self.clock = Clock()
        self.log = C.AuthorityLog(Path(self.tmp.name) / "authority.jsonl")
        self.c = C.Contracts(self.db, self.log, now=self.clock)
        self.n = 0

    def ev(self):
        self.n += 1
        return "ev-%d" % self.n

    def state(self, table, column, ident):
        return self.db.execute("SELECT state FROM %s WHERE %s=?" % (table, column), (ident,)).fetchone()[0]

    def receipt(self, **changes):
        r = {"repo": "o/r", "pr": 5, "head": H1, "packet_sha256": PKT, "policy_revision": POLICY, "verdict": "PASS"}
        r.update(changes)
        return r

    def active_grant(self, **scope):
        s = {"repo": "o/r", "pr": 5, "head": H1, "base": BASE}
        s.update(scope)
        g = self.c.propose_grant("merge", "queue:fixture#6165f60532c0", "ahc-policy", s, POLICY, event_id=self.ev())
        g = self.c.validate_grant(g["id"], expected_version=g["version"], event_id=self.ev())
        return self.c.activate_grant(g["id"], expected_version=g["version"], event_id=self.ev())

    def merge_params(self, grant, **changes):
        p = {"repo": "o/r", "pr": 5, "head": H1, "base": BASE, "grant": grant, "method": "squash"}
        p.update(changes)
        return p


class ReviewTests(Base):
    def row(self, **kw):
        args = dict(kind="code", repo="O/R", pr=5, head=H1, packet_sha256=PKT, policy_revision=POLICY)
        args.update(kw)
        return self.c.require_review(**args)

    def walk(self, row, *states, **kw):
        for to in states:
            row = self.c.review(row["id"], to, expected_version=row["version"], event_id=self.ev(), **kw)
        return row

    def test_bound_row_is_idempotent_and_reaches_passed_on_a_matching_receipt(self):
        row = self.row()
        self.assertEqual(self.row()["id"], row["id"], "same binding, same row")
        self.assertNotEqual(self.row(policy_revision="policy-r2")["id"], row["id"], "policy revision is bound")
        row = self.walk(row, "queued", "running")
        row = self.c.review(row["id"], "passed", expected_version=row["version"], event_id=self.ev(),
                            receipt=self.receipt())
        self.assertEqual(row["state"], "passed")

    def test_receipt_for_another_subject_or_verdict_is_refused(self):
        row = self.walk(self.row(), "queued", "running")
        for changes in ({"head": H2}, {"packet_sha256": "e" * 64}, {"policy_revision": "policy-r2"}, {"pr": 6},
                        {"repo": "o/other"}, {"verdict": "BLOCK"}):
            with self.subTest(changes), self.assertRaises(C.ContractError):
                self.c.review(row["id"], "passed", expected_version=row["version"], event_id=self.ev(),
                              receipt=self.receipt(**changes))
        self.assertEqual(self.state("reviews", "id", row["id"]), "running", "nothing was written")
        with self.assertRaises(C.ContractError):
            self.c.review(row["id"], "findings", expected_version=row["version"], event_id=self.ev(),
                          receipt=self.receipt())

    def test_unlisted_transitions_actors_versions_and_event_reuse_are_refused(self):
        row = self.row()
        with self.assertRaises(C.ContractError):
            self.c.review(row["id"], "passed", expected_version=row["version"], event_id=self.ev(),
                          receipt=self.receipt())   # required -> passed does not exist
        with self.assertRaises(C.ContractError):
            self.c.review(row["id"], "queued", expected_version=row["version"], event_id=self.ev(),
                          actor="worker")
        with self.assertRaises(C.VersionConflict):
            self.c.review(row["id"], "queued", expected_version=row["version"] + 1, event_id=self.ev())
        with self.assertRaises(C.VersionConflict):
            self.c.review(row["id"], "queued", expected_version=None, event_id=self.ev())
        row = self.c.review(row["id"], "queued", expected_version=row["version"], event_id="ev-fixed")
        with self.assertRaises(C.ContractError):
            self.c.review(row["id"], "running", expected_version=row["version"], event_id="ev-fixed")

    def test_outcome_unknown_requeues_only_when_the_unit_is_gone(self):
        row = self.walk(self.row(), "queued", "running", "outcome-unknown")
        with self.assertRaises(C.ContractError):
            self.c.review(row["id"], "queued", expected_version=row["version"], event_id=self.ev())
        row = self.c.review(row["id"], "queued", expected_version=row["version"], event_id=self.ev(), unit_gone=True)
        self.assertEqual(row["state"], "queued")

    def test_new_head_supersedes_queued_cancels_running_and_leaves_unknown_for_readback(self):
        queued = self.walk(self.row(kind="code"), "queued")
        running = self.walk(self.row(kind="red-team"), "queued", "running")
        unknown = self.walk(self.row(kind="spec"), "queued", "running", "outcome-unknown")
        passed = self.c.review(self.walk(self.row(kind="sign-off"), "queued", "running")["id"], "passed",
                               expected_version=3, event_id=self.ev(), receipt=self.receipt())
        moved = dict(self.c.supersede_reviews("o/r", 5, H2, lambda rid: "rv-new", "sup"))
        self.assertEqual(moved, {queued["id"]: "superseded", running["id"]: "cancelling"})
        self.assertEqual(self.state("reviews", "id", unknown["id"]), "outcome-unknown")
        self.assertEqual(self.state("reviews", "id", passed["id"]), "passed", "history never changes")
        r = self.db.execute("SELECT version FROM reviews WHERE id=?", (running["id"],)).fetchone()[0]
        self.c.review(running["id"], "superseded", expected_version=r, event_id=self.ev())

    def test_waiver_needs_a_user_or_answer_source(self):
        row = self.row()
        with self.assertRaises(C.ContractError):
            self.c.review(row["id"], "waived", expected_version=row["version"], event_id=self.ev(),
                          waiver_source="agent:a80eaaad")
        self.c.review(row["id"], "waived", expected_version=row["version"], event_id=self.ev(),
                      waiver_source="user:s/u \"waive it\"")


class GrantTests(Base):
    def test_lifecycle_writes_the_authority_record_first(self):
        g = self.active_grant()
        self.assertEqual(g["state"], "active")
        self.assertEqual(self.log.records()[-1]["to"], "active")
        self.assertEqual(self.log.records()[-1]["label"], "local-not-off-host")
        op = self.c.intend("merge", self.merge_params(g["id"]), lease_ok=True, event_id=self.ev())
        g = self.c._row("grants", "id", g["id"])
        self.assertEqual((g["state"], g["operation"]), ("reserved", op["key"]))

    def test_authority_write_failure_leaves_the_grant_unchanged(self):
        g = self.c.propose_grant("merge", "queue:fixture", "ahc-policy",
                                 {"repo": "o/r", "pr": 5, "head": H1, "base": BASE}, POLICY, event_id=self.ev())
        g = self.c.validate_grant(g["id"], expected_version=g["version"], event_id=self.ev())
        Path(self.log.path).mkdir()   # the authority path is now a directory: the append fails
        with self.assertRaises(C.AuthorityError):
            self.c.activate_grant(g["id"], expected_version=g["version"], event_id=self.ev())
        self.assertEqual(self.state("grants", "id", g["id"]), "validated")

    def test_proposal_and_validation_guards(self):
        scope = {"repo": "o/r", "pr": 5, "head": H1, "base": BASE}
        with self.assertRaises(C.ContractError):
            self.c.propose_grant("merge", "queue:x", "agent-owner", scope, POLICY, event_id=self.ev())
        with self.assertRaises(C.ContractError):
            self.c.propose_grant("merge", "inferred:x", "ahc-policy", scope, POLICY, event_id=self.ev())
        for bad in ({"repo": "o/r", "pr": 5, "head": H1}, dict(scope, head="")):
            with self.subTest(bad), self.assertRaises(C.ContractError):
                g = self.c.propose_grant("merge", "queue:x", "ahc-policy", bad, POLICY, event_id=self.ev())
                self.c.validate_grant(g["id"], expected_version=g["version"], event_id=self.ev())
        g = self.c.propose_grant("merge", "queue:x", "ahc-policy", scope, POLICY, uses=2, event_id=self.ev())
        with self.assertRaises(C.ContractError):
            self.c.validate_grant(g["id"], expected_version=g["version"], event_id=self.ev())

    def test_reservation_is_scoped_single_and_never_past_expiry(self):
        g = self.active_grant()
        with self.assertRaises(C.ContractError):
            self.c.intend("merge", self.merge_params(g["id"], head=H2), lease_ok=True, event_id=self.ev())
        self.assertEqual(self.state("grants", "id", g["id"]), "active", "an out-of-scope op reserves nothing")
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM operations").fetchone()[0], 0)
        self.c.intend("merge", self.merge_params(g["id"]), lease_ok=True, event_id=self.ev())
        with self.assertRaises(C.ContractError):
            self.c.intend("merge", self.merge_params(g["id"], method="merge", base="e" * 40), lease_ok=True,
                          event_id=self.ev())
        late = self.active_grant(pr=6)
        self.clock.t += C.B47_GRANT_SECONDS + 1
        with self.assertRaises(C.ContractError):
            self.c.intend("merge", self.merge_params(late["id"], pr=6), lease_ok=True, event_id=self.ev())

    def test_reserved_past_expiry_has_no_transition_until_its_operation_settles(self):
        g = self.active_grant()
        idle = self.active_grant(pr=7)
        op = self.c.intend("merge", self.merge_params(g["id"]), lease_ok=True, event_id=self.ev())
        op = self.c.dispatch(op["key"], expected_version=op["version"], event_id=self.ev(), lease_ok=True)
        self.clock.t += C.B47_GRANT_SECONDS + 1
        self.assertEqual(self.c.expire_grants("sweep"), [idle["id"]])
        self.assertEqual(self.state("grants", "id", g["id"]), "reserved")
        op = self.c.confirm(op["key"], {"merged": True, "mergeCommit": "f" * 40}, expected_version=op["version"],
                            event_id=self.ev())
        self.assertEqual(self.state("grants", "id", g["id"]), "consumed", "settling still consumes it")

    def test_release_before_dispatch_returns_active_or_expired(self):
        g = self.active_grant()
        op = self.c.intend("merge", self.merge_params(g["id"]), lease_ok=True, event_id=self.ev())
        self.c.abandon(op["key"], expected_version=op["version"], event_id=self.ev())
        row = self.c._row("grants", "id", g["id"])
        self.assertEqual((row["state"], row["operation"]), ("active", ""))
        g2 = self.active_grant(pr=8)
        op = self.c.intend("merge", self.merge_params(g2["id"], pr=8), lease_ok=True, event_id=self.ev())
        self.clock.t += C.B47_GRANT_SECONDS + 1
        self.c.abandon(op["key"], expected_version=op["version"], event_id=self.ev())
        self.assertEqual(self.state("grants", "id", g2["id"]), "expired")

    def test_revocation_needs_an_allowed_actor_and_stops_retry(self):
        g = self.active_grant()
        with self.assertRaises(C.ContractError):
            self.c.revoke_grant(g["id"], expected_version=g["version"], event_id=self.ev(), actor="worker",
                                source="x")
        op = self.c.intend("merge", self.merge_params(g["id"]), lease_ok=True, event_id=self.ev())
        op = self.c.dispatch(op["key"], expected_version=op["version"], event_id=self.ev(), lease_ok=True)
        op = self.c.absent(op["key"], "typed-refusal", {"http": 405}, expected_version=op["version"],
                           event_id=self.ev())
        g = self.c._row("grants", "id", g["id"])
        self.c.revoke_grant(g["id"], expected_version=g["version"], event_id=self.ev(), actor="kill-switch",
                            source="kill switch on")
        op = self.c.retry(op["key"], self.merge_params(g["id"]), expected_version=op["version"], event_id=self.ev(),
                          lease_ok=True)
        self.assertEqual((op["state"], op["incident"]), ("held", 1), "revoked: absent-proven goes to held, not intent")


class OperationTests(Base):
    def dispatched(self):
        g = self.active_grant()
        op = self.c.intend("merge", self.merge_params(g["id"]), lease_ok=True, event_id=self.ev())
        return g, self.c.dispatch(op["key"], expected_version=op["version"], event_id=self.ev(), lease_ok=True)

    def test_key_is_derived_by_core_and_other_parameters_are_an_error(self):
        g = self.active_grant()
        k1 = self.c.operation_key("merge", self.merge_params(g["id"]))
        self.assertEqual(k1, self.c.operation_key("merge", self.merge_params(g["id"], repo="O/R")))
        self.assertEqual(k1, self.c.operation_key("merge", self.merge_params(g["id"], method="rebase")))
        with self.assertRaises(C.ContractError):
            self.c.operation_key("merge", {"repo": "o/r", "pr": 5})
        with self.assertRaises(C.ContractError):
            self.c.operation_key("deploy", self.merge_params(g["id"]))
        op = self.c.intend("merge", self.merge_params(g["id"]), lease_ok=True, event_id=self.ev())
        self.assertEqual(self.c.intend("merge", self.merge_params(g["id"]), lease_ok=True,
                                       event_id=self.ev())["key"], op["key"], "same params: same row")
        with self.assertRaises(C.OperationConflict):
            self.c.intend("merge", self.merge_params(g["id"], method="rebase"), lease_ok=True, event_id=self.ev())

    def test_intent_needs_a_lease_and_dispatch_needs_lease_heartbeat_and_reserved_grant(self):
        g = self.active_grant()
        with self.assertRaises(C.ContractError):
            self.c.intend("merge", self.merge_params(g["id"]), lease_ok=False, event_id=self.ev())
        op = self.c.intend("merge", self.merge_params(g["id"]), lease_ok=True, event_id=self.ev())
        for kw in ({"lease_ok": False}, {"lease_ok": True, "heartbeat_ok": False}):
            with self.subTest(kw), self.assertRaises(C.ContractError):
                self.c.dispatch(op["key"], expected_version=op["version"], event_id=self.ev(), **kw)
        g = self.c._row("grants", "id", g["id"])
        self.c.revoke_grant(g["id"], expected_version=g["version"], event_id=self.ev(), actor="main", source="m")
        with self.assertRaises(C.ContractError):
            self.c.dispatch(op["key"], expected_version=op["version"], event_id=self.ev(), lease_ok=True)
        self.assertEqual(self.c._row("operations", "key", op["key"])["dispatch_count"], 0)

    def test_dispatch_count_rises_before_the_request_and_caps_at_b10(self):
        g, op = self.dispatched()
        self.assertEqual(op["dispatch_count"], 1)
        params = self.merge_params(g["id"])
        for _ in range(C.B10_DISPATCHES - 1):
            op = self.c.absent(op["key"], "typed-refusal", {"code": "base-moved"}, expected_version=op["version"],
                               event_id=self.ev())
            op = self.c.retry(op["key"], params, expected_version=op["version"], event_id=self.ev(), lease_ok=True)
            op = self.c.dispatch(op["key"], expected_version=op["version"], event_id=self.ev(), lease_ok=True)
        self.assertEqual(op["dispatch_count"], C.B10_DISPATCHES)
        op = self.c.absent(op["key"], "typed-refusal", {"code": "x"}, expected_version=op["version"],
                           event_id=self.ev())
        op = self.c.retry(op["key"], params, expected_version=op["version"], event_id=self.ev(), lease_ok=True)
        self.assertEqual(op["state"], "held")

    def test_dispatch_itself_refuses_past_b10(self):
        # defence in depth: even an intent row that reached the cap by another path is never sent again
        g = self.active_grant()
        op = self.c.intend("merge", self.merge_params(g["id"]), lease_ok=True, event_id=self.ev())
        self.db.execute("UPDATE operations SET dispatch_count=? WHERE key=?", (C.B10_DISPATCHES, op["key"]))
        with self.assertRaisesRegex(C.ContractError, "B10"):
            self.c.dispatch(op["key"], expected_version=op["version"], event_id=self.ev(), lease_ok=True)

    def test_absence_needs_the_25_proof(self):
        g, op = self.dispatched()
        with self.assertRaises(C.ContractError):
            self.c.absent(op["key"], "not-found-now", {"x": 1}, expected_version=op["version"], event_id=self.ev())
        with self.assertRaises(C.ContractError):
            self.c.unknown(op["key"], expected_version=op["version"], event_id=self.ev())   # before B55
        self.clock.t += C.B55_REQUEST_SECONDS
        op = self.c.unknown(op["key"], expected_version=op["version"], event_id=self.ev())
        for proof, closed in (("typed-refusal", True), ("fence-closed-quiet", False), ("fence-closed-quiet", True)):
            with self.subTest(proof=proof, closed=closed), self.assertRaises(C.ContractError):
                self.c.absent(op["key"], proof, {"x": 1}, expected_version=op["version"], event_id=self.ev(),
                              request_closed=closed)
        self.clock.t += C.B54_LATE_SECONDS
        with self.assertRaises(C.ContractError):
            self.c.absent(op["key"], "fence-closed-quiet", {"x": 1}, expected_version=op["version"],
                          event_id=self.ev(), request_closed=False)
        op = self.c.absent(op["key"], "fence-closed-quiet", {"pr": "OPEN", "head": H1}, expected_version=op["version"],
                           event_id=self.ev(), request_closed=True)
        self.assertEqual(op["state"], "absent-proven")

    def test_unknown_goes_held_at_the_b37_count_and_only_an_operator_settles_it(self):
        g, op = self.dispatched()
        op = self.c.unknown(op["key"], expected_version=op["version"], event_id=self.ev(), restart=True)
        self.assertEqual(op["escalate_at"], self.clock.t + C.B42_INCIDENT_SECONDS)
        for _ in range(C.B37_PROBES):
            op = self.c.readback_missed(op["key"], expected_version=op["version"], event_id=self.ev())
        self.assertEqual((op["state"], op["incident"]), ("held", 1))
        self.assertEqual(self.state("grants", "id", g["id"]), "reserved", "held keeps the grant reserved")
        with self.assertRaises(C.ContractError):
            self.c.confirm(op["key"], {"merged": True}, expected_version=op["version"], event_id=self.ev())
        with self.assertRaises(C.ContractError):
            self.c.abandon(op["key"], expected_version=op["version"], event_id=self.ev(), actor="operator")
        self.c.abandon(op["key"], expected_version=op["version"], event_id=self.ev(), actor="operator",
                       evidence={"note": "PR closed by hand; outcome unknown"})
        self.assertEqual(self.state("grants", "id", g["id"]), "consumed", "uncertain use is spent")

    def test_retention_tombstones_settled_rows_only_and_refuses_the_key_after(self):
        g, op = self.dispatched()
        g2 = self.active_grant(pr=9)
        pending = self.c.intend("merge", self.merge_params(g2["id"], pr=9), lease_ok=True, event_id=self.ev())
        self.c.confirm(op["key"], {"merged": True}, expected_version=op["version"], event_id=self.ev())
        self.clock.t += C.B48_RETENTION_SECONDS + 1
        self.assertEqual(self.c.retain(), 1)
        self.assertEqual(self.c._row("operations", "key", pending["key"])["tombstone"], 0, "never before terminal")
        with self.assertRaises(C.ContractError):
            self.c.intend("merge", self.merge_params(g["id"]), lease_ok=True, event_id=self.ev())

    def test_every_transition_is_recorded(self):
        g, op = self.dispatched()
        rows = self.db.execute("SELECT entity, from_state, to_state FROM transitions ORDER BY seq").fetchall()
        self.assertIn(("operation", "intent", "dispatched"), rows)
        self.assertIn(("grant", "active", "reserved"), rows)
        self.assertEqual(len({r[0] for r in self.db.execute("SELECT event_id FROM transitions")}),
                         self.db.execute("SELECT COUNT(*) FROM transitions").fetchone()[0])

    def test_transition_tables_match_the_design_rows(self):
        self.assertEqual(set(C.Contracts.OP), {
            ("intent", "dispatched"), ("intent", "abandoned"), ("dispatched", "confirmed"),
            ("dispatched", "absent-proven"), ("dispatched", "outcome-unknown"), ("outcome-unknown", "confirmed"),
            ("outcome-unknown", "absent-proven"), ("outcome-unknown", "held"), ("outcome-unknown", "outcome-unknown"),
            ("absent-proven", "intent"), ("absent-proven", "held"), ("absent-proven", "abandoned"),
            ("held", "confirmed"), ("held", "absent-proven"), ("held", "abandoned")})
        self.assertNotIn(("reserved", "expired"), {k for k in C.Contracts.GRANT if C.Contracts.GRANT[k] == ()})
        for frm in C.Contracts.GRANT_TERMINAL:
            self.assertFalse([k for k in C.Contracts.GRANT if k[0] == frm], "terminal grant states have no exit")
        for frm in C.Contracts.REVIEW_TERMINAL:
            self.assertFalse([k for k in C.Contracts.REVIEW if k[0] == frm], "terminal review states have no exit")


if __name__ == "__main__":
    unittest.main()
