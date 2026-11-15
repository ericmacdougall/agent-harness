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

    # ---- Grant / Effect fixtures (spec ahc-m1-v2c G1-G9, E1-E12)

    def scope(self, **changes):
        s = {"repo": "o/r", "pr": 5, "head": H1, "base": BASE}
        s.update(changes)
        return s

    def issued(self, **changes):
        return self.c.issue_grant("merge", "queue:fixture#6165f60532c0", "ahc-policy", self.scope(**changes), POLICY,
                                  event_id=self.ev())

    def active_grant(self, **changes):
        g = self.issued(**changes)
        return self.c.activate_grant(g["id"], expected_version=g["version"], event_id=self.ev())

    def params(self, **changes):
        p = {"repo": "o/r", "pr": 5, "head": H1, "base": BASE, "policy_revision": POLICY, "method": "merge",
             "default_branch": "main"}
        p.update(changes)
        return p

    def reserved(self, **changes):
        g = self.active_grant(**{k: v for k, v in changes.items() if k in ("repo", "pr", "head", "base")})
        op = self.c.intend(self.params(**changes), lease_ok=True, event_id=self.ev())
        g = self.c.reserve_grant(g["id"], op["key"], expected_version=g["version"], event_id=self.ev(),
                                 mirror_read_back=True)
        return g, self.c._row("operations", "key", op["key"])

    def obs(self, **changes):
        o = {"at": self.clock.t, "kill_switch": False, "pr_state": "OPEN", "pr_head": H1, "branch": BASE,
             "checks_green": True, "built_sha": M, "built_parents": [BASE, H1], "conflict": False}
        o.update(changes)
        return o

    def send(self, op):
        return self.c.dispatch(op["key"], self.obs(), expected_version=op["version"], event_id=self.ev(),
                               lease_ok=True, mirror_read_back=True)

    def dispatched(self, **changes):
        g, op = self.reserved(**changes)
        return g, self.send(op)

    def readback(self, **changes):
        r = {"at": self.clock.t, "branch": M, "parents": [BASE, H1], "pr_merged": True}
        r.update(changes)
        return r

    def gstate(self, g):
        return self.state("grants", "id", g["id"])


M = "e" * 40


class ReviewTests(Base):
    UID = 63595

    def row(self, **kw):
        args = dict(kind="adversarial", repo="O/R", pr=5, head=H1, packet_sha256=PKT, policy_revision=POLICY)
        args.update(kw)
        return self.c.require_review(**args)

    def walk(self, row, *states, **kw):
        for to in states:
            if to == "running":
                row = self.c.start_attempt(row["id"], "ahc-review-%s" % row["id"], self.UID,
                                           expected_version=row["version"], event_id=self.ev())
            else:
                row = self.c.review(row["id"], to, expected_version=row["version"], event_id=self.ev(), **kw)
        return row

    def result(self, row, to="passed", **kw):
        args = dict(expected_version=row["version"], event_id=self.ev(), receipt=self.receipt(), peer_uid=self.UID)
        args.update(kw)
        return self.c.review(row["id"], to, **args)

    def test_bound_row_is_idempotent_and_reaches_passed_on_a_matching_receipt(self):
        row = self.row()
        self.assertEqual(self.row()["id"], row["id"], "same binding, same row")
        self.assertNotEqual(self.row(policy_revision="policy-r2")["id"], row["id"], "policy revision is bound")
        row = self.walk(row, "queued", "running")
        self.assertEqual((row["producer_unit"], row["producer_uid"]), ("ahc-review-" + row["id"], self.UID))
        self.assertEqual(self.result(row)["state"], "passed")

    def test_result_from_another_producer_is_unverified_and_authorizes_nothing(self):
        # spec H2 / NEG-12: only the uid of the unit core started for this row can settle it
        row = self.walk(self.row(), "queued", "running")
        for peer in (None, 1000, self.UID + 1, str(self.UID)):
            with self.subTest(peer=peer), self.assertRaisesRegex(C.ContractError, "unverified-producer"):
                self.result(row, peer_uid=peer)
        with self.assertRaises(C.ContractError):
            self.c.start_attempt(row["id"], "", self.UID, expected_version=row["version"], event_id=self.ev())
        self.assertEqual(self.state("reviews", "id", row["id"]), "running")

    def test_receipt_for_another_subject_or_verdict_is_refused(self):
        row = self.walk(self.row(), "queued", "running")
        for changes in ({"head": H2}, {"packet_sha256": "e" * 64}, {"policy_revision": "policy-r2"}, {"pr": 6},
                        {"repo": "o/other"}, {"verdict": "BLOCK"}):
            with self.subTest(changes), self.assertRaises(C.ContractError):
                self.result(row, receipt=self.receipt(**changes))
        self.assertEqual(self.state("reviews", "id", row["id"]), "running", "nothing was written")
        with self.assertRaises(C.ContractError):
            self.result(row, "findings")

    def test_spec_row_passes_from_required_on_its_attach_record_only(self):
        spec = self.row(kind="spec", packet_sha256="5" * 64)
        self.c.review(spec["id"], "passed", expected_version=spec["version"], event_id=self.ev(),
                      receipt=self.receipt(packet_sha256="5" * 64))
        adversarial = self.row()
        with self.assertRaises(C.ContractError):   # an attempt kind never passes without running
            self.result(adversarial)

    def test_unlisted_transitions_actors_versions_and_event_reuse_are_refused(self):
        row = self.row()
        with self.assertRaises(C.ContractError):
            self.c.review(row["id"], "findings", expected_version=row["version"], event_id=self.ev(),
                          receipt=self.receipt(verdict="BLOCK"))   # required -> findings does not exist
        with self.assertRaises(C.ContractError):
            self.c.review(row["id"], "waived", expected_version=row["version"], event_id=self.ev())
        with self.assertRaises(C.ContractError):
            self.c.review(row["id"], "queued", expected_version=row["version"], event_id=self.ev(),
                          actor="worker")
        with self.assertRaises(C.VersionConflict):
            self.c.review(row["id"], "queued", expected_version=row["version"] + 1, event_id=self.ev())
        with self.assertRaises(C.VersionConflict):
            self.c.review(row["id"], "queued", expected_version=None, event_id=self.ev())
        with self.assertRaises(C.ContractError):
            self.c.require_review("code", "o/r", 5, H1, PKT, POLICY)
        row = self.c.review(row["id"], "queued", expected_version=row["version"], event_id="ev-fixed")
        with self.assertRaises(C.ContractError):
            self.c.start_attempt(row["id"], "u", self.UID, expected_version=row["version"], event_id="ev-fixed")

    def test_outcome_unknown_requeues_only_when_the_unit_is_gone(self):
        row = self.walk(self.row(), "queued", "running", "outcome-unknown")
        with self.assertRaises(C.ContractError):
            self.c.review(row["id"], "queued", expected_version=row["version"], event_id=self.ev())
        row = self.c.review(row["id"], "queued", expected_version=row["version"], event_id=self.ev(), unit_gone=True)
        self.assertEqual(row["state"], "queued")

    def test_new_head_supersedes_rows_and_cancels_running_first(self):
        queued = self.walk(self.row(kind="adversarial"), "queued")
        running = self.walk(self.row(kind="red-team"), "queued", "running")
        unknown = self.walk(self.row(kind="adversarial", packet_sha256="9" * 64), "queued", "running",
                            "outcome-unknown")
        spec = self.row(kind="spec")
        passed = self.result(self.walk(self.row(kind="red-team", packet_sha256="8" * 64), "queued", "running"),
                             receipt=self.receipt(packet_sha256="8" * 64))
        moved = dict(self.c.supersede_reviews("o/r", 5, H2, lambda rid: "rv-new", "sup"))
        self.assertEqual(moved, {queued["id"]: "superseded", running["id"]: "cancelling",
                                 unknown["id"]: "superseded", spec["id"]: "superseded"})
        self.assertEqual(self.state("reviews", "id", passed["id"]), "passed", "history never changes")
        r = self.db.execute("SELECT version FROM reviews WHERE id=?", (running["id"],)).fetchone()[0]
        self.c.review(running["id"], "superseded", expected_version=r, event_id=self.ev())
        r = self.c._row("reviews", "id", unknown["id"])
        with self.assertRaises(C.ContractError):   # a late receipt for a superseded row authorizes nothing
            self.c.review(unknown["id"], "passed", expected_version=r["version"], event_id=self.ev(),
                          receipt=self.receipt(packet_sha256="9" * 64), peer_uid=self.UID)

class GrantTests(Base):
    def test_g01_issue_is_validated_authority_first_and_one_per_scope(self):
        g = self.issued()
        self.assertEqual(g["state"], "validated")
        rec = self.log.records()[-1]
        self.assertEqual((rec["grant"], rec["to"], rec["label"]), (g["id"], "validated", "local-not-off-host"))
        self.assertEqual(g["authority_seq"], rec["seq"])
        with self.assertRaisesRegex(C.ContractError, "already covers"):
            self.issued()
        self.issued(head=H2)    # another scope is another grant
        # the unique index enforces it even for a writer that skips the check
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.execute("INSERT INTO grants(id, kind, source, principal, repo, pr, head, base, policy_revision, "
                            "uses, expires_at, state, version, created, updated) VALUES "
                            "('x','merge','queue:x','ahc-policy','o/r',5,?,?,'p',1,0,'active',1,0,0)", (H1, BASE))

    def test_g01_guards(self):
        for principal in ("agent-owner", "main", "ahc-core"):
            with self.subTest(principal), self.assertRaises(C.ContractError):
                self.c.issue_grant("merge", "queue:x", principal, self.scope(), POLICY, event_id=self.ev())
        with self.assertRaises(C.ContractError):
            self.c.issue_grant("merge", "inferred:x", "ahc-policy", self.scope(), POLICY, event_id=self.ev())
        for bad in ({"repo": "o/r", "pr": 5, "head": H1}, self.scope(head=""), self.scope(base=None)):
            with self.subTest(bad), self.assertRaises(C.ContractError):
                self.c.issue_grant("merge", "queue:x", "ahc-policy", bad, POLICY, event_id=self.ev())
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM grants").fetchone()[0], 0)

    def test_g01_a_terminal_grant_frees_its_scope(self):
        g = self.active_grant()
        self.c.revoke_grant(g["id"], expected_version=g["version"], event_id=self.ev(), by="main", source="m")
        self.assertEqual(self.issued()["state"], "validated")

    def test_g02_activate_and_an_authority_failure_changes_nothing(self):
        g = self.issued()
        Path(self.log.path).unlink()
        Path(self.log.path).mkdir()   # the authority path is now a directory: reading and appending fail
        with self.assertRaises(C.AuthorityError):
            self.c.activate_grant(g["id"], expected_version=g["version"], event_id=self.ev())
        self.assertEqual(self.gstate(g), "validated")
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM transitions WHERE to_state='active'").fetchone()[0], 0)

    def test_g03_reserve_needs_the_mirror_read_back_and_exactly_this_scope(self):
        g = self.active_grant()
        op = self.c.intend(self.params(), lease_ok=True, event_id=self.ev())
        with self.assertRaisesRegex(C.ContractError, "mirror"):
            self.c.reserve_grant(g["id"], op["key"], expected_version=g["version"], event_id=self.ev(),
                                 mirror_read_back=False)
        other = self.c.intend(self.params(head=H2), lease_ok=True, event_id=self.ev())
        with self.assertRaisesRegex(C.ContractError, "scope"):
            self.c.reserve_grant(g["id"], other["key"], expected_version=g["version"], event_id=self.ev(),
                                 mirror_read_back=True)
        rev = self.c.intend(self.params(policy_revision="policy-r2"), lease_ok=True, event_id=self.ev())
        with self.assertRaisesRegex(C.ContractError, "policy revision"):
            self.c.reserve_grant(g["id"], rev["key"], expected_version=g["version"], event_id=self.ev(),
                                 mirror_read_back=True)
        self.assertEqual(self.gstate(g), "active")
        g = self.c.reserve_grant(g["id"], op["key"], expected_version=g["version"], event_id=self.ev(),
                                 mirror_read_back=True)
        self.assertEqual((g["state"], g["operation"], g["bound_key"]), ("reserved", op["key"], op["key"]))
        self.assertEqual(self.log.records()[-1]["to"], "reserved")
        with self.assertRaises(C.ContractError):     # a second reservation of a reserved grant
            self.c.reserve_grant(g["id"], op["key"], expected_version=g["version"], event_id=self.ev(),
                                 mirror_read_back=True)

    def test_g03_never_past_expiry(self):
        g = self.active_grant()
        op = self.c.intend(self.params(), lease_ok=True, event_id=self.ev())
        self.clock.t += C.B47_GRANT_SECONDS
        with self.assertRaisesRegex(C.ContractError, "expiry"):
            self.c.reserve_grant(g["id"], op["key"], expected_version=g["version"], event_id=self.ev(),
                                 mirror_read_back=True)

    def test_g04_consumed_on_confirm_and_never_reused(self):
        g, op = self.dispatched()
        self.c.confirm(op["key"], self.readback(), expected_version=op["version"], event_id=self.ev())
        g = self.c._row("grants", "id", g["id"])
        self.assertEqual(g["state"], "consumed")
        self.assertEqual(self.log.records()[-1]["to"], "consumed")
        with self.assertRaises(C.ContractError):
            self.c.reserve_grant(g["id"], op["key"], expected_version=g["version"], event_id=self.ev(),
                                 mirror_read_back=True)

    def test_g05_released_before_dispatch_is_active_and_bound_to_its_key(self):
        g, op = self.reserved()
        self.c.abandon_unsent(op["key"], expected_version=op["version"], event_id=self.ev(), reason="W5")
        g = self.c._row("grants", "id", g["id"])
        self.assertEqual((g["state"], g["operation"], g["bound_key"]), ("active", "", op["key"]))
        # E9 raises the generation, so the next operation has another key and may not take this grant (G5).
        # OPEN QUESTION for the spec owner (v2c W5 + G5 + E9): until expiry this scope has no usable grant.
        nxt = self.c.intend(self.params(), lease_ok=True, event_id=self.ev())
        self.assertEqual(nxt["generation"], 1)
        with self.assertRaisesRegex(C.ContractError, "same operation key"):
            self.c.reserve_grant(g["id"], nxt["key"], expected_version=g["version"], event_id=self.ev(),
                                 mirror_read_back=True)

    def test_g05_released_after_a_definite_refusal(self):
        g, op = self.dispatched()
        op = self.c.refused(op["key"], "non-fast-forward", {"stderr": "rejected (non-fast-forward)"},
                            expected_version=op["version"], event_id=self.ev(), request_closed=True)
        op = self.c.after_refusal(op["key"], self.params(), expected_version=op["version"], event_id=self.ev(),
                                  lease_ok=True)
        self.assertEqual((op["state"], op["proof"]), ("abandoned", "definite-refusal"))
        self.assertEqual(self.gstate(g), "active", "a definite refusal spends nothing")

    def test_g06_released_past_expiry_expires(self):
        g, op = self.reserved()
        self.clock.t += C.B47_GRANT_SECONDS + 1
        self.c.abandon_unsent(op["key"], expected_version=op["version"], event_id=self.ev(), reason="W4")
        self.assertEqual(self.gstate(g), "expired")

    def test_g07_sweep_expires_unreserved_grants_only(self):
        idle = self.active_grant(pr=7)
        fresh = self.issued(pr=8)
        g, op = self.dispatched()
        self.clock.t += C.B47_GRANT_SECONDS + 1
        self.assertEqual(sorted(self.c.expire_grants("sweep")), sorted([idle["id"], fresh["id"]]))
        self.assertEqual(self.gstate(g), "reserved", "a reserved grant past expiry has no transition")
        op = self.c.confirm(op["key"], self.readback(), expected_version=op["version"], event_id=self.ev())
        self.assertEqual(self.gstate(g), "consumed", "settling still consumes it")

    def test_g08_main_revokes_and_nobody_else(self):
        g = self.active_grant()
        for by in ("worker", "ahc-core", "ahc-policy", ""):
            with self.subTest(by), self.assertRaises(C.ContractError):
                self.c.revoke_grant(g["id"], expected_version=g["version"], event_id=self.ev(), by=by, source="x")
        with self.assertRaises(C.ContractError):
            self.c.revoke_grant(g["id"], expected_version=g["version"], event_id=self.ev(), by="main", source="")
        g = self.c.revoke_grant(g["id"], expected_version=g["version"], event_id=self.ev(), by="main", source="m")
        self.assertEqual(g["state"], "revoked")
        self.assertEqual(self.db.execute("SELECT actor FROM transitions WHERE to_state='revoked'").fetchone()[0],
                         "main")

    def test_g09_kill_switch_revokes_in_flight_and_absent_proven_goes_held(self):
        g, op = self.dispatched()
        g = self.c.revoke_grant(g["id"], expected_version=g["version"], event_id=self.ev(), by="kill-switch",
                                source="kill switch read on")
        self.assertEqual(self.db.execute("SELECT actor FROM transitions WHERE to_state='revoked'").fetchone()[0],
                         "ahc-core")
        op = self.c.refused(op["key"], "transient", {"stderr": "connection reset"}, expected_version=op["version"],
                            event_id=self.ev(), request_closed=True)
        op = self.c.after_refusal(op["key"], self.params(), expected_version=op["version"], event_id=self.ev(),
                                  lease_ok=True)
        self.assertEqual((op["state"], op["incident"]), ("held", 1), "E11: revoked, so never back to intent")
        self.assertEqual(self.gstate(g), "revoked")


class OperationTests(Base):
    def test_e01_key_is_derived_from_the_tuple_and_generation(self):
        k = C.Contracts.operation_key("o/r", 5, H1, BASE, POLICY, 0)
        self.assertEqual(k, C.Contracts.operation_key("O/R", "5", H1, BASE, POLICY, 0))
        others = {C.Contracts.operation_key("o/r", 5, H2, BASE, POLICY, 0),
                  C.Contracts.operation_key("o/r", 5, H1, H2, POLICY, 0),
                  C.Contracts.operation_key("o/r", 5, H1, BASE, "policy-r2", 0),
                  C.Contracts.operation_key("o/r", 5, H1, BASE, POLICY, 1)}
        self.assertNotIn(k, others)
        self.assertEqual(len(others), 4)
        for g in (-1, True, "0", None):
            with self.subTest(g), self.assertRaises(C.ContractError):
                C.Contracts.operation_key("o/r", 5, H1, BASE, POLICY, g)
        with self.assertRaises(C.ContractError):
            C.Contracts.operation_key("o/r", 5, H1, "", POLICY, 0)

    def test_e01_intent_is_idempotent_merge_only_and_needs_a_lease(self):
        with self.assertRaises(C.ContractError):
            self.c.intend(self.params(), lease_ok=False, event_id=self.ev())
        for method in ("squash", "rebase"):
            with self.subTest(method), self.assertRaises(C.ContractError):
                self.c.intend(self.params(method=method), lease_ok=True, event_id=self.ev())
        op = self.c.intend(self.params(), lease_ok=True, event_id=self.ev())
        self.assertEqual(op["key"], C.Contracts.operation_key("o/r", 5, H1, BASE, POLICY, 0))
        self.assertEqual(self.c.intend(self.params(), lease_ok=True, event_id=self.ev())["key"], op["key"])
        with self.assertRaises(C.OperationConflict):
            self.c.intend(self.params(default_branch="trunk"), lease_ok=True, event_id=self.ev())
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM operations").fetchone()[0], 1)

    def test_e01_generation_rises_only_after_an_unsent_abandon(self):
        g, op = self.reserved()
        self.c.abandon_unsent(op["key"], expected_version=op["version"], event_id=self.ev(), reason="W5")
        nxt = self.c.intend(self.params(), lease_ok=True, event_id=self.ev())
        self.assertEqual((nxt["generation"], nxt["key"] != op["key"]), (1, True))
        # a sent operation at (H, B) that was abandoned never yields a fresh key
        g2, sent = self.dispatched(pr=6)
        sent = self.c.refused(sent["key"], "stale", {"stderr": "stale info"}, expected_version=sent["version"],
                              event_id=self.ev(), request_closed=True)
        self.c.after_refusal(sent["key"], self.params(pr=6), expected_version=sent["version"], event_id=self.ev(),
                             lease_ok=True)
        with self.assertRaisesRegex(C.ContractError, "never gets a fresh key"):
            self.c.intend(self.params(pr=6), lease_ok=True, event_id=self.ev())

    def test_e02_every_guard_is_checked_and_nothing_counts_on_refusal(self):
        g, op = self.reserved()
        bad = {"kill switch": self.obs(kill_switch=True), "kill switch unread": self.obs(kill_switch=None),
               "pr closed": self.obs(pr_state="CLOSED"), "head moved": self.obs(pr_head=H2),
               "base moved": self.obs(branch=H2), "red check": self.obs(checks_green=False),
               "no M": self.obs(built_sha=""), "wrong parents": self.obs(built_parents=[H1, BASE]),
               "conflict": self.obs(conflict=True), "conflict unread": self.obs(conflict=None),
               "stale": self.obs(at=self.clock.t - C.Contracts.OBSERVATION_SECONDS),
               "future": self.obs(at=self.clock.t + 1), "no time": self.obs(at=None)}
        for name, o in bad.items():
            with self.subTest(name), self.assertRaises(C.ContractError):
                self.c.dispatch(op["key"], o, expected_version=op["version"], event_id=self.ev(), lease_ok=True,
                                mirror_read_back=True)
        for kw in ({"lease_ok": False, "mirror_read_back": True}, {"lease_ok": True, "mirror_read_back": False}):
            with self.subTest(kw), self.assertRaises(C.ContractError):
                self.c.dispatch(op["key"], self.obs(), expected_version=op["version"], event_id=self.ev(), **kw)
        row = self.c._row("operations", "key", op["key"])
        self.assertEqual((row["state"], row["dispatch_count"]), ("intent", 0))
        op = self.send(row)
        self.assertEqual((op["state"], op["dispatch_count"], op["built_sha"]), ("dispatched", 1, M))
        self.assertEqual(op["probe_at"], self.clock.t + C.B55_REQUEST_SECONDS)

    def test_e02_needs_the_grant_reserved_for_this_key(self):
        g = self.active_grant()
        op = self.c.intend(self.params(), lease_ok=True, event_id=self.ev())
        with self.assertRaisesRegex(C.ContractError, "reserved"):
            self.send(op)
        g2, op2 = self.reserved(pr=6)
        g2 = self.c.revoke_grant(g2["id"], expected_version=g2["version"], event_id=self.ev(), by="main",
                                 source="m")
        with self.assertRaisesRegex(C.ContractError, "reserved"):
            self.send(op2)

    def test_e02_dispatch_caps_at_b10_through_transient_retries(self):
        g, op = self.dispatched()
        for _ in range(C.B10_DISPATCHES - 1):
            op = self.c.refused(op["key"], "transient", {"stderr": "reset"}, expected_version=op["version"],
                                event_id=self.ev(), request_closed=True)
            op = self.c.after_refusal(op["key"], self.params(), expected_version=op["version"], event_id=self.ev(),
                                      lease_ok=True)
            self.assertEqual(op["state"], "intent")
            op = self.send(op)
        self.assertEqual(op["dispatch_count"], C.B10_DISPATCHES)
        op = self.c.refused(op["key"], "transient", {"stderr": "reset"}, expected_version=op["version"],
                            event_id=self.ev(), request_closed=True)
        op = self.c.after_refusal(op["key"], self.params(), expected_version=op["version"], event_id=self.ev(),
                                  lease_ok=True)
        self.assertEqual((op["state"], op["incident"]), ("held", 1), "E11: the third dispatch was used")

    def test_e02_dispatch_itself_refuses_past_b10(self):
        g, op = self.reserved()
        self.db.execute("UPDATE operations SET dispatch_count=? WHERE key=?", (C.B10_DISPATCHES, op["key"]))
        with self.assertRaisesRegex(C.ContractError, "B10"):
            self.send(op)

    def test_e03_confirms_only_m_with_parents_b_h(self):
        g, op = self.dispatched()
        for name, r in {"branch not M": self.readback(branch=BASE), "parents": self.readback(parents=[H1, BASE]),
                        "one parent": self.readback(parents=[H1]),
                        "stale": self.readback(at=self.clock.t - C.Contracts.OBSERVATION_SECONDS)}.items():
            with self.subTest(name), self.assertRaises(C.ContractError):
                self.c.confirm(op["key"], r, expected_version=op["version"], event_id=self.ev())
        op = self.c.confirm(op["key"], self.readback(), expected_version=op["version"], event_id=self.ev())
        self.assertEqual((op["state"], op["pr_unmarked"]), ("confirmed", 0))
        self.assertIsNotNone(op["settled_at"])

    def test_e12_unmarked_pr_confirms_only_after_ten_minutes(self):
        g, op = self.dispatched()
        with self.assertRaisesRegex(C.ContractError, "10 min"):
            self.c.confirm(op["key"], self.readback(pr_merged=False), expected_version=op["version"],
                           event_id=self.ev())
        self.clock.t += C.Contracts.PR_MARK_SECONDS
        op = self.c.confirm(op["key"], self.readback(pr_merged=False), expected_version=op["version"],
                            event_id=self.ev())
        self.assertEqual((op["state"], op["pr_unmarked"]), ("confirmed", 1))
        self.assertEqual(self.gstate(g), "consumed")

    def test_e04_absence_needs_a_typed_refusal_and_a_closed_request(self):
        g, op = self.dispatched()
        for refusal, ev, closed in (("not-found-now", {"x": 1}, True), ("transient", {}, True),
                                    ("transient", {"x": 1}, False), ("non-fast-forward", None, True)):
            with self.subTest(refusal=refusal, closed=closed), self.assertRaises(C.ContractError):
                self.c.refused(op["key"], refusal, ev, expected_version=op["version"], event_id=self.ev(),
                               request_closed=closed)
        op = self.c.refused(op["key"], "non-fast-forward", {"stderr": "rejected"}, expected_version=op["version"],
                            event_id=self.ev(), request_closed=True)
        self.assertEqual((op["state"], op["refusal"]), ("absent-proven", "non-fast-forward"))

    def test_e05_e06_unknown_then_held_keeps_the_grant_and_only_an_operator_settles(self):
        g, op = self.dispatched()
        with self.assertRaisesRegex(C.ContractError, "B55"):
            self.c.unknown(op["key"], expected_version=op["version"], event_id=self.ev())
        self.clock.t += C.B55_REQUEST_SECONDS
        op = self.c.unknown(op["key"], expected_version=op["version"], event_id=self.ev())
        self.assertEqual(op["escalate_at"], self.clock.t + C.B42_INCIDENT_SECONDS)
        n = self.db.execute("SELECT COUNT(*) FROM transitions").fetchone()[0]
        for _ in range(C.B37_PROBES - 1):
            op = self.c.readback_missed(op["key"], expected_version=op["version"], event_id=self.ev())
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM transitions").fetchone()[0], n,
                         "a missed readback is a counter, not a transition")
        op = self.c.readback_missed(op["key"], expected_version=op["version"], event_id=self.ev())
        self.assertEqual((op["state"], op["incident"], op["readbacks"]), ("held", 1, C.B37_PROBES))
        self.clock.t += C.B47_GRANT_SECONDS
        self.c.expire_grants("sweep")
        self.assertEqual(self.gstate(g), "reserved", "held keeps the grant reserved past expiry")
        with self.assertRaises(C.ContractError):
            self.c.confirm(op["key"], self.readback(), expected_version=op["version"], event_id=self.ev())
        with self.assertRaises(C.ContractError):
            self.c.settle_held(op["key"], "abandoned", {"note": "x"}, expected_version=op["version"],
                               event_id=self.ev(), actor="ahc-core")
        with self.assertRaises(C.ContractError):
            self.c.settle_held(op["key"], "abandoned", {}, expected_version=op["version"], event_id=self.ev(),
                               actor="reconcile")
        op = self.c.settle_held(op["key"], "abandoned", {"note": "PR closed by hand; outcome unknown"},
                                expected_version=op["version"], event_id=self.ev(), actor="reconcile")
        self.assertEqual((op["state"], op["proof"]), ("abandoned", "unknown-spent"))
        self.assertEqual(self.gstate(g), "consumed", "an uncertain use is spent (G4)")

    def test_e10_held_confirmed_by_main_with_evidence(self):
        g, op = self.dispatched()
        op = self.c.unknown(op["key"], expected_version=op["version"], event_id=self.ev(), restart=True)
        for _ in range(C.B37_PROBES):
            op = self.c.readback_missed(op["key"], expected_version=op["version"], event_id=self.ev())
        op = self.c.confirm(op["key"], {"merge_commit": M, "checked_by": "main"}, expected_version=op["version"],
                            event_id=self.ev(), actor="main")
        self.assertEqual(op["state"], "confirmed")
        self.assertEqual(self.gstate(g), "consumed")

    def test_e07_retry_carries_the_same_parameters_and_a_lease(self):
        g, op = self.dispatched()
        op = self.c.refused(op["key"], "transient", {"stderr": "reset"}, expected_version=op["version"],
                            event_id=self.ev(), request_closed=True)
        with self.assertRaises(C.OperationConflict):
            self.c.after_refusal(op["key"], self.params(default_branch="trunk"), expected_version=op["version"],
                                 event_id=self.ev(), lease_ok=True)
        with self.assertRaises(C.ContractError):
            self.c.after_refusal(op["key"], self.params(), expected_version=op["version"], event_id=self.ev(),
                                 lease_ok=False)
        op = self.c.after_refusal(op["key"], self.params(), expected_version=op["version"], event_id=self.ev(),
                                  lease_ok=True)
        self.assertEqual((op["state"], op["dispatch_count"]), ("intent", 1))
        self.assertEqual(self.gstate(g), "reserved")

    def test_e09_only_an_intent_is_abandoned_and_a_dispatched_one_is_not(self):
        g, op = self.dispatched()
        with self.assertRaises(C.ContractError):
            self.c.abandon_unsent(op["key"], expected_version=op["version"], event_id=self.ev(), reason="W4")
        g2, op2 = self.reserved(pr=6)
        op2 = self.c.abandon_unsent(op2["key"], expected_version=op2["version"], event_id=self.ev(), reason="W4")
        self.assertEqual((op2["state"], op2["proof"]), ("abandoned", "never-sent"))

    def test_e09_after_e7_releases_the_grant_but_never_mints_a_fresh_key(self):
        g, op = self.dispatched()
        op = self.c.refused(op["key"], "transient", {"stderr": "reset"}, expected_version=op["version"],
                            event_id=self.ev(), request_closed=True)
        op = self.c.after_refusal(op["key"], self.params(), expected_version=op["version"], event_id=self.ev(),
                                  lease_ok=True)
        op = self.c.abandon_unsent(op["key"], expected_version=op["version"], event_id=self.ev(), reason="W5")
        self.assertEqual((op["state"], op["proof"]), ("abandoned", "refused-then-left"))
        self.assertEqual(self.gstate(g), "active", "every dispatch was proven absent: the grant is released")
        with self.assertRaisesRegex(C.ContractError, "never gets a fresh key"):
            self.c.intend(self.params(), lease_ok=True, event_id=self.ev())

    def test_retention_tombstones_settled_rows_only_and_refuses_the_key_after(self):
        g, op = self.dispatched()
        g2, pending = self.reserved(pr=9)
        self.c.confirm(op["key"], self.readback(), expected_version=op["version"], event_id=self.ev())
        self.clock.t += C.B48_RETENTION_SECONDS + 1
        self.assertEqual(self.c.retain(), 1)
        self.assertEqual(self.c._row("operations", "key", pending["key"])["tombstone"], 0, "never before terminal")
        row = self.c._row("operations", "key", op["key"])
        self.assertEqual((row["state"], row["params"]), ("confirmed", None))
        with self.assertRaisesRegex(C.ContractError, "tombstoned"):
            self.c.intend(self.params(), lease_ok=True, event_id=self.ev())

    def test_every_transition_is_recorded_once(self):
        self.dispatched()
        rows = self.db.execute("SELECT entity, from_state, to_state FROM transitions ORDER BY seq").fetchall()
        for want in (("grant", None, "validated"), ("grant", "validated", "active"), ("grant", "active", "reserved"),
                     ("operation", None, "intent"), ("operation", "intent", "dispatched")):
            self.assertIn(want, rows)
        self.assertEqual(len({r[0] for r in self.db.execute("SELECT event_id FROM transitions")}),
                         self.db.execute("SELECT COUNT(*) FROM transitions").fetchone()[0])

    def test_transition_tables_match_the_spec_rows(self):
        self.assertEqual(set(C.Contracts.OP), {
            ("intent", "dispatched"), ("dispatched", "confirmed"), ("outcome-unknown", "confirmed"),
            ("dispatched", "absent-proven"), ("outcome-unknown", "absent-proven"), ("dispatched", "outcome-unknown"),
            ("outcome-unknown", "held"), ("absent-proven", "intent"), ("absent-proven", "abandoned"),
            ("intent", "abandoned"), ("held", "confirmed"), ("held", "abandoned"), ("absent-proven", "held")})
        self.assertEqual(set(C.Contracts.GRANT), {
            ("validated", "active"), ("active", "reserved"), ("reserved", "consumed"), ("reserved", "active"),
            ("reserved", "expired"), ("validated", "expired"), ("active", "expired"),
            ("validated", "revoked"), ("active", "revoked"), ("reserved", "revoked")})
        self.assertNotIn("proposed", {s for k in C.Contracts.GRANT for s in k})
        for frm in C.Contracts.GRANT_TERMINAL:
            self.assertFalse([k for k in C.Contracts.GRANT if k[0] == frm], "terminal grant states have no exit")
        for frm in C.Contracts.OP_TERMINAL:
            self.assertFalse([k for k in C.Contracts.OP if k[0] == frm], "terminal operation states have no exit")
        for frm in C.Contracts.REVIEW_TERMINAL:
            self.assertFalse([k for k in C.Contracts.REVIEW if k[0] == frm], "terminal review states have no exit")


if __name__ == "__main__":
    unittest.main()
