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

    # ---- Grant / Effect fixtures (spec ahc-m1-v2e G1-G9, E1-E12)

    KILL = 7

    def scope(self, **changes):
        s = {"repo": "o/r", "pr": 5, "head": H1, "base": BASE, "merge_sha": M}
        s.update(changes)
        return s

    def issued(self, **changes):
        return self.c.issue_grant("merge", "queue:fixture#6165f60532c0", "ahc-policy", self.scope(**changes), POLICY,
                                  event_id=self.ev(), kill_epoch=self.KILL)

    def active_grant(self, **changes):
        g = self.issued(**changes)
        return self.c.activate_grant(g["id"], expected_version=g["version"], event_id=self.ev())

    def params(self, **changes):
        p = {"repo": "o/r", "pr": 5, "head": H1, "base": BASE, "merge_sha": M, "policy_revision": POLICY,
             "method": "merge", "default_branch": "main"}
        p.update(changes)
        return p

    def reserve(self, g, op, **kw):
        kw.setdefault("mirror_read_back", True)
        kw.setdefault("kill_epoch", self.KILL)
        return self.c.reserve_grant(g["id"], op["key"], expected_version=g["version"], event_id=self.ev(), **kw)

    def reserved(self, **changes):
        g = self.active_grant(**{k: v for k, v in changes.items() if k in ("repo", "pr", "head", "base",
                                                                           "merge_sha")})
        op = self.c.intend(self.params(**changes), lease_ok=True, event_id=self.ev())
        g = self.reserve(g, op)
        return g, self.c._row("operations", "key", op["key"])

    def obs(self, row=None, **changes):
        base, head, m = (row["base"], row["head"], row["merge_sha"]) if row else (BASE, H1, M)
        o = {"at": self.clock.t, "kill_switch": False, "kill_epoch": self.KILL, "pr_state": "OPEN", "pr_head": head,
             "draft": False, "tip": base, "candidate": m, "parents": [base, head], "checks_green": True}
        o.update(changes)
        return o

    def send(self, op):
        return self.c.dispatch(op["key"], self.obs(op), expected_version=op["version"], event_id=self.ev(),
                               lease_ok=True, mirror_read_back=True)

    def dispatched(self, **changes):
        g, op = self.reserved(**changes)
        return g, self.send(op)

    def readback(self, **changes):
        r = {"at": self.clock.t, "tip": M, "m_reachable": True, "compare": "identical", "parents": [BASE, H1],
             "pr_merged": True}
        r.update(changes)
        return r

    def tip(self, sha=BASE):
        return {"at": self.clock.t, "tip": sha}

    def gstate(self, g):
        return self.state("grants", "id", g["id"])


M = "e" * 40
M2 = "f" * 40


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
    def test_g01_issue_is_validated_authority_first_one_per_candidate_with_epochs(self):
        g = self.issued()
        self.assertEqual((g["state"], g["merge_sha"], g["authority_epoch"], g["kill_epoch"], g["cap_held"]),
                         ("validated", M, 1, self.KILL, 1))
        rec = self.log.records()[-1]
        self.assertEqual((rec["grant"], rec["to"], rec["label"]), (g["id"], "validated", "local-not-off-host"))
        self.assertEqual(rec["scope"]["merge_sha"], M)
        with self.assertRaisesRegex(C.ContractError, "already covers"):
            self.issued()
        self.issued(merge_sha=M2)    # another candidate is another grant
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.execute("INSERT INTO grants(id, kind, source, principal, repo, pr, head, base, merge_sha, "
                            "policy_revision, uses, expires_at, state, authority_epoch, kill_epoch, cap_day, "
                            "cap_held, version, created, updated) VALUES ('x','merge','queue:x','ahc-policy','o/r',"
                            "5,?,?,?,'p',1,0,'active',1,1,0,1,1,0,0)", (H1, BASE, M))

    def test_g01_guards(self):
        for principal in ("agent-owner", "main", "ahc-core"):
            with self.subTest(principal), self.assertRaises(C.ContractError):
                self.c.issue_grant("merge", "queue:x", principal, self.scope(), POLICY, event_id=self.ev(),
                                   kill_epoch=1)
        with self.assertRaises(C.ContractError):
            self.c.issue_grant("merge", "inferred:x", "ahc-policy", self.scope(), POLICY, event_id=self.ev(),
                               kill_epoch=1)
        for bad in ({"repo": "o/r", "pr": 5, "head": H1, "base": BASE}, self.scope(head=""),
                    self.scope(merge_sha=None)):
            with self.subTest(bad), self.assertRaises(C.ContractError):
                self.c.issue_grant("merge", "queue:x", "ahc-policy", bad, POLICY, event_id=self.ev(), kill_epoch=1)
        for epoch in (None, "1", 1.0, True):
            with self.subTest(epoch=epoch), self.assertRaises(C.ContractError):
                self.c.issue_grant("merge", "queue:x", "ahc-policy", self.scope(), POLICY, event_id=self.ev(),
                                   kill_epoch=epoch)
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM grants").fetchone()[0], 0)

    def test_g01_cap1_is_reserved_at_issue_and_released_only_by_g5_g7(self):
        gs = [self.issued(pr=100 + i) for i in range(C.Contracts.CAP1_PER_DAY)]
        with self.assertRaisesRegex(C.ContractError, "CAP1"):
            self.issued(pr=200)
        self.c.revoke_grant(gs[0]["id"], expected_version=gs[0]["version"], event_id=self.ev(), by="main",
                            source="m")
        with self.assertRaisesRegex(C.ContractError, "CAP1"):
            self.issued(pr=200)       # a revocation keeps the slot: the count never goes down by G8/G9
        self.c.retire_grant(gs[1]["id"], expected_version=gs[1]["version"], event_id=self.ev(), reason="W5")
        self.assertEqual(self.issued(pr=200)["state"], "validated", "G5 released one slot")
        self.clock.t += C.B47_GRANT_SECONDS + 1    # next UTC day as well: a new day has its own slots
        self.assertEqual(self.c.cap_used("o/r"), 0)
        self.assertEqual(self.issued(pr=300)["cap_day"], self.c.utc_day())

    def test_g01_a_terminal_grant_frees_its_candidate(self):
        g = self.active_grant()
        self.c.revoke_grant(g["id"], expected_version=g["version"], event_id=self.ev(), by="main", source="m")
        self.assertEqual(self.issued()["state"], "validated")

    def test_g02_activate_and_an_authority_failure_changes_nothing(self):
        g = self.issued()
        Path(self.log.path).unlink()
        Path(self.log.path).mkdir()
        with self.assertRaises(C.AuthorityError):
            self.c.activate_grant(g["id"], expected_version=g["version"], event_id=self.ev())
        self.assertEqual(self.gstate(g), "validated")

    def test_g03_reserve_needs_the_mirror_the_epochs_and_exactly_this_scope(self):
        g = self.active_grant()
        op = self.c.intend(self.params(), lease_ok=True, event_id=self.ev())
        with self.assertRaisesRegex(C.ContractError, "mirror"):
            self.reserve(g, op, mirror_read_back=False)
        with self.assertRaisesRegex(C.ContractError, "kill epoch"):
            self.reserve(g, op, kill_epoch=self.KILL + 1)
        with self.assertRaises(C.OperationConflict):    # same M, other H: the same key with other parameters
            self.c.intend(self.params(head=H2), lease_ok=True, event_id=self.ev())
        for other in (self.params(merge_sha=M2), self.params(pr=6), self.params(policy_revision="policy-r2")):
            o = self.c.intend(other, lease_ok=True, event_id=self.ev())
            with self.subTest(other), self.assertRaises(C.ContractError):
                self.reserve(g, o)
        self.assertEqual(self.gstate(g), "active")
        g = self.reserve(g, op)
        self.assertEqual((g["state"], g["operation"]), ("reserved", op["key"]))
        with self.assertRaises(C.ContractError):
            self.reserve(g, op)

    def test_g03_an_earlier_authority_epoch_never_reserves(self):
        g = self.active_grant()
        op = self.c.intend(self.params(), lease_ok=True, event_id=self.ev())
        self.db.execute("UPDATE contract_meta SET v='2' WHERE k='authority_epoch'")   # a restore (T10)
        with self.assertRaisesRegex(C.ContractError, "authority epoch"):
            self.reserve(g, op)

    def test_g03_never_past_expiry(self):
        g = self.active_grant()
        op = self.c.intend(self.params(), lease_ok=True, event_id=self.ev())
        self.clock.t += C.B47_GRANT_SECONDS
        with self.assertRaisesRegex(C.ContractError, "expiry"):
            self.reserve(g, op)

    def test_g04_consumed_on_confirm_keeps_the_slot_and_is_never_reused(self):
        g, op = self.dispatched()
        self.c.confirm(op["key"], self.readback(), expected_version=op["version"], event_id=self.ev())
        g = self.c._row("grants", "id", g["id"])
        self.assertEqual((g["state"], g["cap_held"]), ("consumed", 1))
        with self.assertRaises(C.ContractError):
            self.reserve(g, op)

    def test_g05_abandoned_unsent_retires_and_a_new_generation_gets_a_new_grant(self):
        g, op = self.reserved()
        self.c.abandon_unsent(op["key"], expected_version=op["version"], event_id=self.ev(), reason="W5")
        g = self.c._row("grants", "id", g["id"])
        self.assertEqual((g["state"], g["cap_held"]), ("retired", 0))
        self.assertEqual(self.log.records()[-1]["to"], "retired")
        g2, op2 = self.reserved()     # same candidate M: a fresh grant (the old one is terminal) and g+1
        self.assertEqual((op2["generation"], g2["state"]), (1, "reserved"))
        self.assertNotEqual(op2["key"], op["key"])

    def test_g05_retires_after_a_definite_refusal_past_expiry_too(self):
        g, op = self.dispatched()
        self.clock.t += C.B47_GRANT_SECONDS + 1
        op = self.c.absent(op["key"], "p1", {"kind": "non-fast-forward"}, expected_version=op["version"],
                           event_id=self.ev())
        self.c.after_absence(op["key"], self.params(), self.tip(H2), expected_version=op["version"],
                             event_id=self.ev(), lease_ok=True)
        self.assertEqual(self.gstate(g), "retired")

    def test_g07_sweep_expires_unreserved_grants_only(self):
        idle = self.active_grant(pr=7)
        fresh = self.issued(pr=8)
        g, op = self.dispatched()
        self.clock.t += C.B47_GRANT_SECONDS + 1
        self.assertEqual(sorted(self.c.expire_grants("sweep")), sorted([idle["id"], fresh["id"]]))
        self.assertEqual(self.gstate(g), "reserved", "a reserved grant past expiry has no transition")
        self.assertEqual(self.c._row("grants", "id", idle["id"])["cap_held"], 0)
        self.c.confirm(op["key"], self.readback(), expected_version=op["version"], event_id=self.ev())
        self.assertEqual(self.gstate(g), "consumed")

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
        self.c.revoke_grant(g["id"], expected_version=self.c._row("grants", "id", g["id"])["version"],
                            event_id=self.ev(), by="kill-switch", source="kill switch read on")
        self.assertEqual(self.db.execute("SELECT actor FROM transitions WHERE to_state='revoked'").fetchone()[0],
                         "ahc-core")
        op = self.c.absent(op["key"], "p3", {"stage": "dns"}, expected_version=op["version"], event_id=self.ev())
        op = self.c.after_absence(op["key"], self.params(), self.tip(), expected_version=op["version"],
                                  event_id=self.ev(), lease_ok=True)
        self.assertEqual((op["state"], op["incident"]), ("held", 1), "E11: revoked, so never back to intent")


class OperationTests(Base):
    def test_e01_key_is_derived_from_m_policy_and_generation(self):
        k = C.Contracts.operation_key("o/r", 5, M, POLICY, 0)
        self.assertEqual(k, C.Contracts.operation_key("O/R", "5", M, POLICY, 0))
        others = {C.Contracts.operation_key("o/r", 5, M2, POLICY, 0),
                  C.Contracts.operation_key("o/r", 6, M, POLICY, 0),
                  C.Contracts.operation_key("o/r", 5, M, "policy-r2", 0),
                  C.Contracts.operation_key("o/r", 5, M, POLICY, 1)}
        self.assertNotIn(k, others)
        self.assertEqual(len(others), 4)
        for g in (-1, True, "0", None):
            with self.subTest(g), self.assertRaises(C.ContractError):
                C.Contracts.operation_key("o/r", 5, M, POLICY, g)

    def test_e01_intent_is_idempotent_merge_only_and_needs_a_lease(self):
        with self.assertRaises(C.ContractError):
            self.c.intend(self.params(), lease_ok=False, event_id=self.ev())
        for method in ("squash", "rebase"):
            with self.subTest(method), self.assertRaises(C.ContractError):
                self.c.intend(self.params(method=method), lease_ok=True, event_id=self.ev())
        with self.assertRaises(C.ContractError):
            self.c.intend(self.params(merge_sha=""), lease_ok=True, event_id=self.ev())
        op = self.c.intend(self.params(), lease_ok=True, event_id=self.ev())
        self.assertEqual(self.c.intend(self.params(), lease_ok=True, event_id=self.ev())["key"], op["key"])
        with self.assertRaises(C.OperationConflict):
            self.c.intend(self.params(default_branch="trunk"), lease_ok=True, event_id=self.ev())

    def test_e01_generation_rises_after_unsent_or_all_absent_and_never_after_an_unproven_send(self):
        g, op = self.dispatched()
        op = self.c.absent(op["key"], "p3", {"stage": "tcp"}, expected_version=op["version"], event_id=self.ev())
        op = self.c.after_absence(op["key"], self.params(), self.tip(), expected_version=op["version"],
                                  event_id=self.ev(), lease_ok=True)
        self.assertEqual(op["state"], "intent")
        op = self.c.abandon_unsent(op["key"], expected_version=op["version"], event_id=self.ev(), reason="W5")
        self.assertEqual(op["proof"], "all-sends-absent")
        self.assertEqual(self.c.intend(self.params(), lease_ok=True, event_id=self.ev())["generation"], 1,
                         "every send proven absent: the same M may integrate again (F2)")
        # an op whose send is not proven absent and was settled abandoned by main never yields a new generation
        g2, op2 = self.dispatched(pr=6)
        op2 = self.c.unknown(op2["key"], expected_version=op2["version"], event_id=self.ev(), restart=True)
        for _ in range(C.B37_PROBES):
            op2 = self.c.readback_missed(op2["key"], expected_version=op2["version"], event_id=self.ev())
        self.c.settle_held(op2["key"], {"note": "closed by hand"}, expected_version=op2["version"],
                           event_id=self.ev(), actor="main")
        with self.assertRaisesRegex(C.ContractError, "never yields a new generation"):
            self.c.intend(self.params(pr=6), lease_ok=True, event_id=self.ev())

    def test_e02_every_guard_is_checked_and_nothing_counts_on_refusal(self):
        g, op = self.reserved()
        bad = {"kill switch": self.obs(kill_switch=True), "kill switch unread": self.obs(kill_switch=None),
               "pr closed": self.obs(pr_state="CLOSED"), "head moved": self.obs(pr_head=H2),
               "draft": self.obs(draft=True), "base moved": self.obs(tip=H2), "candidate moved": self.obs(candidate=M2),
               "wrong parents": self.obs(parents=[H1, BASE]), "red check": self.obs(checks_green=False),
               "stale": self.obs(at=self.clock.t - C.Contracts.OBSERVATION_SECONDS),
               "future": self.obs(at=self.clock.t + 1), "no time": self.obs(at=None)}
        for name, o in bad.items():
            with self.subTest(name), self.assertRaises(C.ContractError):
                self.c.dispatch(op["key"], o, expected_version=op["version"], event_id=self.ev(), lease_ok=True,
                                mirror_read_back=True)
        for kw in ({"lease_ok": False, "mirror_read_back": True}, {"lease_ok": True, "mirror_read_back": False}):
            with self.subTest(kw), self.assertRaises(C.ContractError):
                self.c.dispatch(op["key"], self.obs(), expected_version=op["version"], event_id=self.ev(), **kw)
        with self.assertRaisesRegex(C.ContractError, "kill epoch"):
            self.c.dispatch(op["key"], self.obs(kill_epoch=self.KILL + 1), expected_version=op["version"],
                            event_id=self.ev(), lease_ok=True, mirror_read_back=True)
        row = self.c._row("operations", "key", op["key"])
        self.assertEqual((row["state"], row["dispatch_count"]), ("intent", 0))
        op = self.send(row)
        self.assertEqual((op["state"], op["dispatch_count"]), ("dispatched", 1))

    def test_e02_needs_the_grant_reserved_for_this_key(self):
        g = self.active_grant()
        op = self.c.intend(self.params(), lease_ok=True, event_id=self.ev())
        with self.assertRaisesRegex(C.ContractError, "reserved"):
            self.send(op)

    def test_e02_dispatch_caps_at_b10_through_p3_retries(self):
        g, op = self.dispatched()
        for _ in range(C.B10_DISPATCHES - 1):
            op = self.c.absent(op["key"], "p3", {"stage": "dns"}, expected_version=op["version"], event_id=self.ev())
            op = self.c.after_absence(op["key"], self.params(), self.tip(), expected_version=op["version"],
                                      event_id=self.ev(), lease_ok=True)
            self.assertEqual(op["state"], "intent")
            op = self.send(op)
        self.assertEqual(op["dispatch_count"], C.B10_DISPATCHES)
        op = self.c.absent(op["key"], "p3", {"stage": "dns"}, expected_version=op["version"], event_id=self.ev())
        op = self.c.after_absence(op["key"], self.params(), self.tip(), expected_version=op["version"],
                                  event_id=self.ev(), lease_ok=True)
        self.assertEqual((op["state"], op["incident"]), ("held", 1), "E11: the third dispatch was used")

    def test_e02_dispatch_itself_refuses_past_b10(self):
        g, op = self.reserved()
        self.db.execute("UPDATE operations SET dispatch_count=? WHERE key=?", (C.B10_DISPATCHES, op["key"]))
        with self.assertRaisesRegex(C.ContractError, "B10"):
            self.send(op)

    def test_e03_confirms_by_ancestry_even_after_another_advance(self):
        g, op = self.dispatched()
        for name, r in {"unreachable": self.readback(m_reachable=False, compare="behind"),
                        "diverged": self.readback(compare="diverged"), "parents": self.readback(parents=[H1, BASE]),
                        "stale": self.readback(at=self.clock.t - C.Contracts.OBSERVATION_SECONDS)}.items():
            with self.subTest(name), self.assertRaises(C.ContractError):
                self.c.confirm(op["key"], r, expected_version=op["version"], event_id=self.ev())
        later = "9" * 40      # another integration advanced the branch past M before the readback (F7)
        op = self.c.confirm(op["key"], self.readback(tip=later, compare="ahead"), expected_version=op["version"],
                            event_id=self.ev())
        self.assertEqual((op["state"], op["pr_unmarked"]), ("confirmed", 0))

    def test_e12_unmarked_pr_confirms_only_after_ten_minutes(self):
        g, op = self.dispatched()
        with self.assertRaisesRegex(C.ContractError, "10 min"):
            self.c.confirm(op["key"], self.readback(pr_merged=False), expected_version=op["version"],
                           event_id=self.ev())
        self.clock.t += C.Contracts.PR_MARK_SECONDS
        op = self.c.confirm(op["key"], self.readback(pr_merged=False), expected_version=op["version"],
                            event_id=self.ev())
        self.assertEqual((op["state"], op["pr_unmarked"]), ("confirmed", 1))

    def test_e04_proofs_p1_p2_p3_and_an_error_at_tip_b_is_not_absence(self):
        g, op = self.dispatched()
        later = self.clock.t
        bad = [("not-found-now", {"x": 1}), ("p1", {"kind": "Something went wrong"}), ("p1", {}),
               ("p2", {"error": "Something went wrong", "readback": {"at": later, "tip": BASE, "m_reachable": False}}),
               ("p2", {"error": "x", "readback": {"at": later, "tip": H2, "m_reachable": True}}),
               ("p2", {"readback": {"at": later, "tip": H2, "m_reachable": False}}),
               ("p2", {"error": "x", "readback": {"at": later - 1, "tip": H2, "m_reachable": False}}),
               ("p3", {"stage": "http"}), ("p3", {})]
        for proof, ev in bad:
            with self.subTest(proof=proof, ev=ev), self.assertRaises(C.ContractError):
                self.c.absent(op["key"], proof, ev, expected_version=op["version"], event_id=self.ev())
        self.assertEqual(self.c._row("operations", "key", op["key"])["state"], "dispatched")
        self.assertEqual(self.gstate(g), "reserved", "an untyped error at tip B keeps the grant reserved")
        self.clock.t += 5
        op = self.c.absent(op["key"], "p2", {"error": "Something went wrong",
                                             "readback": {"at": self.clock.t, "tip": H2, "m_reachable": False}},
                           expected_version=op["version"], event_id=self.ev())
        self.assertEqual((op["state"], op["proof"], op["proven_absent"]), ("absent-proven", "p2", 1))

    def test_e05_e06_unknown_then_held_keeps_the_grant_and_only_an_operator_settles(self):
        g, op = self.dispatched()
        with self.assertRaisesRegex(C.ContractError, "B55"):
            self.c.unknown(op["key"], expected_version=op["version"], event_id=self.ev())
        self.clock.t += C.B55_REQUEST_SECONDS
        op = self.c.unknown(op["key"], expected_version=op["version"], event_id=self.ev())
        n = self.db.execute("SELECT COUNT(*) FROM transitions").fetchone()[0]
        for _ in range(C.B37_PROBES - 1):
            op = self.c.readback_missed(op["key"], expected_version=op["version"], event_id=self.ev())
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM transitions").fetchone()[0], n)
        op = self.c.readback_missed(op["key"], expected_version=op["version"], event_id=self.ev())
        self.assertEqual((op["state"], op["incident"]), ("held", 1))
        self.clock.t += C.B47_GRANT_SECONDS
        self.c.expire_grants("sweep")
        self.assertEqual(self.gstate(g), "reserved")
        with self.assertRaises(C.ContractError):
            self.c.confirm(op["key"], self.readback(), expected_version=op["version"], event_id=self.ev())
        with self.assertRaises(C.ContractError):
            self.c.settle_held(op["key"], {"note": "x"}, expected_version=op["version"], event_id=self.ev(),
                               actor="ahc-core")
        op = self.c.settle_held(op["key"], {"note": "PR closed by hand; outcome unknown"},
                                expected_version=op["version"], event_id=self.ev(), actor="main")
        self.assertEqual((op["state"], op["proof"]), ("abandoned", "unknown-spent"))
        self.assertEqual(self.gstate(g), "consumed", "an uncertain use is spent (G4)")

    def held(self, **changes):
        g, op = self.dispatched(**changes)
        op = self.c.unknown(op["key"], expected_version=op["version"], event_id=self.ev(), restart=True)
        for _ in range(C.B37_PROBES):
            op = self.c.readback_missed(op["key"], expected_version=op["version"], event_id=self.ev())
        return g, op

    def test_e10_reconcile_confirms_when_m_is_reachable_and_abandons_only_past_b54_with_tip_off_b(self):
        g, op = self.held()
        op = self.c.confirm(op["key"], self.readback(), expected_version=op["version"], event_id=self.ev(),
                            actor="reconcile")
        self.assertEqual(op["state"], "confirmed")
        g2, op2 = self.held(pr=6)
        unreachable = {"at": self.clock.t, "tip": H2, "m_reachable": False}
        with self.assertRaisesRegex(C.ContractError, "B54"):
            self.c.settle_held(op2["key"], unreachable, expected_version=op2["version"], event_id=self.ev(),
                               actor="reconcile")
        self.clock.t += C.B54_LATE_SECONDS
        for ev in ({"at": self.clock.t, "tip": BASE, "m_reachable": False},
                   {"at": self.clock.t, "tip": H2, "m_reachable": True},
                   {"at": self.clock.t - C.Contracts.OBSERVATION_SECONDS, "tip": H2, "m_reachable": False}):
            with self.subTest(ev), self.assertRaises(C.ContractError):
                self.c.settle_held(op2["key"], ev, expected_version=op2["version"], event_id=self.ev(),
                                   actor="reconcile")
        op2 = self.c.settle_held(op2["key"], {"at": self.clock.t, "tip": H2, "m_reachable": False},
                                 expected_version=op2["version"], event_id=self.ev(), actor="reconcile")
        self.assertEqual(op2["state"], "abandoned")

    def test_e07_retry_is_p3_only_with_the_tip_still_b(self):
        for proof, ev, tip, want in (("p3", {"stage": "dns"}, BASE, "intent"),
                                     ("p3", {"stage": "dns"}, H2, "abandoned"),
                                     ("p1", {"kind": "non-fast-forward"}, BASE, "abandoned"),
                                     ("p1", {"kind": "ref-lock"}, H2, "abandoned")):
            with self.subTest(proof=proof, tip=tip):
                g, op = self.dispatched(pr=hash((proof, tip)) % 1000 + 10)
                op = self.c.absent(op["key"], proof, ev, expected_version=op["version"], event_id=self.ev())
                p = self.params(pr=op["pr"])
                op = self.c.after_absence(op["key"], p, self.tip(tip), expected_version=op["version"],
                                          event_id=self.ev(), lease_ok=True)
                self.assertEqual(op["state"], want)
                self.assertEqual(self.gstate(g), "reserved" if want == "intent" else "retired")

    def test_e07_p2_never_retries_even_if_the_tip_is_rewound_to_b(self):
        g, op = self.dispatched()
        self.clock.t += 1
        op = self.c.absent(op["key"], "p2", {"error": "Something went wrong",
                                             "readback": {"at": self.clock.t, "tip": H2, "m_reachable": False}},
                           expected_version=op["version"], event_id=self.ev())
        op = self.c.after_absence(op["key"], self.params(), self.tip(BASE), expected_version=op["version"],
                                  event_id=self.ev(), lease_ok=True)
        self.assertEqual(op["state"], "abandoned", "only p3 (nothing sent) may retry")
        self.assertEqual(op["dispatch_count"], 1)

    def test_f4_applied_then_connection_reset_is_settled_by_readback_not_retried(self):
        """The server applied the CAS and the connection then reset: no proof exists, so no absent-proven, no
        second dispatch; the readback confirms by ancestry."""
        g, op = self.dispatched()
        for proof, ev in (("p3", {"stage": "reset-after-send"}), ("p1", {"kind": "connection reset"})):
            with self.subTest(proof), self.assertRaises(C.ContractError):
                self.c.absent(op["key"], proof, ev, expected_version=op["version"], event_id=self.ev())
        self.clock.t += C.B55_REQUEST_SECONDS
        op = self.c.unknown(op["key"], expected_version=op["version"], event_id=self.ev())
        op = self.c.confirm(op["key"], self.readback(tip="9" * 40, compare="ahead"), expected_version=op["version"],
                            event_id=self.ev())
        self.assertEqual((op["state"], op["dispatch_count"]), ("confirmed", 1))

    def test_e07_retry_carries_the_same_parameters_and_a_lease(self):
        g, op = self.dispatched()
        op = self.c.absent(op["key"], "p3", {"stage": "tls"}, expected_version=op["version"], event_id=self.ev())
        with self.assertRaises(C.OperationConflict):
            self.c.after_absence(op["key"], self.params(default_branch="trunk"), self.tip(),
                                 expected_version=op["version"], event_id=self.ev(), lease_ok=True)
        with self.assertRaises(C.ContractError):
            self.c.after_absence(op["key"], self.params(), self.tip(), expected_version=op["version"],
                                 event_id=self.ev(), lease_ok=False)

    def test_e08_p2_abandons_and_releases(self):
        g, op = self.dispatched()
        self.clock.t += 1
        op = self.c.absent(op["key"], "p2", {"error": "Something went wrong",
                                             "readback": {"at": self.clock.t, "tip": H2, "m_reachable": False}},
                           expected_version=op["version"], event_id=self.ev())
        op = self.c.after_absence(op["key"], self.params(), self.tip(H2), expected_version=op["version"],
                                  event_id=self.ev(), lease_ok=True)
        self.assertEqual((op["state"], op["proof"]), ("abandoned", "all-sends-absent"))
        self.assertEqual(self.gstate(g), "retired")

    def test_e09_only_an_intent_with_every_send_absent_is_abandoned_unsent(self):
        g, op = self.dispatched()
        with self.assertRaises(C.ContractError):
            self.c.abandon_unsent(op["key"], expected_version=op["version"], event_id=self.ev(), reason="W4")
        g2, op2 = self.reserved(pr=6)
        op2 = self.c.abandon_unsent(op2["key"], expected_version=op2["version"], event_id=self.ev(), reason="W4")
        self.assertEqual((op2["state"], op2["proof"]), ("abandoned", "never-sent"))

    def test_late_apply_watch_raises_an_incident_and_turns_merging_off(self):
        g, op = self.reserved()
        op = self.c.abandon_unsent(op["key"], expected_version=op["version"], event_id=self.ev(), reason="cancel")
        self.assertEqual([w["key"] for w in self.c.watched("o/r")], [op["key"]])
        with self.assertRaises(C.ContractError):
            self.c.late_apply(op["key"], {"at": self.clock.t, "m_reachable": False}, event_id=self.ev())
        self.assertFalse(self.c.merging_off("o/r"))
        flag = self.c.late_apply(op["key"], {"at": self.clock.t, "tip": M, "m_reachable": True}, event_id=self.ev())
        self.assertEqual((flag["merging_off"], flag["cause"]), (1, "late-apply:%s" % op["key"]))
        self.assertTrue(self.c.merging_off("O/R"))
        self.assertEqual(self.c._row("operations", "key", op["key"])["incident"], 1)
        with self.assertRaises(C.ContractError):
            self.c.set_merging("o/r", off=False, cause="x", actor="ahc-core")
        self.c.set_merging("o/r", off=False, cause="main reconciled", actor="main")
        self.assertFalse(self.c.merging_off("o/r"))
        self.clock.t += C.Contracts.LATE_WATCH_SECONDS + 1
        self.assertEqual(self.c.watched("o/r"), [], "the watch lasts 30 days")

    def test_retention_tombstones_settled_rows_only_and_refuses_the_key_after(self):
        g, op = self.dispatched()
        g2, pending = self.reserved(pr=9)
        self.c.confirm(op["key"], self.readback(), expected_version=op["version"], event_id=self.ev())
        self.clock.t += C.B48_RETENTION_SECONDS + 1
        self.assertEqual(self.c.retain(), 1)
        self.assertEqual(self.c._row("operations", "key", pending["key"])["tombstone"], 0)
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
            ("validated", "active"), ("active", "reserved"), ("reserved", "consumed"),
            ("validated", "retired"), ("active", "retired"), ("reserved", "retired"),
            ("validated", "expired"), ("active", "expired"),
            ("validated", "revoked"), ("active", "revoked"), ("reserved", "revoked")})
        for frm in C.Contracts.GRANT_TERMINAL:
            self.assertFalse([k for k in C.Contracts.GRANT if k[0] == frm], "terminal grant states have no exit")
        for frm in C.Contracts.OP_TERMINAL:
            self.assertFalse([k for k in C.Contracts.OP if k[0] == frm], "terminal operation states have no exit")
        for frm in C.Contracts.REVIEW_TERMINAL:
            self.assertFalse([k for k in C.Contracts.REVIEW if k[0] == frm], "terminal review states have no exit")


class LegacyTests(Base):
    def test_unsettled_legacy_rows_are_reported(self):
        self.db.execute("CREATE TABLE grants_v3_legacy (id TEXT, state TEXT, repo TEXT)")
        self.db.execute("CREATE TABLE operations_v3_legacy (key TEXT, state TEXT)")
        self.db.executemany("INSERT INTO grants_v3_legacy VALUES (?,?,?)",
                            [("g1", "reserved", "o/r"), ("g2", "consumed", "o/r")])
        self.db.executemany("INSERT INTO operations_v3_legacy VALUES (?,?)", [("k1", "held"), ("k2", "confirmed")])
        self.assertEqual(self.c.legacy_unsettled(), [
            {"table": "grants_v3_legacy", "id": "g1", "state": "reserved", "repo": "o/r"},
            {"table": "operations_v3_legacy", "id": "k1", "state": "held", "repo": None}])


if __name__ == "__main__":
    unittest.main()
