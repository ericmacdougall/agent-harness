"""ahc_contracts: Review, Grant and Operation (Effect) transitions per spec ahc-m1-v2g2 (goodqa#16049 M-1): the
fast-forward of the default branch from B to the reviewed H, keyed (repo, pr, B, H, revision, g)."""
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
B2 = "9" * 40         # a moved default-branch tip
OTHER = "8" * 40      # some other tip, neither B nor H
PKT = "d" * 64
POLICY = "policy-r1"
CORE1, CORE2 = "1" * 64, "2" * 64     # two attached spec cores (Q-A6)
BOOT = "test-boot"                    # the boot id the Contracts under test run in (D-a3)


def stamped(o):
    """An observation stamped the way Contracts.stamp does: the monotonic stamp follows the test clock's `at`
    (one fake clock drives both), and the boot is the test boot unless a test sets another."""
    o.setdefault("mono", o.get("at"))
    o.setdefault("boot", BOOT)
    return o


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
        self.c = C.Contracts(self.db, self.log, now=self.clock, mono=self.clock, boot_id=BOOT)
        self.n = 0

    def ev(self):
        self.n += 1
        return "ev-%d" % self.n

    def state(self, table, column, ident):
        return self.db.execute("SELECT state FROM %s WHERE %s=?" % (table, column), (ident,)).fetchone()[0]

    def receipt(self, **changes):
        r = {"repo": "o/r", "pr": 5, "head": H1, "snapshot_base": BASE, "packet_sha256": PKT,
             "policy_revision": POLICY, "verdict": "PASS"}
        r.update(changes)
        return r

    # ---- Grant / Effect fixtures (spec ahc-m1-v2g2 G1-G9, E1-E16)

    KILL = 7

    def scope(self, **changes):
        s = {"repo": "o/r", "pr": 5, "head": H1, "base": BASE}
        s.update(changes)
        return s

    def issued(self, **changes):
        return self.c.issue_grant("merge", "queue:fixture#6165f60532c0", "ahc-policy", self.scope(**changes), POLICY,
                                  event_id=self.ev(), kill_epoch=self.KILL)

    def active_grant(self, **changes):
        g = self.issued(**changes)
        return self.c.activate_grant(g["id"], expected_version=g["version"], event_id=self.ev())

    def params(self, **changes):
        p = {"repo": "o/r", "pr": 5, "head": H1, "base": BASE, "policy_revision": POLICY, "method": "fast-forward",
             "default_branch": "main"}
        p.update(changes)
        return p

    def reserve(self, g, op, **kw):
        kw.setdefault("mirror_read_back", True)
        kw.setdefault("kill_epoch", self.KILL)
        return self.c.reserve_grant(g["id"], op["key"], expected_version=g["version"], event_id=self.ev(), **kw)

    def reserved(self, **changes):
        g = self.active_grant(**{k: v for k, v in changes.items() if k in C.Contracts.SCOPE})
        op = self.c.intend(self.params(**changes), lease_ok=True, event_id=self.ev())
        g = self.reserve(g, op)
        return g, self.c._row("operations", "key", op["key"])

    def obs(self, row=None, **changes):
        base, head = (row["base"], row["head"]) if row else (BASE, H1)
        o = {"at": self.clock.t, "kill_switch": False, "kill_epoch": self.KILL, "pr_state": "OPEN", "pr_head": head,
             "draft": False, "tip": base, "compare": "ahead", "checks_green": True}
        o.update(changes)
        return stamped(o)

    def send(self, op):
        return self.c.dispatch(op["key"], self.obs(op), expected_version=op["version"], event_id=self.ev(),
                               lease_ok=True, mirror_read_back=True)

    def dispatched(self, **changes):
        g, op = self.reserved(**changes)
        return g, self.send(op)

    @staticmethod
    def entry(before=BASE, after=H1, kind="push"):
        return {"before": before, "after": after, "type": kind}

    def read(self, tip=OTHER, entries=(), complete=True, **changes):
        r = {"at": self.clock.t, "tip": tip, "activity": {"complete": complete, "entries": list(entries)}}
        r.update(changes)
        return stamped(r)

    def readback(self, **changes):
        """E3 by the tip: the default branch is exactly H."""
        r = {"at": self.clock.t, "tip": H1, "pr_merged": True}
        r.update(changes)
        return stamped(r)

    def gstate(self, g):
        return self.state("grants", "id", g["id"])

    def grow(self, g):
        return self.c._row("grants", "id", g["id"])

    def fenced(self, **changes):
        g, op = self.dispatched(**changes)
        self.clock.t += C.E13_FIRST_READ_SECONDS
        first = self.read()
        self.clock.t += C.E13_READ_GAP_SECONDS
        op = self.c.fence(op["key"], "Something went wrong", [first, self.read()], expected_version=op["version"],
                          event_id=self.ev())
        return g, op

    def held(self, **changes):
        g, op = self.dispatched(**changes)
        op = self.c.unknown(op["key"], expected_version=op["version"], event_id=self.ev(), restart=True)
        for _ in range(C.B37_PROBES):
            op = self.c.readback_missed(op["key"], expected_version=op["version"], event_id=self.ev())
        return g, op

    def absent_p(self, proof="p1", **changes):
        g, op = self.dispatched(**changes)
        ev = {"kind": "non-fast-forward"} if proof == "p1" else {"stage": "dns"}
        return g, self.c.absent(op["key"], proof, ev, expected_version=op["version"], event_id=self.ev())

    def after(self, op, read, params=None, lease_ok=True):
        return self.c.after_absence(op["key"], params or self.params(pr=op["pr"]), read,
                                    expected_version=op["version"], event_id=self.ev(), lease_ok=lease_ok)


class ReviewTests(Base):
    UID = 63595

    def row(self, **kw):
        args = dict(kind="adversarial", repo="O/R", pr=5, head=H1, packet_sha256=PKT, policy_revision=POLICY)
        args.update(kw)
        args.setdefault("snapshot_base", "" if args["kind"] == "spec" else BASE)
        args.setdefault("spec_core", CORE1 if args["kind"] == "spec" else "")
        args.setdefault("item", "wi-review-tests")
        return self.c.require_review(**args)

    # ---- Q-A6 (spec owner ruling on slice 1a): a spec row is bound to the spec core it reviewed

    def spec_pass(self, row, core):
        return self.c.review(row["id"], "passed", expected_version=row["version"], event_id=self.ev(),
                             receipt=self.receipt(packet_sha256=row["packet_sha256"], snapshot_base=None,
                                                  spec_core=core))

    def test_qa6_a_new_spec_core_at_the_same_subject_is_a_new_row(self):
        old = self.row(kind="spec")
        new = self.row(kind="spec", spec_core=CORE2)
        self.assertNotEqual(new["id"], old["id"], "same head, packet and policy, new core: a replacement row")
        self.assertEqual((old["spec_core"], new["spec_core"]), (CORE1, CORE2))
        self.assertEqual(self.spec_pass(old, CORE1)["state"], "passed")
        self.assertEqual(self.state("reviews", "id", new["id"]), "required", "the old pass does not carry over")

    def test_qa6_a_spec_row_needs_a_full_core_and_a_code_row_has_none(self):
        for bad in ("", None, "A" * 64, "a" * 40, CORE1 + "0"):
            with self.subTest(bad=bad), self.assertRaisesRegex(C.ContractError, "spec core"):
                self.row(kind="spec", spec_core=bad)
        with self.assertRaisesRegex(C.ContractError, "spec core"):
            self.row(kind="adversarial", spec_core=CORE1)
        with self.assertRaises(sqlite3.IntegrityError):     # the CHECK holds even for a direct write
            self.db.execute("INSERT INTO reviews(id, kind, repo, pr, head, snapshot_base, packet_sha256, "
                            "policy_revision, state, version, created, updated, spec_core) VALUES "
                            "('rv-x', 'spec', 'o/r', 5, ?, '', ?, ?, 'required', 1, 0, 0, '')", (H1, PKT, POLICY))
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.execute("INSERT INTO reviews(id, kind, repo, pr, head, snapshot_base, packet_sha256, "
                            "policy_revision, state, version, created, updated, spec_core) VALUES "
                            "('rv-y', 'adversarial', 'o/r', 5, ?, ?, ?, ?, 'required', 1, 0, 0, ?)",
                            (H1, BASE, PKT, POLICY, CORE1))

    def test_qa6_r11_passes_a_spec_row_only_on_an_attach_record_for_its_core(self):
        row = self.row(kind="spec")
        for core in (CORE2, None, ""):
            with self.subTest(core=core), self.assertRaisesRegex(C.ContractError, "spec_core"):
                self.spec_pass(row, core)
        self.assertEqual(self.state("reviews", "id", row["id"]), "required")
        self.assertEqual(self.spec_pass(row, CORE1)["state"], "passed")

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
                      receipt=self.receipt(packet_sha256="5" * 64, spec_core=CORE1))
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
        # v2g16 R14: an outcome-unknown row's unit may still be running, so it is cancelled first, like a running
        # row; it never jumps straight to superseded (the pre-R14 shortcut, flipped in slice 1a).
        self.assertEqual(moved, {queued["id"]: "superseded", running["id"]: "cancelling",
                                 unknown["id"]: "cancelling", spec["id"]: "superseded"})
        self.assertEqual(self.state("reviews", "id", passed["id"]), "passed", "history never changes")
        for rid in (running["id"], unknown["id"]):
            r = self.c._row("reviews", "id", rid)
            with self.assertRaises(C.ContractError):   # R15: a result arriving while cancelling authorizes nothing
                self.c.review(rid, "passed", expected_version=r["version"], event_id=self.ev(),
                              receipt=self.receipt(packet_sha256=r["packet_sha256"]), peer_uid=self.UID)
            self.c.review(rid, "superseded", expected_version=r["version"], event_id=self.ev())
        r = self.c._row("reviews", "id", unknown["id"])
        with self.assertRaises(C.ContractError):   # a late receipt for a superseded row authorizes nothing
            self.c.review(unknown["id"], "passed", expected_version=r["version"], event_id=self.ev(),
                          receipt=self.receipt(packet_sha256="9" * 64), peer_uid=self.UID)
        other = self.walk(self.row(kind="adversarial", packet_sha256="7" * 64), "queued", "running",
                          "outcome-unknown")
        with self.assertRaisesRegex(C.ContractError, "no transition outcome-unknown -> superseded"):
            self.c.review(other["id"], "superseded", expected_version=other["version"], event_id=self.ev(),
                          successor="rv-new")

    def test_r01_code_rows_bind_the_snapshot_base_and_spec_rows_store_empty(self):
        row = self.row()
        self.assertEqual(row["snapshot_base"], BASE)
        self.assertNotEqual(self.row(snapshot_base=B2)["id"], row["id"], "B_r is part of the binding")
        for bad in ("", None, "C" * 40, "c" * 12, H1):
            with self.subTest(bad=bad), self.assertRaises(C.ContractError):
                self.row(snapshot_base=bad)
        spec = self.row(kind="spec")
        self.assertEqual(spec["snapshot_base"], "")
        self.assertEqual(self.row(kind="spec")["id"], spec["id"], "'' de-duplicates where NULL would not")
        with self.assertRaises(C.ContractError):
            self.row(kind="spec", snapshot_base=BASE)

    def test_r04_a_receipt_for_another_snapshot_base_is_refused(self):
        row = self.walk(self.row(), "queued", "running")
        for bad in (B2, None):
            with self.subTest(bad=bad), self.assertRaisesRegex(C.ContractError, "snapshot_base"):
                self.result(row, receipt=self.receipt(snapshot_base=bad))
        self.assertEqual(self.result(row)["state"], "passed")


class GrantTests(Base):
    def test_g01_issue_is_validated_authority_first_one_per_b_h_with_epochs(self):
        g = self.issued()
        self.assertEqual((g["state"], g["head"], g["base"], g["authority_epoch"], g["kill_epoch"], g["cap_held"]),
                         ("validated", H1, BASE, 1, self.KILL, 1))
        rec = self.log.records()[-1]
        self.assertEqual((rec["grant"], rec["to"], rec["label"]), (g["id"], "validated", "local-not-off-host"))
        self.assertEqual(rec["scope"], {"repo": "o/r", "pr": 5, "head": H1, "base": BASE})
        with self.assertRaisesRegex(C.ContractError, "already covers"):
            self.issued()
        self.issued(base=B2)    # a moved base is another (B, H): another grant
        with self.assertRaises(sqlite3.IntegrityError):
            self.db.execute("INSERT INTO grants(id, kind, source, principal, repo, pr, head, base, "
                            "policy_revision, uses, expires_at, state, authority_epoch, kill_epoch, cap_day, "
                            "cap_held, version, created, updated) VALUES ('x','merge','queue:x','ahc-policy','o/r',"
                            "5,?,?,'p',1,0,'active',1,1,0,1,1,0,0)", (H1, BASE))

    def test_g01_guards(self):
        for principal in ("agent-owner", "main", "ahc-core"):
            with self.subTest(principal), self.assertRaises(C.ContractError):
                self.c.issue_grant("merge", "queue:x", principal, self.scope(), POLICY, event_id=self.ev(),
                                   kill_epoch=1)
        with self.assertRaises(C.ContractError):
            self.c.issue_grant("merge", "inferred:x", "ahc-policy", self.scope(), POLICY, event_id=self.ev(),
                               kill_epoch=1)
        for bad in ({"repo": "o/r", "pr": 5, "head": H1}, self.scope(head=""), self.scope(base=H1),
                    self.scope(head="A" * 40), dict(self.scope(), merge_sha="e" * 40)):
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

    def test_g01_a_terminal_grant_frees_its_b_h(self):
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
        for other in (self.params(base=B2), self.params(head=H2), self.params(pr=6),
                      self.params(policy_revision="policy-r2")):
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
        g = self.grow(g)
        self.assertEqual((g["state"], g["cap_held"]), ("consumed", 1))
        with self.assertRaises(C.ContractError):
            self.reserve(g, op)

    def test_g05_abandoned_unsent_retires_and_a_new_generation_gets_a_new_grant(self):
        g, op = self.reserved()
        self.c.abandon_unsent(op["key"], expected_version=op["version"], event_id=self.ev(), reason="W5")
        g = self.grow(g)
        self.assertEqual((g["state"], g["cap_held"]), ("retired", 0))
        self.assertEqual(self.log.records()[-1]["to"], "retired")
        g2, op2 = self.reserved()     # same (B, H): a fresh grant (the old one is terminal) and g+1
        self.assertEqual((op2["generation"], g2["state"]), (1, "reserved"))
        self.assertNotEqual(op2["key"], op["key"])

    def test_g05_retires_after_a_definite_refusal_past_expiry_too(self):
        g, op = self.absent_p("p1")
        self.clock.t += C.B47_GRANT_SECONDS + 1
        self.after(op, self.read(tip=B2))
        self.assertEqual(self.gstate(g), "retired")

    def test_g05_retires_only_on_the_allow_list(self):
        """Fail closed: every abandonment proof outside never-sent / all-sends-absent consumes the grant."""
        self.assertEqual(C.Contracts.RETIRE_PROOFS, ("never-sent", "all-sends-absent"))
        for n, proof in enumerate(("unknown-spent", "never-applies", "p2", None, "anything-new")):
            with self.subTest(proof=proof):
                g, op = self.reserved(pr=50 + n)
                self.db.execute("UPDATE operations SET state='abandoned', proof=? WHERE key=?", (proof, op["key"]))
                self.c._settle_grant_for(self.c._row("operations", "key", op["key"]), self.ev())
                self.assertEqual((self.gstate(g), self.grow(g)["cap_held"]), ("consumed", 1))

    def test_g07_sweep_expires_unreserved_grants_only(self):
        idle = self.active_grant(pr=7)
        fresh = self.issued(pr=8)
        g, op = self.dispatched()
        self.clock.t += C.B47_GRANT_SECONDS + 1
        self.assertEqual(sorted(self.c.expire_grants("sweep")), sorted([idle["id"], fresh["id"]]))
        self.assertEqual(self.gstate(g), "reserved", "a reserved grant past expiry has no transition")
        self.assertEqual(self.grow(idle)["cap_held"], 0)
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
        self.c.revoke_grant(g["id"], expected_version=self.grow(g)["version"], event_id=self.ev(),
                            by="kill-switch", source="kill switch read on")
        self.assertEqual(self.db.execute("SELECT actor FROM transitions WHERE to_state='revoked'").fetchone()[0],
                         "ahc-core")
        op = self.c.absent(op["key"], "p3", {"stage": "dns"}, expected_version=op["version"], event_id=self.ev())
        op = self.after(op, self.read(tip=BASE))
        self.assertEqual((op["state"], op["incident"]), ("held", 1), "E11: revoked, so never back to intent")


class OperationTests(Base):
    def test_e01_key_is_derived_from_b_h_policy_and_generation(self):
        k = C.Contracts.operation_key("o/r", 5, BASE, H1, POLICY, 0)
        self.assertEqual(k, C.Contracts.operation_key("O/R", "5", BASE, H1, POLICY, 0))
        others = {C.Contracts.operation_key("o/r", 5, B2, H1, POLICY, 0),
                  C.Contracts.operation_key("o/r", 5, BASE, H2, POLICY, 0),
                  C.Contracts.operation_key("o/r", 6, BASE, H1, POLICY, 0),
                  C.Contracts.operation_key("o/r", 5, BASE, H1, "policy-r2", 0),
                  C.Contracts.operation_key("o/r", 5, BASE, H1, POLICY, 1)}
        self.assertNotIn(k, others)
        self.assertEqual(len(others), 5)
        for g in (-1, True, "0", None):
            with self.subTest(g), self.assertRaises(C.ContractError):
                C.Contracts.operation_key("o/r", 5, BASE, H1, POLICY, g)
        for b, h in ((H1, H1), ("C" * 40, H1), (BASE, "a" * 12), ("", H1)):
            with self.subTest(b=b, h=h), self.assertRaises(C.ContractError):
                C.Contracts.operation_key("o/r", 5, b, h, POLICY, 0)

    def test_e01_intent_is_idempotent_fast_forward_only_and_needs_a_lease(self):
        with self.assertRaises(C.ContractError):
            self.c.intend(self.params(), lease_ok=False, event_id=self.ev())
        for method in ("merge", "squash", "rebase", "force"):
            with self.subTest(method), self.assertRaises(C.ContractError):
                self.c.intend(self.params(method=method), lease_ok=True, event_id=self.ev())
        with self.assertRaises(C.ContractError):     # no candidate M exists in v2g: an extra key is refused
            self.c.intend(dict(self.params(), merge_sha="e" * 40), lease_ok=True, event_id=self.ev())
        with self.assertRaises(C.ContractError):
            self.c.intend(self.params(base=""), lease_ok=True, event_id=self.ev())
        op = self.c.intend(self.params(), lease_ok=True, event_id=self.ev())
        self.assertEqual(op["kind"], "fast-forward")
        self.assertEqual(self.c.intend(self.params(), lease_ok=True, event_id=self.ev())["key"], op["key"])
        with self.assertRaises(C.OperationConflict):
            self.c.intend(self.params(default_branch="trunk"), lease_ok=True, event_id=self.ev())

    def test_e01_generation_rises_after_unsent_or_all_absent_and_never_after_an_unproven_send(self):
        g, op = self.absent_p("p3")
        op = self.after(op, self.read(tip=BASE))
        self.assertEqual(op["state"], "intent")
        op = self.c.abandon_unsent(op["key"], expected_version=op["version"], event_id=self.ev(), reason="W5")
        self.assertEqual(op["proof"], "all-sends-absent")
        self.assertEqual(self.c.intend(self.params(), lease_ok=True, event_id=self.ev())["generation"], 1,
                         "every send proven absent: the same (B, H) may integrate again (F2)")
        g2, op2 = self.held(pr=6)
        self.c.settle_held(op2["key"], {"note": "closed by hand"}, expected_version=op2["version"],
                           event_id=self.ev(), actor="main")
        with self.assertRaisesRegex(C.ContractError, "never yields a new generation"):
            self.c.intend(self.params(pr=6), lease_ok=True, event_id=self.ev())

    def test_t2_age_is_monotonic_and_ignores_wall_clock_steps(self):
        """D-a3: a wall-clock step (NTP, a manual set) changes neither verdict. A 3 h old observation is stale
        however the wall clock was set back, and a fresh one stays fresh after the wall clock jumps."""
        g, op = self.reserved()
        mono = [self.clock.t]
        c = C.Contracts(self.db, self.log, now=self.clock, mono=lambda: mono[0], boot_id=BOOT)
        old = self.obs(mono=mono[0] - 3 * 3600)                   # the wall stamp `at` still reads "now"
        with self.assertRaisesRegex(C.ContractError, "stale"):
            c.dispatch(op["key"], old, expected_version=op["version"], event_id=self.ev(), lease_ok=True,
                       mirror_read_back=True)
        fresh = self.obs(at=self.clock.t + 3600, mono=mono[0] - 30)   # wall clock ahead by an hour
        self.clock.t -= 7200                                           # then set back two hours
        op = c.dispatch(op["key"], fresh, expected_version=op["version"], event_id=self.ev(), lease_ok=True,
                        mirror_read_back=True)
        self.assertEqual(op["state"], "dispatched")

    def test_stamp_uses_this_boot_and_the_real_monotonic_clock(self):
        c = C.Contracts(self.db, self.log)
        o = c.stamp({"tip": BASE})
        self.assertEqual((o["tip"], o["boot"]), (BASE, c.boot_id))
        self.assertTrue(c.boot_id.startswith(("linux:", "process:")), c.boot_id)
        c._fresh(o)                                                      # fresh as stamped
        with self.assertRaisesRegex(C.ContractError, "another boot"):
            C.Contracts(self.db, self.log, boot_id="linux:another-boot")._fresh(o)
        if c.boot_id.startswith("process:"):           # no kernel boot id: another process's stamp is stale
            with self.assertRaisesRegex(C.ContractError, "another boot"):
                C.Contracts(self.db, self.log)._fresh(o)
        with self.assertRaisesRegex(C.ContractError, "stale"):
            c._fresh(dict(o, mono=o["mono"] - C.Contracts.OBSERVATION_SECONDS))

    def test_e02_every_guard_is_checked_and_nothing_counts_on_refusal(self):
        g, op = self.reserved()
        bad = {"kill switch": self.obs(kill_switch=True), "kill switch unread": self.obs(kill_switch=None),
               "pr closed": self.obs(pr_state="CLOSED"), "head moved": self.obs(pr_head=H2),
               "draft": self.obs(draft=True), "base moved": self.obs(tip=B2), "tip is H": self.obs(tip=H1),
               "identical": self.obs(compare="identical"), "diverged": self.obs(compare="diverged"),
               "behind": self.obs(compare="behind"), "compare unread": self.obs(compare=None),
               "red check": self.obs(checks_green=False),
               "stale": self.obs(at=self.clock.t - C.Contracts.OBSERVATION_SECONDS),
               "future": self.obs(at=self.clock.t + 1), "no time": self.obs(at=None), "bool time": self.obs(at=True),
               # D-a3: the age is the monotonic stamp's, whatever the wall-clock stamp says
               "mono stale, wall fresh": self.obs(mono=self.clock.t - C.Contracts.OBSERVATION_SECONDS),
               "mono future": self.obs(mono=self.clock.t + 1), "no mono": self.obs(mono=None),
               "bool mono": self.obs(mono=True), "mono as text": self.obs(mono=str(self.clock.t)),
               "other boot": self.obs(boot="another-boot"), "no boot": self.obs(boot=None)}
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

    def test_e02_the_request_is_after_oid_reviewed_h_before_oid_b_never_forced(self):
        g, op = self.dispatched()
        data = json.loads(self.db.execute("SELECT data FROM transitions WHERE to_state='dispatched'").fetchone()[0])
        self.assertEqual(data["request"], {"method": "updateRefs", "beforeOid": BASE, "afterOid": H1,
                                           "force": False})
        self.assertEqual(data["request"]["afterOid"], self.grow(g)["head"], "afterOid is the granted, reviewed H")

    def test_e02_needs_the_grant_reserved_for_this_key(self):
        self.active_grant()
        op = self.c.intend(self.params(), lease_ok=True, event_id=self.ev())
        with self.assertRaisesRegex(C.ContractError, "reserved"):
            self.send(op)

    def test_e02_dispatch_caps_at_b10_through_p3_retries(self):
        g, op = self.dispatched()
        for _ in range(C.B10_DISPATCHES - 1):
            op = self.c.absent(op["key"], "p3", {"stage": "dns"}, expected_version=op["version"], event_id=self.ev())
            op = self.after(op, self.read(tip=BASE))
            self.assertEqual(op["state"], "intent")
            op = self.send(op)
        self.assertEqual(op["dispatch_count"], C.B10_DISPATCHES)
        op = self.c.absent(op["key"], "p3", {"stage": "dns"}, expected_version=op["version"], event_id=self.ev())
        op = self.after(op, self.read(tip=BASE))
        self.assertEqual((op["state"], op["incident"]), ("held", 1), "E11: the third dispatch was used")

    def test_e02_dispatch_itself_refuses_past_b10(self):
        g, op = self.reserved()
        self.db.execute("UPDATE operations SET dispatch_count=? WHERE key=?", (C.B10_DISPATCHES, op["key"]))
        with self.assertRaisesRegex(C.ContractError, "B10"):
            self.send(op)

    def test_e03_confirms_on_tip_h_or_a_b_h_entry_never_on_reachability(self):
        g, op = self.dispatched()
        bad = {"reachable only": self.read(tip=OTHER, h_reachable=True, compare="ahead", activity=None),
               "no entry": self.read(tip=OTHER),
               "incomplete with entry": self.read(tip=OTHER, entries=[self.entry()], complete=False),
               "unread activity": self.read(tip=OTHER, activity={"entries": [self.entry()]}),
               "other before": self.read(tip=OTHER, entries=[self.entry(before=B2)]),
               "other after": self.read(tip=OTHER, entries=[self.entry(after=H2)]),
               "tip still B": self.read(tip=BASE),
               "stale": self.readback(at=self.clock.t - C.Contracts.OBSERVATION_SECONDS)}
        for name, r in bad.items():
            with self.subTest(name), self.assertRaises(C.ContractError):
                self.c.confirm(op["key"], dict(r, pr_merged=True), expected_version=op["version"],
                               event_id=self.ev())
        # another integration advanced the branch past H before the readback: the activity entry confirms
        op = self.c.confirm(op["key"], dict(self.read(tip=OTHER, entries=[self.entry(after=OTHER, before=H1),
                                                                          self.entry()]), pr_merged=True),
                            expected_version=op["version"], event_id=self.ev())
        self.assertEqual((op["state"], op["pr_unmarked"]), ("confirmed", 0))
        g2, op2 = self.dispatched(pr=6)
        op2 = self.c.confirm(op2["key"], self.readback(activity=None), expected_version=op2["version"],
                             event_id=self.ev())
        self.assertEqual(op2["state"], "confirmed", "tip == H confirms without an activity read")

    def test_e12_unmarked_pr_confirms_only_after_ten_minutes(self):
        g, op = self.dispatched()
        with self.assertRaisesRegex(C.ContractError, "10 min"):
            self.c.confirm(op["key"], self.readback(pr_merged=False), expected_version=op["version"],
                           event_id=self.ev())
        self.clock.t += C.Contracts.PR_MARK_SECONDS
        op = self.c.confirm(op["key"], self.readback(pr_merged=False), expected_version=op["version"],
                            event_id=self.ev())
        self.assertEqual((op["state"], op["pr_unmarked"]), ("confirmed", 1))

    def test_e04_only_p1_and_p3_are_absence(self):
        g, op = self.dispatched()
        bad = [("not-found-now", {"x": 1}), ("p1", {"kind": "Something went wrong"}), ("p1", {}),
               ("p2", {"error": "Something went wrong", "readback": self.read()}),
               ("p3", {"stage": "http"}), ("p3", {"stage": "reset-after-send"}), ("p3", {})]
        for proof, ev in bad:
            with self.subTest(proof=proof, ev=ev), self.assertRaises(C.ContractError):
                self.c.absent(op["key"], proof, ev, expected_version=op["version"], event_id=self.ev())
        self.assertEqual(self.c._row("operations", "key", op["key"])["state"], "dispatched")
        self.assertEqual(self.gstate(g), "reserved", "an untyped error keeps the grant reserved")
        op = self.c.absent(op["key"], "p1", {"kind": "ref-lock"}, expected_version=op["version"], event_id=self.ev())
        self.assertEqual((op["state"], op["proof"], op["proven_absent"]), ("absent-proven", "p1", 1))

    def test_e13_p2_fences_after_two_complete_reads_and_keeps_the_grant_reserved(self):
        g, op = self.fenced()
        self.assertEqual((op["state"], op["proof"]), ("fenced", "p2"))
        self.assertEqual(op["escalate_at"], self.clock.t + C.FENCED_ESCALATE_SECONDS, "escalates to main at 4 h")
        self.assertEqual((self.gstate(g), self.grow(g)["cap_held"]), ("reserved", 1))

    def test_e13_guards(self):
        g, op = self.dispatched()
        sent = self.clock.t
        self.clock.t = sent + C.E13_FIRST_READ_SECONDS + C.E13_READ_GAP_SECONDS

        def at(dt, **kw):
            return self.read(at=sent + dt, **kw)
        ok1, ok2 = at(C.E13_FIRST_READ_SECONDS), at(C.E13_FIRST_READ_SECONDS + C.E13_READ_GAP_SECONDS)
        bad = {"one read": ("x", [ok2]), "no error": ("", [ok1, ok2]),
               "too early": ("x", [at(C.E13_FIRST_READ_SECONDS - 1), ok2]),
               "too close": ("x", [ok1, at(C.E13_FIRST_READ_SECONDS + C.E13_READ_GAP_SECONDS - 1)]),
               "tip B": ("x", [ok1, at(180, tip=BASE)]), "tip H": ("x", [at(120, tip=H1), ok2]),
               "entry": ("x", [ok1, at(180, entries=[self.entry()])]),
               "incomplete": ("x", [ok1, at(180, complete=False)]), "no tip": ("x", [ok1, at(180, tip=None)])}
        for name, (error, reads) in bad.items():
            with self.subTest(name), self.assertRaises(C.ContractError):
                self.c.fence(op["key"], error, reads, expected_version=op["version"], event_id=self.ev())
        self.assertEqual(self.c._row("operations", "key", op["key"])["state"], "dispatched")
        self.assertEqual(self.c.fence(op["key"], "no-response", [ok1, ok2], expected_version=op["version"],
                                      event_id=self.ev())["state"], "fenced")

    def test_e13_monotonic_wall_jump_forward_does_not_shorten_the_wait(self):
        """goodqa#16193, spec owner T-2: E13's delays are measured on the monotonic clock. Here the wall clock
        jumps forward an hour right after the dispatch while only 30 s pass on the monotonic clock."""
        mono = [self.clock.t]
        self.c = C.Contracts(self.db, self.log, now=self.clock, mono=lambda: mono[0], boot_id=BOOT)
        g, op = self.dispatched()
        sent = mono[0]
        self.clock.t += 3600                                         # wall: an hour later
        mono[0] = sent + 90
        # by their wall stamps these reads are an hour after the dispatch and 60 s apart: wall time would accept them
        early = [self.read(at=self.clock.t - 60, mono=sent + 30), self.read(mono=sent + 90)]
        with self.assertRaisesRegex(C.ContractError, "at least 2 min"):
            self.c.fence(op["key"], "no-response", early, expected_version=op["version"], event_id=self.ev())
        mono[0] = sent + C.E13_FIRST_READ_SECONDS + C.E13_READ_GAP_SECONDS
        ok = [self.read(mono=sent + C.E13_FIRST_READ_SECONDS), self.read(mono=mono[0])]
        self.assertEqual(self.c.fence(op["key"], "no-response", ok, expected_version=op["version"],
                                      event_id=self.ev())["state"], "fenced")

    def test_e13_monotonic_a_restart_restarts_the_wait(self):
        g, op = self.dispatched()
        sent = self.clock.t
        # restarted onto another boot: its monotonic clock starts near zero, the dispatch's stamp means nothing
        boot2, mono = "boot-after-restart", [5.0]
        c2 = C.Contracts(self.db, self.log, now=self.clock, mono=lambda: mono[0], boot_id=boot2)

        def read2(m, **kw):
            return self.read(mono=m, boot=boot2, **kw)
        mono[0] = 500.0                  # both reads would be 2 min "after the dispatch" if old stamps counted
        late = [read2(440.0), read2(500.0)]
        self.clock.t = sent + 1000
        with self.assertRaisesRegex(C.ContractError, "restart"):
            c2.fence(op["key"], "no-response", late, expected_version=op["version"], event_id=self.ev())
        row = c2._row("operations", "key", op["key"])
        self.assertEqual((row["wait_boot"], row["wait_mono"], row["version"]), (boot2, 500.0, op["version"]),
                         "the wait restarted at the restart's own stamp; bookkeeping, no version change")
        with self.assertRaises(C.ContractError):                      # the old boot's reads are stale here
            c2.fence(op["key"], "no-response", [self.read(), self.read()], expected_version=op["version"],
                     event_id=self.ev())
        mono[0] = 500.0 + C.E13_FIRST_READ_SECONDS + C.E13_READ_GAP_SECONDS
        ok = [read2(500.0 + C.E13_FIRST_READ_SECONDS), read2(mono[0])]
        self.assertEqual(c2.fence(op["key"], "no-response", ok, expected_version=op["version"],
                                  event_id=self.ev())["state"], "fenced")
        self.assertEqual(c2.e13_wait_start(op["key"]), 500.0, "a second call on the same boot keeps the stamp")

    def test_e13_a_fenced_op_never_yields_a_new_grant_or_generation(self):
        g, op = self.fenced()
        self.assertEqual(self.c.intend(self.params(), lease_ok=True, event_id=self.ev())["key"], op["key"],
                         "the same (B, H) maps back to the fenced op, never to g+1")
        with self.assertRaisesRegex(C.ContractError, "already covers"):
            self.issued()
        with self.assertRaises(C.ContractError):
            self.c.confirm(op["key"], self.readback(), expected_version=op["version"], event_id=self.ev())

    def test_e13_also_fences_from_outcome_unknown(self):
        g, op = self.dispatched()
        self.clock.t += C.B55_REQUEST_SECONDS
        op = self.c.unknown(op["key"], expected_version=op["version"], event_id=self.ev())
        first = self.read()
        self.clock.t += C.E13_READ_GAP_SECONDS
        op = self.c.fence(op["key"], "no-response", [first, self.read()], expected_version=op["version"],
                          event_id=self.ev())
        self.assertEqual((op["state"], self.gstate(g)), ("fenced", "reserved"))

    def test_e14_the_watch_also_confirms_on_tip_h(self):
        g, op = self.fenced()
        op = self.c.watch_confirm(op["key"], self.read(tip=H1, activity=None), expected_version=op["version"],
                                  event_id=self.ev())
        self.assertEqual((op["state"], self.gstate(g)), ("confirmed", "consumed"))
        self.assertTrue(self.c.merging_off("o/r"))

    def test_e14_the_watch_confirms_a_fenced_op_with_an_incident_and_merging_off(self):
        g, op = self.fenced()
        for r in (self.read(), self.read(entries=[self.entry()], complete=False), self.read(tip=BASE)):
            with self.subTest(r=r), self.assertRaises(C.ContractError):
                self.c.watch_confirm(op["key"], r, expected_version=op["version"], event_id=self.ev())
        self.assertFalse(self.c.merging_off("o/r"))
        op = self.c.watch_confirm(op["key"], self.read(entries=[self.entry()]), expected_version=op["version"],
                                  event_id=self.ev())
        self.assertEqual((op["state"], op["incident"]), ("confirmed", 1))
        self.assertTrue(self.c.merging_off("o/r"))
        self.assertEqual((self.gstate(g), self.grow(g)["cap_held"]), ("consumed", 1))

    def test_e15_main_abandons_a_fenced_op_on_evidence_and_the_grant_is_consumed(self):
        g, op = self.fenced()
        for actor in ("ahc-core", "reconcile", "ahc-merge"):
            with self.subTest(actor), self.assertRaises(C.ContractError):
                self.c.settle_fenced(op["key"], {"note": "x"}, expected_version=op["version"], event_id=self.ev(),
                                     actor=actor)
        with self.assertRaises(C.ContractError):
            self.c.settle_fenced(op["key"], {}, expected_version=op["version"], event_id=self.ev(), actor="main")
        op = self.c.settle_fenced(op["key"], {"support": "GitHub confirmed the request was dropped"},
                                  expected_version=op["version"], event_id=self.ev(), actor="main")
        self.assertEqual(op["state"], "abandoned")
        self.assertEqual((self.gstate(g), self.grow(g)["cap_held"]), ("consumed", 1), "CAP1 stays charged")
        with self.assertRaisesRegex(C.ContractError, "never yields a new generation"):
            self.c.intend(self.params(), lease_ok=True, event_id=self.ev())

    def test_e05_e06_unknown_then_held_keeps_the_grant_and_only_main_abandons(self):
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
        self.clock.t += C.B47_GRANT_SECONDS * 400     # time never settles a held op (no B54)
        self.c.expire_grants("sweep")
        self.assertEqual(self.gstate(g), "reserved")
        self.assertEqual(self.c.retain(), 0, "a held op is never tombstoned")
        with self.assertRaises(C.ContractError):
            self.c.confirm(op["key"], self.readback(), expected_version=op["version"], event_id=self.ev())
        for actor in ("ahc-core", "reconcile"):
            with self.subTest(actor), self.assertRaises(C.ContractError):
                self.c.settle_held(op["key"], stamped({"at": self.clock.t, "tip": OTHER}), expected_version=op["version"],
                                   event_id=self.ev(), actor=actor)
        op = self.c.settle_held(op["key"], {"note": "PR closed by hand; outcome unknown"},
                                expected_version=op["version"], event_id=self.ev(), actor="main")
        self.assertEqual((op["state"], op["proof"]), ("abandoned", "unknown-spent"))
        self.assertEqual(self.gstate(g), "consumed", "an uncertain use is spent (G4)")

    def test_e10_reconcile_confirms_on_tip_h_or_fences_on_a_complete_off_read(self):
        g, op = self.held()
        op = self.c.confirm(op["key"], self.readback(), expected_version=op["version"], event_id=self.ev(),
                            actor="reconcile")
        self.assertEqual(op["state"], "confirmed")
        g2, op2 = self.held(pr=6)
        for r in (self.read(tip=BASE), self.read(tip=H1), self.read(complete=False),
                  self.read(entries=[self.entry()]),
                  self.read(at=self.clock.t - C.Contracts.OBSERVATION_SECONDS)):
            with self.subTest(r=r), self.assertRaises(C.ContractError):
                self.c.fence_held(op2["key"], r, expected_version=op2["version"], event_id=self.ev())
        op2 = self.c.fence_held(op2["key"], self.read(), expected_version=op2["version"], event_id=self.ev())
        self.assertEqual((op2["state"], self.gstate(g2)), ("fenced", "reserved"))

    def test_e07_retry_is_p3_only_with_the_tip_still_b(self):
        for n, (proof, read, want) in enumerate((("p3", self.read(tip=BASE), "intent"),
                                  ("p3", self.read(tip=B2), "abandoned"),
                                  ("p1", self.read(tip=BASE), "abandoned"),
                                  ("p1", self.read(tip=B2), "abandoned"))):
            with self.subTest(proof=proof, tip=read["tip"]):
                g, op = self.absent_p(proof, pr=100 + n)
                op = self.after(op, read)
                self.assertEqual(op["state"], want)
                self.assertEqual(self.gstate(g), "reserved" if want == "intent" else "retired")

    def test_e08_needs_a_complete_activity_read(self):
        for n, (proof, tip) in enumerate((("p1", BASE), ("p1", B2), ("p3", B2))):
            with self.subTest(proof=proof, tip=tip):
                g, op = self.absent_p(proof, pr=200 + n)
                for r in (self.read(tip=tip, complete=False), self.read(tip=tip, activity=None)):
                    with self.assertRaisesRegex(C.ContractError, "activity"):
                        self.after(op, r)
                self.assertEqual(self.c._row("operations", "key", op["key"])["state"], "absent-proven")

    def test_e16_absence_contradicted_by_a_readback_abandons_with_an_incident_and_retires(self):
        for n, (proof, read) in enumerate((("p1", self.read(tip=H1, activity=None)),
                            ("p1", self.read(tip=OTHER, entries=[self.entry()])),
                            ("p3", self.read(tip=H1)),
                            ("p3", self.read(tip=OTHER, entries=[self.entry()])),
                            ("p1", self.read(tip=BASE, entries=[self.entry()])))):
            with self.subTest(proof=proof, tip=read["tip"]):
                g, op = self.absent_p(proof, pr=300 + n)
                op = self.after(op, read)
                self.assertEqual((op["state"], op["incident"]), ("abandoned", 1), "never credited as confirmed")
                self.assertEqual((self.gstate(g), self.grow(g)["cap_held"]), ("retired", 0))
                data = json.loads(self.db.execute("SELECT data FROM transitions WHERE id=? AND to_state='abandoned'",
                                                  (op["key"],)).fetchone()[0])
                self.assertEqual((data["row"], data["incident"]), ("E16", "integrated-elsewhere"))

    def test_f4_applied_then_connection_reset_is_settled_by_readback_not_retried(self):
        """The server applied the CAS and the connection then reset: no proof exists, so no absent-proven, no
        second dispatch; the readback confirms on the activity entry."""
        g, op = self.dispatched()
        for proof, ev in (("p3", {"stage": "reset-after-send"}), ("p1", {"kind": "connection reset"})):
            with self.subTest(proof), self.assertRaises(C.ContractError):
                self.c.absent(op["key"], proof, ev, expected_version=op["version"], event_id=self.ev())
        self.clock.t += C.B55_REQUEST_SECONDS
        op = self.c.unknown(op["key"], expected_version=op["version"], event_id=self.ev())
        op = self.c.confirm(op["key"], dict(self.read(entries=[self.entry()]), pr_merged=True),
                            expected_version=op["version"], event_id=self.ev())
        self.assertEqual((op["state"], op["dispatch_count"]), ("confirmed", 1))

    def test_e07_retry_carries_the_same_parameters_and_a_lease(self):
        g, op = self.absent_p("p3")
        with self.assertRaises(C.OperationConflict):
            self.after(op, self.read(tip=BASE), params=self.params(default_branch="trunk"))
        with self.assertRaises(C.ContractError):
            self.after(op, self.read(tip=BASE), lease_ok=False)

    def test_e09_only_an_intent_with_every_send_absent_is_abandoned_unsent(self):
        g, op = self.dispatched()
        with self.assertRaises(C.ContractError):
            self.c.abandon_unsent(op["key"], expected_version=op["version"], event_id=self.ev(), reason="W4")
        g2, op2 = self.reserved(pr=6)
        op2 = self.c.abandon_unsent(op2["key"], expected_version=op2["version"], event_id=self.ev(), reason="W4")
        self.assertEqual((op2["state"], op2["proof"]), ("abandoned", "never-sent"))

    def test_late_apply_watch_covers_fenced_forever_and_abandoned_for_30_days(self):
        g, op = self.reserved()
        op = self.c.abandon_unsent(op["key"], expected_version=op["version"], event_id=self.ev(), reason="cancel")
        gf, fenced = self.fenced(pr=6)
        self.assertEqual({w["key"]: w["state"] for w in self.c.watched("o/r")},
                         {op["key"]: "abandoned", fenced["key"]: "fenced"})
        for r in (self.read(), self.read(entries=[self.entry()], complete=False)):
            with self.subTest(r=r), self.assertRaises(C.ContractError):
                self.c.late_apply(op["key"], r, event_id=self.ev())
        with self.assertRaises(C.ContractError):
            self.c.late_apply(fenced["key"], self.read(entries=[self.entry()]), event_id=self.ev())   # E14 instead
        self.assertFalse(self.c.merging_off("o/r"))
        flag = self.c.late_apply(op["key"], self.read(entries=[self.entry()]), event_id=self.ev())
        self.assertEqual((flag["merging_off"], flag["cause"]), (1, "late-apply:%s" % op["key"]))
        self.assertTrue(self.c.merging_off("O/R"))
        self.assertEqual(self.c._row("operations", "key", op["key"])["incident"], 1)
        with self.assertRaises(C.ContractError):
            self.c.set_merging("o/r", off=False, cause="x", actor="ahc-core")
        self.c.set_merging("o/r", off=False, cause="main reconciled", actor="main")
        self.assertFalse(self.c.merging_off("o/r"))
        self.clock.t += C.Contracts.LATE_WATCH_SECONDS + 1
        self.assertEqual([w["key"] for w in self.c.watched("o/r")], [fenced["key"]],
                         "the abandoned watch lasts 30 days; a fenced op is watched without expiry")

    def test_retention_tombstones_settled_rows_only_never_fenced_or_held(self):
        g, op = self.dispatched()
        g2, pending = self.reserved(pr=9)
        gf, fenced = self.fenced(pr=10)
        gh, held = self.held(pr=11)
        self.c.confirm(op["key"], self.readback(), expected_version=op["version"], event_id=self.ev())
        self.clock.t += C.B48_RETENTION_SECONDS * 10
        self.assertEqual(self.c.retain(), 1)
        for row in (pending, fenced, held):
            self.assertEqual(self.c._row("operations", "key", row["key"])["tombstone"], 0)
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
            ("dispatched", "absent-proven"), ("outcome-unknown", "absent-proven"),
            ("dispatched", "fenced"), ("outcome-unknown", "fenced"), ("fenced", "confirmed"), ("fenced", "abandoned"),
            ("dispatched", "outcome-unknown"), ("outcome-unknown", "held"), ("absent-proven", "intent"),
            ("absent-proven", "abandoned"), ("intent", "abandoned"), ("held", "confirmed"), ("held", "abandoned"),
            ("held", "fenced"), ("absent-proven", "held")})
        self.assertEqual(C.Contracts.OP[("fenced", "abandoned")], ("main",), "E15 is main's only")
        self.assertEqual(C.Contracts.OP[("held", "abandoned")], ("main",), "no reconcile horizon abandons (E10)")
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
        self.assertFalse(hasattr(C, "B54_LATE_SECONDS"), "there is no late-request horizon")


class WatchAttributionTests(Base):
    """Spec v2g4 (core 71971fc8), Late-apply watch: each activity entry id is attributed to at most one op; an
    entry is explained when it confirmed an op (E3/E12/E14/E10) or was named by an E16 incident. The watch fires
    only on an unexplained (B, H) entry, or on tip == H with no confirmed (or E16) op at the same
    (repo, pr, B, H, revision). Every poll goes through watched(), as the runner's would."""

    @staticmethod
    def e(eid, before=BASE, after=H1):
        return {"id": eid, "before": before, "after": after, "type": "push"}

    def poll(self, read):
        """One watch poll over the repo: late_apply on every watched abandoned op; returns the keys that raised."""
        raised = []
        for w in self.c.watched("o/r"):
            if w["state"] == "abandoned" and self.c.late_apply(w["key"], read, event_id=self.ev()) is not None:
                raised.append(w["key"])
        return raised

    def e8_abandoned(self):
        g, op = self.absent_p("p1")
        return self.after(op, self.read(tip=B2))

    def incidents(self, op):
        return self.c._row("operations", "key", op["key"])["incident"]

    def test_a_abandoned_g_then_g1_confirmed_at_the_same_b_h_raises_nothing(self):
        g0 = self.e8_abandoned()
        self.assertEqual((g0["state"], g0["proof"]), ("abandoned", "all-sends-absent"))
        g1, op1 = self.dispatched()
        self.assertEqual(op1["generation"], g0["generation"] + 1)
        self.c.confirm(op1["key"], self.readback(), expected_version=op1["version"], event_id=self.ev())
        for _ in range(2):
            self.assertEqual(self.poll(self.read(tip=H1, entries=[self.e("ev-gh-1")])), [])
            self.assertEqual(self.poll(self.readback()), [], "tip == H is explained by the confirmed g+1")
        self.assertFalse(self.c.merging_off("o/r"))
        self.assertEqual(self.incidents(g0), 0)

    def test_a_the_entry_read_at_confirm_is_attributed_there(self):
        g0 = self.e8_abandoned()
        g1, op1 = self.dispatched()
        confirm_read = self.read(tip=H1, entries=[self.e("ev-gh-1")], pr_merged=True)
        op1 = self.c.confirm(op1["key"], confirm_read, expected_version=op1["version"], event_id=self.ev())
        self.assertEqual(self.db.execute("SELECT op_key, how FROM attributions WHERE entry_id='ev-gh-1'").fetchone(),
                         (op1["key"], "confirm"))
        self.assertEqual(self.poll(self.read(tip=H1, entries=[self.e("ev-gh-1")])), [])
        self.assertFalse(self.c.merging_off("o/r"))

    def test_b_an_e16_op_raises_once_and_not_again_on_the_next_poll(self):
        g, op = self.absent_p("p1")
        op = self.after(op, self.read(tip=H1))                     # E16: something else integrated H
        self.assertEqual((op["state"], op["incident"]), ("abandoned", 1))
        for read in (self.read(tip=H1, entries=[self.e("ev-gh-7")]), self.read(tip=H1, entries=[self.e("ev-gh-7")]),
                     self.readback()):
            self.assertEqual(self.poll(read), [])
        self.assertEqual(self.incidents(op), 1, "the E16 incident is the only one")
        self.assertFalse(self.c.merging_off("o/r"))

    def test_b_an_e16_op_with_its_entry_holds_that_entry(self):
        g, op = self.absent_p("p1")
        op = self.after(op, self.read(tip=OTHER, entries=[self.e("ev-gh-8")]))
        self.assertEqual(self.db.execute("SELECT op_key, how FROM attributions WHERE entry_id='ev-gh-8'").fetchone(),
                         (op["key"], "E16"))
        self.assertEqual(self.poll(self.read(entries=[self.e("ev-gh-8")])), [])
        self.assertEqual(self.incidents(op), 1)

    def test_c_a_second_unexplained_b_h_entry_after_a_rewind_raises_once(self):
        g0 = self.e8_abandoned()
        g1, op1 = self.dispatched()
        self.c.confirm(op1["key"], self.read(tip=H1, entries=[self.e("ev-gh-1")], pr_merged=True),
                       expected_version=op1["version"], event_id=self.ev())
        self.assertEqual(self.poll(self.read(tip=H1, entries=[self.e("ev-gh-1")])), [])
        # the branch is rewound to B and the (B, H) update applies a second time: g+1 explains only its own entry
        again = self.read(tip=H1, entries=[self.e("ev-gh-1"), self.e("ev-gh-2", before=H1, after=BASE),
                                           self.e("ev-gh-3")])
        self.assertEqual(self.poll(again), [g0["key"]])
        self.assertTrue(self.c.merging_off("o/r"))
        self.assertEqual(self.incidents(g0), 1)
        self.assertEqual(self.db.execute("SELECT op_key, how FROM attributions WHERE entry_id='ev-gh-3'").fetchone(),
                         (g0["key"], "late-apply"))
        self.assertEqual(self.poll(again), [], "the same entry never raises twice")
        self.assertEqual(self.incidents(g0), 1)

    def test_c_a_tip_confirmed_op_claims_one_entry_only_when_two_arrive_in_one_read(self):
        g0 = self.e8_abandoned()
        g1, op1 = self.dispatched()
        self.c.confirm(op1["key"], self.readback(), expected_version=op1["version"], event_id=self.ev())
        two = self.read(tip=H1, entries=[self.e("ev-gh-1"), self.e("ev-gh-3")])
        self.assertEqual(self.poll(two), [g0["key"]], "g+1 explains one application of (B, H), not two")
        self.assertEqual(dict(self.db.execute("SELECT entry_id, how FROM attributions").fetchall()),
                         {"ev-gh-1": "confirm", "ev-gh-3": "late-apply"})

    def test_an_entry_without_an_id_is_never_explained(self):
        g0 = self.e8_abandoned()
        g1, op1 = self.dispatched()
        self.c.confirm(op1["key"], self.readback(), expected_version=op1["version"], event_id=self.ev())
        anonymous = self.read(tip=H1, entries=[self.entry()])
        self.assertEqual(self.poll(anonymous), [g0["key"]], "no id: it cannot be attributed (fail closed)")

    def test_tip_h_with_no_explainer_raises_once_per_op(self):
        g0 = self.e8_abandoned()
        self.assertEqual(self.poll(self.readback()), [g0["key"]])
        self.assertEqual(self.poll(self.readback()), [])
        self.assertEqual(self.incidents(g0), 1)

    def test_an_explainer_at_another_revision_or_pr_explains_nothing(self):
        g0 = self.e8_abandoned()
        g1, op1 = self.dispatched(pr=6)
        self.c.confirm(op1["key"], self.readback(), expected_version=op1["version"], event_id=self.ev())
        self.assertEqual(self.poll(self.read(tip=H1, entries=[self.e("ev-gh-1")])), [g0["key"]])

    def test_an_incomplete_read_still_raises_and_claims_nothing(self):
        g0 = self.e8_abandoned()
        with self.assertRaises(C.ContractError):
            self.c.late_apply(g0["key"], self.read(entries=[self.e("ev-gh-1")], complete=False), event_id=self.ev())
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM attributions").fetchone()[0], 0)


class LegacyTests(Base):
    def test_unsettled_legacy_rows_are_reported(self):
        self.db.execute("CREATE TABLE grants_v3_legacy (id TEXT, state TEXT, repo TEXT)")
        self.db.execute("CREATE TABLE operations_v3_legacy (key TEXT, state TEXT)")
        self.db.execute("CREATE TABLE reviews_v3_legacy (id TEXT, state TEXT)")
        self.db.executemany("INSERT INTO grants_v3_legacy VALUES (?,?,?)",
                            [("g1", "reserved", "o/r"), ("g2", "consumed", "o/r")])
        self.db.executemany("INSERT INTO operations_v3_legacy VALUES (?,?)", [("k1", "held"), ("k2", "confirmed")])
        self.db.execute("INSERT INTO reviews_v3_legacy VALUES ('r1', 'running')")
        self.assertEqual(self.c.legacy_unsettled(), [
            {"table": "grants_v3_legacy", "id": "g1", "state": "reserved", "repo": "o/r"},
            {"table": "operations_v3_legacy", "id": "k1", "state": "held", "repo": None}])


if __name__ == "__main__":
    unittest.main()
