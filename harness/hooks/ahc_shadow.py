#!/usr/bin/env python3
"""ahc shadow pipeline pieces (goodqa#16049 slice 1 (b), spec slice1b r9).

- The outbox delivery (AC-14): wi_notices is the outbox. Contracts._wi_notice is the one chokepoint that writes it,
  after the R5 scan. Delivery here re-scans each text (a second gate, never the only one) and, in this slice,
  delivers only to the shadow digest file. Nothing is sent to a PR, a ticket or an inbox.
- The review scheduler (AC-9, goodqa#16204 item 2): it offers only Contracts.offerable_rows, so a row of a
  terminal or merged item never takes an attempt slot.
- Status (AC-9 item 3): a review row of a finished item renders as "inert: item <state>", never as queued.
- The findings result producer (AC-9 item 4): a findings receipt carries `finding_ids`, filtered to the id rule and
  capped at 64, with the dropped count flagged.

No function here makes a network call or launches a child; every time stamp comes from the Contracts clock.
"""
from __future__ import annotations

import ahc_contracts as C
import ahc_scan

DIGEST_HEADER = "ahc shadow digest (receipts only; nothing here authorizes a merge)"


def deliver_digest(contracts, append, limit=500):
    """Deliver undelivered outbox rows to the shadow digest, oldest first. `append(text)` writes one block to the
    shadow digest file (the runner passes its private append). Each text is scanned again before it leaves: a
    text that is no longer clean is quarantined here and never written. Returns (delivered, quarantined).

    A row is marked delivered only after its line was appended, so a crash between the two re-delivers one line
    (at-least-once into a local file; the line carries its event id, so a reader can see a repeat)."""
    db = contracts.db
    rows = db.execute("SELECT rowid, event_id, item, row_id, kind, text FROM wi_notices WHERE delivered IS NULL "
                      "ORDER BY created, rowid LIMIT ?", (int(limit),)).fetchall()
    delivered = quarantined = 0
    for rowid, event_id, item, row_id, kind, text in rows:
        tier = ahc_scan.verdict(ahc_scan.scan_report(str(text).encode("utf-8", "replace"), path="digest"))
        with contracts.tx():
            if tier["action"] != ahc_scan.CLEAN:
                db.execute("INSERT OR IGNORE INTO wi_quarantine(event_id, item, row_id, kind, reason, created) "
                           "VALUES (?,?,?,?,?,?)", (event_id, item, row_id, kind,
                                                    "R5 %s at delivery; text withheld" % tier["action"],
                                                    contracts.now()))
                db.execute("UPDATE wi_notices SET text=?, delivered=? WHERE rowid=?",
                           ("withheld by R5 at delivery", contracts.now(), rowid))
                quarantined += 1
                continue
        append("shadow %s %s %s [%s]: %s\n" % (kind, item, row_id, event_id, text))
        with contracts.tx():
            db.execute("UPDATE wi_notices SET delivered=? WHERE rowid=? AND delivered IS NULL",
                       (contracts.now(), rowid))
        delivered += 1
    return delivered, quarantined


def review_status(contracts, row):
    """How status and the digest show one review row: its state, or "inert: item <state>" when the row waits for
    an attempt while its item is finished."""
    owner = contracts._row("work_items", "id", row["item"]) if row["item"] else None
    if owner is not None and owner["state"] in C.Contracts.FINISHED and row["state"] in C.Contracts.INERT_FROM:
        return "inert: item %s" % owner["state"]
    return row["state"]


def status_lines(contracts):
    """`ahc status` lines for the WorkItem ledger: each item, then each of its review rows."""
    out = []
    db = contracts.db
    for (iid,) in db.execute("SELECT id FROM work_items ORDER BY created, id").fetchall():
        item = contracts._row("work_items", "id", iid)
        out.append("item %s %-17s %s#%s %s" % (iid, item["state"], item["repo"], item["pr"], item["head"][:12]))
        for (rid,) in db.execute("SELECT id FROM reviews WHERE item=? ORDER BY round, kind, id", (iid,)).fetchall():
            row = contracts._row("reviews", "id", rid)
            out.append("  review %s %s r%d: %s" % (row["kind"], rid, row["round"], review_status(contracts, row)))
    return out


class ReviewScheduler:
    """Offers queued review rows to the R3 runner, at most `slots` per tick. `launch(row)` starts the row's
    attempt unit and returns (unit, uid) as core read them; it is injected (the bound R3 runner in production, a
    fake in tests). A refusal from start_attempt is recorded in the result, never retried in the same tick."""

    def __init__(self, contracts, launch, slots=1):
        self.c = contracts
        self.launch = launch
        self.slots = int(slots)

    def tick(self, event_prefix):
        offered, started, refused = [], [], []
        for row in self.c.offerable_rows(limit=self.slots):
            offered.append(row["id"])
            unit, uid = self.launch(row)
            try:
                self.c.start_attempt(row["id"], unit, uid, expected_version=row["version"],
                                     event_id="%s-start-%s" % (event_prefix, row["id"]))
                started.append(row["id"])
            except C.ContractError as error:
                refused.append((row["id"], str(error)))
        return {"offered": offered, "started": started, "refused": refused}


def findings_receipt(row, verdict, finding_ids, **extra):
    """The result producer's receipt for one review row (AC-9 item 4): the row's binding, the verdict and the
    finding ids that pass the id rule, capped at 64. Any dropped id is counted in `finding_ids_dropped`, which the
    W3 escalation flags."""
    kept, dropped = C.Contracts.finding_ids(finding_ids)
    receipt = {"repo": row["repo"], "pr": row["pr"], "head": row["head"], "packet_sha256": row["packet_sha256"],
               "policy_revision": row["policy_revision"], "verdict": verdict, "finding_ids": kept}
    if row["snapshot_base"]:
        receipt["snapshot_base"] = row["snapshot_base"]
    if row["kind"] == "spec":
        receipt["spec_core"] = row["spec_core"]
    if dropped:
        receipt["finding_ids_dropped"] = dropped
    receipt.update(extra)
    return receipt
