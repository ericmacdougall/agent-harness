#!/usr/bin/env python3
"""ahc shadow pipeline pieces (goodqa#16049 slice 1 (b), spec slice1b r9).

- The outbox delivery (AC-14): wi_notices is the outbox. Contracts._wi_notice is the one chokepoint that writes it,
  after the R5 scan. Delivery here re-scans each text (a second gate, never the only one) and, in this slice,
  delivers only to the shadow digest file. Nothing is sent to a PR, a ticket or an inbox.
- The review scheduler (AC-9, goodqa#16204 item 2): it offers only Contracts.offerable_rows, so a row of a
  terminal or merged item never takes an attempt slot. In the tick it offers rows to the R3 Launcher of the injected
  ahc_review.ReviewStage (AC-8; owner ruling: the tick schedules R3), after the stage settles completion signals.
- R2 at admission (option A, ASSUMPTION): core builds the review packet from its own clone at W1 and binds the item
  and its review rows to that packet's sha256; the owner's packet sha is listed in the packet's fenced owner
  section. A packet that cannot be built leaves the request held (fail closed, retried next tick).
- Status (AC-9 item 3): a review row of a finished item renders as "inert: item <state>", never as queued.
- The findings result producer (AC-9 item 4): a findings receipt carries `finding_ids`, filtered to the id rule and
  capped at 64, with the dropped count flagged.

No function here makes a network call or launches a child itself: reads go through the injected producer and
review attempts through the injected ReviewStage (AC-13 forms). Every time stamp comes from the Contracts clock.
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
    """Offers queued review rows to R3, at most `slots` per tick. `launch(row)` is the R3 Launcher's launch
    (ahc_review.Launcher: intent, unit, start_attempt) and returns (status, detail); "running" means the row is bound
    to its unit. Anything else is recorded in the result, never retried in the same tick."""

    def __init__(self, contracts, launch, slots=1):
        self.c = contracts
        self.launch = launch
        self.slots = int(slots)

    def tick(self, event_prefix):
        offered, started, refused = [], [], []
        for row in self.c.offerable_rows(limit=self.slots):
            offered.append(row["id"])
            status, detail = self.launch(row)
            if status == "running":
                started.append(row["id"])
            else:
                refused.append((row["id"], "%s: %s" % (status, detail)))
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


# ---------------------------------------------------------------- AC-3 / AC-4: the shadow boundary and tick

import hashlib  # noqa: E402
import json  # noqa: E402
import os  # noqa: E402
import re  # noqa: E402

from ahc_crash import crash_at  # noqa: E402

SHADOW_ENV = "AHC_SHADOW"
REQUEST_PREFIX = "shadow_req:"
# goodqa#16262: a held request's hold record sits beside it under its own prefix, outside REQUEST_PREFIX's LIKE
HOLD_PREFIX = "shadow_hold:"


def hold_key(request_key):
    """The hold record's key for a request key (shadow_req:<repo>#<pr>@<head> -> shadow_hold:<repo>#<pr>@<head>)."""
    return HOLD_PREFIX + request_key[len(REQUEST_PREFIX):]


# goodqa#16262 d5 F2: retryable holds are re-evaluated after 1, 2, 4, 8, 16, then 32 shadow ticks (capped), counted
# by shadow_tick_seq, which each tick increments once in its first transaction. Permanent holds wait for a new head.
SEQ_KEY = "shadow_tick_seq"
HOLD_KINDS = ("retryable", "permanent")


def hold_wait(count):
    """Ticks to wait after the `count`-th consecutive hold (1-based): 1, 2, 4, 8, 16, then 32."""
    return min(2 ** (max(int(count), 1) - 1), 32)


def tick_seq(contracts):
    row = contracts.db.execute("SELECT v FROM contract_meta WHERE k=?", (SEQ_KEY,)).fetchone()
    return int(row[0]) if row else 0


def _meta(contracts, key):
    row = contracts.db.execute("SELECT v FROM contract_meta WHERE k=?", (key,)).fetchone()
    return row[0] if row else None


CORE_HEX = re.compile(r"[0-9a-f]{64}")


def w1_hold(req, obs):
    """goodqa#16262 d5 RULED-4 checks 1-4 for a W1 request against its observation: (kind, reason) of the first that
    fails, or None. Check 5 (the lineage binding) is admit_item's. The reader was called only with the Refs ticket."""
    if obs.get("refs_problem"):
        return "permanent", str(obs["refs_problem"])                                          # check 1
    refs = C.parse_ticket_text(obs.get("refs_ticket"))
    if refs is None:                                            # fail closed: no check-1 result at all
        return "retryable", "refs: the observation carries no Refs ticket"
    label = C.ticket_text(refs)
    if C.parse_request_ticket(req.get("ticket")) != refs:                                     # check 2 (RT-21)
        return "retryable", "request ticket %s is not %s; resubmit with the ticket `GoodQA %s`" % (
            json.dumps(req.get("ticket")), label, label)
    core = obs.get("attached_core")
    if not (isinstance(core, str) and CORE_HEX.fullmatch(core)):                              # check 3
        return "retryable", "no attached spec on %s" % label
    if C.parse_ticket_text(obs.get("spec_ticket")) != refs:                                   # check 4
        return "retryable", "spec record names %s" % (obs.get("spec_ticket") or "no ticket")
    return None


def write_hold(contracts, key, read_value, read_hold, kind, reason):
    """Hold the request at `key` (RT-20: a compare-and-set). The write happens only if the request is still exactly
    `read_value` and its hold record still exactly `read_hold` (None: none) as the tick read them; otherwise nothing is
    written and False is returned, and the request is re-evaluated on the next tick."""
    if kind not in HOLD_KINDS:
        raise ValueError("a hold is retryable or permanent")
    with contracts.tx():
        if _meta(contracts, key) != read_value or read_value is None or _meta(contracts, hold_key(key)) != read_hold:
            return False
        count = (json.loads(read_hold)["count"] if read_hold else 0) + 1
        record = {"kind": kind, "reason": str(reason)[:300], "count": count,
                  "next_tick": tick_seq(contracts) + hold_wait(count) if kind == "retryable" else None}
        contracts.db.execute("INSERT OR REPLACE INTO contract_meta(k, v) VALUES (?, ?)",
                             (hold_key(key), C._canon(record)))
    return True
# Rows the tick evaluates. W1 is admission; W16 is main's stamped CLI (AC-6) and W20 the owner's cancel, so the tick
# never applies them. W21 is evaluated only when AC-7's send flag is on (ahc_w21).
TICK_ROWS = tuple(r for r in C.Contracts.WI_TRANSITIONS if r not in ("W1", "W16", "W20", "W21"))
MUTATING_METHODS = ("POST", "PUT", "PATCH", "DELETE")


def shadow_on():
    """AHC_SHADOW: only the exact value 1 enables the shadow pipeline (default off)."""
    return os.environ.get(SHADOW_ENV) == "1"


def legacy_live_repos(db):
    """Repos with a non-terminal legacy (P0) item; such a repo stays wholly in the legacy pipeline until drained."""
    try:
        import ahc_runner  # noqa: PLC0415
        rows = db.execute("SELECT request FROM items WHERE state IN (%s)" % ",".join(
            "?" * len(ahc_runner.NON_TERMINAL)), sorted(ahc_runner.NON_TERMINAL)).fetchall()
    except Exception:  # noqa: BLE001 - a ledger without the legacy table has no legacy items
        return set()
    out = set()
    for (req,) in rows:
        try:
            out.add(str(json.loads(req).get("repo", "")).lower())
        except (ValueError, AttributeError):
            continue
    return out


def pipeline_of(db, repo, config):
    """AC-3: "shadow" when AHC_SHADOW is 1, the repo is on the policy record's shadow list (config `shadow_repos`)
    and it has no live legacy item; otherwise "legacy". A repo is in exactly one pipeline."""
    repo = str(repo).lower()
    listed = {str(r).lower() for r in (config.get("shadow_repos") or [])}
    if shadow_on() and repo in listed and repo not in legacy_live_repos(db):
        return "shadow"
    return "legacy"


def queue_request(contracts, norm):
    """A submit for a shadow repo: the request is held for the shadow tick's admission (W1) and never enters the
    legacy items table. Idempotent per (repo, pr, head)."""
    key = "%s%s#%d@%s" % (REQUEST_PREFIX, norm["repo"], int(norm["pr"]), norm["head"])
    with contracts.tx():
        current = _meta(contracts, key)
        if current is None:
            # goodqa#16262 d5 F2: a request at a new head replaces any held request for the same (repo, pr), and its
            # hold record (prefix compared exactly, never with LIKE wildcards)
            prefix = "%s%s#%d@" % (REQUEST_PREFIX, norm["repo"], int(norm["pr"]))
            for (other,) in contracts.db.execute("SELECT k FROM contract_meta WHERE substr(k, 1, ?) = ? AND k != ?",
                                                 (len(prefix), prefix, key)).fetchall():
                if _meta(contracts, hold_key(other)) is not None:
                    contracts.db.execute("DELETE FROM contract_meta WHERE k IN (?, ?)", (other, hold_key(other)))
            contracts.db.execute("INSERT INTO contract_meta(k, v) VALUES (?, ?)",
                                 (key, C._canon({k: norm.get(k) for k in ("repo", "pr", "head", "base",
                                                                          "packet_sha256", "owner", "ticket")})))
        else:
            # a same-head resubmit of a queued (never admitted: admission deletes the request) request replaces only
            # its ticket, and resets a retryable hold's backoff so it is re-evaluated on the next tick
            req = json.loads(current)
            if norm.get("ticket") != req.get("ticket"):
                req["ticket"] = norm.get("ticket")
                contracts.db.execute("UPDATE contract_meta SET v=? WHERE k=?", (C._canon(req), key))
                raw = _meta(contracts, hold_key(key))
                hold = json.loads(raw) if raw else None
                if hold and hold.get("kind") == "retryable":
                    hold.update(count=0, next_tick=tick_seq(contracts))
                    contracts.db.execute("UPDATE contract_meta SET v=? WHERE k=?", (C._canon(hold), hold_key(key)))
    return key


GIT_WRITES = ("push", "commit", "merge", "update-ref", "tag", "branch", "rebase", "reset", "am", "cherry-pick",
              "revert", "send-pack", "remote", "config", "notes", "replace", "commit-tree")


def is_mutating(tool, args):
    """AC-3 / NEG-7: whether a gh or git argv (without the executable) writes. gh: any HTTP method other than GET,
    GraphQL, -f/-F/--field/--raw-field/--input (they switch gh api to POST), and every verb but `pr view` and
    `api`. git: push and every ref-, object- or config-writing subcommand."""
    args = [str(a) for a in args]
    if tool == "git":
        return any(a in GIT_WRITES for a in args if not a.startswith("-"))
    if not args:
        return False
    if args[0] == "pr":
        return args[1:2] != ["view"]
    if args[0] != "api":
        return True
    rest = args[1:]
    if "graphql" in rest or any(a in ("-f", "-F", "--field", "--raw-field", "--input") for a in rest):
        return True
    for i, a in enumerate(rest):
        if a in ("--method", "-X") and i + 1 < len(rest) and rest[i + 1].upper() != "GET":
            return True
        if a.startswith("--method=") and a.split("=", 1)[1].upper() != "GET":
            return True
    return False


def event_id(obs_id, item, row):
    """AC-4: a WorkItem move's event id is a function of (observation id, item, row) only."""
    return "wi:" + hashlib.sha256(json.dumps([obs_id, item, row]).encode()).hexdigest()[:32]


class ShadowTick:
    """One shadow pass: admit held requests (W1), observe each live WorkItem once through the producer, select one
    row per item (T7) and apply it through Contracts.wi_move, then deliver the outbox to the shadow digest.

    `producer` is an ahc_observe.Producer; `clone(repo, head, base)` returns the daemon clone holding H and the tip;
    `config` holds `shadow_repos`. Crash safety is the version CAS under BEGIN IMMEDIATE and the guard re-read in
    wi_move; WorkItems take no lease. A refused observation moves nothing. Nothing here dispatches an Effect or
    writes to GitHub."""

    def __init__(self, contracts, producer, clone, config, digest_append=None, w21=None, review=None,
                 store_packet=None, load_packet=None):
        self.c = contracts
        self.producer = producer
        self.clone = clone
        self.config = config
        self.digest_append = digest_append
        self.w21 = w21                       # AC-7: the W21 sender (ahc_w21.Sender), or None (W21 not evaluated)
        self.review = review                 # AC-8: ahc_review.ReviewStage, or None (no review step)
        self.store_packet = store_packet     # R2: writes a built packet where the R3 unit reads it
        self.load_packet = load_packet       # R2 (PR 273 receipt F2): sha -> the stored packet's bytes, or None

    def _repos(self):
        return sorted({str(r).lower() for r in self.config.get("shadow_repos") or []
                       if pipeline_of(self.c.db, r, self.config) == "shadow"})

    def _observe(self, summary, repo, pr, item=None, base=None, head=None, bases=()):
        import ahc_observe  # noqa: PLC0415
        import ahc_guard  # noqa: PLC0415
        try:
            clone = self.clone(repo, head, base)
            obs = self.producer.observe(repo, pr, item=item, clone=clone, snapshot_bases=bases, base=base)
        except ahc_observe.ObservationRefused as error:
            summary["refused"].append((item or "%s#%s" % (repo, pr), str(error)))
            return None
        except ahc_guard.LaunchRefused as error:
            summary["incidents"].append((item or "%s#%s" % (repo, pr), "launch refused: %s" % error))
            return None
        except Exception as error:  # noqa: BLE001 - a clone or read failure fails closed for this item only
            summary["refused"].append((item or "%s#%s" % (repo, pr), "%s: %s" % (type(error).__name__, error)))
            return None
        crash_at("tick.observed")
        return obs

    def admit_requests(self, summary):
        seq = tick_seq(self.c)
        rows = self.c.db.execute("SELECT k, v FROM contract_meta WHERE k LIKE ? ORDER BY k",
                                 (REQUEST_PREFIX + "%",)).fetchall()
        for key, value in rows:
            req = json.loads(value)
            if pipeline_of(self.c.db, req["repo"], self.config) != "shadow":
                continue
            # goodqa#16262 d5 AC-3 (e), NEG-13: a request at a live item's (repo, pr, head) is a duplicate. It is
            # consumed before `_observe` (no admission read, no GoodQA reader call, no hold, no R2 queueing), with
            # admit_item's own live-item predicate; admit_item's live return stays as the in-transaction recheck.
            with self.c.tx():
                live = self.c.db.execute(
                    "SELECT id FROM work_items WHERE repo=? AND pr=? AND head=? AND state NOT IN (%s)"
                    % ",".join("?" * len(C.Contracts.WI_TERMINAL)),
                    (str(req["repo"]).lower(), int(req["pr"]), req["head"]) + C.Contracts.WI_TERMINAL).fetchone()
                if live:
                    self.c.db.execute("DELETE FROM contract_meta WHERE k IN (?, ?)", (key, hold_key(key)))
            if live:
                summary["duplicates"].append((key, "duplicate of live item %s" % live[0]))
                continue
            raw = _meta(self.c, hold_key(key))
            if raw is not None:
                hold = json.loads(raw)
                if hold.get("kind") != "retryable" or seq < int(hold.get("next_tick") or 0):
                    summary["held"].append((key, hold.get("reason")))
                    continue
            if self.c.db.execute("SELECT 1 FROM work_items WHERE repo=? AND pr=? AND head!=? AND state IN (%s)"
                                 % ",".join("?" * len(C.Contracts._WI_LIVE)),
                                 (req["repo"], req["pr"], req["head"]) + C.Contracts._WI_LIVE).fetchone():
                continue                     # the packet for a live item's H': W4 or W24 takes it with the successor
            obs = self._observe(summary, req["repo"], req["pr"], base=req.get("base"), head=req["head"])
            if obs is None:
                continue
            if obs["pr_head"] != req["head"] or obs["pr_state"] != "OPEN":
                self._drop_request(summary, key, "head moved or PR not open at admission")
                continue
            # goodqa#16262 d5 RULED-4 checks 1-4: a failure holds the request (compare-and-set on what this tick read)
            failed = w1_hold(req, obs)
            if failed:
                self._hold(summary, key, value, raw, *failed)
                continue
            try:
                packet = self.r2_packet(req, obs, base=obs["tip"])
            except Exception as error:  # noqa: BLE001 - R2 fails closed: the request stays held
                summary["refused"].append((key, "admission: the R2 packet was not built: %s" % str(error)[:200]))
                continue
            rev = (obs.get("policy") or {}).get("revision")
            core = obs.get("attached_core")
            try:
                # One transaction this method opens itself: any error rolls back every admission write (the binding
                # row, the item, its review rows and the R2 queueing), so nothing partial commits (goodqa#16325).
                with self.c.tx():
                    # goodqa#16262: W1 binds the lineage to the Refs ticket the reader was called with (check 5)
                    item = self.c.admit_item(req["repo"], req["pr"], req["head"], obs["tip"], rev, core,
                                             packet["sha256"], event_id=event_id(obs["id"], key, "W1"),
                                             ticket=C.parse_ticket_text(obs.get("refs_ticket")))
                    self.r2_queue_item(item, packet)
                    # RT-19: every delete of a request takes its hold record
                    self.c.db.execute("DELETE FROM contract_meta WHERE k IN (?, ?)", (key, hold_key(key)))
            except C.BindingMismatch as error:
                self._hold(summary, key, value, raw, "permanent", str(error))           # check 5: NEG-14
                continue
            except C.ContractError as error:
                self._drop_request(summary, key, str(error))
                continue
            summary["admitted"].append(item["id"])

    def _hold(self, summary, key, value, raw, kind, reason):
        if write_hold(self.c, key, value, raw, kind, reason):
            summary["held"].append((key, reason))
        else:                                    # RT-20: changed since this tick read it; re-evaluated next tick
            summary["conflicts"].append((key, "hold", "the request or its hold changed during the tick"))

    def _drop_request(self, summary, key, reason):
        summary["refused"].append((key, "admission: %s" % reason))
        with self.c.tx():                        # RT-19: every delete of a request takes its hold record
            self.c.db.execute("DELETE FROM contract_meta WHERE k IN (?, ?)", (key, hold_key(key)))

    def r2_packet(self, req, obs, base):
        """R2 (option A): core's packet for (repo, pr, H) against B_r = `base`, built from core's own clone through the
        producer's git (AC-13 forms) and stored for the R3 unit. The owner's request is the fenced owner section."""
        import ahc_review  # noqa: PLC0415
        clone = self.clone(req["repo"], req["head"], base)
        owner = "\n".join("%s: %s" % (k, req.get(k)) for k in ("repo", "pr", "head", "base", "owner", "ticket",
                                                              "packet_sha256"))
        packet = ahc_review.build_packet(
            lambda args: self.producer._git(args, clone, 60)[:2], repo=req["repo"], pr=req["pr"], base=base,
            head=req["head"], spec_core_text=obs.get("spec_core_text"), spec_core_sha=obs.get("attached_core"),
            owner_text="The owner's request (its own packet is not core's input; its sha256 is listed):\n" + owner)
        if self.store_packet is not None:
            self.store_packet(packet)
        return packet

    def r2_required(self, summary):
        """PR 273 receipt F2: R2 for code rows required after their item's admission, which no admission or
        successor transaction queued: W16's extension rounds and W27's replacement rows (admission and W4/W24
        successors queue theirs in the same transaction, so a row reaches here only through those two or an
        interrupted queueing). Every required attempt-kind row of a pr-gate item in a shadow repo, bound to its
        item's packet, is queued from that stored packet once it re-verifies (hash, core's header, repo, PR, H and
        B_r) through r2_queue. Runs before the scheduler, every tick; idempotent (the row is then queued). A row
        that cannot be queued stays required and is reported in `refused` each tick, never dropped silently."""
        import ahc_review  # noqa: PLC0415
        repos = self._repos()
        if not repos:
            return
        rows = self.c.db.execute(
            "SELECT r.id FROM reviews r JOIN work_items w ON w.id = r.item WHERE r.state='required' AND "
            "w.state='pr-gate' AND r.packet_sha256 = w.packet_sha256 AND r.repo IN (%s) AND r.kind IN (%s) "
            "ORDER BY r.id" % (",".join("?" * len(repos)), ",".join("?" * len(C.Contracts.ATTEMPT_KINDS))),
            tuple(repos) + C.Contracts.ATTEMPT_KINDS).fetchall()
        for (rid,) in rows:
            row = self.c._row("reviews", "id", rid)
            try:
                if self.load_packet is None:
                    raise C.ContractError("R2: no packet store to read the stored packet from")
                packet = ahc_review.stored_packet(self.load_packet(row["packet_sha256"]), row["packet_sha256"])
                with self.c.tx():
                    ahc_review.r2_queue(self.c, rid, packet)
                summary["requeued"].append(rid)
            except C.ContractError as error:
                summary["refused"].append((rid, "R2 for a later round: %s" % str(error)[:200]))

    def r2_queue_item(self, item, packet):
        """R2 required -> queued for every attempt-kind row of the item bound to this packet."""
        import ahc_review  # noqa: PLC0415
        for (rid,) in self.c.db.execute("SELECT id FROM reviews WHERE item=? AND state='required' AND kind IN (%s) "
                                        "ORDER BY id" % ",".join("?" * len(C.Contracts.ATTEMPT_KINDS)),
                                        (item["id"],) + C.Contracts.ATTEMPT_KINDS).fetchall():
            ahc_review.r2_queue(self.c, rid, packet)

    def candidates(self, item, obs):
        """Every tick row whose guard holds for the item on this observation, with the target and mark it needs."""
        holding, args = [], {}
        rows = TICK_ROWS + (("W21",) if self.w21 is not None and self.w21.enabled() else ())
        for row in rows:
            if item["state"] not in C.Contracts.WI_TRANSITIONS[row][0]:
                continue
            tries = [dict()]
            if row == "W24":
                tries = [dict(mark="head-moved"), dict(mark="closed-in-flight"), dict(mark="")]
            elif row == "W25":
                tries = [dict(to="superseded"), dict(to="closed-unmerged")]
            for kw in tries:
                ok, _why = self.c.wi_holds(item["id"], row, obs, **kw)
                if ok:
                    holding.append(row)
                    args[row] = kw
                    break
        return holding, args

    def tick(self, tag="tick"):
        summary = {"admitted": [], "duplicates": [], "held": [], "moved": [], "refused": [], "conflicts": [],
                   "incidents": [], "observed": [], "requeued": []}
        with self.c.tx():                     # goodqa#16262 F2: the hold backoff counts ticks
            self.c.db.execute("INSERT INTO contract_meta(k, v) VALUES (?, '1') ON CONFLICT(k) DO UPDATE SET "
                              "v = CAST(CAST(v AS INTEGER) + 1 AS TEXT)", (SEQ_KEY,))
        self.admit_requests(summary)
        for repo in self._repos():
            items = [self.c._row("work_items", "id", i) for (i,) in self.c.db.execute(
                "SELECT id FROM work_items WHERE repo=? AND state IN (%s) ORDER BY created, id"
                % ",".join("?" * len(C.Contracts._WI_LIVE + ("merged",))), (repo,) + C.Contracts._WI_LIVE
                + ("merged",)).fetchall()]
            observed = {}
            for item in items:
                bases = [b for (b,) in self.c.db.execute(
                    "SELECT DISTINCT snapshot_base FROM reviews WHERE item=? AND snapshot_base != ''", (item["id"],))]
                obs = self._observe(summary, repo, item["pr"], item=item["id"], base=item["base"],
                                    head=item["head"], bases=bases)
                if obs is not None:
                    observed[item["id"]] = obs
                    summary["observed"].append(obs["id"])
            queue = {i: o for i, o in observed.items()
                     if self.c._row("work_items", "id", i)["state"] in ("pr-gate", "merge-ready")}
            for item in items:
                if item["id"] not in observed:
                    continue
                self._move(summary, item["id"], dict(observed[item["id"]], queue=queue))
        self.r2_required(summary)
        if self.review is not None:
            summary["review"] = self.review.settle()
            summary["scheduled"] = ReviewScheduler(self.c, self.review.launch_row, slots=self.review.slots).tick(tag)
        if self.w21 is not None:
            summary["w21"] = self.w21.pump()
        if self.digest_append is not None:
            summary["digest"] = deliver_digest(self.c, self.digest_append)
        return summary

    def _move(self, summary, iid, obs):
        item = self.c._row("work_items", "id", iid)
        holding, args = self.candidates(item, obs)
        row = C.Contracts.select_row(holding, self.c.item_unsettled(item))
        if row is None:
            return None
        kw = dict(args.get(row, {}))
        packet = None
        if row in ("W4", "W24") and (row == "W4" or kw.get("mark") == "head-moved"):
            try:
                packet, base = self._successor_packet(item, obs)
            except Exception as error:  # noqa: BLE001 - R2 fails closed: the move waits
                summary["refused"].append((iid, "%s: the successor's R2 packet was not built: %s"
                                           % (row, str(error)[:200])))
                return None
            if packet is None:
                summary["refused"].append((iid, "%s waits for the owner's packet at H'" % row))
                return None
            kw["successor_packet"], kw["successor_base"] = packet["sha256"], base
        ev = event_id(obs["id"], iid, row)
        try:
            if packet is None:
                moved = self.c.wi_move(iid, row, expected_version=item["version"], event_id=ev, actor="ahc-core",
                                       obs=obs, **kw)
            else:
                with self.c.tx():                   # the successor's code rows, in the move's transaction
                    moved = self.c.wi_move(iid, row, expected_version=item["version"], event_id=ev,
                                           actor="ahc-core", obs=obs, **kw)
                    succ = self.c._row("work_items", "id", self.c._row("work_items", "id", iid)["successor"])
                    self.r2_queue_item(succ, packet)
        except C.VersionConflict as error:
            summary["conflicts"].append((iid, row, str(error)))       # NEG-10: another tick applied first
            return None
        except C.ContractError as error:
            summary["refused"].append((iid, "%s: %s" % (row, error)))
            return None
        if "successor_packet" in kw:
            consumed = "%s%s#%d@%s" % (REQUEST_PREFIX, item["repo"], item["pr"], obs["pr_head"])
            with self.c.tx():                       # RT-19: the request's hold goes with it
                self.c.db.execute("DELETE FROM contract_meta WHERE k IN (?, ?)", (consumed, hold_key(consumed)))
        summary["moved"].append((iid, row, moved["state"] if moved else None))
        return row

    def _successor_packet(self, item, obs):
        """W4 and W24's successor at H' gets core's own R2 packet, returned with its B_r:
        - W21's own update (a resolved send whose H' is the new head): B_r is the tip the send merged, which must be
          H'^2 in core's clone (r9: B_r = parent2); the owner's held request, if any, is the fenced owner section.
        - otherwise the owner's held request for (repo, pr, H') is needed (ASSUMPTION: without one W4 waits) and
          B_r is the item's base.
        (None, None) when neither holds."""
        new_head = obs["pr_head"]
        key = "%s%s#%d@%s" % (REQUEST_PREFIX, item["repo"], item["pr"], new_head)
        held = self.c.db.execute("SELECT v FROM contract_meta WHERE k=?", (key,)).fetchone()
        held = json.loads(held[0]) if held else None
        send = self.c.db.execute("SELECT base FROM w21_sends WHERE repo=? AND pr=? AND state='resolved' AND new_head=?",
                                 (item["repo"], item["pr"], new_head)).fetchone()
        if send:
            base = send[0]
            clone = self.clone(item["repo"], new_head, base)
            rc, out, _err = self.producer._git(["rev-parse", "--verify", "--quiet", new_head + "^2"], clone, 30)
            if rc != 0 or out.strip() != base:
                raise C.ContractError("W21's successor: H'^2 is not the tip the send merged")
            req = held or {"repo": item["repo"], "pr": item["pr"], "head": new_head, "base": base,
                           "owner": "ahc (W21 update-branch, no owner request)", "ticket": "", "packet_sha256": ""}
        elif held:
            base, req = item["base"], held
        else:
            return None, None
        return self.r2_packet(dict(req, head=new_head), obs, base=base), base
